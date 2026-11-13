// Package pkgurl implements package URL (PURL) and CPE handling.
//
// PURLs are the join key between endpoint inventory and advisory data; CPEs are
// still required because NVD only speaks CPE. Both are parsed defensively:
// scanned software identification is attacker-influenced data.
package pkgurl

import (
	"fmt"
	"net/url"
	"strings"
)

// PURL is a parsed package URL.
type PURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
	Subpath    string
}

// String renders the canonical purl representation.
func (p PURL) String() string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	if p.Namespace != "" {
		b.WriteString("/")
		segs := strings.Split(p.Namespace, "/")
		for i, seg := range segs {
			if i > 0 {
				b.WriteString("/")
			}
			b.WriteString(escapeSegment(seg))
		}
	}
	b.WriteString("/")
	b.WriteString(escapeSegment(p.Name))
	if p.Version != "" {
		b.WriteString("@")
		b.WriteString(p.Version)
	}
	if len(p.Qualifiers) > 0 {
		// deterministic ordering
		keys := make([]string, 0, len(p.Qualifiers))
		for k := range p.Qualifiers {
			keys = append(keys, k)
		}
		sortStrings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+p.Qualifiers[k])
		}
		b.WriteString("?" + strings.Join(parts, "&"))
	}
	if p.Subpath != "" {
		b.WriteString("#" + p.Subpath)
	}
	return b.String()
}

// escapeSegment percent-encodes a purl path segment per the package-url spec.
// The '@' delimiter inside an npm scope, '+' in Debian package names and other
// reserved characters must be encoded or the purl is ambiguous.
func escapeSegment(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// Parse parses a purl string. It returns an error for malformed input rather
// than silently producing a partial identity.
func Parse(raw string) (PURL, error) {
	var p PURL
	if !strings.HasPrefix(raw, "pkg:") {
		return p, fmt.Errorf("purl must start with pkg: (%q)", raw)
	}
	rest := strings.TrimPrefix(raw, "pkg:")
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		p.Subpath = rest[i+1:]
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		p.Qualifiers = map[string]string{}
		for _, kv := range strings.Split(rest[i+1:], "&") {
			if kv == "" {
				continue
			}
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return p, fmt.Errorf("bad qualifier %q", kv)
			}
			dec, err := url.QueryUnescape(v)
			if err != nil {
				return p, fmt.Errorf("bad qualifier value: %w", err)
			}
			p.Qualifiers[k] = dec
		}
		rest = rest[:i]
	}
	// type[/namespace]/name[@version]
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return p, fmt.Errorf("purl missing type/name (%q)", raw)
	}
	p.Type = strings.ToLower(rest[:slash])
	rest = rest[slash+1:]
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		v, err := url.PathUnescape(rest[at+1:])
		if err != nil {
			return p, fmt.Errorf("bad version: %w", err)
		}
		p.Version = v
		rest = rest[:at]
	}
	if i := strings.LastIndexByte(rest, '/'); i >= 0 {
		ns, err := url.PathUnescape(rest[:i])
		if err != nil {
			return p, fmt.Errorf("bad namespace: %w", err)
		}
		p.Namespace = ns
		rest = rest[i+1:]
	}
	name, err := url.PathUnescape(rest)
	if err != nil {
		return p, fmt.Errorf("bad name: %w", err)
	}
	p.Name = name
	if p.Type == "" || p.Name == "" {
		return p, fmt.Errorf("purl missing type or name (%q)", raw)
	}
	return p, nil
}

// EcosystemPURLType maps an OSV-style ecosystem to a purl type and namespace.
func EcosystemPURLType(ecosystem string) (purlType, namespace string, qualifiers map[string]string) {
	e := strings.ToLower(ecosystem)
	switch {
	case strings.HasPrefix(e, "ubuntu:"):
		ver := strings.TrimPrefix(ecosystem, "Ubuntu:")
		ver = strings.TrimSuffix(strings.ToLower(ver), ":lts")
		return "deb", "ubuntu", map[string]string{"distro": "ubuntu-" + ver}
	case strings.HasPrefix(e, "debian:"):
		ver := strings.TrimPrefix(ecosystem, "Debian:")
		return "deb", "debian", map[string]string{"distro": "debian-" + ver}
	case strings.HasPrefix(e, "alpine:"):
		ver := strings.TrimPrefix(ecosystem, "Alpine:")
		return "apk", "alpine", map[string]string{"distro": "alpine-" + ver}
	case strings.HasPrefix(e, "red hat"), strings.HasPrefix(e, "rhel"):
		return "rpm", "redhat", nil
	case strings.HasPrefix(e, "rocky"):
		return "rpm", "rocky", nil
	case strings.HasPrefix(e, "almalinux"):
		return "rpm", "almalinux", nil
	case strings.HasPrefix(e, "fedora"):
		return "rpm", "fedora", nil
	case strings.HasPrefix(e, "opensuse"), strings.HasPrefix(e, "suse"):
		return "rpm", "opensuse", nil
	case e == "pypi":
		return "pypi", "", nil
	case e == "npm":
		return "npm", "", nil
	case e == "go":
		return "golang", "", nil
	case e == "crates.io":
		return "cargo", "", nil
	case e == "hex":
		return "hex", "", nil
	case e == "maven":
		return "maven", "", nil
	case e == "nuget":
		return "nuget", "", nil
	case e == "rubygems":
		return "gem", "", nil
	case e == "packagist":
		return "composer", "", nil
	case e == "pub":
		return "pub", "", nil
	default:
		return "", "", nil
	}
}

// BuildPURL constructs a purl for an inventory package. It returns "" when the
// ecosystem has no known purl mapping, so callers must not assume a purl exists.
func BuildPURL(ecosystem, name, version string) string {
	purlType, ns, quals := EcosystemPURLType(ecosystem)
	if purlType == "" {
		return ""
	}
	p := PURL{Type: purlType, Version: version, Qualifiers: quals}
	switch purlType {
	case "npm":
		if strings.HasPrefix(name, "@") {
			// scoped packages carry the scope as namespace
			if scope, pkg, ok := strings.Cut(name, "/"); ok {
				p.Namespace = scope
				p.Name = pkg
			} else {
				p.Name = name
			}
		} else {
			p.Name = name
		}
	case "golang", "maven", "composer":
		if i := strings.LastIndexByte(name, '/'); i >= 0 {
			p.Namespace = name[:i]
			p.Name = name[i+1:]
		} else {
			p.Name = name
		}
	default:
		p.Namespace = ns
		p.Name = name
	}
	if p.Namespace == "" && ns != "" {
		p.Namespace = ns
	}
	return p.String()
}

// NormalizeName canonicalises a package name for matching within an ecosystem.
// Advisory feeds and package managers disagree on case and separators for PyPI;
// matching on the raw string silently loses vulnerabilities.
func NormalizeName(ecosystem, name string) string {
	name = strings.TrimSpace(name)
	e := strings.ToLower(ecosystem)
	switch {
	case strings.HasPrefix(e, "pypi"):
		// PEP 503 normalisation
		name = strings.ToLower(name)
		var b strings.Builder
		lastSep := false
		for _, r := range name {
			switch r {
			case '-', '_', '.':
				if !lastSep {
					b.WriteByte('-')
					lastSep = true
				}
			default:
				b.WriteRune(r)
				lastSep = false
			}
		}
		return b.String()
	case strings.HasPrefix(e, "debian"), strings.HasPrefix(e, "ubuntu"),
		strings.HasPrefix(e, "npm"), strings.HasPrefix(e, "alpine"),
		strings.HasPrefix(e, "red hat"), strings.HasPrefix(e, "rocky"),
		strings.HasPrefix(e, "almalinux"), strings.HasPrefix(e, "fedora"):
		return strings.ToLower(name)
	default:
		return name
	}
}

// CPE is a parsed CPE 2.3 formatted string binding.
//
//	cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
type CPE struct {
	Part, Vendor, Product, Version string
	Update, Edition, Language      string
	SwEdition, TargetSW, TargetHW  string
	Other                          string
}

var cpeFields = 11

// ParseCPE parses a cpe:2.3 formatted string binding.
func ParseCPE(raw string) (CPE, error) {
	var c CPE
	parts := splitCPE(raw)
	if len(parts) != cpeFields+2 || parts[0] != "cpe" || parts[1] != "2.3" {
		return c, fmt.Errorf("not a CPE 2.3 formatted string: %q", raw)
	}
	dst := []*string{
		&c.Part, &c.Vendor, &c.Product, &c.Version, &c.Update, &c.Edition,
		&c.Language, &c.SwEdition, &c.TargetSW, &c.TargetHW, &c.Other,
	}
	for i, d := range dst {
		v := parts[i+2]
		if unescaped, err := unescapeCPE(v); err == nil {
			*d = unescaped
		} else {
			*d = v
		}
	}
	return c, nil
}

// splitCPE splits on ':' while honouring backslash escapes, which CPE uses to
// embed literal colons in attribute values.
func splitCPE(raw string) []string {
	var out []string
	cur := strings.Builder{}
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '\\':
			cur.WriteByte(raw[i])
			if i+1 < len(raw) {
				i++
				cur.WriteByte(raw[i])
			}
		case ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(raw[i])
		}
	}
	out = append(out, cur.String())
	return out
}

func unescapeCPE(v string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			i++
			b.WriteByte(v[i])
			continue
		}
		b.WriteByte(v[i])
	}
	return b.String(), nil
}

// String renders the formatted string binding with minimal escaping.
func (c CPE) String() string {
	esc := func(s string) string {
		if s == "" {
			return "*"
		}
		r := strings.NewReplacer(`\`, `\\`, `:`, `\:`)
		return r.Replace(s)
	}
	return fmt.Sprintf("cpe:2.3:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
		esc(c.Part), esc(c.Vendor), esc(c.Product), esc(c.Version), esc(c.Update),
		esc(c.Edition), esc(c.Language), esc(c.SwEdition), esc(c.TargetSW),
		esc(c.TargetHW), esc(c.Other))
}

// CPEToPURLType maps a CPE part/vendor/product triple to a purl type when a
// reliable mapping exists. This is deliberately conservative: guessing an
// ecosystem produces cross-ecosystem false positives.
func CPEToPURLType(part, vendor, product string) (string, bool) {
	if part != "a" && part != "o" && part != "h" {
		return "", false
	}
	switch strings.ToLower(vendor) {
	case "fedoraproject", "redhat", "canonical", "debian", "opensuse", "almalinux", "rocky":
		return "deb", true
	default:
		return "", false
	}
}
