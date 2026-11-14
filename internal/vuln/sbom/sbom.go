// Package sbom reads software bills of materials and dependency manifests into
// the scanner's package inventory.
//
// The parsers are deliberately narrow and data-only: no file in a document is
// executed or interpreted, and unknown formats are rejected rather than guessed.
package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/pkgurl"
)

// MaxDocumentBytes bounds how much of a document is read.
const MaxDocumentBytes = 64 << 20

// Format identifies the detected document type.
type Format string

const (
	FormatCycloneDX    Format = "cyclonedx"
	FormatSPDX         Format = "spdx"
	FormatSyft         Format = "syft"
	FormatNpmLock      Format = "npm-lock"
	FormatRequirements Format = "requirements.txt"
	FormatGoSum        Format = "go.sum"
	FormatCargoLock    Format = "Cargo.lock"
	FormatComposer     Format = "composer.lock"
	FormatGemfileLock  Format = "Gemfile.lock"
	FormatUnknown      Format = "unknown"
)

// Document is a parsed SBOM or manifest.
type Document struct {
	Path     string          `json:"path"`
	Format   Format          `json:"format"`
	Packages []model.Package `json:"packages"`
	// Subject names what the document describes (an image ref, a project, ...).
	Subject  string   `json:"subject,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// ParseFile detects and parses a supported document.
func ParseFile(path string) (Document, error) {
	st, err := os.Stat(path)
	if err != nil {
		return Document{}, err
	}
	if st.IsDir() {
		return Document{}, fmt.Errorf("%s is a directory; point at a manifest or SBOM file", path)
	}
	if st.Size() > MaxDocumentBytes {
		return Document{}, fmt.Errorf("%s is larger than %d bytes", path, int64(MaxDocumentBytes))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	doc, err := Parse(data, filepath.Base(path))
	if err != nil {
		return Document{}, err
	}
	doc.Path = path
	return doc, nil
}

// Parse detects the document format from its content and name.
func Parse(data []byte, name string) (Document, error) {
	doc := Document{Path: name, Format: FormatUnknown}
	trimmed := strings.TrimSpace(string(data))
	lowerName := strings.ToLower(name)

	switch {
	case strings.HasPrefix(trimmed, "{"):
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(data, &probe); err != nil {
			return doc, fmt.Errorf("invalid JSON: %w", err)
		}
		switch {
		case probe["bomFormat"] != nil:
			pkgs, subject, warnings, err := parseCycloneDX(data)
			doc.Format, doc.Packages, doc.Subject, doc.Warnings = FormatCycloneDX, pkgs, subject, warnings
			return doc, err
		case probe["spdxVersion"] != nil:
			pkgs, subject, warnings, err := parseSPDX(data)
			doc.Format, doc.Packages, doc.Subject, doc.Warnings = FormatSPDX, pkgs, subject, warnings
			return doc, err
		case probe["artifacts"] != nil && probe["descriptor"] != nil:
			pkgs, warnings, err := parseSyft(data)
			doc.Format, doc.Packages, doc.Warnings = FormatSyft, pkgs, warnings
			return doc, err
		case strings.Contains(lowerName, "composer"):
			pkgs, warnings, err := parseComposer(data)
			doc.Format, doc.Packages, doc.Warnings = FormatComposer, pkgs, warnings
			return doc, err
		case strings.Contains(lowerName, "package-lock") || probe["lockfileVersion"] != nil:
			pkgs, warnings, err := parseNpmLock(data)
			doc.Format, doc.Packages, doc.Warnings = FormatNpmLock, pkgs, warnings
			return doc, err
		default:
			return doc, fmt.Errorf("JSON document is not a supported SBOM or manifest (expected CycloneDX, SPDX, Syft, package-lock.json or composer.lock)")
		}
	case strings.Contains(lowerName, "cargo.lock") || (strings.Contains(trimmed, "[[package]]") && !strings.Contains(trimmed, "{")):
		pkgs, warnings, err := parseCargoLock(trimmed)
		doc.Format, doc.Packages, doc.Warnings = FormatCargoLock, pkgs, warnings
		return doc, err
	case strings.Contains(trimmed, "GEM") && strings.Contains(trimmed, "specs:"):
		pkgs, warnings, err := parseGemfileLock(trimmed)
		doc.Format, doc.Packages, doc.Warnings = FormatGemfileLock, pkgs, warnings
		return doc, err
	case strings.HasSuffix(lowerName, "go.sum") || looksGoSum(trimmed):
		pkgs, warnings, err := parseGoSum(trimmed)
		doc.Format, doc.Packages, doc.Warnings = FormatGoSum, pkgs, warnings
		return doc, err
	case looksRequirements(trimmed) || (strings.HasPrefix(lowerName, "requirements") && strings.HasSuffix(lowerName, ".txt")):
		pkgs, warnings, err := parseRequirements(trimmed)
		doc.Format, doc.Packages, doc.Warnings = FormatRequirements, pkgs, warnings
		return doc, err
	default:
		return doc, fmt.Errorf("unrecognised document %q: expected an SBOM (CycloneDX/SPDX/Syft) or a supported manifest", name)
	}
}

// ------------------------------------------------------------------ formats ---

type component struct {
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	PURL       string      `json:"purl"`
	Type       string      `json:"type"`
	Group      string      `json:"group"`
	Scope      string      `json:"scope"`
	Components []component `json:"components"`
}

func parseCycloneDX(data []byte) ([]model.Package, string, []string, error) {
	var doc struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Component component `json:"component"`
		} `json:"metadata"`
		Components []component `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, "", nil, fmt.Errorf("parse CycloneDX: %w", err)
	}
	if strings.ToLower(doc.BomFormat) != "cyclonedx" {
		return nil, "", nil, fmt.Errorf("not a CycloneDX document")
	}
	subject := doc.Metadata.Component.Name
	var warnings []string
	var out []model.Package
	for _, p := range flatten(doc.Components) {
		pkg, ok := packageFromComponent(p)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("skipped component %q: no version", p.Name))
			continue
		}
		out = append(out, pkg)
	}
	return dedupe(out), subject, warnings, nil
}

func flatten(list []component) []component {
	out := make([]component, 0, len(list))
	for _, c := range list {
		out = append(out, c)
		out = append(out, flatten(c.Components)...)
	}
	return out
}

func packageFromComponent(c component) (model.Package, bool) {
	version := strings.TrimSpace(c.Version)
	name := strings.TrimSpace(c.Name)
	purl := strings.TrimSpace(c.PURL)
	if purl != "" {
		if parsed, err := pkgurl.Parse(purl); err == nil {
			if name == "" {
				name = parsed.Name
			}
			if version == "" {
				version = parsed.Version
			}
		}
	}
	if name == "" || version == "" {
		return model.Package{}, false
	}
	ecosystem := ecosystemFor(purl, c.Group, name)
	if ecosystem == "" {
		// A component without a purl and without a known ecosystem cannot be
		// correlated; keep it visible but flagged as unknown.
		ecosystem = string(model.EcosystemUnknown)
	}
	return model.Package{
		Name:      name,
		Version:   version,
		Ecosystem: ecosystem,
		PURL:      purl,
		Source:    model.OriginManifest,
		Manager:   "sbom",
	}, true
}

func parseSPDX(data []byte) ([]model.Package, string, []string, error) {
	var doc struct {
		SPDXVersion string `json:"spdxVersion"`
		Name        string `json:"name"`
		Packages    []struct {
			Name         string `json:"name"`
			VersionInfo  string `json:"versionInfo"`
			ExternalRefs []struct {
				ReferenceType    string `json:"referenceType"`
				ReferenceLocator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, "", nil, fmt.Errorf("parse SPDX: %w", err)
	}
	var warnings []string
	var out []model.Package
	for _, p := range doc.Packages {
		purl := ""
		for _, ref := range p.ExternalRefs {
			if ref.ReferenceType == "purl" {
				purl = ref.ReferenceLocator
				break
			}
		}
		pkg, ok := packageFromComponent(component{Name: p.Name, Version: p.VersionInfo, PURL: purl})
		if !ok {
			warnings = append(warnings, fmt.Sprintf("skipped SPDX package %q: no version", p.Name))
			continue
		}
		out = append(out, pkg)
	}
	return dedupe(out), doc.Name, warnings, nil
}

func parseSyft(data []byte) ([]model.Package, []string, error) {
	var doc struct {
		Artifacts []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
			PURL    string `json:"purl"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse Syft JSON: %w", err)
	}
	var warnings []string
	var out []model.Package
	for _, a := range doc.Artifacts {
		pkg, ok := packageFromComponent(component{Name: a.Name, Version: a.Version, PURL: a.PURL})
		if !ok {
			continue
		}
		if pkg.Ecosystem == string(model.EcosystemUnknown) {
			if e := ecosystemForType(a.Type); e != "" {
				pkg.Ecosystem = e
			}
		}
		out = append(out, pkg)
	}
	return dedupe(out), warnings, nil
}

func parseNpmLock(data []byte) ([]model.Package, []string, error) {
	var doc struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Version string `json:"version"`
			Name    string `json:"name"`
			Dev     bool   `json:"dev"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse package-lock.json: %w", err)
	}
	var out []model.Package
	var warnings []string
	for path, meta := range doc.Packages {
		if path == "" || meta.Version == "" {
			continue
		}
		name := meta.Name
		if name == "" {
			name = strings.TrimPrefix(path[strings.LastIndex(path, "node_modules/")+len("node_modules/"):], "/")
		}
		pkg, ok := packageFromComponent(component{Name: name, Version: meta.Version, PURL: pkgurl.BuildPURL("npm", name, meta.Version)})
		if !ok {
			continue
		}
		out = append(out, pkg)
	}
	if len(out) == 0 {
		// v1 lockfile shape.
		for name, dep := range doc.Dependencies {
			if dep.Version == "" {
				continue
			}
			pkg, ok := packageFromComponent(component{Name: name, Version: dep.Version, PURL: pkgurl.BuildPURL("npm", name, dep.Version)})
			if ok {
				out = append(out, pkg)
			}
		}
	}
	if len(out) == 0 {
		warnings = append(warnings, "no packages with versions found in package-lock.json")
	}
	return dedupe(out), warnings, nil
}

func parseRequirements(text string) ([]model.Package, []string, error) {
	var out []model.Package
	var warnings []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip environment markers and extras: "requests[socks]==2.31.0 ; python_version>='3.9'"
		if i := strings.Index(line, ";"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.Index(line, "["); i >= 0 {
			if j := strings.Index(line, "]"); j > i {
				line = line[:i] + line[j+1:]
			}
		}
		var name, version string
		switch {
		case strings.Contains(line, "=="):
			name, version, _ = strings.Cut(line, "==")
		case strings.Contains(line, "==="):
			name, version, _ = strings.Cut(line, "===")
		default:
			if name = strings.TrimSpace(line); name != "" {
				warnings = append(warnings, fmt.Sprintf("skipped %q: pinned version required for correlation", name))
			}
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		version = strings.TrimSpace(strings.Fields(version)[0])
		if name == "" || version == "" {
			continue
		}
		out = append(out, model.Package{
			Name: name, Version: version, Ecosystem: string(model.EcosystemPyPI),
			PURL: pkgurl.BuildPURL("PyPI", name, version), Source: model.OriginManifest, Manager: "requirements.txt",
		})
	}
	if len(out) == 0 {
		return nil, warnings, fmt.Errorf("no pinned requirements found (use name==version)")
	}
	return dedupe(out), warnings, nil
}

func parseGoSum(text string) ([]model.Package, []string, error) {
	seen := map[string]bool{}
	var out []model.Package
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasSuffix(fields[1], "/go.mod") {
			continue
		}
		version := strings.TrimPrefix(fields[1], "v")
		key := fields[0] + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, model.Package{
			Name: fields[0], Version: version, Ecosystem: string(model.EcosystemGo),
			PURL: pkgurl.BuildPURL("Go", fields[0], version), Source: model.OriginManifest, Manager: "go.sum",
		})
	}
	return dedupe(out), nil, nil
}

func parseCargoLock(text string) ([]model.Package, []string, error) {
	var out []model.Package
	var name string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name = ") {
			name = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
			continue
		}
		if strings.HasPrefix(line, "version = ") && name != "" {
			version := strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
			out = append(out, model.Package{
				Name: name, Version: version, Ecosystem: string(model.EcosystemCargo),
				PURL: pkgurl.BuildPURL("crates.io", name, version), Source: model.OriginManifest, Manager: "Cargo.lock",
			})
			name = ""
		}
	}
	return dedupe(out), nil, nil
}

func parseComposer(data []byte) ([]model.Package, []string, error) {
	var doc struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		PackagesDev []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse composer.lock: %w", err)
	}
	var out []model.Package
	for _, p := range append(doc.Packages, doc.PackagesDev...) {
		version := strings.TrimPrefix(p.Version, "v")
		if p.Name == "" || version == "" {
			continue
		}
		out = append(out, model.Package{
			Name: p.Name, Version: version, Ecosystem: string(model.EcosystemPackagist),
			PURL: pkgurl.BuildPURL("Packagist", p.Name, version), Source: model.OriginManifest, Manager: "composer.lock",
		})
	}
	return dedupe(out), nil, nil
}

func parseGemfileLock(text string) ([]model.Package, []string, error) {
	var out []model.Package
	inSpecs := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "  specs:") {
			inSpecs = true
			continue
		}
		if inSpecs {
			if strings.TrimSpace(line) == "" {
				inSpecs = false
				continue
			}
			if !strings.HasPrefix(line, "    ") {
				continue
			}
			entry := strings.TrimSpace(line)
			if i := strings.Index(entry, " ("); i > 0 {
				name := entry[:i]
				version := strings.TrimSuffix(entry[i+2:], ")")
				if version == "" {
					continue
				}
				out = append(out, model.Package{
					Name: name, Version: version, Ecosystem: string(model.EcosystemRubyGems),
					PURL: pkgurl.BuildPURL("RubyGems", name, version), Source: model.OriginManifest, Manager: "Gemfile.lock",
				})
			}
		}
	}
	return dedupe(out), nil, nil
}

// ------------------------------------------------------------------ helpers ---

// ecosystemFor maps a purl (or a group name) to an OSV ecosystem.
func ecosystemFor(purl, group, name string) string {
	if purl != "" {
		if p, err := pkgurl.Parse(purl); err == nil {
			switch p.Type {
			case "npm":
				return string(model.EcosystemNPM)
			case "pypi":
				return string(model.EcosystemPyPI)
			case "golang":
				return string(model.EcosystemGo)
			case "cargo":
				return string(model.EcosystemCargo)
			case "maven":
				return string(model.EcosystemMaven)
			case "gem":
				return string(model.EcosystemRubyGems)
			case "composer":
				return string(model.EcosystemPackagist)
			case "nuget":
				return string(model.EcosystemNuGet)
			case "deb":
				return distroEcosystem("deb", p.Namespace, p.Qualifiers["distro"])
			case "apk":
				return distroEcosystem("apk", p.Namespace, p.Qualifiers["distro"])
			case "rpm":
				return distroEcosystem("rpm", p.Namespace, p.Qualifiers["distro"])
			}
		}
	}
	if strings.HasPrefix(name, "org.") || strings.HasPrefix(name, "com.") || group != "" {
		return string(model.EcosystemMaven)
	}
	return ""
}

func ecosystemForType(t string) string {
	switch strings.ToLower(t) {
	case "npm":
		return string(model.EcosystemNPM)
	case "python", "pip":
		return string(model.EcosystemPyPI)
	case "go-module":
		return string(model.EcosystemGo)
	case "rust-crate":
		return string(model.EcosystemCargo)
	case "gem":
		return string(model.EcosystemRubyGems)
	case "java-archive":
		return string(model.EcosystemMaven)
	case "php-composer":
		return string(model.EcosystemPackagist)
	case "deb":
		return "Debian"
	case "apk":
		return "Alpine"
	}
	return ""
}

// distroEcosystem builds OSV's distribution ecosystem from a purl namespace and
// distro qualifier (pkg:deb/ubuntu/...?distro=ubuntu-24.04).
func distroEcosystem(purlType, namespace, distro string) string {
	version := ""
	if distro != "" {
		if i := strings.LastIndex(distro, "-"); i > 0 {
			version = distro[i+1:]
		}
	}
	switch strings.ToLower(namespace) {
	case "ubuntu":
		if version == "" {
			return ""
		}
		if version == "24.04" || version == "22.04" || version == "20.04" || version == "18.04" {
			return "Ubuntu:" + version + ":LTS"
		}
		return "Ubuntu:" + version
	case "debian":
		if version == "" {
			return ""
		}
		return "Debian:" + version
	case "alpine":
		if version == "" {
			return ""
		}
		parts := strings.Split(version, ".")
		if len(parts) >= 2 {
			version = parts[0] + "." + parts[1]
		}
		return "Alpine:v" + version
	case "redhat", "rhel":
		return "Red Hat"
	case "rocky":
		return "Rocky Linux"
	case "almalinux":
		return "AlmaLinux"
	case "fedora":
		return "Fedora"
	}
	return ""
}

func looksGoSum(text string) bool {
	lines := strings.SplitN(text, "\n", 5)
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 3 && strings.HasPrefix(f[1], "v") && strings.HasPrefix(f[2], "h1:") {
			return true
		}
	}
	return false
}

func looksRequirements(text string) bool {
	lines := strings.SplitN(text, "\n", 10)
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if strings.Contains(l, "==") && !strings.Contains(l, "{") && !strings.Contains(l, ":") {
			return true
		}
	}
	return false
}

func dedupe(in []model.Package) []model.Package {
	seen := map[string]bool{}
	out := make([]model.Package, 0, len(in))
	for _, p := range in {
		key := strings.ToLower(p.Ecosystem) + "\x00" + strings.ToLower(p.Name) + "\x00" + p.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}
