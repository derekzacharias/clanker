// Package cpe implements CPE 2.3 formatted string binding parsing, wildcard
// matching, NVD version ranges and NVD configuration-tree evaluation.
//
// It exists because application vulnerability correlation lives or dies on
// matching installed software against NVD's cpeMatch data correctly: a string
// comparison between "120.0.10" and "120.0.9" is wrong, and a naive substring
// match between "chrome" and "google_chrome_os" produces false positives.
package cpe

import (
	"fmt"
	"strings"
)

// Part values for a CPE 2.3 binding.
const (
	PartApplication = "a"
	PartOS          = "o"
	PartHardware    = "h"
)

// Any and NA are the two special attribute values in CPE 2.3.
const (
	Any = "*"
	NA  = "-"
)

// CPE is a parsed CPE 2.3 formatted string binding:
//
//	cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
type CPE struct {
	Part, Vendor, Product, Version string
	Update, Edition, Language      string
	SwEdition, TargetSW, TargetHW  string
	Other                          string
}

// IsAny reports whether the attribute is the ANY wildcard or empty.
func isAny(v string) bool { return v == "" || v == Any }

// Parse parses a cpe:2.3 formatted string binding. Escaped characters
// (backslash-escaped colons etc.) are honoured per NIST IR 7695.
func Parse(raw string) (CPE, error) {
	var c CPE
	parts := splitEscaped(raw)
	if len(parts) != 13 || parts[0] != "cpe" || parts[1] != "2.3" {
		return c, fmt.Errorf("not a CPE 2.3 formatted string: %q", raw)
	}
	dst := []*string{
		&c.Part, &c.Vendor, &c.Product, &c.Version, &c.Update, &c.Edition,
		&c.Language, &c.SwEdition, &c.TargetSW, &c.TargetHW, &c.Other,
	}
	for i, d := range dst {
		v, err := unescape(parts[i+2])
		if err != nil {
			return c, fmt.Errorf("invalid CPE escape in %q: %w", raw, err)
		}
		*d = v
	}
	return c, nil
}

// MustParse parses or panics. Only for static test fixtures.
func MustParse(raw string) CPE {
	c, err := Parse(raw)
	if err != nil {
		panic(err)
	}
	return c
}

// String renders the binding with the minimal escaping required.
func (c CPE) String() string {
	esc := func(s string) string {
		if s == "" {
			return Any
		}
		r := strings.NewReplacer(`\`, `\\`, `:`, `\:`)
		return r.Replace(s)
	}
	return fmt.Sprintf("cpe:2.3:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
		esc(c.Part), esc(c.Vendor), esc(c.Product), esc(c.Version), esc(c.Update),
		esc(c.Edition), esc(c.Language), esc(c.SwEdition), esc(c.TargetSW),
		esc(c.TargetHW), esc(c.Other))
}

// splitEscaped splits on ':' honouring backslash escapes.
func splitEscaped(raw string) []string {
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

// unescape resolves CPE escapes. The CPE 2.3 spec lists the escapable set,
// but the live NVD dictionary also escapes characters outside it (notably
// parentheses in version strings), so any escaped character is unescaped as
// itself; a dangling backslash is still an error.
func unescape(v string) (string, error) {
	if !strings.Contains(v, `\`) {
		return v, nil
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' {
			b.WriteByte(v[i])
			continue
		}
		if i+1 >= len(v) {
			return "", fmt.Errorf("dangling backslash")
		}
		i++
		b.WriteByte(v[i])
	}
	return b.String(), nil
}

// escape renders one attribute with the escapes required by the spec.
func escape(s string) string {
	if s == "" {
		return Any
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.ContainsRune(`:*?!\"'#%&+;<=>^`+"`"+`{|}~ `, rune(c)) || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

// ComponentMatches compares one attribute: the pattern may contain the CPE
// wildcards '*' (any sequence) and '?' (any single character). Matching is
// case-insensitive, as the CPE specification requires.
func ComponentMatches(pattern, value string) bool {
	if isAny(pattern) {
		return true
	}
	return wildcardMatch(strings.ToLower(pattern), strings.ToLower(value))
}

// wildcardMatch implements '*'/'?' matching. It has no backtracking explosion:
// patterns come from advisory feeds, and a linear two-pointer scan covers the
// practical cases (single leading/trailing/embedded '*').
func wildcardMatch(pattern, value string) bool {
	pi, vi := 0, 0
	star, mark := -1, 0
	for vi < len(value) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == value[vi]):
			pi++
			vi++
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			mark = vi
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			vi = mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// Matches reports whether the target CPE is covered by this binding pattern.
// Every non-ANY attribute of the pattern must match the target; the target's
// own attributes are concrete values.
//
// NA semantics: for the identity attributes (part, vendor, product, version)
// a "-" pattern matches only a "-" target — a criteria naming vendor "-"
// matches nothing real. For the descriptive attributes (update, edition,
// language, sw_edition, target_sw, target_hw, other) NVD fills "-" as a
// placeholder meaning "unspecified", so it is treated as non-constraining:
// treating it strictly would silently drop most application criteria (e.g.
// mozilla:firefox criteria carry target_sw "-").
func (c CPE) Matches(target CPE) bool {
	identity := []struct {
		pat, val string
	}{
		{c.Part, target.Part}, {c.Vendor, target.Vendor}, {c.Product, target.Product},
		{c.Version, target.Version},
	}
	for _, f := range identity {
		if !ComponentMatches(f.pat, f.val) {
			return false
		}
	}
	descriptive := []struct {
		pat, val string
	}{
		{c.Update, target.Update}, {c.Edition, target.Edition},
		{c.Language, target.Language}, {c.SwEdition, target.SwEdition},
		{c.TargetSW, target.TargetSW}, {c.TargetHW, target.TargetHW},
		{c.Other, target.Other},
	}
	for _, f := range descriptive {
		if f.pat == NA {
			continue // "not applicable" filled in by NVD: no constraint
		}
		if !ComponentMatches(f.pat, f.val) {
			return false
		}
	}
	return true
}

// NewTarget builds a concrete CPE from the observed facts of an installed
// application. Unknown attributes become ANY so pattern matching never rejects
// a candidate merely because the inventory did not record that dimension.
// Known release channels map onto the attributes NVD uses for them (e.g.
// Firefox ESR lives in sw_edition).
func NewTarget(vendor, product, version, edition, channel, arch string) CPE {
	c := CPE{
		Part:    PartApplication,
		Vendor:  orAny(vendor),
		Product: orAny(product),
		Version: orAny(version),
		Edition: orAny(edition),
		Other:   orAny(channel),
	}
	switch strings.ToLower(strings.TrimSpace(channel)) {
	case "esr":
		// NVD models extended-support releases as a software edition.
		c.SwEdition = "esr"
	}
	switch strings.ToLower(arch) {
	case "x64", "amd64", "x86_64":
		c.TargetSW, c.TargetHW = "x64", "x64"
	case "x86", "i386", "i686":
		c.TargetSW, c.TargetHW = "x86", "x86"
	case "arm64", "aarch64":
		c.TargetSW, c.TargetHW = "arm64", "arm64"
	default:
		c.TargetSW, c.TargetHW = orAny(arch), Any
	}
	return c
}

func orAny(v string) string {
	if strings.TrimSpace(v) == "" {
		return Any
	}
	return v
}
