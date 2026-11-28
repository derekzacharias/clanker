// Package norm turns raw endpoint inventory names into normalized vendor /
// product / version / edition / channel identities suitable for CPE and
// advisory lookups.
//
// Why it exists: the display names installers write into the registry
// ("Google Chrome (64-bit)", "Mozilla Firefox (x64 en-US)", "Microsoft 365
// Apps for enterprise - en-us") never equal the standardized names NVD and
// vendors use ("chrome", "firefox", "365_apps"). String equality against
// advisory data therefore misses most applications. The rules are data, not
// code: see rules.json, which can be extended without touching the engine.
//
// Accuracy contract: an alias or pattern mapping is deterministic and
// auditable, and carries high confidence. Fuzzy (token-similarity) matching
// only produces *candidates*; a fuzzy mapping must never by itself establish
// that an application is vulnerable — the caller must downgrade any finding
// derived solely from a fuzzy mapping.
package norm

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

//go:embed rules.json
var rulesJSON []byte

// App is the normalized identity of an installed application.
type App struct {
	// Name is the raw display name, preserved verbatim for provenance.
	Name string
	// Publisher is the raw publisher, preserved verbatim.
	Publisher string
	// Vendor / Product are the canonical identifiers (NVD-style lowercase,
	// underscore-joined product names).
	Vendor  string
	Product string
	// Version is the cleaned version string.
	Version string
	Edition string
	Channel string
	Arch    string
	// Confidence is 0..1 for the vendor/product mapping quality.
	Confidence float64
	// Method names how the mapping was derived:
	// "alias" (deterministic rule), "pattern" (deterministic regex),
	// "fuzzy" (similarity candidate, must not establish vulnerability alone),
	// "unmapped" (no mapping).
	Method string
	// MatchSource records which rule matched, for provenance.
	MatchSource string
}

// Rule is one product mapping rule from rules.json.
type Rule struct {
	Match   string `json:"match"`
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Channel string `json:"channel"`
}

type rulesDoc struct {
	SchemaVersion   int               `json:"schema_version"`
	Vendors         map[string]string `json:"vendors"`
	Products        []Rule            `json:"products"`
	VersionCleaners []struct {
		Match string `json:"match"`
		Keep  string `json:"keep"`
	} `json:"version_cleaners"`
	ArchHints []struct {
		Match string `json:"match"`
		Arch  string `json:"arch"`
	} `json:"arch_hints"`
	ChannelHints []struct {
		Match   string `json:"match"`
		Channel string `json:"channel"`
	} `json:"channel_hints"`
}

// Engine applies the loaded rules. It is safe for concurrent use.
type Engine struct {
	vendors  map[string]string
	products []compiledRule
	version  []compiledRule
	arch     []compiledRule
	channels []compiledRule
	// index maps normalized candidate names (lowercased, punctuation
	// collapsed) to rules, for fuzzy candidate search.
	index []indexEntry
}

type compiledRule struct {
	re      *regexp.Regexp
	rule    Rule
	arch    string
	channel string
	keep    string
}

type indexEntry struct {
	key     string
	vendor  string
	product string
	display string
}

// Default is the engine with the embedded rules. It is validated at load:
// a broken rules file must fail startup, not misbehave during scans.
var Default = mustLoad(rulesJSON)

func mustLoad(raw []byte) *Engine {
	e, err := Load(raw)
	if err != nil {
		panic("embedded norm rules are invalid: " + err.Error())
	}
	return e
}

// Load builds an engine from a rules document.
func Load(raw []byte) (*Engine, error) {
	var doc rulesDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	if doc.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported rules schema %d", doc.SchemaVersion)
	}
	e := &Engine{vendors: map[string]string{}}
	for alias, vendor := range doc.Vendors {
		e.vendors[strings.ToLower(strings.TrimSpace(alias))] = strings.ToLower(strings.TrimSpace(vendor))
	}
	compile := func(match string) (*regexp.Regexp, error) {
		re, err := regexp.Compile(match)
		if err != nil {
			return nil, fmt.Errorf("bad pattern %q: %w", match, err)
		}
		return re, nil
	}
	for _, r := range doc.Products {
		re, err := compile(r.Match)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(r.Vendor) == "" || strings.TrimSpace(r.Product) == "" {
			return nil, fmt.Errorf("product rule %q has no vendor/product", r.Match)
		}
		cr := compiledRule{re: re, rule: Rule{
			Match: r.Match, Vendor: strings.ToLower(strings.TrimSpace(r.Vendor)),
			Product: strings.ToLower(strings.TrimSpace(r.Product)), Channel: r.Channel,
		}}
		e.products = append(e.products, cr)
		e.index = append(e.index, indexEntry{
			key: indexKey(r.Match), vendor: cr.rule.Vendor, product: cr.rule.Product,
			display: displayOf(r.Match),
		})
	}
	for _, c := range doc.VersionCleaners {
		re, err := compile(c.Match)
		if err != nil {
			return nil, err
		}
		e.version = append(e.version, compiledRule{re: re, keep: c.Keep})
	}
	for _, a := range doc.ArchHints {
		re, err := compile(a.Match)
		if err != nil {
			return nil, err
		}
		e.arch = append(e.arch, compiledRule{re: re, arch: a.Arch})
	}
	for _, c := range doc.ChannelHints {
		re, err := compile(c.Match)
		if err != nil {
			return nil, err
		}
		e.channels = append(e.channels, compiledRule{re: re, channel: strings.ToLower(c.Channel)})
	}
	sort.Slice(e.index, func(i, j int) bool { return e.index[i].display > e.index[j].display })
	return e, nil
}

// Normalize maps a raw inventory record to a normalized identity.
func (e *Engine) Normalize(displayName, publisher, version, arch string) App {
	a := App{
		Name:      strings.TrimSpace(displayName),
		Publisher: strings.TrimSpace(publisher),
		Version:   cleanVersion(e, strings.TrimSpace(version)),
		Arch:      normalizeArch(strings.TrimSpace(arch)),
		Method:    "unmapped",
	}
	name := strings.TrimSpace(displayName)
	// Strip trailing architecture and locale decorations from the display
	// name; they are recorded separately.
	name = stripDecorations(name)
	// Patterns in the rules file are written lowercase; matching is
	// case-insensitive by comparing against the lowercased name.
	matchName := strings.ToLower(name)
	a.Arch = firstNonEmpty(a.Arch, archFromName(e, matchName))

	// Channel / edition hints.
	if ch := channelFromName(e, matchName); ch != "" {
		a.Channel = strings.ToLower(ch)
	}
	if a.Channel != "" && strings.Contains(matchName, "preview") {
		a.Edition = "preview"
	}

	// Deterministic mapping: the publisher alias first (strongest signal,
	// exact identifier), then product patterns.
	if vendor, ok := e.vendors[strings.ToLower(strings.TrimSpace(publisher))]; ok {
		a.Vendor = vendor
	}
	for _, r := range e.products {
		if r.re.MatchString(matchName) {
			// A publisher-derived vendor that contradicts the rule loses:
			// the rule knows the product family, publishers are unreliable.
			a.Vendor = r.rule.Vendor
			a.Product = r.rule.Product
			if r.rule.Channel != "" && a.Channel == "" {
				a.Channel = strings.ToLower(r.rule.Channel)
			}
			a.Method = "pattern"
			a.MatchSource = r.rule.Match
			a.Confidence = 0.9
			return a
		}
	}
	if a.Vendor != "" {
		// Publisher mapped but no product: keep the vendor; the caller can
		// still look the product up in the CPE dictionary by name.
		a.Confidence = 0.5
		return a
	}
	return a
}

// Candidates returns fuzzy candidate mappings for a name that did not match
// any deterministic rule. Callers must treat these as suggestions only.
type Candidate struct {
	Vendor, Product string
	Score           float64
}

// Candidates returns the top fuzzy candidates (at most limit) for a display
// name. A score of 1.0 means an exact normalized match.
func (e *Engine) Candidates(displayName string, limit int) []Candidate {
	name := stripDecorations(strings.TrimSpace(displayName))
	want := tokenSet(name)
	if len(want) == 0 {
		return nil
	}
	type scored struct {
		c     Candidate
		score float64
	}
	var out []scored
	for _, entry := range e.index {
		have := tokenSet(entry.display)
		if len(have) == 0 {
			continue
		}
		score := jaccard(want, have)
		// Typos break token equality, so combine the token score with a
		// bigram score over the whole string: "googl chrome" must still
		// surface "google chrome" as a candidate.
		if bg := bigramDice(name, entry.display); bg > score {
			score = bg
		}
		if score < 0.5 {
			continue
		}
		out = append(out, scored{c: Candidate{Vendor: entry.vendor, Product: entry.product}, score: score})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].score > out[j].score })
	if len(out) > limit {
		out = out[:limit]
	}
	res := make([]Candidate, 0, len(out))
	for _, s := range out {
		res = append(res, s.c)
	}
	return res
}

// ------------------------------------------------------------------ helpers --

var decorationRe = regexp.MustCompile(`(?i)\s*\((x64|x86|arm64|64-bit|32-bit|64 bit|32 bit)(\s+[a-z]{2}-[a-z]{2})?\)$`)

func stripDecorations(name string) string {
	for {
		n := decorationRe.ReplaceAllString(name, "")
		if n == name {
			return strings.TrimSpace(n)
		}
		name = n
	}
}

func normalizeArch(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "x64", "amd64", "x86_64", "64-bit", "64 bit":
		return "x64"
	case "x86", "i386", "i686", "32-bit", "32 bit":
		return "x86"
	case "arm64", "aarch64":
		return "arm64"
	}
	return strings.TrimSpace(arch)
}

func archFromName(e *Engine, name string) string {
	for _, a := range e.arch {
		if a.re.MatchString(name) {
			return a.arch
		}
	}
	return ""
}

func channelFromName(e *Engine, name string) string {
	for _, c := range e.channels {
		if m := c.re.FindStringSubmatch(name); m != nil {
			if c.channel == "$1" && len(m) > 1 {
				return strings.ToLower(m[1])
			}
			return c.channel
		}
	}
	return ""
}

func cleanVersion(e *Engine, version string) string {
	version = strings.TrimSpace(version)
	// Strip common suffixes like " (build 123)".
	for _, c := range e.version {
		if m := c.re.FindStringSubmatch(version); m != nil {
			for i, g := range m {
				if c.keep == "$"+fmt.Sprint(i) {
					return strings.TrimSpace(g)
				}
			}
			if c.keep != "" {
				return strings.TrimSpace(c.re.ReplaceAllString(version, c.keep))
			}
		}
	}
	return version
}

// tokenSet lowercases and splits a name into alphanumeric tokens.
func tokenSet(s string) map[string]bool {
	fields := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	})
	out := map[string]bool{}
	for _, f := range fields {
		if f != "" {
			out[f] = true
		}
	}
	return out
}

// jaccard is the token-set similarity in [0,1].
func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter, union := 0, len(b)
	for t := range a {
		if b[t] {
			inter++
		} else {
			union++
		}
	}
	return float64(inter) / float64(union)
}

// bigramDice is the Sørensen–Dice coefficient over character bigrams of the
// normalized strings. It tolerates typos and inserted spaces that token
// comparison rejects.
func bigramDice(a, b string) float64 {
	set := func(s string) map[string]int {
		m := map[string]int{}
		var prev rune
		first := true
		for _, r := range strings.ToLower(s) {
			if r < 'a' || r > 'z' {
				prev = 0
				first = true
				continue
			}
			if !first {
				m[string([]rune{prev, r})]++
			}
			prev = r
			first = false
		}
		return m
	}
	sa, sb := set(a), set(b)
	if len(sa) == 0 || len(sb) == 0 {
		return 0
	}
	var inter int
	for g, n := range sa {
		if m, ok := sb[g]; ok {
			inter += min(n, m)
		}
	}
	total := 0
	for _, n := range sa {
		total += n
	}
	for _, n := range sb {
		total += n
	}
	return 2 * float64(inter) / float64(total)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// indexKey normalizes a match pattern into searchable tokens.
func indexKey(pattern string) string {
	return strings.ToLower(stripRegex(pattern))
}

// stripRegex removes regex syntax from a pattern for display purposes.
func stripRegex(pattern string) string {
	var b strings.Builder
	escaped := false
	inClass := false
	for _, r := range pattern {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '[':
			inClass = true
		case r == ']' && inClass:
			inClass = false
		case inClass:
		case r == '(' || r == ')' || r == '^' || r == '$' || r == '?' || r == '+':
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// displayOf renders a human-readable approximation of a match pattern, used
// only for fuzzy candidate scoring.
func displayOf(pattern string) string {
	// Cheap heuristic: strip anchors and quantifiers.
	s := strings.TrimPrefix(pattern, "^")
	s = strings.TrimSuffix(s, "$")
	return s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
