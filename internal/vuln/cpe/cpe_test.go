package cpe

import (
	"testing"

	"github.com/bgdnvk/clanker/internal/vuln/version"
)

func appTargets(vendor, product, version, arch string) Targets {
	return Targets{App: NewTarget(vendor, product, version, "", "", arch)}
}

func TestParseRoundTrip(t *testing.T) {
	cases := []string{
		"cpe:2.3:a:google:chrome:120.0.6099.109:*:*:*:*:*:*:*",
		"cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
		"cpe:2.3:a:foo:bar\\:baz:1.0:*:*:*:*:*:*:*", // escaped colon
		"cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*",
	}
	for _, raw := range cases {
		c, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q): %v", raw, err)
		}
		if got := c.String(); got != raw {
			t.Errorf("round trip %q -> %q", raw, got)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	bad := []string{
		"",
		"cpe:2.2:a:google:chrome",
		"cpe:2.3:a:google", // too few fields
		"cpe:2.3:a:google:chrome:1.0:*:*:*:*:*:*:*:*",  // too many
		"cpe:2.3:a:google:chrome:1\\q:0:*:*:*:*:*:*:*", // 14 fields: the escaped token splits the version
		"cpe:2.3:a:google:chrome:1\\",                  // dangling backslash
	}
	for _, raw := range bad {
		if _, err := Parse(raw); err == nil {
			t.Errorf("Parse(%q): expected error", raw)
		}
	}
}

func TestParseEscapedParens(t *testing.T) {
	// The live NVD dictionary escapes characters outside the spec's list,
	// notably parentheses in version strings. They must parse, not poison the
	// index.
	c, err := Parse(`cpe:2.3:h:cisco:7920_wireless_ip_phone:1.0\(8\):*:*:*:*:*:*:*`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != "1.0(8)" {
		t.Fatalf("version = %q, want 1.0(8)", c.Version)
	}
}

func TestParseEscapedColon(t *testing.T) {
	c, err := Parse(`cpe:2.3:a:microsoft:windows_10:1607:*:*:*:*:*:*:*`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Vendor != "microsoft" || c.Product != "windows_10" {
		t.Fatalf("unexpected parse: %+v", c)
	}
}

func TestMatchesWildcards(t *testing.T) {
	pattern := MustParse("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*")
	target := NewTarget("google", "chrome", "120.0.6099.109", "", "", "x64")
	if !pattern.Matches(target) {
		t.Fatal("wildcard version pattern should match any chrome version")
	}
	if pattern.Matches(NewTarget("google", "chromeos", "1.0", "", "", "")) {
		t.Fatal("chromeos must not match chrome")
	}
	if pattern.Matches(NewTarget("mozilla", "firefox", "1.0", "", "", "")) {
		t.Fatal("firefox must not match chrome pattern")
	}
}

func TestMatchesCaseInsensitive(t *testing.T) {
	pattern := MustParse("cpe:2.3:a:Google:CHROME:*:*:*:*:*:*:*:*")
	if !pattern.Matches(NewTarget("google", "chrome", "1.0", "", "", "")) {
		t.Fatal("CPE matching must be case-insensitive")
	}
}

func TestMatchesQuestionMark(t *testing.T) {
	pattern := MustParse("cpe:2.3:a:microsoft:window?:*:*:*:*:*:*:*:*")
	if !pattern.Matches(NewTarget("microsoft", "windows", "1.0", "", "", "")) {
		t.Fatal("? wildcard should match one character")
	}
	if pattern.Matches(NewTarget("microsoft", "windowsx", "1.0", "", "", "")) {
		t.Fatal("? must match exactly one character")
	}
}

func TestMatchesArchConstrained(t *testing.T) {
	x64 := MustParse("cpe:2.3:a:acme:app:*:*:*:*:*:x64:x64:*")
	if !x64.Matches(NewTarget("acme", "app", "1.0", "", "", "x64")) {
		t.Fatal("x64 pattern should match x64 target")
	}
	if x64.Matches(NewTarget("acme", "app", "1.0", "", "", "x86")) {
		t.Fatal("x64 pattern must not match x86 target")
	}
}

func TestMatchesNAPlaceholderDoesNotConstrain(t *testing.T) {
	// Real NVD shape: application criteria commonly carry target_sw "-"
	// (the dictionary's "not applicable" filler). It must not reject a
	// concrete x64 target — strict NA matching would silently drop most
	// application criteria.
	pattern := MustParse("cpe:2.3:a:mozilla:firefox:*:*:*:*:-:*:*:*")
	target := NewTarget("mozilla", "firefox", "122.0.1", "", "", "x64")
	if !pattern.Matches(target) {
		t.Fatal("NA target_sw must be a non-constraining placeholder")
	}
	// Identity attributes stay strict: vendor/product/version "-" match
	// nothing real.
	if (CPE{Part: "a", Vendor: "-", Product: "firefox", Version: Any}).Matches(target) {
		t.Fatal("vendor NA must not match a concrete target")
	}
	if (CPE{Part: "a", Vendor: "mozilla", Product: "firefox", Version: "-"}).Matches(target) {
		t.Fatal("version NA must not match a concrete version")
	}
}

// The real CVE-2024-1546 configuration: an OR node with an ESR range
// (sw_edition esr, < 115.8) and a generic range (sw_edition *, < 123.0).
func firefox1546Config() Node {
	return Node{Operator: "OR", Matches: []Match{
		{
			Criteria:        "cpe:2.3:a:mozilla:firefox:*:*:*:*:esr:*:*:*",
			Vulnerable:      true,
			Range:           Range{EndExcluding: "115.8.0"},
			MatchCriteriaID: "esr",
		},
		{
			Criteria:        "cpe:2.3:a:mozilla:firefox:*:*:*:*:-:*:*:*",
			Vulnerable:      true,
			Range:           Range{EndExcluding: "123.0"},
			MatchCriteriaID: "generic",
		},
	}}
}

func TestFirefoxEditionShadowing(t *testing.T) {
	// Regular Firefox: the generic range applies.
	reg := NewTarget("mozilla", "firefox", "122.0.1", "", "", "x64")
	if ev := firefox1546Config().Evaluate(Targets{App: reg}, nil); !ev.Matched || !ev.Vulnerable {
		t.Fatalf("firefox 122.0.1 must be vulnerable (< 123.0): %+v", ev)
	}
	if ev := firefox1546Config().Evaluate(Targets{App: NewTarget("mozilla", "firefox", "123.0", "", "", "x64")}, nil); ev.Matched {
		t.Fatal("firefox 123.0 must not be vulnerable")
	}

	// ESR build 115.7: vulnerable via the ESR range.
	esrVuln := NewTarget("mozilla", "firefox", "115.7.0", "", "esr", "x64")
	if ev := firefox1546Config().Evaluate(Targets{App: esrVuln}, nil); !ev.Matched || !ev.Vulnerable {
		t.Fatalf("ESR 115.7 must be vulnerable (< 115.8): %+v", ev)
	}
	// ESR build 115.8.1: fixed in the ESR line. The generic range says
	// "< 123.0 affected", which would flag it — edition shadowing must
	// keep the generic entry out.
	esrFixed := NewTarget("mozilla", "firefox", "115.8.1", "", "esr", "x64")
	ev := firefox1546Config().Evaluate(Targets{App: esrFixed}, nil)
	if ev.Matched {
		t.Fatalf("fixed ESR 115.8.1 must not match the generic range: %+v", ev)
	}
	// The shadowing only kicks in when the node HAS an esr-specific entry.
	genericOnly := Node{Operator: "OR", Matches: []Match{firefox1546Config().Matches[1]}}
	if ev := genericOnly.Evaluate(Targets{App: esrFixed}, nil); !ev.Matched {
		t.Fatalf("a node with only a generic range still matches (no edition data to shadow it): %+v", ev)
	}
}

func TestRangeContains(t *testing.T) {
	cmp := func(a, b string) (int, error) { return version.Compare("", a, b) }

	cases := []struct {
		name    string
		r       Range
		version string
		want    bool
	}{
		{"inside inclusive", Range{StartIncluding: "1.0", EndExcluding: "2.0"}, "1.5", true},
		{"start inclusive boundary", Range{StartIncluding: "1.0", EndExcluding: "2.0"}, "1.0", true},
		{"end exclusive boundary", Range{StartIncluding: "1.0", EndExcluding: "2.0"}, "2.0", false},
		{"below range", Range{StartIncluding: "1.0"}, "0.9", false},
		{"above range", Range{EndIncluding: "2.0"}, "2.0.1", false},
		{"start excluding boundary", Range{StartExcluding: "1.0"}, "1.0", false},
		{"start excluding above", Range{StartExcluding: "1.0"}, "1.0.1", true},
		{"empty range contains all", Range{}, "anything", true},
		{"numeric not lexicographic", Range{StartIncluding: "120.0.10"}, "120.0.9", false},
		{"numeric not lexicographic above", Range{StartIncluding: "120.0.9"}, "120.0.10", true},
		{"four part versions", Range{StartIncluding: "119.0.6045.105", EndExcluding: "120.0.6099.110"}, "120.0.6099.109", true},
	}
	for _, tc := range cases {
		got, err := tc.r.Contains(tc.version, cmp)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: Contains(%q) = %v, want %v", tc.name, tc.version, got, tc.want)
		}
	}
}

func TestRangeRejectsDoubleBounds(t *testing.T) {
	r := Range{StartIncluding: "1.0", StartExcluding: "1.0"}
	if _, err := r.Contains("1.0", nil); err == nil {
		t.Fatal("double-bounded range must be a correlation error, not a match")
	}
}

func TestRangeUnparsableVersionIsError(t *testing.T) {
	r := Range{StartIncluding: "1.0"}
	cmp := func(a, b string) (int, error) {
		return 0, errCompare
	}
	if _, err := r.Contains("1.0", cmp); err == nil {
		t.Fatal("unparsable version must error, never silently miss")
	}
}

var errCompare = &testErr{}

type testErr struct{}

func (e *testErr) Error() string { return "unparsable" }

func TestRangeDescribe(t *testing.T) {
	cases := []struct {
		r    Range
		want string
	}{
		{Range{StartIncluding: "1.0", EndExcluding: "2.0"}, "[1.0, 2.0)"},
		{Range{StartExcluding: "1.0"}, "> 1.0"},
		{Range{EndIncluding: "2.0"}, "<= 2.0"},
		{Range{}, "any"},
	}
	for _, tc := range cases {
		if got := tc.r.Describe(); got != tc.want {
			t.Errorf("Describe() = %q, want %q", got, tc.want)
		}
	}
}

func chromeVulnConfig(affectedStart, affectedEnd string) Node {
	m := Match{Criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", Vulnerable: true}
	m.StartIncluding = affectedStart
	m.EndExcluding = affectedEnd
	return Node{Operator: "OR", Matches: []Match{m}}
}

func TestEvaluateSimpleVulnerableNode(t *testing.T) {
	targets := appTargets("google", "chrome", "120.0.6099.109", "")
	ev := chromeVulnConfig("119.0.0.0", "120.0.6099.110").Evaluate(targets, nil)
	if !ev.Matched || !ev.Vulnerable {
		t.Fatalf("expected vulnerable match, got %+v", ev)
	}
	if len(ev.MatchedCriteria) == 0 {
		t.Fatal("matched criteria must be recorded for evidence")
	}
}

func TestEvaluatePatchedVersionNotVulnerable(t *testing.T) {
	targets := appTargets("google", "chrome", "120.0.6099.110", "")
	ev := chromeVulnConfig("119.0.0.0", "120.0.6099.110").Evaluate(targets, nil)
	if ev.Matched {
		t.Fatalf("patched version outside range must not match: %+v", ev)
	}
}

func TestEvaluateExactVersionMatch(t *testing.T) {
	n := Node{Operator: "OR", Matches: []Match{{
		Criteria:   "cpe:2.3:a:7-zip:7-zip:23.01:*:*:*:*:*:*:*",
		Vulnerable: true,
	}}}
	if ev := n.Evaluate(appTargets("7-zip", "7-zip", "23.01", ""), nil); !ev.Matched || !ev.Vulnerable {
		t.Fatalf("exact version must match: %+v", ev)
	}
	if ev := n.Evaluate(appTargets("7-zip", "7-zip", "23.02", ""), nil); ev.Matched {
		t.Fatal("different version must not match exact criteria")
	}
}

func TestEvaluateAndOrTrees(t *testing.T) {
	// CVE affecting chrome only on Windows: AND(chrome-range, windows-os)
	chrome := chromeVulnConfig("119.0.0.0", "120.0.0.0")
	windows := Node{Operator: "OR", Matches: []Match{{
		Criteria: "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*", Vulnerable: true,
	}}}
	tree := Node{Operator: "AND", Children: []Node{chrome, windows}}

	winTargets := appTargets("google", "chrome", "119.0.1", "")
	winTargets.OS = []CPE{
		MustParse("cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*"),
		MustParse("cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"),
	}
	if ev := tree.Evaluate(winTargets, nil); !ev.Matched || !ev.Vulnerable {
		t.Fatalf("AND of chrome range + windows should match: %+v", ev)
	}
	// A linux host: the OS prerequisite fails, so the AND fails.
	linuxTargets := appTargets("google", "chrome", "119.0.1", "")
	linuxTargets.OS = []CPE{MustParse("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*")}
	if ev := tree.Evaluate(linuxTargets, nil); ev.Matched {
		t.Fatalf("AND with unsatisfied environment constraint must not match: %+v", ev)
	}
	// No OS identity known: fails closed (prerequisites are not assumed).
	if ev := tree.Evaluate(appTargets("google", "chrome", "119.0.1", ""), nil); ev.Matched {
		t.Fatalf("unknown environment must fail closed: %+v", ev)
	}
	// Generic windows criteria matches via the generic identity when the
	// specific one does not exist in the feed.
	onlyGeneric := appTargets("google", "chrome", "119.0.1", "")
	onlyGeneric.OS = []CPE{MustParse("cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*")}
	if ev := tree.Evaluate(onlyGeneric, nil); !ev.Matched {
		t.Fatalf("generic windows identity should satisfy the OS prerequisite: %+v", ev)
	}
}

func TestEvaluateNegatedNode(t *testing.T) {
	// CVE that does NOT apply when a specific component is present.
	n := Node{
		Operator: "OR",
		Negate:   true,
		Matches:  []Match{{Criteria: "cpe:2.3:a:acme:component:1.0:*:*:*:*:*:*:*", Vulnerable: true}},
	}
	if ev := n.Evaluate(appTargets("acme", "component", "1.0", ""), nil); ev.Matched {
		t.Fatalf("negated node must not match when the component is present: %+v", ev)
	}
	if ev := n.Evaluate(appTargets("acme", "component", "2.0", ""), nil); !ev.Matched {
		t.Fatalf("negated node must match when the component is absent: %+v", ev)
	}
}

func TestEvaluateConfigsVulnerableAndFixed(t *testing.T) {
	// The classic NVD shape: an OR node where one criteria covers affected
	// versions and another names the fixed version.
	config := []Node{{
		Operator: "OR",
		Matches: []Match{
			{
				Criteria:        "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*",
				Vulnerable:      true,
				Range:           Range{EndExcluding: "124.0"},
				MatchCriteriaID: "mc-1",
			},
			{
				Criteria:        "cpe:2.3:a:mozilla:firefox:124.0:*:*:*:*:*:*:*",
				Vulnerable:      false,
				MatchCriteriaID: "mc-2",
			},
		},
	}}
	res := EvaluateConfigs(config, appTargets("mozilla", "firefox", "123.0.1", ""), nil)
	if !res.Vulnerable {
		t.Fatalf("123.0.1 inside <124.0 must be vulnerable: %+v", res)
	}

	res = EvaluateConfigs(config, appTargets("mozilla", "firefox", "124.0", ""), nil)
	if res.Vulnerable {
		t.Fatal("124.0 matches only the fixed criteria; must not be vulnerable")
	}
	if !res.MatchedNotVulnerable {
		t.Fatal("fixed version must be recorded as matched-not-vulnerable")
	}
	if len(res.FixedVersions) == 0 || res.FixedVersions[0] != "124.0" {
		t.Fatalf("fixed version must be collected: %v", res.FixedVersions)
	}
	if len(res.MatchedCPEs) == 0 {
		t.Fatal("matched CPEs must be collected for evidence")
	}
}

func TestEvaluateUnknownVersionNeverMatches(t *testing.T) {
	n := chromeVulnConfig("119.0.0.0", "120.0.0.0")
	if ev := n.Evaluate(appTargets("google", "chrome", "", ""), nil); ev.Matched {
		t.Fatal("unknown installed version must never match a version-dependent criteria")
	}
}

func TestEvaluateMalformedCriteriaFailsClosed(t *testing.T) {
	n := Node{Operator: "OR", Matches: []Match{{Criteria: "not-a-cpe", Vulnerable: true}}}
	if ev := n.Evaluate(appTargets("google", "chrome", "1.0", ""), nil); ev.Matched {
		t.Fatal("malformed criteria must fail closed")
	}
}

func TestEvaluateVersionWithLetters(t *testing.T) {
	// e.g. LibreOffice 7.6.4.1 — generic comparator handles dot-separated numbers.
	n := Node{Operator: "OR", Matches: []Match{{
		Criteria:   "cpe:2.3:a:libreoffice:libreoffice:*:*:*:*:*:*:*:*",
		Vulnerable: true,
		Range:      Range{StartIncluding: "7.6.0", EndExcluding: "7.6.5"},
	}}}
	ev := n.Evaluate(appTargets("libreoffice", "libreoffice", "7.6.4.1", ""), nil)
	if !ev.Matched || !ev.Vulnerable {
		t.Fatalf("7.6.4.1 should be inside [7.6.0, 7.6.5): %+v", ev)
	}
	// e.g. OpenSSL-style 1.1.1v vs 1.1.1w letter suffixes (generic comparator
	// treats trailing letters ordinally).
	n2 := Node{Operator: "OR", Matches: []Match{{
		Criteria:   "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
		Vulnerable: true,
		Range:      Range{StartIncluding: "1.1.1", EndExcluding: "1.1.1w"},
	}}}
	ev2 := n2.Evaluate(appTargets("openssl", "openssl", "1.1.1v", ""), nil)
	if !ev2.Matched {
		t.Fatalf("1.1.1v must be inside [1.1.1, 1.1.1w): %+v", ev2)
	}
	ev3 := n2.Evaluate(appTargets("openssl", "openssl", "1.1.1w", ""), nil)
	if ev3.Matched {
		t.Fatalf("1.1.1w must be outside [1.1.1, 1.1.1w): %+v", ev3)
	}
}

func TestNewTargetArchMapping(t *testing.T) {
	cases := map[string][2]string{
		"x64":   {"x64", "x64"},
		"amd64": {"x64", "x64"},
		"x86":   {"x86", "x86"},
		"arm64": {"arm64", "arm64"},
	}
	for arch, want := range cases {
		c := NewTarget("v", "p", "1.0", "", "", arch)
		if c.TargetSW != want[0] || c.TargetHW != want[1] {
			t.Errorf("arch %s -> (%s,%s), want (%s,%s)", arch, c.TargetSW, c.TargetHW, want[0], want[1])
		}
	}
}

func TestWildcardMatchEdges(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"*", "", true},
		{"*", "anything", true},
		{"foo*", "foobar", true},
		{"foo*", "barfoo", false},
		{"*bar", "foobar", true},
		{"f?o", "foo", true},
		{"f?o", "fo", false},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "aXbY", false},
	}
	for _, tc := range cases {
		if got := wildcardMatch(tc.pattern, tc.value); got != tc.want {
			t.Errorf("wildcardMatch(%q,%q) = %v, want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
}

func TestComponentMatches(t *testing.T) {
	if !ComponentMatches("*", "anything") {
		t.Fatal("ANY must match everything")
	}
	if !ComponentMatches("", "x") {
		t.Fatal("empty pattern must be treated as ANY")
	}
	if !ComponentMatches("Chrome", "CHROME") {
		t.Fatal("component match must be case-insensitive")
	}
	if got := escape("a:b c"); got != `a\:b\ c` {
		t.Fatalf("escape(a:b c) = %q", got)
	}
}
