package cpe

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/version"
)

// CompareFunc compares two versions for one ecosystem: -1, 0 or 1, or an error
// when either value cannot be parsed. Callers supply an ecosystem-aware
// comparator (internal/vuln/version); the CPE package itself never falls back
// to string comparison.
type CompareFunc func(a, b string) (int, error)

// defaultCmp is the generic tokenwise comparator (numeric runs compared
// numerically, e.g. 120.0.10 > 120.0.9). The assessment pipeline always
// supplies an ecosystem-aware comparator; this default exists so a nil
// comparator can never panic and never silently degrade to string comparison.
func defaultCmp() CompareFunc {
	return func(a, b string) (int, error) { return version.Compare("", a, b) }
}

// Targets holds the CPE identities a configuration can be evaluated against.
// NVD configuration trees mix parts: the vulnerable product is an application
// (part "a") while environment prerequisites name operating systems (part "o")
// or hardware (part "h"). A criteria only matches the target of its own part,
// so "vulnerable on Windows" never matches a Linux host.
//
// OS holds a list because NVD trees disagree about specificity: a Windows 11
// host must match both `cpe:2.3:o:microsoft:windows_11:*` and the generic
// `cpe:2.3:o:microsoft:windows:*`. The list is tried in order; the first
// matching identity decides.
type Targets struct {
	App      CPE   // part "a": the installed application
	OS       []CPE // part "o": operating-system identities, specific first
	Hardware CPE   // part "h": the hardware platform
}

// For selects the target for a criteria part. A missing target fails closed:
// prerequisites that cannot be identified are not assumed present.
func (t Targets) For(part string) (CPE, bool) {
	switch part {
	case PartApplication:
		return t.App, t.App.Part == PartApplication || t.App.Part == ""
	case PartOS:
		for _, os := range t.OS {
			if os.Part == PartOS {
				return os, true
			}
		}
		return CPE{}, false
	case PartHardware:
		return t.Hardware, t.Hardware.Part == PartHardware
	}
	return CPE{}, false
}

// AppVersion is the installed application version under evaluation.
func (t Targets) AppVersion() string { return t.App.Version }

// Range is one NVD version range: the four bound fields of a cpeMatch entry
// (versionStartIncluding, versionStartExcluding, versionEndIncluding,
// versionEndExcluding). At most one start and one end bound may be set.
type Range struct {
	StartIncluding string `json:"versionStartIncluding,omitempty"`
	StartExcluding string `json:"versionStartExcluding,omitempty"`
	EndIncluding   string `json:"versionEndIncluding,omitempty"`
	EndExcluding   string `json:"versionEndExcluding,omitempty"`
}

// Empty reports whether no bound is set.
func (r Range) Empty() bool {
	return r.StartIncluding == "" && r.StartExcluding == "" && r.EndIncluding == "" && r.EndExcluding == ""
}

// Validate rejects ranges with contradictory or double bounds: evaluating an
// ambiguous range is a correlation error, not a match.
func (r Range) Validate() error {
	startSet, endSet := 0, 0
	if r.StartIncluding != "" {
		startSet++
	}
	if r.StartExcluding != "" {
		startSet++
	}
	if r.EndIncluding != "" {
		endSet++
	}
	if r.EndExcluding != "" {
		endSet++
	}
	if startSet > 1 || endSet > 1 {
		return fmt.Errorf("invalid version range: both including and excluding bounds set for the same end (%s)", r.Describe())
	}
	return nil
}

// Contains reports whether version falls inside the range. Bounds are evaluated
// inclusively or exclusively per the bound kind, using the supplied comparator.
// A comparison failure (unparsable version) is an error, never a silent miss.
func (r Range) Contains(version string, cmp CompareFunc) (bool, error) {
	if err := r.Validate(); err != nil {
		return false, err
	}
	if r.Empty() {
		return true, nil
	}
	if cmp == nil {
		cmp = defaultCmp()
	}
	if r.StartIncluding != "" {
		c, err := cmp(version, r.StartIncluding)
		if err != nil {
			return false, fmt.Errorf("compare %q with start bound %q: %w", version, r.StartIncluding, err)
		}
		if c < 0 {
			return false, nil
		}
	}
	if r.StartExcluding != "" {
		c, err := cmp(version, r.StartExcluding)
		if err != nil {
			return false, fmt.Errorf("compare %q with start bound %q: %w", version, r.StartExcluding, err)
		}
		if c <= 0 {
			return false, nil
		}
	}
	if r.EndIncluding != "" {
		c, err := cmp(version, r.EndIncluding)
		if err != nil {
			return false, fmt.Errorf("compare %q with end bound %q: %w", version, r.EndIncluding, err)
		}
		if c > 0 {
			return false, nil
		}
	}
	if r.EndExcluding != "" {
		c, err := cmp(version, r.EndExcluding)
		if err != nil {
			return false, fmt.Errorf("compare %q with end bound %q: %w", version, r.EndExcluding, err)
		}
		if c >= 0 {
			return false, nil
		}
	}
	return true, nil
}

// Describe renders the range for humans and evidence strings, e.g.
// "[1.0.0, 2.0.0)" using mathematical interval notation.
func (r Range) Describe() string {
	var lo, hi string
	switch {
	case r.StartIncluding != "":
		lo = "[" + r.StartIncluding
	case r.StartExcluding != "":
		lo = "(" + r.StartExcluding
	}
	switch {
	case r.EndIncluding != "":
		hi = r.EndIncluding + "]"
	case r.EndExcluding != "":
		hi = r.EndExcluding + ")"
	}
	switch {
	case lo != "" && hi != "":
		return lo + ", " + hi
	case lo != "":
		bound := strings.TrimLeft(lo, "[(")
		if strings.HasPrefix(lo, "(") {
			return "> " + bound
		}
		return ">= " + bound
	case hi != "":
		bound := strings.TrimRight(hi, "])")
		if strings.HasSuffix(hi, ")") {
			return "< " + bound
		}
		return "<= " + bound
	}
	return "any"
}

// Match is one cpeMatch entry from an NVD configuration node.
type Match struct {
	Criteria        string `json:"criteria"`
	MatchCriteriaID string `json:"matchCriteriaId"`
	Range
	Vulnerable bool `json:"vulnerable"`
}

// ParsedCriteria returns the criteria's CPE binding, parsed once.
func (m Match) ParsedCriteria() (CPE, error) { return Parse(m.Criteria) }

// Node is one NVD configuration node. Leaf nodes carry cpeMatch entries;
// non-leaf nodes carry children combined with the node operator. Negate
// inverts the result of the whole node.
type Node struct {
	Operator string  `json:"operator,omitempty"` // "AND" | "OR"; empty = leaf
	Negate   bool    `json:"negate"`
	Children []Node  `json:"nodes,omitempty"` // NVD names this field "nodes"
	Matches  []Match `json:"cpeMatch,omitempty"`
}

// Evaluation is the outcome of evaluating a configuration tree against one
// installed-software target.
type Evaluation struct {
	// Matched is true when the boolean expression of the node evaluated true.
	Matched bool
	// Vulnerable is true when the satisfied expression involves at least one
	// cpeMatch with vulnerable=true. A node satisfied only through
	// vulnerable=false entries means "this target matches the configuration
	// but the CVE does not apply" (typically the fixed-version entry).
	Vulnerable bool
	// MatchedCriteria lists the criteria strings that matched (including
	// their version constraints), for evidence.
	MatchedCriteria []string
	// Details lists the decisions taken, for evidence and debugging.
	Details []string
}

// Evaluate evaluates one node against the targets.
func (n Node) Evaluate(targets Targets, cmp CompareFunc) Evaluation {
	if cmp == nil {
		cmp = defaultCmp()
	}
	ev := n.evaluate(targets, cmp)
	if n.Negate {
		ev.Matched = !ev.Matched
		// Negation inverts only the match: NVD never publishes negated
		// vulnerable=true entries, so negated nodes are environment
		// constraints, and vulnerability is decided by the matched path.
		if !ev.Matched {
			ev.Vulnerable = false
			ev.MatchedCriteria = nil
		}
		ev.Details = append(ev.Details, fmt.Sprintf("node negated (result inverted: matched=%v)", ev.Matched))
	}
	return ev
}

func (n Node) evaluate(targets Targets, cmp CompareFunc) Evaluation {
	op := strings.ToUpper(strings.TrimSpace(n.Operator))
	if len(n.Children) > 0 {
		// Internal node: combine children with the operator. An empty
		// operator on an internal node is malformed feed data; treat it as
		// OR so a single positive child still surfaces the CVE, and record
		// the anomaly.
		if op != "AND" && op != "OR" {
			if op != "" {
				return Evaluation{Matched: false, Details: []string{fmt.Sprintf("unknown operator %q ignored", n.Operator)}}
			}
			op = "OR"
		}
		var evs []Evaluation
		for _, c := range n.Children {
			evs = append(evs, c.evaluate(targets, cmp))
		}
		return combine(op, evs)
	}
	// Leaf node: combine its cpeMatch entries.
	matches := n.Matches
	if len(matches) > 0 {
		matches = preferEditionMatches(matches, targets)
	}
	var evs []Evaluation
	for _, m := range matches {
		evs = append(evs, evaluateMatch(m, targets, cmp))
	}
	if len(evs) == 0 {
		return Evaluation{Details: []string{"leaf node with no cpeMatch entries"}}
	}
	return combine(op, evs)
}

// preferEditionMatches resolves edition-specific criteria against generic
// ones. NVD models extended-support releases with a sw_edition on the
// criteria (e.g. mozilla:firefox sw_edition="esr" with its own version
// range) while the generic entry keeps sw_edition "*". A target that IS an
// ESR build must be evaluated against the ESR range only: the generic range
// says "Firefox < 123.0 is affected", which would flag a fixed ESR 115.8
// build as vulnerable. When the installed build carries an edition and the
// node has edition-specific criteria for its product, the generic entries
// for that product are shadowed.
func preferEditionMatches(matches []Match, targets Targets) []Match {
	app := targets.App
	if isAny(app.SwEdition) || isAny(app.Vendor) || isAny(app.Product) {
		return matches
	}
	editionSpecific := false
	for _, m := range matches {
		crit, err := m.ParsedCriteria()
		if err != nil || !namesProduct(crit, app) {
			continue
		}
		if strings.EqualFold(crit.SwEdition, app.SwEdition) {
			editionSpecific = true
		}
	}
	if !editionSpecific {
		return matches
	}
	out := make([]Match, 0, len(matches))
	for _, m := range matches {
		crit, err := m.ParsedCriteria()
		if err == nil && namesProduct(crit, app) && (isAny(crit.SwEdition) || crit.SwEdition == NA) {
			// Generic entry for this product: shadowed by the
			// edition-specific one.
			continue
		}
		out = append(out, m)
	}
	return out
}

// namesProduct reports whether the criteria concretely names the same
// application identity as the target (wildcards do not name anything).
func namesProduct(crit, target CPE) bool {
	return crit.Part == PartApplication &&
		!isAny(crit.Vendor) && !isAny(crit.Product) &&
		ComponentMatches(crit.Vendor, target.Vendor) &&
		ComponentMatches(crit.Product, target.Product)
}

// evaluateMatch decides whether one cpeMatch entry covers the target of the
// criteria's part. Part "o" criteria try every OS identity.
func evaluateMatch(m Match, targets Targets, cmp CompareFunc) Evaluation {
	crit, err := m.ParsedCriteria()
	if err != nil {
		return Evaluation{Matched: false, Details: []string{fmt.Sprintf("unparsable criteria %q: %v", m.Criteria, err)}}
	}
	target, ok := targets.For(crit.Part)
	if !ok {
		return Evaluation{Matched: false, Details: []string{
			fmt.Sprintf("criteria %s needs part %q but no such target identity is known", crit.String(), crit.Part),
		}}
	}
	if crit.Part == PartOS {
		var last *Evaluation
		for _, os := range targets.OS {
			if os.Part != PartOS {
				continue
			}
			ev := evaluateCriteriaAgainst(m, crit, os, cmp)
			last = &ev
			if ev.Matched {
				return ev
			}
		}
		if last != nil {
			return *last
		}
		return Evaluation{Matched: false, Details: []string{"no operating-system identity is known"}}
	}
	return evaluateCriteriaAgainst(m, crit, target, cmp)
}

// evaluateCriteriaAgainst checks one criteria against one concrete target.
func evaluateCriteriaAgainst(m Match, crit, target CPE, cmp CompareFunc) Evaluation {
	// Identity: every non-version attribute must match.
	if !crit.Matches(target) {
		return Evaluation{Matched: false, Details: []string{
			fmt.Sprintf("criteria %s does not match target %s", crit.String(), target.String()),
		}}
	}
	// Version: an exact criteria version must equal the installed version; a
	// wildcard version is constrained by any published range. Without a known
	// installed version, a version-dependent match cannot be confirmed.
	installed := target.Version
	if installed == "" {
		return Evaluation{Matched: false, Details: []string{
			"installed version unknown; version-dependent match not evaluated",
		}}
	}
	if !isAny(crit.Version) && !ComponentMatches(crit.Version, installed) {
		return Evaluation{Matched: false, Details: []string{
			fmt.Sprintf("criteria version %q != installed %q", crit.Version, installed),
		}}
	}
	if !m.Range.Empty() {
		inside, err := m.Range.Contains(installed, cmp)
		if err != nil {
			return Evaluation{Matched: false, Details: []string{
				fmt.Sprintf("range %s not evaluated for %q: %v", m.Range.Describe(), installed, err),
			}}
		}
		if !inside {
			return Evaluation{Matched: false, Details: []string{
				fmt.Sprintf("installed version %q outside range %s", installed, m.Range.Describe()),
			}}
		}
	}
	vuln := "fixed/not-vulnerable"
	if m.Vulnerable {
		vuln = "vulnerable"
	}
	return Evaluation{Matched: true, Vulnerable: m.Vulnerable, MatchedCriteria: []string{m.Criteria}, Details: []string{
		fmt.Sprintf("criteria %s (%s) matches installed %s %s", crit.String(), vuln, target.Product, installed),
	}}
}

// combine folds child evaluations under an AND/OR operator.
func combine(op string, evs []Evaluation) Evaluation {
	out := Evaluation{}
	switch op {
	case "AND":
		out.Matched = true
		vulnSeen := false
		var matched []string
		for _, e := range evs {
			out.Matched = out.Matched && e.Matched
			vulnSeen = vulnSeen || e.Vulnerable
			matched = append(matched, e.MatchedCriteria...)
			out.Details = append(out.Details, e.Details...)
		}
		// AND: vulnerable only when every requirement matched and the
		// conjunction includes a vulnerable=true entry.
		out.Vulnerable = out.Matched && vulnSeen
		if out.Matched {
			out.MatchedCriteria = matched
		}
	case "OR":
		for _, e := range evs {
			out.Matched = out.Matched || e.Matched
			if e.Matched && e.Vulnerable {
				out.Vulnerable = true
			}
			if e.Matched {
				out.MatchedCriteria = append(out.MatchedCriteria, e.MatchedCriteria...)
			}
			out.Details = append(out.Details, e.Details...)
		}
	}
	return out
}

// TreeResult is the evaluation of a whole NVD configurations array.
type TreeResult struct {
	// Vulnerable: at least one configuration node matched with a
	// vulnerable=true path.
	Vulnerable bool
	// MatchedNotVulnerable: a node matched but only through vulnerable=false
	// entries (e.g. the fixed version).
	MatchedNotVulnerable bool
	// FixedVersions collects versions from vulnerable=false criteria that
	// matched (candidate fix versions from NVD data).
	FixedVersions []string
	// MatchedCPEs are the criteria that matched, for evidence.
	MatchedCPEs []string
	// Details records the evaluation walk.
	Details []string
}

// EvaluateConfigs evaluates a full NVD configurations array against the
// targets. A CVE is vulnerable when any node evaluates true with a
// vulnerable=true path. Nodes that match only through vulnerable=false
// entries record the fixed version instead.
func EvaluateConfigs(nodes []Node, targets Targets, cmp CompareFunc) TreeResult {
	var res TreeResult
	for _, n := range nodes {
		ev := n.Evaluate(targets, cmp)
		res.Details = append(res.Details, ev.Details...)
		if !ev.Matched {
			continue
		}
		collectMatchedCriteria(&n, targets, cmp, &res)
		if ev.Vulnerable {
			res.Vulnerable = true
		} else {
			res.MatchedNotVulnerable = true
			collectFixed(&n, targets, &res)
		}
	}
	sort.Strings(res.FixedVersions)
	res.FixedVersions = uniqueSorted(res.FixedVersions)
	res.MatchedCPEs = uniqueSorted(res.MatchedCPEs)
	return res
}

// collectMatchedCriteria records the criteria whose full match (including
// version constraints) contributed to a matched node, so evidence shows
// exactly which CPE binding decided the result.
func collectMatchedCriteria(n *Node, targets Targets, cmp CompareFunc, res *TreeResult) {
	if len(n.Children) > 0 {
		for i := range n.Children {
			collectMatchedCriteria(&n.Children[i], targets, cmp, res)
		}
		return
	}
	for _, m := range n.Matches {
		if evaluateMatch(m, targets, cmp).Matched {
			res.MatchedCPEs = append(res.MatchedCPEs, m.Criteria)
		}
	}
}

func collectFixed(n *Node, targets Targets, res *TreeResult) {
	if len(n.Children) > 0 {
		for i := range n.Children {
			collectFixed(&n.Children[i], targets, res)
		}
		return
	}
	for _, m := range n.Matches {
		if m.Vulnerable {
			continue
		}
		crit, err := m.ParsedCriteria()
		if err != nil {
			continue
		}
		matched := false
		if crit.Part == PartOS {
			for _, os := range targets.OS {
				if os.Part == PartOS && crit.Matches(os) {
					matched = true
					break
				}
			}
		} else if target, ok := targets.For(crit.Part); ok && crit.Matches(target) {
			matched = true
		}
		if !matched {
			continue
		}
		res.MatchedCPEs = append(res.MatchedCPEs, m.Criteria)
		if !isAny(crit.Version) {
			res.FixedVersions = append(res.FixedVersions, crit.Version)
		}
		if !m.Range.Empty() && m.Range.StartIncluding != "" {
			res.FixedVersions = append(res.FixedVersions, m.Range.StartIncluding)
		}
	}
}

func uniqueSorted(in []string) []string {
	if len(in) < 2 {
		return in
	}
	sort.Strings(in)
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
