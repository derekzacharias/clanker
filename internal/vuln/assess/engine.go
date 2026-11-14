package assess

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// Engine correlates an inventory against advisory data.
type Engine struct {
	Store  *intel.Store
	OSV    *intel.OSVClient
	Online bool
	// Vendor is the distribution vendor used in remediation text (Ubuntu,
	// Debian, Red Hat...). Empty when unknown.
	Vendor string
	// Host is the asset identifier recorded on every finding.
	Host string
	// AssetCriticality scales risk (0..1). Enterprise callers set this per
	// asset; the endpoint agent leaves it at the default.
	AssetCriticality float64
	// Exposed marks an asset reachable from untrusted networks (network scans).
	Exposed bool
	// IncludeNotAffected keeps checked-and-not-affected records in the report
	// for false-positive review. Default false to keep reports readable.
	IncludeNotAffected bool
	// Concurrency bounds advisory detail fetches.
	Concurrency int
	// Now is injectable for deterministic tests.
	Now func() time.Time
	// Weights tunes the risk model.
	Weights RiskWeights
	// Policy holds the detection decisions in force. The zero value means the
	// shipped defaults; see assess.ParsePolicy for rule-provided policies.
	Policy Policy
	// Progress reports pipeline stages to a caller (CLI/HTTP). It is optional and
	// must be cheap: it is called from the scan goroutine.
	Progress func(stage, detail string)

	feedErrors []string
	stats      Stats
}

// Stats records what the assessment actually did.
type Stats struct {
	PackagesConsidered int
	PackagesMatched    int
	AdvisoriesFetched  int
	AdvisoriesCached   int
	Findings           int
	Suppressed         int
	// UpstreamDisagreements counts advisories that OSV's own matching flagged
	// for this version while authoritative version data said not affected.
	UpstreamDisagreements int
	UncoveredEcosystems   map[string]int
	Errors                []string
}

// Result is the engine output.
type Result struct {
	Findings []model.Finding
	Stats    Stats
}

// policy returns the effective detection policy. A zero policy (empty outcome
// strings and no trusted vendors) means "shipped defaults".
func (e *Engine) policy() Policy {
	p := e.Policy
	if p.BackportOutcome == "" && p.UnlistedBuildOutcome == "" && p.ForeignBuildOutcome == "" && len(p.TrustedVendors) == 0 {
		return DefaultPolicy()
	}
	return p
}

// PolicyNotes exposes the non-default detection decisions for reporting.
func (e *Engine) PolicyNotes() []string { return e.policy().Notes() }

func (e *Engine) progress(stage, detail string) {
	if e.Progress != nil {
		e.Progress(stage, detail)
	}
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now().UTC()
}

// SupportsOSV reports whether an ecosystem can be correlated against OSV.
func SupportsOSV(ecosystem string) bool {
	l := strings.ToLower(ecosystem)
	switch {
	case l == "", l == "unknown", l == "windows", l == "homebrew":
		return false
	}
	return true
}

// Assess runs correlation + enrichment for a whole inventory.
func (e *Engine) Assess(ctx context.Context, inv model.Inventory) (Result, error) {
	res := Result{}
	e.stats = Stats{UncoveredEcosystems: map[string]int{}}
	if e.Concurrency <= 0 {
		e.Concurrency = 8
	}
	if e.OSV == nil {
		e.OSV = intel.NewOSVClient()
	}

	candidates := make([]model.Package, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		if !SupportsOSV(p.Ecosystem) {
			e.stats.UncoveredEcosystems[p.Ecosystem]++
			continue
		}
		if err := versionValidate(p); err != nil {
			e.stats.Errors = append(e.stats.Errors, fmt.Sprintf("%s %s: %v", p.Name, p.Version, err))
			continue
		}
		candidates = append(candidates, p)
	}
	e.stats.PackagesConsidered = len(candidates)
	e.progress("inventory", fmt.Sprintf("%d packages to correlate", len(candidates)))

	// 1) candidate discovery + detail retrieval
	advisoriesByPackage := map[string][]intel.Advisory{}
	osvMatched := map[string]map[string]bool{}
	if e.Online {
		fetched, matched, err := e.fetchOnline(ctx, candidates)
		if err != nil {
			e.stats.Errors = append(e.stats.Errors, "OSV query failed: "+err.Error())
		}
		advisoriesByPackage = fetched
		osvMatched = matched
	}

	// 2) cached advisory fallback (also the entire offline path)
	if e.Store != nil {
		for _, p := range candidates {
			key := pkgKey(p)
			cached, err := e.Store.AdvisoriesFor(ctx, p.Ecosystem, p.Name)
			if err != nil {
				e.stats.Errors = append(e.stats.Errors, "cache read failed: "+err.Error())
				continue
			}
			advisoriesByPackage[key] = mergeAdvisories(advisoriesByPackage[key], cached)
			if len(cached) > 0 {
				e.stats.AdvisoriesCached += len(cached)
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("assessment cancelled: %w", err)
	}
	e.progress("intelligence", fmt.Sprintf("%d advisories fetched, %d from cache", e.stats.AdvisoriesFetched, e.stats.AdvisoriesCached))

	// 3) match
	var findings []model.Finding
	for _, p := range candidates {
		advs := advisoriesByPackage[pkgKey(p)]
		if len(advs) == 0 {
			continue
		}
		matchedAny := false
		for _, adv := range advs {
			out, ok := Classify(p, adv, e.policy())
			if !ok {
				continue
			}
			matchedAny = true
			// OSV's Ubuntu records publish open-ended ranges (introduced 0, no
			// fixed), so its own matching flags every version. When the vendor
			// enumeration contradicts that, keep the vendor verdict but record
			// the disagreement instead of hiding it.
			if out.Applicability == model.ApplicabilityNotAffected && osvMatched[pkgKey(p)][adv.ID] {
				e.stats.UpstreamDisagreements++
				out.Evidence = append(out.Evidence, model.Evidence{
					Kind:   "upstream_matching_over_inclusive",
					Source: "OSV",
					Detail: "OSV's own query matched this installed version, but the advisory's version data shows it is fixed; the vendor verdict is used",
				})
			}
			if out.Applicability == model.ApplicabilityNotAffected && !e.IncludeNotAffected {
				e.stats.Suppressed++
				continue
			}
			findings = append(findings, e.findingFor(p, adv, out))
		}
		if matchedAny {
			e.stats.PackagesMatched++
		}
	}

	e.progress("matching", fmt.Sprintf("%d matched records", len(findings)))

	// 4) collapse advisories that describe the same vulnerability
	findings = dedupeFindings(findings)

	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("assessment cancelled: %w", err)
	}

	// 5) enrich with KEV / EPSS and score risk
	for i := range findings {
		e.enrich(ctx, &findings[i])
		e.score(&findings[i])
	}
	e.progress("enrichment", fmt.Sprintf("%d findings scored", len(findings)))
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].RiskScore != findings[j].RiskScore {
			return findings[i].RiskScore > findings[j].RiskScore
		}
		return findings[i].VulnerabilityID < findings[j].VulnerabilityID
	})
	for i := range findings {
		findings[i].FindingID = fmt.Sprintf("FINDING-%04d", i+1)
		findings[i].StableID = model.FindingStableID(e.Host, findings[i])
	}

	res.Findings = findings
	e.stats.Findings = len(findings)
	res.Stats = e.stats
	return res, nil
}

func versionValidate(p model.Package) error {
	if strings.TrimSpace(p.Version) == "" {
		return fmt.Errorf("empty installed version")
	}
	return nil
}

func pkgKey(p model.Package) string {
	return strings.ToLower(p.Ecosystem) + "\x00" + strings.ToLower(p.Name) + "\x00" + p.Version
}

// fetchOnline queries OSV for every candidate and fetches advisory details.
//
// querybatch is treated as candidate discovery only: the authoritative verdict
// still comes from Match(), so a difference between OSV's own matching and ours
// surfaces as an explicit needs_investigation rather than a silent pass.
func (e *Engine) fetchOnline(ctx context.Context, pkgs []model.Package) (map[string][]intel.Advisory, map[string]map[string]bool, error) {
	queries := make([]intel.Query, 0, len(pkgs))
	for _, p := range pkgs {
		queries = append(queries, intel.Query{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version})
	}
	refs, err := e.OSV.QueryBatch(ctx, queries)
	if err != nil && len(refs) == 0 {
		return nil, nil, err
	}

	// collect unique advisory IDs
	idSet := map[string]struct{}{}
	for _, list := range refs {
		for _, r := range list {
			idSet[r.ID] = struct{}{}
		}
	}
	ids := make([]string, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	details := make(map[string]intel.Advisory, len(ids))
	var mu sync.Mutex
	sem := make(chan struct{}, e.Concurrency)
	var wg sync.WaitGroup
	var firstErr error

	for _, id := range ids {
		// cache hit: skip the network call unless a newer revision exists
		if e.Store != nil {
			if cached, ok, err := e.Store.AdvisoryByID(ctx, id); err == nil && ok {
				mu.Lock()
				details[id] = cached
				mu.Unlock()
				continue
			}
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			adv, err := e.OSV.FetchVuln(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("%s: %w", id, err)
				}
				return
			}
			details[id] = adv
		}(id)
	}
	wg.Wait()

	if e.Store != nil && len(details) > 0 {
		toSave := make([]intel.Advisory, 0, len(details))
		for _, a := range details {
			toSave = append(toSave, a)
		}
		if err := e.Store.SaveAdvisories(ctx, toSave); err != nil {
			e.stats.Errors = append(e.stats.Errors, "cache write failed: "+err.Error())
		}
	}
	e.stats.AdvisoriesFetched = len(details)

	out := map[string][]intel.Advisory{}
	matched := map[string]map[string]bool{}
	for i, p := range pkgs {
		if i >= len(refs) {
			break
		}
		for _, ref := range refs[i] {
			if _, ok := matched[pkgKey(p)]; !ok {
				matched[pkgKey(p)] = map[string]bool{}
			}
			matched[pkgKey(p)][ref.ID] = true
			if adv, ok := details[ref.ID]; ok {
				out[pkgKey(p)] = append(out[pkgKey(p)], adv)
			}
		}
	}
	return out, matched, firstErr
}

func mergeAdvisories(a, b []intel.Advisory) []intel.Advisory {
	seen := map[string]bool{}
	for _, x := range a {
		seen[x.Source+"\x00"+x.ID] = true
	}
	for _, x := range b {
		if seen[x.Source+"\x00"+x.ID] {
			continue
		}
		seen[x.Source+"\x00"+x.ID] = true
		a = append(a, x)
	}
	return a
}

// findingFor converts a match outcome into a reportable finding, applying the
// vendor backport rule for upstream-only advisories.
func (e *Engine) findingFor(p model.Package, adv intel.Advisory, out Outcome) model.Finding {
	severity, cvss, vector, sevSource := intel.InterpretSeverities(adv.Severities)
	f := model.Finding{
		Asset:            e.Host,
		Product:          p.Name,
		InstalledVersion: p.Version,
		Ecosystem:        p.Ecosystem,
		VulnerabilityID:  primaryVulnID(adv),
		Aliases:          mergeStrings(adv.CVEIDs(), adv.Aliases),
		Source:           adv.Source,
		Affected:         out.Applicability,
		ValidationStatus: model.ValidationVersion,
		Confidence:       out.Confidence,
		Severity:         severity,
		Evidence:         out.Evidence,
		VendorAdvisory:   out.VendorAdvisory,
		FixedVersion:     out.FixedVersion,
		Explanation:      out.Explanation,
		RaiseConfidence:  out.Raise,
		LowerConfidence:  out.Lower,
		AdvisoryID:       adv.ID,
		PackageRef:       p.Name + "@" + p.Version,
	}
	if cvss != nil {
		f.CVSS = &model.CVSS{Vector: cvss.Vector, Score: cvss.Score, Source: cvss.Source}
		if sevSource != "" && f.CVSS.Source == "" {
			f.CVSS.Source = sevSource
		}
	} else if vector != "" {
		f.CVSS = &model.CVSS{Vector: vector, Source: sevSource}
	}
	checked := adv.FetchedAt
	if checked.IsZero() {
		checked = e.now()
	}
	f.LastChecked = &checked

	// Vendor backport downgrades are applied by Classify (see
	// applyBackportPolicy) so evaluation and production share one decision path.

	f.Remediation = remediationFor(f, adv, out)
	return f
}

// looksDistroVersion detects a distribution revision suffix (1.2.3-4ubuntu1).
func looksDistroVersion(v string) bool {
	i := strings.LastIndexByte(v, '-')
	if i < 0 || i == len(v)-1 {
		return false
	}
	rev := v[i+1:]
	return strings.ContainsAny(rev, "0123456789")
}

func distroRevision(v string) string {
	if i := strings.LastIndexByte(v, '-'); i >= 0 && i < len(v)-1 {
		return v[i+1:]
	}
	return "package"
}

func primaryVulnID(adv intel.Advisory) string {
	cves := adv.CVEIDs()
	if len(cves) > 0 {
		return cves[0]
	}
	return adv.ID
}

func remediationFor(f model.Finding, adv intel.Advisory, out Outcome) string {
	vendor := ""
	if f.VendorAdvisory != nil {
		vendor = f.VendorAdvisory.Vendor
	}
	switch f.Affected {
	case model.ApplicabilityNotAffected:
		return "No action required: authoritative data indicates the installed build is not affected."
	case model.ApplicabilityNeedsInvestigation:
		return "Determine applicability manually: compare the installed build with the vendor advisory and record the result before treating this as exploitable."
	}
	if f.FixedVersion != "" {
		if vendor != "" {
			return fmt.Sprintf("Upgrade %s to %s or later using %s packages, then rescan.", f.Product, f.FixedVersion, vendor)
		}
		return fmt.Sprintf("Upgrade %s to %s or later, then rescan.", f.Product, f.FixedVersion)
	}
	if out.DistroAdvisory {
		return fmt.Sprintf("Apply the %s security update for %s (no fixed version published in the advisory), then rescan.", vendorOr(adv), f.Product)
	}
	return "Review the referenced advisory for vendor guidance; no fixed version is published in the available data."
}

func vendorOr(adv intel.Advisory) string {
	if adv.Source != "" {
		return adv.Source
	}
	return "vendor"
}

// dedupeFindings collapses multiple advisories describing the same CVE for the
// same package, unioning their evidence.
func dedupeFindings(in []model.Finding) []model.Finding {
	groups := map[string]int{}
	var out []model.Finding
	for _, f := range in {
		key := strings.ToLower(f.Ecosystem) + "\x00" + strings.ToLower(f.Product) + "\x00" + f.InstalledVersion + "\x00" + primaryFindingKey(f)
		idx, ok := groups[key]
		if !ok {
			groups[key] = len(out)
			out = append(out, f)
			continue
		}
		merged := mergeFinding(out[idx], f)
		out[idx] = merged
	}
	return out
}

func primaryFindingKey(f model.Finding) string {
	for _, a := range f.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return strings.ToUpper(a)
		}
	}
	if strings.HasPrefix(f.VulnerabilityID, "CVE-") {
		return strings.ToUpper(f.VulnerabilityID)
	}
	return f.VulnerabilityID
}

func mergeFinding(a, b model.Finding) model.Finding {
	// Prefer the distro-backed verdict: it speaks the installed build's version
	// scheme and therefore beats upstream range matching.
	aDistro := a.VendorAdvisory != nil
	bDistro := b.VendorAdvisory != nil
	if bDistro && !aDistro {
		a, b = b, a
		aDistro = true
	}
	if outranks(b, a) && !aDistro {
		a, b = b, a
	}
	if a.FixedVersion == "" && b.FixedVersion != "" {
		a.FixedVersion = b.FixedVersion
	}
	if a.CVSS == nil && b.CVSS != nil {
		a.CVSS = b.CVSS
	} else if a.CVSS != nil && b.CVSS != nil && b.CVSS.Score > a.CVSS.Score {
		a.CVSS = b.CVSS
	}
	if a.Severity == model.SeverityUnknown && b.Severity != model.SeverityUnknown {
		a.Severity = b.Severity
	}
	seen := map[string]bool{}
	for _, e := range a.Evidence {
		seen[e.Kind+"\x00"+e.Detail] = true
	}
	for _, e := range b.Evidence {
		if seen[e.Kind+"\x00"+e.Detail] {
			continue
		}
		seen[e.Kind+"\x00"+e.Detail] = true
		a.Evidence = append(a.Evidence, e)
	}
	a.Aliases = mergeStrings(a.Aliases, b.Aliases, a.VulnerabilityID, b.VulnerabilityID)
	if a.VendorAdvisory == nil {
		a.VendorAdvisory = b.VendorAdvisory
	}
	a.Explanation = strings.TrimSpace(a.Explanation + " Also reported by " + b.Source + " (" + b.AdvisoryID + "): " + b.Explanation)
	return a
}

func outranks(a, b model.Finding) bool {
	rank := func(f model.Finding) int {
		switch f.Affected {
		case model.ApplicabilityConfirmed:
			return 5
		case model.ApplicabilityProbable:
			return 4
		case model.ApplicabilityPotential:
			return 3
		case model.ApplicabilityNeedsInvestigation:
			return 2
		case model.ApplicabilityNotAffected:
			return 1
		}
		return 0
	}
	return rank(a) > rank(b)
}

func mergeStrings(lists ...any) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range lists {
		switch v := item.(type) {
		case []string:
			for _, s := range v {
				if s == "" || seen[s] {
					continue
				}
				seen[s] = true
				out = append(out, s)
			}
		case string:
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
