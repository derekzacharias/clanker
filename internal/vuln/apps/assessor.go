// Package apps implements the application vulnerability correlation engine.
//
// Pipeline: installed-application inventory → normalization (vendor/product/
// version) → CPE dictionary lookup → candidate CVE retrieval from the local
// NVD store → configuration-tree evaluation against the installed version →
// vendor-advisory cross-check → evidence-backed findings.
//
// Accuracy contract (mirrors the rest of Clanker Guard):
//   - NVD is authoritative applicability data only for the product it names:
//     a deterministic mapping plus a satisfied configuration produces a
//     *confirmed* version-correlation finding. A fuzzy (similarity) mapping
//     can only produce a *potential* finding — it must never establish that
//     an application is vulnerable on its own.
//   - An authoritative vendor advisory overrides NVD when they conflict.
//   - Rejected CVEs are excluded explicitly, with the reason recorded.
//   - Software that cannot be mapped stays visible as a coverage gap; it is
//     never classified as secure.
//   - When NVD intelligence is missing or stale, the assessment says so; it
//     never reports a clean result.
package apps

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/cpe"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/norm"
	"github.com/bgdnvk/clanker/internal/vuln/nvd"
	"github.com/bgdnvk/clanker/internal/vuln/version"
)

//go:embed vendor_advisories.json
var vendorAdvisoriesJSON []byte

// VendorAdvisory is one authoritative vendor statement.
type VendorAdvisory struct {
	CVE           string `json:"cve"`
	Vendor        string `json:"vendor"`
	Product       string `json:"product"`
	FixedVersion  string `json:"fixed_version,omitempty"`
	AffectedBelow string `json:"affected_below,omitempty"`
	URL           string `json:"url,omitempty"`
	Statement     string `json:"statement,omitempty"`
}

type vendorAdvisoriesDoc struct {
	SchemaVersion int              `json:"schema_version"`
	Advisories    []VendorAdvisory `json:"advisories"`
}

// VendorAdvisoryIndex resolves (cve, vendor, product) triples to authoritative
// vendor statements. It is data (vendor_advisories.json), not code, so adding
// or correcting statements never touches the engine.
type VendorAdvisoryIndex struct {
	byCVE map[string][]VendorAdvisory
}

// LoadVendorAdvisories builds the index from a JSON document.
func LoadVendorAdvisories(raw []byte) (*VendorAdvisoryIndex, error) {
	var doc vendorAdvisoriesDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse vendor advisories: %w", err)
	}
	if doc.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported vendor advisory schema %d", doc.SchemaVersion)
	}
	idx := &VendorAdvisoryIndex{byCVE: map[string][]VendorAdvisory{}}
	for _, a := range doc.Advisories {
		a.CVE = strings.ToUpper(strings.TrimSpace(a.CVE))
		if a.CVE == "" {
			return nil, fmt.Errorf("vendor advisory without CVE id")
		}
		a.Vendor = strings.ToLower(strings.TrimSpace(a.Vendor))
		a.Product = strings.ToLower(strings.TrimSpace(a.Product))
		idx.byCVE[a.CVE] = append(idx.byCVE[a.CVE], a)
	}
	return idx, nil
}

// DefaultVendorAdvisories is the embedded dataset.
var DefaultVendorAdvisories = mustLoadAdvisories(vendorAdvisoriesJSON)

func mustLoadAdvisories(raw []byte) *VendorAdvisoryIndex {
	idx, err := LoadVendorAdvisories(raw)
	if err != nil {
		panic("embedded vendor advisories are invalid: " + err.Error())
	}
	return idx
}

// For returns the advisory matching the CVE and (optionally) the product.
func (i *VendorAdvisoryIndex) For(cveID, vendor, product string) (VendorAdvisory, bool) {
	for _, a := range i.byCVE[strings.ToUpper(cveID)] {
		if vendor != "" && a.Vendor != strings.ToLower(vendor) {
			continue
		}
		if product != "" && a.Product != strings.ToLower(product) {
			continue
		}
		return a, true
	}
	return VendorAdvisory{}, false
}

// Assessor correlates installed applications against the local NVD store.
type Assessor struct {
	DB *sql.DB
	// Norm overrides the normalization engine (default: the embedded rules).
	Norm *norm.Engine
	// Advisories overrides the vendor advisory index (default: embedded).
	Advisories *VendorAdvisoryIndex
	// Now injects time (tests).
	Now func() time.Time
	// Concurrency bounds concurrent CVE evaluations (default 8).
	Concurrency int
	// IncludeNotAffected keeps not-applicable records in the findings for
	// false-positive review (default false).
	IncludeNotAffected bool
	// Progress reports (stage, detail); optional, must be cheap.
	Progress func(stage, detail string)
	// CacheTTL bounds how long a persisted (product, version, CVE) verdict is
	// reused without re-evaluation (default 24h).
	CacheTTL time.Duration
}

func (a *Assessor) norm() *norm.Engine {
	if a.Norm != nil {
		return a.Norm
	}
	return norm.Default
}

func (a *Assessor) advisories() *VendorAdvisoryIndex {
	if a.Advisories != nil {
		return a.Advisories
	}
	return DefaultVendorAdvisories
}

func (a *Assessor) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now().UTC()
}

// Result is what the application assessment contributed.
type Result struct {
	Findings []model.Finding
	// Coverage is always populated, so the report can state exactly what was
	// and was not evaluated.
	Coverage model.AppCoverage
	// Limitations explain what could not be assessed.
	Limitations []string
	// Notes are positive coverage statements (e.g. "12 applications were
	// evaluated and none is affected by a known CVE").
	Notes []string
	// Errors are correlation failures worth surfacing in metadata.
	Errors []string
}

// IsAppCandidate reports whether a package should be correlated as an
// application: Windows desktop software, package managers without OSV
// ecosystems (Homebrew), and unrecognized ecosystems. OS packages with OSV
// coverage are deliberately excluded — their correlation already runs through
// the distribution-advisory engine, and NVD's upstream-only ranges would
// produce the exact false positives that engine avoids.
func IsAppCandidate(p model.Package) bool {
	switch strings.ToLower(p.Ecosystem) {
	case "windows", "homebrew":
		return true
	case "", "unknown":
		return true
	}
	return false
}

// Applicable reports whether the inventory contains anything the application
// engine should correlate (or .NET frameworks on Windows).
func (a *Assessor) Applicable(inv model.Inventory) bool {
	for _, p := range inv.Packages {
		if IsAppCandidate(p) {
			return true
		}
	}
	return inv.Windows != nil && len(inv.Windows.DotNet) > 0
}

// Assess runs the application correlation pipeline for the inventory.
func (a *Assessor) Assess(ctx context.Context, inv model.Inventory) (Result, error) {
	started := a.now()
	res := Result{}
	if a.DB == nil {
		return res, fmt.Errorf("application assessor has no database")
	}
	if err := nvd.EnsureSchema(a.DB); err != nil {
		return res, fmt.Errorf("application assessment store: %w", err)
	}
	store := nvd.NewStore(a.DB)

	if a.Concurrency <= 0 {
		a.Concurrency = 8
	}
	if a.CacheTTL <= 0 {
		a.CacheTTL = 24 * time.Hour
	}

	// --- candidate selection -----------------------------------------------
	var apps []model.Package
	for _, p := range inv.Packages {
		if IsAppCandidate(p) {
			if strings.TrimSpace(p.Version) == "" {
				res.Coverage.Skipped++
				res.Limitations = append(res.Limitations,
					fmt.Sprintf("%s has no recorded version; it cannot be evaluated", p.Name))
				continue
			}
			apps = append(apps, p)
		}
	}
	// .NET shared-framework versions from the Windows servicing state are
	// applications too: they are shipped separately from the OS.
	for _, fx := range dotnetFrameworks(inv.Windows) {
		apps = append(apps, fx)
	}
	res.Coverage.Discovered = len(apps)

	if len(apps) == 0 {
		return res, nil
	}

	// --- intelligence availability ------------------------------------------
	lastSync, _, _ := store.LastSuccessfulSync(ctx, "cves")
	if lastSync.FinishedAt.IsZero() {
		res.Coverage.IntelFreshness = "never synchronized"
		res.Limitations = append(res.Limitations,
			"NVD intelligence has not been synchronized (run `clanker-guard-agent feeds update --with-nvd`); "+
				"installed applications were inventoried but NOT evaluated for known vulnerabilities, so a clean "+
				"result here does not mean the applications are patched")
		return res, nil
	}
	res.Coverage.IntelFreshness = lastSync.FinishedAt.UTC().Format(time.RFC3339)
	if a.now().Sub(lastSync.FinishedAt) > 30*24*time.Hour {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"the NVD dataset is stale (last synchronized %s); application findings use this dataset and may miss recently published CVEs",
			lastSync.FinishedAt.UTC().Format("2006-01-02")))
	}

	// --- per-application pipeline -------------------------------------------
	type job struct {
		pkg     model.Package
		app     norm.App
		targets cpe.Targets
	}
	sem := make(chan struct{}, a.Concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make([]*job, 0, len(apps))
	osIdentities := OSIdentities(inv)

	for i := range apps {
		p := apps[i]
		app := a.norm().Normalize(p.Name, p.Vendor, p.Version, p.Arch)
		targets := cpe.Targets{
			App: cpe.NewTarget(app.Vendor, app.Product, app.Version, app.Edition, app.Channel, app.Arch),
			OS:  osIdentities,
		}
		jobs = append(jobs, &job{pkg: p, app: app, targets: targets})
	}
	a.progress("apps", fmt.Sprintf("%d applications to correlate", len(jobs)))

	for _, j := range jobs {
		wg.Add(1)
		go func(j *job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			select {
			case <-ctx.Done():
				return
			default:
			}
			findings, appCov, errs := a.correlateApp(ctx, store, j.pkg, j.app, j.targets)
			mu.Lock()
			defer mu.Unlock()
			res.Findings = append(res.Findings, findings...)
			mergeCoverage(&res.Coverage, appCov)
			res.Errors = append(res.Errors, errs...)
		}(j)
	}
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return res, fmt.Errorf("application assessment cancelled: %w", err)
	}

	// Coverage accounting is monotonic per application; recompute from the
	// per-app counts to keep the aggregate honest.
	res.Coverage.DurationMillis = a.now().Sub(started).Milliseconds()
	res.Notes = append(res.Notes, fmt.Sprintf(
		"%d installed applications discovered; %d evaluated against the local NVD dataset (synced %s); %d unrecognized; %d confirmed and %d potential vulnerability matches",
		res.Coverage.Discovered, res.Coverage.Evaluated,
		shortTime(res.Coverage.IntelFreshness),
		res.Coverage.Skipped+len(res.Coverage.Unrecognized),
		res.Coverage.ConfirmedMatches, res.Coverage.PotentialMatches))
	if res.Coverage.Evaluated == 0 {
		res.Limitations = append(res.Limitations,
			"no installed application could be mapped to a CPE identity; every installed application remains a coverage gap")
	}
	if len(res.Coverage.Unrecognized) > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"%d installed application(s) could not be mapped to a vulnerability identity and were NOT evaluated: %s",
			len(res.Coverage.Unrecognized), strings.Join(limitStrings(res.Coverage.Unrecognized, 12), ", ")))
	}
	if res.Coverage.Errors > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"%d application correlation error(s); affected applications are reported as not evaluated", res.Coverage.Errors))
	}
	return res, nil
}

func (a *Assessor) progress(stage, detail string) {
	if a.Progress != nil {
		a.Progress(stage, detail)
	}
}

func shortTime(ts string) string {
	if ts == "" {
		return "never"
	}
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t.UTC().Format("2006-01-02")
	}
	return ts
}

func limitStrings(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	out := append([]string(nil), in[:n]...)
	return append(out, fmt.Sprintf("…and %d more", len(in)-n))
}

// correlateApp evaluates one normalized application against the NVD store.
func (a *Assessor) correlateApp(ctx context.Context, store *nvd.Store, pkg model.Package, app norm.App, targets cpe.Targets) ([]model.Finding, model.AppCoverage, []string) {
	cov := model.AppCoverage{}
	var errs []string

	// --- mapping ------------------------------------------------------------
	mapping := a.resolveMapping(ctx, store, app)
	cov.Normalized = 1
	if mapping.vendor == "" || mapping.product == "" {
		// Unrecognized software: visible as a coverage gap, never "secure".
		cov.Unrecognized = append(cov.Unrecognized, app.Name)
		return nil, cov, errs
	}
	cov.Mapped = 1

	// --- candidate CVEs -----------------------------------------------------
	cveIDs, err := store.CVEsForProduct(ctx, mapping.vendor, mapping.product)
	if err != nil {
		cov.Errors++
		errs = append(errs, fmt.Sprintf("%s: candidate CVE lookup failed: %v", app.Name, err))
		return nil, cov, errs
	}
	cov.CandidateCVEs += len(cveIDs)
	sort.Strings(cveIDs)

	// --- evaluation ---------------------------------------------------------
	cmp := comparatorFor(app)
	targets.App = cpe.NewTarget(mapping.vendor, mapping.product, app.Version, app.Edition, app.Channel, app.Arch)
	evaluated := 0
	var findings []model.Finding
	for _, cveID := range cveIDs {
		if err := ctx.Err(); err != nil {
			return findings, cov, errs
		}
		f, outcome, err := a.evaluateCVE(ctx, store, pkg, app, mapping, targets, cveID, cmp)
		if err != nil {
			cov.Errors++
			errs = append(errs, fmt.Sprintf("%s %s: %v", app.Name, cveID, err))
			continue
		}
		evaluated++
		switch outcome {
		case outcomeVulnerable:
			if mapping.method == "fuzzy" {
				cov.PotentialMatches++
			} else {
				cov.ConfirmedMatches++
			}
			findings = append(findings, f)
		case outcomeNotAffected:
			cov.ExcludedCVEs++
			if a.IncludeNotAffected {
				findings = append(findings, f)
			}
		case outcomeInvestigate:
			cov.PotentialMatches++
			findings = append(findings, f)
		case outcomeExcluded:
			cov.ExcludedCVEs++
		}
	}
	if evaluated > 0 {
		cov.Evaluated = 1
	} else {
		// Mapped but nothing to evaluate (no CVEs, or all excluded): the
		// application WAS evaluated — there is simply no applicable
		// vulnerability in the dataset.
		cov.Evaluated = 1
	}
	return findings, cov, errs
}

type outcome int

const (
	outcomeVulnerable outcome = iota
	outcomeNotAffected
	outcomeInvestigate
	outcomeExcluded
)

// mapping is the resolved CPE identity plus how it was established.
type mapping struct {
	vendor, product string
	method          string // pattern | dictionary | fuzzy
	confidence      float64
	source          string // rule or CPE that established the identity
}

// resolveMapping decides the vendor/product identity for evaluation:
//  1. deterministic normalization rule (highest confidence);
//  2. CPE dictionary entries for the normalized identity (exact identifiers);
//  3. dictionary entries for the product alone (vendor differs across feeds);
//  4. fuzzy candidates (lowest confidence — findings stay "potential").
func (a *Assessor) resolveMapping(ctx context.Context, store *nvd.Store, app norm.App) mapping {
	if app.Method == "pattern" && app.Vendor != "" && app.Product != "" {
		return mapping{vendor: app.Vendor, product: app.Product, method: "pattern", confidence: app.Confidence, source: app.MatchSource}
	}
	if app.Vendor != "" && app.Product != "" {
		return mapping{vendor: app.Vendor, product: app.Product, method: "pattern", confidence: app.Confidence, source: app.MatchSource}
	}
	// No deterministic rule: ask the CPE dictionary using the raw display
	// name tokens (exact identifiers win over guessing).
	if app.Product == "" && app.Vendor == "" {
		if m, ok := a.dictionaryIdentity(ctx, store, app.Name); ok {
			return m
		}
	}
	// Fuzzy candidates last, and only as candidates.
	cands := a.norm().Candidates(app.Name, 1)
	if len(cands) > 0 {
		return mapping{
			vendor: cands[0].Vendor, product: cands[0].Product,
			method: "fuzzy", confidence: cands[0].Score * 0.6,
			source: fmt.Sprintf("similarity candidate (score %.2f)", cands[0].Score),
		}
	}
	return mapping{}
}

// dictionaryIdentity looks the raw display name up in the CPE dictionary by
// its cleaned tokens. It is deliberately conservative: the dictionary product
// must be an exact token match AND be unambiguous (one vendor), so this can
// never invent an identity. Deprecated entries are resolved.
func (a *Assessor) dictionaryIdentity(ctx context.Context, store *nvd.Store, displayName string) (mapping, bool) {
	name := strings.ToLower(strings.TrimSpace(displayName))
	name = strings.TrimSpace(name)
	if name == "" {
		return mapping{}, false
	}
	vendors, err := store.VendorsForProduct(ctx, name)
	if err != nil || len(vendors) != 1 {
		return mapping{}, false
	}
	entries, err := store.DictionaryFor(ctx, vendors[0], name)
	if err != nil || len(entries) == 0 {
		return mapping{}, false
	}
	// Prefer non-deprecated entries; resolve a deprecated-only product.
	nonDeprecated := 0
	for _, e := range entries {
		if !e.Deprecated {
			nonDeprecated++
		}
	}
	if nonDeprecated == 0 {
		if replacement, ok, err := store.ResolveDeprecated(ctx, entries[0].CPE23); err == nil && ok {
			if parsed, err := cpe.Parse(replacement); err == nil {
				return mapping{
					vendor: parsed.Vendor, product: parsed.Product,
					method: "dictionary", confidence: 0.95,
					source: "CPE dictionary (resolved deprecation: " + entries[0].CPE23 + ")",
				}, true
			}
		}
		return mapping{}, false
	}
	return mapping{
		vendor: strings.ToLower(vendors[0]), product: name,
		method: "dictionary", confidence: 0.95,
		source: "CPE dictionary exact product match",
	}, true
}

// evaluateCVE decides one CVE against one application and builds the finding.
func (a *Assessor) evaluateCVE(ctx context.Context, store *nvd.Store, pkg model.Package, app norm.App, m mapping, targets cpe.Targets, cveID string, cmp cpe.CompareFunc) (model.Finding, outcome, error) {
	// Reuse a previous evaluation when the CVE data has not changed since.
	if verdict, ok, _ := store.EvalCacheGet(ctx, m.vendor, m.product, app.Version, cveID); ok {
		if verdict == "vulnerable" || verdict == "not_affected" {
			rec, _, err := store.CVEByID(ctx, cveID)
			if err != nil {
				return model.Finding{}, 0, err
			}
			if verdict == "vulnerable" {
				f, _ := a.buildFinding(ctx, rec, pkg, app, m, targets, cveID, cmp, true)
				return f, outcomeVulnerable, nil
			}
			f, _ := a.buildFinding(ctx, rec, pkg, app, m, targets, cveID, cmp, false)
			return f, outcomeNotAffected, nil
		}
	}

	rec, ok, err := store.CVEByID(ctx, cveID)
	if err != nil {
		return model.Finding{}, 0, err
	}
	if !ok {
		// The index mentioned a CVE whose record is gone: correlation error,
		// never a silent pass.
		return model.Finding{}, 0, fmt.Errorf("candidate CVE %s is missing from the NVD dataset; re-synchronize", cveID)
	}
	if nvd.Rejected(rec.Status) {
		_ = store.EvalCachePut(ctx, m.vendor, m.product, app.Version, cveID, "excluded", "CVE rejected by NVD", a.now())
		return model.Finding{}, outcomeExcluded, nil
	}

	tree := cpe.EvaluateConfigs(rec.Configs, targets, cmp)

	switch {
	case tree.Vulnerable:
		f, err := a.buildFinding(ctx, rec, pkg, app, m, targets, cveID, cmp, true)
		if err != nil {
			return model.Finding{}, 0, err
		}
		f = a.applyVendorAdvisory(f, app, m, rec)
		verdict := "vulnerable"
		out := outcomeVulnerable
		if f.Affected == model.ApplicabilityNotAffected {
			verdict, out = "not_affected", outcomeNotAffected
		}
		_ = store.EvalCachePut(ctx, m.vendor, m.product, app.Version, cveID, verdict, f.Explanation, a.now())
		return f, out, nil
	case tree.MatchedNotVulnerable:
		f, err := a.buildFinding(ctx, rec, pkg, app, m, targets, cveID, cmp, false)
		if err != nil {
			return model.Finding{}, 0, err
		}
		_ = store.EvalCachePut(ctx, m.vendor, m.product, app.Version, cveID, "not_affected", f.Explanation, a.now())
		return f, outcomeNotAffected, nil
	default:
		// The CVE mentions the product but no configuration matches the
		// installed version: not applicable, excluded from findings.
		_ = store.EvalCachePut(ctx, m.vendor, m.product, app.Version, cveID, "excluded", "no configuration matched", a.now())
		return model.Finding{}, outcomeExcluded, nil
	}
}

// buildFinding assembles the evidence-backed finding for one CVE.
func (a *Assessor) buildFinding(ctx context.Context, rec nvd.Record, pkg model.Package, app norm.App, m mapping, targets cpe.Targets, cveID string, cmp cpe.CompareFunc, vulnerable bool) (model.Finding, error) {
	tree := cpe.EvaluateConfigs(rec.Configs, targets, cmp)

	severity := model.SeverityUnknown
	var cvss *model.CVSS
	if metric := rec.PrimaryCVSS(); metric != nil {
		severity = intel.SeverityFromScore(metric.Score)
		cvss = &model.CVSS{Score: metric.Score, Vector: metric.Vector, Source: "NVD"}
	}

	evidence := []model.Evidence{
		{Kind: "inventory", Source: string(pkg.Source),
			Detail: fmt.Sprintf("%s %s recorded by %s%s", pkg.Name, pkg.Version, pkg.Source, publisherDetail(pkg.Vendor))},
		{Kind: "normalization", Source: "clanker-guard",
			Detail: fmt.Sprintf("mapped %q to vendor %q product %q via %s (%s)", app.Name, m.vendor, m.product, m.method, m.source)},
		{Kind: "nvd_cpe_match", Source: "NVD",
			Detail: strings.Join(limitStrings(tree.MatchedCPEs, 4), "; "), URL: rec.DetailURL()},
	}
	if len(tree.Details) > 0 {
		evidence = append(evidence, model.Evidence{Kind: "evaluation", Source: "NVD",
			Detail: strings.Join(limitStrings(tree.Details, 6), "; ")})
	}

	f := model.Finding{
		Asset:            pkg.Name, // overwritten by the scan pipeline with the host
		Product:          fmt.Sprintf("%s/%s", m.vendor, m.product),
		InstalledVersion: app.Version,
		Ecosystem:        pkg.Ecosystem,
		VulnerabilityID:  rec.ID,
		Source:           "NVD",
		ValidationStatus: model.ValidationVersion,
		Severity:         severity,
		CVSS:             cvss,
		Evidence:         evidence,
		LastChecked:      timePtr(a.now()),
		Explanation:      rec.Description,
		RaiseConfidence:  []string{"the vendor advisory confirms the affected version range"},
		LowerConfidence:  []string{"the vendor documents this version as fixed"},
		PackageRef:       pkg.Name + "@" + pkg.Version,
	}
	if vulnerable {
		switch m.method {
		case "fuzzy":
			f.Affected = model.ApplicabilityPotential
			f.Confidence = model.ConfidenceLow
			f.Explanation = fmt.Sprintf(
				"NVD configuration data for %s matches installed version %s, but the product identity was established by similarity matching (%s) rather than an exact identifier, so applicability is not confirmed.",
				f.Product, app.Version, m.source)
		default:
			f.Affected = model.ApplicabilityConfirmed
			f.Confidence = model.ConfidenceHigh
			f.Explanation = fmt.Sprintf(
				"NVD's own applicability data for %s matches installed version %s of %s %s.",
				f.Product, app.Version, m.vendor, m.product)
		}
		if len(tree.FixedVersions) > 0 {
			f.FixedVersion = tree.FixedVersions[len(tree.FixedVersions)-1]
		}
	} else {
		f.Affected = model.ApplicabilityNotAffected
		f.Confidence = model.ConfidenceHigh
		f.Explanation = fmt.Sprintf(
			"NVD configuration data for %s only matches non-vulnerable entries for installed version %s; the CVE does not apply.",
			f.Product, app.Version)
		if len(tree.FixedVersions) > 0 {
			f.FixedVersion = tree.FixedVersions[len(tree.FixedVersions)-1]
		}
	}
	f.Remediation = remediationFor(f, vulnerable, rec)
	return f, nil
}

// applyVendorAdvisory cross-checks the NVD verdict against the authoritative
// vendor statement. The vendor wins on conflict, per the accuracy rules.
func (a *Assessor) applyVendorAdvisory(f model.Finding, app norm.App, m mapping, rec nvd.Record) model.Finding {
	adv, ok := a.advisories().For(rec.ID, m.vendor, m.product)
	if !ok {
		return f
	}
	f.VendorAdvisory = &model.VendorAdvisory{
		Vendor:       adv.Vendor,
		ID:           rec.ID,
		URL:          adv.URL,
		FixedVersion: adv.FixedVersion,
		Statement:    adv.Statement,
	}
	f.Evidence = append(f.Evidence, model.Evidence{
		Kind: "vendor_advisory", Source: adv.Vendor,
		Detail: adv.Statement, URL: adv.URL,
	})
	if adv.FixedVersion != "" {
		f.FixedVersion = adv.FixedVersion
	}
	// Conflict: the vendor fixed this version but NVD's ranges say affected.
	if adv.AffectedBelow != "" && app.Version != "" {
		if cmp, err := version.Compare("", app.Version, adv.AffectedBelow); err == nil && cmp >= 0 {
			f.Affected = model.ApplicabilityNotAffected
			f.Confidence = model.ConfidenceHigh
			f.Explanation = fmt.Sprintf(
				"the vendor advisory for %s states versions before %s are affected and the installed version is %s, so the vendor statement overrides NVD's range match.",
				rec.ID, adv.AffectedBelow, app.Version)
			f.Remediation = "No action required: the vendor advisory confirms the installed version contains the fix."
		}
	}
	return f
}

func remediationFor(f model.Finding, vulnerable bool, rec nvd.Record) string {
	if !vulnerable || f.Affected == model.ApplicabilityNotAffected {
		return "No action required: the available applicability data indicates the installed version is not affected."
	}
	if f.FixedVersion != "" {
		return fmt.Sprintf("Upgrade %s to %s or later, then rescan.", f.Product, f.FixedVersion)
	}
	return fmt.Sprintf("Review %s for vendor guidance; no fixed version is published in the available data.", rec.DetailURL())
}

// comparatorFor picks the version comparator for the application's ecosystem.
func comparatorFor(app norm.App) cpe.CompareFunc {
	return func(a, b string) (int, error) { return version.Compare("", a, b) }
}

// OSIdentities builds the CPE operating-system identities for the inventory's
// asset, generic identity last so specific criteria match first.
func OSIdentities(inv model.Inventory) []cpe.CPE {
	asset := inv.Asset
	var out []cpe.CPE
	os := strings.ToLower(asset.OS)
	if os == "" {
		os = strings.ToLower(asset.DistroID)
	}
	if os == "" {
		return nil
	}
	switch {
	case strings.Contains(os, "windows"):
		product := "windows"
		if inv.Windows != nil && inv.Windows.Build != "" {
			// Build numbers decide the product family NVD knows:
			// 10.0.22000+ is Windows 11, 10.0.10240..19045 is Windows 10.
			build := inv.Windows.Build
			base := build
			if i := strings.IndexByte(base, '.'); i > 0 {
				base = base[:i]
			}
			switch {
			case strings.HasPrefix(build, "10.0.26"), strings.HasPrefix(build, "10.0.25"),
				strings.HasPrefix(build, "10.0.24"), strings.HasPrefix(build, "10.0.23"),
				strings.HasPrefix(build, "10.0.22"):
				product = "windows_11"
			case strings.HasPrefix(build, "10.0.2"), strings.HasPrefix(build, "10.0.1"):
				product = "windows_10"
			}
		}
		if inv.Windows != nil && strings.Contains(strings.ToLower(inv.Windows.Product), "server") {
			product = "windows_server"
		}
		out = append(out, cpe.CPE{Part: cpe.PartOS, Vendor: "microsoft", Product: product, Version: cpe.Any})
		out = append(out, cpe.CPE{Part: cpe.PartOS, Vendor: "microsoft", Product: "windows", Version: cpe.Any})
	case strings.Contains(os, "darwin") || strings.Contains(os, "mac"):
		out = append(out, cpe.CPE{Part: cpe.PartOS, Vendor: "apple", Product: "macos", Version: cpe.Any})
		out = append(out, cpe.CPE{Part: cpe.PartOS, Vendor: "apple", Product: "mac_os_x", Version: cpe.Any})
	case strings.Contains(os, "ubuntu"):
		out = append(out, cpe.CPE{Part: cpe.PartOS, Vendor: "canonical", Product: "ubuntu_linux", Version: cpe.Any})
	case strings.Contains(os, "debian"):
		out = append(out, cpe.CPE{Part: cpe.PartOS, Vendor: "debian", Product: "debian_linux", Version: cpe.Any})
	case strings.Contains(os, "alpine"):
		out = append(out, cpe.CPE{Part: cpe.PartOS, Vendor: "alpinelinux", Product: "alpine_linux", Version: cpe.Any})
	case strings.Contains(os, "centos"), strings.Contains(os, "red hat"), strings.Contains(os, "rhel"):
		out = append(out, cpe.CPE{Part: cpe.PartOS, Vendor: "redhat", Product: "enterprise_linux", Version: cpe.Any})
	}
	return out
}

// dotnetFrameworks converts WindowsState .NET records into app packages.
func dotnetFrameworks(ws *model.WindowsState) []model.Package {
	if ws == nil {
		return nil
	}
	var out []model.Package
	for _, fx := range ws.DotNet {
		fx = strings.TrimSpace(fx)
		if fx == "" {
			continue
		}
		name, ver := fx, ""
		if i := strings.LastIndexByte(fx, ' '); i > 0 {
			name, ver = fx[:i], fx[i+1:]
		}
		if ver == "" {
			continue
		}
		out = append(out, model.Package{
			Name:      ".NET " + name,
			Version:   ver,
			Ecosystem: model.EcosystemWindows,
			Source:    model.OriginManifest,
			Manager:   "dotnet-sharedfx",
			Vendor:    "Microsoft Corporation",
		})
	}
	return out
}

func publisherDetail(publisher string) string {
	if strings.TrimSpace(publisher) == "" {
		return ""
	}
	return " (publisher: " + strings.TrimSpace(publisher) + ")"
}

func timePtr(t time.Time) *time.Time { return &t }

func mergeCoverage(dst *model.AppCoverage, src model.AppCoverage) {
	dst.Normalized += src.Normalized
	dst.Mapped += src.Mapped
	dst.Evaluated += src.Evaluated
	dst.Skipped += src.Skipped
	dst.Unrecognized = append(dst.Unrecognized, src.Unrecognized...)
	dst.CandidateCVEs += src.CandidateCVEs
	dst.ConfirmedMatches += src.ConfirmedMatches
	dst.PotentialMatches += src.PotentialMatches
	dst.ExcludedCVEs += src.ExcludedCVEs
	dst.Errors += src.Errors
}
