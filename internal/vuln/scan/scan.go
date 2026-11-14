// Package scan wires inventory, intelligence, assessment and reporting into the
// two user-facing entry points: `clanker vuln` and `clanker-guard-agent`.
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/assess"
	"github.com/bgdnvk/clanker/internal/vuln/improve"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/inventory"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/netscan"
	"github.com/bgdnvk/clanker/internal/vuln/report"
)

// Options controls a local assessment run.
type Options struct {
	Root               string
	CachePath          string
	Offline            bool
	Format             string
	OutputPath         string // "-" writes to Stdout
	IncludeNotAffected bool
	Policy             model.Policy
	NoPython           bool
	NoNpm              bool
	NoRuby             bool
	Vendor             string
	ToolVersion        string
	Now                func() time.Time
	Stdout             io.Writer
	Stderr             io.Writer
	// AssetCriticality feeds the risk model (0..1).
	AssetCriticality float64
	// Collectors overrides the inventory collector set (tests, embedded use).
	Collectors []inventory.Collector

	// --- network assessment ---
	// Scope is the authorised target set. Setting it selects network mode.
	Scope *model.Scope
	// TargetPorts overrides the scope's port list (still bounded per host).
	TargetPorts []int
	// NetConcurrency / NetConnectTimeout bound discovery.
	NetConcurrency    int
	NetConnectTimeout time.Duration
	// NVDAPIKey raises NVD's rate limit when supplied.
	NVDAPIKey string
	// NVDFunc overrides the NVD CPE lookup (tests, embedded use).
	NVDFunc func(ctx context.Context, cpe string) ([]netscan.CVEMatch, error)

	// --- software / container assessment ---
	// SBOMPath is a CycloneDX/SPDX/Syft document or a dependency manifest.
	SBOMPath string
	// Image is a container image reference (requires a local Docker daemon).
	Image string
	// DockerPath overrides the docker CLI.
	DockerPath string
	// MaxImageBytes refuses images above this size.
	MaxImageBytes int64
	// Progress receives pipeline stage updates (used by the HTTP API). It must
	// not block: callers keep it cheap.
	Progress func(Stage)
	// SkipRender keeps the report out of the filesystem (the HTTP API serves the
	// report from the history database instead).
	SkipRender bool
}

// Result summarises what a run produced.
type Result struct {
	Report     model.Report
	OutputPath string
	ExitCode   int
	Incomplete bool
}

// DefaultCachePath returns the per-user intelligence cache location.
func DefaultCachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil || dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "clanker-guard", "intel.db")
}

func (o *Options) normalize() {
	if o.Root == "" {
		o.Root = "/"
	}
	if o.CachePath == "" {
		o.CachePath = DefaultCachePath()
	}
	if o.Format == "" {
		o.Format = "json"
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.ToolVersion == "" {
		o.ToolVersion = "dev"
	}
}

// Run performs an assessment. The mode is chosen by the options: an image
// reference, an SBOM path, an authorised network scope, or the local endpoint.
func Run(ctx context.Context, opts Options) (Result, error) {
	opts.normalize()
	switch {
	case strings.TrimSpace(opts.Image) != "" || strings.TrimSpace(opts.SBOMPath) != "":
		return runSBOM(ctx, opts)
	case opts.Scope != nil:
		return runNetwork(ctx, opts)
	default:
		return runLocal(ctx, opts)
	}
}

// runLocal performs the endpoint assessment.
func runLocal(ctx context.Context, opts Options) (Result, error) {
	opts.normalize()
	started := opts.Now()

	store, err := intel.OpenStore(opts.CachePath)
	if err != nil {
		return Result{}, fmt.Errorf("open intelligence cache: %w", err)
	}
	defer store.Close()

	// --- inventory -----------------------------------------------------------
	collectorOpts := inventory.DefaultOptions()
	collectorOpts.Root = opts.Root
	collectorOpts.IncludePython = !opts.NoPython
	collectorOpts.IncludeNode = !opts.NoNpm
	collectorOpts.IncludeRuby = !opts.NoRuby
	collectors := opts.Collectors
	if len(collectors) == 0 {
		collectors = inventory.DefaultCollectors()
	}
	opts.report(Stage{Name: "discovery", Percent: 5, Detail: "collecting installed software"})
	runner := &inventory.Runner{Collectors: collectors}
	inv, err := runner.Run(ctx, collectorOpts)
	if err != nil {
		return Result{}, fmt.Errorf("inventory failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("assessment cancelled: %w", err)
	}
	if len(inv.Packages) == 0 {
		return Result{}, fmt.Errorf("inventory returned no packages; refusing to report a clean scan")
	}
	if opts.Vendor == "" {
		opts.Vendor = inv.Asset.DistroID
	}
	opts.report(Stage{Name: "discovery", Percent: 20, Detail: fmt.Sprintf("%d packages collected", len(inv.Packages))})

	return finish(ctx, store, opts, started, inv, nil, "local", nil, nil, nil, nil)
}

// pipelineInput is what a mode hands to the shared reporting stage.
type pipelineInput struct {
	Mode             string
	Inventory        model.Inventory
	ExtraFindings    []model.Finding
	Scope            *model.Scope
	ExtraSources     []string
	ExtraLimitations []string
	ExtraErrors      []string
	Incomplete       bool
	// CoverageHint overrides the "packages inspected" count when the mode did not
	// build packages (network assessment counts services instead).
	CoverageHint *model.Coverage
}

// finish runs correlation, reporting and history for any mode.
func finish(ctx context.Context, store *intel.Store, opts Options, started time.Time,
	inv model.Inventory, extra []model.Finding, mode string, scope *model.Scope,
	extraSources, extraLimits, extraErrors []string) (Result, error) {
	return finishWith(ctx, store, opts, started, pipelineInput{
		Mode: mode, Inventory: inv, ExtraFindings: extra, Scope: scope,
		ExtraSources: extraSources, ExtraLimitations: extraLimits, ExtraErrors: extraErrors,
	})
}

func finishWith(ctx context.Context, store *intel.Store, opts Options, started time.Time, in pipelineInput) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("assessment cancelled: %w", err)
	}

	// Deployed improvement rules shape detection. A missing or broken rule set
	// falls back to the shipped policy and records why.
	detectionPolicy, ruleID, _, _ := improve.ActivePolicy(ctx, store)
	engine := &assess.Engine{
		Policy: detectionPolicy,
		Host:   in.Inventory.Asset.Hostname,
		Progress: func(stage, detail string) {
			opts.report(Stage{Name: stage, Percent: stagePercent(stage), Detail: detail})
		},
		Store: store,
		// Network and SBOM modes never call OSV for the host: network evidence is
		// NVD-derived and SBOM components are correlated from the cache/OSV
		// depending on the offline flag.
		Online:             !opts.Offline && in.Mode != "network",
		Vendor:             vendorName(opts.Vendor, in.Inventory.Asset.DistroID),
		IncludeNotAffected: opts.IncludeNotAffected,
		AssetCriticality:   opts.AssetCriticality,
		Now:                opts.Now,
	}
	res, assessErr := engine.Assess(ctx, in.Inventory)
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("assessment cancelled: %w", err)
	}

	errors := append([]string{}, in.ExtraErrors...)
	errors = append(errors, res.Stats.Errors...)
	incomplete := in.Incomplete
	if assessErr != nil {
		errors = append(errors, "assessment failed: "+assessErr.Error())
		incomplete = true
	}
	if opts.Offline && in.Mode != "network" {
		if n, _ := store.AdvisoryCount(ctx); n == 0 {
			errors = append(errors, "offline mode with an empty advisory cache: run `clanker vuln feeds update` while online")
			incomplete = true
		}
	}

	findings := res.Findings
	if len(in.ExtraFindings) > 0 {
		findings = append(findings, in.ExtraFindings...)
	}
	// One finalisation pass gives observations the same enrichment, scoring,
	// ordering and stable identity as advisory-derived findings.
	findings = engine.Finalize(ctx, findings)
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("assessment cancelled: %w", err)
	}

	opts.report(Stage{Name: "report", Percent: 92, Detail: "assembling report"})

	feedStates, _ := FeedStates(ctx, store)
	coverage := model.Coverage{
		PackagesInspected: len(in.Inventory.Packages),
		PackagesMatched:   res.Stats.PackagesMatched,
		AdvisoriesChecked: res.Stats.AdvisoriesFetched + res.Stats.AdvisoriesCached,
		Sources:           coverageSources(opts.Offline, feedStates),
		NotCovered:        notCovered(res.Stats),
		Limitations:       limitations(opts.Offline),
	}
	if in.CoverageHint != nil {
		coverage = *in.CoverageHint
		if coverage.Sources == nil {
			coverage.Sources = coverageSources(opts.Offline, feedStates)
		}
	}
	coverage.Sources = appendUnique(coverage.Sources, in.ExtraSources...)
	coverage.Limitations = appendUnique(coverage.Limitations, in.ExtraLimitations...)

	var previous *model.RunRecord
	if prev, err := store.PreviousRun(ctx, in.Inventory.Asset.Hostname, ""); err == nil {
		previous = prev
	}

	rep := report.Build(report.BuildOptions{
		ToolVersion:     opts.ToolVersion,
		Mode:            in.Mode,
		Inventory:       in.Inventory,
		Findings:        findings,
		Started:         started,
		Finished:        opts.Now(),
		Offline:         opts.Offline,
		FeedStates:      feedStates,
		Errors:          errors,
		Policy:          opts.Policy,
		Coverage:        coverage,
		Previous:        previous,
		Scope:           in.Scope,
		DetectionPolicy: policyNotesFor(engine.PolicyNotes(), ruleID),
	})

	rec := model.RunRecord{
		ID:           rep.ReportID,
		Host:         rep.Metadata.Host,
		StartedAt:    started,
		FinishedAt:   opts.Now(),
		FindingIDs:   report.FindingFingerprints(findings),
		FindingCount: rep.Summary.Total,
		Actionable:   rep.Summary.Actionable,
		KEVCount:     rep.Summary.KEVCount,
	}
	if payload, err := report.MarshalJSON(rep); err == nil {
		if err := store.SaveRun(ctx, rec, payload); err != nil {
			errors = append(errors, "history write failed: "+err.Error())
		}
	}

	outPath := ""
	if !opts.SkipRender {
		var err error
		outPath, err = writeReport(opts, rep)
		if err != nil {
			return Result{Report: rep, Incomplete: incomplete}, err
		}
	}
	opts.report(Stage{Name: "done", Percent: 100, Detail: fmt.Sprintf("%d findings", len(findings))})
	return Result{
		Report:     rep,
		OutputPath: outPath,
		ExitCode:   report.ExitCode(rep, incomplete),
		Incomplete: incomplete,
	}, nil
}

func appendUnique(base []string, extra ...string) []string {
	seen := map[string]bool{}
	for _, s := range base {
		seen[s] = true
	}
	for _, s := range extra {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		base = append(base, s)
	}
	return base
}

// Stage is one progress update for a running assessment.
type Stage struct {
	Name    string `json:"stage"`
	Percent int    `json:"percent"`
	Detail  string `json:"detail,omitempty"`
}

func (o *Options) report(st Stage) {
	if o.Progress != nil {
		o.Progress(st)
	}
}

// stagePercent maps a pipeline stage to a coarse progress percentage. These are
// deliberately coarse: a scan's duration is dominated by network calls, so a
// precise percentage would be a fabricated number in the UI.
func stagePercent(stage string) int {
	switch stage {
	case "inventory":
		return 35
	case "intelligence":
		return 60
	case "matching":
		return 75
	case "enrichment":
		return 85
	default:
		return 50
	}
}

// policyNotesFor records which detection decisions (and rule) shaped the run.
func policyNotesFor(notes []string, ruleID string) []string {
	out := append([]string(nil), notes...)
	if ruleID != "" {
		out = append(out, "deployed detection rule "+ruleID)
	}
	return out
}

func writeReport(opts Options, rep model.Report) (string, error) {
	out := opts.OutputPath
	if out == "" {
		ext := "json"
		switch strings.ToLower(opts.Format) {
		case "markdown", "md":
			ext = "md"
		case "sarif":
			ext = "sarif"
		case "html":
			ext = "html"
		}
		out = filepath.Join(".", "clanker-guard-report."+ext)
	}
	if out == "-" {
		return "stdout", report.Render(opts.Stdout, rep, opts.Format)
	}
	f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	defer f.Close()
	if err := report.Render(f, rep, opts.Format); err != nil {
		return "", err
	}
	return out, nil
}

func vendorName(explicit, distroID string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	return titleVendor(distroID)
}

func titleVendor(id string) string {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "ubuntu":
		return "Ubuntu"
	case "debian":
		return "Debian"
	case "rocky", "rockylinux":
		return "Rocky Linux"
	case "almalinux":
		return "AlmaLinux"
	case "rhel", "redhat":
		return "Red Hat"
	case "fedora":
		return "Fedora"
	case "alpine":
		return "Alpine"
	default:
		return id
	}
}

func coverageSources(offline bool, feeds []model.FeedState) []string {
	sources := []string{}
	if offline {
		sources = append(sources, "OSV cache")
	} else {
		sources = append(sources, "OSV (api.osv.dev)")
	}
	for _, f := range feeds {
		if f.Records > 0 {
			sources = append(sources, fmt.Sprintf("%s (%d records)", f.Source, f.Records))
		}
	}
	return sources
}

func notCovered(stats assess.Stats) []string {
	var out []string
	keys := make([]string, 0, len(stats.UncoveredEcosystems))
	for k := range stats.UncoveredEcosystems {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		name := k
		if name == "" || name == "unknown" {
			name = "packages with no ecosystem mapping"
		}
		out = append(out, fmt.Sprintf("%s: no public advisory ecosystem available (%d packages)", name, stats.UncoveredEcosystems[k]))
	}
	return out
}

func limitations(offline bool) []string {
	out := []string{
		"version-correlation only: no network validation or active exploitation checks were performed",
		"vendor backports are inferred from distribution version data; when a vendor does not publish affected builds the finding stays 'needs_investigation'",
		"OSV coverage differs per ecosystem; absence of an advisory is not evidence of a fix",
		"distribution advisories with open-ended version ranges are resolved from the vendor's affected-version enumeration, not from upstream matching (which is over-inclusive)",
	}
	if offline {
		out = append(out, "offline mode: only advisories already present in the local cache were consulted")
	}
	return out
}

// FeedStates converts cached sync metadata into report feed states.
func FeedStates(ctx context.Context, store *intel.Store) ([]model.FeedState, error) {
	states, err := store.SyncStates(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]model.FeedState, 0, len(states))
	for _, s := range states {
		last := s.LastSync
		stale := false
		switch strings.ToUpper(s.Source) {
		case "KEV":
			stale = last.IsZero() || time.Since(last) > 7*24*time.Hour
		case "EPSS":
			stale = last.IsZero() || time.Since(last) > 3*24*time.Hour
		default:
			stale = last.IsZero() || time.Since(last) > 30*24*time.Hour
		}
		out = append(out, model.FeedState{
			Source:   s.Source,
			LastSync: &last,
			Records:  s.Records,
			Stale:    stale,
		})
	}
	return out, nil
}

// UpdateFeeds refreshes KEV and EPSS, and optionally prefetches OSV advisories
// for the local inventory so that later scans can run offline.
func UpdateFeeds(ctx context.Context, cachePath string, withOSV bool, stderr io.Writer) ([]intel.SyncInfo, error) {
	if cachePath == "" {
		cachePath = DefaultCachePath()
	}
	store, err := intel.OpenStore(cachePath)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	fetcher := intel.NewFetcher()
	kev, err := fetcher.FetchKEV(ctx)
	if err != nil {
		return nil, fmt.Errorf("KEV update failed (existing data left untouched): %w", err)
	}
	if err := store.SaveKEV(ctx, kev); err != nil {
		return nil, err
	}
	if err := store.RecordSync(ctx, "KEV", len(kev), "CISA Known Exploited Vulnerabilities catalog"); err != nil {
		return nil, err
	}
	fmt.Fprintf(stderr, "KEV: %d records\n", len(kev))

	epss, err := fetcher.FetchEPSS(ctx)
	if err != nil {
		return nil, fmt.Errorf("EPSS update failed (existing data left untouched): %w", err)
	}
	if err := store.SaveEPSS(ctx, epss, 5000); err != nil {
		return nil, err
	}
	if err := store.RecordSync(ctx, "EPSS", len(epss), "FIRST EPSS scores"); err != nil {
		return nil, err
	}
	fmt.Fprintf(stderr, "EPSS: %d records\n", len(epss))

	if withOSV {
		n, err := prefetchOSV(ctx, store, stderr)
		if err != nil {
			return nil, err
		}
		if err := store.RecordSync(ctx, "OSV", n, "advisories for the local inventory"); err != nil {
			return nil, err
		}
	}

	return store.SyncStates(ctx)
}

// prefetchOSV resolves and caches advisories for the packages installed here.
func prefetchOSV(ctx context.Context, store *intel.Store, stderr io.Writer) (int, error) {
	runner := &inventory.Runner{Collectors: inventory.DefaultCollectors()}
	inv, err := runner.Run(ctx, inventory.DefaultOptions())
	if err != nil {
		return 0, err
	}
	var queries []intel.Query
	for _, p := range inv.Packages {
		if !assess.SupportsOSV(p.Ecosystem) {
			continue
		}
		queries = append(queries, intel.Query{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version})
	}
	client := intel.NewOSVClient()
	refs, err := client.QueryBatch(ctx, queries)
	if err != nil {
		return 0, err
	}
	ids := map[string]struct{}{}
	for _, list := range refs {
		for _, r := range list {
			ids[r.ID] = struct{}{}
		}
	}
	var advs []intel.Advisory
	for id := range ids {
		if _, ok, _ := store.AdvisoryByID(ctx, id); ok {
			continue
		}
		adv, err := client.FetchVuln(ctx, id)
		if err != nil {
			fmt.Fprintf(stderr, "warning: could not cache advisory %s: %v\n", id, err)
			continue
		}
		advs = append(advs, adv)
	}
	if len(advs) > 0 {
		if err := store.SaveAdvisories(ctx, advs); err != nil {
			return 0, err
		}
	}
	total, _ := store.AdvisoryCount(ctx)
	fmt.Fprintf(stderr, "OSV: cached %d new advisories (%d total)\n", len(advs), total)
	return total, nil
}

// FeedStatus prints the cache state.
func FeedStatus(ctx context.Context, cachePath string, w io.Writer) error {
	if cachePath == "" {
		cachePath = DefaultCachePath()
	}
	store, err := intel.OpenStore(cachePath)
	if err != nil {
		return err
	}
	defer store.Close()

	states, err := FeedStates(ctx, store)
	if err != nil {
		return err
	}
	if len(states) == 0 {
		fmt.Fprintln(w, "no intelligence cached yet — run `clanker vuln feeds update`")
		return nil
	}
	fmt.Fprintf(w, "%-8s %-22s %-10s %s\n", "SOURCE", "LAST SYNC (UTC)", "RECORDS", "STATE")
	for _, s := range states {
		last := "never"
		if s.LastSync != nil && !s.LastSync.IsZero() {
			last = s.LastSync.UTC().Format("2006-01-02 15:04:05")
		}
		state := "fresh"
		if s.Stale {
			state = "STALE"
		}
		fmt.Fprintf(w, "%-8s %-22s %-10d %s\n", s.Source, last, s.Records, state)
	}
	return nil
}

// InventoryOnly collects and prints the endpoint inventory.
func InventoryOnly(ctx context.Context, root, format string, w io.Writer) error {
	opts := inventory.DefaultOptions()
	if root != "" {
		opts.Root = root
	}
	inv, err := (&inventory.Runner{Collectors: inventory.DefaultCollectors()}).Run(ctx, opts)
	if err != nil {
		return err
	}
	if format == "markdown" || format == "md" {
		fmt.Fprintf(w, "# Inventory — %s\n\n%s %s (%s)\n\n| Package | Version | Ecosystem | Source |\n|---|---|---|---|\n",
			inv.Asset.Hostname, inv.Asset.OS, inv.Asset.OSVersion, inv.Asset.Arch)
		for _, p := range inv.Packages {
			fmt.Fprintf(w, "| %s | %s | %s | %s |\n", p.Name, p.Version, p.Ecosystem, p.Source)
		}
		return nil
	}
	return renderJSON(w, inv)
}

// RenderStored re-renders the latest stored run in a different format.
func RenderStored(ctx context.Context, cachePath string, rep *model.Report, format string, w io.Writer) error {
	if rep == nil {
		return fmt.Errorf("no stored report available")
	}
	return report.Render(w, *rep, format)
}

// Ask answers questions strictly from a stored report. It is deterministic: no
// model is consulted, so the same report always yields the same answer.
func Ask(rep model.Report, question string) string {
	q := strings.ToLower(question)
	actionable := make([]model.Finding, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		if f.Affected == model.ApplicabilityNotAffected {
			continue
		}
		actionable = append(actionable, f)
	}
	header := fmt.Sprintf("Based on report %s for %s (%d findings, %d actionable):\n",
		rep.ReportID, rep.Metadata.Host, rep.Summary.Total, rep.Summary.Actionable)

	switch {
	case strings.Contains(q, "kev") || strings.Contains(q, "known exploited") || strings.Contains(q, "exploited"):
		var kev []model.Finding
		for _, f := range actionable {
			if f.CISAKEV {
				kev = append(kev, f)
			}
		}
		if len(kev) == 0 {
			return header + "\nNo findings in this report are listed in CISA KEV."
		}
		var b strings.Builder
		b.WriteString(header)
		fmt.Fprintf(&b, "\n%d finding(s) are in CISA KEV:\n", len(kev))
		for _, f := range kev {
			fmt.Fprintf(&b, "- %s %s (%s, risk %.1f, added %s)\n", f.Product, f.InstalledVersion, f.VulnerabilityID, f.RiskScore, kevDate(f))
		}
		b.WriteString("\nPrioritise these: KEV membership means exploitation has been observed in the wild.")
		return b.String()

	case strings.Contains(q, "patch first") || strings.Contains(q, "first") || strings.Contains(q, "priorit") ||
		strings.Contains(q, "most critical") || strings.Contains(q, "fix first"):
		if len(actionable) == 0 {
			return header + "\nNothing actionable is recorded in this report."
		}
		var b strings.Builder
		b.WriteString(header)
		b.WriteString("\nHighest remediation priority:\n")
		for i, f := range actionable {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&b, "%d. %s %s — %s (severity %s, confidence %s, risk %.1f)\n   %s\n",
				i+1, f.Product, f.InstalledVersion, f.VulnerabilityID, f.Severity, f.Confidence, f.RiskScore, f.Remediation)
		}
		return b.String()

	case strings.Contains(q, "patch") || strings.Contains(q, "fix") || strings.Contains(q, "upgrade"):
		var withFix []model.Finding
		for _, f := range actionable {
			if f.FixedVersion != "" {
				withFix = append(withFix, f)
			}
		}
		var b strings.Builder
		b.WriteString(header)
		if len(withFix) == 0 {
			b.WriteString("\nNo finding in this report has a published fixed version.")
			return b.String()
		}
		fmt.Fprintf(&b, "\n%d finding(s) have a published fixed version:\n", len(withFix))
		for _, f := range withFix {
			fmt.Fprintf(&b, "- %s %s → %s (%s)\n", f.Product, f.InstalledVersion, f.FixedVersion, f.VulnerabilityID)
		}
		return b.String()

	case strings.Contains(q, "explain") || strings.Contains(q, "evidence") || strings.Contains(q, "why"):
		id := extractVulnToken(question)
		for _, f := range rep.Findings {
			if id != "" && !strings.EqualFold(f.VulnerabilityID, id) && !containsFold(f.Aliases, id) {
				continue
			}
			var b strings.Builder
			fmt.Fprintf(&b, "%s — %s %s (%s)\n", f.VulnerabilityID, f.Product, f.InstalledVersion, f.Ecosystem)
			fmt.Fprintf(&b, "Applicability: %s (confidence %s)\nWhy: %s\n\n", f.Affected, f.Confidence, f.Explanation)
			b.WriteString("Evidence:\n")
			for _, e := range f.Evidence {
				fmt.Fprintf(&b, "- [%s] %s\n", e.Kind, e.Detail)
			}
			fmt.Fprintf(&b, "\nRemediation: %s\n", f.Remediation)
			return b.String()
		}
		return header + "\nNo finding matches that identifier in this report."

	default:
		var b strings.Builder
		b.WriteString(header)
		fmt.Fprintf(&b, "\nSeverity mix: critical %d, high %d, medium %d, low %d; KEV %d; needs investigation %d.\n",
			rep.Summary.BySeverity[model.SeverityCritical], rep.Summary.BySeverity[model.SeverityHigh],
			rep.Summary.BySeverity[model.SeverityMedium], rep.Summary.BySeverity[model.SeverityLow],
			rep.Summary.KEVCount, rep.Summary.ByAffected[string(model.ApplicabilityNeedsInvestigation)])
		if len(actionable) > 0 {
			b.WriteString("\nTop items by risk:\n")
			for i, f := range actionable {
				if i >= 3 {
					break
				}
				fmt.Fprintf(&b, "- %s %s (%s, risk %.1f)\n", f.Product, f.InstalledVersion, f.VulnerabilityID, f.RiskScore)
			}
			b.WriteString("\nAsk about \"KEV\", \"patch first\", \"available fixes\", or \"explain <CVE-id>\" for details.")
		}
		return b.String()
	}
}

func kevDate(f model.Finding) string {
	if f.KEV == nil || f.KEV.DateAdded == "" {
		return "date unknown"
	}
	return f.KEV.DateAdded
}

func extractVulnToken(q string) string {
	for _, field := range strings.Fields(q) {
		tok := strings.Trim(field, ".,;:()\"'")
		up := strings.ToUpper(tok)
		if strings.HasPrefix(up, "CVE-") || strings.HasPrefix(up, "GHSA-") ||
			strings.HasPrefix(up, "DEBIAN-CVE-") || strings.HasPrefix(up, "UBUNTU-CVE-") {
			return up
		}
	}
	return ""
}

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

func renderJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
