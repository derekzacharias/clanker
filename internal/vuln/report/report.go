// Package report assembles and renders assessment reports.
//
// Report shape is a contract with downstream tooling (CI gates, SARIF
// ingestion, ticketing), so it is versioned and covered by schema tests.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// SchemaVersion is bumped when the report contract changes incompatibly.
const SchemaVersion = "1.0"

// BuildOptions carries everything needed to assemble a report.
type BuildOptions struct {
	ToolVersion string
	Mode        string
	Inventory   model.Inventory
	Findings    []model.Finding
	Started     time.Time
	Finished    time.Time
	Offline     bool
	FeedStates  []model.FeedState
	Errors      []string
	Policy      model.Policy
	Scope       *model.Scope
	Coverage    model.Coverage
	Previous    *model.RunRecord
	ReportID    string
}

// Build assembles the report, computing the summary and run delta.
func Build(opts BuildOptions) model.Report {
	if opts.ReportID == "" {
		opts.ReportID = newID(opts.Inventory.Asset.Hostname, opts.Started)
	}
	finished := opts.Finished
	finishedPtr := &finished
	if finished.IsZero() {
		finishedPtr = nil
	}

	coverage := opts.Coverage
	if coverage.PackagesInspected == 0 {
		coverage.PackagesInspected = len(opts.Inventory.Packages)
	}
	if coverage.Sources == nil {
		coverage.Sources = []string{}
	}
	if coverage.NotCovered == nil {
		coverage.NotCovered = []string{}
	}

	rep := model.Report{
		SchemaVersion: SchemaVersion,
		ReportID:      opts.ReportID,
		Metadata: model.ScanMetadata{
			ToolVersion:   opts.ToolVersion,
			StartedAt:     opts.Started,
			FinishedAt:    finishedPtr,
			Mode:          opts.Mode,
			Host:          opts.Inventory.Asset.Hostname,
			Offline:       opts.Offline,
			FeedFreshness: opts.FeedStates,
			Permissions:   permissionsNote(),
			Errors:        opts.Errors,
			SkippedChecks: opts.Inventory.Skipped,
			Coverage:      coverage,
			Scope:         opts.Scope,
			Policy:        opts.Policy,
		},
		Inventory: opts.Inventory,
		Findings:  opts.Findings,
		Summary:   Summarize(opts.Findings),
	}
	if rep.Findings == nil {
		rep.Findings = []model.Finding{}
	}
	if opts.Previous != nil {
		rep.Delta = computeDelta(opts.Previous, opts.Findings)
	}
	return rep
}

// valueOr returns s, or fallback when s is blank. Reports prefer an explicit
// "unknown" over an empty cell that a reader might interpret as "checked and fine".
func valueOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func offlineLabel(offline bool) string {
	if offline {
		return "local cache only (offline)"
	}
	return "online (OSV) + local enrichment cache"
}

func permissionsNote() string {
	return "unprivileged: package-manager metadata only; no credentials, documents or secrets were read"
}

// Summarize computes counts and the top-risk list.
func Summarize(findings []model.Finding) model.Summary {
	s := model.Summary{
		BySeverity: map[string]int{},
		ByAffected: map[string]int{},
	}
	type scored struct {
		id    string
		score float64
	}
	var top []scored
	for _, f := range findings {
		s.Total++
		s.BySeverity[normalizeSeverity(f.Severity)]++
		s.ByAffected[string(f.Affected)]++
		if f.CISAKEV {
			s.KEVCount++
		}
		switch f.Affected {
		case model.ApplicabilityConfirmed, model.ApplicabilityValidated, model.ApplicabilityProbable:
			s.Actionable++
		case model.ApplicabilityNotAffected:
			s.NotAffected++
			s.Suppressed++
		}
		if f.Affected != model.ApplicabilityNotAffected {
			top = append(top, scored{id: f.FindingID, score: f.RiskScore})
		}
	}
	sort.SliceStable(top, func(i, j int) bool { return top[i].score > top[j].score })
	for i := 0; i < len(top) && i < 5; i++ {
		s.TopRisk = append(s.TopRisk, top[i].id)
	}
	for _, sev := range []string{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityNone, model.SeverityUnknown} {
		if _, ok := s.BySeverity[sev]; !ok {
			s.BySeverity[sev] = 0
		}
	}
	return s
}

func normalizeSeverity(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical", "high", "medium", "low", "none":
		return strings.ToLower(sev)
	default:
		return model.SeverityUnknown
	}
}

func computeDelta(prev *model.RunRecord, findings []model.Finding) *model.Delta {
	current := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		if f.Affected == model.ApplicabilityNotAffected {
			continue
		}
		current[fingerprint(f)] = struct{}{}
	}
	previous := make(map[string]struct{}, len(prev.FindingIDs))
	for _, id := range prev.FindingIDs {
		previous[id] = struct{}{}
	}
	d := &model.Delta{PreviousReportID: prev.ID}
	for fp := range current {
		if _, ok := previous[fp]; !ok {
			d.NewFindings = append(d.NewFindings, fp)
		}
	}
	for fp := range previous {
		if _, ok := current[fp]; !ok {
			d.ResolvedFindings = append(d.ResolvedFindings, fp)
		}
	}
	sort.Strings(d.NewFindings)
	sort.Strings(d.ResolvedFindings)
	return d
}

// FindingID returns the stable identity of a finding. It is used for history,
// delta comparison and as the URL identifier in the HTTP API, so it must not
// depend on report-local numbering.
func FindingID(f model.Finding) string { return fingerprint(f) }

// fingerprint is the stable identity used for history/delta comparison. It must
// not include report-local data such as finding ids or timestamps.
func fingerprint(f model.Finding) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		strings.ToLower(f.Ecosystem), strings.ToLower(f.Product), f.InstalledVersion, f.VulnerabilityID,
	}, "\x00")))
	return hex.EncodeToString(h[:8])
}

// FindingFingerprints returns the stable fingerprints for a finding set; the
// run history stores these so deltas survive re-numbering.
func FindingFingerprints(findings []model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Affected == model.ApplicabilityNotAffected {
			continue
		}
		out = append(out, fingerprint(f))
	}
	sort.Strings(out)
	return out
}

func newID(host string, started time.Time) string {
	if started.IsZero() {
		started = time.Now().UTC()
	}
	h := sha256.Sum256([]byte(host + started.UTC().Format(time.RFC3339Nano)))
	return "SCAN-" + started.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(h[:4])
}

// Render writes the report in the requested format.
//
// Supported: json, markdown (md), sarif, html.
func Render(w io.Writer, rep model.Report, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		return renderJSON(w, rep)
	case "markdown", "md":
		return renderMarkdown(w, rep)
	case "sarif":
		return renderSARIF(w, rep)
	case "html":
		return renderHTML(w, rep)
	default:
		return fmt.Errorf("unsupported format %q (use json, markdown, sarif or html)", format)
	}
}

// ExitCode maps an assessment onto the documented CLI exit codes.
//
//	0 - completed, nothing above the policy threshold
//	2 - completed, findings above the threshold
//	3 - configuration error
//	4 - incomplete assessment (feed/collection failures that reduce coverage)
func ExitCode(rep model.Report, incomplete bool) int {
	if incomplete {
		return 4
	}
	if rep.Metadata.Policy.FailOnSeverity == "" && !rep.Metadata.Policy.FailOnKEV {
		return 0
	}
	threshold := severityRank(rep.Metadata.Policy.FailOnSeverity)
	for _, f := range rep.Findings {
		if f.Affected == model.ApplicabilityNotAffected || f.Affected == model.ApplicabilityNeedsInvestigation {
			continue
		}
		if rep.Metadata.Policy.FailOnKEV && f.CISAKEV {
			return 2
		}
		if threshold > 0 && severityRank(f.Severity) >= threshold {
			return 2
		}
	}
	return 0
}

var severityRanks = map[string]int{
	model.SeverityUnknown: 0, model.SeverityNone: 1, model.SeverityLow: 2,
	model.SeverityMedium: 3, model.SeverityHigh: 4, model.SeverityCritical: 5,
}

func severityRank(s string) int {
	return severityRanks[normalizeSeverity(s)]
}

// MarshalJSON is provided for callers that need the exact bytes stored in the
// run history.
func MarshalJSON(rep model.Report) ([]byte, error) {
	return json.MarshalIndent(rep, "", "  ")
}
