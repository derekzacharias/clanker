package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

func renderJSON(w io.Writer, rep model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// ---------------------------------------------------------------- markdown ---

func renderMarkdown(w io.Writer, rep model.Report) error {
	b := &strings.Builder{}
	fmt.Fprintf(b, "# Clanker Guard assessment — %s\n\n", valueOr(rep.Metadata.Host, "unknown host"))
	fmt.Fprintf(b, "- Report ID: `%s`\n", rep.ReportID)
	fmt.Fprintf(b, "- Tool: clanker-guard %s (schema %s)\n", valueOr(rep.Metadata.ToolVersion, "dev"), rep.SchemaVersion)
	fmt.Fprintf(b, "- Mode: %s\n", valueOr(rep.Metadata.Mode, "local"))
	fmt.Fprintf(b, "- Started: %s\n", rep.Metadata.StartedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	if rep.Metadata.FinishedAt != nil {
		fmt.Fprintf(b, "- Finished: %s\n", rep.Metadata.FinishedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	fmt.Fprintf(b, "- Asset: %s %s (%s, %s)\n", rep.Inventory.Asset.OS, rep.Inventory.Asset.OSVersion,
		valueOr(rep.Inventory.Asset.Arch, "arch unknown"), valueOr(rep.Inventory.Asset.Kernel, "kernel unknown"))
	fmt.Fprintf(b, "- Intelligence: %s\n", offlineLabel(rep.Metadata.Offline))
	fmt.Fprintf(b, "- Packages inspected: %d\n\n", rep.Metadata.Coverage.PackagesInspected)

	// Executive summary
	b.WriteString("## Executive summary\n\n")
	s := rep.Summary
	fmt.Fprintf(b, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(b, "| Findings (actionable) | %d |\n", s.Actionable)
	fmt.Fprintf(b, "| Critical / High / Medium / Low | %d / %d / %d / %d |\n",
		s.BySeverity[model.SeverityCritical], s.BySeverity[model.SeverityHigh],
		s.BySeverity[model.SeverityMedium], s.BySeverity[model.SeverityLow])
	fmt.Fprintf(b, "| CISA KEV | %d |\n", s.KEVCount)
	fmt.Fprintf(b, "| Needs investigation | %d |\n", s.ByAffected[string(model.ApplicabilityNeedsInvestigation)])
	fmt.Fprintf(b, "| Checked and not affected | %d |\n\n", s.NotAffected)

	b.WriteString("> A completed scan means the listed sources were consulted for the listed packages. ")
	b.WriteString("It does **not** mean the asset is free of vulnerabilities: see coverage and limitations below.\n\n")

	// Coverage
	b.WriteString("## Coverage\n\n")
	fmt.Fprintf(b, "- Packages in inventory: %d\n", len(rep.Inventory.Packages))
	fmt.Fprintf(b, "- Sources consulted: %s\n", strings.Join(rep.Metadata.Coverage.Sources, ", "))
	if len(rep.Metadata.Coverage.NotCovered) > 0 {
		fmt.Fprintf(b, "- Not covered: %s\n", strings.Join(rep.Metadata.Coverage.NotCovered, "; "))
	}
	if len(rep.Metadata.Coverage.Limitations) > 0 {
		fmt.Fprintf(b, "- Limitations: %s\n", strings.Join(rep.Metadata.Coverage.Limitations, "; "))
	}
	if len(rep.Inventory.Skipped) > 0 {
		b.WriteString("- Skipped checks:\n")
		for _, sk := range rep.Inventory.Skipped {
			fmt.Fprintf(b, "  - `%s`: %s\n", sk.Check, sk.Reason)
		}
	}
	b.WriteString("\n")

	// Feed freshness
	if len(rep.Metadata.FeedFreshness) > 0 {
		b.WriteString("## Intelligence freshness\n\n| Source | Last sync | Records | Stale |\n|---|---|---|---|\n")
		for _, f := range rep.Metadata.FeedFreshness {
			last := "never"
			if f.LastSync != nil {
				last = f.LastSync.UTC().Format("2006-01-02 15:04")
			}
			fmt.Fprintf(b, "| %s | %s | %d | %t |\n", f.Source, last, f.Records, f.Stale)
		}
		b.WriteString("\n")
	}

	// KEV first: it is the strongest prioritisation signal.
	if s.KEVCount > 0 {
		b.WriteString("## Known exploited (CISA KEV)\n\n")
		for _, f := range rep.Findings {
			if !f.CISAKEV {
				continue
			}
			fmt.Fprintf(b, "- **%s** — %s %s (%s)", f.VulnerabilityID, f.Product, f.InstalledVersion, f.Severity)
			if f.KEV != nil && f.KEV.DateAdded != "" {
				fmt.Fprintf(b, ", added to KEV %s", f.KEV.DateAdded)
			}
			if f.KEV != nil && f.KEV.Ransomware != "" {
				fmt.Fprintf(b, ", ransomware use: %s", f.KEV.Ransomware)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	// Findings by severity
	b.WriteString("## Findings\n\n")
	if len(rep.Findings) == 0 {
		b.WriteString("_No findings in the assessed scope._\n\n")
	}
	grouped := map[string][]model.Finding{}
	for _, f := range rep.Findings {
		grouped[normalizeSeverity(f.Severity)] = append(grouped[normalizeSeverity(f.Severity)], f)
	}
	for _, sev := range []string{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityUnknown, model.SeverityNone} {
		list := grouped[sev]
		if len(list) == 0 {
			continue
		}
		fmt.Fprintf(b, "### %s (%d)\n\n", strings.Title(sev), len(list)) //nolint:staticcheck // simple ASCII title
		for _, f := range list {
			fmt.Fprintf(b, "#### %s — %s %s\n\n", f.VulnerabilityID, f.Product, f.InstalledVersion)
			fmt.Fprintf(b, "| Field | Value |\n|---|---|\n")
			fmt.Fprintf(b, "| Finding | %s |\n", f.FindingID)
			fmt.Fprintf(b, "| Ecosystem | %s |\n", f.Ecosystem)
			fmt.Fprintf(b, "| Source | %s (%s) |\n", f.Source, f.AdvisoryID)
			fmt.Fprintf(b, "| Applicability | %s |\n", f.Affected)
			fmt.Fprintf(b, "| Confidence | %s |\n", f.Confidence)
			fmt.Fprintf(b, "| Severity | %s |\n", f.Severity)
			if f.CVSS != nil {
				fmt.Fprintf(b, "| CVSS | %.1f (%s) |\n", f.CVSS.Score, valueOr(f.CVSS.Vector, "no vector"))
			}
			if f.EPSS != nil {
				fmt.Fprintf(b, "| EPSS | %.3f (%.1f%% percentile) |\n", f.EPSS.Score, f.EPSS.Percentile*100)
			}
			fmt.Fprintf(b, "| Risk score | %.1f |\n", f.RiskScore)
			fmt.Fprintf(b, "| Fixed version | %s |\n", valueOr(f.FixedVersion, "not published"))
			fmt.Fprintf(b, "\n**Why this classification:** %s\n\n", f.Explanation)
			if len(f.Evidence) > 0 {
				b.WriteString("**Evidence**\n\n")
				for _, e := range f.Evidence {
					fmt.Fprintf(b, "- `%s` — %s", e.Kind, e.Detail)
					if e.URL != "" {
						fmt.Fprintf(b, " (%s)", e.URL)
					}
					b.WriteString("\n")
				}
				b.WriteString("\n")
			}
			if len(f.RaiseConfidence) > 0 || len(f.LowerConfidence) > 0 {
				b.WriteString("**What would change this verdict**\n\n")
				for _, r := range f.RaiseConfidence {
					fmt.Fprintf(b, "- raises confidence: %s\n", r)
				}
				for _, r := range f.LowerConfidence {
					fmt.Fprintf(b, "- lowers confidence: %s\n", r)
				}
				b.WriteString("\n")
			}
			fmt.Fprintf(b, "**Remediation:** %s\n\n", f.Remediation)
			if f.VendorAdvisory != nil && f.VendorAdvisory.URL != "" {
				fmt.Fprintf(b, "Vendor advisory: %s\n\n", f.VendorAdvisory.URL)
			}
		}
	}

	// Delta
	if rep.Delta != nil {
		b.WriteString("## Since the previous scan\n\n")
		fmt.Fprintf(b, "- New findings: %d\n", len(rep.Delta.NewFindings))
		fmt.Fprintf(b, "- Resolved findings: %d\n\n", len(rep.Delta.ResolvedFindings))
	}

	// Errors
	if len(rep.Metadata.Errors) > 0 {
		b.WriteString("## Errors and degraded coverage\n\n")
		for _, e := range rep.Metadata.Errors {
			fmt.Fprintf(b, "- %s\n", e)
		}
		b.WriteString("\n")
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// ------------------------------------------------------------------- sarif ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	FullDescription  sarifMessage   `json:"fullDescription,omitempty"`
	Help             sarifMessage   `json:"help,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
	DefaultConfig    map[string]any `json:"defaultConfiguration,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Message      sarifMessage      `json:"message"`
	Locations    []sarifLocation   `json:"locations"`
	Properties   map[string]any    `json:"properties,omitempty"`
	Fingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

func renderSARIF(w io.Writer, rep model.Report) error {
	rules := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range rep.Findings {
		if f.Affected == model.ApplicabilityNotAffected {
			continue
		}
		ruleID := f.VulnerabilityID
		if _, ok := rules[ruleID]; !ok {
			rules[ruleID] = sarifRule{
				ID:               ruleID,
				Name:             sanitizeRuleName(ruleID),
				ShortDescription: sarifMessage{Text: fmt.Sprintf("%s in %s %s", f.VulnerabilityID, f.Product, f.InstalledVersion)},
				FullDescription:  sarifMessage{Text: f.Explanation},
				Help:             sarifMessage{Text: f.Remediation},
				Properties: map[string]any{
					"ecosystem":     f.Ecosystem,
					"applicability": string(f.Affected),
					"confidence":    string(f.Confidence),
					"severity":      f.Severity,
					"cisaKev":       f.CISAKEV,
				},
			}
		}
		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f),
			Message: sarifMessage{Text: fmt.Sprintf("%s %s: %s", f.Product, f.InstalledVersion, f.Explanation)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: "endpoint://" + valueOr(rep.Metadata.Host, "unknown")},
					Region:           sarifRegion{StartLine: 1},
				},
				LogicalLocations: []sarifLogicalLocation{{Name: f.Product + "@" + f.InstalledVersion, Kind: "package"}},
			}},
			Properties: map[string]any{
				"riskScore":     f.RiskScore,
				"fixedVersion":  f.FixedVersion,
				"epss":          epssValue(f),
				"khk":           f.CISAKEV,
				"installedWith": f.Ecosystem,
			},
			Fingerprints: map[string]string{"clankerGuard/v1": fingerprint(f)},
		})
	}
	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "clanker-guard",
				Version:        valueOr(rep.Metadata.ToolVersion, "dev"),
				InformationURI: "https://github.com/bgdnvk/clanker",
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifLevel(f model.Finding) string {
	switch f.Affected {
	case model.ApplicabilityNeedsInvestigation:
		return "note"
	case model.ApplicabilityNotAffected:
		return "none"
	}
	switch normalizeSeverity(f.Severity) {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func epssValue(f model.Finding) *float64 {
	if f.EPSS == nil {
		return nil
	}
	v := f.EPSS.Score
	return &v
}

func sanitizeRuleName(id string) string {
	return strings.NewReplacer("-", "_", ".", "_").Replace(id)
}

// -------------------------------------------------------------------- html ---

var htmlTemplate = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Clanker Guard — {{.Metadata.Host}}</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1f2933;max-width:1100px}
h1{margin-bottom:.2rem} .meta{color:#52606d;font-size:.9rem;margin-bottom:1.5rem}
table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{border:1px solid #d9e2ec;padding:.45rem .6rem;text-align:left;font-size:.9rem;vertical-align:top}
th{background:#f5f7fa}
.badge{display:inline-block;padding:.1rem .45rem;border-radius:3px;font-size:.75rem;font-weight:600;color:#fff}
.critical{background:#7f1d1d}.high{background:#b91c1c}.medium{background:#b45309}.low{background:#166534}.unknown{background:#475569}.none{background:#475569}
.warn{background:#fff7ed;border-left:4px solid #f59e0b;padding:.7rem 1rem;margin:1rem 0}
details{margin:.6rem 0;border:1px solid #e4e7eb;border-radius:4px;padding:.5rem .75rem}
summary{cursor:pointer;font-weight:600}
code{background:#f5f7fa;padding:.1rem .3rem;border-radius:3px}
</style></head><body>
<h1>Clanker Guard assessment</h1>
<div class="meta">
Host <strong>{{.Metadata.Host}}</strong> · {{.Inventory.Asset.OS}} {{.Inventory.Asset.OSVersion}} · mode {{.Metadata.Mode}} ·
tool {{.Metadata.ToolVersion}} · report <code>{{.ReportID}}</code> · {{if .Metadata.Offline}}offline intelligence{{else}}online intelligence{{end}}
</div>

<div class="warn">A completed scan means the listed sources were consulted for {{.Metadata.Coverage.PackagesInspected}} packages.
It does not mean this asset is free of vulnerabilities — review coverage and limitations.</div>

<h2>Summary</h2>
<table><tr><th>Actionable</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>KEV</th><th>Needs investigation</th><th>Not affected</th></tr>
<tr><td>{{.Summary.Actionable}}</td>
<td>{{index .Summary.BySeverity "critical"}}</td><td>{{index .Summary.BySeverity "high"}}</td>
<td>{{index .Summary.BySeverity "medium"}}</td><td>{{index .Summary.BySeverity "low"}}</td>
<td>{{.Summary.KEVCount}}</td>
<td>{{index .Summary.ByAffected "needs_investigation"}}</td><td>{{.Summary.NotAffected}}</td></tr></table>

<h2>Findings</h2>
{{if not .Findings}}<p>No findings in the assessed scope.</p>{{end}}
{{range .Findings}}
<details>
<summary><span class="badge {{.Severity}}">{{.Severity}}</span> {{.VulnerabilityID}} — {{.Product}} {{.InstalledVersion}} <small>({{.Affected}}, confidence {{.Confidence}}, risk {{printf "%.1f" .RiskScore}})</small></summary>
<p><strong>Why:</strong> {{.Explanation}}</p>
<p><strong>Remediation:</strong> {{.Remediation}}</p>
{{if .Evidence}}<p><strong>Evidence</strong></p><ul>{{range .Evidence}}<li><code>{{.Kind}}</code> {{.Detail}} {{if .URL}}<a href="{{.URL}}">advisory</a>{{end}}</li>{{end}}</ul>{{end}}
{{if .FixedVersion}}<p><strong>Fixed version:</strong> {{.FixedVersion}}</p>{{end}}
</details>
{{end}}

<h2>Coverage and limitations</h2>
<ul>
<li>Packages in inventory: {{len .Inventory.Packages}}</li>
<li>Sources: {{range .Metadata.Coverage.Sources}}<code>{{.}}</code> {{end}}</li>
{{range .Metadata.Coverage.NotCovered}}<li>Not covered: {{.}}</li>{{end}}
{{range .Metadata.Coverage.Limitations}}<li>Limitation: {{.}}</li>{{end}}
{{range .Metadata.SkippedChecks}}<li>Skipped <code>{{.Check}}</code>: {{.Reason}}</li>{{end}}
</ul>
</body></html>`))

func renderHTML(w io.Writer, rep model.Report) error {
	return htmlTemplate.Execute(w, rep)
}
