package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// Software asset inventory export.
//
// A findings report answers "what can hurt me"; the inventory answers "what is
// installed", which is the question an asset register, a CMDB import or a
// procurement/licence review starts from. It is deliberately one row per package
// per host so it can be filtered, joined and diffed like any other asset list —
// the same data a CycloneDX SBOM carries, in the format those teams actually use.
//
// The two assessment columns (known_findings, max_severity) are derived from the
// same report by matching package+version+ecosystem, so a row also shows which
// installed software has known issues. They are counts, not a risk verdict:
// applicability still lives in the report.

// InventoryColumns is the CSV header. Order is part of the contract; tests pin it.
var InventoryColumns = []string{
	"host",
	"os",
	"os_version",
	"kernel",
	"arch",
	"ecosystem",
	"manager",
	"package",
	"version",
	"release",
	"vendor",
	"origin",
	"purl",
	"source",
	"privileges_required",
	"known_findings",
	"max_severity",
	"report_id",
	"scanned_at",
}

// SoftwareInventoryCSV renders one row per installed package for every report
// given, sorted by host then package, so repeated exports diff cleanly.
func SoftwareInventoryCSV(reports []model.Report) ([]byte, error) {
	type row struct {
		host  string
		name  string
		ver   string
		cells []string
	}
	rows := make([]row, 0, 128)

	for _, rep := range reports {
		asset := rep.Inventory.Asset
		host := firstNonEmpty(asset.Hostname, rep.Metadata.Host, "unknown")
		scanned := rep.Inventory.CollectedAt
		if scanned.IsZero() {
			if rep.Metadata.FinishedAt != nil {
				scanned = *rep.Metadata.FinishedAt
			} else {
				scanned = rep.Metadata.StartedAt
			}
		}
		findings := indexFindings(rep)

		for _, p := range rep.Inventory.Packages {
			sev := "none"
			count := 0
			if f, ok := findings[findingKey(p.Ecosystem, p.Name, p.Version)]; ok {
				sev = f.maxSeverity
				count = f.count
			}
			rows = append(rows, row{
				host: host,
				name: p.Name,
				ver:  p.Version,
				cells: []string{
					host,
					asset.OS,
					asset.OSVersion,
					asset.Kernel,
					firstNonEmpty(p.Arch, asset.Arch),
					p.Ecosystem,
					p.Manager,
					p.Name,
					p.Version,
					p.Release,
					p.Vendor,
					p.Origin,
					p.PURL,
					string(p.Source),
					boolCell(p.NeedsPrivileges),
					fmt.Sprintf("%d", count),
					sev,
					rep.ReportID,
					formatTime(scanned),
				},
			})
		}
	}

	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].host != rows[j].host {
			return rows[i].host < rows[j].host
		}
		if rows[i].name != rows[j].name {
			return rows[i].name < rows[j].name
		}
		return rows[i].ver < rows[j].ver
	})

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(InventoryColumns); err != nil {
		return nil, err
	}
	for _, r := range rows {
		if err := w.Write(neutralise(r.cells)); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type findingStats struct {
	count       int
	maxSeverity string
}

func indexFindings(rep model.Report) map[string]findingStats {
	out := make(map[string]findingStats, len(rep.Findings))
	for _, f := range rep.Findings {
		key := findingKey(f.Ecosystem, f.Product, f.InstalledVersion)
		cur, ok := out[key]
		if !ok {
			cur = findingStats{maxSeverity: model.SeverityUnknown}
		}
		cur.count++
		// An unrecognised severity is reported as "unknown" rather than guessed.
		sev := normalizeSeverity(f.Severity)
		if severityRank(sev) > severityRank(cur.maxSeverity) {
			cur.maxSeverity = sev
		}
		out[key] = cur
	}
	return out
}

func findingKey(ecosystem, name, version string) string {
	return strings.ToLower(ecosystem) + "\x00" + strings.ToLower(name) + "\x00" + version
}

func boolCell(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// neutralise defuses spreadsheet formula injection.
//
// Package names, file paths and hostnames come from the scanned system or from an SBOM that
// someone else produced. A cell beginning with =, +, - or @ is executed by Excel and Sheets,
// so a crafted package name ("=HYPERLINK(...)") becomes a live formula the moment the
// inventory export is opened. Prefixing a single quote is the standard, visible-only fix:
// the text is unchanged for a reader who is not using a spreadsheet.
func neutralise(cells []string) []string {
	out := make([]string, len(cells))
	for i, c := range cells {
		trimmed := strings.TrimLeft(c, " \t\r\n")
		if trimmed == "" {
			out[i] = c
			continue
		}
		switch trimmed[0] {
		case '=', '+', '-', '@', '\t', '\r':
			out[i] = "'" + c
		default:
			out[i] = c
		}
	}
	return out
}
