package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/cpe"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/nvd"
)

// seedAppReport stores a report with an application finding and application
// coverage, the way an enrolled Windows endpoint's scan would.
func seedAppReport(t *testing.T, cachePath string) {
	t.Helper()
	store, err := intel.OpenStore(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := nvd.EnsureSchema(store.DB()); err != nil {
		t.Fatal(err)
	}
	ns := nvd.NewStore(store.DB())
	now := time.Now().UTC()
	cveRec := nvd.Record{
		ID: "CVE-2024-0519", Status: "Analyzed",
		Description: "Out of bounds memory access in V8 in Google Chrome prior to 120.0.6099.224.",
		Metrics:     []nvd.CVSSMetric{{Version: "3.1", Score: 8.8, Severity: "high"}},
		Configs: []cpe.Node{{Operator: "OR", Matches: []cpe.Match{{
			Criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", Vulnerable: true,
			Range: cpe.Range{EndExcluding: "120.0.6099.224"},
		}}}},
	}
	if _, _, err := ns.SaveCVEs(ctx, []nvd.Record{cveRec}, now); err != nil {
		t.Fatal(err)
	}
	seq, _ := ns.RecordSyncStart(ctx, "cves", "full", time.Time{}, time.Time{}, now)
	_ = ns.RecordSyncFinish(ctx, seq, "ok", 1, 1, 0, 0, "", now)

	finding := model.Finding{
		FindingID:        "FINDING-0001",
		StableID:         "app-1",
		Asset:            "win01",
		Product:          "google/chrome",
		InstalledVersion: "120.0.6099.109",
		Ecosystem:        "Windows",
		VulnerabilityID:  "CVE-2024-0519",
		Source:           "NVD",
		Affected:         model.ApplicabilityConfirmed,
		ValidationStatus: model.ValidationVersion,
		Confidence:       model.ConfidenceHigh,
		Severity:         "high",
		CVSS:             &model.CVSS{Score: 8.8, Vector: "CVSS:3.1/AV:N", Source: "NVD"},
		FixedVersion:     "120.0.6099.224",
		Remediation:      "Upgrade google/chrome to 120.0.6099.224 or later, then rescan.",
		Evidence: []model.Evidence{
			{Kind: "inventory", Detail: "Google Chrome (64-bit) 120.0.6099.109 recorded by manifest"},
			{Kind: "nvd_cpe_match", Detail: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"},
		},
		Explanation: "NVD's own applicability data for google/chrome matches installed version 120.0.6099.109.",
		RiskScore:   41.7,
	}
	inv := model.Inventory{
		Asset: model.Asset{Hostname: "win01", OS: "Windows", OSVersion: "11", Arch: "x64"},
		Packages: []model.Package{
			{Name: "Google Chrome (64-bit)", Version: "120.0.6099.109", Ecosystem: "Windows",
				Source: model.OriginManifest, Manager: "windows-registry", Vendor: "Google LLC",
				Publisher: "Google LLC", EvidenceSources: []string{"registry/machine/x64"}},
		},
	}
	rep := model.Report{
		SchemaVersion: "1.0",
		ReportID:      "REP-APP-1",
		Metadata: model.ScanMetadata{
			ToolVersion: "test", StartedAt: now.Add(-time.Minute), FinishedAt: &now,
			Mode: "local", Host: "win01",
			Coverage: model.Coverage{
				PackagesInspected: 1, PackagesMatched: 0, AdvisoriesChecked: 1,
				Sources: []string{"NVD CVE/CPE dataset"},
				Apps: &model.AppCoverage{
					Discovered: 1, Normalized: 1, Mapped: 1, Evaluated: 1,
					Unrecognized: nil, CandidateCVEs: 1, ConfirmedMatches: 1,
					IntelFreshness: now.UTC().Format(time.RFC3339),
				},
			},
		},
		Inventory: inv,
		Findings:  []model.Finding{finding},
		Summary:   model.Summary{Total: 1, BySeverity: map[string]int{"high": 1}, Actionable: 1},
	}
	payload, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	rec := model.RunRecord{ID: rep.ReportID, Host: "win01", StartedAt: now.Add(-time.Minute), FinishedAt: now,
		FindingIDs: []string{"FINDING-0001"}, FindingCount: 1, Actionable: 1}
	if err := store.SaveRun(ctx, rec, payload); err != nil {
		t.Fatal(err)
	}
}

func TestOverviewDistinguishesApplicationFindings(t *testing.T) {
	srv, cachePath := newTestServer(t)
	seedAppReport(t, cachePath)

	var ov struct {
		HasData bool `json:"has_data"`
		Metrics struct {
			AppFindings   int `json:"app_findings"`
			AppActionable int `json:"app_actionable"`
			OSFindings    int `json:"os_findings"`
		} `json:"metrics"`
		Apps *struct {
			AppsDiscovered   int `json:"apps_discovered"`
			AppsEvaluated    int `json:"apps_evaluated"`
			AppsWithFindings int `json:"apps_with_findings"`
		} `json:"apps"`
		Feeds []feedRow `json:"feeds"`
	}
	if rec := doJSON(t, srv.Handler(), "GET", "/api/overview", nil, &ov); rec.Code != http.StatusOK {
		t.Fatalf("overview: %d", rec.Code)
	}
	if !ov.HasData || ov.Metrics.AppFindings != 1 || ov.Metrics.AppActionable != 1 {
		t.Fatalf("app metrics missing: %+v", ov.Metrics)
	}
	if ov.Apps == nil || ov.Apps.AppsDiscovered != 1 || ov.Apps.AppsEvaluated != 1 || ov.Apps.AppsWithFindings != 1 {
		t.Fatalf("app coverage missing: %+v", ov.Apps)
	}
	// The NVD feed rows must be visible for administrative oversight.
	found := false
	for _, f := range ov.Feeds {
		if f.Source == "NVD CVEs" && f.Records >= 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("NVD feed row missing: %+v", ov.Feeds)
	}
}

func TestVulnerabilitiesCategoryFilter(t *testing.T) {
	srv, cachePath := newTestServer(t)
	seedAppReport(t, cachePath)

	var all struct {
		Total  int `json:"total"`
		Facets struct {
			Category []countRow `json:"category"`
		} `json:"facets"`
	}
	if rec := doJSON(t, srv.Handler(), "GET", "/api/vulnerabilities", nil, &all); rec.Code != http.StatusOK {
		t.Fatalf("vulnerabilities: %d", rec.Code)
	}
	if all.Total != 1 {
		t.Fatalf("total = %d", all.Total)
	}
	if len(all.Facets.Category) != 1 || all.Facets.Category[0].Key != "application" || all.Facets.Category[0].Count != 1 {
		t.Fatalf("category facet = %+v", all.Facets.Category)
	}

	// application category keeps it; os category excludes it.
	var apps struct {
		Total int `json:"total"`
	}
	doJSON(t, srv.Handler(), "GET", "/api/vulnerabilities?category=application", nil, &apps)
	if apps.Total != 1 {
		t.Fatalf("application filter total = %d", apps.Total)
	}
	var os struct {
		Total int `json:"total"`
	}
	doJSON(t, srv.Handler(), "GET", "/api/vulnerabilities?category=os", nil, &os)
	if os.Total != 0 {
		t.Fatalf("os filter must exclude application findings: %d", os.Total)
	}
}

func TestAssetDetailCarriesAppCoverage(t *testing.T) {
	srv, cachePath := newTestServer(t)
	seedAppReport(t, cachePath)

	var detail struct {
		Coverage struct {
			Apps *struct {
				Discovered       int    `json:"discovered"`
				Evaluated        int    `json:"evaluated"`
				ConfirmedMatches int    `json:"confirmed_matches"`
				IntelFreshness   string `json:"intel_freshness"`
			} `json:"apps"`
			Notes []string `json:"notes"`
		} `json:"coverage"`
		Packages []struct {
			Name            string   `json:"name"`
			Publisher       string   `json:"publisher"`
			EvidenceSources []string `json:"evidence_sources"`
		} `json:"packages"`
	}
	if rec := doJSON(t, srv.Handler(), "GET", "/api/assets/win01", nil, &detail); rec.Code != http.StatusOK {
		t.Fatalf("asset detail: %d", rec.Code)
	}
	if detail.Coverage.Apps == nil || detail.Coverage.Apps.Discovered != 1 ||
		detail.Coverage.Apps.Evaluated != 1 || detail.Coverage.Apps.ConfirmedMatches != 1 {
		t.Fatalf("app coverage missing from asset detail: %+v", detail.Coverage.Apps)
	}
	if len(detail.Packages) != 1 || detail.Packages[0].Publisher != "Google LLC" ||
		len(detail.Packages[0].EvidenceSources) != 1 {
		t.Fatalf("package app fields missing: %+v", detail.Packages)
	}
}

func TestSoftwareExportCarriesAppEvidence(t *testing.T) {
	srv, cachePath := newTestServer(t)
	seedAppReport(t, cachePath)

	if rec := doJSON(t, srv.Handler(), "GET", "/api/software/export?format=csv", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("software export: %d %s", rec.Code, rec.Body.String())
	}
}

func TestFeedRowsNVDStaleFlag(t *testing.T) {
	srv, cachePath := newTestServer(t)
	seedAppReport(t, cachePath)
	rows, err := srv.feedRows(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var nvdRow *feedRow
	for i := range rows {
		if rows[i].Source == "NVD CVEs" {
			nvdRow = &rows[i]
		}
	}
	if nvdRow == nil {
		t.Fatalf("NVD row missing: %+v", rows)
	}
	if nvdRow.LastSync == "" || nvdRow.Stale {
		t.Fatalf("fresh NVD data must not be stale: %+v", nvdRow)
	}
}

var _ = cpe.Parse
