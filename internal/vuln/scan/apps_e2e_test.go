package scan

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/cpe"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/inventory"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/nvd"
)

// windowsFixtureCollector replays a real Windows 11 inventory without needing
// a Windows host: registry uninstall entries plus servicing state.
type windowsFixtureCollector struct {
	chromeVersion string
}

func (c *windowsFixtureCollector) Name() string { return "windows_fixture" }

func (c *windowsFixtureCollector) Collect(ctx context.Context, opts inventory.Options) ([]model.Package, error) {
	return []model.Package{
		{
			Name: "Google Chrome (64-bit)", Version: c.chromeVersion,
			Ecosystem: model.EcosystemWindows, Source: model.OriginManifest,
			Manager: "windows-registry", Vendor: "Google LLC", Arch: "x64",
		},
		{
			Name: "Some Internal Tool 1.0", Version: "1.0",
			Ecosystem: model.EcosystemWindows, Source: model.OriginManifest,
			Manager: "windows-registry", Vendor: "ACME Corp",
		},
	}, nil
}

func (c *windowsFixtureCollector) CollectState(ctx context.Context, opts inventory.Options) (model.WindowsState, error) {
	return model.WindowsState{
		Product:         "Windows 11 Pro",
		DisplayVersion:  "23H2",
		Build:           "10.0.22631.3155",
		Edition:         "Professional",
		WUAStatus:       "unavailable: fixture host has no update service",
		CollectorStatus: map[string]string{"identity": "ok"},
	}, nil
}

// seedNVDCache seeds the local NVD store the way `feeds update --with-nvd` would.
func seedNVDCache(t *testing.T, cachePath string) {
	t.Helper()
	store, err := intel.OpenStore(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := nvd.EnsureSchema(store.DB()); err != nil {
		t.Fatal(err)
	}
	ns := nvd.NewStore(store.DB())
	now := time.Now().UTC()
	cfg := cpe.Node{Operator: "OR", Matches: []cpe.Match{
		{
			Criteria:        "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
			MatchCriteriaID: "mc-1", Vulnerable: true,
			Range: cpe.Range{EndExcluding: "120.0.6099.224"},
		},
		{
			Criteria:        "cpe:2.3:a:google:chrome:120.0.6099.224:*:*:*:*:*:*:*",
			MatchCriteriaID: "mc-2", Vulnerable: false,
		},
	}}
	rec := nvd.Record{
		ID: "CVE-2024-0519", Status: "Analyzed",
		Description: "Out of bounds memory access in V8 in Google Chrome prior to 120.0.6099.224.",
		Metrics:     []nvd.CVSSMetric{{Version: "3.1", Score: 8.8, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Severity: "high", Type: "Primary"}},
		Configs:     []cpe.Node{cfg},
	}
	if _, _, err := ns.SaveCVEs(ctx2(), []nvd.Record{rec}, now); err != nil {
		t.Fatal(err)
	}
	seq, err := ns.RecordSyncStart(ctx2(), "cves", "full", time.Time{}, time.Time{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := ns.RecordSyncFinish(ctx2(), seq, "ok", 1, 1, 0, 0, "", now); err != nil {
		t.Fatal(err)
	}
}

func ctx2() context.Context { return context.Background() }

func TestWindowsApplicationEndToEnd(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "intel.db")
	seedNVDCache(t, cachePath)

	// --- vulnerable scan ----------------------------------------------------
	res, err := Run(context.Background(), Options{
		Collectors: []inventory.Collector{&windowsFixtureCollector{chromeVersion: "120.0.6099.109"}},
		CachePath:  cachePath,
		Offline:    true,
		Format:     "json",
		OutputPath: filepath.Join(t.TempDir(), "report1.json"),
		Now:        func() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) },
		Stderr:     io_Discard{},
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	var found *model.Finding
	for i := range res.Report.Findings {
		if res.Report.Findings[i].VulnerabilityID == "CVE-2024-0519" {
			found = &res.Report.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("expected CVE-2024-0519 for vulnerable Chrome, got %d findings: %+v",
			len(res.Report.Findings), res.Report.Findings)
	}
	if found.Affected != model.ApplicabilityConfirmed || found.Confidence != model.ConfidenceHigh {
		t.Fatalf("finding state: %s/%s", found.Affected, found.Confidence)
	}
	if found.FixedVersion != "120.0.6099.224" {
		t.Fatalf("fixed version: %q", found.FixedVersion)
	}
	if found.Remediation == "" {
		t.Fatal("remediation must be present")
	}
	// Coverage must say what happened, including the unmapped internal tool.
	cov := res.Report.Metadata.Coverage.Apps
	if cov == nil {
		t.Fatal("application coverage must be present in the report")
	}
	if cov.Discovered != 2 || cov.Evaluated != 1 || cov.Mapped != 1 || len(cov.Unrecognized) != 1 {
		t.Fatalf("coverage: %+v", cov)
	}
	if cov.ConfirmedMatches != 1 {
		t.Fatalf("confirmed matches: %+v", cov)
	}
	// The assessment must not pretend to be complete for apps without NVD
	// intelligence checks... it has them. And the unrecognized app must be
	// named in the limitations.
	covered := false
	for _, l := range res.Report.Metadata.Coverage.Limitations {
		if containsStr(l, "Some Internal Tool") {
			covered = true
		}
	}
	if !covered {
		t.Fatalf("unrecognized application must be visible in limitations: %v", res.Report.Metadata.Coverage.Limitations)
	}

	// --- patched rescan ------------------------------------------------------
	res2, err := Run(context.Background(), Options{
		Collectors: []inventory.Collector{&windowsFixtureCollector{chromeVersion: "120.0.6099.224"}},
		CachePath:  cachePath,
		Offline:    true,
		Format:     "json",
		OutputPath: filepath.Join(t.TempDir(), "report2.json"),
		Now:        func() time.Time { return time.Date(2026, 11, 13, 13, 0, 0, 0, time.UTC) },
		Stderr:     io_Discard{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res2.Report.Findings {
		if f.VulnerabilityID == "CVE-2024-0519" {
			t.Fatalf("patched Chrome must not produce CVE-2024-0519: %+v", f)
		}
	}
	if res2.Report.Delta == nil || len(res2.Report.Delta.ResolvedFindings) == 0 {
		t.Fatalf("upgrading the application must resolve the previous finding: %+v", res2.Report.Delta)
	}
	if res2.ExitCode != 0 {
		t.Fatalf("patched run should exit 0, got %d", res2.ExitCode)
	}
}

func TestWindowsApplicationMissingNVDIntelligenceIsVisible(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "intel.db") // empty: never synced
	res, err := Run(context.Background(), Options{
		Collectors: []inventory.Collector{&windowsFixtureCollector{chromeVersion: "120.0.6099.109"}},
		CachePath:  cachePath,
		Offline:    true,
		Format:     "json",
		OutputPath: filepath.Join(t.TempDir(), "report.json"),
		Now:        func() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) },
		Stderr:     io_Discard{},
	})
	if err != nil {
		t.Fatal(err)
	}
	cov := res.Report.Metadata.Coverage.Apps
	if cov == nil || cov.Evaluated != 0 {
		t.Fatalf("without NVD intelligence nothing may be evaluated: %+v", cov)
	}
	found := false
	for _, l := range res.Report.Metadata.Coverage.Limitations {
		if containsStr(l, "NOT evaluated") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing-intelligence limitation required: %v", res.Report.Metadata.Coverage.Limitations)
	}
}

func containsStr(s, sub string) bool {
	return len(sub) <= len(s) && (s == sub || indexOfStr(s, sub) >= 0)
}

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
