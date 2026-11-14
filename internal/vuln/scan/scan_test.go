package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/inventory"
	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// fixtureRoot builds a fake endpoint: an Ubuntu os-release plus a dpkg status
// with one vulnerable and one fixed package. No network and no real host data
// are involved, so this test is safe to run anywhere.
func fixtureRoot(t *testing.T, vulnerable bool) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"etc", "var/lib/dpkg"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	osRelease := `PRETTY_NAME="Ubuntu 24.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
`
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(osRelease), 0o644); err != nil {
		t.Fatal(err)
	}
	version := "3.0.11-0ubuntu3.1"
	if !vulnerable {
		version = "3.0.13-0ubuntu3.9"
	}
	status := "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nSource: openssl\nVersion: " + version + "\n" +
		"\nPackage: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.2.21-2ubuntu4\n"
	if err := os.WriteFile(filepath.Join(root, "var/lib/dpkg/status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// seedCache writes an Ubuntu advisory plus KEV/EPSS records, i.e. the state a
// user has after `clanker vuln feeds update --with-osv`.
func seedCache(t *testing.T, cachePath string) {
	t.Helper()
	store, err := intel.OpenStore(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	adv := intel.Advisory{
		ID:     "UBUNTU-CVE-2026-0001",
		Source: "Ubuntu",
		Affected: []intel.Affected{{
			Ecosystem: "Ubuntu:24.04:LTS",
			Name:      "openssl",
			Versions:  []string{"3.0.11-0ubuntu3.1", "3.0.11-0ubuntu3.2"},
			Ranges:    []intel.Range{{Type: "ECOSYSTEM", Events: []intel.Event{{Introduced: "0"}}}},
		}},
		Severities: []intel.SeverityEntry{{Type: "Ubuntu", Score: "high"}},
		References: []intel.Reference{{Type: "ADVISORY", URL: "https://ubuntu.com/security/CVE-2026-0001"}},
		FetchedAt:  time.Now().UTC(),
	}
	if err := store.SaveAdvisories(ctx, []intel.Advisory{adv}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveKEV(ctx, []intel.KEVEntry{{CVEID: "CVE-2026-0001", DateAdded: "2026-11-01", Name: "openssl test"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveEPSS(ctx, []intel.EPSSEntry{{CVE: "CVE-2026-0001", Score: 0.7, Percentile: 0.99}}, 10); err != nil {
		t.Fatal(err)
	}
}

func TestRunEndToEndOffline(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "intel.db")
	seedCache(t, cachePath)
	out := filepath.Join(t.TempDir(), "report.json")

	res, err := Run(context.Background(), Options{
		Root:       fixtureRoot(t, true),
		Collectors: []inventory.Collector{&inventory.OSPackageCollector{}},
		CachePath:  cachePath,
		Offline:    true,
		Format:     "json",
		OutputPath: out,
		Policy:     model.Policy{FailOnSeverity: "high"},
		Now:        func() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) },
		Stderr:     io_Discard{},
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(res.Report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Report.Findings))
	}
	f := res.Report.Findings[0]
	if f.Asset == "" {
		t.Fatal("finding is missing the asset identifier")
	}
	if f.VulnerabilityID != "CVE-2026-0001" || f.Affected != model.ApplicabilityConfirmed {
		t.Fatalf("unexpected finding: %+v", f)
	}
	if !f.CISAKEV || f.EPSS == nil {
		t.Fatalf("enrichment missing: kev=%v epss=%+v", f.CISAKEV, f.EPSS)
	}
	if res.ExitCode != 2 {
		t.Fatalf("expected policy exit code 2, got %d", res.ExitCode)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("report not written: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	if doc["schema_version"] != "1.0" {
		t.Fatalf("unexpected schema version: %v", doc["schema_version"])
	}

	// A second run must produce a delta against the stored history.
	res2, err := Run(context.Background(), Options{
		Root:       fixtureRoot(t, false), // patched
		Collectors: []inventory.Collector{&inventory.OSPackageCollector{}},
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
	if len(res2.Report.Findings) != 0 {
		t.Fatalf("patched fixture should have no actionable findings, got %+v", res2.Report.Findings)
	}
	if res2.Report.Delta == nil || len(res2.Report.Delta.ResolvedFindings) != 1 {
		t.Fatalf("expected the previous finding to be reported resolved: %+v", res2.Report.Delta)
	}
	if res2.ExitCode != 0 {
		t.Fatalf("clean run should exit 0, got %d", res2.ExitCode)
	}
}

func TestRunRefusesEmptyInventory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Run(context.Background(), Options{
		Root:       root,
		Collectors: []inventory.Collector{&inventory.OSPackageCollector{}},
		CachePath:  filepath.Join(t.TempDir(), "intel.db"),
		Offline:    true,
		Stderr:     io_Discard{},
	})
	if err == nil {
		t.Fatal("an empty inventory must be an error: a scan with no packages cannot be reported as clean")
	}
}

// io_Discard keeps the tests quiet without importing io/os in each case.
type io_Discard struct{}

func (io_Discard) Write(p []byte) (int, error) { return len(p), nil }

// TestRunAbortsWhenCancelled covers the cancellation defect found by the
// Playwright suite: a cancelled scan must return an error and must not write a
// report, which would otherwise become the newest baseline for the host.
func TestRunAbortsWhenCancelled(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "intel.db")
	seedCache(t, cachePath)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the work starts

	_, err := Run(ctx, Options{
		Root:       fixtureRoot(t, true),
		CachePath:  cachePath,
		Offline:    true,
		Format:     "json",
		OutputPath: filepath.Join(t.TempDir(), "report.json"),
		Collectors: []inventory.Collector{&inventory.OSPackageCollector{}},
		Stderr:     io_Discard{},
	})
	if err == nil {
		t.Fatal("a cancelled scan must return an error, not a report")
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("error should say the run was cancelled, got %v", err)
	}

	store, openErr := intel.OpenStore(cachePath)
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer store.Close()
	runs, listErr := store.ListRuns(context.Background(), 10)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(runs) != 0 {
		t.Fatalf("a cancelled scan must not be stored as an assessment, found %d", len(runs))
	}
}
