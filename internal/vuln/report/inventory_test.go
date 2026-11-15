package report

import (
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

func inventoryFixture() model.Report {
	finished := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	return model.Report{
		ReportID: "SCAN-20261115T120000Z-aaaa1111",
		Metadata: model.ScanMetadata{
			ToolVersion: "0.1.1",
			StartedAt:   finished.Add(-90 * time.Second),
			FinishedAt:  &finished,
			Mode:        "local",
			Host:        "web01",
		},
		Inventory: model.Inventory{
			Asset:       model.Asset{Hostname: "web01", OS: "Ubuntu", OSVersion: "24.04", Kernel: "6.8.0-40", Arch: "amd64"},
			CollectedAt: finished.Add(-80 * time.Second),
			Packages: []model.Package{
				{Name: "openssl", Version: "3.0.13-1", Ecosystem: "Ubuntu:24.04", Arch: "amd64", Source: model.OriginDpkg,
					Manager: "apt", Vendor: "ubuntu", Origin: "openssl", Release: "1ubuntu1", PURL: "pkg:deb/ubuntu/openssl@3.0.13-1"},
				{Name: "zlib1g", Version: "1:1.3.dfsg-3", Ecosystem: "Ubuntu:24.04", Arch: "amd64", Source: model.OriginDpkg},
				// A comma and a quote prove the writer quotes instead of mangling rows.
				{Name: `weird,pkg"name`, Version: "1.0", Ecosystem: "npm", Source: model.OriginNpm, NeedsPrivileges: true},
			},
		},
		Findings: []model.Finding{
			{VulnerabilityID: "CVE-2026-0002", Product: "openssl", InstalledVersion: "3.0.13-1", Ecosystem: "Ubuntu:24.04", Severity: "medium"},
			{VulnerabilityID: "CVE-2026-0003", Product: "openssl", InstalledVersion: "3.0.13-1", Ecosystem: "Ubuntu:24.04", Severity: "critical"},
			// A finding for a package that is no longer installed must not leak
			// onto an unrelated row.
			{VulnerabilityID: "CVE-0000-0001", Product: "gone-package", InstalledVersion: "1.0", Ecosystem: "Ubuntu:24.04", Severity: "high"},
		},
	}
}

func parseCSV(t *testing.T, body []byte) ([]string, [][]string) {
	t.Helper()
	rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v\n%s", err, body)
	}
	if len(rows) == 0 {
		t.Fatal("no rows")
	}
	return rows[0], rows[1:]
}

func TestSoftwareInventoryCSVShape(t *testing.T) {
	body, err := SoftwareInventoryCSV([]model.Report{inventoryFixture()})
	if err != nil {
		t.Fatalf("SoftwareInventoryCSV: %v", err)
	}
	header, rows := parseCSV(t, body)

	// The header is the contract an asset register imports against.
	want := strings.Join(InventoryColumns, ",")
	if got := strings.Join(header, ","); got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want one per installed package (3)", len(rows))
	}
	// Sorted by package name, so repeated exports diff cleanly.
	if rows[0][7] != "openssl" || rows[1][7] != `weird,pkg"name` || rows[2][7] != "zlib1g" {
		t.Fatalf("rows are not sorted by package: %v", []string{rows[0][7], rows[1][7], rows[2][7]})
	}

	index := map[string]int{}
	for i, col := range header {
		index[col] = i
	}
	openssl := rows[0]
	if openssl[index["host"]] != "web01" || openssl[index["os_version"]] != "24.04" {
		t.Fatalf("host/os columns = %q / %q", openssl[index["host"]], openssl[index["os_version"]])
	}
	if openssl[index["source"]] != "dpkg" || openssl[index["manager"]] != "apt" {
		t.Fatalf("source/manager = %q / %q", openssl[index["source"]], openssl[index["manager"]])
	}
	if openssl[index["purl"]] != "pkg:deb/ubuntu/openssl@3.0.13-1" {
		t.Fatalf("purl = %q", openssl[index["purl"]])
	}
	// Derived assessment columns: two findings, worst is critical.
	if got := openssl[index["known_findings"]]; got != "2" {
		t.Fatalf("known_findings = %q, want 2", got)
	}
	if got := openssl[index["max_severity"]]; got != "critical" {
		t.Fatalf("max_severity = %q, want critical", got)
	}
	if got := openssl[index["report_id"]]; got != "SCAN-20261115T120000Z-aaaa1111" {
		t.Fatalf("report_id = %q", got)
	}
	if got := openssl[index["scanned_at"]]; !strings.HasPrefix(got, "2026-11-15T11:58:40Z") {
		t.Fatalf("scanned_at = %q, want the collection time", got)
	}

	// A package with no findings says so instead of borrowing another row's.
	zlib := rows[2]
	if zlib[index["known_findings"]] != "0" || zlib[index["max_severity"]] != "none" {
		t.Fatalf("zlib row = findings %q severity %q", zlib[index["known_findings"]], zlib[index["max_severity"]])
	}

	// Quoting survives a comma and a quote in the package name.
	weird := rows[1]
	if weird[index["package"]] != `weird,pkg"name` {
		t.Fatalf("package with a comma/quote was mangled: %q", weird[index["package"]])
	}
	if weird[index["privileges_required"]] != "true" {
		t.Fatalf("privileges_required = %q, want true", weird[index["privileges_required"]])
	}
	// The package records no arch, so the host arch is used rather than a blank.
	if weird[index["arch"]] != "amd64" {
		t.Fatalf("arch fallback = %q, want the host arch", weird[index["arch"]])
	}
}

func TestSoftwareInventoryCSVMultipleHosts(t *testing.T) {
	first := inventoryFixture()
	second := inventoryFixture()
	second.ReportID = "SCAN-2"
	second.Metadata.Host = "db01"
	second.Inventory.Asset = model.Asset{Hostname: "db01", OS: "Debian", OSVersion: "12"}
	second.Inventory.Packages = []model.Package{{Name: "postgresql", Version: "16.3", Ecosystem: "Debian:12", Source: model.OriginDpkg}}
	second.Findings = nil

	body, err := SoftwareInventoryCSV([]model.Report{first, second})
	if err != nil {
		t.Fatal(err)
	}
	_, rows := parseCSV(t, body)
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want 3 (web01) + 1 (db01)", len(rows))
	}
	// Hosts are grouped and sorted, so a fleet export reads like a register.
	if rows[0][0] != "db01" || rows[1][0] != "web01" || rows[3][0] != "web01" {
		t.Fatalf("rows are not grouped by host: %v", []string{rows[0][0], rows[1][0], rows[2][0], rows[3][0]})
	}
}

func TestSoftwareInventoryCSVEmpty(t *testing.T) {
	body, err := SoftwareInventoryCSV(nil)
	if err != nil {
		t.Fatal(err)
	}
	header, rows := parseCSV(t, body)
	if len(header) != len(InventoryColumns) {
		t.Fatalf("header = %v", header)
	}
	if len(rows) != 0 {
		t.Fatalf("expected no data rows, got %d", len(rows))
	}
}

func TestSoftwareInventoryCSVFallsBackToMetadataHost(t *testing.T) {
	rep := inventoryFixture()
	rep.Inventory.Asset.Hostname = ""
	body, err := SoftwareInventoryCSV([]model.Report{rep})
	if err != nil {
		t.Fatal(err)
	}
	_, rows := parseCSV(t, body)
	if rows[0][0] != "web01" {
		t.Fatalf("host fallback = %q, want metadata.host", rows[0][0])
	}
}
