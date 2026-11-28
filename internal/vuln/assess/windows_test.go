package assess

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/msrc"
)

// A host that ran the Windows Update Agent and has an applicable missing security update must
// produce a finding for the CVE that update fixes — with the KB as the remedy.
func TestApplicableMissingUpdateBecomesAFinding(t *testing.T) {
	db := msrcTestDB(t)
	inv := windowsInventory()

	res, err := (&WindowsAssessor{DB: db}).Assess(context.Background(), inv, "win01")
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.VulnerabilityID != "CVE-2026-40001" || f.FixedVersion != "KB5044284" {
		t.Fatalf("finding = %+v", f)
	}
	if f.Severity != "high" { // MSRC "Important" maps to high
		t.Fatalf("severity = %q", f.Severity)
	}
	if f.Affected != model.ApplicabilityConfirmed {
		t.Fatalf("applicability = %q, want confirmed (the update service said so)", f.Affected)
	}
	if !strings.Contains(f.Remediation, "Windows Update") {
		t.Fatalf("remediation does not say how to fix it: %q", f.Remediation)
	}
	// Evidence must name the update, the build and the advisory.
	joined := ""
	for _, e := range f.Evidence {
		joined += e.Kind + ":" + e.Detail + "\n"
	}
	for _, want := range []string{"windows_update", "KB5044284", "installed_build", "10.0.26100.1742"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("evidence missing %q:\n%s", want, joined)
		}
	}
}

// The same update, once installed, must not be reported: absence of a KB is not the test,
// applicability is.
func TestInstalledUpdateIsNotAFinding(t *testing.T) {
	db := msrcTestDB(t)
	inv := windowsInventory()
	inv.Windows.InstalledUpdates = []string{"KB5044284"}

	res, err := (&WindowsAssessor{DB: db}).Assess(context.Background(), inv, "win01")
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("installed update still reported: %+v", res.Findings)
	}
}

// If the update service did not run, the honest answer is "not assessed" — not zero findings
// presented as a clean host.
func TestUnavailableUpdateServiceReportsCoverageGap(t *testing.T) {
	db := msrcTestDB(t)
	inv := windowsInventory()
	inv.Windows.WUAStatus = "unavailable: access denied"

	res, err := (&WindowsAssessor{DB: db}).Assess(context.Background(), inv, "win01")
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings were invented without an applicability check: %+v", res.Findings)
	}
	if len(res.Limitations) == 0 || !strings.Contains(strings.Join(res.Limitations, " "), "NOT assessed") {
		t.Fatalf("limitations do not warn: %v", res.Limitations)
	}
}

// A missing Windows block means an old agent: the report says so rather than implying safety.
func TestMissingWindowsStateIsReported(t *testing.T) {
	db := msrcTestDB(t)
	inv := windowsInventory()
	inv.Windows = nil
	res, err := (&WindowsAssessor{DB: db}).Assess(context.Background(), inv, "win01")
	if err != nil || len(res.Findings) != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if !strings.Contains(strings.Join(res.Limitations, " "), "did not report Windows servicing data") {
		t.Fatalf("limitations = %v", res.Limitations)
	}
}

// Feature updates and drivers are not vulnerabilities.
func TestNonSecurityUpdatesAreIgnored(t *testing.T) {
	db := msrcTestDB(t)
	inv := windowsInventory()
	inv.Windows.MissingUpdates[0].Classification = []string{"Feature Packs"}

	res, _ := (&WindowsAssessor{DB: db}).Assess(context.Background(), inv, "win01")
	if len(res.Findings) != 0 {
		t.Fatalf("a feature pack became a vulnerability: %+v", res.Findings)
	}
}

// Deterministic identity: two runs produce the same finding id, so reports dedupe.
func TestWindowsFindingsAreDeterministic(t *testing.T) {
	db := msrcTestDB(t)
	a, _ := (&WindowsAssessor{DB: db}).Assess(context.Background(), windowsInventory(), "win01")
	b, _ := (&WindowsAssessor{DB: db}).Assess(context.Background(), windowsInventory(), "win01")
	if len(a.Findings) != 1 || len(b.Findings) != 1 || a.Findings[0].StableID != b.Findings[0].StableID {
		t.Fatalf("ids differ between runs: %q vs %q", a.Findings[0].StableID, b.Findings[0].StableID)
	}
}

func windowsInventory() model.Inventory {
	return model.Inventory{
		Asset: model.Asset{Hostname: "win01", OS: "Windows 11 Pro", OSVersion: "24H2", Arch: "amd64"},
		Windows: &model.WindowsState{
			Product:        "Windows 11 Pro",
			DisplayVersion: "24H2",
			Build:          "10.0.26100.1742",
			WUAStatus:      "ok",
			MissingUpdates: []model.WindowsUpdate{{
				Title:          "2026-12 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5044284)",
				KBs:            []string{"KB5044284"},
				MsrcSeverity:   "Important",
				Classification: []string{"Security Updates", "Critical Updates"},
				RebootBehavior: "CanRequestReboot",
			}},
		},
	}
}

// msrcTestDB builds a cache containing the fixture advisory for Windows 11 24H2.
func msrcTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "intel.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if err := msrc.EnsureSchema(db); err != nil {
		t.Fatal(err)
	}
	doc, err := msrc.ParseDocument([]byte(msrcFixture))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := msrc.StoreDocumentForTest(db, doc); err != nil {
		t.Fatalf("store: %v", err)
	}
	return db
}

const msrcFixture = `<cvrfdoc xmlns="http://www.icasi.org/CVRF/schema/cvrf/1.1">
  <DocumentTitle>December 2026 Security Updates</DocumentTitle>
  <DocumentTracking><Identification><ID>2026-Dec</ID></Identification></DocumentTracking>
  <ProductTree><Branch Type="Vendor" Name="Microsoft"><Branch Type="Product Family" Name="Windows">
    <FullProductName ProductID="12085">Windows 11 Version 24H2 for x64-based Systems</FullProductName>
  </Branch></Branch></ProductTree>
  <Vulnerability><CVE>CVE-2026-40001</CVE><Title>Windows RCE</Title>
    <CVSSScoreSets><ScoreSet><BaseScore>8.8</BaseScore></ScoreSet></CVSSScoreSets>
    <Threats><Threat Type="Severity"><Description>Important</Description></Threat></Threats>
    <Remediations><Remediation Type="2"><Description>5044284</Description>
      <URL>https://catalog.update.microsoft.com/x</URL><ProductID>12085</ProductID></Remediation></Remediations>
  </Vulnerability>
</cvrfdoc>`

// A fully patched host must produce a positive, specific statement — not silence. Silence is what
// made a patched Windows endpoint look like a broken scanner.
func TestPatchedHostSaysSoExplicitly(t *testing.T) {
	db := msrcTestDB(t)
	inv := windowsInventory()
	inv.Windows.MissingUpdates = nil // nothing applicable
	inv.Windows.InstalledUpdates = []string{"KB5044284", "KB5044285"}

	res, err := (&WindowsAssessor{DB: db}).Assess(context.Background(), inv, "win01")
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	// The clean result is a note, not a limitation: the host was assessed and came back current.
	notes := strings.Join(res.Notes, " ")
	if !strings.Contains(notes, "no missing security updates") {
		t.Fatalf("notes do not state the host is current: %v", res.Notes)
	}
	if !strings.Contains(notes, "Windows 11 Pro 24H2") || !strings.Contains(notes, "10.0.26100.1742") {
		t.Fatalf("notes do not name what was assessed: %v", res.Notes)
	}
	// The application assessment now covers what used to be the undisclosed gap;
	// the Windows assessment names the hand-off explicitly.
	if !strings.Contains(strings.Join(res.Notes, " "), "application-level vulnerability assessment") {
		t.Fatalf("notes do not name the application-assessment hand-off: %v", res.Notes)
	}
}

// A host with only a definition update applicable (Defender signatures) is not vulnerable.
func TestDefinitionUpdatesDoNotProduceFindings(t *testing.T) {
	db := msrcTestDB(t)
	inv := windowsInventory()
	inv.Windows.MissingUpdates = []model.WindowsUpdate{{
		Title: "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602",
		KBs:   []string{"KB2267602"}, Classification: []string{"Definition Updates"},
	}}
	res, _ := (&WindowsAssessor{DB: db}).Assess(context.Background(), inv, "win01")
	if len(res.Findings) != 0 {
		t.Fatalf("a signature update became a vulnerability: %+v", res.Findings)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "no missing security updates") {
		t.Fatalf("notes should say the host is current: %v", res.Notes)
	}
}
