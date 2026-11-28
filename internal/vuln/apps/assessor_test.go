package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/bgdnvk/clanker/internal/vuln/cpe"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/nvd"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.TempDir()+"/apps.db?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := nvd.EnsureSchema(db); err != nil {
		t.Fatal(err)
	}
	return db
}

// seedChromeCVE stores one CVE: affected chrome < 120.0.6099.224.
func seedChromeCVE(t *testing.T, db *sql.DB) {
	t.Helper()
	cfg := cpe.Node{
		Operator: "OR",
		Matches: []cpe.Match{
			{
				Criteria:        "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
				MatchCriteriaID: "mc-1",
				Vulnerable:      true,
				Range:           cpe.Range{EndExcluding: "120.0.6099.224"},
			},
			{
				Criteria:        "cpe:2.3:a:google:chrome:120.0.6099.224:*:*:*:*:*:*:*",
				MatchCriteriaID: "mc-2",
				Vulnerable:      false,
			},
		},
	}
	rec := nvd.Record{
		ID:          "CVE-2024-0519",
		Status:      "Analyzed",
		Description: "Out of bounds memory access in V8 in Google Chrome prior to 120.0.6099.224.",
		Metrics:     []nvd.CVSSMetric{{Version: "3.1", Score: 8.8, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Severity: "high", Type: "Primary"}},
		Configs:     []cpe.Node{cfg},
		References:  []nvd.Reference{{URL: "https://chromereleases.googleblog.com/2024/01/stable-channel-update-for-desktop_16.html"}},
	}
	if _, _, err := nvd.NewStore(db).SaveCVEs(context.Background(), []nvd.Record{rec}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func windowsInventory(pkgs ...model.Package) model.Inventory {
	return model.Inventory{
		Asset:    model.Asset{Hostname: "win-test", OS: "Windows", OSVersion: "11", Arch: "x64"},
		Windows:  &model.WindowsState{Product: "Windows 11 Pro", DisplayVersion: "23H2", Build: "10.0.22631.3155"},
		Packages: pkgs,
	}
}

func chromePkg(version string) model.Package {
	return model.Package{
		Name: "Google Chrome (64-bit)", Version: version,
		Ecosystem: model.EcosystemWindows, Source: model.OriginManifest,
		Manager: "windows-registry", Vendor: "Google LLC", Arch: "x64",
	}
}

func TestVulnerableApplicationConfirmed(t *testing.T) {
	db := openDB(t)
	seedChromeCVE(t, db)
	store := nvd.NewStore(db)
	now := time.Now().UTC()
	_, _ = store.RecordSyncStart(context.Background(), "cves", "full", time.Time{}, time.Time{}, now)
	_ = store.RecordSyncFinish(context.Background(), 1, "ok", 1, 1, 0, 0, "", now)

	a := &Assessor{DB: db, Now: func() time.Time { return now }}
	res, err := a.Assess(context.Background(), windowsInventory(chromePkg("120.0.6099.109")))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.VulnerabilityID != "CVE-2024-0519" {
		t.Fatalf("wrong CVE: %s", f.VulnerabilityID)
	}
	if f.Affected != model.ApplicabilityConfirmed {
		t.Fatalf("deterministic mapping + NVD range match must be confirmed, got %s (%s)", f.Affected, f.Explanation)
	}
	if f.Confidence != model.ConfidenceHigh {
		t.Fatalf("confidence = %s", f.Confidence)
	}
	if f.Severity != "high" || f.CVSS == nil || f.CVSS.Score != 8.8 {
		t.Fatalf("severity/cvss: %s %+v", f.Severity, f.CVSS)
	}
	if f.FixedVersion != "120.0.6099.224" {
		t.Fatalf("fixed version must come from the non-vulnerable criteria: %q", f.FixedVersion)
	}
	// Evidence must let a human reproduce the verdict.
	kinds := map[string]bool{}
	for _, e := range f.Evidence {
		kinds[e.Kind] = true
	}
	for _, want := range []string{"inventory", "normalization", "nvd_cpe_match", "vendor_advisory"} {
		if !kinds[want] {
			t.Errorf("missing evidence kind %q: %+v", want, f.Evidence)
		}
	}
	if f.VendorAdvisory == nil || f.VendorAdvisory.URL == "" {
		t.Error("vendor advisory must be attached")
	}
	if f.Remediation == "" {
		t.Error("remediation must be present")
	}
}

func TestPatchedApplicationNotVulnerable(t *testing.T) {
	db := openDB(t)
	seedChromeCVE(t, db)
	store := nvd.NewStore(db)
	now := time.Now().UTC()
	_, _ = store.RecordSyncStart(context.Background(), "cves", "full", time.Time{}, time.Time{}, now)
	_ = store.RecordSyncFinish(context.Background(), 1, "ok", 1, 1, 0, 0, "", now)

	a := &Assessor{DB: db, Now: func() time.Time { return now }}
	res, err := a.Assess(context.Background(), windowsInventory(chromePkg("120.0.6099.224")))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("patched version must produce no findings: %+v", res.Findings)
	}
	if res.Coverage.ExcludedCVEs != 1 {
		t.Fatalf("the evaluated-but-not-applicable CVE must be counted as excluded: %+v", res.Coverage)
	}
	if res.Coverage.Evaluated != 1 {
		t.Fatalf("the patched application WAS evaluated: %+v", res.Coverage)
	}
	// The note must state that a real evaluation happened.
	found := false
	for _, n := range res.Notes {
		if contains(n, "evaluated") {
			found = true
		}
	}
	if !found {
		t.Fatalf("coverage note missing: %v", res.Notes)
	}
}

func TestIncludeNotAffectedKeepsRecords(t *testing.T) {
	db := openDB(t)
	seedChromeCVE(t, db)
	store := nvd.NewStore(db)
	now := time.Now().UTC()
	_, _ = store.RecordSyncStart(context.Background(), "cves", "full", time.Time{}, time.Time{}, now)
	_ = store.RecordSyncFinish(context.Background(), 1, "ok", 1, 1, 0, 0, "", now)

	a := &Assessor{DB: db, Now: func() time.Time { return now }, IncludeNotAffected: true}
	res, err := a.Assess(context.Background(), windowsInventory(chromePkg("120.0.6099.224")))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Affected != model.ApplicabilityNotAffected {
		t.Fatalf("not-affected record must be kept for review: %+v", res.Findings)
	}
}

func TestFuzzyMappingIsOnlyPotential(t *testing.T) {
	db := openDB(t)
	seedChromeCVE(t, db)
	store := nvd.NewStore(db)
	now := time.Now().UTC()
	_, _ = store.RecordSyncStart(context.Background(), "cves", "full", time.Time{}, time.Time{}, now)
	_ = store.RecordSyncFinish(context.Background(), 1, "ok", 1, 1, 0, 0, "", now)

	// A typo'd display name: the deterministic rules must not match.
	pkg := chromePkg("120.0.6099.109")
	pkg.Name = "Googl Chrome 120"
	a := &Assessor{DB: db, Now: func() time.Time { return now }}
	res, err := a.Assess(context.Background(), windowsInventory(pkg))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.VulnerabilityID == "CVE-2024-0519" {
			if f.Affected != model.ApplicabilityPotential {
				t.Fatalf("fuzzy mapping must never establish vulnerability: %s", f.Affected)
			}
			if f.Confidence != model.ConfidenceLow {
				t.Fatalf("fuzzy confidence must be low: %s", f.Confidence)
			}
			return
		}
	}
	t.Fatalf("fuzzy candidate should still surface the CVE as potential: %+v", res.Findings)
}

func TestUnrecognizedSoftwareIsVisible(t *testing.T) {
	db := openDB(t)
	seedChromeCVE(t, db)
	store := nvd.NewStore(db)
	now := time.Now().UTC()
	_, _ = store.RecordSyncStart(context.Background(), "cves", "full", time.Time{}, time.Time{}, now)
	_ = store.RecordSyncFinish(context.Background(), 1, "ok", 1, 1, 0, 0, "", now)

	pkg := model.Package{Name: "Custom Internal Widget 3.14", Version: "3.14", Ecosystem: model.EcosystemWindows, Source: model.OriginManifest}
	a := &Assessor{DB: db, Now: func() time.Time { return now }}
	res, err := a.Assess(context.Background(), windowsInventory(pkg))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("unrecognized software must produce no findings: %+v", res.Findings)
	}
	if len(res.Coverage.Unrecognized) != 1 || res.Coverage.Unrecognized[0] != "Custom Internal Widget 3.14" {
		t.Fatalf("unrecognized software must be a visible coverage gap: %+v", res.Coverage)
	}
	if len(res.Limitations) == 0 {
		t.Fatal("a limitation must explain the unrecognized application")
	}
}

func TestRejectedCVEExcluded(t *testing.T) {
	db := openDB(t)
	seedChromeCVE(t, db)
	rec := nvd.Record{ID: "CVE-2024-9999", Status: "Rejected", Description: "DO NOT USE.",
		Configs: []cpe.Node{{Operator: "OR", Matches: []cpe.Match{
			{Criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", Vulnerable: true},
		}}}}
	now := time.Now().UTC()
	if _, _, err := nvd.NewStore(db).SaveCVEs(context.Background(), []nvd.Record{rec}, now); err != nil {
		t.Fatal(err)
	}
	_, _ = nvd.NewStore(db).RecordSyncStart(context.Background(), "cves", "full", time.Time{}, time.Time{}, now)
	_ = nvd.NewStore(db).RecordSyncFinish(context.Background(), 1, "ok", 2, 2, 0, 0, "", now)

	a := &Assessor{DB: db, Now: func() time.Time { return now }}
	res, err := a.Assess(context.Background(), windowsInventory(chromePkg("120.0.6099.109")))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.VulnerabilityID == "CVE-2024-9999" {
			t.Fatalf("rejected CVE must never become a finding: %+v", f)
		}
	}
	if res.Coverage.ExcludedCVEs != 1 {
		t.Fatalf("rejected CVE must be counted as excluded: %+v", res.Coverage)
	}
}

func TestVendorAdvisoryOverridesNVD(t *testing.T) {
	db := openDB(t)
	// NVD says affected < 125.0.0.0, but the vendor advisory says the fix
	// shipped in 124.0.6367.201. Installed 124.0.6367.201 → not affected.
	cfg := cpe.Node{Operator: "OR", Matches: []cpe.Match{{
		Criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", Vulnerable: true,
		Range: cpe.Range{EndExcluding: "125.0.0.0"},
	}}}
	rec := nvd.Record{ID: "CVE-2024-4671", Status: "Analyzed", Description: "Use after free in Visuals.",
		Configs: []cpe.Node{cfg}}
	now := time.Now().UTC()
	if _, _, err := nvd.NewStore(db).SaveCVEs(context.Background(), []nvd.Record{rec}, now); err != nil {
		t.Fatal(err)
	}
	_, _ = nvd.NewStore(db).RecordSyncStart(context.Background(), "cves", "full", time.Time{}, time.Time{}, now)
	_ = nvd.NewStore(db).RecordSyncFinish(context.Background(), 1, "ok", 1, 1, 0, 0, "", now)

	a := &Assessor{DB: db, Now: func() time.Time { return now }}
	res, err := a.Assess(context.Background(), windowsInventory(chromePkg("124.0.6367.201")))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("vendor advisory must override NVD: %+v", res.Findings)
	}
	if res.Coverage.ExcludedCVEs != 1 {
		t.Fatalf("coverage: %+v", res.Coverage)
	}
}

func TestMissingVersionSkipped(t *testing.T) {
	db := openDB(t)
	seedChromeCVE(t, db)
	now := time.Now().UTC()
	_, _ = nvd.NewStore(db).RecordSyncStart(context.Background(), "cves", "full", time.Time{}, time.Time{}, now)
	_ = nvd.NewStore(db).RecordSyncFinish(context.Background(), 1, "ok", 1, 1, 0, 0, "", now)

	pkg := chromePkg("")
	a := &Assessor{DB: db, Now: func() time.Time { return now }}
	res, err := a.Assess(context.Background(), windowsInventory(pkg))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("no version → no findings: %+v", res.Findings)
	}
	if res.Coverage.Skipped != 1 {
		t.Fatalf("version-less application must be skipped visibly: %+v", res.Coverage)
	}
}

func TestNoNVDIntelligenceIsALimitation(t *testing.T) {
	db := openDB(t) // no sync recorded
	a := &Assessor{DB: db, Now: time.Now}
	res, err := a.Assess(context.Background(), windowsInventory(chromePkg("120.0.6099.109")))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("no findings without intelligence: %+v", res.Findings)
	}
	found := false
	for _, l := range res.Limitations {
		if contains(l, "NOT evaluated") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing-intelligence limitation required: %v", res.Limitations)
	}
	if res.Coverage.Evaluated != 0 {
		t.Fatalf("nothing was evaluated: %+v", res.Coverage)
	}
}

func TestEvalCacheReuse(t *testing.T) {
	db := openDB(t)
	seedChromeCVE(t, db)
	now := time.Now().UTC()
	_, _ = nvd.NewStore(db).RecordSyncStart(context.Background(), "cves", "full", time.Time{}, time.Time{}, now)
	_ = nvd.NewStore(db).RecordSyncFinish(context.Background(), 1, "ok", 1, 1, 0, 0, "", now)

	a := &Assessor{DB: db, Now: func() time.Time { return now }}
	inv := windowsInventory(chromePkg("120.0.6099.109"))
	if _, err := a.Assess(context.Background(), inv); err != nil {
		t.Fatal(err)
	}
	verdict, ok, err := nvd.NewStore(db).EvalCacheGet(context.Background(), "google", "chrome", "120.0.6099.109", "CVE-2024-0519")
	if err != nil || !ok || verdict != "vulnerable" {
		t.Fatalf("eval cache: %q %v %v", verdict, ok, err)
	}
	// A second scan with the same inputs reuses the cached verdict.
	res2, err := a.Assess(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Findings) != 1 {
		t.Fatalf("cached run must produce the same findings: %+v", res2.Findings)
	}
}

func TestDotNetFrameworksAreCandidates(t *testing.T) {
	db := openDB(t)
	cfg := cpe.Node{Operator: "OR", Matches: []cpe.Match{{
		Criteria: "cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*", Vulnerable: true,
		Range: cpe.Range{EndExcluding: "8.0.7"},
	}}}
	rec := nvd.Record{ID: "CVE-2024-38095", Status: "Analyzed", Description: ".NET DoS.",
		Configs: []cpe.Node{cfg}}
	now := time.Now().UTC()
	if _, _, err := nvd.NewStore(db).SaveCVEs(context.Background(), []nvd.Record{rec}, now); err != nil {
		t.Fatal(err)
	}
	_, _ = nvd.NewStore(db).RecordSyncStart(context.Background(), "cves", "full", time.Time{}, time.Time{}, now)
	_ = nvd.NewStore(db).RecordSyncFinish(context.Background(), 1, "ok", 1, 1, 0, 0, "", now)

	inv := windowsInventory()
	inv.Windows.DotNet = []string{"Microsoft.NETCore.App 8.0.6"}
	a := &Assessor{DB: db, Now: func() time.Time { return now }}
	res, err := a.Assess(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].VulnerabilityID != "CVE-2024-38095" {
		t.Fatalf(".NET shared frameworks must be evaluated: %+v", res.Findings)
	}
}

func TestOSIdentities(t *testing.T) {
	inv := windowsInventory()
	inv.Windows.Build = "10.0.22631.3155"
	ids := OSIdentities(inv)
	if len(ids) != 2 || ids[0].Product != "windows_11" || ids[1].Product != "windows" {
		t.Fatalf("windows 11 identities: %+v", ids)
	}
	inv.Windows.Build = "10.0.19045.0"
	ids = OSIdentities(inv)
	if ids[0].Product != "windows_10" {
		t.Fatalf("windows 10 identity: %+v", ids)
	}
	inv2 := model.Inventory{Asset: model.Asset{OS: "Ubuntu", DistroID: "ubuntu"}}
	ids2 := OSIdentities(inv2)
	if len(ids2) == 0 || ids2[0].Vendor != "canonical" {
		t.Fatalf("ubuntu identity: %+v", ids2)
	}
}

func TestIsAppCandidate(t *testing.T) {
	if !IsAppCandidate(model.Package{Ecosystem: "Windows"}) ||
		!IsAppCandidate(model.Package{Ecosystem: "Homebrew"}) ||
		!IsAppCandidate(model.Package{Ecosystem: "unknown"}) {
		t.Fatal("windows/homebrew/unknown must be app candidates")
	}
	if IsAppCandidate(model.Package{Ecosystem: "Ubuntu:24.04:LTS"}) ||
		IsAppCandidate(model.Package{Ecosystem: "PyPI"}) ||
		IsAppCandidate(model.Package{Ecosystem: "npm"}) {
		t.Fatal("OSV-covered ecosystems must stay with the distribution engine")
	}
}

func TestVendorAdvisoryIndex(t *testing.T) {
	adv, ok := DefaultVendorAdvisories.For("CVE-2024-0519", "google", "chrome")
	if !ok || adv.FixedVersion != "120.0.6099.224" || adv.URL == "" {
		t.Fatalf("chrome advisory: %+v %v", adv, ok)
	}
	if _, ok := DefaultVendorAdvisories.For("CVE-2024-0519", "mozilla", "firefox"); ok {
		t.Fatal("vendor mismatch must not match")
	}
	if _, err := LoadVendorAdvisories([]byte(`{"schema_version": 2}`)); err == nil {
		t.Fatal("bad schema must fail")
	}
	if _, err := LoadVendorAdvisories([]byte(`{"schema_version": 1, "advisories": [{"cve": ""}]}`)); err == nil {
		t.Fatal("advisory without CVE must fail")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

var _ = json.Marshal // keep encoding/json for future evidence serialization checks
var _ = fmt.Sprintf
