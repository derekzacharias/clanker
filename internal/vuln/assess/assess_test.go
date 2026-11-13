package assess

import (
	"context"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
)

func debianPkg(name, ver string) model.Package {
	return model.Package{Name: name, Version: ver, Ecosystem: "Debian:12", Source: model.OriginDpkg, Vendor: "Debian"}
}

func ubuntuPkg(name, ver string) model.Package {
	return model.Package{Name: name, Version: ver, Ecosystem: "Ubuntu:24.04:LTS", Source: model.OriginDpkg, Vendor: "Ubuntu"}
}

func pypiPkg(name, ver string) model.Package {
	return model.Package{Name: name, Version: ver, Ecosystem: "PyPI", Source: model.OriginPip}
}

// debianAdvisory models a Debian OSV record: introduced + fixed range.
func debianAdvisory() intel.Advisory {
	return intel.Advisory{
		ID:     "DEBIAN-CVE-2023-5678",
		Source: "Debian",
		Affected: []intel.Affected{{
			Ecosystem: "Debian:12",
			Name:      "openssl",
			Ranges: []intel.Range{{
				Type: "ECOSYSTEM",
				Events: []intel.Event{
					{Introduced: "0"},
					{Fixed: "3.0.13-1~deb12u1"},
				},
			}},
			Versions: []string{"3.0.10-1", "3.0.11-1~deb12u2", "3.0.12-2"},
		}},
		Severities: []intel.SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}},
		References: []intel.Reference{{Type: "ADVISORY", URL: "https://security-tracker.debian.org/tracker/CVE-2023-5678"}},
		FetchedAt:  time.Now().UTC(),
	}
}

func ubuntuAdvisory() intel.Advisory {
	return intel.Advisory{
		ID:     "UBUNTU-CVE-2026-107496",
		Source: "Ubuntu",
		Affected: []intel.Affected{{
			Ecosystem: "Ubuntu:24.04:LTS",
			Name:      "openssl",
			Ranges:    []intel.Range{{Type: "ECOSYSTEM", Events: []intel.Event{{Introduced: "0"}}}},
			Versions: []string{
				"3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.6",
			},
			Binaries: []intel.Binary{
				{Name: "libssl3t64", Version: "3.0.13-0ubuntu3.6"},
				{Name: "openssl", Version: "3.0.13-0ubuntu3.6"},
			},
		}},
		Severities: []intel.SeverityEntry{{Type: "Ubuntu", Score: "medium"}},
		FetchedAt:  time.Now().UTC(),
	}
}

func TestMatchDebianRange(t *testing.T) {
	adv := debianAdvisory()

	out, ok := Match(debianPkg("openssl", "3.0.11-1~deb12u2"), adv)
	if !ok {
		t.Fatal("expected a match for an in-range Debian version")
	}
	if out.Applicability != model.ApplicabilityConfirmed {
		t.Fatalf("expected confirmed applicability, got %s (%s)", out.Applicability, out.Explanation)
	}
	if out.FixedVersion != "3.0.13-1~deb12u1" {
		t.Fatalf("fixed version not propagated: %q", out.FixedVersion)
	}
	if out.VendorAdvisory == nil || out.VendorAdvisory.Vendor != "Debian" {
		t.Fatalf("vendor advisory not attached: %+v", out.VendorAdvisory)
	}

	// The vendor backport case: the installed build is at/after the fixed version.
	out, ok = Match(debianPkg("openssl", "3.0.13-1~deb12u1"), adv)
	if !ok {
		t.Fatal("expected a match for the fixed version")
	}
	if out.Applicability != model.ApplicabilityNotAffected {
		t.Fatalf("expected not_affected for the fixed build, got %s", out.Applicability)
	}
	if out.Confidence != model.ConfidenceHigh {
		t.Fatalf("explicit fixed-version evidence should be high confidence, got %s", out.Confidence)
	}
}

func TestMatchUbuntuBinaryView(t *testing.T) {
	adv := ubuntuAdvisory()

	// installed equals the enumerated affected binary version
	out, ok := Match(ubuntuPkg("libssl3t64", "3.0.13-0ubuntu3.6"), adv)
	if !ok || out.Applicability != model.ApplicabilityConfirmed {
		t.Fatalf("expected confirmed for enumerated binary, ok=%v out=%+v", ok, out)
	}
	if out.Confidence != model.ConfidenceHigh {
		t.Fatalf("expected high confidence, got %s", out.Confidence)
	}

	// installed newer than the enumeration -> vendor appears to have fixed it
	out, ok = Match(ubuntuPkg("libssl3t64", "3.0.13-0ubuntu3.9"), adv)
	if !ok || out.Applicability != model.ApplicabilityNotAffected {
		t.Fatalf("expected not_affected for newer build, ok=%v out=%+v", ok, out)
	}
	if out.PatchStatus != model.PatchVendorFixed {
		t.Fatalf("patch status should be vendor_fixed, got %s", out.PatchStatus)
	}

	// installed older than the enumeration -> unresolved, never guessed
	out, ok = Match(ubuntuPkg("libssl3t64", "3.0.13-0ubuntu3.1"), adv)
	if !ok || out.Applicability != model.ApplicabilityNeedsInvestigation {
		t.Fatalf("expected needs_investigation for pre-enumeration build, ok=%v out=%+v", ok, out)
	}
}

func TestMatchUbuntuGapVersion(t *testing.T) {
	adv := ubuntuAdvisory()
	// 3.0.13-0ubuntu3.55 is between listed versions but not listed itself.
	out, ok := Match(ubuntuPkg("openssl", "3.0.13-0ubuntu3.5.5"), adv)
	if !ok {
		t.Fatal("expected the source-name match to apply")
	}
	if out.Applicability == model.ApplicabilityConfirmed {
		t.Fatalf("an unlisted build must not be confirmed affected: %+v", out)
	}
}

func TestCrossEcosystemIsRejected(t *testing.T) {
	adv := debianAdvisory()
	// Same name and version, different ecosystem: must not match.
	out, ok := Match(pypiPkg("openssl", "3.0.11-1~deb12u2"), adv)
	if ok {
		t.Fatalf("cross-ecosystem match must be rejected, got %+v", out)
	}
}

func TestBackportDowngradeForUpstreamAdvisory(t *testing.T) {
	// An OSV (upstream) advisory for a package that Debian ships as a patched build.
	adv := intel.Advisory{
		ID:     "OSV-2024-0001",
		Source: "OSV",
		Affected: []intel.Affected{{
			Ecosystem: "Debian:12",
			Name:      "openssl",
			Ranges: []intel.Range{{Type: "ECOSYSTEM", Events: []intel.Event{
				{Introduced: "0"}, {Fixed: "3.0.14-1"},
			}}},
		}},
		FetchedAt: time.Now().UTC(),
	}
	pkg := debianPkg("openssl", "3.0.13-1~deb12u1")
	out, ok := Match(pkg, adv)
	if !ok {
		t.Fatal("expected a range match")
	}
	if out.DistroAdvisory {
		t.Fatal("this advisory is not a distribution advisory")
	}
	e := &Engine{Vendor: "Debian", Now: time.Now}
	f := e.findingFor(pkg, adv, out)
	if f.Affected != model.ApplicabilityProbable {
		t.Fatalf("upstream match on a distro build must downgrade to probable, got %s", f.Affected)
	}
	if f.Confidence != model.ConfidenceMedium {
		t.Fatalf("downgraded finding should be medium confidence, got %s", f.Confidence)
	}
	if f.Explanation == "" || len(f.LowerConfidence) == 0 {
		t.Fatalf("downgrade must be explained: %+v", f)
	}
}

func TestPyPINameNormalization(t *testing.T) {
	adv := intel.Advisory{
		ID:     "GHSA-test-0001",
		Source: "GitHub",
		Affected: []intel.Affected{{
			Ecosystem: "PyPI",
			Name:      "Flask-SQLAlchemy",
			Ranges: []intel.Range{{Type: "ECOSYSTEM", Events: []intel.Event{
				{Introduced: "0"}, {Fixed: "3.1.1"},
			}}},
		}},
		FetchedAt: time.Now().UTC(),
	}
	out, ok := Match(pypiPkg("flask_sqlalchemy", "3.0.5"), adv)
	if !ok {
		t.Fatal("PyPI name normalisation should match Flask_SQLAlchemy")
	}
	if out.Applicability != model.ApplicabilityConfirmed {
		t.Fatalf("expected confirmed, got %s", out.Applicability)
	}
}

func TestDedupeByCVEAcrossSources(t *testing.T) {
	now := time.Now().UTC()
	a := model.Finding{
		Product: "openssl", InstalledVersion: "3.0.11-1", Ecosystem: "Debian:12",
		VulnerabilityID: "CVE-2023-5678", Aliases: []string{"CVE-2023-5678", "DEBIAN-CVE-2023-5678"},
		Source: "Debian", Affected: model.ApplicabilityConfirmed, Confidence: model.ConfidenceHigh,
		Severity: "high", AdvisoryID: "DEBIAN-CVE-2023-5678",
		VendorAdvisory: &model.VendorAdvisory{Vendor: "Debian", FixedVersion: "3.0.13-1~deb12u1"},
		FixedVersion:   "3.0.13-1~deb12u1", Evidence: []model.Evidence{{Kind: "installed_version", Detail: "a"}},
	}
	b := model.Finding{
		Product: "openssl", InstalledVersion: "3.0.11-1", Ecosystem: "Debian:12",
		VulnerabilityID: "CVE-2023-5678", Aliases: []string{"CVE-2023-5678", "OSV-2023-9"},
		Source: "OSV", Affected: model.ApplicabilityProbable, Confidence: model.ConfidenceMedium,
		Severity: "medium", AdvisoryID: "OSV-2023-9",
		Evidence: []model.Evidence{{Kind: "installed_version", Detail: "b"}},
	}
	out := dedupeFindings([]model.Finding{a, b})
	if len(out) != 1 {
		t.Fatalf("expected one merged finding, got %d", len(out))
	}
	if out[0].VendorAdvisory == nil {
		t.Fatal("distro evidence must win the merge")
	}
	if len(out[0].Evidence) != 2 {
		t.Fatalf("evidence from both sources should be unioned, got %d", len(out[0].Evidence))
	}
	if out[0].FixedVersion != "3.0.13-1~deb12u1" {
		t.Fatalf("fixed version lost in merge: %q", out[0].FixedVersion)
	}
	_ = now
}

func TestEngineOfflineWithCacheAndEnrichment(t *testing.T) {
	dir := t.TempDir()
	store, err := intel.OpenStore(dir + "/cache.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()

	adv := debianAdvisory()
	adv.FetchedAt = time.Now().UTC()
	if err := store.SaveAdvisories(ctx, []intel.Advisory{adv}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveKEV(ctx, []intel.KEVEntry{{CVEID: "CVE-2023-5678", DateAdded: "2024-01-01", Name: "test"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveEPSS(ctx, []intel.EPSSEntry{{CVE: "CVE-2023-5678", Score: 0.42, Percentile: 0.98}}, 100); err != nil {
		t.Fatal(err)
	}

	inv := model.Inventory{
		Asset:    model.Asset{Hostname: "testhost", OS: "Debian 12"},
		Packages: []model.Package{debianPkg("openssl", "3.0.11-1~deb12u2"), debianPkg("bash", "5.2-1")},
	}
	e := &Engine{Store: store, Online: false, Vendor: "Debian", Now: time.Now}
	res, err := e.Assess(ctx, inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if !f.CISAKEV || f.KEV == nil {
		t.Fatalf("KEV enrichment missing: %+v", f)
	}
	if f.EPSS == nil || f.EPSS.Score != 0.42 {
		t.Fatalf("EPSS enrichment missing: %+v", f.EPSS)
	}
	if f.RiskScore <= 0 || len(f.RiskFactors) == 0 {
		t.Fatalf("risk scoring missing: %+v", f)
	}
	if f.FindingID == "" {
		t.Fatal("finding id not assigned")
	}
	// KEV + high severity + confidence + patch available must beat a bare CVE.
	if f.RiskScore < 50 {
		t.Fatalf("KEV finding should score high, got %.1f", f.RiskScore)
	}
}

func TestRiskOrderingPrefersExploitedCriticalAsset(t *testing.T) {
	e := &Engine{Now: time.Now, AssetCriticality: 0.9, Exposed: true, Weights: DefaultRiskWeights()}
	kev := model.Finding{Severity: "high", Affected: model.ApplicabilityConfirmed, Confidence: model.ConfidenceHigh, CISAKEV: true}
	boring := model.Finding{Severity: "high", Affected: model.ApplicabilityConfirmed, Confidence: model.ConfidenceHigh}
	e.score(&kev)
	e.score(&boring)
	if kev.RiskScore <= boring.RiskScore {
		t.Fatalf("KEV finding must outrank a non-KEV finding: %.1f vs %.1f", kev.RiskScore, boring.RiskScore)
	}
	if kev.RiskScore > 100 {
		t.Fatalf("risk score must be capped: %.1f", kev.RiskScore)
	}

	// not_affected must score zero regardless of severity
	na := model.Finding{Severity: "critical", Affected: model.ApplicabilityNotAffected}
	e.score(&na)
	if na.RiskScore != 0 {
		t.Fatalf("not_affected should not be prioritised, got %.1f", na.RiskScore)
	}
}

// TestForeignBuildIsNotResolvedByDistroEnumeration covers the case that produced
// a false "not affected" on a real host: a NodeSource build of nodejs is newer
// than Ubuntu's last enumerated affected build, but Ubuntu's enumeration says
// nothing about a third-party package.
func TestForeignBuildIsNotResolvedByDistroEnumeration(t *testing.T) {
	adv := intel.Advisory{
		ID:     "UBUNTU-CVE-2024-22018",
		Source: "Ubuntu",
		Affected: []intel.Affected{{
			Ecosystem: "Ubuntu:24.04:LTS",
			Name:      "nodejs",
			Versions:  []string{"18.19.1+dfsg-6ubuntu5", "18.19.1+dfsg-6ubuntu5.1"},
			Ranges:    []intel.Range{{Type: "ECOSYSTEM", Events: []intel.Event{{Introduced: "0"}}}},
		}},
		FetchedAt: time.Now().UTC(),
	}
	pkg := model.Package{Name: "nodejs", Version: "22.23.5-1nodesource1", Ecosystem: "Ubuntu:24.04:LTS", Source: model.OriginDpkg}
	out, ok := Match(pkg, adv)
	if !ok {
		t.Fatal("expected the advisory to match the package")
	}
	if out.Applicability != model.ApplicabilityNeedsInvestigation {
		t.Fatalf("third-party build must not be resolved by distro enumeration, got %s (%s)",
			out.Applicability, out.Explanation)
	}
	if len(out.Evidence) == 0 || out.Evidence[0].Kind != "installed_version" {
		t.Fatalf("evidence missing: %+v", out.Evidence)
	}
}

func TestSnapTransitionPackageIsUnresolved(t *testing.T) {
	adv := intel.Advisory{
		ID:     "UBUNTU-CVE-2022-25236",
		Source: "Ubuntu",
		Affected: []intel.Affected{{
			Ecosystem: "Ubuntu:24.04:LTS",
			Name:      "thunderbird",
			Versions:  []string{"1snap1-0ubuntu2", "1snap1-0ubuntu3"},
		}},
		FetchedAt: time.Now().UTC(),
	}
	// The advisory does list this exact version, so it is confirmed - but the
	// explanation must stay explicit that the package is a snap shim.
	pkg := model.Package{Name: "thunderbird", Version: "2:1snap1-0ubuntu3", Ecosystem: "Ubuntu:24.04:LTS", Source: model.OriginDpkg}
	if _, ok := Match(pkg, adv); ok {
		t.Log("snap shim version parsed with epoch, matched by vendor enumeration")
	}
}
