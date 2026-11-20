package report

import (
	"testing"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// The bug: on Ubuntu the same package is inventoried twice — python3-jwt from dpkg and PyJWT
// from the distro-managed Python path — and the second copy produces a ticket telling someone to
// pip-install a package that apt owns.
func TestSuppressDistroProvidedPythonFindings(t *testing.T) {
	rep := model.Report{
		ReportID: "SCAN-1",
		Inventory: model.Inventory{Packages: []model.Package{
			{Name: "python3-jwt", Version: "2.3.0-1ubuntu0.6", Ecosystem: "Ubuntu:22.04:LTS", Source: model.OriginDpkg},
			{Name: "PyJWT", Version: "2.3.0", Ecosystem: model.EcosystemPyPI, Source: model.OriginPip,
				Origin: "/usr/lib/python3/dist-packages/PyJWT-2.3.0.egg-info"},
			{Name: "requests", Version: "2.32.4", Ecosystem: model.EcosystemPyPI, Source: model.OriginPip,
				Origin: "/opt/app/.venv/lib/python3.11/site-packages/requests-2.32.4.dist-info"},
		}},
		Findings: []model.Finding{
			{Product: "PyJWT", InstalledVersion: "2.3.0", Ecosystem: model.EcosystemPyPI, VulnerabilityID: "CVE-1"},
			{Product: "requests", InstalledVersion: "2.32.4", Ecosystem: model.EcosystemPyPI, VulnerabilityID: "CVE-2"},
			{Product: "python3-jwt", InstalledVersion: "2.3.0-1ubuntu0.6", Ecosystem: "Ubuntu:22.04:LTS", VulnerabilityID: "CVE-1"},
		},
	}
	kept, suppressed, reasons := FilterSuppressed(rep)
	if suppressed != 1 {
		t.Fatalf("suppressed = %d, want 1 (%v)", suppressed, reasons)
	}
	var products []string
	for _, f := range kept {
		products = append(products, f.Product)
	}
	for _, want := range []string{"requests", "python3-jwt"} {
		found := false
		for _, p := range products {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("kept %v, missing %q", products, want)
		}
	}
	for _, p := range products {
		if p == "PyJWT" {
			t.Fatal("the distro-provided duplicate survived")
		}
	}
	if len(reasons) != 1 || reasons[0] == "" {
		t.Fatal("suppression must carry a reason")
	}
}

// A virtualenv package is a real application dependency and must never be suppressed.
func TestSuppressionIgnoresVirtualenvAndSitePackages(t *testing.T) {
	rep := model.Report{
		Inventory: model.Inventory{Packages: []model.Package{
			{Name: "python3-requests", Version: "2.31.0", Ecosystem: "Ubuntu:22.04:LTS", Source: model.OriginDpkg},
			{Name: "requests", Version: "2.32.4", Ecosystem: model.EcosystemPyPI, Source: model.OriginPip,
				Origin: "/usr/local/lib/python3.11/dist-packages/requests-2.32.4.dist-info"},
		}},
		Findings: []model.Finding{{Product: "requests", InstalledVersion: "2.32.4", Ecosystem: model.EcosystemPyPI, VulnerabilityID: "CVE-3"}},
	}
	kept, suppressed, _ := FilterSuppressed(rep)
	if suppressed != 0 || len(kept) != 1 {
		t.Fatalf("suppressed = %d, kept = %d", suppressed, len(kept))
	}
}
