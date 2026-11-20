package report

import (
	"fmt"
	"path"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// Suppressing distribution-provided Python duplicates.
//
// The collector now skips Python distributions installed under Debian/Ubuntu's
// /usr/lib/python3*/dist-packages, because dpkg already reports them. Reports produced before
// that fix still contain both copies, and the duplicate is not harmless: it names a package
// (`PyJWT`) that pip does not own, so any remediation built from it is wrong ("pip install"
// cannot upgrade a system package).
//
// Rather than editing stored evidence, readers filter: the finding stays in the report as
// written, and everything that presents or acts on findings skips the copy that the OS package
// manager already covers. The suppression is derived from the report itself — an origin path
// inside a distribution directory plus a dpkg/apk/rpm package on the same host — so it needs no
// new data and works on history.

// suppressedFinding reports whether a finding duplicates a distribution-managed package.
//
// It returns a human reason so the UI can explain the omission instead of silently hiding it.
func suppressedFinding(rep model.Report, f model.Finding) (string, bool) {
	if !isPyPI(f.Ecosystem) {
		return "", false
	}
	product := strings.ToLower(strings.TrimSpace(f.Product))
	if product == "" {
		return "", false
	}
	seenOS := false
	for _, p := range rep.Inventory.Packages {
		if isOSOrigin(p.Source) {
			seenOS = true
		}
	}
	if !seenOS {
		// No OS package manager on this host: the PyPI copy is all we have.
		return "", false
	}
	for _, p := range rep.Inventory.Packages {
		if !isPyPI(p.Ecosystem) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(p.Name), product) {
			continue
		}
		if !isDistroPythonOrigin(p.Origin) {
			continue
		}
		if strings.TrimSpace(p.Version) != "" && strings.TrimSpace(f.InstalledVersion) != "" &&
			p.Version != f.InstalledVersion {
			continue
		}
		return fmt.Sprintf("%s is installed by the operating system (found in %s); the OS package "+
			"manager owns it, so it is reported there instead of as a Python dependency", p.Name, p.Origin), true
	}
	return "", false
}

// FilterSuppressed returns the findings that do not duplicate an OS-owned Python package, the
// number suppressed, and one reason per suppressed finding.
func FilterSuppressed(rep model.Report) ([]model.Finding, int, []string) {
	out := make([]model.Finding, 0, len(rep.Findings))
	var reasons []string
	for _, f := range rep.Findings {
		if reason, ok := suppressedFinding(rep, f); ok {
			reasons = append(reasons, reason)
			continue
		}
		out = append(out, f)
	}
	return out, len(rep.Findings) - len(out), reasons
}

func isPyPI(ecosystem string) bool {
	return strings.EqualFold(strings.TrimSpace(ecosystem), string(model.EcosystemPyPI))
}

func isOSOrigin(o model.PackageOrigin) bool {
	switch o {
	case model.OriginDpkg, model.OriginAPK, model.OriginRPM:
		return true
	}
	return false
}

// isDistroPythonOrigin mirrors the collector's rule: /usr/lib/python3*/dist-packages belongs to
// the distribution; site-packages (including /usr/local and virtualenvs) does not.
func isDistroPythonOrigin(origin string) bool {
	if strings.TrimSpace(origin) == "" {
		return false
	}
	clean := path.Clean(strings.ReplaceAll(origin, "\\", "/"))
	if strings.HasPrefix(clean, "/usr/lib/python3.") && strings.Contains(clean, "/dist-packages/") {
		return true
	}
	return strings.HasPrefix(clean, "/usr/lib/python3/dist-packages/")
}

// SuppressedPackages returns the inventory entries that are distro-owned Python distributions —
// the ones whose findings are suppressed. Callers use it to clean up work items that were
// derived before the suppression existed.
func SuppressedPackages(rep model.Report) []model.Package {
	osCovered := false
	for _, p := range rep.Inventory.Packages {
		if isOSOrigin(p.Source) {
			osCovered = true
			break
		}
	}
	if !osCovered {
		return nil
	}
	var out []model.Package
	for _, p := range rep.Inventory.Packages {
		if isPyPI(p.Ecosystem) && isDistroPythonOrigin(p.Origin) {
			out = append(out, p)
		}
	}
	return out
}
