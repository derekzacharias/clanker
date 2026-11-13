package api

import (
	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// findingFingerprint mirrors report.FindingID so the API can match a finding to
// the fingerprints stored in run history (used for first-seen dates).
func findingFingerprint(f findingDoc) string {
	return model.FindingFingerprint(model.Finding{
		Ecosystem:        f.Ecosystem,
		Product:          f.Product,
		InstalledVersion: f.InstalledVersion,
		VulnerabilityID:  f.VulnerabilityID,
	})
}

// findingIdentity is the URL identity of a finding: the history fingerprint plus
// the asset, so two hosts with the same package/CVE do not collide.
func findingIdentity(host string, f findingDoc) string {
	return model.FindingStableID(host, model.Finding{
		Ecosystem:        f.Ecosystem,
		Product:          f.Product,
		InstalledVersion: f.InstalledVersion,
		VulnerabilityID:  f.VulnerabilityID,
	})
}
