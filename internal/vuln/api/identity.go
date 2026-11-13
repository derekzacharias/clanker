package api

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/report"
)

// findingFingerprint mirrors report.FindingID so the API can match a finding to
// the fingerprints stored in run history (used for first-seen dates).
func findingFingerprint(f findingDoc) string {
	return report.FindingID(model.Finding{
		Ecosystem:        f.Ecosystem,
		Product:          f.Product,
		InstalledVersion: f.InstalledVersion,
		VulnerabilityID:  f.VulnerabilityID,
	})
}

// findingIdentity is the URL identity of a finding: the history fingerprint plus
// the asset, so two hosts with the same package/CVE do not collide.
func findingIdentity(host string, f findingDoc) string {
	sum := sha256.Sum256([]byte(strings.ToLower(host) + "\x00" + findingFingerprint(f)))
	return hex.EncodeToString(sum[:8])
}
