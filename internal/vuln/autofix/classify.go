package autofix

import (
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/remediate"
)

// Classify decides what kind of remedy a finding admits, using only the evidence the
// scanner already produced.
//
// The order matters. "Not affected" wins over everything, because acting on a finding
// the scanner already discounted turns a false positive into a real change. A known
// fixed version wins next, because that is the only case where the remedy is a fact
// rather than a judgement. Everything else needs a verdict.
func Classify(f model.Finding) Class {
	if f.Affected == model.ApplicabilityNotAffected {
		return ClassSkip
	}
	if strings.TrimSpace(f.Product) == "" || strings.TrimSpace(f.VulnerabilityID) == "" {
		return ClassSkip
	}
	if strings.TrimSpace(f.FixedVersion) != "" {
		return ClassUpgrade
	}
	return ClassTriage
}

// NeedsInvestigation reports whether the scanner itself is unsure, which is where an
// applicability verdict is worth the tokens.
func NeedsInvestigation(f model.Finding) bool {
	return f.Affected == model.ApplicabilityNeedsInvestigation
}

// Category is the routing category from the remediation package. It is re-exported here
// so callers do not need two imports to answer "can I patch a file, or is this an OS
// package that needs a command?".
func Category(f model.Finding) string { return remediate.Category(f) }

// Patchable reports whether a fix for this finding could plausibly be a repository
// change. OS packages and firmware are remediated by upgrading or reconfiguring a host,
// not by editing the application's manifest, so they never become a generated patch.
func Patchable(f model.Finding) bool {
	switch Category(f) {
	case "app_dependency", "container_image", "cloud_config":
		return true
	default:
		return false
	}
}

// Bumpable reports whether the fix is "move this dependency to the version the advisory
// names", which the runner can do deterministically in a manifest.
func Bumpable(f model.Finding) bool {
	return Classify(f) == ClassUpgrade && Category(f) == "app_dependency"
}

// Priority returns a sortable rank so a --limit run spends its budget on the findings
// that matter: KEV first, then severity, then EPSS.
func Priority(f model.Finding) int {
	rank := 0
	switch strings.ToLower(f.Severity) {
	case "critical":
		rank += 4000
	case "high":
		rank += 3000
	case "medium":
		rank += 2000
	case "low":
		rank += 1000
	}
	if f.CISAKEV {
		rank += 10000
	}
	if f.EPSS != nil {
		rank += int(f.EPSS.Score * 100)
	}
	return rank
}

// VerdictSummary is the deterministic fallback text when no model is configured. It
// states the facts and refuses to invent a conclusion, which is the honest answer.
func VerdictSummary(f model.Finding) string {
	var b strings.Builder
	b.WriteString("Automated triage (deterministic, no model configured).\n\n")
	b.WriteString("No fixed version is published for this advisory, so there is nothing to upgrade to.\n")
	b.WriteString("Applicability as reported by the scanner: " + string(f.Affected) + ".\n")
	if f.Explanation != "" {
		b.WriteString("Scanner explanation: " + f.Explanation + "\n")
	}
	b.WriteString("\nA person or a configured model has to decide between: not applicable (suppress with " +
		"an expiry), mitigated by a compensating control, or confirmed exposure requiring a config change.\n")
	return b.String()
}
