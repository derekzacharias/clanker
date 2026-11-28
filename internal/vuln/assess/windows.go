package assess

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/msrc"
)

// Windows assessment.
//
// Linux correlation asks "does this installed version fall inside an advisory's range". Windows
// is different in a way that matters: the endpoint can *ask Windows itself* which security
// updates are applicable and missing. That answer is stronger evidence than any build-number
// guess, so it is the primary path:
//
//	missing update (WUA says applicable, not installed) → its KB → CVEs fixed by that KB
//
// When the endpoint could not run the Windows Update Agent, this assessment produces **no
// findings and says so**. It never converts "we could not check" into "nothing is wrong", and
// it never infers vulnerability from an absent KB alone.

// WindowsResult is what Windows correlation contributed.
type WindowsResult struct {
	Findings []model.Finding
	// Notes are what the assessment positively established, such as "this host has no missing
	// security updates". They are not limitations: a patched host must not be described as
	// incompletely assessed just because its clean result needs a sentence.
	Notes []string
	// Limitations explain what was not assessed, or could not be decided. They belong in the
	// report's coverage limitations, never in its errors: an error makes the whole assessment
	// look broken, which is how a current Windows endpoint ended up reported as "incomplete".
	Limitations []string
	// Indeterminate counts items that could not be decided (kept visible, never dropped).
	Indeterminate int
}

// WindowsAssessor correlates a Windows inventory against Microsoft advisories.
type WindowsAssessor struct {
	DB  *sql.DB
	Now func() time.Time
}

// Assess produces findings for the endpoint.
func (w *WindowsAssessor) Assess(ctx context.Context, inv model.Inventory, host string) (WindowsResult, error) {
	if inv.Windows == nil {
		return WindowsResult{Limitations: []string{
			"the endpoint did not report Windows servicing data, so Windows update findings were not produced",
		}}, nil
	}
	ws := inv.Windows
	res := WindowsResult{}
	if strings.TrimSpace(ws.Build) == "" {
		res.Limitations = append(res.Limitations, "the Windows build number is unknown; update applicability could not be evaluated")
		return res, nil
	}
	if !strings.EqualFold(strings.TrimSpace(ws.WUAStatus), "ok") {
		reason := strings.TrimSpace(ws.WUAStatus)
		if reason == "" {
			reason = "not reported"
		}
		res.Limitations = append(res.Limitations,
			fmt.Sprintf("the Windows Update Agent did not run (%s); missing security updates were NOT assessed on this "+
				"endpoint, so a clean result here does not mean the host is patched", reason))
		return res, nil
	}
	if w.DB == nil {
		res.Limitations = append(res.Limitations, "Microsoft advisory data is unavailable on this host; Windows update findings were skipped")
		return res, nil
	}
	count, _ := msrc.AdvisoryCount(ctx, w.DB)
	if count == 0 {
		res.Limitations = append(res.Limitations,
			"Microsoft advisory data has not been imported (run `clanker-guard-agent feeds update --with-msrc`); "+
				"applicable updates are known but their CVEs are not")
	}

	match, notes := msrc.WindowsProductMatch(ws.Product, ws.DisplayVersion, inv.Asset.Arch)
	res.Limitations = append(res.Limitations, notes...)

	installed := map[string]bool{}
	for _, kb := range ws.InstalledUpdates {
		if n := msrc.NormalizeKB(kb); n != "" {
			installed[n] = true
		}
	}

	seen := map[string]bool{} // CVE+KB: one finding per vulnerability per update
	securityMissing := 0
	for _, u := range ws.MissingUpdates {
		// Only security updates become findings. A feature update or driver is not a
		// vulnerability, and treating it as one would bury the real work.
		if !u.IsSecurityUpdate() {
			continue
		}
		kbs := []string{}
		for _, kb := range u.KBs {
			if n := msrc.NormalizeKB(kb); n != "" && !installed[n] {
				kbs = append(kbs, n)
			}
		}
		if len(kbs) == 0 {
			continue
		}
		securityMissing++
		for _, kb := range kbs {
			cves, err := msrc.KBsForProduct(ctx, w.DB, kb, match)
			if err != nil {
				return res, err
			}
			for _, c := range cves {
				key := c.CVE + "/" + kb
				if seen[key] {
					continue
				}
				seen[key] = true
				res.Findings = append(res.Findings, windowsFinding(host, ws, u, kb, c))
			}
			if len(cves) == 0 {
				// The update is applicable but the advisory mapping does not name this
				// product: keep it as an indeterminate record rather than inventing a CVE.
				res.Indeterminate++
				res.Limitations = append(res.Limitations, fmt.Sprintf(
					"%s (%s) is applicable and not installed, but no advisory in the imported data maps it to a CVE for %q; "+
						"the update itself is still missing", kb, u.Title, ws.Product))
			}
		}
	}
	// With advisories present and nothing missing, this is a real clean result — and saying it
	// is the difference between "your machine is current" and "we found nothing to say".
	if count > 0 && len(res.Findings) == 0 && res.Indeterminate == 0 && securityMissing == 0 {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"Windows Update Agent reports no missing security updates on this host: %s %s, build %s, "+
				"%d installed updates checked against %d Microsoft advisories. This assessment found no "+
				"applicable Windows vulnerability at this patch level.",
			firstNonEmpty(ws.Product, "Windows"), firstNonEmpty(ws.DisplayVersion, ""), ws.Build,
			len(installed), count))
	}
	// Windows applications are assessed by the application correlation engine
	// (NVD/CPE), which reports its own coverage. Note how many applications
	// were inventoried here so the two assessments can be compared.
	res.Notes = append(res.Notes, fmt.Sprintf(
		"%d installed application(s) inventoried for application-level vulnerability assessment", len(inv.Packages)))

	// A host with a pending reboot has not finished applying what it has: say so, so a
	// "patched" reading is not trusted until the reboot happens.
	if ws.PendingReboot {
		res.Limitations = append(res.Limitations,
			"this host has a pending reboot"+pendingDetail(ws.PendingReasons)+
				"; updates already staged may not be in effect until it restarts")
	}
	return res, nil
}

func pendingDetail(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	return " (" + strings.Join(reasons, ", ") + ")"
}

// windowsFinding turns one (missing update, CVE) pair into a finding.
func windowsFinding(host string, ws *model.WindowsState, u model.WindowsUpdate, kb string, c msrc.CVEForKB) model.Finding {
	sev := strings.ToLower(strings.TrimSpace(c.Severity))
	if sev == "" {
		sev = strings.ToLower(strings.TrimSpace(u.MsrcSeverity))
	}
	sev = normalizeWindowsSeverity(sev)

	evidence := []model.Evidence{
		{Kind: "windows_update", Source: "Windows Update Agent",
			Detail: fmt.Sprintf("%s is applicable to this host and not installed (Windows Update Agent search)", kb)},
		{Kind: "installed_build", Source: "registry",
			Detail: fmt.Sprintf("%s %s, build %s", ws.Product, ws.DisplayVersion, ws.Build)},
	}
	if u.Title != "" {
		evidence = append(evidence, model.Evidence{Kind: "update_title", Source: "Windows Update Agent", Detail: u.Title})
	}
	if u.MsrcSeverity != "" {
		evidence = append(evidence, model.Evidence{Kind: "vendor_severity", Source: "Microsoft", Detail: u.MsrcSeverity})
	}
	if c.URL != "" {
		evidence = append(evidence, model.Evidence{Kind: "advisory", Source: "Microsoft Security Update Guide",
			Detail: c.Title, URL: c.URL})
	}

	remediation := fmt.Sprintf("Install %s from Windows Update (or the Microsoft Update Catalog). "+
		"Cumulative updates supersede earlier ones: installing the newest applicable cumulative update for this "+
		"release addresses this and any superseded fixes.", kb)
	if needsReboot(u) {
		remediation += " A restart is required for the update to take effect."
	}

	return model.Finding{
		FindingID:        "WIN-" + strings.ToLower(strings.ReplaceAll(kb, "KB", "")) + "-" + c.CVE,
		StableID:         stableWindowsID(host, kb, c.CVE),
		Asset:            host,
		Product:          firstNonEmpty(ws.Product, "Windows"),
		InstalledVersion: ws.Build,
		Ecosystem:        "Windows",
		VulnerabilityID:  c.CVE,
		Source:           "Microsoft Security Update Guide",
		Affected:         model.ApplicabilityConfirmed,
		ValidationStatus: model.ValidationVersion,
		Confidence:       model.ConfidenceHigh,
		Severity:         sev,
		CVSS:             cvssPtr(c.CVSS),
		Explanation: fmt.Sprintf("%s is missing on this host. Microsoft's advisory for %s (%s) lists %s as the fix, "+
			"and Windows Update reports it as applicable and not installed.",
			kb, c.CVE, firstNonEmpty(c.Title, "security update"), kb),
		Evidence:     evidence,
		FixedVersion: kb,
		Remediation:  remediation,
	}
}

func needsReboot(u model.WindowsUpdate) bool {
	return strings.Contains(strings.ToLower(u.RebootBehavior), "alwaysrequirereboot") ||
		strings.Contains(strings.ToLower(u.RebootBehavior), "canrequestreboot")
}

func normalizeWindowsSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "important":
		return "high"
	case "moderate":
		return "medium"
	case "low":
		return "low"
	case "high":
		return "high"
	case "medium":
		return "medium"
	}
	return "unknown"
}

func cvssPtr(v float64) *model.CVSS {
	if v <= 0 {
		return nil
	}
	return &model.CVSS{Score: v, Source: "Microsoft"}
}

func stableWindowsID(host, kb, cve string) string {
	parts := []string{strings.ToLower(host), "windows", strings.ToLower(kb), cve}
	sort.Strings(parts) // deterministic regardless of caller ordering
	return "win-" + strings.Join(parts, "-")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
