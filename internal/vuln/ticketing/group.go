package ticketing

import (
	"fmt"
	"sort"
	"strings"
)

// Consolidated remediation.
//
// One Windows cumulative update fixes hundreds or thousands of CVEs. Filing a ticket per CVE is
// technically traceable and operationally useless: an administrator would receive a thousand
// tickets for one restart. So a *remediation action* — one KB on one asset, or one product
// upgrade — becomes one ticket that lists the CVEs it closes, while every individual finding
// stays in the database for audit, reporting and risk.
//
// The grouping key is deliberately the same information the dashboard already groups by:
// asset + product + fixed version. Nothing new has to be maintained in two places.

// Group is the input for a consolidated ticket: the remediation action and its evidence.
type Group struct {
	Asset     string
	Hostname  string
	OS        string
	OSVersion string
	IP        string
	Product   string
	Installed string
	Fixed     string
	// Action names the remediation in the operator's terms ("KB5127648", "Chrome 131.0.6778.86").
	Action string
	// Kind is windows_update, package_upgrade or application_upgrade; it selects the wording
	// and the verification steps.
	Kind   string
	Access AccessBlock
	// Findings are the individual vulnerabilities this action closes.
	Findings []Finding
	// Reboot marks actions that need a restart to take effect.
	Reboot bool
	// References are vendor links (advisories, catalogs).
	References []Reference
}

// GroupKey is the stable identity of a remediation action on one asset.
//
// It doubles as the ticket's dedupe key, so a second assessment of an unchanged host returns the
// existing issue instead of opening another one.
func GroupKey(asset, product, fixed string) string {
	return "group:" + strings.ToLower(strings.TrimSpace(asset)) + "|" +
		strings.ToLower(strings.TrimSpace(product)) + "|" + strings.TrimSpace(fixed)
}

// GroupTitle summarises the action: severity, what to install, where, and how much it closes.
func GroupTitle(g Group) string {
	sev := strings.ToUpper(groupSeverity(g).Label)
	action := firstNonEmpty(g.Action, g.Fixed, g.Product)
	host := firstNonEmpty(g.Hostname, g.Asset)
	n := len(g.Findings)
	noun := "CVE"
	if n != 1 {
		noun = "CVEs"
	}
	return fmt.Sprintf("[%s] %s — %s on %s (%d %s)", sev, action, g.Product, host, n, noun)
}

// groupSeverity is the worst severity in the group, with its counts.
type severitySummary struct {
	Label string
	Count int
}

func groupSeverity(g Group) severitySummary {
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	best, count := "", 0
	for _, f := range g.Findings {
		s := strings.ToLower(strings.TrimSpace(f.EffectiveSeverity))
		if s == "" {
			s = strings.ToLower(strings.TrimSpace(f.Severity))
		}
		if rank[s] > rank[best] {
			best = s
			count = 1
		} else if s == best {
			count++
		}
	}
	if best == "" {
		best = "unknown"
	}
	return severitySummary{Label: best, Count: count}
}

// RenderGroup produces the consolidated issue body.
//
// Layout: what to do, where, what it closes, then the evidence. The CVE list is inside a
// <details> block so a thousand entries do not bury the instructions, and it is capped with an
// explicit note rather than silently truncated.
func RenderGroup(g Group) string {
	var b strings.Builder
	sev := groupSeverity(g)
	counts := severityCounts(g)
	kev := kevCount(g)

	b.WriteString("# Remediation: " + firstNonEmpty(g.Action, g.Fixed, g.Product) + "\n\n")
	b.WriteString(fmt.Sprintf("This action closes **%d %s** on one host, highest severity **%s**",
		len(g.Findings), plural(len(g.Findings), "vulnerability", "vulnerabilities"), strings.ToUpper(sev.Label)))
	if kev > 0 {
		b.WriteString(fmt.Sprintf(", including **%d known-exploited**", kev))
	}
	b.WriteString(".\n")

	b.WriteString("\n## Affected system\n\n| Field | Value |\n|---|---|\n")
	row := func(k, v string) { fmt.Fprintf(&b, "| %s | %s |\n", k, tableCell(firstNonEmpty(v, "_not recorded_"))) }
	row("Hostname", firstNonEmpty(g.Hostname, g.Asset))
	row("IP address", g.IP)
	row("Operating system", strings.TrimSpace(g.OS+" "+g.OSVersion))
	row("Product", g.Product)
	row("Installed", g.Installed)
	row("Fixed by", g.Fixed)

	b.WriteString("\n## What to do\n\n")
	switch g.Kind {
	case "windows_update":
		b.WriteString(fmt.Sprintf("Install **%s** on this host, then restart if Windows asks for it. "+
			"Microsoft cumulative updates are cumulative: the newest applicable one supersedes earlier fixes for the same release.\n",
			firstNonEmpty(g.Action, g.Fixed)))
		if cmd := g.Access.SSHCommand(); cmd != "" {
			fmt.Fprintf(&b, "\nConnect first:\n\n```bash\n%s\n```\n", cmd)
		}
		b.WriteString("\n```powershell\n")
		b.WriteString("# preferred: let Windows install it with its own servicing stack\n")
		b.WriteString("UsoClient StartScan; UsoClient StartDownload; UsoClient StartInstall\n")
		b.WriteString("# or install the downloaded .msu manually\n")
		fmt.Fprintf(&b, "wusa.exe \"%s.msu\" /quiet /norestart\n", firstNonEmpty(g.Action, g.Fixed))
		b.WriteString("```\n")
	default:
		fmt.Fprintf(&b, "Upgrade **%s** from `%s` to **%s** using the vendor's supported installer, then redeploy or restart "+
			"the application as its installer requires.\n", g.Product, firstNonEmpty(g.Installed, "unknown"), g.Fixed)
	}
	if g.Reboot {
		b.WriteString("\n> **A restart is required.** Schedule a maintenance window before starting.\n")
	}

	b.WriteString("\n## What this closes\n\n")
	b.WriteString("| Severity | CVEs |\n|---|---|\n")
	for _, s := range []string{"critical", "high", "medium", "low", "unknown"} {
		if counts[s] > 0 {
			fmt.Fprintf(&b, "| %s | %d |\n", strings.ToUpper(s), counts[s])
		}
	}
	if kev > 0 {
		b.WriteString(fmt.Sprintf("\n**Known exploited (CISA KEV):** %d — treat as urgent.\n", kev))
	}

	cves := sortedCVEs(g.Findings)
	const inlineLimit = 150
	b.WriteString("\n<details><summary>All CVEs closed by this action (" + fmt.Sprint(len(cves)) + ")</summary>\n\n")
	for i, c := range cves {
		if i >= inlineLimit {
			fmt.Fprintf(&b, "\n- …and %d more (see the Clanker Guard remediation detail for the full list)\n", len(cves)-inlineLimit)
			break
		}
		fmt.Fprintf(&b, "- %s\n", c)
	}
	b.WriteString("\n</details>\n")

	b.WriteString("\n## Verify\n\n")
	switch g.Kind {
	case "windows_update":
		b.WriteString("```powershell\n")
		fmt.Fprintf(&b, "# is the update present, and what build are we on now?\nGet-HotFix -Id %s -ErrorAction SilentlyContinue\n",
			strings.ReplaceAll(firstNonEmpty(g.Action, g.Fixed), "KB", "KB"))
		b.WriteString("Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' | Select-Object CurrentBuild,UBR,DisplayVersion\n")
		b.WriteString("```\n\n")
		b.WriteString("Then re-scan this host from Clanker Guard. The findings close only when a later assessment " +
			"no longer reports the update as missing — a successful command is not the same as a verified fix.\n")
	default:
		b.WriteString("Confirm the installed version, then re-scan from Clanker Guard; the findings close only when the " +
			"scanner no longer sees the affected version.\n")
	}

	if len(g.References) > 0 {
		b.WriteString("\n## References\n\n")
		seen := map[string]bool{}
		for _, r := range g.References {
			if r.URL == "" || seen[r.URL] {
				continue
			}
			seen[r.URL] = true
			fmt.Fprintf(&b, "- %s: %s\n", firstNonEmpty(r.Label, r.URL), r.URL)
		}
	}
	b.WriteString("\n---\n\n")
	b.WriteString("_One ticket per remediation action, generated by Clanker Guard. The individual CVE findings remain in " +
		"Clanker Guard for audit and reporting; this issue tracks the change that closes them._\n")
	return b.String()
}

// GroupDigest fingerprints what the ticket says, so a changed CVE set updates the issue instead of
// creating a second one.
func GroupDigest(g Group) string {
	var parts []string
	for _, c := range sortedCVEs(g.Findings) {
		parts = append(parts, c)
	}
	parts = append(parts, firstNonEmpty(g.Fixed, ""), fmt.Sprint(g.Reboot))
	return fmt.Sprintf("%x", sha256Prefix(strings.Join(parts, "\n")))
}

func severityCounts(g Group) map[string]int {
	out := map[string]int{}
	for _, f := range g.Findings {
		s := strings.ToLower(strings.TrimSpace(firstNonEmpty(f.EffectiveSeverity, f.Severity)))
		if s == "" {
			s = "unknown"
		}
		out[s]++
	}
	return out
}

func kevCount(g Group) int {
	n := 0
	for _, f := range g.Findings {
		if f.KEV {
			n++
		}
	}
	return n
}

func sortedCVEs(findings []Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		id := strings.TrimSpace(f.VulnerabilityID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
