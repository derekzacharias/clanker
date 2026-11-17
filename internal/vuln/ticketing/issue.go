package ticketing

import (
	"fmt"
	"sort"
	"strings"
)

// Finding is the evidence the issue text is built from. It mirrors only what the
// description needs, so the renderer has no dependency on the store or the API types.
type Finding struct {
	// FindingKey is the stable identity (asset + package + version + advisory), used for
	// duplicate prevention and for the marker a retry searches for.
	FindingKey       string
	Asset            string
	Hostname         string
	OS               string
	OSVersion        string
	Product          string
	InstalledVersion string
	Ecosystem        string
	VulnerabilityID  string
	Aliases          []string
	Severity         string
	// EffectiveSeverity accounts for KEV and internet exposure; it is what the SLA was
	// computed from, and what the ticket should say.
	EffectiveSeverity string
	CVSS              *float64
	CVSSVector        string
	EPSS              *float64
	KEV               bool
	Explanation       string
	// RemediationText and its provenance. The brief requires keeping verified advisory
	// guidance distinct from anything the scanner generated itself.
	RemediationText   string
	RemediationSource string
	RemediationOrigin string
	FixedVersion      string
	Evidence          []Evidence
	References        []Reference
	FirstSeen         string
	LastSeen          string
	ReportID          string
	// Ownership, when the work item has it.
	Team     string
	Owner    string
	DueAt    string
	Priority string
	// Access is how a person reaches the host (SSH target, jump host, runbook).
	// References only: no credentials are ever stored or printed.
	Access AccessBlock
	// Runbook is the team's own procedure, already rendered with this finding's values.
	Runbook string
}

// Evidence is one scanner observation.
type Evidence struct {
	Kind   string
	Source string
	Detail string
	URL    string
}

// Reference is an advisory or vendor link.
type Reference struct {
	Label string
	URL   string
}

// Marker is embedded in every issue description. A retry after a timeout searches for it,
// so an issue that GitLab already created is adopted rather than duplicated.
func Marker(findingKey string) string {
	return "<!-- clanker-guard:finding:" + findingKey + " -->"
}

// MarkerSearch is the text a recovery lookup passes to GitLab's search.
func MarkerSearch(findingKey string) string {
	return "clanker-guard:finding:" + findingKey
}

// Title builds "[HIGH] CVE-XXXX-YYYY | Outdated <package> | <asset>".
//
// The asset makes a list of tickets readable in GitLab, and the severity prefix is what
// makes them sortable there without opening each one.
func Title(f Finding) string {
	sev := strings.ToUpper(firstNonEmpty(f.EffectiveSeverity, f.Severity, "unknown"))
	cve := firstNonEmpty(f.VulnerabilityID, "(no advisory id)")
	pkg := firstNonEmpty(f.Product, f.Ecosystem, "unknown package")
	asset := firstNonEmpty(f.Asset, f.Hostname, "unknown asset")
	return fmt.Sprintf("[%s] %s | %s | %s", sev, cve, pkg, asset)
}

// RenderDescription produces the issue body.
//
// Rules it follows, in order of importance:
//   - state only what the scanner observed, and say "not recorded" rather than guessing;
//   - never invent commands: if no fixed version is published, the ticket says so;
//   - keep verified advisory text attributed, so a reader knows where it came from;
//   - include the Clanker Guard finding id so the ticket can be traced back.
func RenderDescription(f Finding) string {
	var b strings.Builder

	b.WriteString("## Vulnerability Information\n\n")
	fmt.Fprintf(&b, "- **CVE:** %s\n", firstNonEmpty(f.VulnerabilityID, "not assigned"))
	if len(f.Aliases) > 0 {
		fmt.Fprintf(&b, "- **Also known as:** %s\n", strings.Join(f.Aliases, ", "))
	}
	fmt.Fprintf(&b, "- **Severity:** %s\n", strings.ToUpper(firstNonEmpty(f.EffectiveSeverity, f.Severity, "unknown")))
	if f.EffectiveSeverity != "" && f.Severity != "" && !strings.EqualFold(f.EffectiveSeverity, f.Severity) {
		fmt.Fprintf(&b, "- **Reported severity:** %s (raised to %s by known exploitation or internet exposure)\n",
			strings.ToUpper(f.Severity), strings.ToUpper(f.EffectiveSeverity))
	}
	if f.CVSS != nil {
		fmt.Fprintf(&b, "- **CVSS:** %s", trimFloat(*f.CVSS))
		if f.CVSSVector != "" {
			fmt.Fprintf(&b, " (%s)", f.CVSSVector)
		}
		b.WriteString("\n")
	} else {
		b.WriteString("- **CVSS:** not scored in the available advisory data\n")
	}
	if f.EPSS != nil {
		fmt.Fprintf(&b, "- **EPSS:** %.2f%% (probability of exploitation in 30 days)\n", *f.EPSS*100)
	}
	if f.KEV {
		b.WriteString("- **CISA KEV:** yes — known to be exploited in the wild\n")
	}
	if f.Priority != "" {
		fmt.Fprintf(&b, "- **Remediation priority:** %s\n", f.Priority)
	}
	if f.DueAt != "" {
		fmt.Fprintf(&b, "- **SLA due:** %s\n", f.DueAt)
	}

	b.WriteString("\n## Affected System\n\n")
	fmt.Fprintf(&b, "- **Hostname:** %s\n", firstNonEmpty(f.Hostname, f.Asset, "not recorded"))
	if f.Hostname != "" && f.Asset != "" && f.Hostname != f.Asset {
		fmt.Fprintf(&b, "- **Asset id:** %s\n", f.Asset)
	}
	if os := strings.TrimSpace(f.OS + " " + f.OSVersion); os != "" {
		fmt.Fprintf(&b, "- **Operating system:** %s\n", os)
	} else {
		b.WriteString("- **Operating system:** not recorded in the assessment\n")
	}
	fmt.Fprintf(&b, "- **Affected package:** %s\n", firstNonEmpty(f.Product, "not recorded"))
	fmt.Fprintf(&b, "- **Installed version:** %s\n", firstNonEmpty(f.InstalledVersion, "not recorded"))
	if f.Ecosystem != "" {
		fmt.Fprintf(&b, "- **Ecosystem:** %s\n", f.Ecosystem)
	}
	if f.Owner != "" || f.Team != "" {
		fmt.Fprintf(&b, "- **Owner:** %s\n", joinNonEmpty(f.Owner, teamInParens(f.Team)))
	}

	b.WriteString("\n## Description\n\n")
	if strings.TrimSpace(f.Explanation) != "" {
		b.WriteString(strings.TrimSpace(f.Explanation) + "\n")
	} else {
		b.WriteString("The scanner matched this package version against an advisory. No further " +
			"explanation was recorded with the finding; see the advisory references below.\n")
	}

	b.WriteString("\n## Detection Evidence\n\n")
	if len(f.Evidence) == 0 {
		b.WriteString("No structured evidence was recorded with this finding.\n")
	} else {
		for _, e := range f.Evidence {
			line := strings.TrimSpace(e.Detail)
			if line == "" {
				continue
			}
			fmt.Fprintf(&b, "- **%s**", firstNonEmpty(e.Kind, "observation"))
			if e.Source != "" {
				fmt.Fprintf(&b, " (%s)", e.Source)
			}
			fmt.Fprintf(&b, ": %s\n", oneLine(line))
			if e.URL != "" {
				fmt.Fprintf(&b, "  - %s\n", e.URL)
			}
		}
	}

	if f.Access.HasAccess() {
		b.WriteString("\n## Access\n\n")
		fmt.Fprintf(&b, "- **Host:** %s\n", firstNonEmpty(f.Access.Host, f.Asset, "not recorded"))
		if cmd := f.Access.SSHCommand(); cmd != "" {
			fmt.Fprintf(&b, "- **Connect:** `%s`\n", cmd)
			if f.Access.SSHJump != "" {
				fmt.Fprintf(&b, "- **Jump host:** %s\n", f.Access.SSHJump)
			}
			b.WriteString("- **Privileges:** sudo is required for the steps below\n")
		}
		if f.Access.Runbook != "" {
			fmt.Fprintf(&b, "- **Runbook:** %s\n", f.Access.Runbook)
		}
	}

	recipe := RecipeFor(f)
	if recipe.Supported && len(recipe.Fix) > 0 {
		b.WriteString("\n## Fix (review before running)\n\n```sh\n")
		for _, line := range recipe.Fix {
			b.WriteString(line + "\n")
		}
		b.WriteString("```\n\n")
		fmt.Fprintf(&b, "_Manager: %s. Generated from the advisory's fixed version — review it for this host first: "+
			"pinned versions, private mirrors and configuration management can all make a manual step the wrong step._\n", recipe.Manager)
		if recipe.Caution != "" {
			b.WriteString("\n" + recipe.Caution + "\n")
		}
		if len(recipe.Verify) > 0 {
			b.WriteString("\n**Check the version after the change:**\n\n```sh\n")
			for _, line := range recipe.Verify {
				b.WriteString(line + "\n")
			}
			b.WriteString("```\n")
		}
		if len(recipe.Rollback) > 0 {
			b.WriteString("\n**Roll back if the change breaks something:**\n\n```sh\n")
			for _, line := range recipe.Rollback {
				b.WriteString(line + "\n")
			}
			b.WriteString("```\n")
		}
	} else if recipe.Caution != "" {
		b.WriteString("\n## Fix\n\n" + recipe.Caution + "\n")
	}

	if strings.TrimSpace(f.Runbook) != "" {
		b.WriteString("\n## Team runbook\n\n")
		b.WriteString(strings.TrimSpace(f.Runbook) + "\n")
	}

	b.WriteString("\n## Advisory guidance\n\n")
	b.WriteString(remediationSection(f))

	b.WriteString("\n## Verification\n\n")
	b.WriteString("1. Apply the fix on the affected system and record the change in your change log.\n")
	if f.FixedVersion != "" {
		fmt.Fprintf(&b, "2. Confirm the installed version is at least `%s`.\n", f.FixedVersion)
	} else {
		b.WriteString("2. Confirm the advisory's fixed version is installed (see references).\n")
	}
	b.WriteString("3. Re-scan the host from Clanker Guard (Endpoints → Scan). The finding is only " +
		"considered resolved when a later assessment stops reporting it — a closed ticket is " +
		"not evidence that the vulnerability is gone.\n")

	refs := append([]Reference{}, f.References...)
	if cve := strings.TrimSpace(f.VulnerabilityID); strings.HasPrefix(cve, "CVE-") {
		refs = append(refs, Reference{Label: "NVD — " + cve, URL: "https://nvd.nist.gov/vuln/detail/" + cve})
		if f.KEV {
			refs = append(refs, Reference{Label: "CISA Known Exploited Vulnerabilities catalog",
				URL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"})
		}
	}
	if len(refs) > 0 {
		b.WriteString("\n## References\n\n")
		seen := map[string]bool{}
		for _, r := range refs {
			if r.URL == "" || seen[r.URL] {
				continue
			}
			seen[r.URL] = true
			fmt.Fprintf(&b, "- %s: %s\n", firstNonEmpty(r.Label, r.URL), r.URL)
		}
	}

	b.WriteString("\n## Source\n\n")
	b.WriteString("- Application: Clanker Guard\n")
	if f.FindingKey != "" {
		fmt.Fprintf(&b, "- Finding ID: `%s`\n", f.FindingKey)
	}
	if f.ReportID != "" {
		fmt.Fprintf(&b, "- Assessment: `%s`\n", f.ReportID)
	}
	if f.FirstSeen != "" {
		fmt.Fprintf(&b, "- First detected: %s\n", f.FirstSeen)
	}
	if f.LastSeen != "" {
		fmt.Fprintf(&b, "- Last confirmed: %s\n", f.LastSeen)
	}

	if f.FindingKey != "" {
		b.WriteString("\n" + Marker(f.FindingKey) + "\n")
	}
	return b.String()
}

// remediationSection states what is known and who said it, and never manufactures a
// command. That distinction is the whole point: an operator must be able to tell advisory
// text from something the scanner composed.
func remediationSection(f Finding) string {
	var b strings.Builder
	text := strings.TrimSpace(f.RemediationText)
	switch {
	case text != "":
		b.WriteString(text + "\n\n")
		origin := strings.TrimSpace(f.RemediationOrigin)
		if origin == "" {
			origin = "scanner"
		}
		switch origin {
		case "advisory":
			fmt.Fprintf(&b, "_Source: vendor/distribution advisory text, quoted by the scanner")
			if f.RemediationSource != "" {
				fmt.Fprintf(&b, " (%s)", f.RemediationSource)
			}
			b.WriteString(". Verified against the advisory for this package — still confirm it " +
				"applies to this host before running it._\n")
		default:
			b.WriteString("_Source: generated by the scanner from the advisory metadata, not verified " +
				"steps. Treat any command as needing review by the system owner before use._\n")
		}
	case f.FixedVersion != "":
		fmt.Fprintf(&b, "Upgrade `%s` to **%s** or later, using the update mechanism this system already "+
			"uses (for example its package manager or the vendor's supported update path).\n\n",
			firstNonEmpty(f.Product, "the affected package"), f.FixedVersion)
		b.WriteString("_Source: advisory fixed version. No command is suggested here: the correct command " +
			"depends on the distribution, the package source, and the change policy of the host._\n")
	default:
		b.WriteString("No fixed version is published in the available advisory data, and no remediation " +
			"steps were recorded with this finding.\n\n")
		b.WriteString("_Next step: check the vendor or distribution advisory linked below for a fix, " +
			"mitigation, or workaround. Do not assume a generic package upgrade resolves this " +
			"issue — it may require a configuration change, an upstream release, or accepting the risk._\n")
	}
	if f.FixedVersion != "" && text != "" {
		fmt.Fprintf(&b, "\nFixed version per the advisory: `%s`.\n", f.FixedVersion)
	}
	return b.String()
}

// Labels merges configured default labels with the ones derived from the finding:
// severity and KEV first, because that is what people filter on in GitLab.
func Labels(configured []string, f Finding) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(configured)+3)
	add := func(l string) {
		l = strings.TrimSpace(l)
		if l == "" || seen[strings.ToLower(l)] {
			return
		}
		seen[strings.ToLower(l)] = true
		out = append(out, l)
	}
	if sev := strings.ToLower(firstNonEmpty(f.EffectiveSeverity, f.Severity)); sev != "" {
		add("security")
		add(sev)
	}
	if f.KEV {
		add("cisa-kev")
	}
	if f.FixedVersion != "" {
		add("fix-available")
	} else {
		add("needs-triage")
	}
	for _, l := range configured {
		add(l)
	}
	return out
}

// LabelString is the comma-separated form GitLab's create endpoint accepts.
func LabelString(labels []string) string {
	clean := make([]string, 0, len(labels))
	for _, l := range labels {
		l = strings.TrimSpace(l)
		if l != "" {
			clean = append(clean, l)
		}
	}
	sort.SliceStable(clean, func(i, j int) bool { return false })
	return strings.Join(clean, ",")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func joinNonEmpty(values ...string) string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return strings.Join(out, " ")
}

func teamInParens(team string) string {
	if strings.TrimSpace(team) == "" {
		return ""
	}
	return "(" + strings.TrimSpace(team) + ")"
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func trimFloat(f float64) string {
	s := fmt.Sprintf("%.1f", f)
	return strings.TrimSuffix(s, ".0")
}
