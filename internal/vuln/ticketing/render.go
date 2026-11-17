package ticketing

import (
	"fmt"
	"strings"
)

// Render turns a plan into the GitLab issue body.
//
// Formatting rules, all of them deliberate:
//   - a table for the affected system, because that is what a person scans for first;
//   - numbered steps with fenced, language-tagged command blocks, so GitLab renders its copy
//     button and nobody has to select text by hand;
//   - verification and rollback as their own steps, never folded into prose;
//   - warnings in their own section, because a reboot notice buried mid-paragraph is a missed
//     reboot;
//   - the scanner's authority stated last and unambiguously: a green command output does not
//     close the finding.
func Render(p Plan) string {
	var b strings.Builder

	b.WriteString("# Security remediation — " + firstNonEmpty(p.CVE, "advisory not assigned") + "\n\n")
	b.WriteString(statusLine(p))
	b.WriteString("\n")

	b.WriteString("\n## Affected system\n\n")
	b.WriteString("| Field | Value |\n|---|---|\n")
	row := func(label, value string) {
		fmt.Fprintf(&b, "| %s | %s |\n", label, tableCell(firstNonEmpty(value, "_not recorded_")))
	}
	row("Hostname", p.System.Hostname)
	row("IP address", p.System.IP)
	os := strings.TrimSpace(p.System.OS + " " + p.System.OSVersion)
	row("Operating system", os)
	row("Package", p.Package)
	row("Installed version", p.Installed)
	row("Fixed version", p.Fixed)
	row("CVE", p.CVE)
	row("Severity", p.Severity)
	row("Advisory", p.Advisory)
	row("Asset ID", p.System.AssetID)

	if strings.TrimSpace(p.Explanation) != "" {
		b.WriteString("\n## What this is\n\n" + strings.TrimSpace(p.Explanation) + "\n")
	}
	if len(p.Evidence) > 0 {
		b.WriteString("\n## Why the scanner believes this\n\n")
		limit := len(p.Evidence)
		if limit > 4 {
			limit = 4
		}
		for _, e := range p.Evidence[:limit] {
			fmt.Fprintf(&b, "- **%s**%s: %s\n", firstNonEmpty(e.Kind, "observation"),
				func() string {
					if e.Source != "" {
						return " (" + e.Source + ")"
					}
					return ""
				}(), oneLine(e.Detail))
		}
		if len(p.Evidence) > limit {
			fmt.Fprintf(&b, "- …and %d more in Clanker Guard.\n", len(p.Evidence)-limit)
		}
	}

	if len(p.Warnings) > 0 || p.Disruptive {
		b.WriteString("\n## Before you start\n\n")
		if p.Disruptive {
			b.WriteString("> **This change is disruptive.** It needs a reboot, a service restart or an image roll-out — " +
				"schedule it accordingly.\n\n")
		}
		for _, w := range p.Warnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
	}
	if len(p.Prerequisites) > 0 {
		b.WriteString("\n**Prerequisites**\n\n")
		for _, pre := range p.Prerequisites {
			fmt.Fprintf(&b, "- %s\n", pre)
		}
	}

	step := 0
	// Step 1: connection, only where the asset type is reached that way.
	if p.System.SSHManaged {
		step++
		b.WriteString(fmt.Sprintf("\n## Step %d: Connect to the affected system\n\n", step))
		if cmd := p.Access.SSHCommand(); cmd != "" {
			fmt.Fprintf(&b, "```bash\n%s\n```\n\n", cmd)
			if p.Access.SSHJump != "" {
				fmt.Fprintf(&b, "The host is reached through `%s`.\n", p.Access.SSHJump)
			}
		} else {
			b.WriteString("No SSH user is recorded for this asset, so no connection command is printed. " +
				"Ask the asset owner for the account and jump host, then run:\n\n")
			fmt.Fprintf(&b, "```bash\nssh <admin-user>@%s\n```\n", firstNonEmpty(p.System.Hostname, "<hostname>"))
		}
		if p.Access.Runbook != "" {
			fmt.Fprintf(&b, "\nRunbook: %s\n", p.Access.Runbook)
		}
	} else if p.System.IP != "" {
		fmt.Fprintf(&b, "\n**Connection:** this asset is not managed over SSH. Its recorded address is `%s`.\n", p.System.IP)
	}

	for _, s := range p.Steps {
		step++
		fmt.Fprintf(&b, "\n## Step %d: %s\n\n", step, s.Title)
		if s.Detail != "" {
			b.WriteString(s.Detail + "\n\n")
		}
		if s.Disruptive && !p.Disruptive {
			b.WriteString("> **Disruptive:** plan a maintenance window for this step.\n\n")
		}
		for _, c := range s.Commands {
			writeCommand(&b, c)
		}
	}

	// Verification always exists as a step; the note after it keeps the two kinds of proof apart.
	step++
	fmt.Fprintf(&b, "\n## Step %d: Verify the fix\n\n", step)
	if len(p.Verify) > 0 {
		for _, c := range p.Verify {
			writeCommand(&b, c)
		}
	} else {
		b.WriteString("No local verification command is defined for this asset type.\n\n")
	}
	if p.VerifyNote != "" {
		b.WriteString("**Local check ≠ resolved.** " + p.VerifyNote + "\n")
	}
	b.WriteString("\n**Scanner confirmation.** Re-scan the asset from Clanker Guard (or wait for the next scheduled scan). " +
		"The finding changes to resolved only when a later assessment no longer reports it. A successful command " +
		"here does not close the finding.\n")

	step++
	fmt.Fprintf(&b, "\n## Step %d: Roll back if something breaks\n\n", step)
	if len(p.Rollback) > 0 {
		for _, c := range p.Rollback {
			writeCommand(&b, c)
		}
		if p.RollbackNote != "" {
			b.WriteString(p.RollbackNote + "\n")
		}
	} else {
		b.WriteString(firstNonEmpty(p.RollbackNote, rollbackAbsentNote(classifyKindForNote(p))) + "\n")
	}

	if strings.TrimSpace(p.Caution()) != "" {
		b.WriteString("\n## Advisory guidance\n\n" + strings.TrimSpace(p.Caution()) + "\n")
	}

	if len(p.References) > 0 {
		b.WriteString("\n## References\n\n")
		seen := map[string]bool{}
		for _, r := range p.References {
			if r.URL == "" || seen[r.URL] {
				continue
			}
			seen[r.URL] = true
			fmt.Fprintf(&b, "- %s: %s\n", firstNonEmpty(r.Label, r.URL), r.URL)
		}
	}

	if p.FindingKey != "" || p.ReportID != "" {
		b.WriteString("\n## Source\n\n")
		b.WriteString("- Application: Clanker Guard\n")
		if p.FindingKey != "" {
			fmt.Fprintf(&b, "- Finding ID: `%s`\n", p.FindingKey)
		}
		if p.ReportID != "" {
			fmt.Fprintf(&b, "- Assessment: `%s`\n", p.ReportID)
		}
		if p.FirstSeen != "" {
			fmt.Fprintf(&b, "- First detected: %s\n", p.FirstSeen)
		}
		if p.LastSeen != "" {
			fmt.Fprintf(&b, "- Last confirmed: %s\n", p.LastSeen)
		}
		if p.FindingKey != "" {
			b.WriteString("\n" + Marker(p.FindingKey) + "\n")
		}
	}

	b.WriteString("\n---\n\n")
	b.WriteString(fmt.Sprintf("_Generated by Clanker Guard. Remediation status: %s (confidence: %s). _\n", p.Status.Label(), p.Confidence))
	return b.String()
}

// statusLine is the one-sentence verdict under the title.
func statusLine(p Plan) string {
	switch p.Status {
	case StatusVerified:
		return "Commands below are generated for this platform and the advisory's fixed version. **Review them against this host before running.**"
	case StatusReview:
		return "A remediation exists but needs a human decision first — read the notes before running anything."
	case StatusNoFix:
		return "**No confirmed fix is published.** The steps below are read-only checks."
	case StatusUnsupported:
		return "**This asset type cannot be patched with shell commands.** The steps below gather what the owner or vendor needs."
	default:
		return "**Manual investigation required.** No command is generated, because the available data is not enough to be sure one would be right."
	}
}

// writeCommand renders one fenced block with a language tag GitLab understands.
func writeCommand(b *strings.Builder, c Command) {
	if len(c.Lines) == 0 {
		return
	}
	lang := c.Lang
	if lang == "" {
		lang = "bash"
	}
	fmt.Fprintf(b, "```%s\n", lang)
	for _, line := range c.Lines {
		b.WriteString(line + "\n")
	}
	b.WriteString("```\n\n")
}

// tableCell keeps a value from breaking the Markdown table it sits in.
func tableCell(v string) string {
	v = strings.ReplaceAll(v, "|", "\\|")
	v = strings.ReplaceAll(v, "\n", " ")
	if strings.TrimSpace(v) == "" {
		return "_not recorded_"
	}
	return v
}

// Caution is the advisory's own remediation text, kept separate from generated commands.
func (p Plan) Caution() string { return p.advisoryText }

// WithAdvisory attaches the advisory's remediation text for the guidance section.
func (p Plan) WithAdvisory(text string) Plan {
	p.advisoryText = text
	return p
}

// classifyKindForNote is only used to choose the wording of a missing rollback.
func classifyKindForNote(p Plan) string {
	switch p.Manager {
	case "apt":
		return kindDeb
	case "dnf", "zypper":
		return kindRPM
	case "apk":
		return kindAPK
	case "brew":
		return kindBrew
	}
	return ""
}

// Compose builds the plan for a finding and renders it, attaching advisory text and references.
func Compose(f Finding) (Plan, string) {
	p := BuildPlan(f)
	if p.Manager == "" && f.RemediationText != "" {
		// Guidance-only assets still benefit from the advisory's own words.
		p.advisoryText = f.RemediationText
	}
	return p, Render(p)
}
