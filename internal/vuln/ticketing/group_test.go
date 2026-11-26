package ticketing

import (
	"fmt"
	"strings"
	"testing"
)

func groupFixture(n int) Group {
	g := Group{
		Asset: "win01", Hostname: "win01", OS: "Windows 11 Pro", OSVersion: "24H2", IP: "192.0.2.25",
		Product: "Windows 11 Pro", Installed: "10.0.26100.1742", Fixed: "KB5127648",
		Action: "KB5127648", Kind: "windows_update", Reboot: true,
		Access: AccessBlock{Host: "win01", SSHUser: "deploy"},
	}
	for i := 0; i < n; i++ {
		g.Findings = append(g.Findings, Finding{
			VulnerabilityID:   fmt.Sprintf("CVE-2026-%05d", i),
			Severity:          "high",
			EffectiveSeverity: []string{"critical", "high", "medium"}[i%3],
			KEV:               i%100 == 0,
		})
	}
	return g
}

// The acceptance case: 1,000 CVEs, one cumulative update, one ticket — and the body has to be
// usable (what to do, what it closes, how to verify), not a wall of CVE ids.
func TestOneTicketForOneCumulativeUpdate(t *testing.T) {
	g := groupFixture(1000)
	title := GroupTitle(g)
	if !strings.Contains(title, "KB5127648") || !strings.Contains(title, "win01") || !strings.Contains(title, "1000 CVEs") {
		t.Fatalf("title = %q", title)
	}
	body := RenderGroup(g)
	for _, want := range []string{
		"# Remediation: KB5127648",
		"| Hostname | win01 |",
		"| Fixed by | KB5127648 |",
		"## What to do",
		"wusa.exe",
		"**A restart is required.**",
		"## What this closes",
		"| CRITICAL |",
		"All CVEs closed by this action (1000)", // the summary states the true count
		"and 850 more",
		"## Verify",
		"Get-HotFix -Id KB5127648",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body is missing %q", want)
		}
	}
	// The CVE list is bounded inside the collapsible block, and the truncation is stated.
	if strings.Count(body, "- CVE-2026-") > 200 {
		t.Fatal("the inline CVE list was not bounded")
	}
	if !strings.Contains(body, "remain in") {
		t.Fatal("the body does not say the individual findings are preserved")
	}
}

// A changed CVE set must change the digest, so the ticket can be updated rather than duplicated.
func TestGroupDigestTracksTheCVEsAndTheFix(t *testing.T) {
	a := GroupDigest(groupFixture(10))
	b := GroupDigest(groupFixture(11))
	if a == b {
		t.Fatal("digest does not change when the CVE set changes")
	}
	g := groupFixture(10)
	same := GroupDigest(g)
	if same != a {
		t.Fatal("digest is not deterministic")
	}
	g.Fixed = "KB9999999"
	if GroupDigest(g) == a {
		t.Fatal("digest does not change when the fix changes")
	}
}

func TestGroupKeyIsStableAndCaseInsensitive(t *testing.T) {
	if GroupKey("WIN01", "Windows 11 Pro", "KB5127648") != GroupKey("win01", "windows 11 pro", "KB5127648") {
		t.Fatal("group key should be case-insensitive")
	}
	if GroupKey("win01", "a", "KB1") == GroupKey("win01", "a", "KB2") {
		t.Fatal("different fixes must have different keys")
	}
}
