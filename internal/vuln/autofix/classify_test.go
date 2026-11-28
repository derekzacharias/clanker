package autofix

import (
	"strings"
	"testing"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

func TestClassifyPrefersEvidenceOverReaction(t *testing.T) {
	cases := []struct {
		name string
		f    model.Finding
		want Class
	}{
		{
			name: "not affected wins over a known fix",
			f: model.Finding{Product: "openssl", VulnerabilityID: "CVE-1",
				Affected: model.ApplicabilityNotAffected, FixedVersion: "3.0.1"},
			want: ClassSkip,
		},
		{
			name: "fixed version means the remedy is known",
			f: model.Finding{Product: "paramiko", VulnerabilityID: "CVE-2",
				Affected: model.ApplicabilityConfirmed, FixedVersion: "3.4.0"},
			want: ClassUpgrade,
		},
		{
			name: "no fixed version needs a verdict",
			f: model.Finding{Product: "thunderbird", VulnerabilityID: "CVE-3",
				Affected: model.ApplicabilityConfirmed},
			want: ClassTriage,
		},
		{
			name: "needs investigation with no fix is still triage",
			f: model.Finding{Product: "nodejs", VulnerabilityID: "CVE-4",
				Affected: model.ApplicabilityNeedsInvestigation},
			want: ClassTriage,
		},
		{
			name: "unidentified finding is not actionable",
			f:    model.Finding{VulnerabilityID: "CVE-5", FixedVersion: "9.9.9"},
			want: ClassSkip,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.f); got != tc.want {
				t.Fatalf("Classify() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPriorityRanksKEVFirstThenSeverity(t *testing.T) {
	kevLow := model.Finding{Severity: "low", CISAKEV: true}
	critNoKEV := model.Finding{Severity: "critical"}
	if Priority(kevLow) <= Priority(critNoKEV) {
		t.Fatalf("a KEV finding must outrank a non-KEV critical: kev=%d crit=%d",
			Priority(kevLow), Priority(critNoKEV))
	}
	high := model.Finding{Severity: "high"}
	med := model.Finding{Severity: "medium"}
	if Priority(high) <= Priority(med) {
		t.Fatalf("high must outrank medium")
	}
}

func TestPatchableIsRestrictedToRepositoryCategories(t *testing.T) {
	if !Patchable(model.Finding{Ecosystem: "PyPI"}) {
		t.Fatal("an application dependency should be patchable in the repository")
	}
	if Patchable(model.Finding{Ecosystem: "Ubuntu:24.04:LTS"}) {
		t.Fatal("an OS package is not a repository change")
	}
	// Bumpable additionally requires a known fixed version.
	f := model.Finding{Ecosystem: "PyPI", Product: "x", VulnerabilityID: "CVE-9", FixedVersion: "2.0.0"}
	if !Bumpable(f) {
		t.Fatal("a PyPI dependency with a fixed version is bumpable")
	}
	f.FixedVersion = ""
	if Bumpable(f) {
		t.Fatal("without a fixed version there is nothing deterministic to bump")
	}
}

func TestVerdictSummaryDoesNotInventAConclusion(t *testing.T) {
	got := VerdictSummary(model.Finding{Affected: model.ApplicabilityConfirmed, Explanation: "because"})
	for _, want := range []string{"deterministic", "No fixed version", "confirmed_applicability"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary missing %q:\n%s", want, got)
		}
	}
}
