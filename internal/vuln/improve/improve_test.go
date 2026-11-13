package improve

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/assess"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
)

const snapCVE = "CVE-2022-25236"

// newEngine returns an improvement engine over a temp database.
func newEngine(t *testing.T) (*Engine, *intel.Store) {
	t.Helper()
	store, err := intel.OpenStore(filepath.Join(t.TempDir(), "intel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	eng, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	eng.Now(func() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) })
	return eng, store
}

// seedAdvisories stores the Ubuntu snap advisory and a Debian backport advisory.
func seedAdvisories(t *testing.T, store *intel.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	snap := intel.Advisory{
		ID: "UBUNTU-" + snapCVE, Source: "Ubuntu",
		References: []intel.Reference{{Type: "ADVISORY", URL: "https://ubuntu.com/security/" + snapCVE}},
		Affected: []intel.Affected{{
			Ecosystem: "Ubuntu:24.04:LTS",
			Name:      "thunderbird",
			Versions:  []string{"1snap1-0ubuntu2", "1snap1-0ubuntu3"},
			Binaries:  []intel.Binary{{Name: "thunderbird", Version: "2:1snap1-0ubuntu3"}},
		}},
		FetchedAt: now,
	}
	debianFixed := intel.Advisory{
		ID: "DEBIAN-CVE-2023-5678", Source: "Debian",
		References: []intel.Reference{{Type: "ADVISORY", URL: "https://security-tracker.debian.org/tracker/CVE-2023-5678"}},
		Affected: []intel.Affected{{
			Ecosystem: "Debian:12", Name: "openssl",
			Ranges: []intel.Range{{Type: "ECOSYSTEM", Events: []intel.Event{{Introduced: "0"}, {Fixed: "3.0.13-1~deb12u1"}}}},
		}},
		FetchedAt: now,
	}
	debianAffected := intel.Advisory{
		ID: "DEBIAN-CVE-2024-0001", Source: "Debian",
		Affected: []intel.Affected{{
			Ecosystem: "Debian:12", Name: "curl",
			Ranges: []intel.Range{{Type: "ECOSYSTEM", Events: []intel.Event{{Introduced: "0"}, {Fixed: "8.5.0-3"}}}},
		}},
		FetchedAt: now,
	}
	if err := store.SaveAdvisories(ctx, []intel.Advisory{snap, debianFixed, debianAffected}); err != nil {
		t.Fatal(err)
	}
}

func snapFinding() FindingRef {
	return FindingRef{
		ID: "abc123", ReportID: "SCAN-1", Host: "host1", CVE: snapCVE,
		AdvisoryID: "UBUNTU-" + snapCVE, Product: "thunderbird", Version: "2:1snap1-0ubuntu3",
		Ecosystem: "Ubuntu:24.04:LTS", Severity: "high",
		Applicability: string(model.ApplicabilityConfirmed), Confidence: "high",
	}
}

// ------------------------------------------------------------- verification ---

func TestFeedbackAloneIsNotProof(t *testing.T) {
	eng, store := newEngine(t)
	seedAdvisories(t, store)
	ctx := context.Background()

	// No structured reason: nothing to verify, classification must not change.
	fb, err := eng.ApplyFeedback(ctx, Feedback{
		Finding: FindingRef{ID: "f1", CVE: "CVE-2024-9999", Product: "openssl", Version: "3.0.11-1",
			Ecosystem: "Debian:12", Applicability: string(model.ApplicabilityConfirmed)},
		Verdict: VerdictFalsePositive, ReasonCode: ReasonOther, Analyst: "analyst",
	})
	if err != nil {
		t.Fatal(err)
	}
	if fb.Verification == nil || fb.Verification.Supported || fb.Verification.Changed {
		t.Fatalf("feedback alone must not be treated as proof: %+v", fb.Verification)
	}
	states, err := eng.States(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 0 {
		t.Fatalf("no classification change should have been stored: %+v", states)
	}
}

func TestVendorPatchVerifiedAgainstDistroAdvisory(t *testing.T) {
	eng, store := newEngine(t)
	seedAdvisories(t, store)
	ctx := context.Background()

	fb, err := eng.ApplyFeedback(ctx, Feedback{
		Finding: FindingRef{ID: "debian-openssl", CVE: "CVE-2023-5678", Product: "openssl",
			Version: "3.0.13-1~deb12u1", Ecosystem: "Debian:12",
			Applicability: string(model.ApplicabilityProbable)},
		Verdict: VerdictFalsePositive, ReasonCode: ReasonVendorPatch, Analyst: "analyst",
	})
	if err != nil {
		t.Fatal(err)
	}
	v := fb.Verification
	if !v.Supported || !v.Changed {
		t.Fatalf("vendor advisory evidence should support the claim: %+v", v)
	}
	if v.Reassessed != string(model.ApplicabilityNotAffected) {
		t.Fatalf("expected not_affected, got %s", v.Reassessed)
	}
	if v.Category != "fp:vendor_backport" {
		t.Fatalf("unexpected signature: %s", v.Category)
	}
	if len(v.Evidence) == 0 {
		t.Fatal("verification must carry evidence")
	}
	states, _ := eng.States(ctx)
	state, ok := states["debian-openssl"]
	if !ok || state.Applicability != string(model.ApplicabilityNotAffected) {
		t.Fatalf("analyst-verified state not applied: %+v", states)
	}
	if state.Verdict != VerdictFalsePositive {
		t.Fatalf("verdict not preserved on the state: %+v", state)
	}
}

func TestVendorPatchContradictedStaysVulnerable(t *testing.T) {
	eng, store := newEngine(t)
	seedAdvisories(t, store)
	ctx := context.Background()

	fb, err := eng.ApplyFeedback(ctx, Feedback{
		Finding: FindingRef{ID: "debian-curl", CVE: "CVE-2024-0001", Product: "curl",
			Version: "8.5.0-2", Ecosystem: "Debian:12",
			Applicability: string(model.ApplicabilityConfirmed)},
		Verdict: VerdictFalsePositive, ReasonCode: ReasonVendorPatch, Analyst: "analyst",
	})
	if err != nil {
		t.Fatal(err)
	}
	if fb.Verification.Supported || fb.Verification.Changed {
		t.Fatalf("contradicting evidence must not change the verdict: %+v", fb.Verification)
	}
	if !strings.Contains(fb.Verification.Explanation, "contradicts") {
		t.Fatalf("explanation should say the evidence contradicts the claim: %s", fb.Verification.Explanation)
	}
	if states, _ := eng.States(ctx); len(states) != 0 {
		t.Fatalf("no state should be stored: %+v", states)
	}
}

func TestVendorPatchWithoutDataIsInconclusive(t *testing.T) {
	eng, store := newEngine(t)
	seedAdvisories(t, store)
	ctx := context.Background()

	fb, err := eng.ApplyFeedback(ctx, Feedback{
		Finding: FindingRef{ID: "x", CVE: "CVE-2020-0000", Product: "nginx", Version: "1.24.0-1",
			Ecosystem: "Debian:12", Applicability: string(model.ApplicabilityConfirmed)},
		Verdict: VerdictFalsePositive, ReasonCode: ReasonVendorPatch, Analyst: "analyst",
	})
	if err != nil {
		t.Fatal(err)
	}
	if fb.Verification.Supported {
		t.Fatal("missing vendor data must not support the claim")
	}
	if fb.Verification.Category != "fp:missing_vendor_data" {
		t.Fatalf("expected missing-vendor-data signature, got %q", fb.Verification.Category)
	}
}

func TestIdentificationClaimOnSnapStub(t *testing.T) {
	eng, store := newEngine(t)
	seedAdvisories(t, store)
	ctx := context.Background()

	fb, err := eng.ApplyFeedback(ctx, Feedback{
		Finding: snapFinding(), Verdict: VerdictFalsePositive,
		ReasonCode: ReasonIdentification, Analyst: "analyst",
	})
	if err != nil {
		t.Fatal(err)
	}
	v := fb.Verification
	if !v.Supported || v.Reassessed != string(model.ApplicabilityNeedsInvestigation) {
		t.Fatalf("snap stub identification should resolve to needs_investigation: %+v", v)
	}
	if v.Category != "fp:snap_stub" {
		t.Fatalf("unexpected signature: %s", v.Category)
	}
}

// -------------------------------------------------------------- evaluation ---

func TestBaselineFixturesMatchShippedBehaviour(t *testing.T) {
	fixtures := BaselineFixtures()
	if len(fixtures) < 6 {
		t.Fatalf("expected a meaningful corpus, got %d fixtures", len(fixtures))
	}
	ev := Evaluate(assess.DefaultPolicy(), fixtures, time.Now())
	if len(ev.Regressions) != 0 {
		t.Fatalf("shipped policy must not regress its own corpus: %v", ev.Regressions)
	}
	if !ev.Candidate.Available {
		t.Fatal("labelled fixtures should produce metrics")
	}
	if ev.Candidate.Recall < 0.99 || ev.Candidate.Precision < 0.99 {
		t.Fatalf("shipped policy should score near-perfectly on the corpus: %+v", ev.Candidate)
	}
	// The default is not an improvement: no fixture changes behaviour.
	if len(ev.Fixed) != 0 || ev.Passed {
		t.Fatalf("the default policy is not an improvement candidate: %+v", ev)
	}
}

func TestSnapPolicyEvaluatesAsImprovement(t *testing.T) {
	pol := assess.DefaultPolicy()
	pol.SnapStubUnresolved = true
	ev := Evaluate(pol, BaselineFixtures(), time.Now())
	if !ev.Passed {
		t.Fatalf("expected the snap-stub rule to pass: %+v", ev)
	}
	if len(ev.Fixed) == 0 {
		t.Fatal("expected at least one corrected fixture")
	}
	if len(ev.Regressions) != 0 {
		t.Fatalf("no regressions expected: %v", ev.Regressions)
	}
	// Detection preserved: the real Thunderbird build is still reported.
	for _, c := range ev.Cases {
		if c.Fixture == "snap-real-build" && c.Candidate == string(model.ApplicabilityNotAffected) {
			t.Fatal("detection of the real build must be preserved")
		}
	}
}

func TestEvaluationRejectsPolicyThatDismissesVulnerableBuilds(t *testing.T) {
	// A fixture labelled "affected" whose expectation says not_affected encodes a
	// bogus rule. Evaluation must not pass it, even though the candidate matches
	// the expectation, because it dismisses a vulnerable build.
	adv := intel.Advisory{
		ID:     "DEBIAN-CVE-9000-9",
		Source: "Debian",
		Affected: []intel.Affected{
			{
				Ecosystem: "Debian:12",
				Name:      "openssl",
				Ranges: []intel.Range{
					{Type: "ECOSYSTEM", Events: []intel.Event{{Introduced: "0"}, {Fixed: "3.0.13-1"}}},
				},
			},
		},
	}
	fixtures := []Fixture{
		{
			ID:       "synthetic-vulnerable",
			Label:    "affected",
			Package:  model.Package{Name: "openssl", Version: "3.0.11-1", Ecosystem: "Debian:12"},
			Advisory: adv,
			Expect:   string(model.ApplicabilityConfirmed),
		},
	}
	// Break the expectation so the fixture claims the vulnerable build is clean.
	fixtures[0].Expect = string(model.ApplicabilityNotAffected)
	ev := Evaluate(assess.DefaultPolicy(), fixtures, time.Now())
	if ev.Passed {
		t.Fatal("an evaluation whose expectations dismiss a vulnerable build must not pass")
	}
}

func TestFixtureFromFeedbackUsesScanAdvisory(t *testing.T) {
	adv := intel.Advisory{ID: "UBUNTU-CVE-1", Source: "Ubuntu"}
	fb := Feedback{
		ID: "FB1",
		Finding: FindingRef{ID: "f1", Product: "thunderbird", Version: "2:1snap1-0ubuntu3",
			Ecosystem: "Ubuntu:24.04:LTS", AdvisoryID: "UBUNTU-CVE-1"},
		Verification: &Verification{Supported: true, Changed: true, Reassessed: string(model.ApplicabilityNeedsInvestigation)},
	}
	f, ok := FixtureFromFeedback(fb, []intel.Advisory{adv}, fb.Verification.Reassessed)
	if !ok {
		t.Fatal("expected a fixture")
	}
	if f.Expect != string(model.ApplicabilityNeedsInvestigation) || f.Origin != "feedback" {
		t.Fatalf("unexpected fixture: %+v", f)
	}
	// Unsupported reviews never generate fixtures.
	fb.Verification.Supported = false
	if _, ok := FixtureFromFeedback(fb, []intel.Advisory{adv}, fb.Verification.Reassessed); ok {
		t.Fatal("unsupported feedback must not create a fixture")
	}
}

// ----------------------------------------------------------- full lifecycle ---

func TestLifecycleProposeTestApproveDeployRollback(t *testing.T) {
	eng, store := newEngine(t)
	seedAdvisories(t, store)
	ctx := context.Background()

	// 1. analyst marks the snap stub as a false positive with structured evidence
	fb, err := eng.ApplyFeedback(ctx, Feedback{
		Finding: snapFinding(), Verdict: VerdictFalsePositive,
		ReasonCode: ReasonIdentification, Analyst: "derek",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !fb.Verification.Supported {
		t.Fatalf("expected supported verification: %+v", fb.Verification)
	}

	// 2. the improvement engine groups it into a proposal and evaluates it
	imps, err := eng.Analyze(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(imps) != 1 {
		t.Fatalf("expected one proposal, got %d", len(imps))
	}
	imp := imps[0]
	if imp.Status != StatusAwaitingApproval {
		t.Fatalf("expected awaiting_approval, got %s (%s)", imp.Status, imp.RejectedReason)
	}
	if imp.Policy == nil || !imp.Policy.SnapStubUnresolved {
		t.Fatalf("proposal should carry the snap-stub policy: %+v", imp.Policy)
	}
	if imp.Evaluation == nil || !imp.Evaluation.Passed {
		t.Fatalf("evaluation should pass: %+v", imp.Evaluation)
	}
	if len(imp.AffectedFindings) != 1 || imp.AffectedFindings[0] != "abc123" {
		t.Fatalf("affected findings not tracked: %v", imp.AffectedFindings)
	}

	// Running analysis again must not duplicate the proposal.
	again, err := eng.Analyze(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 1 || again[0].ID != imp.ID {
		t.Fatalf("analysis should be idempotent, got %+v", again)
	}

	// 3. deployment before approval is refused
	if _, err := eng.Transition(ctx, imp.ID, StatusDeployed, "derek", ""); err == nil {
		t.Fatal("deploy before approval must be refused")
	}

	// 4. approve (requires an actor)
	if _, err := eng.Transition(ctx, imp.ID, StatusApproved, "", ""); err == nil {
		t.Fatal("approval without an actor must be refused")
	}
	if _, err := eng.Transition(ctx, imp.ID, StatusApproved, "derek", "reviewed the fixtures"); err != nil {
		t.Fatal(err)
	}

	// 5. deploy activates a versioned rule
	deployed, err := eng.Transition(ctx, imp.ID, StatusDeployed, "derek", "deployed to detection policy")
	if err != nil {
		t.Fatal(err)
	}
	if deployed.RuleID == "" {
		t.Fatal("deployed improvement must reference its rule")
	}
	pol, ruleID, _ := eng.ActivePolicy(ctx)
	if ruleID != deployed.RuleID || !pol.SnapStubUnresolved {
		t.Fatalf("active policy not updated: rule=%q snap=%v", ruleID, pol.SnapStubUnresolved)
	}

	// 6. rollback returns to the shipped policy and records the event
	if _, err := eng.Transition(ctx, imp.ID, StatusRolledBack, "derek", "regression watch"); err != nil {
		t.Fatal(err)
	}
	pol, ruleID, _ = eng.ActivePolicy(ctx)
	if ruleID != "" || pol.SnapStubUnresolved {
		t.Fatalf("rollback should restore defaults: rule=%q snap=%v", ruleID, pol.SnapStubUnresolved)
	}

	events, err := eng.Events(ctx, imp.ID)
	if err != nil {
		t.Fatal(err)
	}
	var transitions []string
	for _, ev := range events {
		transitions = append(transitions, string(ev.From)+"→"+string(ev.To))
	}
	joined := strings.Join(transitions, ",")
	for _, want := range []string{"proposed→testing", "testing→awaiting_approval", "awaiting_approval→approved", "approved→deployed", "deployed→rolled_back"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing lifecycle event %q in %v", want, transitions)
		}
	}
}

func TestTransitionRejectsInvalidMoves(t *testing.T) {
	eng, store := newEngine(t)
	seedAdvisories(t, store)
	ctx := context.Background()

	if _, err := eng.ApplyFeedback(ctx, Feedback{Finding: snapFinding(), Verdict: VerdictFalsePositive,
		ReasonCode: ReasonIdentification, Analyst: "derek"}); err != nil {
		t.Fatal(err)
	}
	imps, err := eng.Analyze(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := imps[0].ID

	if _, err := eng.Transition(ctx, id, StatusDeployed, "derek", ""); err == nil {
		t.Fatal("awaiting_approval → deployed must be refused")
	}
	if _, err := eng.Transition(ctx, id, StatusRejected, "derek", ""); err == nil {
		t.Fatal("rejection without a reason must be refused")
	}
	if _, err := eng.Transition(ctx, id, StatusRejected, "derek", "duplicate of IMP-0001"); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Transition(ctx, id, StatusApproved, "derek", ""); err == nil {
		t.Fatal("rejected proposals must be terminal")
	}
}

// -------------------------------------------------------------- retention ----

func TestQualityMetricsAndRetention(t *testing.T) {
	eng, store := newEngine(t)
	seedAdvisories(t, store)
	ctx := context.Background()

	if _, err := eng.ApplyFeedback(ctx, Feedback{Finding: snapFinding(), Verdict: VerdictFalsePositive,
		ReasonCode: ReasonIdentification, Analyst: "derek"}); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.ApplyFeedback(ctx, Feedback{Finding: FindingRef{ID: "other"}, Verdict: VerdictConfirmed,
		ReasonCode: "", Analyst: "derek"}); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Analyze(ctx); err != nil {
		t.Fatal(err)
	}

	q, err := eng.Quality(ctx, FindingStats{Considered: 100, Actionable: 40, NeedsInvestigation: 10})
	if err != nil {
		t.Fatal(err)
	}
	if q.Reviewed != 2 || q.FalsePositives != 1 || q.Confirmed != 1 {
		t.Fatalf("unexpected review counts: %+v", q)
	}
	if q.FalsePositiveRate == nil || *q.FalsePositiveRate != 0.5 {
		t.Fatalf("false-positive rate over reviewed findings should be 0.5: %+v", q.FalsePositiveRate)
	}
	if q.ReviewedRate == nil || *q.ReviewedRate != 0.02 {
		t.Fatalf("reviewed rate should reflect the finding population: %+v", q.ReviewedRate)
	}
	if q.OpenImprovements != 1 || q.DeployedImprovements != 0 {
		t.Fatalf("improvement counts wrong: %+v", q)
	}
	if len(q.Notes) == 0 {
		t.Fatal("small-sample caveat missing")
	}

	// Export and delete
	exp, err := eng.ExportFeedback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(exp.Feedback) != 2 || len(exp.States) != 1 {
		t.Fatalf("export must include history and states: %+v", exp)
	}
	raw, err := json.Marshal(exp)
	if err != nil || len(raw) == 0 {
		t.Fatalf("export should be serialisable: %v", err)
	}
	if err := eng.DeleteFeedback(ctx, snapFinding().ID); err != nil {
		t.Fatal(err)
	}
	states, _ := eng.States(ctx)
	if _, ok := states[snapFinding().ID]; ok {
		t.Fatal("deleting feedback must also remove the analyst-verified state")
	}
}

func mustOpen(t *testing.T, path string) *intel.Store {
	t.Helper()
	s, err := intel.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
