package improve

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/assess"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// ActivePolicy is the scan-time entry point: it returns the detection policy
// currently deployed by the improvement engine (or the shipped defaults).
func ActivePolicy(ctx context.Context, store *intel.Store) (assess.Policy, string, []string, error) {
	eng, err := New(store)
	if err != nil {
		// A broken improvement database must not stop scanning; fall back to the
		// shipped policy and surface the reason.
		return assess.DefaultPolicy(), "", []string{"improvement engine unavailable: " + err.Error()}, err
	}
	pol, ruleID, notes := eng.ActivePolicy(ctx)
	return pol, ruleID, notes, nil
}

// pattern is the deterministic description of one recurring limitation.
type pattern struct {
	Signature string
	Category  Category
	Title     string
	Problem   string
	Proposed  string
	Benefit   string
	Risk      string
	// Policy is the candidate detection policy. Nil means "no safe automated
	// change exists": the proposal is recorded for research and cannot be
	// tested or deployed.
	Policy *assess.Policy
}

// patternsFor maps a verification signature to a concrete proposal. This is a
// lookup table, not a model: the same evidence always yields the same proposal.
func patternsFor(signature string, sample Feedback) pattern {
	switch signature {
	case "fp:snap_stub":
		pol := assess.DefaultPolicy()
		pol.SnapStubUnresolved = true
		return pattern{
			Signature: signature,
			Category:  CategoryDetectionAccuracy,
			Title:     "Stop resolving snap transition packages from vendor version data",
			Problem: "Snap transition packages (" + quoteVersion(sample) + ") carry no application code, but Ubuntu's advisory " +
				"enumerates the stub version, so the scanner reported it as a confirmed vulnerability.",
			Proposed: "Treat versions carrying a snap transition marker as unresolved (needs investigation) instead of " +
				"confirming them from the distribution's affected-version enumeration.",
			Benefit: "Removes a class of false positives for packages that were migrated to snaps, without dismissing " +
				"real builds of the same product.",
			Risk:   "low",
			Policy: &pol,
		}
	case "fp:vendor_backport":
		pol := assess.DefaultPolicy()
		pol.BackportOutcome = string(model.ApplicabilityNeedsInvestigation)
		return pattern{
			Signature: signature,
			Category:  CategoryDetectionAccuracy,
			Title:     "Require vendor confirmation before treating upstream range matches on distro builds as probable",
			Problem: "When only an upstream advisory is available, a distribution build with a backported fix still lands " +
				"in the remediation queue as 'probable'. Analysts repeatedly verified such findings as not applicable.",
			Proposed: "Classify upstream-only matches on distribution builds as needs investigation instead of probable, " +
				"so they are reviewed before they count as actionable.",
			Benefit: "Reduces actionable false positives on distributions that backport security fixes.",
			Risk:    "medium",
			Policy:  &pol,
		}
	case "fp:foreign_build":
		return pattern{
			Signature: signature,
			Category:  CategoryCoverage,
			Title:     "Distinguish vendor builds from third-party rebuilds",
			Problem: "The scanner can detect that a package is a third-party rebuild (for example NodeSource) but cannot " +
				"say which advisory range applies to it, so those findings stay unresolved.",
			Proposed: "Record package provenance (maintainer/origin fields from dpkg and rpm metadata) and match against " +
				"the packager's advisories when they are available.",
			Benefit: "Turns unresolved third-party findings into either confident matches or confirmed non-issues.",
			Risk:    "medium",
		}
	case "fp:missing_vendor_data":
		return pattern{
			Signature: signature,
			Category:  CategoryIntelligence,
			Title:     "Fetch the vendor advisory during verification",
			Problem: "Analysts reported a vendor patch, but no distribution advisory for that CVE was cached, so the " +
				"claim could not be verified without leaving the tool.",
			Proposed: "On a verified vendor-patch claim, fetch the distribution advisory for that CVE and cache it, then " +
				"re-correlate the finding.",
			Benefit: "Turns an inconclusive review into a verified classification and improves the cache for later scans.",
			Risk:    "low",
		}
	case "fp:configuration_evidence":
		return pattern{
			Signature: signature,
			Category:  CategoryCoverage,
			Title:     "Collect configuration evidence for applicability claims",
			Problem: "Claims such as 'the vulnerable feature is not enabled' cannot be checked because the scanner does " +
				"not collect the relevant configuration.",
			Proposed: "Add read-only configuration collectors (service enablement, listener bindings, module lists) and " +
				"make applicability rules able to require them.",
			Benefit: "Allows configuration-dependent advisories to be resolved instead of guessed.",
			Risk:    "medium",
		}
	default:
		return pattern{
			Signature: signature,
			Category:  CategoryDetectionAccuracy,
			Title:     "Investigate recurring review outcome",
			Problem:   "Analysts repeatedly reached the same conclusion for this class of finding.",
			Proposed:  "Research the limitation and define a deterministic rule change with fixtures.",
			Benefit:   "Less manual review for this finding class.",
			Risk:      "medium",
		}
	}
}

func quoteVersion(fb Feedback) string {
	if fb.Finding.Version == "" {
		return "unknown version"
	}
	return fb.Finding.Version
}

// Analyze groups verified reviews into improvement proposals, evaluates any
// candidate rule against fixtures, and returns the improvements touched.
//
// It is deterministic and idempotent: running it twice without new feedback
// updates the same proposals rather than creating duplicates.
func (e *Engine) Analyze(ctx context.Context) ([]Improvement, error) {
	feedback, err := e.RecentFeedback(ctx, 500)
	if err != nil {
		return nil, err
	}

	groups := map[string][]Feedback{}
	for _, fb := range feedback {
		if fb.Verdict != VerdictFalsePositive || fb.Verification == nil || !fb.Verification.Supported {
			continue
		}
		sig := fb.Verification.Category
		if sig == "" {
			continue
		}
		groups[sig] = append(groups[sig], fb)
	}
	sigs := make([]string, 0, len(groups))
	for sig := range groups {
		sigs = append(sigs, sig)
	}
	sort.Strings(sigs)

	var out []Improvement
	for _, sig := range sigs {
		group := groups[sig]
		imp, err := e.upsertProposal(ctx, sig, group)
		if err != nil {
			return nil, err
		}
		if imp != nil {
			out = append(out, *imp)
		}
	}
	return out, nil
}

func (e *Engine) upsertProposal(ctx context.Context, signature string, group []Feedback) (*Improvement, error) {
	pat := patternsFor(signature, group[0])

	existing, err := e.FindBySignature(ctx, signature)
	if err != nil {
		return nil, err
	}

	// Only merge into proposals that have not already been decided. A deployed
	// improvement receiving new feedback means the rule did not cover the case,
	// which must produce a fresh proposal instead of silently editing history.
	mergeable := existing != nil && (existing.Status == StatusProposed ||
		existing.Status == StatusTesting || existing.Status == StatusAwaitingApproval)

	imp := Improvement{}
	if mergeable {
		imp = *existing
	} else {
		imp = Improvement{
			ID:        newID("IMP"),
			Category:  pat.Category,
			Status:    StatusProposed,
			Signature: signature,
			CreatedAt: e.now(),
		}
	}
	imp.Category = pat.Category
	imp.Title = pat.Title
	imp.Problem = pat.Problem
	imp.ProposedChange = pat.Proposed
	imp.ExpectedBenefit = pat.Benefit
	imp.RiskLevel = pat.Risk
	imp.Policy = pat.Policy
	imp.PolicyNotes = nil
	if pat.Policy != nil {
		imp.PolicyNotes = pat.Policy.Notes()
	}

	seen := map[string]bool{}
	for _, id := range imp.AffectedFindings {
		seen[id] = true
	}
	for _, fb := range group {
		if fb.Finding.ID == "" || seen[fb.Finding.ID] {
			continue
		}
		seen[fb.Finding.ID] = true
		imp.AffectedFindings = append(imp.AffectedFindings, fb.Finding.ID)
	}
	sort.Strings(imp.AffectedFindings)
	imp.Evidence = evidenceFor(group)

	// Fixtures: the shipped corpus plus one case per verified review.
	fixtures := BaselineFixtures()
	for _, fb := range group {
		advisories, err := e.store.AdvisoriesFor(ctx, fb.Finding.Ecosystem, fb.Finding.Product)
		if err != nil {
			continue
		}
		expect := fb.Verification.Reassessed
		if pat.Policy != nil {
			// A policy tightening is expected to produce its target outcome for
			// the reviewed finding, which is what the tests then verify.
			expect = policyExpectation(*pat.Policy, fb.Finding.Applicability)
		}
		if f, ok := FixtureFromFeedback(fb, advisories, expect); ok {
			fixtures = append(fixtures, f)
		}
	}
	imp.Fixtures = SortedFixtures(fixtures)

	if imp.Policy == nil {
		// No safe automated change exists yet: keep it in research, never deployable.
		imp.Status = StatusDiscovered
		imp.Evaluation = nil
		imp.UpdatedAt = e.now()
		if err := e.SaveImprovement(ctx, imp); err != nil {
			return nil, err
		}
		_ = e.AppendEvent(ctx, Event{ImprovementID: imp.ID, From: StatusDiscovered, To: StatusDiscovered,
			Actor: "system:caie", Note: "proposal recorded; no deterministic rule change is defined yet"})
		return &imp, nil
	}

	// Proposed → testing → pass/fail, all recorded.
	before := imp.Status
	if err := e.SaveImprovement(ctx, imp); err != nil {
		return nil, err
	}
	if before != StatusProposed && !mergeable {
		before = imp.Status
	}
	_ = e.AppendEvent(ctx, Event{ImprovementID: imp.ID, From: before, To: StatusTesting,
		Actor: "system:caie", Note: fmt.Sprintf("%d fixtures evaluated", len(imp.Fixtures))})

	evaluation := Evaluate(*imp.Policy, imp.Fixtures, e.now())
	imp.Evaluation = &evaluation
	imp.Status = StatusTesting
	if evaluation.Passed {
		imp.Status = StatusAwaitingApproval
	} else {
		imp.Status = StatusRejected
		imp.RejectedReason = strings.Join(evaluation.Notes, "; ")
		if imp.RejectedReason == "" {
			imp.RejectedReason = "evaluation failed"
		}
	}
	imp.UpdatedAt = e.now()
	if err := e.SaveImprovement(ctx, imp); err != nil {
		return nil, err
	}
	_ = e.AppendEvent(ctx, Event{ImprovementID: imp.ID, From: StatusTesting, To: imp.Status,
		Actor: "system:caie", Note: evaluationSummary(evaluation)})

	// Link the reviews that produced this proposal.
	for _, fb := range group {
		_, _ = e.db.ExecContext(ctx, `UPDATE finding_feedback SET improvement_id = ? WHERE id = ?`, imp.ID, fb.ID)
	}
	return &imp, nil
}

// policyExpectation is the outcome a policy is expected to produce for a finding
// that the shipped policy classified as "original".
func policyExpectation(pol assess.Policy, original string) string {
	if pol.SnapStubUnresolved {
		return string(model.ApplicabilityNeedsInvestigation)
	}
	if pol.BackportOutcome == string(model.ApplicabilityNeedsInvestigation) {
		return string(model.ApplicabilityNeedsInvestigation)
	}
	return original
}

func evaluationSummary(ev Evaluation) string {
	if ev.Passed {
		return fmt.Sprintf("passed: %d fixtures, %d behaviours corrected, no regressions",
			len(ev.Cases), len(ev.Fixed))
	}
	if len(ev.Regressions) > 0 {
		return "failed: " + strings.Join(ev.Regressions, "; ")
	}
	return "failed: " + strings.Join(ev.Notes, "; ")
}

func evidenceFor(group []Feedback) []model.Evidence {
	var out []model.Evidence
	for _, fb := range group {
		if fb.Verification == nil {
			continue
		}
		detail := fmt.Sprintf("%s %s (%s): %s", fb.Finding.Product, fb.Finding.Version,
			fb.Finding.CVE, fb.Verification.Explanation)
		out = append(out, model.Evidence{
			Kind:   "analyst_review",
			Source: fb.Analyst,
			Detail: detail,
		})
		for _, ev := range fb.Verification.Evidence {
			if ev.Kind == "vendor_advisory_not_affected" || ev.Kind == "package_identity" {
				out = append(out, ev)
			}
		}
	}
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

// EvaluateImprovement re-runs the fixture suite for a proposal. It is the
// explicit "Run tests" action and the guard used before deployment.
func (e *Engine) EvaluateImprovement(ctx context.Context, id string) (*Improvement, error) {
	imp, err := e.GetImprovement(ctx, id)
	if err != nil || imp == nil {
		return nil, fmt.Errorf("improvement %q not found", id)
	}
	if imp.Policy == nil {
		return nil, fmt.Errorf("improvement %q has no testable rule change", id)
	}
	if imp.Status == StatusDeployed || imp.Status == StatusRolledBack {
		return nil, fmt.Errorf("improvement %q is %s and can no longer be re-tested", id, imp.Status)
	}
	evaluation := Evaluate(*imp.Policy, imp.Fixtures, e.now())
	imp.Evaluation = &evaluation
	from := imp.Status
	switch {
	case evaluation.Passed:
		imp.Status = StatusAwaitingApproval
	case imp.Status == StatusApproved:
		// An approved proposal that now fails must not stay approveable.
		imp.Status = StatusRejected
		imp.RejectedReason = strings.Join(evaluation.Notes, "; ")
	default:
		imp.Status = StatusRejected
		imp.RejectedReason = strings.Join(evaluation.Notes, "; ")
	}
	imp.UpdatedAt = e.now()
	if err := e.SaveImprovement(ctx, *imp); err != nil {
		return nil, err
	}
	_ = e.AppendEvent(ctx, Event{ImprovementID: id, From: from, To: imp.Status,
		Actor: "system:caie", Note: evaluationSummary(evaluation)})
	return imp, nil
}

// Transition moves a proposal through the lifecycle, enforcing guards and
// recording every step. Deployment is the only operation that changes scan
// behaviour, and it requires a passed evaluation plus an explicit approval.
func (e *Engine) Transition(ctx context.Context, id string, to Status, actor, note string) (*Improvement, error) {
	imp, err := e.GetImprovement(ctx, id)
	if err != nil {
		return nil, err
	}
	if imp == nil {
		return nil, fmt.Errorf("improvement %q not found", id)
	}
	if actor == "" {
		return nil, fmt.Errorf("an actor is required for every lifecycle transition")
	}
	if !CanTransition(imp.Status, to) {
		return nil, fmt.Errorf("cannot move improvement from %s to %s", imp.Status, to)
	}

	switch to {
	case StatusApproved:
		if imp.Evaluation == nil || !imp.Evaluation.Passed {
			return nil, fmt.Errorf("improvement has no passing evaluation; run the tests before approving")
		}
		now := e.now()
		imp.ApprovedBy = actor
		imp.ApprovedAt = &now
	case StatusDeployed:
		if imp.Status != StatusApproved {
			return nil, fmt.Errorf("only an approved improvement can be deployed")
		}
		if imp.Policy == nil {
			return nil, fmt.Errorf("improvement has no rule change to deploy")
		}
		// Re-evaluate immediately before touching production behaviour: a stale
		// payload must not deploy untested code paths.
		fresh := Evaluate(*imp.Policy, imp.Fixtures, e.now())
		if !fresh.Passed {
			return nil, fmt.Errorf("re-evaluation at deploy time failed: %s", evaluationSummary(fresh))
		}
		imp.Evaluation = &fresh
		payload, err := assess.MarshalPolicy(*imp.Policy)
		if err != nil {
			return nil, err
		}
		rule, err := e.activateRule(ctx, RuleKindDetectionPolicy, string(payload), imp.ID)
		if err != nil {
			return nil, err
		}
		now := e.now()
		imp.RuleID = rule.ID
		imp.DeployedAt = &now
	case StatusRolledBack:
		deactivated, err := e.deactivateRule(ctx, RuleKindDetectionPolicy)
		if err != nil {
			return nil, err
		}
		if err := e.restorePreviousRule(ctx, RuleKindDetectionPolicy, deactivated); err != nil {
			return nil, err
		}
		now := e.now()
		imp.RolledBackAt = &now
	case StatusRejected:
		if strings.TrimSpace(note) == "" {
			return nil, fmt.Errorf("a rejection requires a reason")
		}
		imp.RejectedReason = note
	}

	from := imp.Status
	imp.Status = to
	imp.UpdatedAt = e.now()
	if err := e.SaveImprovement(ctx, *imp); err != nil {
		return nil, err
	}
	if err := e.AppendEvent(ctx, Event{ImprovementID: id, From: from, To: to, Actor: actor, Note: note}); err != nil {
		return nil, err
	}
	return imp, nil
}

// restorePreviousRule re-activates the newest rule version below the one that was
// just deactivated, so a rollback returns to the previous known-good behaviour.
//
// The previous id is read and the row set closed before the update: the store
// serialises SQLite onto one connection, so issuing a write while a query is
// still open would deadlock.
func (e *Engine) restorePreviousRule(ctx context.Context, kind string, justDeactivated *Rule) error {
	exclude := ""
	if justDeactivated != nil {
		exclude = justDeactivated.ID
	}
	rows, err := e.db.QueryContext(ctx, `SELECT id FROM improvement_rules
		WHERE kind = ? AND active = 0 AND deactivated_at IS NOT NULL AND id <> ?
		ORDER BY version DESC LIMIT 1`, kind, exclude)
	if err != nil {
		return err
	}
	var previous string
	if rows.Next() {
		if err := rows.Scan(&previous); err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()
	if previous == "" {
		return nil // nothing to restore: defaults are now in force
	}
	_, err = e.db.ExecContext(ctx, `UPDATE improvement_rules SET active = 1, deactivated_at = NULL WHERE id = ?`, previous)
	return err
}
