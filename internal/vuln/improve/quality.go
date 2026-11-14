package improve

import (
	"context"
	"encoding/json"
	"fmt"
)

// FindingStats are the scanner-side counts the quality view needs. They are
// passed in by the caller (the API has the current dataset) so this package
// never re-derives findings.
type FindingStats struct {
	Considered         int
	Actionable         int
	NeedsInvestigation int
}

// Quality computes detection-quality metrics from reviewed findings.
//
// The false-positive rate is deliberately reported only over reviewed findings:
// there is no ground truth for unreviewed findings, so a population-wide
// "precision" would be fabricated. The UI shows the sample size next to it.
func (e *Engine) Quality(ctx context.Context, stats FindingStats) (QualityMetrics, error) {
	q := QualityMetrics{
		FindingsConsidered:         stats.Considered,
		Actionable:                 stats.Actionable,
		NeedsInvestigationFindings: stats.NeedsInvestigation,
	}

	feedback, err := e.RecentFeedback(ctx, 5000)
	if err != nil {
		return q, err
	}
	reviewed := map[string]bool{}
	for _, fb := range feedback {
		if !reviewed[fb.Finding.ID] {
			reviewed[fb.Finding.ID] = true
			q.Reviewed++
		}
		switch fb.Verdict {
		case VerdictConfirmed:
			q.Confirmed++
		case VerdictFalsePositive:
			q.FalsePositives++
		case VerdictNeedsInvestigation:
			q.NeedsInvestigation++
		case VerdictRemediated:
			q.Remediated++
		}
		if fb.Verification == nil {
			continue
		}
		switch {
		case fb.Verification.Supported && fb.Verification.Changed:
			q.VerificationSupported++
		case fb.Verification.Supported:
			q.VerificationSupported++
		case fb.Verification.Confidence == "high" && !fb.Verification.Supported:
			q.VerificationContradicted++
		default:
			q.VerificationInconclusive++
		}
	}

	if q.Reviewed > 0 {
		rate := float64(q.FalsePositives) / float64(q.Reviewed)
		q.FalsePositiveRate = &rate
	} else {
		q.Notes = append(q.Notes, "no findings reviewed yet: no false-positive rate can be computed")
	}
	if stats.Considered > 0 {
		rate := float64(q.Reviewed) / float64(stats.Considered)
		q.ReviewedRate = &rate
	}

	counts, err := e.CountByStatus(ctx)
	if err != nil {
		return q, err
	}
	for status, n := range counts {
		switch status {
		case StatusDeployed, StatusMonitoring:
			q.DeployedImprovements += n
		case StatusRejected:
			q.RejectedImprovements += n
		case StatusDiscovered, StatusResearching, StatusProposed, StatusTesting, StatusAwaitingApproval, StatusApproved:
			q.OpenImprovements += n
		}
	}
	if q.Reviewed < 5 {
		noun := "findings"
		if q.Reviewed == 1 {
			noun = "finding"
		}
		q.Notes = append(q.Notes, fmt.Sprintf(
			"%d reviewed %s: the false-positive rate is anecdotal until at least 5 are reviewed", q.Reviewed, noun))
	}
	if q.VerificationInconclusive > 0 {
		q.Notes = append(q.Notes,
			"some reviews could not be verified against cached advisories; they are recorded but did not change a classification")
	}
	return q, nil
}

// FeedbackExport is the portable review history (for export/delete requests).
type FeedbackExport struct {
	GeneratedAt string     `json:"generated_at"`
	Feedback    []Feedback `json:"feedback"`
	States      []State    `json:"states"`
}

// ExportFeedback returns review history and analyst-verified states.
func (e *Engine) ExportFeedback(ctx context.Context) (FeedbackExport, error) {
	feedback, err := e.RecentFeedback(ctx, 10000)
	if err != nil {
		return FeedbackExport{}, err
	}
	states, err := e.States(ctx)
	if err != nil {
		return FeedbackExport{}, err
	}
	out := FeedbackExport{GeneratedAt: e.now().Format("2006-01-02T15:04:05Z07:00"), Feedback: feedback}
	for _, s := range states {
		out.States = append(out.States, s)
	}
	return out, nil
}

// DeleteFeedback removes review history for one finding (data-deletion request).
// Analyst-verified states are removed with it so no orphaned overrides remain.
func (e *Engine) DeleteFeedback(ctx context.Context, findingID string) error {
	if findingID == "" {
		return fmt.Errorf("finding id is required")
	}
	if _, err := e.db.ExecContext(ctx, `DELETE FROM finding_feedback WHERE finding_id = ?`, findingID); err != nil {
		return err
	}
	_, err := e.db.ExecContext(ctx, `DELETE FROM finding_state WHERE finding_id = ?`, findingID)
	return err
}

// PurgeFeedbackBefore drops reviews older than a cutoff (retention policy).
func (e *Engine) PurgeFeedbackBefore(ctx context.Context, cutoff string) (int64, error) {
	res, err := e.db.ExecContext(ctx, `DELETE FROM finding_feedback WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// MarshalVerification is a small helper for API responses that need the stored
// verification payload as raw JSON.
func MarshalVerification(v *Verification) json.RawMessage {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
