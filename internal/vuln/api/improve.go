package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/improve"
	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// ---------------------------------------------------------------- dataset bits ---

// analystView is the analyst-verified overlay on a finding. The scanner's own
// classification is never overwritten; both are exposed.
type analystView struct {
	Verdict       string        `json:"verdict"`
	Applicability string        `json:"applicability"`
	Confidence    string        `json:"confidence"`
	Explanation   string        `json:"explanation"`
	Evidence      []evidenceRow `json:"evidence,omitempty"`
	VerifiedAt    string        `json:"verified_at"`
}

// effective is the classification the UI should treat as current: an
// evidence-backed analyst correction wins, otherwise the scanner verdict.
func (v vulnRow) effective() string {
	if v.Analyst != nil && v.Analyst.Applicability != "" {
		return v.Analyst.Applicability
	}
	return v.Affected
}

// applyAnalystStates overlays verified corrections onto the finding rows.
func (d *dataset) applyAnalystStates(states map[string]improve.State) {
	apply := func(v *vulnRow) {
		st, ok := states[v.ID]
		if !ok {
			return
		}
		v.Effective = st.Applicability
		view := &analystView{
			Verdict:       string(st.Verdict),
			Applicability: st.Applicability,
			Confidence:    st.Confidence,
			Explanation:   st.Explanation,
			VerifiedAt:    st.UpdatedAt.UTC().Format(time.RFC3339),
		}
		for _, e := range st.Evidence {
			view.Evidence = append(view.Evidence, evidenceRow{Kind: e.Kind, Detail: e.Detail, URL: e.URL, Source: e.Source})
		}
		v.Analyst = view
	}
	for host := range d.Hosts {
		hv := d.Hosts[host]
		for i := range hv.Findings {
			apply(&hv.Findings[i])
		}
	}
	for i := range d.Vulns {
		apply(&d.Vulns[i])
	}
	for id, row := range d.ByID {
		apply(row)
		d.ByID[id] = row
	}
}

// --------------------------------------------------------------- feedback API ---

func (s *Server) handleFindingFeedback(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Verdict    string `json:"verdict"`
		ReasonCode string `json:"reason_code"`
		ReasonText string `json:"reason_text"`
		Analyst    string `json:"analyst"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	verdict := improve.Verdict(req.Verdict)
	if !improve.ValidVerdict(verdict) {
		writeError(w, http.StatusBadRequest, "invalid_verdict",
			"verdict must be confirmed, false_positive, needs_investigation, remediated or request_verification")
		return
	}
	reason := improve.ReasonCode(req.ReasonCode)
	if !improve.ValidReason(reason) {
		writeError(w, http.StatusBadRequest, "invalid_reason",
			"reason_code must be vendor_patch_installed, incorrect_identification, feature_not_enabled, advisory_not_applicable or other")
		return
	}
	if verdict == improve.VerdictFalsePositive && reason == "" {
		writeError(w, http.StatusBadRequest, "reason_required",
			"a false-positive review needs a reason code so the system can verify it")
		return
	}

	ds, err := s.buildDataset(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dataset_error", err.Error())
		return
	}
	row, ok := ds.ByID[id]
	if !ok {
		writeError(w, http.StatusNotFound, "finding_not_found", "no finding with that identifier")
		return
	}

	ref := improve.FindingRef{
		ID: row.ID, ReportID: row.ReportID, Host: row.Asset, CVE: row.CVE,
		AdvisoryID: row.AdvisoryID, Product: row.Product, Version: row.InstalledVersion,
		Ecosystem: row.Ecosystem, Severity: row.Severity,
		Applicability: row.Affected, Confidence: row.Confidence, Explanation: row.Explanation,
	}
	fb, err := s.improve.ApplyFeedback(r.Context(), improve.Feedback{
		Finding: ref, Verdict: verdict, ReasonCode: reason,
		ReasonText: sanitizeText(req.ReasonText), Analyst: firstNonEmpty(req.Analyst, "web-ui"),
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "feedback_rejected", err.Error())
		return
	}

	// Surface any proposal this review created or updated.
	improvements, _ := s.improve.Analyze(r.Context())
	var touched []string
	for _, imp := range improvements {
		for _, id := range imp.AffectedFindings {
			if id == row.ID {
				touched = append(touched, imp.ID)
				break
			}
		}
	}
	states, _ := s.improve.States(r.Context())
	state, hasState := states[row.ID]

	writeJSON(w, http.StatusAccepted, map[string]any{
		"feedback":        fb,
		"verification":    fb.Verification,
		"state":           stateOrNil(state, hasState),
		"improvement_ids": touched,
		"note":            "feedback is recorded; the classification only changes when advisory evidence supports it",
	})
}

func (s *Server) handleFindingHistory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	feedback, err := s.improve.FeedbackForFinding(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "history_error", err.Error())
		return
	}
	states, err := s.improve.States(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "history_error", err.Error())
		return
	}
	state, ok := states[id]
	out := map[string]any{"feedback": feedback}
	if ok {
		out["state"] = state
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeleteFeedback(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.improve.DeleteFeedback(r.Context(), id); err != nil {
		writeError(w, http.StatusBadRequest, "delete_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func stateOrNil(st improve.State, ok bool) *improve.State {
	if !ok {
		return nil
	}
	return &st
}

// ------------------------------------------------------------ improvement API ---

func (s *Server) handleImprovements(w http.ResponseWriter, r *http.Request) {
	items, err := s.improve.ListImprovements(r.Context(), 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "improvements_error", err.Error())
		return
	}
	status := r.URL.Query().Get("status")
	if status != "" {
		filtered := items[:0]
		for _, imp := range items {
			if string(imp.Status) == status {
				filtered = append(filtered, imp)
			}
		}
		items = filtered
	}
	counts, _ := s.improve.CountByStatus(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"counts": counts,
		"total":  len(items),
	})
}

func (s *Server) handleImprovement(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	imp, err := s.improve.GetImprovement(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "improvement_error", err.Error())
		return
	}
	if imp == nil {
		writeError(w, http.StatusNotFound, "improvement_not_found", "no improvement with that id")
		return
	}
	events, _ := s.improve.Events(r.Context(), id)
	rules, _ := s.improve.ListRules(r.Context())
	activePolicy, activeRuleID, notes := s.improve.ActivePolicy(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"improvement": imp,
		"events":      events,
		"rules":       rules,
		"active": map[string]any{
			"rule_id": activeRuleID,
			"notes":   notes,
			"policy":  activePolicy,
		},
	})
}

func (s *Server) handleImprovementTransition(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		To    string `json:"to"`
		Actor string `json:"actor"`
		Note  string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	target := improve.Status(req.To)
	imp, err := s.improve.Transition(r.Context(), id, target, firstNonEmpty(req.Actor, "web-ui"), sanitizeText(req.Note))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "transition_rejected", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"improvement": imp})
}

func (s *Server) handleImprovementEvaluate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	imp, err := s.improve.EvaluateImprovement(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "evaluation_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"improvement": imp})
}

func (s *Server) handleQuality(w http.ResponseWriter, r *http.Request) {
	ds, err := s.buildDataset(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dataset_error", err.Error())
		return
	}
	stats := improve.FindingStats{}
	seen := map[string]bool{}
	for host := range ds.Hosts {
		for _, f := range ds.Hosts[host].Findings {
			if f.Affected == string(model.ApplicabilityNotAffected) {
				continue
			}
			if !seen[f.ID] {
				seen[f.ID] = true
				stats.Considered++
			}
			switch f.effective() {
			case string(model.ApplicabilityConfirmed), string(model.ApplicabilityValidated), string(model.ApplicabilityProbable):
				stats.Actionable++
			case string(model.ApplicabilityNeedsInvestigation):
				stats.NeedsInvestigation++
			}
		}
	}
	q, err := s.improve.Quality(r.Context(), stats)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "quality_error", err.Error())
		return
	}
	counts, _ := s.improve.CountByStatus(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"metrics":            q,
		"improvement_counts": counts,
		"recent_feedback":    recentFeedbackSummaries(r.Context(), s),
	})
}

func recentFeedbackSummaries(ctx context.Context, s *Server) []map[string]any {
	feedback, err := s.improve.RecentFeedback(ctx, 20)
	if err != nil {
		return nil
	}
	out := make([]map[string]any, 0, len(feedback))
	for _, fb := range feedback {
		row := map[string]any{
			"finding_id": fb.Finding.ID,
			"cve":        fb.Finding.CVE,
			"product":    fb.Finding.Product,
			"verdict":    fb.Verdict,
			"reason":     fb.ReasonCode,
			"analyst":    fb.Analyst,
			"created_at": fb.CreatedAt,
		}
		if fb.Verification != nil {
			row["supported"] = fb.Verification.Supported
			row["explanation"] = fb.Verification.Explanation
		}
		out = append(out, row)
	}
	return out
}

func (s *Server) handleFeedbackExport(w http.ResponseWriter, r *http.Request) {
	exp, err := s.improve.ExportFeedback(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "export_error", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="clanker-guard-feedback.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(exp)
}

// ------------------------------------------------------- improvement answers ---

// answerImprovementQuestion answers questions about detection quality and the
// improvement loop from stored evidence. Returns ok=false to fall through to the
// finding-oriented Ask Guard implementation.
func (s *Server) answerImprovementQuestion(ctx context.Context, ds *dataset, question string) (string, []map[string]any, bool) {
	q := strings.ToLower(question)

	wantsLearning := strings.Contains(q, "learn") || strings.Contains(q, "false-positive review") ||
		strings.Contains(q, "false positive review") || strings.Contains(q, "my reviews")
	wantsMissing := strings.Contains(q, "capabilit") || strings.Contains(q, "missing") || strings.Contains(q, "not supported")
	wantsTests := strings.Contains(q, "test") && (strings.Contains(q, "support") || strings.Contains(q, "fixture") || strings.Contains(q, "proposed"))
	wantsImprovements := strings.Contains(q, "improvement")

	if !wantsLearning && !wantsMissing && !wantsTests && !wantsImprovements {
		return "", nil, false
	}

	improvements, _ := s.improve.ListImprovements(ctx, 50)
	counts, _ := s.improve.CountByStatus(ctx)
	var b strings.Builder

	switch {
	case wantsTests:
		var target *improve.Improvement
		for i := range improvements {
			if improvements[i].Evaluation != nil {
				target = &improvements[i]
				break
			}
		}
		if target == nil {
			b.WriteString("No improvement has been evaluated yet, so there are no test results to show.")
			return b.String(), nil, true
		}
		fmt.Fprintf(&b, "Improvement %s (%s) was evaluated against %d fixtures: %d corrected behaviour(s), %d regression(s).\n\n",
			target.ID, target.Title, len(target.Evaluation.Cases), len(target.Evaluation.Fixed), len(target.Evaluation.Regressions))
		b.WriteString("Cases:\n")
		for _, c := range target.Evaluation.Cases {
			status := "pass"
			if !c.Pass {
				status = "fail"
			}
			fmt.Fprintf(&b, "- %s [%s] expected %s, baseline %s, candidate %s\n",
				c.Fixture, status, c.Expected, c.Baseline, c.Candidate)
		}
		if target.Evaluation.Passed {
			b.WriteString("\nThe candidate passed: no vulnerable fixture was dismissed and no patched fixture was re-reported.")
		} else {
			b.WriteString("\nThe candidate did not pass and cannot be deployed.")
		}
		return b.String(), improvementCitations(improvements, ds), true

	case wantsMissing:
		b.WriteString("Capabilities this build does not implement (reported by the API, not inferred):\n")
		b.WriteString("- network assessment (service discovery, TLS/SSH analysis, safe validation)\n")
		b.WriteString("- SBOM ingestion and CycloneDX export\n")
		b.WriteString("- managed agent check-in (no push channel, no mutual TLS yet)\n")
		if ds != nil {
			seen := map[string]bool{}
			for host := range ds.Hosts {
				for _, nc := range ds.Hosts[host].Coverage.NotCovered {
					if seen[nc] {
						continue
					}
					seen[nc] = true
					fmt.Fprintf(&b, "- coverage gap: %s\n", nc)
				}
			}
		}
		var discovered []string
		for _, imp := range improvements {
			if imp.Status == improve.StatusDiscovered || imp.Status == improve.StatusResearching {
				discovered = append(discovered, fmt.Sprintf("%s — %s", imp.ID, imp.Title))
			}
		}
		if len(discovered) > 0 {
			b.WriteString("\nRecorded research items:\n")
			for _, d := range discovered {
				fmt.Fprintf(&b, "- %s\n", d)
			}
		}
		return b.String(), nil, true

	case wantsLearning:
		feedback, _ := s.improve.RecentFeedback(ctx, 200)
		if len(feedback) == 0 {
			b.WriteString("No analyst reviews have been recorded yet, so nothing has been learned from them.\n")
			b.WriteString("Mark a finding as a false positive with a reason to start the loop.")
			return b.String(), nil, true
		}
		var supported, contradicted, inconclusive int
		for _, fb := range feedback {
			if fb.Verification == nil {
				continue
			}
			switch {
			case fb.Verification.Supported:
				supported++
			case fb.Verification.Confidence == "high":
				contradicted++
			default:
				inconclusive++
			}
		}
		fmt.Fprintf(&b, "From %d review(s): %d were supported by advisory evidence, %d were contradicted by it, and %d could not be verified with cached data.\n",
			len(feedback), supported, contradicted, inconclusive)
		if contradicted > 0 {
			b.WriteString("\nContradicted reviews did not change any classification: analyst feedback alone is never treated as proof.\n")
		}
		if len(improvements) > 0 {
			b.WriteString("\nProposals derived from those reviews:\n")
			for _, imp := range improvements {
				fmt.Fprintf(&b, "- %s [%s] %s (%d affected finding(s))\n",
					imp.ID, imp.Status, imp.Title, len(imp.AffectedFindings))
			}
		} else {
			b.WriteString("\nNo improvement proposal has been generated yet.")
		}
		return b.String(), improvementCitations(improvements, ds), true

	default: // improvements overview
		if len(improvements) == 0 {
			b.WriteString("There are no improvement proposals yet. Verified reviews generate them automatically.")
			return b.String(), nil, true
		}
		fmt.Fprintf(&b, "%d proposal(s): awaiting review %d, deployed %d, rejected %d.\n\n",
			len(improvements), counts[improve.StatusAwaitingApproval]+counts[improve.StatusProposed]+counts[improve.StatusTesting],
			counts[improve.StatusDeployed]+counts[improve.StatusMonitoring], counts[improve.StatusRejected])
		for _, imp := range improvements {
			line := fmt.Sprintf("- %s [%s] %s", imp.ID, imp.Status, imp.Title)
			if imp.Evaluation != nil {
				line += fmt.Sprintf(" — tests %s", map[bool]string{true: "passed", false: "failed"}[imp.Evaluation.Passed])
			}
			b.WriteString(line + "\n")
		}
		return b.String(), improvementCitations(improvements, ds), true
	}
}

// improvementCitations points at the findings behind the proposals.
func improvementCitations(improvements []improve.Improvement, ds *dataset) []map[string]any {
	if ds == nil {
		return nil
	}
	var out []map[string]any
	seen := map[string]bool{}
	for _, imp := range improvements {
		for _, fid := range imp.AffectedFindings {
			row, ok := ds.ByID[fid]
			if !ok || seen[fid] {
				continue
			}
			seen[fid] = true
			out = append(out, map[string]any{
				"id": row.ID, "cve": row.CVE, "product": row.Product,
				"severity": row.Severity, "affected": row.effective(),
				"advisory_url": firstRefURL(*row),
			})
			if len(out) >= 10 {
				return out
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]["cve"]) < fmt.Sprint(out[j]["cve"]) })
	return out
}

func firstRefURL(v vulnRow) string {
	if len(v.References) > 0 {
		return v.References[0].URL
	}
	return ""
}

// sanitizeText keeps free-text notes bounded and strips control characters: the
// UI text is data, never interpreted.
func sanitizeText(s string) string {
	if len(s) > 2000 {
		s = s[:2000]
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 32 {
			return r
		}
		return -1
	}, s)
}
