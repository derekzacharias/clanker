package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/remediate"
)

// Remediation orchestration (Milestone 1): ownership → routing → work items.
//
// Findings remain immutable evidence. Everything an operator changes about "who
// fixes this and by when" lives in remediation items, so a closed item never rewrites
// what a scan reported.

// currentPolicy reads the configurable SLA/routing policy from settings.
func (s *Server) currentPolicy(r *http.Request) remediate.Policy {
	vals, err := s.store.Settings(r.Context())
	if err != nil {
		s.log.Warn("read remediation policy", "err", err)
		return remediate.DefaultPolicy()
	}
	return remediate.PolicyFromSettings(vals)
}

// reconcileReport folds a finished assessment into remediation work. Called from the
// report-ingest path and from local scan completion, so every route into the store is
// covered exactly once.
func (s *Server) reconcileReport(rep model.Report) {
	policy := remediate.PolicyFromSettings(s.mustSettings())
	created, updated, reopened, err := s.remediate.Reconcile(rep, policy)
	if err != nil {
		s.log.Warn("reconcile remediation work", "report", rep.ReportID, "err", err)
		return
	}
	if created+updated+reopened > 0 {
		s.log.Info("remediation reconciled", "report", rep.ReportID, "created", created,
			"updated", updated, "reopened", reopened)
	}
}

// backfillRemediation reconciles the newest stored report per host once at startup.
//
// Without it a dashboard upgraded to this build shows an empty remediation queue
// until the next scan, which reads as "nothing to do" rather than "not yet derived".
func (s *Server) backfillRemediation() {
	ctx := context.Background()
	runs, err := s.store.ListRuns(ctx, 200)
	if err != nil {
		s.log.Warn("backfill remediation", "err", err)
		return
	}
	policy := remediate.PolicyFromSettings(s.mustSettings())
	seen := map[string]bool{}
	hosts, created, updated := 0, 0, 0
	for _, run := range runs {
		if seen[run.Host] {
			continue
		}
		seen[run.Host] = true
		hosts++
		payload, err := s.store.ReportByID(ctx, run.ID)
		if err != nil {
			continue
		}
		var rep model.Report
		if err := json.Unmarshal(payload, &rep); err != nil {
			continue
		}
		c, u, _, err := s.remediate.Reconcile(rep, policy)
		if err != nil {
			s.log.Warn("backfill remediation", "host", run.Host, "err", err)
			continue
		}
		created += c
		updated += u
	}
	if hosts > 0 {
		s.log.Info("remediation backfilled from stored assessments", "hosts", hosts, "created", created, "updated", updated)
	}
}

// mustSettings returns the settings map, or an empty one when the store cannot be
// read: a remediation reconcile must never fail an assessment that already succeeded.
func (s *Server) mustSettings() map[string]string {
	vals, err := s.store.Settings(context.Background())
	if err != nil {
		s.log.Warn("read settings", "err", err)
		return map[string]string{}
	}
	return vals
}

// handleOwnershipList returns the ownership inventory: each asset with its record (if
// any) and how much work is waiting on it. ?triage=true keeps only assets that still
// have unowned work, which is the queue that needs a human decision.
func (s *Server) handleOwnershipList(w http.ResponseWriter, r *http.Request) {
	triage := strings.EqualFold(r.URL.Query().Get("triage"), "true")
	rows, err := s.remediate.AssetOverview(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ownership_error", err.Error())
		return
	}
	if triage {
		kept := rows[:0]
		for _, row := range rows {
			if row.Triaged {
				kept = append(kept, row)
			}
		}
		rows = kept
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rows, "total": len(rows)})
}

// handleOwnershipBulk records responsibility for many assets in one action.
//
// Assigning assets one at a time is what makes triage queues stay unowned, so this
// exists to make the right action the easy one. It is deliberately bounded and
// all-or-nothing per asset: a bad name is reported, never silently dropped.
func (s *Server) handleOwnershipBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Assets      []string `json:"assets"`
		Team        string   `json:"team"`
		Owner       string   `json:"owner"`
		Exposure    string   `json:"exposure"`
		Environment string   `json:"environment"`
		Criticality string   `json:"criticality"`
		Contact     string   `json:"contact"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	team := strings.TrimSpace(body.Team)
	if team == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "a team is required: unowned work belongs in triage, not in a bulk assignment")
		return
	}
	assets := make([]string, 0, len(body.Assets))
	seen := map[string]bool{}
	for _, raw := range body.Assets {
		a := strings.TrimSpace(raw)
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		assets = append(assets, a)
	}
	if len(assets) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "no assets were given")
		return
	}
	if len(assets) > 200 {
		writeError(w, http.StatusBadRequest, "invalid_request", "at most 200 assets can be assigned at once")
		return
	}

	updated := make([]string, 0, len(assets))
	failed := map[string]string{}
	for _, asset := range assets {
		_, err := s.remediate.SetOwnership(r.Context(), remediate.Ownership{
			Asset:       asset,
			Team:        team,
			Owner:       strings.TrimSpace(body.Owner),
			Exposure:    strings.TrimSpace(body.Exposure),
			Environment: strings.TrimSpace(body.Environment),
			Criticality: strings.TrimSpace(body.Criticality),
			Contact:     strings.TrimSpace(body.Contact),
			Source:      "manual",
		})
		if err != nil {
			failed[asset] = err.Error()
			continue
		}
		updated = append(updated, asset)
	}
	s.audit(r, "ownership.bulk", team, fmt.Sprintf("assets=%s", strings.Join(updated, ",")))
	s.log.Info("asset ownership assigned in bulk", "team", team, "assets", len(updated),
		"failed", len(failed), "remote", s.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"updated": updated,
		"failed":  failed,
		"total":   len(updated),
	})
}

// handleOwnershipGet returns one asset's ownership (or the triage placeholder).
func (s *Server) handleOwnershipGet(w http.ResponseWriter, r *http.Request) {
	own, err := s.remediate.Ownership(r.PathValue("host"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ownership_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, own)
}

// handleOwnershipPut records responsibility for an asset.
func (s *Server) handleOwnershipPut(w http.ResponseWriter, r *http.Request) {
	var body remediate.Ownership
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	body.Asset = r.PathValue("host")
	own, err := s.remediate.SetOwnership(r.Context(), body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ownership_error", err.Error())
		return
	}
	s.audit(r, "ownership.set", own.Asset,
		fmt.Sprintf("team=%q owner=%q exposure=%q status=%s", own.Team, own.Owner, own.Exposure, own.Status))
	s.log.Info("asset ownership recorded", "asset", own.Asset, "team", own.Team, "status", own.Status, "remote", s.clientIP(r))
	writeJSON(w, http.StatusOK, own)
}

// remediationView is a work item plus the one derived fact a client cannot compute
// without a clock: whether it is past its deadline.
type remediationView struct {
	remediate.Item
	Overdue bool `json:"overdue"`
}

// handleRemediationList lists work items with the dashboard's filters.
func (s *Server) handleRemediationList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := remediate.Filter{
		Team:        strings.TrimSpace(q.Get("team")),
		Owner:       strings.TrimSpace(q.Get("owner")),
		Asset:       strings.TrimSpace(q.Get("asset")),
		Severity:    strings.TrimSpace(q.Get("severity")),
		State:       strings.TrimSpace(q.Get("state")),
		Environment: strings.TrimSpace(q.Get("environment")),
		Overdue:     strings.EqualFold(q.Get("overdue"), "true"),
	}
	if raw := q.Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 1000 {
			f.Limit = n
		}
	}
	items, err := s.remediate.List(r.Context(), f, s.currentPolicy(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "remediation_error", err.Error())
		return
	}
	now := s.opts.Now()
	type row struct {
		remediate.Item
		Overdue bool `json:"overdue"`
	}
	out := make([]row, 0, len(items))
	for _, item := range items {
		out = append(out, row{Item: item, Overdue: item.Overdue(now)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "total": len(out)})
}

// handleRemediationGroups folds findings into remediation units.
func (s *Server) handleRemediationGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.remediate.Groups(r.Context(), s.currentPolicy(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "remediation_error", err.Error())
		return
	}
	items := 0
	for _, g := range groups {
		items += g.Items
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": groups, "total": len(groups), "findings": items})
}

// handleRemediationSummary serves the dashboard counts, computed in SQL.
func (s *Server) handleRemediationSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := s.remediate.Summary(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "remediation_error", err.Error())
		return
	}
	teams, _ := s.remediate.TeamsInUse(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"summary":   sum,
		"teams":     teams,
		"generated": s.opts.Now().Format(time.RFC3339),
		"policy":    s.currentPolicy(r),
		// Nothing can be executed yet: the agent has no remediation action, and the
		// dashboard says so rather than offering a button that cannot work.
		"automation": map[string]any{"enabled": false, "reason": "automated remediation is not implemented in this build"},
	})
}

// handleRemediationGet returns one work item.
func (s *Server) handleRemediationGet(w http.ResponseWriter, r *http.Request) {
	item, err := s.remediate.Get(r.PathValue("id"))
	if err != nil {
		if errors.Is(err, remediate.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "no such remediation item")
			return
		}
		writeError(w, http.StatusInternalServerError, "remediation_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"item": item, "overdue": item.Overdue(s.opts.Now())})
}

// handleRemediationPatch assigns ownership or moves the workflow state.
func (s *Server) handleRemediationPatch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Team  *string `json:"team"`
		Owner *string `json:"owner"`
		State *string `json:"state"`
		Notes *string `json:"notes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	patch := remediate.Patch{Team: body.Team, Owner: body.Owner, Notes: body.Notes}
	if body.State != nil {
		state, err := remediate.ValidateState(*body.State)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_state", err.Error())
			return
		}
		patch.State = &state
	}
	item, err := s.remediate.Update(r.Context(), r.PathValue("id"), patch)
	if err != nil {
		if errors.Is(err, remediate.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "no such remediation item")
			return
		}
		// A refused transition is a client error, not a server fault.
		writeError(w, http.StatusConflict, "invalid_transition", err.Error())
		return
	}
	var changes []string
	if body.Team != nil {
		changes = append(changes, fmt.Sprintf("team=%q", item.Team))
	}
	if body.Owner != nil {
		changes = append(changes, fmt.Sprintf("owner=%q", item.Owner))
	}
	if body.State != nil {
		changes = append(changes, fmt.Sprintf("state=%s", item.State))
	}
	s.audit(r, "remediation.update", item.ID, strings.Join(changes, " "))
	s.log.Info("remediation item updated", "id", item.ID, "state", item.State, "team", item.Team, "remote", s.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"item": item})
}

// handleRemediationVerify marks an item resolved from a later assessment.
//
// The assessment is the evidence, so it is checked rather than taken on trust: the report
// must exist, cover this asset, be newer than the last time the finding was seen, and no
// longer contain it. Without those checks "resolved" is a string the caller made up, and
// the whole point of the workflow — that closure means something — evaporates.
func (s *Server) handleRemediationVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ReportID string `json:"report_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	item, err := s.remediate.Get(r.PathValue("id"))
	if err != nil {
		if errors.Is(err, remediate.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "no such remediation item")
			return
		}
		writeError(w, http.StatusInternalServerError, "remediation_error", err.Error())
		return
	}
	reportID := strings.TrimSpace(body.ReportID)
	if reportID == "" {
		// Convenience without slack: "the latest assessment for this asset" still has to
		// satisfy every check below.
		rec, _, err := s.store.LatestReportFor(r.Context(), item.Asset)
		if err != nil {
			writeError(w, http.StatusConflict, "verification_report_missing",
				"name an assessment that no longer reports this finding; none is stored for "+item.Asset)
			return
		}
		reportID = rec.ID
	}
	rec, rep, err := s.store.AssessmentByID(r.Context(), reportID)
	if err != nil {
		writeError(w, http.StatusConflict, "verification_report_missing",
			fmt.Sprintf("no stored assessment with id %q: verification needs a report that exists", reportID))
		return
	}
	if !strings.EqualFold(strings.TrimSpace(rep.Metadata.Host), strings.TrimSpace(item.Asset)) {
		writeError(w, http.StatusConflict, "verification_wrong_asset",
			fmt.Sprintf("assessment %s covers %s, not %s", rec.ID, rep.Metadata.Host, item.Asset))
		return
	}
	for _, f := range rep.Findings {
		if remediate.FindingKey(item.Asset, f) == item.FindingKey {
			writeError(w, http.StatusConflict, "verification_still_present",
				fmt.Sprintf("assessment %s still reports this finding, so it is not resolved", rec.ID))
			return
		}
	}
	// "Newer" is measured report-to-report, not against the server clock: the agent stamps
	// its own finished_at, and comparing that to server time would fail every scan from a
	// host whose clock runs slightly behind — a false accusation of stale evidence.
	finished := rec.FinishedAt
	if finished.IsZero() {
		finished = rep.Metadata.StartedAt
	}
	switch prevRec, _, prevErr := s.store.AssessmentByID(r.Context(), item.ReportID); {
	case prevErr == nil:
		prevFinished := prevRec.FinishedAt
		if prevFinished.IsZero() {
			prevFinished = finished.Add(-time.Second)
		}
		if !finished.After(prevFinished) {
			writeError(w, http.StatusConflict, "verification_report_older",
				fmt.Sprintf("assessment %s finished %s, not after the assessment that reported this finding (%s, %s); run a new scan",
					rec.ID, finished.UTC().Format(time.RFC3339), prevRec.ID, prevFinished.UTC().Format(time.RFC3339)))
			return
		}
	default:
		// The reporting assessment is no longer stored (pruned or imported): the only
		// defensible check left is that this is the newest assessment we hold for the asset.
		latest, _, err := s.store.LatestReportFor(r.Context(), item.Asset)
		if err != nil || latest.ID != rec.ID {
			writeError(w, http.StatusConflict, "verification_report_older",
				fmt.Sprintf("assessment %s is not the newest stored assessment for %s; run a new scan",
					rec.ID, item.Asset))
			return
		}
	}
	updated, err := s.remediate.MarkVerified(r.Context(), item.ID, rec.ID)
	if err != nil {
		if errors.Is(err, remediate.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "no such remediation item")
			return
		}
		writeError(w, http.StatusConflict, "not_verifiable", err.Error())
		return
	}
	s.audit(r, "remediation.verify", updated.ID,
		fmt.Sprintf("resolved by assessment %s (asset %s, %s)", rec.ID, updated.Asset, updated.VulnerabilityID))
	s.log.Info("remediation verified", "id", updated.ID, "report", rec.ID,
		"run_finished", finished.UTC().Format(time.RFC3339), "remote", s.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"item": updated})
}

// handleRemediationAccept records a time-boxed risk acceptance.
//
// Accepting risk is a decision with an owner and a review date, not a state you can drop an
// item into. The finding stays visible (the summary counts accepted risk separately) and
// comes back when the date passes.
func (s *Server) handleRemediationAccept(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
		Days   int    `json:"days"`
		Until  string `json:"until"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	until := s.opts.Now().UTC().Truncate(24 * time.Hour)
	switch {
	case strings.TrimSpace(body.Until) != "":
		parsed, err := time.Parse("2006-01-02", strings.TrimSpace(body.Until))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "until must be a date (YYYY-MM-DD)")
			return
		}
		until = parsed
	case body.Days > 0:
		if body.Days > 365 {
			writeError(w, http.StatusBadRequest, "invalid_request", "an acceptance cannot run longer than 365 days")
			return
		}
		until = until.AddDate(0, 0, body.Days)
	default:
		writeError(w, http.StatusBadRequest, "invalid_request",
			"choose a review date: an accepted risk without an expiry is a forgotten finding")
		return
	}
	item, err := s.remediate.AcceptRisk(r.Context(), r.PathValue("id"), body.Reason, s.actorName(r), until)
	if err != nil {
		if errors.Is(err, remediate.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "no such remediation item")
			return
		}
		writeError(w, http.StatusConflict, "invalid_acceptance", err.Error())
		return
	}
	s.audit(r, "remediation.accept", item.ID,
		fmt.Sprintf("reason=%q until=%s vuln=%s asset=%s", item.AcceptReason,
			until.UTC().Format("2006-01-02"), item.VulnerabilityID, item.Asset))
	s.log.Info("risk accepted", "id", item.ID, "until", until.Format("2006-01-02"),
		"by", item.AcceptedBy, "remote", s.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"item": item})
}

// handleRemediationPolicy reads or writes the SLA and routing policy.
func (s *Server) handleRemediationPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.currentPolicy(r))
		return
	}
	var policy remediate.Policy
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&policy); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	encoded, err := remediate.EncodePolicy(policy)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}
	if err := s.store.SetSetting(r.Context(), "remediation.policy", encoded); err != nil {
		writeError(w, http.StatusInternalServerError, "settings_error", err.Error())
		return
	}
	s.log.Info("remediation policy updated", "remote", s.clientIP(r))
	writeJSON(w, http.StatusOK, policy)
}
