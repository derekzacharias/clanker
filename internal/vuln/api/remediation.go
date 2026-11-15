package api

import (
	"context"
	"encoding/json"
	"errors"
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

// handleOwnershipList returns ownership records; ?triage=true is the unassigned queue.
func (s *Server) handleOwnershipList(w http.ResponseWriter, r *http.Request) {
	triage := strings.EqualFold(r.URL.Query().Get("triage"), "true")
	records, err := s.remediate.ListOwnership(r.Context(), triage)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ownership_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": records, "total": len(records)})
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
	s.log.Info("asset ownership recorded", "asset", own.Asset, "team", own.Team, "status", own.Status, "remote", s.clientIP(r))
	writeJSON(w, http.StatusOK, own)
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
	s.log.Info("remediation item updated", "id", item.ID, "state", item.State, "team", item.Team, "remote", s.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"item": item})
}

// handleRemediationVerify marks an item resolved from a later assessment. The
// verification itself is the evidence — never a manual "done".
func (s *Server) handleRemediationVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ReportID string `json:"report_id"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body)
	item, err := s.remediate.MarkVerified(r.Context(), r.PathValue("id"), body.ReportID)
	if err != nil {
		if errors.Is(err, remediate.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "no such remediation item")
			return
		}
		writeError(w, http.StatusConflict, "not_verifiable", err.Error())
		return
	}
	s.log.Info("remediation verified", "id", item.ID, "report", body.ReportID, "remote", s.clientIP(r))
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
