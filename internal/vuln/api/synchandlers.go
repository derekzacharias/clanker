package api

import (
	"net/http"
	"strings"
)

// handleIntelSyncStatus returns the unified per-source synchronization view.
func (s *Server) handleIntelSyncStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.buildIntelSyncView(r.Context()))
}

// handleIntelSyncHistory returns the consolidated synchronization history.
func (s *Server) handleIntelSyncHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 50
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		if n, ok := atoi(raw); ok && n > 0 && n <= 200 {
			limit = n
		}
	}
	rows, err := s.syncHistory(r.Context(), strings.TrimSpace(q.Get("source")), strings.TrimSpace(q.Get("outcome")), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sync_history_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rows, "total": len(rows)})
}

// handleIntelSyncStart queues a synchronization for one source. A source that
// is already running returns 409 so the dashboard can disable its button.
func (s *Server) handleIntelSyncStart(w http.ResponseWriter, r *http.Request) {
	source := strings.ToLower(strings.TrimSpace(r.PathValue("source")))
	if !isSyncSource(source) {
		writeError(w, http.StatusBadRequest, "unknown_source", "unknown intelligence source; choose kev, epss, nvd or msrc")
		return
	}
	actor := s.actorName(r)
	jobID, started, err := s.syncOneSource(r.Context(), source, "manual", actor)
	if err != nil {
		if strings.Contains(err.Error(), "already running") {
			writeError(w, http.StatusConflict, "already_running", err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "sync_error", err.Error())
		return
	}
	if !started {
		writeError(w, http.StatusConflict, "already_running", "a synchronization for this source is already running")
		return
	}
	s.audit(r, "intel_sync_started", source, "manual synchronization requested")
	// Accepted, not completed: the client must poll for the outcome.
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": jobID, "source": source, "accepted": true})
}

// handleIntelSyncCancel cancels a running synchronization.
func (s *Server) handleIntelSyncCancel(w http.ResponseWriter, r *http.Request) {
	source := strings.ToLower(strings.TrimSpace(r.PathValue("source")))
	if !isSyncSource(source) {
		writeError(w, http.StatusBadRequest, "unknown_source", "unknown intelligence source")
		return
	}
	s.registry.mu.Lock()
	job, ok := s.registry.running[source]
	s.registry.mu.Unlock()
	if !ok || job.Cancel == nil {
		writeError(w, http.StatusNotFound, "not_running", "no synchronization is running for this source")
		return
	}
	job.Cancel()
	s.audit(r, "intel_sync_cancelled", source, "synchronization cancelled by operator")
	writeJSON(w, http.StatusOK, map[string]any{"cancelled": true, "source": source})
}

func isSyncSource(source string) bool {
	for _, def := range syncSources {
		if def.ID == source {
			return true
		}
	}
	return false
}

func atoi(raw string) (int, bool) {
	n := 0
	if raw == "" {
		return 0, false
	}
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}
