package api

import (
	"net/http"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"strconv"
	"strings"
	"time"
)

// audit records one durable action against the diary table.
//
// It deliberately cannot change the outcome of the request: the work already happened, so
// a failed audit write is a loud log line, not an error the operator sees. The alternative
// — refusing to assign work because the diary is unavailable — trades a missing record for
// a stuck queue.
func (s *Server) audit(r *http.Request, action, target, detail string) {
	if s.store == nil {
		return
	}
	err := s.store.AppendAudit(r.Context(), intel.AuditEntry{
		At:     time.Now().UTC().Format(time.RFC3339),
		Actor:  s.actorName(r),
		Action: action,
		Target: target,
		Detail: detail,
		Remote: s.clientIP(r),
	})
	if err != nil {
		s.log.Warn("audit write failed", "action", action, "target", target, "err", err)
	}
}

// handleAudit lists the diary, newest first.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 100
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	items, err := s.store.ListAudit(r.Context(), limit,
		strings.TrimSpace(q.Get("action")), strings.TrimSpace(q.Get("actor")))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit_error", err.Error())
		return
	}
	actions, err := s.store.AuditActions(r.Context())
	if err != nil {
		s.log.Warn("audit action list failed", "err", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items), "actions": actions})
}
