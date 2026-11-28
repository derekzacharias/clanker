package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

// The operator's own NVD API key.
//
// A key raises NVD's rate limit from 5 to 50 requests per 30 seconds, which
// turns the first full population from hours into minutes. The key is the
// operator's property: it is stored only in this server's settings table
// (the same 0600-protected SQLite cache everything else lives in), it is
// never included in any response after it is saved, and only the fact that a
// key is configured is ever shown.

const nvdKeySetting = "nvd_api_key"

// handleNVDKeyGet reports whether a key is configured — never the key itself.
func (s *Server) handleNVDKeyGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": s.nvdKeyConfigured(),
	})
}

// handleNVDKeyPut stores or clears the operator's NVD API key. The value is
// deliberately not echoed back, and the audit trail records only the fact of
// the change.
func (s *Server) handleNVDKeyPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	key := strings.TrimSpace(body.APIKey)
	if len(key) > 64 {
		writeError(w, http.StatusBadRequest, "invalid_key", "the NVD API key is at most 64 characters")
		return
	}
	wasConfigured := s.nvdKeyConfigured()
	if key == "" {
		if err := s.store.SetSetting(r.Context(), nvdKeySetting, ""); err != nil {
			writeError(w, http.StatusInternalServerError, "settings_error", err.Error())
			return
		}
		if wasConfigured {
			s.audit(r, "nvd_api_key_cleared", "settings", "the NVD API key was removed")
		}
		writeJSON(w, http.StatusOK, map[string]any{"configured": false})
		return
	}
	if err := s.store.SetSetting(r.Context(), nvdKeySetting, key); err != nil {
		writeError(w, http.StatusInternalServerError, "settings_error", err.Error())
		return
	}
	if !wasConfigured {
		s.audit(r, "nvd_api_key_set", "settings", "an NVD API key was saved (the value is never recorded)")
	}
	// The next scheduled or manual sync runs at the keyed rate limit; nothing
	// else needs to change.
	writeJSON(w, http.StatusOK, map[string]any{"configured": true})
}

// nvdKeyConfigured reports whether the settings table holds a key.
func (s *Server) nvdKeyConfigured() bool {
	return strings.TrimSpace(s.mustSettings()[nvdKeySetting]) != ""
}
