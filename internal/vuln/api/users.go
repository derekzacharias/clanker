package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/auth"
)

// Account management. Admin-only, enforced centrally by requiredPermission.

// handleUsersList returns the accounts, without password hashes.
func (s *Server) handleUsersList(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []auth.PublicUser{}, "total": 0,
			"note": "password sign-in is not configured; add an account to enable it"})
		return
	}
	users := s.auth.Users()
	writeJSON(w, http.StatusOK, map[string]any{"items": users, "total": len(users)})
}

// handleUserCreate adds an account.
func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeError(w, http.StatusConflict, "password_auth_disabled",
			"no credential file exists yet; run `clanker vuln auth set-password` once to create the first administrator")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	role, err := auth.ParseRole(body.Role)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_role", err.Error())
		return
	}
	user, err := s.auth.AddUser(body.Username, body.Password, role)
	if err != nil {
		writeError(w, userErrorStatus(err), "user_error", err.Error())
		return
	}
	s.audit(r, "user.create", user.Username, "role="+string(user.Role))
	s.log.Info("account created", "user", user.Username, "role", user.Role, "by", s.actorName(r))
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

// handleUserUpdate changes a role, disables an account, or sets a password.
func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeError(w, http.StatusConflict, "password_auth_disabled", "password sign-in is not configured")
		return
	}
	var body struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
		Password *string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	name := r.PathValue("username")
	// A viewer cannot be the one to change roles at all; that is already enforced by the
	// route permission. This is the second lock: you cannot promote yourself.
	if me := s.actorName(r); strings.EqualFold(me, name) && body.Role != nil {
		if role, err := auth.ParseRole(*body.Role); err == nil && role != s.auth.Role(me) {
			writeError(w, http.StatusForbidden, "self_promotion",
				"an administrator cannot change their own role; ask another administrator")
			return
		}
	}
	var (
		user auth.PublicUser
		err  error
	)
	switch {
	case body.Password != nil:
		user, err = s.auth.SetPassword(name, *body.Password)
		if err == nil {
			s.audit(r, "user.password_reset", name, "sessions invalidated")
		}
	case body.Role != nil:
		role, perr := auth.ParseRole(*body.Role)
		if perr != nil {
			writeError(w, http.StatusBadRequest, "invalid_role", perr.Error())
			return
		}
		user, err = s.auth.SetRole(name, role)
		if err == nil {
			s.audit(r, "user.role", name, "role="+string(role))
		}
	case body.Disabled != nil:
		user, err = s.auth.SetDisabled(name, *body.Disabled)
		if err == nil {
			s.audit(r, "user.disabled", name, "disabled="+boolStr(*body.Disabled))
		}
	default:
		writeError(w, http.StatusBadRequest, "invalid_request", "nothing to change: send role, disabled or password")
		return
	}
	if err != nil {
		writeError(w, userErrorStatus(err), "user_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

// handleUserDelete removes an account.
func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeError(w, http.StatusConflict, "password_auth_disabled", "password sign-in is not configured")
		return
	}
	name := r.PathValue("username")
	if strings.EqualFold(s.actorName(r), name) {
		writeError(w, http.StatusForbidden, "self_delete",
			"you cannot delete the account you are signed in with")
		return
	}
	if err := s.auth.DeleteUser(name); err != nil {
		writeError(w, userErrorStatus(err), "user_error", err.Error())
		return
	}
	s.audit(r, "user.delete", name, "")
	s.log.Info("account deleted", "user", name, "by", s.actorName(r))
	writeJSON(w, http.StatusOK, map[string]any{"deleted": name})
}

// handleAccessMe tells the UI who it is and what it may do.
func (s *Server) handleAccessMe(w http.ResponseWriter, r *http.Request) {
	method, sess := s.authenticate(r)
	resp := map[string]any{
		"authenticated": method != authNone,
		"username":      "",
		"role":          "",
		"permissions":   map[string]bool{"read": false, "write": false, "admin": false},
		"accounts":      0,
	}
	if method == authViaCookie {
		role := s.auth.Role(sess.Username)
		resp["username"] = sess.Username
		resp["role"] = string(role)
		resp["permissions"] = map[string]bool{
			"read": role.Allows(auth.PermRead), "write": role.Allows(auth.PermWrite),
			"admin": role.Allows(auth.PermAdmin),
		}
	}
	if method == authViaToken {
		resp["username"] = "api-token"
		resp["role"] = string(auth.RoleAdmin)
		resp["permissions"] = map[string]bool{"read": true, "write": true, "admin": true}
	}
	if s.auth != nil {
		resp["accounts"] = len(s.auth.Users())
	}
	writeJSON(w, http.StatusOK, resp)
}

// userErrorStatus maps account errors to the status the UI explains.
func userErrorStatus(err error) int {
	switch {
	case errors.Is(err, auth.ErrUserExists), errors.Is(err, auth.ErrLastAdmin):
		return http.StatusConflict
	case errors.Is(err, auth.ErrUserMissing):
		return http.StatusNotFound
	case errors.Is(err, auth.ErrNotConfigured):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}
