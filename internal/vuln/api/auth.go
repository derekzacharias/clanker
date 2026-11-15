package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/auth"
)

// The dashboard supports two ways in, and they answer different needs:
//
//   - session cookie — the browser signs in once on /login with the password set
//     by `clanker vuln auth set-password`, and stays signed in until the cookie
//     expires. This is the path a human uses.
//   - X-Guard-Token — a shared secret for scripts, the endpoint agent and
//     pre-password deployments. It is unchanged so existing automation keeps
//     working.
//
// Nothing here weakens the old behaviour: a loopback server with neither
// configured still needs no credentials at all.
const sessionCookieName = "guard_session"

const (
	// loginMaxFailures is how many wrong passwords an address may try inside
	// loginLimitWindow before further attempts are refused outright.
	loginMaxFailures = 10
	loginLimitWindow = 15 * time.Minute
	// loginLimiterMaxIPs bounds memory if requests arrive from many addresses.
	loginLimiterMaxIPs = 1024
	// maxLoginBodyBytes is generous for a JSON credential pair and small enough
	// that a hostile client cannot make the server buffer much.
	maxLoginBodyBytes = 8 << 10
)

// publicAPIPaths stay reachable without a dashboard credential. They are
// deliberately the only ones: /api/health exposes liveness, the auth endpoints
// must work before a session exists, and the agent endpoints authenticate with an
// agent bearer token inside the handler (an endpoint has no browser session).
var publicAPIPaths = map[string]bool{
	"/api/health":         true,
	"/api/auth/session":   true,
	"/api/auth/login":     true,
	"/api/auth/logout":    true,
	"/api/agents/enroll":  true,
	"/api/agents/checkin": true,
	"/api/agents/report":  true,
	// Work is pulled by the agent, authenticated with its own token in the handler.
	"/api/agents/tasks/claim":    true,
	"/api/agents/tasks/complete": true,
}

type authMethod int

const (
	authNone authMethod = iota
	authViaCookie
	authViaToken
)

// authRequired reports whether any credential is configured. When it is false
// the deployment is unauthenticated (loopback development) and every route is
// open, exactly as before password support existed.
func (s *Server) authRequired() bool {
	return s.opts.Token != "" || s.auth != nil
}

// authenticate accepts either a valid session cookie or the API token. A
// cookie-authenticated request is additionally subject to
// cookieMutationAllowed: see the middleware.
func (s *Server) authenticate(r *http.Request) (authMethod, auth.Session) {
	if s.auth != nil {
		if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
			if sess, err := s.auth.Session(c.Value, s.opts.Now()); err == nil {
				return authViaCookie, sess
			}
		}
	}
	if s.opts.Token != "" {
		// Constant time so the token cannot be recovered byte-by-byte from
		// response latency across many requests.
		got := []byte(strings.TrimSpace(r.Header.Get("X-Guard-Token")))
		want := []byte(s.opts.Token)
		if len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1 {
			return authViaToken, auth.Session{}
		}
	}
	return authNone, auth.Session{}
}

func (s *Server) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	resp := authSessionResponse{
		Required:   s.authRequired(),
		Methods:    map[string]bool{"password": s.auth != nil, "token": s.opts.Token != ""},
		SessionTTL: s.opts.SessionTTL.String(),
	}
	method, sess := s.authenticate(r)
	switch method {
	case authViaCookie:
		resp.Authenticated = true
		resp.Username = sess.Username
		resp.ExpiresAt = sess.ExpiresAt.Format(time.RFC3339)
	case authViaToken:
		resp.Authenticated = true
	}
	// An anonymous caller learns whether a password exists (it has to: that is
	// how the login page knows what to render) but never the account name.
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeError(w, http.StatusConflict, "password_auth_disabled",
			"this server has no password configured; run `clanker vuln auth set-password` and restart it")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	now := s.opts.Now()
	ip := s.clientIP(r)
	if retryAfter, blocked := s.logins.blocked(ip, now); blocked {
		// Retry-After lets a well-behaved client back off instead of hammering.
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
		s.log.Warn("sign-in rate limited", "remote", ip, "retry_after", retryAfter.String())
		writeError(w, http.StatusTooManyRequests, "too_many_attempts",
			"too many failed sign-in attempts; wait a few minutes and try again")
		return
	}
	username := strings.TrimSpace(body.Username)
	if !s.auth.Verify(username, body.Password) {
		s.logins.fail(ip, now)
		// One message for both causes: distinguishing them would confirm which
		// usernames exist.
		s.log.Warn("sign-in rejected", "remote", ip, "user", username)
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid username or password")
		return
	}
	value, expires, err := s.auth.SignSession(now, s.opts.SessionTTL)
	if err != nil {
		s.log.Error("sign a session", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "could not create a session")
		return
	}
	s.logins.reset(ip)
	s.setSessionCookie(w, r, value, expires)
	s.log.Info("sign-in succeeded", "remote", ip, "user", username, "expires", expires.Format(time.RFC3339))
	writeJSON(w, http.StatusOK, authSessionResponse{
		Authenticated: true,
		Required:      true,
		Username:      username,
		ExpiresAt:     expires.Format(time.RFC3339),
		Methods:       map[string]bool{"password": true, "token": s.opts.Token != ""},
		SessionTTL:    s.opts.SessionTTL.String(),
	})
}

// authFilePath is the credential path, empty when password sign-in is off.
func (s *Server) authFilePath() string {
	if s.auth == nil {
		return ""
	}
	return s.auth.Path()
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	// A session cookie that arrived cross-site must not be destroyed by that site:
	// forced logout is not a breach, but it is still someone else acting on the
	// user's session. Requests without a cookie (a stale tab, a script) are fine.
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" && !cookieMutationAllowed(r) {
		s.log.Warn("cross-site logout refused", "origin", r.Header.Get("Origin"), "remote", s.clientIP(r))
		writeError(w, http.StatusForbidden, "cross_site_request", "sign out from the dashboard itself")
		return
	}
	// Deliberately unauthenticated and idempotent: signing out of an already
	// expired session must not fail, or the UI would trap the user.
	s.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(expires.Sub(s.opts.Now()).Seconds()),
		HttpOnly: true, // unreadable from JavaScript, so XSS cannot exfiltrate it
		SameSite: http.SameSiteStrictMode,
		Secure:   requestIsHTTPS(r),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   requestIsHTTPS(r),
	})
}

type authSessionResponse struct {
	Authenticated bool            `json:"authenticated"`
	Required      bool            `json:"required"`
	Username      string          `json:"username,omitempty"`
	ExpiresAt     string          `json:"expires_at,omitempty"`
	SessionTTL    string          `json:"session_ttl,omitempty"`
	Methods       map[string]bool `json:"methods"`
}

// cookieMutationAllowed blocks cross-site state changes that ride on a session
// cookie. SameSite=Strict already stops browsers sending the cookie
// cross-site; this is the second lock, and it also covers SameSite bypasses in
// older clients. Token-authenticated requests are exempt: a cross-origin page
// cannot set X-Guard-Token, so they are not CSRF-able.
func cookieMutationAllowed(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	}
	// Modern browsers always send Sec-Fetch-Site for fetch/form submissions. If
	// neither header is present the request did not come from a browser page
	// carrying a cookie, so a cookie-authenticated mutation is refused.
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	default:
		return false
	}
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	// Behind a TLS-terminating proxy the cookie still needs the Secure flag.
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

// clientIP resolves the address a request came from.
//
// X-Forwarded-For is honoured only when the immediate peer is a configured
// trusted proxy: otherwise any client could forge the header and escape the login
// rate limit. The list is walked right to left so the leftmost (client-supplied)
// entries cannot be used to impersonate someone else.
func (s *Server) clientIP(r *http.Request) string {
	peer := hostOnly(r.RemoteAddr)
	ip := net.ParseIP(peer)
	if ip == nil || !s.isTrustedProxy(ip) {
		return peer
	}
	xff := r.Header.Get("X-Forwarded-For")
	if strings.TrimSpace(xff) == "" {
		return peer
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := net.ParseIP(strings.TrimSpace(parts[i]))
		if candidate == nil {
			continue
		}
		if s.isTrustedProxy(candidate) {
			// Another proxy in the chain; keep looking left.
			continue
		}
		return candidate.String()
	}
	return peer
}

func (s *Server) isTrustedProxy(ip net.IP) bool {
	for _, network := range s.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// parseTrustedProxies turns the configured proxy list into networks.
func parseTrustedProxies(entries []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range entries {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if !strings.Contains(item, "/") {
				if ip := net.ParseIP(item); ip != nil {
					bits := 32
					if ip.To4() == nil {
						bits = 128
					}
					item = fmt.Sprintf("%s/%d", ip.String(), bits)
				}
			}
			_, network, err := net.ParseCIDR(item)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy %q: %w", item, err)
			}
			out = append(out, network)
		}
	}
	return out, nil
}

// loginLimiter throttles password guessing per source address.
type loginLimiter struct {
	mu     sync.Mutex
	byIP   map[string]*loginWindow
	max    int
	window time.Duration
}

type loginWindow struct {
	failures int
	reset    time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{byIP: map[string]*loginWindow{}, max: max, window: window}
}

// blocked reports whether ip has spent its attempts, and how long until it may
// try again.
func (l *loginLimiter) blocked(ip string, now time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.byIP[ip]
	if !ok || !now.Before(w.reset) || w.failures < l.max {
		return 0, false
	}
	return w.reset.Sub(now), true
}

func (l *loginLimiter) fail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.byIP[ip]
	if !ok || !now.Before(w.reset) {
		w = &loginWindow{reset: now.Add(l.window)}
		l.byIP[ip] = w
	}
	w.failures++
	if len(l.byIP) > loginLimiterMaxIPs {
		l.sweepLocked(now)
	}
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.byIP, ip)
}

func (l *loginLimiter) sweepLocked(now time.Time) {
	for ip, w := range l.byIP {
		if !now.Before(w.reset) {
			delete(l.byIP, ip)
		}
	}
}
