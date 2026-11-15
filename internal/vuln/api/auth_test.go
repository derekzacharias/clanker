package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/auth"
)

const testPassword = "correct-horse-battery"

// clock is an injectable, movable "now" so expiry and rate-limit windows can be
// tested without sleeping.
type clock struct{ t time.Time }

func (c *clock) Now() time.Time          { return c.t }
func (c *clock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *clock {
	return &clock{t: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
}

// newAuthedServer starts a server that requires a password, using a throwaway
// cache so tests never touch the developer's real intelligence database.
func newAuthedServer(t *testing.T, clk *clock, mutate ...func(*Options)) (*Server, string) {
	t.Helper()
	authPath := filepath.Join(t.TempDir(), "clanker-guard", "auth.json")
	if _, err := auth.Write(authPath, "admin", testPassword); err != nil {
		t.Fatalf("write credentials: %v", err)
	}
	opts := Options{
		CachePath:   filepath.Join(t.TempDir(), "intel.db"),
		AuthPath:    authPath,
		ToolVersion: "test-1.0",
		SessionTTL:  2 * time.Hour,
		Now:         clk.Now,
	}
	for _, m := range mutate {
		m(&opts)
	}
	srv, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, authPath
}

func request(t *testing.T, h http.Handler, method, path string, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func login(t *testing.T, h http.Handler, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		t.Fatal(err)
	}
	return request(t, h, "POST", "/api/auth/login", string(body), map[string]string{
		// A real browser sends Origin on a same-origin POST.
		"Origin": "http://example.com",
	})
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	t.Fatalf("response set no %s cookie; headers: %v", sessionCookieName, rec.Header())
	return nil
}

func TestUnauthenticatedServerStaysOpen(t *testing.T) {
	// Loopback development with neither a password nor a token: unchanged
	// behaviour, every route reachable.
	srv, err := New(Options{CachePath: filepath.Join(t.TempDir(), "intel.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	if rec := request(t, srv.Handler(), "GET", "/api/overview", "", nil); rec.Code != 200 {
		t.Fatalf("GET /api/overview = %d, want 200", rec.Code)
	}
	var sess authSessionResponse
	request(t, srv.Handler(), "GET", "/api/auth/session", "", nil)
	if rec := request(t, srv.Handler(), "GET", "/api/auth/session", "", nil); rec.Code != 200 {
		t.Fatalf("session endpoint = %d", rec.Code)
	} else if err := json.Unmarshal(rec.Body.Bytes(), &sess); err != nil {
		t.Fatal(err)
	}
	if sess.Required || sess.Authenticated {
		t.Fatalf("unauthenticated server reported %+v", sess)
	}
}

func TestLoginGrantsAccessWithHardenedCookie(t *testing.T) {
	clk := newClock()
	srv, _ := newAuthedServer(t, clk)
	h := srv.Handler()

	if rec := request(t, h, "GET", "/api/overview", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous overview = %d, want 401", rec.Code)
	}

	rec := login(t, h, "admin", testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d: %s", rec.Code, rec.Body.String())
	}
	cookie := sessionCookie(t, rec)
	if !cookie.HttpOnly {
		t.Error("session cookie must be HttpOnly so JavaScript cannot read it")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("Path = %q, want /", cookie.Path)
	}
	if got := cookie.MaxAge; got < 7000 || got > 7300 {
		t.Errorf("MaxAge = %d, want about 2h", got)
	}

	rec = request(t, h, "GET", "/api/overview", "", map[string]string{"Cookie": cookie.String()})
	if rec.Code != http.StatusOK {
		t.Fatalf("overview with session = %d: %s", rec.Code, rec.Body.String())
	}

	var sess authSessionResponse
	rec = request(t, h, "GET", "/api/auth/session", "", map[string]string{"Cookie": cookie.String()})
	if err := json.Unmarshal(rec.Body.Bytes(), &sess); err != nil {
		t.Fatal(err)
	}
	if !sess.Authenticated || sess.Username != "admin" || !sess.Required {
		t.Fatalf("session = %+v, want authenticated admin", sess)
	}
	if !sess.Methods["password"] {
		t.Fatal("session response must advertise the password method")
	}
}

func TestSessionEndpointDoesNotLeakTheAccountName(t *testing.T) {
	clk := newClock()
	srv, _ := newAuthedServer(t, clk)
	rec := request(t, srv.Handler(), "GET", "/api/auth/session", "", nil)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if got, ok := raw["username"]; ok {
		t.Fatalf("anonymous session response leaked username %v", got)
	}
	if raw["required"] != true {
		t.Fatalf("required = %v, want true", raw["required"])
	}
}

func TestLoginRejectsBadCredentialsWithoutLeakingWhich(t *testing.T) {
	clk := newClock()
	srv, _ := newAuthedServer(t, clk)
	h := srv.Handler()

	wrongPassword := login(t, h, "admin", "not-the-password")
	wrongUser := login(t, h, "someone", testPassword)
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"wrong password": wrongPassword,
		"unknown user":   wrongUser,
	} {
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401", name, rec.Code)
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == sessionCookieName && c.Value != "" {
				t.Fatalf("%s: issued a session cookie", name)
			}
		}
		if !strings.Contains(rec.Body.String(), "invalid username or password") {
			t.Fatalf("%s: message should not distinguish user from password: %s", name, rec.Body.String())
		}
	}
	if wrongPassword.Body.String() != wrongUser.Body.String() {
		t.Fatal("the two failures must be byte-identical")
	}
}

func TestLoginIsRateLimited(t *testing.T) {
	clk := newClock()
	srv, _ := newAuthedServer(t, clk)
	h := srv.Handler()

	for i := 0; i < loginMaxFailures; i++ {
		if rec := login(t, h, "admin", "wrong-password"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, rec.Code)
		}
	}
	rec := login(t, h, "admin", testPassword)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt after the limit = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 must carry Retry-After")
	}
	// The limit is not a lockout: once the window passes, the right password
	// works again and the counter is cleared.
	clk.Advance(loginLimitWindow + time.Minute)
	if rec := login(t, h, "admin", testPassword); rec.Code != http.StatusOK {
		t.Fatalf("login after window = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestExpiredSessionIsRejected(t *testing.T) {
	clk := newClock()
	srv, _ := newAuthedServer(t, clk)
	h := srv.Handler()

	cookie := sessionCookie(t, login(t, h, "admin", testPassword))
	clk.Advance(3 * time.Hour) // SessionTTL is 2h
	if rec := request(t, h, "GET", "/api/overview", "", map[string]string{"Cookie": cookie.String()}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired session = %d, want 401", rec.Code)
	}
}

func TestSessionSurvivesServerRestart(t *testing.T) {
	clk := newClock()
	srv, authPath := newAuthedServer(t, clk)
	cookie := sessionCookie(t, login(t, srv.Handler(), "admin", testPassword))
	srv.Close()

	// A restart reads the same credential file: the signing key persisted, so the
	// browser is still signed in. This is the whole point of the login page.
	restarted, err := New(Options{
		CachePath:  filepath.Join(t.TempDir(), "intel.db"),
		AuthPath:   authPath,
		SessionTTL: 2 * time.Hour,
		Now:        clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if rec := request(t, restarted.Handler(), "GET", "/api/overview", "", map[string]string{"Cookie": cookie.String()}); rec.Code != 200 {
		t.Fatalf("session after restart = %d, want 200", rec.Code)
	}
}

func TestChangingPasswordSignsOutExistingSessions(t *testing.T) {
	clk := newClock()
	srv, authPath := newAuthedServer(t, clk)
	cookie := sessionCookie(t, login(t, srv.Handler(), "admin", testPassword))
	srv.Close()

	if _, err := auth.Write(authPath, "admin", "a-brand-new-password"); err != nil {
		t.Fatal(err)
	}
	rotated, err := New(Options{CachePath: filepath.Join(t.TempDir(), "intel.db"), AuthPath: authPath, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Close()
	if rec := request(t, rotated.Handler(), "GET", "/api/overview", "", map[string]string{"Cookie": cookie.String()}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale session after password change = %d, want 401", rec.Code)
	}
}

func TestLogoutClearsTheCookie(t *testing.T) {
	clk := newClock()
	srv, _ := newAuthedServer(t, clk)
	h := srv.Handler()
	cookie := sessionCookie(t, login(t, h, "admin", testPassword))

	rec := request(t, h, "POST", "/api/auth/logout", "", map[string]string{
		"Cookie": cookie.String(),
		"Origin": "http://example.com",
	})
	if rec.Code != 200 {
		t.Fatalf("logout = %d", rec.Code)
	}
	cleared := sessionCookie(t, rec)
	if cleared.Value != "" || cleared.MaxAge >= 0 {
		t.Fatalf("logout did not clear the cookie: %+v", cleared)
	}
	// Logout stays callable repeatedly (a stale tab, a double click).
	if rec := request(t, h, "POST", "/api/auth/logout", "", nil); rec.Code != 200 {
		t.Fatalf("second logout = %d, want 200", rec.Code)
	}
}

func TestCrossSiteLogoutIsRefused(t *testing.T) {
	clk := newClock()
	srv, _ := newAuthedServer(t, clk)
	h := srv.Handler()
	cookie := sessionCookie(t, login(t, h, "admin", testPassword))

	rec := request(t, h, "POST", "/api/auth/logout", "", map[string]string{
		"Cookie": cookie.String(),
		"Origin": "http://evil.example",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site logout = %d, want 403", rec.Code)
	}
	// The session is untouched, so the browser stays signed in.
	if rec := request(t, h, "GET", "/api/overview", "", map[string]string{"Cookie": cookie.String()}); rec.Code != 200 {
		t.Fatalf("session after refused logout = %d, want 200", rec.Code)
	}
}

func TestCrossSiteStateChangeIsRefused(t *testing.T) {
	clk := newClock()
	srv, _ := newAuthedServer(t, clk)
	h := srv.Handler()
	cookie := sessionCookie(t, login(t, h, "admin", testPassword))
	body := `{"policy":{"fail_on":"high","fail_on_kev":false},"offline_default":false,"release_base":""}`

	// Safe methods need no origin check: a navigation to a report must work.
	if rec := request(t, h, "GET", "/api/overview", "", map[string]string{"Cookie": cookie.String()}); rec.Code != 200 {
		t.Fatalf("GET with cookie = %d, want 200", rec.Code)
	}
	// A cookie-carrying PUT from another site is CSRF: refused before the handler.
	rec := request(t, h, "PUT", "/api/settings", body, map[string]string{
		"Cookie": cookie.String(),
		"Origin": "http://evil.example",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site PUT = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	// The same request from the dashboard itself is allowed.
	rec = request(t, h, "PUT", "/api/settings", body, map[string]string{
		"Cookie":         cookie.String(),
		"Origin":         "http://example.com",
		"Sec-Fetch-Site": "same-origin",
	})
	if rec.Code != 200 {
		t.Fatalf("same-origin PUT = %d: %s", rec.Code, rec.Body.String())
	}
	// Sec-Fetch-Site alone is enough when a client omits Origin.
	rec = request(t, h, "PUT", "/api/settings", body, map[string]string{
		"Cookie":         cookie.String(),
		"Sec-Fetch-Site": "same-origin",
	})
	if rec.Code != 200 {
		t.Fatalf("PUT with Sec-Fetch-Site = %d: %s", rec.Code, rec.Body.String())
	}
	// A cookie-authenticated mutation with no provenance headers at all is
	// refused rather than assumed to be local.
	rec = request(t, h, "PUT", "/api/settings", body, map[string]string{"Cookie": cookie.String()})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("PUT without provenance = %d, want 403", rec.Code)
	}
}

func TestAPITokenStillWorks(t *testing.T) {
	srv, err := New(Options{
		CachePath: filepath.Join(t.TempDir(), "intel.db"),
		Token:     "s3cret-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	h := srv.Handler()

	if rec := request(t, h, "GET", "/api/overview", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d, want 401", rec.Code)
	}
	if rec := request(t, h, "GET", "/api/overview", "", map[string]string{"X-Guard-Token": "wrong"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token = %d, want 401", rec.Code)
	}
	if rec := request(t, h, "GET", "/api/overview", "", map[string]string{"X-Guard-Token": "s3cret-token"}); rec.Code != 200 {
		t.Fatalf("valid token = %d, want 200", rec.Code)
	}
	// A token holder is authenticated for the UI's session probe too.
	var sess authSessionResponse
	rec := request(t, h, "GET", "/api/auth/session", "", map[string]string{"X-Guard-Token": "s3cret-token"})
	if err := json.Unmarshal(rec.Body.Bytes(), &sess); err != nil {
		t.Fatal(err)
	}
	if !sess.Authenticated || !sess.Methods["token"] || sess.Methods["password"] {
		t.Fatalf("session = %+v, want token-authenticated without a password", sess)
	}
}

func TestLoginIsRefusedWhenNoPasswordIsConfigured(t *testing.T) {
	srv, err := New(Options{CachePath: filepath.Join(t.TempDir(), "intel.db"), Token: "s3cret-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	rec := login(t, srv.Handler(), "admin", testPassword)
	if rec.Code != http.StatusConflict {
		t.Fatalf("login without a password = %d, want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "auth set-password") {
		t.Fatalf("the error should say how to enable passwords: %s", rec.Body.String())
	}
}

func TestNonLoopbackListenRequiresCredentials(t *testing.T) {
	srv, err := New(Options{CachePath: filepath.Join(t.TempDir(), "intel.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	// TEST-NET-1 address: the guard trips before any bind is attempted.
	err = srv.Listen("192.0.2.10:8787")
	if err == nil {
		t.Fatal("Listen accepted a non-loopback address without credentials")
	}
	if !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("unhelpful refusal: %v", err)
	}
}

func TestPasswordAuthenticationSatisfiesTheListenGuard(t *testing.T) {
	clk := newClock()
	srv, _ := newAuthedServer(t, clk)
	// Non-loopback is allowed once a password exists — the bind itself fails
	// because 192.0.2.10 is not a local address, which is a different error from
	// the "refusing to listen ... without authentication" guard.
	err := srv.Listen("192.0.2.10:8787")
	if err == nil {
		t.Fatal("expected a bind failure for a non-local address")
	}
	if strings.Contains(err.Error(), "refusing to listen") {
		t.Fatalf("password auth should satisfy the guard, got %v", err)
	}
}

// TestClientIPBehindATrustedProxy is what makes internet exposure safe: behind the
// TLS proxy every request arrives from one address, so rate limits and logs must see
// the real client — but only when the peer really is the proxy, or any client could
// forge X-Forwarded-For and escape the login limiter.
func TestClientIPBehindATrustedProxy(t *testing.T) {
	srv, err := New(Options{
		CachePath:      filepath.Join(t.TempDir(), "intel.db"),
		TrustedProxies: []string{"10.0.0.5", "172.16.0.0/12"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	mk := func(remote, xff string) *http.Request {
		r := httptest.NewRequest("GET", "/api/overview", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	cases := []struct{ name, remote, xff, want string }{
		{"untrusted peer ignores the header", "203.0.113.9:5555", "1.1.1.1", "203.0.113.9"},
		{"trusted peer uses the client", "10.0.0.5:443", "198.51.100.7", "198.51.100.7"},
		{"leftmost entries cannot be spoofed", "10.0.0.5:443", "1.2.3.4, 198.51.100.7", "198.51.100.7"},
		{"proxy chain skips trusted hops", "10.0.0.5:443", "198.51.100.7, 172.20.0.3", "198.51.100.7"},
		{"trusted peer without a header", "10.0.0.5:443", "", "10.0.0.5"},
		{"garbage header falls back to the peer", "10.0.0.5:443", "not-an-ip", "10.0.0.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := srv.clientIP(mk(tc.remote, tc.xff)); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestInvalidTrustedProxyIsRejected(t *testing.T) {
	if _, err := New(Options{CachePath: filepath.Join(t.TempDir(), "intel.db"), TrustedProxies: []string{"nonsense"}}); err == nil {
		t.Fatal("an invalid trusted-proxy entry must fail startup, not be ignored")
	}
}
