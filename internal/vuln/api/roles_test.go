package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// withCookie issues a request as a signed-in browser.
func withCookie(t *testing.T, h http.Handler, method, path, body string, cookie *http.Cookie) int {
	t.Helper()
	headers := map[string]string{
		"Origin": "http://example.com",
		"Cookie": cookie.Name + "=" + cookie.Value,
	}
	return request(t, h, method, path, body, headers).Code
}

// signIn returns the session cookie for an account.
func signIn(t *testing.T, h http.Handler, username, password string) *http.Cookie {
	t.Helper()
	rec := login(t, h, username, password)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %s = %d: %s", username, rec.Code, rec.Body.String())
	}
	return sessionCookie(t, rec)
}

// The middle role does the work; the read-only role does not change anything; only the
// administrator manages accounts and configuration.
func TestRolesGateTheApi(t *testing.T) {
	srv, _ := newAuthedServer(t, newClock())
	h := srv.Handler()
	if _, err := srv.auth.AddUser("dana", "another-long-password", "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.auth.AddUser("victor", "another-long-password", "viewer"); err != nil {
		t.Fatal(err)
	}
	admin := signIn(t, h, "admin", testPassword)
	operator := signIn(t, h, "dana", "another-long-password")
	viewer := signIn(t, h, "victor", "another-long-password")

	// Everyone can read.
	for name, c := range map[string]*http.Cookie{"admin": admin, "operator": operator, "viewer": viewer} {
		if code := withCookie(t, h, "GET", "/api/remediation", "", c); code != http.StatusOK {
			t.Fatalf("%s read = %d", name, code)
		}
	}

	// A viewer cannot change work.
	if code := withCookie(t, h, "PATCH", "/api/remediation/REM-x", `{"team":"X"}`, viewer); code != http.StatusForbidden {
		t.Fatalf("viewer mutation = %d, want 403", code)
	}

	// An operator can change work (the 404/409 is the item be ing absent, not a refusal).
	if code := withCookie(t, h, "PATCH", "/api/remediation/REM-x", `{"team":"X"}`, operator); code == http.StatusForbidden {
		t.Fatal("operator was refused a work-item change")
	}

	// An operator cannot manage accounts or configuration.
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/api/users", `{"username":"eve","password":"another-long-password","role":"admin"}`},
		{"PATCH", "/api/users/victor", `{"role":"admin"}`},
		{"PUT", "/api/settings", `{"policy":{"fail_on":"high"}}`},
		{"PUT", "/api/integrations/gitlab", `{"enabled":false}`},
		{"POST", "/api/maintenance/run", ``},
		{"POST", "/api/agents/enroll-token", ``},
	} {
		if code := withCookie(t, h, tc.method, tc.path, tc.body, operator); code != http.StatusForbidden {
			t.Fatalf("operator %s %s = %d, want 403", tc.method, tc.path, code)
		}
	}

	// An administrator can.
	if code := withCookie(t, h, "PUT", "/api/settings", `{"policy":{"fail_on":"high"}}`, admin); code != http.StatusOK {
		t.Fatalf("admin settings = %d", code)
	}
	if code := withCookie(t, h, "POST", "/api/users",
		`{"username":"eve","password":"another-long-password","role":"operator"}`, admin); code != http.StatusOK {
		t.Fatalf("admin create user = %d", code)
	}
}

// The role is read per request, so a demotion takes effect without waiting for the cookie
// to expire — and a promotion likewise.
func TestRoleChangeAppliesToAnExistingSession(t *testing.T) {
	srv, _ := newAuthedServer(t, newClock())
	h := srv.Handler()
	if _, err := srv.auth.AddUser("dana", "another-long-password", "operator"); err != nil {
		t.Fatal(err)
	}
	admin := signIn(t, h, "admin", testPassword)
	dana := signIn(t, h, "dana", "another-long-password")

	if code := withCookie(t, h, "PATCH", "/api/remediation/REM-x", `{"team":"X"}`, dana); code == http.StatusForbidden {
		t.Fatal("operator could not change work before the demotion")
	}
	if code := withCookie(t, h, "PATCH", "/api/users/dana", `{"role":"viewer"}`, admin); code != http.StatusOK {
		t.Fatalf("demote = %d", code)
	}
	if code := withCookie(t, h, "PATCH", "/api/remediation/REM-x", `{"team":"X"}`, dana); code != http.StatusForbidden {
		t.Fatalf("demoted operator kept write access: %d", code)
	}
	if code := withCookie(t, h, "GET", "/api/remediation", "", dana); code != http.StatusOK {
		t.Fatalf("demoted account lost read access: %d", code)
	}
}

// Locking the organisation out of its own dashboard is the failure this prevents.
func TestAdministratorCannotRemoveTheLastAdminOrThemselves(t *testing.T) {
	srv, _ := newAuthedServer(t, newClock())
	h := srv.Handler()
	admin := signIn(t, h, "admin", testPassword)

	if code := withCookie(t, h, "PATCH", "/api/users/admin", `{"role":"operator"}`, admin); code != http.StatusForbidden {
		t.Fatalf("self-demotion = %d, want 403", code)
	}
	if code := withCookie(t, h, "DELETE", "/api/users/admin", "", admin); code != http.StatusForbidden {
		t.Fatalf("self-delete = %d, want 403", code)
	}
	// Even with a second account present, the only admin cannot be demoted by itself.
	if code := withCookie(t, h, "PATCH", "/api/users/admin", `{"disabled":true}`, admin); code != http.StatusConflict {
		t.Fatalf("disabling the last admin = %d, want 409", code)
	}
}

// The shared deployment token keeps working as an administrator: scripts and the agent
// depend on it, and quietly reducing its power would break existing automation.
func TestDeploymentTokenStillActsAsAdmin(t *testing.T) {
	srv, _ := newAuthedServer(t, newClock(), func(o *Options) { o.Token = "deploy-token" })
	h := srv.Handler()
	token := map[string]string{"X-Guard-Token": "deploy-token", "Origin": "http://example.com"}
	if code := request(t, h, "PUT", "/api/settings", `{"policy":{"fail_on":"high"}}`, token).Code; code != http.StatusOK {
		t.Fatalf("token settings = %d", code)
	}
	var me struct {
		Role        string          `json:"role"`
		Permissions map[string]bool `json:"permissions"`
	}
	rec := request(t, h, "GET", "/api/access/me", "", token)
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.Role != "admin" || !me.Permissions["admin"] {
		t.Fatalf("access/me for the token = %+v", me)
	}
}

// Account changes are recorded, because "who created that admin" is a question.
func TestAccountChangesAreAudited(t *testing.T) {
	srv, _ := newAuthedServer(t, newClock())
	h := srv.Handler()
	admin := signIn(t, h, "admin", testPassword)
	withCookie(t, h, "POST", "/api/users", `{"username":"dana","password":"another-long-password","role":"operator"}`, admin)
	withCookie(t, h, "PATCH", "/api/users/dana", `{"role":"viewer"}`, admin)

	var audit struct {
		Items []struct {
			Action string `json:"action"`
			Target string `json:"target"`
		} `json:"items"`
	}
	rec := request(t, h, "GET", "/api/audit", "", map[string]string{
		"Cookie": admin.Name + "=" + admin.Value,
	})
	if err := json.Unmarshal(rec.Body.Bytes(), &audit); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, e := range audit.Items {
		seen[e.Action] = e.Target
	}
	for _, want := range []string{"user.create", "user.role", "auth.login"} {
		if _, ok := seen[want]; !ok {
			t.Fatalf("audit is missing %q: %v", want, seen)
		}
	}
	if strings.TrimSpace(seen["user.role"]) != "dana" {
		t.Fatalf("user.role target = %q", seen["user.role"])
	}
}

// A sign-in is recorded under the account that signed in, not under the transport that
// carried the request: otherwise the diary cannot answer "who logged in".
func TestLoginIsAttributedToTheAccount(t *testing.T) {
	srv, _ := newAuthedServer(t, newClock())
	h := srv.Handler()
	admin := signIn(t, h, "admin", testPassword)

	var audit struct {
		Items []struct {
			Action string `json:"action"`
			Actor  string `json:"actor"`
		} `json:"items"`
	}
	rec := request(t, h, "GET", "/api/audit?action=auth.login", "", map[string]string{
		"Cookie": admin.Name + "=" + admin.Value,
	})
	if err := json.Unmarshal(rec.Body.Bytes(), &audit); err != nil {
		t.Fatal(err)
	}
	if len(audit.Items) == 0 || audit.Items[0].Actor != "admin" {
		t.Fatalf("login audit = %+v, want actor admin", audit.Items)
	}
}
