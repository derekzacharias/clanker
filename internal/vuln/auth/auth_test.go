package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPassword = "correct-horse-battery"

func newStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "clanker-guard", "auth.json")
	st, err := Write(path, "admin", testPassword)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	return st
}

func TestWriteThenLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clanker-guard", "auth.json")
	if _, err := Load(path); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Load(missing) = %v, want ErrNotConfigured", err)
	}

	if _, err := Write(path, "admin", testPassword); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("credential file mode = %o, want 600", got)
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := dir.Mode().Perm(); got != 0o700 {
		t.Fatalf("credential dir mode = %o, want 700", got)
	}

	st, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st.Username() != "admin" {
		t.Fatalf("Username = %q, want admin", st.Username())
	}
	if _, ok := st.Verify("admin", testPassword); !ok {
		t.Fatal("Verify rejected the password that was just written")
	}
	if _, insecure := st.InsecurePerms(); insecure {
		t.Fatal("freshly written file must not be reported as insecure")
	}
}

func TestLoadReportsWorldReadableFile(t *testing.T) {
	st := newStore(t)
	if err := os.Chmod(st.Path(), 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	loaded, err := Load(st.Path())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	mode, insecure := loaded.InsecurePerms()
	if !insecure || mode != 0o644 {
		t.Fatalf("InsecurePerms = (%o, %v), want (644, true)", mode, insecure)
	}
}

func TestLoadRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"not json":    "{",
		"no username": `{"password_hash":"$2a$10$x","session_key":"` + randomKey() + `"}`,
		"bad hash":    `{"username":"admin","password_hash":"nope","session_key":"` + randomKey() + `"}`,
		"short key":   `{"username":"admin","password_hash":"` + validHash(t) + `","session_key":"c2hvcnQ"}`,
		"missing key": `{"username":"admin","password_hash":"` + validHash(t) + `"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load accepted a corrupt credential file")
			}
		})
	}
}

func TestValidateCredentials(t *testing.T) {
	cases := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{"ok", "admin", testPassword, false},
		{"ok long", "security@example.com", strings.Repeat("a", MaxPasswordBytes), false},
		{"empty username", "  ", testPassword, true},
		{"control char", "ad\nmin", testPassword, true},
		{"long username", strings.Repeat("u", MaxUsernameLength+1), testPassword, true},
		{"short password", "admin", strings.Repeat("a", MinPasswordLength-1), true},
		{"bcrypt limit", "admin", strings.Repeat("a", MaxPasswordBytes+1), true},
		{"whitespace password", "admin", strings.Repeat(" ", MinPasswordLength+2), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCredentials(tc.username, tc.password)
			if tc.wantErr && err == nil {
				t.Fatal("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	st := newStore(t)
	if _, ok := st.Verify("admin", testPassword); !ok {
		t.Fatal("correct credentials rejected")
	}
	if _, ok := st.Verify("admin", "wrong-password-here"); ok {
		t.Fatal("wrong password accepted")
	}
	// Usernames are case-insensitive on purpose: "Admin" and "admin" are the same person,
	// and caps lock should not look like a wrong password. The stored name keeps its case.
	if u, ok := st.Verify("Admin", testPassword); !ok || u.Username != "admin" {
		t.Fatal("case-insensitive sign-in should succeed and return the stored name")
	}
	if _, err := st.AddUser("ADMIN", "another-long-password", RoleViewer); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate differing only by case = %v, want ErrUserExists", err)
	}
	if _, ok := st.Verify("admin", strings.Repeat("a", MaxPasswordBytes+10)); ok {
		t.Fatal("over-long password accepted")
	}
}

func TestSessionRoundTrip(t *testing.T) {
	st := newStore(t)
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	value, expires, err := st.SignSession(now, 2*time.Hour)
	if err != nil {
		t.Fatalf("SignSession: %v", err)
	}
	if !expires.Equal(now.Add(2 * time.Hour)) {
		t.Fatalf("expiry = %s, want %s", expires, now.Add(2*time.Hour))
	}
	sess, err := st.Session(value, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if sess.Username != "admin" {
		t.Fatalf("username = %q", sess.Username)
	}
	if sess.SessionID == "" {
		t.Fatal("session id is empty")
	}
	if !sess.ExpiresAt.Equal(expires) {
		t.Fatalf("payload expiry = %s, want %s", sess.ExpiresAt, expires)
	}

	// A cookie signed at 05:06 is dead two hours later, to the second.
	if _, err := st.Session(value, now.Add(2*time.Hour)); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expired session error = %v, want ErrInvalidSession", err)
	}
	// Two logins must not produce the same cookie.
	other, _, err := st.SignSession(now, time.Hour)
	if err != nil {
		t.Fatalf("SignSession: %v", err)
	}
	if other == value {
		t.Fatal("two sessions share a cookie value")
	}
}

func TestSessionRejectsTampering(t *testing.T) {
	st := newStore(t)
	now := time.Now().UTC()
	value, _, err := st.SignSession(now, time.Hour)
	if err != nil {
		t.Fatalf("SignSession: %v", err)
	}
	parts := strings.Split(value, ".")

	// Re-sign nothing: extend the payload expiry and keep the old MAC.
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var p sessionPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	p.Exp = now.Add(100 * time.Hour).Unix()
	forged, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	forgedValue := parts[0] + "." + base64.RawURLEncoding.EncodeToString(forged) + "." + parts[2]

	cases := map[string]string{
		"extended expiry": forgedValue,
		"flipped mac":     parts[0] + "." + parts[1] + "." + flip(parts[2]),
		"wrong version":   "v2." + parts[1] + "." + parts[2],
		"missing parts":   parts[0] + "." + parts[1],
		"empty":           "",
		"random":          "v1.not-base64.at-all",
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := st.Session(bad, now); !errors.Is(err, ErrInvalidSession) {
				t.Fatalf("Session(%q) error = %v, want ErrInvalidSession", bad, err)
			}
		})
	}
}

func TestSessionKeyRotationInvalidatesSessions(t *testing.T) {
	st := newStore(t)
	now := time.Now().UTC()
	value, _, err := st.SignSession(now, time.Hour)
	if err != nil {
		t.Fatalf("SignSession: %v", err)
	}
	if _, err := st.Session(value, now); err != nil {
		t.Fatalf("Session before rotation: %v", err)
	}

	rotated, err := Write(st.Path(), st.Username(), "another-long-password")
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := rotated.Session(value, now); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("session survived a password change: %v", err)
	}
	// The file on disk carries the rotated key too.
	reloaded, err := Load(st.Path())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := reloaded.Session(value, now); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("reloaded store accepted a pre-rotation session: %v", err)
	}
	if _, ok := reloaded.Verify("admin", "another-long-password"); !ok {
		t.Fatal("reloaded store rejected the new password")
	}
}

func TestRemove(t *testing.T) {
	st := newStore(t)
	if err := Remove(st.Path()); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := Load(st.Path()); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Load after Remove = %v, want ErrNotConfigured", err)
	}
	// Removing something absent is not an error; the CLI can be idempotent.
	if err := Remove(st.Path()); err != nil {
		t.Fatalf("Remove(absent): %v", err)
	}
}

func TestDefaultPath(t *testing.T) {
	t.Setenv("CLANKER_GUARD_AUTH_FILE", "/tmp/custom-auth.json")
	if got := DefaultPath(); got != "/tmp/custom-auth.json" {
		t.Fatalf("DefaultPath = %q, want the env override", got)
	}
	t.Setenv("CLANKER_GUARD_AUTH_FILE", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	want := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "clanker-guard", "auth.json")
	if got := DefaultPath(); got != want {
		t.Fatalf("DefaultPath = %q, want %q", got, want)
	}
}

// --- helpers ---

func flip(s string) string {
	if s == "" {
		return "x"
	}
	b := []byte(s)
	if b[0] == 'a' {
		b[0] = 'b'
	} else {
		b[0] = 'a'
	}
	return string(b)
}

func randomKey() string {
	return base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
}

func validHash(t *testing.T) string {
	t.Helper()
	st := newStore(t)
	u, ok := st.users["admin"]
	if !ok {
		t.Fatal("admin account missing")
	}
	return u.PasswordHash
}

// A deployment that upgrades must not lose its login: the old single-credential file becomes
// one administrator, the file is rewritten in the new shape, and the same password works.
func TestLegacyCredentialFileMigratesToAnAdministrator(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	legacy := map[string]any{
		"username":      "admin",
		"password_hash": string(hash),
		"session_key":   randomKey(),
		"updated_at":    time.Now().UTC().Format(time.RFC3339),
	}
	raw, _ := json.MarshalIndent(legacy, "", "  ")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := Load(path)
	if err != nil {
		t.Fatalf("Load legacy: %v", err)
	}
	if _, ok := st.Verify("admin", testPassword); !ok {
		t.Fatal("the migrated account cannot sign in")
	}
	if st.Role("admin") != RoleAdmin {
		t.Fatalf("migrated role = %q, want admin", st.Role("admin"))
	}
	// The file is now version 2: a subsequent load must not need the old fields at all.
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc Credentials
	if err := json.Unmarshal(written, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != 2 || len(doc.Users) != 1 || doc.Username != "" {
		t.Fatalf("migrated document = %+v", doc)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("reload migrated file: %v", err)
	}
}

// The whole point of roles is that the middle one cannot do everything.
func TestRoleLadder(t *testing.T) {
	cases := []struct {
		role Role
		want map[Permission]bool
	}{
		{RoleViewer, map[Permission]bool{PermRead: true, PermWrite: false, PermAdmin: false}},
		{RoleOperator, map[Permission]bool{PermRead: true, PermWrite: true, PermAdmin: false}},
		{RoleAdmin, map[Permission]bool{PermRead: true, PermWrite: true, PermAdmin: true}},
	}
	for _, tc := range cases {
		for perm, want := range tc.want {
			if got := tc.role.Allows(perm); got != want {
				t.Fatalf("%s.Allows(%v) = %v, want %v", tc.role, perm, got, want)
			}
		}
	}
	if _, err := ParseRole("superuser"); err == nil {
		t.Fatal("an unknown role was accepted")
	}
}

// Locking every administrator out of their own tool is the failure mode this guards.
func TestTheLastAdministratorCannotBeRemoved(t *testing.T) {
	st := newStore(t) // one admin
	if _, err := st.SetRole("admin", RoleOperator); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin = %v, want ErrLastAdmin", err)
	}
	if _, err := st.SetDisabled("admin", true); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable last admin = %v, want ErrLastAdmin", err)
	}
	if err := st.DeleteUser("admin"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin = %v, want ErrLastAdmin", err)
	}

	// With a second administrator, the first can be demoted.
	if _, err := st.AddUser("ops-admin", "another-long-password", RoleAdmin); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if _, err := st.SetRole("admin", RoleOperator); err != nil {
		t.Fatalf("demote with a second admin = %v", err)
	}
	// ...but now the second one is the last, so it is protected.
	if _, err := st.SetRole("ops-admin", RoleViewer); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote the remaining admin = %v, want ErrLastAdmin", err)
	}
}

// Changing a password must end that account's sessions and nobody else's.
func TestPasswordChangeInvalidatesOnlyThatAccountsSessions(t *testing.T) {
	st := newStore(t)
	if _, err := st.AddUser("dana", "another-long-password", RoleOperator); err != nil {
		t.Fatal(err)
	}
	adminCookie, _, err := st.SignSessionFor("admin", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	danaCookie, _, err := st.SignSessionFor("dana", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetPassword("dana", "changed-long-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Session(danaCookie, time.Now()); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("dana's old session = %v, want ErrInvalidSession", err)
	}
	if _, err := st.Session(adminCookie, time.Now()); err != nil {
		t.Fatalf("admin's session was invalidated by someone else's password change: %v", err)
	}
}

// Disabling an account ends its sessions immediately, and a disabled account cannot sign in.
func TestDisabledAccountLosesAccessAtOnce(t *testing.T) {
	st := newStore(t)
	if _, err := st.AddUser("dana", "another-long-password", RoleOperator); err != nil {
		t.Fatal(err)
	}
	cookie, _, err := st.SignSessionFor("dana", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetDisabled("dana", true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Session(cookie, time.Now()); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("disabled account's session = %v, want ErrInvalidSession", err)
	}
	if _, ok := st.Verify("dana", "another-long-password"); ok {
		t.Fatal("a disabled account could sign in")
	}
	if st.Role("dana") != "" {
		t.Fatalf("disabled account still has role %q", st.Role("dana"))
	}
}

// A role change applies to the running session, because the role is read from the store.
func TestRoleChangeIsImmediate(t *testing.T) {
	st := newStore(t)
	if _, err := st.AddUser("dana", "another-long-password", RoleViewer); err != nil {
		t.Fatal(err)
	}
	cookie, _, err := st.SignSessionFor("dana", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := st.Session(cookie, time.Now())
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if sess.Role.Allows(PermWrite) {
		t.Fatal("a viewer was granted write")
	}
	if _, err := st.SetRole("dana", RoleOperator); err != nil {
		t.Fatal(err)
	}
	sess, err = st.Session(cookie, time.Now())
	if err != nil {
		t.Fatalf("Session after promotion: %v", err)
	}
	if !sess.Role.Allows(PermWrite) {
		t.Fatal("promotion did not take effect on the existing session")
	}
}
