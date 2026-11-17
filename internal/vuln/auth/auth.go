// Package auth stores Clanker Guard's local accounts and signs browser session cookies.
//
// It started as a single username/password pair and has grown into a small user table with
// three roles, because one shared login cannot answer "who accepted this risk". The on-disk
// format is versioned: a file written by an older build (one credential) is migrated on load
// and written back in the new shape, so upgrading does not lock anybody out.
//
// Roles are read from the store on every request rather than carried in the cookie. That
// costs one map lookup and means a demotion takes effect immediately instead of when the
// session expires.
//
// Sessions are stateless — an HMAC-SHA256 over a small JSON payload — so restarting the
// server does not sign anybody out. Each user carries a session epoch that is bumped when
// their password changes or the account is disabled: their existing cookies stop working
// without disturbing anyone else.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	// MinPasswordLength is the shortest accepted password. Length is the only
	// requirement enforced: composition rules produce predictable passwords
	// ("Password1!") without adding real strength.
	MinPasswordLength = 10
	// MaxPasswordBytes is bcrypt's hard input limit. Longer passwords are
	// rejected instead of silently truncated, because truncation would make two
	// different passwords interchangeable.
	MaxPasswordBytes = 72
	// MaxUsernameLength bounds the account name printed in the UI and logs.
	MaxUsernameLength = 64
	// MaxUsers bounds the account list; this is a dashboard, not a directory.
	MaxUsers = 100
	// DefaultSessionTTL is how long a browser stays signed in.
	DefaultSessionTTL = 30 * 24 * time.Hour

	sessionVersion = "v1"
	fileVersion    = 2
	bcryptCost     = bcrypt.DefaultCost
)

// dummyHash keeps a wrong username as expensive to test as a wrong password, so
// response timing cannot be used to discover which account names exist.
const dummyHash = "$2a$10$UU39lAXHnvWTFFNlTmlByeZkQgYmbUSF4KhCNcuEaxPOon7lex9MW"

var (
	// ErrNotConfigured means no credential file exists yet: password login is
	// switched off and the server falls back to loopback-only or token auth.
	ErrNotConfigured = errors.New("password authentication is not configured")
	// ErrInvalidSession covers every reason a cookie is not usable (bad
	// signature, malformed payload, expired). Callers must not distinguish them
	// in a response: the client's only correct reaction is to sign in again.
	ErrInvalidSession = errors.New("session is invalid or expired")
	// ErrUserExists, ErrUserMissing and ErrLastAdmin are the account-management
	// refusals an operator can act on.
	ErrUserExists  = errors.New("that username already exists")
	ErrUserMissing = errors.New("no such user")
	ErrLastAdmin   = errors.New("this is the last active administrator; add another admin first")
)

// Role is what an account may do.
type Role string

const (
	// RoleViewer can read everything and change nothing.
	RoleViewer Role = "viewer"
	// RoleOperator does the work: assign, accept risk, verify, ticket, scan.
	RoleOperator Role = "operator"
	// RoleAdmin also manages accounts and configuration.
	RoleAdmin Role = "admin"
)

// ParseRole validates a role name from a request or a CLI flag.
func ParseRole(raw string) (Role, error) {
	switch Role(strings.ToLower(strings.TrimSpace(raw))) {
	case RoleViewer:
		return RoleViewer, nil
	case RoleOperator:
		return RoleOperator, nil
	case RoleAdmin:
		return RoleAdmin, nil
	default:
		return "", fmt.Errorf("role must be viewer, operator or admin")
	}
}

// Permission is the level a request needs.
type Permission int

const (
	// PermRead is any authenticated read.
	PermRead Permission = iota
	// PermWrite changes security data: assignments, states, tickets, scans.
	PermWrite
	// PermAdmin changes accounts or the integration and policy configuration.
	PermAdmin
)

// Allows reports whether the role grants the permission. Admin implies everything;
// operator implies read and write; viewer only reads.
func (r Role) Allows(p Permission) bool {
	switch r {
	case RoleAdmin:
		return true
	case RoleOperator:
		return p == PermRead || p == PermWrite
	case RoleViewer:
		return p == PermRead
	default:
		return false
	}
}

// User is one account. The password hash never leaves this package except on disk.
type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Role         Role      `json:"role"`
	Disabled     bool      `json:"disabled,omitempty"`
	SessionEpoch int       `json:"session_epoch,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// PublicUser is what the API and the UI may see.
type PublicUser struct {
	Username  string    `json:"username"`
	Role      Role      `json:"role"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (u User) public() PublicUser {
	return PublicUser{Username: u.Username, Role: u.Role, Disabled: u.Disabled,
		CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt}
}

// Credentials is the on-disk document.
//
// Version 1 held a single Username/PasswordHash. Those fields are still read so an existing
// deployment migrates instead of losing its login; they are never written again.
type Credentials struct {
	Version      int       `json:"version,omitempty"`
	SessionKey   string    `json:"session_key"`
	Users        []User    `json:"users,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
	Username     string    `json:"username,omitempty"`      // v1 only
	PasswordHash string    `json:"password_hash,omitempty"` // v1 only
}

// Session is a verified cookie payload.
type Session struct {
	Username  string
	SessionID string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Role      Role
}

// Store holds the accounts plus the signing key.
type Store struct {
	path       string
	key        []byte
	users      map[string]User
	order      []string
	insecurePF os.FileMode
	legacy     bool
}

// DefaultPath returns the credential path: $CLANKER_GUARD_AUTH_FILE when set,
// otherwise <user config dir>/clanker-guard/auth.json.
func DefaultPath() string {
	if p := strings.TrimSpace(os.Getenv("CLANKER_GUARD_AUTH_FILE")); p != "" {
		return p
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "clanker-guard", "auth.json")
	}
	return filepath.Join(".", ".clanker-auth.json")
}

// Load reads the credential file, migrating a single-credential file to the user table.
func Load(path string) (*Store, error) {
	if path == "" {
		path = DefaultPath()
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotConfigured
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var doc Credentials
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	key, err := base64.RawURLEncoding.DecodeString(doc.SessionKey)
	if err != nil || len(key) < 32 {
		return nil, fmt.Errorf("%s has a missing or too-short session_key", path)
	}
	st := &Store{path: path, key: key, users: map[string]User{}}
	if len(doc.Users) > 0 {
		for _, u := range doc.Users {
			if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err != nil {
				return nil, fmt.Errorf("%s has an unusable password hash for %q", path, u.Username)
			}
			role, err := ParseRole(string(u.Role))
			if err != nil {
				// An unknown role in the file is a downgrade, not a lockout.
				role = RoleViewer
			}
			u.Role = role
			st.users[strings.ToLower(u.Username)] = u
			st.order = append(st.order, strings.ToLower(u.Username))
		}
	} else {
		// Version 1: one credential. Keep it working as the administrator.
		if strings.TrimSpace(doc.Username) == "" || doc.PasswordHash == "" {
			return nil, fmt.Errorf("%s is missing username or password_hash", path)
		}
		if _, err := bcrypt.Cost([]byte(doc.PasswordHash)); err != nil {
			return nil, fmt.Errorf("%s has an unusable password_hash: %w", path, err)
		}
		now := time.Now().UTC()
		u := User{Username: doc.Username, PasswordHash: doc.PasswordHash, Role: RoleAdmin,
			CreatedAt: now, UpdatedAt: now}
		st.users[strings.ToLower(u.Username)] = u
		st.order = []string{strings.ToLower(u.Username)}
		st.legacy = true
	}
	// A credential file readable by other accounts is a standing risk; the server keeps
	// working but says so loudly rather than failing at startup.
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		st.insecurePF = mode
	}
	if st.legacy {
		// Write the migrated shape immediately: leaving it in the old form keeps a second
		// code path alive for no reason, and the next role change would need it.
		if err := st.persist(); err != nil {
			return nil, fmt.Errorf("migrate %s to version %d: %w", path, fileVersion, err)
		}
	}
	return st, nil
}

// persist writes the current accounts, atomically and with 0600.
func (s *Store) persist() error {
	doc := Credentials{
		Version:    fileVersion,
		SessionKey: base64.RawURLEncoding.EncodeToString(s.key),
		UpdatedAt:  time.Now().UTC(),
		Users:      make([]User, 0, len(s.users)),
	}
	for _, key := range s.order {
		if u, ok := s.users[key]; ok {
			doc.Users = append(doc.Users, u)
		}
	}
	if len(doc.Users) == 0 {
		return errors.New("refusing to write a credential file with no users")
	}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return writeFile0600(s.path, encoded)
}

// Path is where the credential was loaded from.
func (s *Store) Path() string { return s.path }

// Username is the first account name, for callers that still assume one user.
func (s *Store) Username() string {
	for _, key := range s.order {
		if u, ok := s.users[key]; ok {
			return u.Username
		}
	}
	return ""
}

// UpdatedAt is when any account last changed.
func (s *Store) UpdatedAt() time.Time {
	var newest time.Time
	for _, u := range s.users {
		if u.UpdatedAt.After(newest) {
			newest = u.UpdatedAt
		}
	}
	return newest
}

// InsecurePerms reports the file mode when the credential file is readable by
// group or others, so the server and CLI can warn instead of staying silent.
func (s *Store) InsecurePerms() (os.FileMode, bool) { return s.insecurePF, s.insecurePF != 0 }

// Users lists accounts in creation order, without password hashes.
func (s *Store) Users() []PublicUser {
	out := make([]PublicUser, 0, len(s.users))
	for _, key := range s.order {
		if u, ok := s.users[key]; ok {
			out = append(out, u.public())
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Role != out[j].Role {
			return roleRank(out[i].Role) > roleRank(out[j].Role)
		}
		return out[i].Username < out[j].Username
	})
	return out
}

func roleRank(r Role) int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	default:
		return 1
	}
}

// Verify checks a username/password pair. It returns the account so the caller can use the
// role and the session epoch. A disabled account is refused, and a wrong username costs the
// same bcrypt work as a wrong password.
func (s *Store) Verify(username, password string) (User, bool) {
	u, ok := s.users[strings.ToLower(strings.TrimSpace(username))]
	if !ok {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
		return User{}, false
	}
	if len(password) > MaxPasswordBytes {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password[:MaxPasswordBytes]))
		return User{}, false
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return User{}, false
	}
	if u.Disabled {
		return User{}, false
	}
	return u, true
}

// Role returns the account's current role, or "" when the account is gone or disabled.
// Reading it per request is what makes a demotion immediate.
func (s *Store) Role(username string) Role {
	u, ok := s.users[strings.ToLower(strings.TrimSpace(username))]
	if !ok || u.Disabled {
		return ""
	}
	return u.Role
}

// Epoch returns the account's session epoch, which invalidates old cookies when it changes.
func (s *Store) Epoch(username string) int {
	u, ok := s.users[strings.ToLower(strings.TrimSpace(username))]
	if !ok {
		return -1
	}
	return u.SessionEpoch
}

// AddUser creates an account.
func (s *Store) AddUser(username, password string, role Role) (PublicUser, error) {
	username = strings.TrimSpace(username)
	if err := ValidateCredentials(username, password); err != nil {
		return PublicUser{}, err
	}
	if _, err := ParseRole(string(role)); err != nil {
		return PublicUser{}, err
	}
	if len(s.users) >= MaxUsers {
		return PublicUser{}, fmt.Errorf("at most %d accounts are supported", MaxUsers)
	}
	key := strings.ToLower(username)
	if _, exists := s.users[key]; exists {
		return PublicUser{}, ErrUserExists
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return PublicUser{}, fmt.Errorf("hash password: %w", err)
	}
	now := time.Now().UTC()
	u := User{Username: username, PasswordHash: string(hash), Role: role, CreatedAt: now, UpdatedAt: now}
	s.users[key] = u
	s.order = append(s.order, key)
	if err := s.persist(); err != nil {
		delete(s.users, key)
		s.order = s.order[:len(s.order)-1]
		return PublicUser{}, err
	}
	return u.public(), nil
}

// SetPassword changes one account's password and invalidates that account's sessions only.
func (s *Store) SetPassword(username, password string) (PublicUser, error) {
	key := strings.ToLower(strings.TrimSpace(username))
	u, ok := s.users[key]
	if !ok {
		return PublicUser{}, ErrUserMissing
	}
	if err := ValidateCredentials(u.Username, password); err != nil {
		return PublicUser{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return PublicUser{}, err
	}
	prev := u
	u.PasswordHash = string(hash)
	u.SessionEpoch++
	u.UpdatedAt = time.Now().UTC()
	s.users[key] = u
	if err := s.persist(); err != nil {
		s.users[key] = prev
		return PublicUser{}, err
	}
	return u.public(), nil
}

// SetRole changes an account's role. The last active admin cannot be demoted: that is the
// difference between a permission change and locking the organisation out of its own tool.
func (s *Store) SetRole(username string, role Role) (PublicUser, error) {
	key := strings.ToLower(strings.TrimSpace(username))
	u, ok := s.users[key]
	if !ok {
		return PublicUser{}, ErrUserMissing
	}
	if _, err := ParseRole(string(role)); err != nil {
		return PublicUser{}, err
	}
	if u.Role == RoleAdmin && role != RoleAdmin && s.activeAdmins() <= 1 {
		return PublicUser{}, ErrLastAdmin
	}
	u.Role = role
	u.UpdatedAt = time.Now().UTC()
	s.users[key] = u
	if err := s.persist(); err != nil {
		return PublicUser{}, err
	}
	return u.public(), nil
}

// SetDisabled disables or re-enables an account. Disabling bumps the session epoch, so the
// account's existing cookies stop working at once.
func (s *Store) SetDisabled(username string, disabled bool) (PublicUser, error) {
	key := strings.ToLower(strings.TrimSpace(username))
	u, ok := s.users[key]
	if !ok {
		return PublicUser{}, ErrUserMissing
	}
	if disabled && u.Role == RoleAdmin && s.activeAdmins() <= 1 {
		return PublicUser{}, ErrLastAdmin
	}
	u.Disabled = disabled
	if disabled {
		u.SessionEpoch++
	}
	u.UpdatedAt = time.Now().UTC()
	s.users[key] = u
	if err := s.persist(); err != nil {
		return PublicUser{}, err
	}
	return u.public(), nil
}

// DeleteUser removes an account, refusing when it would leave no administrator.
func (s *Store) DeleteUser(username string) error {
	key := strings.ToLower(strings.TrimSpace(username))
	u, ok := s.users[key]
	if !ok {
		return ErrUserMissing
	}
	if u.Role == RoleAdmin && s.activeAdmins() <= 1 {
		return ErrLastAdmin
	}
	delete(s.users, key)
	trimmed := s.order[:0]
	for _, k := range s.order {
		if k != key {
			trimmed = append(trimmed, k)
		}
	}
	s.order = trimmed
	if err := s.persist(); err != nil {
		s.users[key] = u
		s.order = append(s.order, key)
		return err
	}
	return nil
}

func (s *Store) activeAdmins() int {
	n := 0
	for _, u := range s.users {
		if u.Role == RoleAdmin && !u.Disabled {
			n++
		}
	}
	return n
}

// ValidateCredentials enforces the rules shared by the CLI, the store and the API.
func ValidateCredentials(username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username must not be empty")
	}
	if len(username) > MaxUsernameLength {
		return fmt.Errorf("username must be at most %d characters", MaxUsernameLength)
	}
	for _, r := range username {
		if r < 0x20 || r == 0x7f {
			return errors.New("username must not contain control characters")
		}
	}
	if len(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(password) > MaxPasswordBytes {
		return fmt.Errorf("password must be at most %d bytes", MaxPasswordBytes)
	}
	if strings.TrimSpace(password) == "" {
		return errors.New("password must not be only whitespace")
	}
	return nil
}

// Remove deletes the credential file. It is not an error when nothing exists.
func Remove(path string) error {
	if path == "" {
		path = DefaultPath()
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Write creates or updates the administrator account named username, creating the file if
// needed. This is the CLI path (`clanker vuln auth set-password`) and the bootstrap: a fresh
// file gets exactly one admin.
func Write(path, username, password string) (*Store, error) {
	if path == "" {
		path = DefaultPath()
	}
	username = strings.TrimSpace(username)
	if err := ValidateCredentials(username, password); err != nil {
		return nil, err
	}
	if st, err := Load(path); err == nil {
		if _, ok := st.users[strings.ToLower(username)]; ok {
			if _, err := st.SetPassword(username, password); err != nil {
				return nil, err
			}
			return st, nil
		}
		if _, err := st.AddUser(username, password, RoleAdmin); err != nil {
			return nil, err
		}
		return st, nil
	} else if !errors.Is(err, ErrNotConfigured) {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	now := time.Now().UTC()
	st := &Store{
		path: path, key: key,
		users: map[string]User{strings.ToLower(username): {
			Username: username, PasswordHash: string(hash), Role: RoleAdmin,
			CreatedAt: now, UpdatedAt: now,
		}},
		order: []string{strings.ToLower(username)},
	}
	if err := st.persist(); err != nil {
		return nil, err
	}
	return st, nil
}

type sessionPayload struct {
	Sub string `json:"sub"`
	SID string `json:"sid"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Epo int    `json:"epo,omitempty"`
}

// SignSessionFor returns a cookie value for one account and its expiry.
func (s *Store) SignSessionFor(username string, now time.Time, ttl time.Duration) (string, time.Time, error) {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	u, ok := s.users[strings.ToLower(strings.TrimSpace(username))]
	if !ok {
		return "", time.Time{}, ErrUserMissing
	}
	sid := make([]byte, 16)
	if _, err := rand.Read(sid); err != nil {
		return "", time.Time{}, fmt.Errorf("generate session id: %w", err)
	}
	expires := now.Add(ttl).UTC()
	payload, err := json.Marshal(sessionPayload{
		Sub: u.Username,
		SID: base64.RawURLEncoding.EncodeToString(sid),
		Iat: now.UTC().Unix(),
		Exp: expires.Unix(),
		Epo: u.SessionEpoch,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	mac := base64.RawURLEncoding.EncodeToString(s.mac(body))
	return sessionVersion + "." + body + "." + mac, expires, nil
}

// SignSession is SignSessionFor for the first account, kept for older callers.
func (s *Store) SignSession(now time.Time, ttl time.Duration) (string, time.Time, error) {
	return s.SignSessionFor(s.Username(), now, ttl)
}

// Session verifies a cookie value and returns its payload.
func (s *Store) Session(value string, now time.Time) (Session, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] != sessionVersion {
		return Session{}, ErrInvalidSession
	}
	body := parts[1]
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Session{}, ErrInvalidSession
	}
	// The signature is checked before the payload is parsed: unsigned input is
	// never deserialised.
	if !hmac.Equal(got, s.mac(body)) {
		return Session{}, ErrInvalidSession
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Session{}, ErrInvalidSession
	}
	var p sessionPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Session{}, ErrInvalidSession
	}
	if p.Sub == "" || p.Exp <= now.UTC().Unix() {
		return Session{}, ErrInvalidSession
	}
	// A disabled account, a deleted account or a changed password ends the session here:
	// the epoch is compared against the account's current value, not the one in the cookie.
	u, ok := s.users[strings.ToLower(p.Sub)]
	if !ok || u.Disabled || u.SessionEpoch != p.Epo {
		return Session{}, ErrInvalidSession
	}
	return Session{
		Username:  u.Username,
		SessionID: p.SID,
		IssuedAt:  time.Unix(p.Iat, 0).UTC(),
		ExpiresAt: time.Unix(p.Exp, 0).UTC(),
		Role:      u.Role,
	}, nil
}

func (s *Store) mac(body string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(sessionVersion + "." + body))
	return m.Sum(nil)
}

// writeFile0600 writes atomically: a partially written credential file would
// lock the operator out of their own dashboard.
func writeFile0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".auth-*.json")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("set permissions on %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// constantTimeEqual is used by tests and by callers comparing short identifiers.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

var _ = constantTimeEqual

// String names the permission for a log line.
func (p Permission) String() string {
	switch p {
	case PermRead:
		return "read"
	case PermWrite:
		return "write"
	case PermAdmin:
		return "administer"
	default:
		return "unknown"
	}
}

// Verb is the human half of the refusal message.
func (p Permission) Verb() string {
	switch p {
	case PermRead:
		return "read"
	case PermWrite:
		return "change"
	case PermAdmin:
		return "administer"
	default:
		return "use"
	}
}
