// Package auth stores Clanker Guard's single local login credential and signs
// browser session cookies.
//
// The dashboard is a single-operator tool, so there is no user database: one
// username/password pair in a 0600 JSON file. The file lives in the user config
// directory rather than beside the scan cache, because the cache is regenerable
// and deleting it must not destroy the login.
//
// Sessions are stateless — an HMAC-SHA256 over a small JSON payload, keyed by a
// random secret stored with the credential — so restarting the server does not
// sign anybody out. The key is rotated whenever the password is written, which
// invalidates every existing session at exactly the moment a credential change
// should invalidate them.
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
	// DefaultSessionTTL is how long a browser stays signed in.
	DefaultSessionTTL = 30 * 24 * time.Hour

	sessionVersion = "v1"
	bcryptCost     = bcrypt.DefaultCost
)

// dummyHash keeps a wrong username as expensive to test as a wrong password, so
// response timing cannot be used to discover the account name. It is a bcrypt
// hash of a throwaway string, not a credential for anything.
const dummyHash = "$2a$10$UU39lAXHnvWTFFNlTmlByeZkQgYmbUSF4KhCNcuEaxPOon7lex9MW"

var (
	// ErrNotConfigured means no credential file exists yet: password login is
	// switched off and the server falls back to loopback-only or token auth.
	ErrNotConfigured = errors.New("password authentication is not configured")
	// ErrInvalidSession covers every reason a cookie is not usable (bad
	// signature, malformed payload, expired). Callers must not distinguish them
	// in a response: the client's only correct reaction is to sign in again.
	ErrInvalidSession = errors.New("session is invalid or expired")
)

// Credentials is the on-disk credential document. SessionKey is base64url of 32
// random bytes; it is a signing key, not something a client ever sees.
type Credentials struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	SessionKey   string    `json:"session_key"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Session is a verified cookie payload.
type Session struct {
	Username  string
	SessionID string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Store is an in-memory credential plus the path it came from.
type Store struct {
	path       string
	cred       Credentials
	key        []byte
	insecurePF os.FileMode
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

// Load reads the credential file. A missing file is ErrNotConfigured, which is a
// normal state (token-only or loopback development), not a failure.
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
	var cred Credentials
	if err := json.Unmarshal(raw, &cred); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	if cred.Username == "" || cred.PasswordHash == "" {
		return nil, fmt.Errorf("%s is missing username or password_hash", path)
	}
	if _, err := bcrypt.Cost([]byte(cred.PasswordHash)); err != nil {
		return nil, fmt.Errorf("%s has an unusable password_hash: %w", path, err)
	}
	key, err := base64.RawURLEncoding.DecodeString(cred.SessionKey)
	if err != nil || len(key) < 32 {
		return nil, fmt.Errorf("%s has a missing or too-short session_key", path)
	}
	st := &Store{path: path, cred: cred, key: key}
	// A credential file readable by other accounts is a standing risk; the
	// server keeps working but says so loudly rather than failing at startup.
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		st.insecurePF = mode
	}
	return st, nil
}

// Write stores username/password, creating the file (and its directory) with
// 0600/0700 permissions. Any existing session is invalidated by rotating the
// signing key.
func Write(path, username, password string) (*Store, error) {
	if path == "" {
		path = DefaultPath()
	}
	username = strings.TrimSpace(username)
	if err := ValidateCredentials(username, password); err != nil {
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
	cred := Credentials{
		Username:     username,
		PasswordHash: string(hash),
		SessionKey:   base64.RawURLEncoding.EncodeToString(key),
		UpdatedAt:    time.Now().UTC(),
	}
	encoded, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if err := writeFile0600(path, encoded); err != nil {
		return nil, err
	}
	return &Store{path: path, cred: cred, key: key}, nil
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

// ValidateCredentials enforces the rules shared by the CLI and the store.
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

// Path is where the credential was loaded from.
func (s *Store) Path() string { return s.path }

// Username is the account name. It is safe to show to an authenticated client.
func (s *Store) Username() string { return s.cred.Username }

// UpdatedAt is when the password was last written.
func (s *Store) UpdatedAt() time.Time { return s.cred.UpdatedAt }

// InsecurePerms reports the file mode when the credential file is readable by
// group or others, so the server and CLI can warn instead of staying silent.
func (s *Store) InsecurePerms() (os.FileMode, bool) { return s.insecurePF, s.insecurePF != 0 }

// Verify reports whether the username/password pair matches. It always performs
// a bcrypt comparison so a wrong username costs the same as a wrong password.
func (s *Store) Verify(username, password string) bool {
	if subtle.ConstantTimeCompare([]byte(username), []byte(s.cred.Username)) != 1 {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
		return false
	}
	if len(password) > MaxPasswordBytes {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password[:MaxPasswordBytes]))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(s.cred.PasswordHash), []byte(password)) == nil
}

type sessionPayload struct {
	Sub string `json:"sub"`
	SID string `json:"sid"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// SignSession returns a cookie value and its expiry.
func (s *Store) SignSession(now time.Time, ttl time.Duration) (string, time.Time, error) {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	sid := make([]byte, 16)
	if _, err := rand.Read(sid); err != nil {
		return "", time.Time{}, fmt.Errorf("generate session id: %w", err)
	}
	expires := now.Add(ttl).UTC()
	payload, err := json.Marshal(sessionPayload{
		Sub: s.cred.Username,
		SID: base64.RawURLEncoding.EncodeToString(sid),
		Iat: now.UTC().Unix(),
		Exp: expires.Unix(),
	})
	if err != nil {
		return "", time.Time{}, err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	mac := base64.RawURLEncoding.EncodeToString(s.mac(body))
	return sessionVersion + "." + body + "." + mac, expires, nil
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
	return Session{
		Username:  p.Sub,
		SessionID: p.SID,
		IssuedAt:  time.Unix(p.Iat, 0).UTC(),
		ExpiresAt: time.Unix(p.Exp, 0).UTC(),
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
