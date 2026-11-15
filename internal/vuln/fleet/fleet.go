// Package fleet stores enrolled Clanker Guard endpoint agents, their per-agent
// credentials, and the activity they report.
//
// Enrollment is the only trust bootstrap: the operator copies one shared
// enrollment token out of the dashboard, an agent exchanges it for a per-agent
// bearer token, and every later call is authenticated with that token. Tokens are
// stored as SHA-256 hashes, so a copy of the database authenticates nothing, and
// revoking one endpoint leaves the rest of the fleet working.
//
// Nothing here accepts a report on trust: the API layer validates the document
// and the store only records what it was given.
package fleet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// States an endpoint can report. Anything else is refused rather than stored, so
// the dashboard can never render an invented status.
const (
	StateEnrolled  = "enrolled"
	StateIdle      = "idle"
	StateScanning  = "scanning"
	StateReporting = "reporting"
	StateError     = "error"
)

// ValidStates is the closed set the API accepts in a check-in.
var ValidStates = map[string]bool{
	StateEnrolled:  true,
	StateIdle:      true,
	StateScanning:  true,
	StateReporting: true,
	StateError:     true,
}

// ReachableWindow is how long after its last check-in an endpoint is still
// treated as reachable when no claim request is held.
//
// "Offline" must mean unreachable. An agent that is watching re-opens its claim
// request within a second, so this window only covers the gap between finishing a
// report and reconnecting. An endpoint that finished an install-time scan and has
// no watcher running is genuinely unreachable, and after this window it is shown
// as offline instead of pretending otherwise.
const ReachableWindow = 60 * time.Second

var (
	// ErrNotFound means no such agent (or the token is for one that was revoked).
	ErrNotFound = errors.New("agent not found")
	// ErrRevoked distinguishes a deliberately revoked endpoint from an unknown one.
	ErrRevoked = errors.New("agent is revoked")
	// ErrIdentityConflict means a hostname is already enrolled and the caller did
	// not prove it holds that agent's credential.
	ErrIdentityConflict = errors.New("hostname is already enrolled by another agent")
)

// Agent is one enrolled endpoint.
type Agent struct {
	ID         string     `json:"id"`
	Host       string     `json:"host"`
	OS         string     `json:"os,omitempty"`
	Version    string     `json:"version,omitempty"`
	State      string     `json:"state"`
	Phase      string     `json:"phase,omitempty"`
	Percent    int        `json:"percent"`
	Message    string     `json:"message,omitempty"`
	Findings   int        `json:"findings"`
	LastReport string     `json:"last_report_id,omitempty"`
	EnrolledAt time.Time  `json:"enrolled_at"`
	LastSeen   *time.Time `json:"last_seen,omitempty"`
	Revoked    bool       `json:"revoked"`
	// LastSequence is the highest submission sequence accepted from this agent. It
	// makes replayed reports detectable without trusting a client-supplied id.
	LastSequence int64 `json:"last_sequence"`

	// hash is the stored credential hash, used only to verify proof of possession
	// during re-enrollment. It is never serialised.
	hash string
}

// Online reports whether the dashboard should treat the endpoint as reachable.
func (a Agent) Online(now time.Time) bool {
	if a.Revoked || a.LastSeen == nil {
		return false
	}
	return now.Sub(*a.LastSeen) < ReachableWindow
}

// Event is one recorded activity update, so "what is it doing" has a short
// history instead of a single mutable row.
type Event struct {
	At      time.Time `json:"at"`
	State   string    `json:"state"`
	Phase   string    `json:"phase,omitempty"`
	Percent int       `json:"percent"`
	Message string    `json:"message,omitempty"`
}

// Checkin is what an agent reports about itself.
type Checkin struct {
	State    string
	Phase    string
	Percent  int
	Message  string
	Findings int
	Version  string
	OS       string
}

const schema = `
CREATE TABLE IF NOT EXISTS agents (
  id             TEXT PRIMARY KEY,
  host           TEXT NOT NULL,
  os             TEXT NOT NULL DEFAULT '',
  version        TEXT NOT NULL DEFAULT '',
  token_hash     TEXT NOT NULL,
  state          TEXT NOT NULL DEFAULT 'enrolled',
  phase          TEXT NOT NULL DEFAULT '',
  percent        INTEGER NOT NULL DEFAULT 0,
  message        TEXT NOT NULL DEFAULT '',
  findings       INTEGER NOT NULL DEFAULT 0,
  last_report_id TEXT NOT NULL DEFAULT '',
  enrolled_at    TEXT NOT NULL,
  last_seen      TEXT,
  revoked        INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_token ON agents(token_hash);
CREATE TABLE IF NOT EXISTS agent_events (
  seq      INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT NOT NULL,
  at       TEXT NOT NULL,
  state    TEXT NOT NULL,
  phase    TEXT NOT NULL DEFAULT '',
  percent  INTEGER NOT NULL DEFAULT 0,
  message  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_agent_events_agent ON agent_events(agent_id, seq DESC);
CREATE TABLE IF NOT EXISTS agent_enroll_tokens (
  token_hash TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at    TEXT,
  used_by    TEXT NOT NULL DEFAULT '',
  label      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_agent_enroll_expiry ON agent_enroll_tokens(expires_at);
`

// enrollTokenKey is the settings row holding the shared bootstrap secret.
const enrollTokenKey = "agents.enroll_token"

// Store owns the fleet tables inside the shared cache database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// New prepares the fleet tables. db is the cache database the API already opened.
func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("fleet: nil database")
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("initialise fleet tables: %w", err)
	}
	if _, err := db.Exec(taskSchema); err != nil {
		return nil, fmt.Errorf("initialise agent task table: %w", err)
	}
	// Ensure columns added after the first release exist on older databases. This
	// must happen before any index references them.
	for _, stmt := range []string{
		`ALTER TABLE agents ADD COLUMN last_sequence INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE agent_tasks ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE agent_tasks ADD COLUMN lease_expires_at TEXT`,
	} {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return nil, fmt.Errorf("migrate fleet schema: %w", err)
		}
	}
	if _, err := db.Exec(taskIndexes); err != nil {
		return nil, fmt.Errorf("initialise agent task indexes: %w", err)
	}
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}, nil
}

// SetClock is for tests.
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// DefaultEnrollTokenTTL bounds how long a freshly minted enrollment token is
// usable. Short enough that a leaked token is not a standing invitation.
const DefaultEnrollTokenTTL = 24 * time.Hour

var (
	// ErrEnrollTokenInvalid means no such token (unknown, or already purged).
	ErrEnrollTokenInvalid = errors.New("enrollment token is not valid")
	// ErrEnrollTokenExpired means the token aged out before it was used.
	ErrEnrollTokenExpired = errors.New("enrollment token has expired")
	// ErrEnrollTokenUsed means the token was already exchanged. Tokens are
	// single-use so one leaked installer command cannot enroll a second endpoint.
	ErrEnrollTokenUsed = errors.New("enrollment token has already been used")
)

// MintEnrollToken creates a single-use enrollment token.
//
// The token is returned in plaintext exactly once; only its SHA-256 is stored, so
// a database copy does not yield usable tokens.
func (s *Store) MintEnrollToken(ctx context.Context, ttl time.Duration, label string) (string, time.Time, error) {
	if ttl <= 0 {
		ttl = DefaultEnrollTokenTTL
	}
	token, err := randomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.now()
	expires := now.Add(ttl)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO agent_enroll_tokens
		(token_hash, created_at, expires_at, label) VALUES (?,?,?,?)`,
		hashToken(token), now.Format(time.RFC3339), expires.Format(time.RFC3339), truncate(label, 100)); err != nil {
		return "", time.Time{}, err
	}
	// Opportunistic cleanup: expired and long-used tokens are useless.
	_, _ = s.db.ExecContext(ctx, `DELETE FROM agent_enroll_tokens
		WHERE expires_at < ? OR (used_at IS NOT NULL AND used_at < ?)`,
		now.Add(-time.Hour).Format(time.RFC3339), now.Add(-7*24*time.Hour).Format(time.RFC3339))
	return token, expires, nil
}

// ConsumeEnrollToken validates a token and burns it atomically. The UPDATE is
// conditional, so two simultaneous enrollments cannot both use one token.
func (s *Store) ConsumeEnrollToken(ctx context.Context, token, usedBy string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return ErrEnrollTokenInvalid
	}
	now := s.now()
	hash := hashToken(token)
	res, err := s.db.ExecContext(ctx, `UPDATE agent_enroll_tokens SET used_at = ?, used_by = ?
		WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`,
		now.Format(time.RFC3339), truncate(usedBy, 120), hash, now.Format(time.RFC3339))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	// Explain the failure precisely enough to act on, without disclosing whether
	// an unknown hash ever existed beyond "not valid".
	var usedAt, expiresAt sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT used_at, expires_at FROM agent_enroll_tokens WHERE token_hash = ?`, hash).
		Scan(&usedAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEnrollTokenInvalid
	}
	if err != nil {
		return err
	}
	if usedAt.Valid && usedAt.String != "" {
		return ErrEnrollTokenUsed
	}
	if expiresAt.Valid {
		if ts, perr := time.Parse(time.RFC3339, expiresAt.String); perr == nil && !now.Before(ts) {
			return ErrEnrollTokenExpired
		}
	}
	return ErrEnrollTokenInvalid
}

// Enroll registers a new endpoint, or re-attaches an existing one when the caller
// proves it already holds that agent's credential.
//
// A hostname is not an identity. Re-enrolling a hostname that is already active
// must NOT rotate the existing agent's credential: otherwise any machine that
// claims the name (DHCP reuse, a clone, an attacker on the segment) would take
// over the endpoint's identity and its findings history. Re-attaching therefore
// requires the current token; an operator who has lost it revokes the agent first
// (POST /api/agents/{id}/revoke), after which enrollment starts a fresh identity.
func (s *Store) Enroll(ctx context.Context, host, osName, version, proofOfPossession string) (Agent, string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return Agent{}, "", errors.New("host is required")
	}
	now := s.now()
	host = truncate(host, 255)
	osName = truncate(osName, 120)
	version = truncate(version, 64)

	existing, err := s.agentByHost(ctx, host)
	if err != nil {
		return Agent{}, "", err
	}
	if existing != nil {
		if strings.TrimSpace(proofOfPossession) == "" {
			return Agent{}, "", ErrIdentityConflict
		}
		// The proof is checked against the agent that owns this hostname, and only
		// that agent: a token for a different endpoint proves nothing here.
		if subtle.ConstantTimeCompare([]byte(hashToken(proofOfPossession)), []byte(existing.hash)) != 1 {
			return Agent{}, "", ErrIdentityConflict
		}
		token, err := randomToken()
		if err != nil {
			return Agent{}, "", err
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE agents SET
			token_hash = ?, os = CASE WHEN ? <> '' THEN ? ELSE os END,
			version = CASE WHEN ? <> '' THEN ? ELSE version END,
			state = ?, phase = '', percent = 0, message = ?, last_seen = ?
			WHERE id = ?`,
			hashToken(token), osName, osName, version, version, StateEnrolled,
			"re-enrolled with proof of possession; token rotated",
			now.Format(time.RFC3339), existing.ID); err != nil {
			return Agent{}, "", err
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO agent_events (agent_id, at, state, phase, percent, message)
			VALUES (?,?,?,?,?,?)`, existing.ID, now.Format(time.RFC3339), StateEnrolled, "", 0,
			"re-enrolled with proof of possession"); err != nil {
			return Agent{}, "", err
		}
		a, err := s.Get(ctx, existing.ID)
		if err != nil {
			return Agent{}, "", err
		}
		return a, token, nil
	}

	token, err := randomToken()
	if err != nil {
		return Agent{}, "", err
	}
	id, err := agentID()
	if err != nil {
		return Agent{}, "", err
	}
	a := Agent{
		ID:         id,
		Host:       host,
		OS:         osName,
		Version:    version,
		State:      StateEnrolled,
		EnrolledAt: now,
		Message:    "enrolled; no check-in yet",
	}
	lastSeen := now
	a.LastSeen = &lastSeen
	if _, err := s.db.ExecContext(ctx, `INSERT INTO agents
		(id, host, os, version, token_hash, state, phase, percent, message, findings, last_report_id, enrolled_at, last_seen, revoked)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0)`,
		a.ID, a.Host, a.OS, a.Version, hashToken(token), a.State, "", 0, a.Message, 0, "",
		now.Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		return Agent{}, "", err
	}
	return a, token, nil
}

// agentByHost returns the newest non-revoked record for a hostname, if any.
func (s *Store) agentByHost(ctx context.Context, host string) (*Agent, error) {
	var (
		a        Agent
		enrolled string
		lastSeen sql.NullString
		revoked  int
	)
	err := s.db.QueryRowContext(ctx, `SELECT id, host, os, version, state, phase, percent, message,
		findings, last_report_id, enrolled_at, last_seen, revoked, token_hash FROM agents
		WHERE host = ? AND revoked = 0 ORDER BY enrolled_at DESC LIMIT 1`, host).
		Scan(&a.ID, &a.Host, &a.OS, &a.Version, &a.State, &a.Phase, &a.Percent, &a.Message,
			&a.Findings, &a.LastReport, &enrolled, &lastSeen, &revoked, &a.hash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.EnrolledAt, _ = time.Parse(time.RFC3339, enrolled)
	if lastSeen.Valid && lastSeen.String != "" {
		if ts, perr := time.Parse(time.RFC3339, lastSeen.String); perr == nil {
			a.LastSeen = &ts
		}
	}
	a.Revoked = revoked != 0
	return &a, nil
}

// Authenticate resolves a bearer token to its agent.
func (s *Store) Authenticate(ctx context.Context, token string) (Agent, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Agent{}, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, `SELECT id, host, os, version, state, phase, percent, message,
		findings, last_report_id, enrolled_at, last_seen, revoked, last_sequence FROM agents WHERE token_hash = ?`,
		hashToken(token))
	var (
		a        Agent
		enrolled string
		lastSeen sql.NullString
		revoked  int
	)
	if err := row.Scan(&a.ID, &a.Host, &a.OS, &a.Version, &a.State, &a.Phase, &a.Percent, &a.Message,
		&a.Findings, &a.LastReport, &enrolled, &lastSeen, &revoked, &a.LastSequence); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Agent{}, ErrNotFound
		}
		return Agent{}, err
	}
	a.EnrolledAt, _ = time.Parse(time.RFC3339, enrolled)
	if lastSeen.Valid && lastSeen.String != "" {
		if ts, perr := time.Parse(time.RFC3339, lastSeen.String); perr == nil {
			a.LastSeen = &ts
		}
	}
	a.Revoked = revoked != 0
	if a.Revoked {
		return Agent{}, ErrRevoked
	}
	return a, nil
}

// Checkin records what an agent is doing right now and appends it to its history.
func (s *Store) Checkin(ctx context.Context, agentID string, ci Checkin) error {
	if !ValidStates[ci.State] {
		return fmt.Errorf("unknown agent state %q", ci.State)
	}
	now := s.now()
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET
		state = ?, phase = ?, percent = ?, message = ?, findings = ?,
		version = CASE WHEN ? <> '' THEN ? ELSE version END,
		os = CASE WHEN ? <> '' THEN ? ELSE os END,
		last_seen = ? WHERE id = ? AND revoked = 0`,
		ci.State, truncate(ci.Phase, 64), clampPercent(ci.Percent), truncate(ci.Message, 500),
		ci.Findings, truncate(ci.Version, 64), truncate(ci.Version, 64),
		truncate(ci.OS, 120), truncate(ci.OS, 120), now.Format(time.RFC3339), agentID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO agent_events (agent_id, at, state, phase, percent, message)
		VALUES (?,?,?,?,?,?)`,
		agentID, now.Format(time.RFC3339), ci.State, truncate(ci.Phase, 64), clampPercent(ci.Percent),
		truncate(ci.Message, 500)); err != nil {
		return err
	}
	// Keep a short trailing history per agent instead of an unbounded table.
	_, err = s.db.ExecContext(ctx, `DELETE FROM agent_events WHERE agent_id = ? AND seq NOT IN (
		SELECT seq FROM agent_events WHERE agent_id = ? ORDER BY seq DESC LIMIT 100)`, agentID, agentID)
	return err
}

// MarkReport records the run id and finding count of an ingested report.
func (s *Store) MarkReport(ctx context.Context, agentID, runID string, findings int) error {
	now := s.now()
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET state = ?, phase = 'idle', percent = 100,
		message = ?, findings = ?, last_report_id = ?, last_seen = ? WHERE id = ? AND revoked = 0`,
		StateIdle, fmt.Sprintf("reported %d findings", findings), findings,
		truncate(runID, 120), now.Format(time.RFC3339), agentID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO agent_events (agent_id, at, state, phase, percent, message)
		VALUES (?,?,?,?,?,?)`, agentID, now.Format(time.RFC3339), StateIdle, "idle", 100,
		fmt.Sprintf("reported %d findings", findings))
	return err
}

// List returns every enrolled agent, newest activity first.
func (s *Store) List(ctx context.Context) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, host, os, version, state, phase, percent, message,
		findings, last_report_id, enrolled_at, last_seen, revoked FROM agents
		ORDER BY COALESCE(last_seen, enrolled_at) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Agent{}
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Get returns one agent by id.
func (s *Store) Get(ctx context.Context, id string) (Agent, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, host, os, version, state, phase, percent, message,
		findings, last_report_id, enrolled_at, last_seen, revoked FROM agents WHERE id = ?`, id)
	return scanAgent(row)
}

// Revoke disables an endpoint's token. The record is kept so its last report and
// history remain attributable.
func (s *Store) Revoke(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET revoked = 1, state = ?, message = ? WHERE id = ?`,
		StateError, "revoked by operator", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Events returns the most recent activity for one agent.
func (s *Store) Events(ctx context.Context, agentID string, limit int) ([]Event, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	rows, err := s.db.QueryContext(ctx, `SELECT at, state, phase, percent, message FROM agent_events
		WHERE agent_id = ? ORDER BY seq DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var at, state, phase, message string
		var percent int
		if err := rows.Scan(&at, &state, &phase, &percent, &message); err != nil {
			return nil, err
		}
		ts, _ := time.Parse(time.RFC3339, at)
		out = append(out, Event{At: ts, State: state, Phase: phase, Percent: percent, Message: message})
	}
	return out, rows.Err()
}

// --- helpers ---

// rowScanner covers *sql.Row and *sql.Rows.
type rowScanner interface{ Scan(dest ...any) error }

func scanAgent(r rowScanner) (Agent, error) {
	var (
		a        Agent
		enrolled string
		lastSeen sql.NullString
		revoked  int
	)
	if err := r.Scan(&a.ID, &a.Host, &a.OS, &a.Version, &a.State, &a.Phase, &a.Percent, &a.Message,
		&a.Findings, &a.LastReport, &enrolled, &lastSeen, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Agent{}, ErrNotFound
		}
		return Agent{}, err
	}
	a.EnrolledAt, _ = time.Parse(time.RFC3339, enrolled)
	if lastSeen.Valid && lastSeen.String != "" {
		if ts, err := time.Parse(time.RFC3339, lastSeen.String); err == nil {
			a.LastSeen = &ts
		}
	}
	a.Revoked = revoked != 0
	return a, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func agentID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate agent id: %w", err)
	}
	return "AGT-" + hex.EncodeToString(b), nil
}

// hashToken is what gets stored: a stolen database row cannot be replayed.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	// Cut on a rune boundary so a multi-byte hostname or message stays valid UTF-8.
	for i := max; i > 0; i-- {
		if utf8ValidPrefix(s[:i]) {
			return s[:i]
		}
	}
	return s[:max]
}

func utf8ValidPrefix(b string) bool {
	for _, r := range b {
		if r == '\uFFFD' {
			return false
		}
	}
	return true
}

func clampPercent(p int) int {
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}

// ---------------------------------------------------------------- tasks ---

// Task states. A task is the only way the server can ask an endpoint to do
// something, and it is still pull-based: the agent claims the work when it next
// checks in. The server never connects to an endpoint.
const (
	TaskQueued  = "queued"
	TaskRunning = "running"
	TaskDone    = "done"
	TaskFailed  = "failed"
	// TaskScan is the only kind today; a scan of the enrolled host.
	TaskScan = "scan"
)

// Task is one unit of work queued for an endpoint.
type Task struct {
	ID          string     `json:"id"`
	AgentID     string     `json:"agent_id"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	RequestedAt time.Time  `json:"requested_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	Note        string     `json:"note,omitempty"`
	ReportID    string     `json:"report_id,omitempty"`
	// Attempts counts claims, so a crash-looping agent is visible and bounded.
	Attempts int `json:"attempts"`
	// LeaseExpiresAt is when the server stops trusting a running claim.
	LeaseExpiresAt *time.Time `json:"lease_expires_at,omitempty"`
}

const taskSchema = `
CREATE TABLE IF NOT EXISTS agent_tasks (
  id           TEXT PRIMARY KEY,
  agent_id     TEXT NOT NULL,
  kind         TEXT NOT NULL,
  status       TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  started_at   TEXT,
  finished_at  TEXT,
  note         TEXT NOT NULL DEFAULT '',
  report_id    TEXT NOT NULL DEFAULT '',
  attempts     INTEGER NOT NULL DEFAULT 0,
  lease_expires_at TEXT
);
`

// taskIndexes are created after the column migrations: an index on a column that
// an older database has not got yet would fail the whole startup.
const taskIndexes = `
CREATE INDEX IF NOT EXISTS idx_agent_tasks_agent ON agent_tasks(agent_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_status ON agent_tasks(agent_id, status);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_lease ON agent_tasks(status, lease_expires_at);
`

// QueueScan asks an endpoint for a scan. Re-queueing while one is still pending
// returns the pending task instead of stacking work: a stuck agent must not
// accumulate a queue nobody asked for.
func (s *Store) QueueScan(ctx context.Context, agentID string) (Task, bool, error) {
	agent, err := s.Get(ctx, agentID)
	if err != nil {
		return Task{}, false, err
	}
	if agent.Revoked {
		return Task{}, false, ErrRevoked
	}
	s.reapExpiredLeases(ctx)
	if pending, err := s.pendingTask(ctx, agentID); err != nil {
		return Task{}, false, err
	} else if pending != nil {
		return *pending, false, nil
	}
	id, err := taskID()
	if err != nil {
		return Task{}, false, err
	}
	now := s.now()
	t := Task{ID: id, AgentID: agentID, Kind: TaskScan, Status: TaskQueued, RequestedAt: now}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO agent_tasks
		(id, agent_id, kind, status, requested_at) VALUES (?,?,?,?,?)`,
		t.ID, t.AgentID, t.Kind, t.Status, now.Format(time.RFC3339)); err != nil {
		return Task{}, false, err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO agent_events (agent_id, at, state, phase, percent, message)
		VALUES (?,?,?,?,?,?)`, agentID, now.Format(time.RFC3339), StateIdle, "queued", 0,
		"scan requested from the dashboard"); err != nil {
		return Task{}, false, err
	}
	return t, true, nil
}

// ClaimTask hands the oldest queued task to the agent and marks it running.
// Claiming is atomic so two concurrent check-ins cannot both start the same scan.
func (s *Store) ClaimTask(ctx context.Context, agentID string) (*Task, error) {
	s.reapExpiredLeases(ctx)
	pending, err := s.pendingTask(ctx, agentID)
	if err != nil || pending == nil {
		return nil, err
	}
	now := s.now()
	lease := now.Add(TaskLease).Format(time.RFC3339)
	res, err := s.db.ExecContext(ctx, `UPDATE agent_tasks SET status = ?, started_at = ?,
		lease_expires_at = ?, attempts = attempts + 1 WHERE id = ? AND status = ?`,
		TaskRunning, now.Format(time.RFC3339), lease, pending.ID, TaskQueued)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Another claim won the race.
		return nil, nil
	}
	pending.Status = TaskRunning
	pending.StartedAt = &now
	return pending, nil
}

// CompleteTask records the outcome of a claimed task.
func (s *Store) CompleteTask(ctx context.Context, agentID, taskID, status, note, reportID string) error {
	if status != TaskDone && status != TaskFailed {
		return fmt.Errorf("task status must be %q or %q", TaskDone, TaskFailed)
	}
	now := s.now()
	res, err := s.db.ExecContext(ctx, `UPDATE agent_tasks SET status = ?, finished_at = ?, note = ?, report_id = ?,
		lease_expires_at = NULL
		WHERE id = ? AND agent_id = ? AND status IN (?, ?)`,
		status, now.Format(time.RFC3339), truncate(note, 500), truncate(reportID, 120),
		taskID, agentID, TaskQueued, TaskRunning)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	msg := "scan finished"
	if status == TaskFailed {
		msg = "scan failed: " + truncate(note, 200)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO agent_events (agent_id, at, state, phase, percent, message)
		VALUES (?,?,?,?,?,?)`, agentID, now.Format(time.RFC3339), StateIdle, "task", 100, msg)
	return err
}

// Tasks returns the most recent tasks for one endpoint, newest first.
func (s *Store) Tasks(ctx context.Context, agentID string, limit int) ([]Task, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, agent_id, kind, status, requested_at, started_at, finished_at, note, report_id,
		attempts, lease_expires_at FROM agent_tasks WHERE agent_id = ? ORDER BY requested_at DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Task{}
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// LatestTask is the newest task for an endpoint, or nil when it never had one.
func (s *Store) LatestTask(ctx context.Context, agentID string) (*Task, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, agent_id, kind, status, requested_at, started_at, finished_at, note, report_id,
		attempts, lease_expires_at FROM agent_tasks WHERE agent_id = ? ORDER BY requested_at DESC LIMIT 1`, agentID)
	t, err := scanTask(row)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) pendingTask(ctx context.Context, agentID string) (*Task, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, agent_id, kind, status, requested_at, started_at, finished_at, note, report_id,
		attempts, lease_expires_at FROM agent_tasks WHERE agent_id = ? AND status IN (?, ?) ORDER BY requested_at LIMIT 1`,
		agentID, TaskQueued, TaskRunning)
	t, err := scanTask(row)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func scanTask(r rowScanner) (Task, error) {
	var (
		t                 Task
		requested         string
		started, finished sql.NullString
		lease             sql.NullString
		note, reportID    string
	)
	if err := r.Scan(&t.ID, &t.AgentID, &t.Kind, &t.Status, &requested, &started, &finished, &note, &reportID,
		&t.Attempts, &lease); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Task{}, ErrNotFound
		}
		return Task{}, err
	}
	t.RequestedAt, _ = time.Parse(time.RFC3339, requested)
	if started.Valid && started.String != "" {
		if ts, err := time.Parse(time.RFC3339, started.String); err == nil {
			t.StartedAt = &ts
		}
	}
	if finished.Valid && finished.String != "" {
		if ts, err := time.Parse(time.RFC3339, finished.String); err == nil {
			t.FinishedAt = &ts
		}
	}
	t.Note = note
	t.ReportID = reportID
	if lease.Valid && lease.String != "" {
		if ts, err := time.Parse(time.RFC3339, lease.String); err == nil {
			t.LeaseExpiresAt = &ts
		}
	}
	return t, nil
}

func taskID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate task id: %w", err)
	}
	return "TASK-" + hex.EncodeToString(b), nil
}

// CancelTask withdraws a scan request that no agent has claimed yet. A running
// scan cannot be cancelled from here: there is no command channel, so the honest
// move is to let it finish rather than pretend it stopped.
func (s *Store) CancelTask(ctx context.Context, agentID string) (int, error) {
	now := s.now()
	res, err := s.db.ExecContext(ctx, `UPDATE agent_tasks SET status = ?, finished_at = ?, note = ?
		WHERE agent_id = ? AND status = ?`,
		TaskFailed, now.Format(time.RFC3339), "cancelled by operator", agentID, TaskQueued)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return 0, ErrNotFound
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO agent_events (agent_id, at, state, phase, percent, message)
		VALUES (?,?,?,?,?,?)`, agentID, now.Format(time.RFC3339), StateIdle, "cancelled", 0,
		"queued scan cancelled by operator")
	return int(n), err
}

// AdvanceSequence records the highest report sequence accepted from an agent.
// It is monotonic by construction: the caller only reaches this after verifying
// that the incoming sequence is greater than the stored one.
func (s *Store) AdvanceSequence(ctx context.Context, agentID string, sequence int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agents SET last_sequence = ?
		WHERE id = ? AND last_sequence < ?`, sequence, agentID, sequence)
	return err
}

// TaskLease is how long a claimed scan may run before the server assumes the agent
// is gone and puts the work back. Generous enough for a full assessment on a slow
// package-heavy endpoint, short enough that a killed agent does not wedge the queue.
const TaskLease = 30 * time.Minute

// maxTaskAttempts bounds how often a task is retried after its lease expires.
const maxTaskAttempts = 3

// reapExpiredLeases returns work whose agent stopped reporting back to the queue.
// Called opportunistically before claiming or queueing, so no background goroutine
// is needed and correctness does not depend on a scheduler.
func (s *Store) reapExpiredLeases(ctx context.Context) {
	now := s.now().Format(time.RFC3339)
	// Retry while attempts remain...
	_, _ = s.db.ExecContext(ctx, `UPDATE agent_tasks
		SET status = ?, lease_expires_at = NULL, attempts = attempts + 1, note = ?
		WHERE status = ? AND lease_expires_at IS NOT NULL AND lease_expires_at < ? AND attempts + 1 < ?`,
		TaskQueued, "lease expired; requeued", TaskRunning, now, maxTaskAttempts)
	// ...and give up afterwards, recording why rather than leaving it running forever.
	_, _ = s.db.ExecContext(ctx, `UPDATE agent_tasks
		SET status = ?, lease_expires_at = NULL, attempts = attempts + 1, finished_at = ?, note = ?
		WHERE status = ? AND lease_expires_at IS NOT NULL AND lease_expires_at < ? AND attempts + 1 >= ?`,
		TaskFailed, now, "lease expired: the agent did not report back", TaskRunning, now, maxTaskAttempts)
}
