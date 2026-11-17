package ticketing

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ErrTicketExists means an issue for this finding and project is already tracked.
var ErrTicketExists = errors.New("a ticket for this finding already exists in that project")

// ErrTicketNotFound is returned for an unknown ticket id.
var ErrTicketNotFound = errors.New("no such ticket")

// Ticket is the link between one finding and one GitLab issue.
//
// GitLab stays the source of truth for the issue's state: this row caches what was last
// read so the dashboard can show it without a request per render, and a stale value is
// always recognisable by LastSyncedAt.
type Ticket struct {
	ID              string `json:"id"`
	FindingKey      string `json:"finding_key"`
	Asset           string `json:"asset"`
	VulnerabilityID string `json:"vulnerability_id"`
	ProjectID       int    `json:"project_id"`
	ProjectPath     string `json:"project_path,omitempty"`
	IssueIID        int    `json:"issue_iid"`
	IssueURL        string `json:"issue_url"`
	Title           string `json:"title"`
	Labels          string `json:"labels,omitempty"`
	State           string `json:"state"`
	Assignee        string `json:"assignee,omitempty"`
	CreatedBy       string `json:"created_by,omitempty"`
	// RemediationStatus is what the plan said when the issue was filed (verified, review,
	// no_fix, ...). It is a snapshot: the finding may change while the ticket waits.
	RemediationStatus string     `json:"remediation_status,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	LastSyncedAt      *time.Time `json:"last_synced_at,omitempty"`
	// Pending is true while a creation is in flight or ended ambiguously. It is what
	// stops a retry from opening a second issue.
	Pending bool `json:"pending"`
	// Note explains a pending/failed reservation in operator terms.
	Note string `json:"note,omitempty"`
}

// Store owns the gitlab_tickets table. It shares the SQLite file with history and
// remediation, so a finding, its work item and its ticket commit against one writer.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// New creates the table if needed. Additive only: existing databases keep working.
func New(db *sql.DB) (*Store, error) {
	s := &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
	if err := s.ensureSchema(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) ensureSchema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS gitlab_tickets (
			id               TEXT PRIMARY KEY,
			finding_key      TEXT NOT NULL,
			asset            TEXT NOT NULL,
			vulnerability_id TEXT NOT NULL,
			project_id       INTEGER NOT NULL,
			project_path     TEXT,
			issue_iid        INTEGER NOT NULL DEFAULT 0,
			issue_url        TEXT NOT NULL DEFAULT '',
			title            TEXT NOT NULL,
			labels           TEXT,
			state            TEXT NOT NULL DEFAULT 'pending',
			assignee         TEXT,
			created_by       TEXT,
			created_at       TEXT NOT NULL,
			last_synced_at   TEXT,
			note             TEXT
		)`,
		// One issue per finding per project. This is the duplicate guard that holds even
		// if two dashboard requests arrive at the same moment.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_gitlab_tickets_unique
			ON gitlab_tickets(finding_key, project_id)`,
		`CREATE INDEX IF NOT EXISTS idx_gitlab_tickets_finding ON gitlab_tickets(finding_key)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("prepare ticket table: %w", err)
		}
	}
	// Existing installs predate these columns, so they are added after the table exists.
	for _, col := range [][2]string{
		{"remediation_status", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := s.ensureColumn("gitlab_tickets", col[0], col[1]); err != nil {
			return err
		}
	}
	return nil
}

// SetClock overrides the clock in tests.
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// Reserve claims the (finding, project) slot before calling GitLab.
//
// It returns the existing row when one is already tracked, so the caller can either
// report "already exists" or adopt an issue found by a recovery search. A reserved-but-
// unfinished row is deliberately *not* replaceable: that is the case where a previous
// attempt may have created an issue, and guessing would be how duplicates happen.
func (s *Store) Reserve(ctx context.Context, t Ticket) (Ticket, bool, error) {
	existing, err := s.get(ctx, t.FindingKey, t.ProjectID)
	if err == nil {
		return existing, false, nil
	}
	if !errors.Is(err, ErrTicketNotFound) {
		return Ticket{}, false, err
	}
	if t.ID == "" {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return Ticket{}, false, err
		}
		t.ID = "TKT-" + hex.EncodeToString(buf[:])
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = s.now()
	}
	t.State = "pending"
	t.IssueURL = ""
	t.IssueIID = 0
	_, err = s.db.ExecContext(ctx, `INSERT INTO gitlab_tickets
		(id, finding_key, asset, vulnerability_id, project_id, project_path, issue_iid, issue_url,
		 title, labels, state, assignee, created_by, remediation_status, created_at, note)
		VALUES (?,?,?,?,?,?,0,'',?,?,'pending',?,?,?,?,?)`,
		t.ID, t.FindingKey, t.Asset, t.VulnerabilityID, t.ProjectID, t.ProjectPath,
		t.Title, t.Labels, t.Assignee, t.CreatedBy, t.RemediationStatus,
		t.CreatedAt.Format(time.RFC3339), t.Note)
	if err != nil {
		// A concurrent insert of the same pair: return what that one reserved.
		if existing, getErr := s.get(ctx, t.FindingKey, t.ProjectID); getErr == nil {
			return existing, false, nil
		}
		return Ticket{}, false, err
	}
	return t, true, nil
}

// Complete records the issue GitLab returned.
func (s *Store) Complete(ctx context.Context, id string, issue Issue, projectPath, assignee string) (Ticket, error) {
	now := s.now()
	labels := LabelString(issue.Labels)
	_, err := s.db.ExecContext(ctx, `UPDATE gitlab_tickets SET
		issue_iid = ?, issue_url = ?, state = ?, labels = ?, assignee = ?,
		project_path = CASE WHEN ? <> '' THEN ? ELSE project_path END,
		last_synced_at = ?, note = ''
		WHERE id = ?`,
		issue.IID, issue.WebURL, stateOrOpened(issue.State), labels, firstNonEmpty(assignee, issue.AssigneeName()),
		projectPath, projectPath, now.Format(time.RFC3339), id)
	if err != nil {
		return Ticket{}, err
	}
	return s.Get(ctx, id)
}

// MarkUnknown records that a creation attempt ended without a definitive answer (timeout,
// dropped connection, 5xx). The row stays pending so the next attempt searches GitLab
// before creating anything.
func (s *Store) MarkUnknown(ctx context.Context, id, note string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE gitlab_tickets SET note = ?, last_synced_at = ? WHERE id = ?`,
		truncate(note, 300), s.now().Format(time.RFC3339), id)
	return err
}

// Abandon removes a reservation whose creation definitively failed (for example a
// rejected token), so the operator can retry cleanly.
func (s *Store) Abandon(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM gitlab_tickets WHERE id = ? AND issue_iid = 0`, id)
	return err
}

// UpdateState stores what a status refresh read, without touching anything else.
func (s *Store) UpdateState(ctx context.Context, id, state, assignee string) (Ticket, error) {
	now := s.now()
	_, err := s.db.ExecContext(ctx, `UPDATE gitlab_tickets SET state = ?, assignee = ?, last_synced_at = ?
		WHERE id = ?`, state, assignee, now.Format(time.RFC3339), id)
	if err != nil {
		return Ticket{}, err
	}
	return s.Get(ctx, id)
}

// ForFinding returns every ticket tracked for a finding (normally one, but a reading of
// the data should not assume that).
func (s *Store) ForFinding(ctx context.Context, findingKey string) ([]Ticket, error) {
	rows, err := s.db.QueryContext(ctx, ticketColumns+` WHERE finding_key = ? ORDER BY created_at`, findingKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Ticket{}
	for rows.Next() {
		t, err := scanTicket(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// List returns the most recent tickets, newest first.
func (s *Store) List(ctx context.Context, limit int) ([]Ticket, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, ticketColumns+` ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Ticket{}
	for rows.Next() {
		t, err := scanTicket(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Get returns one ticket by id.
func (s *Store) Get(ctx context.Context, id string) (Ticket, error) {
	row := s.db.QueryRowContext(ctx, ticketColumns+` WHERE id = ?`, id)
	t, err := scanTicket(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Ticket{}, ErrTicketNotFound
		}
		return Ticket{}, err
	}
	return t, nil
}

func (s *Store) get(ctx context.Context, findingKey string, projectID int) (Ticket, error) {
	row := s.db.QueryRowContext(ctx, ticketColumns+` WHERE finding_key = ? AND project_id = ?`,
		findingKey, projectID)
	t, err := scanTicket(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Ticket{}, ErrTicketNotFound
		}
		return Ticket{}, err
	}
	return t, nil
}

const ticketColumns = `SELECT id, finding_key, asset, vulnerability_id, project_id,
	COALESCE(project_path,''), issue_iid, issue_url, title, COALESCE(labels,''), state,
	COALESCE(assignee,''), COALESCE(created_by,''), COALESCE(remediation_status,''),
	created_at, COALESCE(last_synced_at,''), COALESCE(note,'') FROM gitlab_tickets`

type scanner interface {
	Scan(dest ...any) error
}

func scanTicket(sc scanner) (Ticket, error) {
	var (
		t       Ticket
		created string
		synced  string
		iid     int
		project int
	)
	if err := sc.Scan(&t.ID, &t.FindingKey, &t.Asset, &t.VulnerabilityID, &project, &t.ProjectPath,
		&iid, &t.IssueURL, &t.Title, &t.Labels, &t.State, &t.Assignee, &t.CreatedBy,
		&t.RemediationStatus, &created, &synced, &t.Note); err != nil {
		return Ticket{}, err
	}
	t.ProjectID = project
	t.IssueIID = iid
	t.CreatedAt, _ = time.Parse(time.RFC3339, created)
	if synced != "" {
		if ts, err := time.Parse(time.RFC3339, synced); err == nil {
			t.LastSyncedAt = &ts
		}
	}
	t.Pending = t.IssueIID == 0
	return t, nil
}

func stateOrOpened(state string) string {
	if state == "" {
		return "opened"
	}
	return state
}

// ensureColumn adds a column to an existing table when the catalogue says it is missing.
func (s *Store) ensureColumn(table, column, ddl string) error {
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	_, err = s.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, ddl))
	return err
}
