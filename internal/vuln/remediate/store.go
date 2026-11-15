package remediate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ErrNotFound means no such remediation item (or ownership record).
var ErrNotFound = errors.New("remediation item not found")

func isNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

const schema = `
CREATE TABLE IF NOT EXISTS asset_owners (
  asset              TEXT PRIMARY KEY,
  team               TEXT NOT NULL DEFAULT '',
  owner              TEXT NOT NULL DEFAULT '',
  service            TEXT NOT NULL DEFAULT '',
  environment        TEXT NOT NULL DEFAULT '',
  criticality        TEXT NOT NULL DEFAULT '',
  exposure           TEXT NOT NULL DEFAULT '',
  contact            TEXT NOT NULL DEFAULT '',
  mechanism          TEXT NOT NULL DEFAULT '',
  maintenance_window TEXT NOT NULL DEFAULT '',
  source             TEXT NOT NULL DEFAULT 'manual',
  status             TEXT NOT NULL DEFAULT 'owned',
  updated_at         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS remediation_items (
  id                TEXT PRIMARY KEY,
  asset             TEXT NOT NULL,
  finding_key       TEXT NOT NULL,
  vulnerability_id  TEXT NOT NULL DEFAULT '',
  product           TEXT NOT NULL DEFAULT '',
  installed_version TEXT NOT NULL DEFAULT '',
  ecosystem         TEXT NOT NULL DEFAULT '',
  severity          TEXT NOT NULL DEFAULT '',
  category          TEXT NOT NULL DEFAULT '',
  team              TEXT NOT NULL DEFAULT '',
  owner             TEXT NOT NULL DEFAULT '',
  state             TEXT NOT NULL,
  priority          TEXT NOT NULL DEFAULT '',
  due_at            TEXT,
  fixed_version     TEXT NOT NULL DEFAULT '',
  remediation       TEXT NOT NULL DEFAULT '',
  evidence          TEXT NOT NULL DEFAULT '',
  report_id         TEXT NOT NULL DEFAULT '',
  notes             TEXT NOT NULL DEFAULT '',
  first_seen        TEXT NOT NULL,
  last_seen         TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rem_state ON remediation_items(state);
CREATE INDEX IF NOT EXISTS idx_rem_team ON remediation_items(team, state);
CREATE INDEX IF NOT EXISTS idx_rem_asset ON remediation_items(asset);
CREATE INDEX IF NOT EXISTS idx_rem_due ON remediation_items(due_at);
`

// Store owns the ownership and remediation tables in the shared cache database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// New prepares the tables. db is the cache database the API already opened, so an
// ownership change and the run it refers to commit against one writer.
func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("remediate: nil database")
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("initialise remediation tables: %w", err)
	}
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}, nil
}

// SetClock is for tests.
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// SetOwnership records (or replaces) the responsibility for an asset.
//
// An empty team is allowed and means "someone must still decide": the record is
// stored with status triage so the asset is visible in the unassigned queue rather
// than silently inheriting a default owner.
func (s *Store) SetOwnership(ctx context.Context, own Ownership) (Ownership, error) {
	asset := strings.TrimSpace(own.Asset)
	if asset == "" {
		return Ownership{}, errors.New("asset is required")
	}
	now := s.now()
	own.Asset = asset
	own.Team = strings.TrimSpace(own.Team)
	own.UpdatedAt = now
	if own.Source == "" {
		own.Source = "manual"
	}
	own.Status = "owned"
	if own.Team == "" {
		own.Status = "triage"
	}
	// Environments are free-form but normalised, so filters and SLA modifiers compare
	// like with like ("Production" and "prod" are the same place).
	env := strings.ToLower(strings.TrimSpace(own.Environment))
	switch env {
	case "prod":
		env = "production"
	case "dev":
		env = "development"
	}
	own.Environment = env
	if own.Criticality != "" {
		own.Criticality = strings.ToLower(own.Criticality)
	}
	if own.Exposure != "" {
		own.Exposure = strings.ToLower(own.Exposure)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO asset_owners
		(asset, team, owner, service, environment, criticality, exposure, contact, mechanism,
		 maintenance_window, source, status, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(asset) DO UPDATE SET
		 team=excluded.team, owner=excluded.owner, service=excluded.service,
		 environment=excluded.environment, criticality=excluded.criticality,
		 exposure=excluded.exposure, contact=excluded.contact, mechanism=excluded.mechanism,
		 maintenance_window=excluded.maintenance_window, source=excluded.source,
		 status=excluded.status, updated_at=excluded.updated_at`,
		own.Asset, own.Team, own.Owner, own.Service, own.Environment, own.Criticality,
		own.Exposure, own.Contact, own.Mechanism, own.MaintenanceWindow, own.Source,
		own.Status, now.Format(time.RFC3339)); err != nil {
		return Ownership{}, err
	}
	// Responsibility improved: adopt the team for items that were waiting for it.
	if own.Status == "owned" {
		_, _ = s.db.ExecContext(ctx, `UPDATE remediation_items
			SET team = ?, state = CASE WHEN state = ? THEN ? ELSE state END,
			    owner = CASE WHEN owner = '' THEN ? ELSE owner END,
			    updated_at = ?
			WHERE asset = ? AND team = ''`,
			own.Team, string(StateAwaitingOwnership), string(StateAssigned), own.Owner,
			now.Format(time.RFC3339), own.Asset)
	}
	return own, nil
}

// Ownership returns the record for an asset; a missing record is not an error, it is
// simply "no ownership recorded" and routes to triage.
func (s *Store) Ownership(asset string) (Ownership, error) {
	var (
		o       Ownership
		updated string
	)
	err := s.db.QueryRow(`SELECT asset, team, owner, service, environment, criticality, exposure,
		contact, mechanism, maintenance_window, source, status, updated_at
		FROM asset_owners WHERE asset = ?`, strings.TrimSpace(asset)).
		Scan(&o.Asset, &o.Team, &o.Owner, &o.Service, &o.Environment, &o.Criticality, &o.Exposure,
			&o.Contact, &o.Mechanism, &o.MaintenanceWindow, &o.Source, &o.Status, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return Ownership{Asset: asset, Status: "triage", Source: "triage"}, nil
	}
	if err != nil {
		return Ownership{}, err
	}
	o.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return o, nil
}

// ListOwnership returns every recorded owner, optionally only the triage queue.
func (s *Store) ListOwnership(ctx context.Context, triageOnly bool) ([]Ownership, error) {
	q := `SELECT asset, team, owner, service, environment, criticality, exposure, contact,
		mechanism, maintenance_window, source, status, updated_at FROM asset_owners`
	if triageOnly {
		q += ` WHERE status = 'triage'`
	}
	q += ` ORDER BY asset`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Ownership{}
	for rows.Next() {
		var (
			o       Ownership
			updated string
		)
		if err := rows.Scan(&o.Asset, &o.Team, &o.Owner, &o.Service, &o.Environment, &o.Criticality,
			&o.Exposure, &o.Contact, &o.Mechanism, &o.MaintenanceWindow, &o.Source, &o.Status, &updated); err != nil {
			return nil, err
		}
		o.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		out = append(out, o)
	}
	return out, rows.Err()
}

// Filter narrows a remediation listing.
type Filter struct {
	Team        string
	Owner       string
	Asset       string
	Severity    string
	State       string
	Environment string
	Overdue     bool
	Limit       int
}

// List returns items matching the filter, most urgent first (due date, then severity).
func (s *Store) List(ctx context.Context, f Filter, policy Policy) ([]Item, error) {
	q := `SELECT id, asset, finding_key, vulnerability_id, product, installed_version, ecosystem,
		severity, category, team, owner, state, priority, due_at, fixed_version, remediation,
		evidence, report_id, notes, first_seen, last_seen, updated_at FROM remediation_items WHERE 1=1`
	args := []any{}
	if f.Team != "" {
		q += ` AND team = ?`
		args = append(args, f.Team)
	}
	if f.Owner != "" {
		q += ` AND owner = ?`
		args = append(args, f.Owner)
	}
	if f.Asset != "" {
		q += ` AND asset = ?`
		args = append(args, f.Asset)
	}
	if f.Severity != "" {
		q += ` AND severity = ?`
		args = append(args, strings.ToLower(f.Severity))
	}
	if f.State != "" {
		q += ` AND state = ?`
		args = append(args, f.State)
	}
	if f.Environment != "" {
		q += ` AND asset IN (SELECT asset FROM asset_owners WHERE environment = ?)`
		args = append(args, strings.ToLower(f.Environment))
	}
	q += ` ORDER BY CASE priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END,
		COALESCE(due_at, '9999'), last_seen DESC`
	if f.Limit > 0 {
		q += ` LIMIT ?`
		args = append(args, f.Limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := s.now()
	out := []Item{}
	for rows.Next() {
		item, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		if f.Overdue && !item.Overdue(now) {
			continue
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// Get returns one item.
func (s *Store) Get(id string) (*Item, error) {
	row := s.db.QueryRow(`SELECT id, asset, finding_key, vulnerability_id, product, installed_version,
		ecosystem, severity, category, team, owner, state, priority, due_at, fixed_version, remediation,
		evidence, report_id, notes, first_seen, last_seen, updated_at FROM remediation_items WHERE id = ?`, id)
	item, err := scanItem(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

// Patch is a partial update from an operator.
type Patch struct {
	Team  *string
	Owner *string
	State *State
	Notes *string
}

// Update applies an operator change with workflow validation.
//
// Assignment and state are separate decisions: assigning a team to a triaged item is
// allowed and moves it to "assigned", while a state change must be a legal edge in the
// workflow. Nothing here can mark work "resolved" — that requires verification of a
// later assessment, so the API refuses a direct move to resolved.
func (s *Store) Update(ctx context.Context, id string, patch Patch) (Item, error) {
	item, err := s.Get(id)
	if err != nil {
		return Item{}, err
	}
	now := s.now()
	if patch.Team != nil {
		item.Team = strings.TrimSpace(*patch.Team)
		if item.Team != "" && item.State == StateAwaitingOwnership {
			item.State = StateAssigned
		}
		if item.Team == "" && item.State == StateAssigned {
			item.State = StateAwaitingOwnership
		}
	}
	if patch.Owner != nil {
		item.Owner = strings.TrimSpace(*patch.Owner)
	}
	if patch.Notes != nil {
		item.Notes = strings.TrimSpace(*patch.Notes)
	}
	if patch.State != nil {
		next := *patch.State
		if next == StateResolved {
			return Item{}, fmt.Errorf("resolved is set by verification, not by hand: run a verification scan")
		}
		if !CanTransition(item.State, next) {
			return Item{}, fmt.Errorf("cannot move from %s to %s", item.State, next)
		}
		item.State = next
	}
	item.UpdatedAt = now
	if err := s.update(*item); err != nil {
		return Item{}, err
	}
	return *item, nil
}

// MarkVerified resolves an item after a later assessment no longer reports it. This is
// the only path to "resolved" from a state that is waiting for verification.
func (s *Store) MarkVerified(ctx context.Context, id, reportID string) (Item, error) {
	item, err := s.Get(id)
	if err != nil {
		return Item{}, err
	}
	// A verified rescan is itself the evidence: it may resolve an item that is
	// waiting for verification or one where the remediation was already applied.
	if item.State != StatePendingVerification && item.State != StateApplied {
		return Item{}, fmt.Errorf("item is %s; verification resolves items that have been remediated", item.State)
	}
	now := s.now()
	item.State = StateResolved
	item.UpdatedAt = now
	item.Notes = strings.TrimSpace(item.Notes + " | verified resolved in " + reportID)
	if err := s.update(*item); err != nil {
		return Item{}, err
	}
	return *item, nil
}

// Summary is the count set the dashboard needs, computed in SQL rather than by
// loading rows into the browser.
type Summary struct {
	Total              int            `json:"total"`
	Open               int            `json:"open"`
	Unassigned         int            `json:"unassigned"`
	Overdue            int            `json:"overdue"`
	TriageAssets       int            `json:"triage_assets"`
	Resolved           int            `json:"resolved"`
	ByState            map[string]int `json:"by_state"`
	ByTeam             map[string]int `json:"by_team"`
	ByPriority         map[string]int `json:"by_priority"`
	AutomationEligible int            `json:"automation_eligible"`
}

// Summary computes the dashboard counts.
func (s *Store) Summary(ctx context.Context) (Summary, error) {
	out := Summary{ByState: map[string]int{}, ByTeam: map[string]int{}, ByPriority: map[string]int{}}
	rows, err := s.db.QueryContext(ctx, `SELECT state, team, priority, due_at, COUNT(*) FROM remediation_items
		GROUP BY state, team, priority, due_at`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	now := s.now()
	for rows.Next() {
		var (
			state, team, priority string
			due                   sql.NullString
			count                 int
		)
		if err := rows.Scan(&state, &team, &priority, &due, &count); err != nil {
			return out, err
		}
		out.Total += count
		out.ByState[state] += count
		out.ByPriority[priority] += count
		label := team
		if label == "" {
			label = "(unassigned)"
		}
		out.ByTeam[label] += count
		switch State(state) {
		case StateResolved, StateRiskAccepted, StateFalsePositive:
			if State(state) == StateResolved {
				out.Resolved += count
			}
			continue
		}
		out.Open += count
		if team == "" {
			out.Unassigned += count
		}
		if due.Valid {
			if ts, perr := time.Parse(time.RFC3339, due.String); perr == nil && now.After(ts) {
				out.Overdue += count
			}
		}
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	// Assets with no ownership record but with work waiting for one.
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT asset) FROM remediation_items WHERE team = ''`).Scan(&out.TriageAssets)
	// Automation eligibility is a policy question; nothing is executable today, so the
	// honest answer is zero rather than "everything is eligible".
	out.AutomationEligible = 0
	return out, nil
}

// Close idempotency for items that a later report no longer contains: this is what
// makes "pending verification" mean something. Called after a reconcile.
func (s *Store) ReconcileAbsences(ctx context.Context, reportID string, assets []string, policy Policy) ([]Item, error) {
	now := s.now()
	moved := []Item{}
	for _, asset := range assets {
		items, err := s.List(ctx, Filter{Asset: asset}, policy)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if item.ReportID == reportID || terminal(item.State) {
				continue
			}
			// The asset was assessed and the finding is gone: it is applied and
			// awaiting independent verification, not resolved.
			if item.State == StatePendingVerification || item.State == StateApplied {
				continue
			}
			item.State = StatePendingVerification
			item.UpdatedAt = now
			if err := s.update(item); err != nil {
				return nil, err
			}
			moved = append(moved, item)
		}
	}
	return moved, nil
}

// --- row plumbing ---

type rowScanner interface{ Scan(dest ...any) error }

func scanItem(r rowScanner) (Item, error) {
	var (
		it                       Item
		state, dueAt             string
		firstSeen, lastSeen, upd string
		due                      sql.NullString
	)
	if err := r.Scan(&it.ID, &it.Asset, &it.FindingKey, &it.VulnerabilityID, &it.Product,
		&it.InstalledVersion, &it.Ecosystem, &it.Severity, &it.Category, &it.Team, &it.Owner,
		&state, &it.Priority, &due, &it.FixedVersion, &it.Remediation, &it.Evidence,
		&it.ReportID, &it.Notes, &firstSeen, &lastSeen, &upd); err != nil {
		return Item{}, err
	}
	it.State = State(state)
	it.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
	it.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
	it.UpdatedAt, _ = time.Parse(time.RFC3339, upd)
	if due.Valid && due.String != "" {
		if ts, err := time.Parse(time.RFC3339, due.String); err == nil {
			it.DueAt = &ts
		}
	}
	_ = dueAt
	return it, nil
}

func (s *Store) insert(item Item) error {
	_, err := s.db.Exec(`INSERT INTO remediation_items
		(id, asset, finding_key, vulnerability_id, product, installed_version, ecosystem, severity,
		 category, team, owner, state, priority, due_at, fixed_version, remediation, evidence,
		 report_id, notes, first_seen, last_seen, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		item.ID, item.Asset, item.FindingKey, item.VulnerabilityID, item.Product,
		item.InstalledVersion, item.Ecosystem, item.Severity, item.Category, item.Team,
		item.Owner, string(item.State), item.Priority, timePtr(item.DueAt),
		item.FixedVersion, item.Remediation, item.Evidence, item.ReportID, item.Notes,
		item.FirstSeen.Format(time.RFC3339), item.LastSeen.Format(time.RFC3339),
		item.UpdatedAt.Format(time.RFC3339))
	return err
}

func (s *Store) update(item Item) error {
	_, err := s.db.Exec(`UPDATE remediation_items SET
		severity=?, category=?, team=?, owner=?, state=?, priority=?, due_at=?, fixed_version=?,
		remediation=?, evidence=?, report_id=?, notes=?, last_seen=?, updated_at=?
		WHERE id=?`,
		item.Severity, item.Category, item.Team, item.Owner, string(item.State), item.Priority,
		timePtr(item.DueAt), item.FixedVersion, item.Remediation, item.Evidence, item.ReportID,
		item.Notes, item.LastSeen.Format(time.RFC3339), item.UpdatedAt.Format(time.RFC3339), item.ID)
	return err
}

func timePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// PolicyFromSettings builds the policy from the dashboard's key/value settings, so an
// organisation can change the SLA windows and team mapping without a rebuild.
func PolicyFromSettings(settings map[string]string) Policy {
	policy := DefaultPolicy()
	if raw := strings.TrimSpace(settings["remediation.policy"]); raw != "" {
		var parsed Policy
		if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
			if len(parsed.Days) > 0 {
				policy.Days = parsed.Days
			}
			policy.AccelerateKEV = parsed.AccelerateKEV
			policy.AccelerateInternetExposure = parsed.AccelerateInternetExposure
			policy.Teams = parsed.Teams
		}
	}
	return policy
}

// EncodePolicy is the inverse, for the settings endpoint.
func EncodePolicy(p Policy) (string, error) {
	blob, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return string(blob), nil
}

// TeamsInUse lists the teams referenced by open items, for filter menus.
func (s *Store) TeamsInUse(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT team FROM remediation_items WHERE team <> '' ORDER BY team`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var team string
		if err := rows.Scan(&team); err != nil {
			return nil, err
		}
		out = append(out, team)
	}
	sort.Strings(out)
	return out, rows.Err()
}
