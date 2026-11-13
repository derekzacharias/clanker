package improve

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/assess"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// Engine owns the improvement tables. It shares the scanner's SQLite handle so
// feedback, rules and scan history cannot diverge.
type Engine struct {
	store *intel.Store
	db    *sql.DB
	now   func() time.Time
}

const schema = `
CREATE TABLE IF NOT EXISTS finding_feedback (
  id           TEXT PRIMARY KEY,
  finding_id   TEXT NOT NULL,
  report_id    TEXT,
  host         TEXT,
  cve          TEXT,
  advisory_id  TEXT,
  product      TEXT,
  version      TEXT,
  ecosystem    TEXT,
  severity     TEXT,
  applicability TEXT,
  verdict      TEXT NOT NULL,
  reason_code  TEXT,
  reason_text  TEXT,
  analyst      TEXT,
  verification TEXT,
  improvement_id TEXT,
  created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feedback_finding ON finding_feedback(finding_id);
CREATE INDEX IF NOT EXISTS idx_feedback_created ON finding_feedback(created_at);

CREATE TABLE IF NOT EXISTS finding_state (
  finding_id    TEXT PRIMARY KEY,
  verdict       TEXT NOT NULL,
  applicability TEXT NOT NULL,
  confidence    TEXT,
  explanation   TEXT,
  evidence      TEXT,
  feedback_id   TEXT,
  updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS improvements (
  id            TEXT PRIMARY KEY,
  category      TEXT NOT NULL,
  status        TEXT NOT NULL,
  signature     TEXT NOT NULL,
  payload       TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_improvements_status ON improvements(status);
CREATE INDEX IF NOT EXISTS idx_improvements_signature ON improvements(signature);

CREATE TABLE IF NOT EXISTS improvement_events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  improvement_id TEXT NOT NULL,
  from_status   TEXT NOT NULL,
  to_status     TEXT NOT NULL,
  actor         TEXT NOT NULL,
  note          TEXT,
  created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_improvement ON improvement_events(improvement_id);

CREATE TABLE IF NOT EXISTS improvement_rules (
  id             TEXT PRIMARY KEY,
  kind           TEXT NOT NULL,
  version        INTEGER NOT NULL,
  payload        TEXT NOT NULL,
  improvement_id TEXT,
  active         INTEGER NOT NULL DEFAULT 0,
  created_at     TEXT NOT NULL,
  deactivated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_rules_kind ON improvement_rules(kind, active);
`

// New initialises the improvement schema on the scanner's database handle.
func New(store *intel.Store) (*Engine, error) {
	if store == nil {
		return nil, fmt.Errorf("improvement engine requires the scanner store")
	}
	db := store.DB()
	if db == nil {
		return nil, fmt.Errorf("scanner store has no database handle")
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("initialise improvement schema: %w", err)
	}
	return &Engine{store: store, db: db, now: func() time.Time { return time.Now().UTC() }}, nil
}

// Now overrides the clock (tests).
func (e *Engine) Now(f func() time.Time) { e.now = f }

func newID(prefix string) string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(b)
}

// ---------------------------------------------------------------- feedback ---

// RecordFeedback persists an analyst review together with its verification.
func (e *Engine) RecordFeedback(ctx context.Context, fb Feedback) error {
	if fb.ID == "" {
		fb.ID = newID("FB")
	}
	if fb.CreatedAt.IsZero() {
		fb.CreatedAt = e.now()
	}
	verification, err := json.Marshal(fb.Verification)
	if err != nil {
		return err
	}
	_, err = e.db.ExecContext(ctx, `INSERT INTO finding_feedback
		(id, finding_id, report_id, host, cve, advisory_id, product, version, ecosystem, severity,
		 applicability, verdict, reason_code, reason_text, analyst, verification, improvement_id, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		fb.ID, fb.Finding.ID, fb.Finding.ReportID, fb.Finding.Host, fb.Finding.CVE, fb.Finding.AdvisoryID,
		fb.Finding.Product, fb.Finding.Version, fb.Finding.Ecosystem, fb.Finding.Severity,
		fb.Finding.Applicability, string(fb.Verdict), string(fb.ReasonCode), fb.ReasonText, fb.Analyst,
		string(verification), fb.ImprovementID, fb.CreatedAt.Format(time.RFC3339))
	return err
}

// FeedbackForFinding returns the review history for one finding, newest first.
func (e *Engine) FeedbackForFinding(ctx context.Context, findingID string) ([]Feedback, error) {
	rows, err := e.db.QueryContext(ctx, `SELECT id, finding_id, report_id, host, cve, advisory_id, product,
		version, ecosystem, severity, applicability, verdict, reason_code, reason_text, analyst,
		verification, improvement_id, created_at
		FROM finding_feedback WHERE finding_id = ? ORDER BY created_at DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Feedback
	for rows.Next() {
		fb, err := scanFeedback(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, fb)
	}
	return out, rows.Err()
}

// RecentFeedback returns the newest reviews across all findings.
func (e *Engine) RecentFeedback(ctx context.Context, limit int) ([]Feedback, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := e.db.QueryContext(ctx, `SELECT id, finding_id, report_id, host, cve, advisory_id, product,
		version, ecosystem, severity, applicability, verdict, reason_code, reason_text, analyst,
		verification, improvement_id, created_at
		FROM finding_feedback ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Feedback
	for rows.Next() {
		fb, err := scanFeedback(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, fb)
	}
	return out, rows.Err()
}

func scanFeedback(r interface{ Scan(...any) error }) (Feedback, error) {
	var (
		fb        Feedback
		verdict   string
		reason    string
		verif     sql.NullString
		improveID string
		created   string
	)
	if err := r.Scan(&fb.ID, &fb.Finding.ID, &fb.Finding.ReportID, &fb.Finding.Host, &fb.Finding.CVE,
		&fb.Finding.AdvisoryID, &fb.Finding.Product, &fb.Finding.Version, &fb.Finding.Ecosystem,
		&fb.Finding.Severity, &fb.Finding.Applicability, &verdict, &reason, &fb.ReasonText,
		&fb.Analyst, &verif, &improveID, &created); err != nil {
		return fb, err
	}
	fb.Verdict = Verdict(verdict)
	fb.ReasonCode = ReasonCode(reason)
	fb.ImprovementID = improveID
	if created != "" {
		fb.CreatedAt, _ = time.Parse(time.RFC3339, created)
	}
	if verif.Valid && verif.String != "" && verif.String != "null" {
		var v Verification
		if err := json.Unmarshal([]byte(verif.String), &v); err == nil {
			fb.Verification = &v
		}
	}
	return fb, nil
}

// SaveState applies the analyst-verified classification for a finding.
func (e *Engine) SaveState(ctx context.Context, s State) error {
	evidence, err := json.Marshal(s.Evidence)
	if err != nil {
		return err
	}
	if s.UpdatedAt.IsZero() {
		s.UpdatedAt = e.now()
	}
	_, err = e.db.ExecContext(ctx, `INSERT INTO finding_state
		(finding_id, verdict, applicability, confidence, explanation, evidence, feedback_id, updated_at)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(finding_id) DO UPDATE SET
		  verdict=excluded.verdict, applicability=excluded.applicability,
		  confidence=excluded.confidence, explanation=excluded.explanation,
		  evidence=excluded.evidence, feedback_id=excluded.feedback_id,
		  updated_at=excluded.updated_at`,
		s.FindingID, string(s.Verdict), s.Applicability, s.Confidence, s.Explanation,
		string(evidence), s.FeedbackID, s.UpdatedAt.Format(time.RFC3339))
	return err
}

// States returns every analyst-verified classification, keyed by finding id.
func (e *Engine) States(ctx context.Context) (map[string]State, error) {
	rows, err := e.db.QueryContext(ctx, `SELECT finding_id, verdict, applicability, confidence,
		explanation, evidence, feedback_id, updated_at FROM finding_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]State{}
	for rows.Next() {
		var (
			s        State
			verdict  string
			evidence string
			updated  string
		)
		if err := rows.Scan(&s.FindingID, &verdict, &s.Applicability, &s.Confidence,
			&s.Explanation, &evidence, &s.FeedbackID, &updated); err != nil {
			return nil, err
		}
		s.Verdict = Verdict(verdict)
		s.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		if evidence != "" {
			_ = json.Unmarshal([]byte(evidence), &s.Evidence)
		}
		out[s.FindingID] = s
	}
	return out, rows.Err()
}

// ------------------------------------------------------------------ rules ----

// ActiveRule returns the currently deployed rule of a kind, if any.
func (e *Engine) ActiveRule(ctx context.Context, kind string) (*Rule, error) {
	row := e.db.QueryRowContext(ctx, `SELECT id, kind, version, payload, COALESCE(improvement_id,''),
		active, created_at, deactivated_at FROM improvement_rules
		WHERE kind = ? AND active = 1 ORDER BY version DESC LIMIT 1`, kind)
	var (
		r        Rule
		active   int
		created  string
		deactive sql.NullString
	)
	err := row.Scan(&r.ID, &r.Kind, &r.Version, &r.Payload, &r.ImprovementID, &active, &created, &deactive)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.Active = active == 1
	r.CreatedAt, _ = time.Parse(time.RFC3339, created)
	if deactive.Valid {
		if t, err := time.Parse(time.RFC3339, deactive.String); err == nil {
			r.DeactivatedAt = &t
		}
	}
	return &r, nil
}

// ActivePolicy returns the detection policy in force and the rule that produced
// it. A malformed rule falls back to defaults and reports why.
func (e *Engine) ActivePolicy(ctx context.Context) (assess.Policy, string, []string) {
	rule, err := e.ActiveRule(ctx, RuleKindDetectionPolicy)
	if err != nil || rule == nil {
		return assess.DefaultPolicy(), "", nil
	}
	pol, err := assess.ParsePolicy([]byte(rule.Payload))
	if err != nil {
		return assess.DefaultPolicy(), "", []string{"deployed rule " + rule.ID + " is unusable: " + err.Error()}
	}
	return pol, rule.ID, pol.Notes()
}

// ListRules returns the rule history, newest first.
func (e *Engine) ListRules(ctx context.Context) ([]Rule, error) {
	rows, err := e.db.QueryContext(ctx, `SELECT id, kind, version, payload, COALESCE(improvement_id,''),
		active, created_at, deactivated_at FROM improvement_rules ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var (
			r        Rule
			active   int
			created  string
			deactive sql.NullString
		)
		if err := rows.Scan(&r.ID, &r.Kind, &r.Version, &r.Payload, &r.ImprovementID,
			&active, &created, &deactive); err != nil {
			return nil, err
		}
		r.Active = active == 1
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		if deactive.Valid {
			if t, err := time.Parse(time.RFC3339, deactive.String); err == nil {
				r.DeactivatedAt = &t
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// activateRule inserts a new active version and deactivates the previous one.
func (e *Engine) activateRule(ctx context.Context, kind, payload, improvementID string) (*Rule, error) {
	var maxVersion int
	if err := e.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM improvement_rules WHERE kind = ?`, kind).Scan(&maxVersion); err != nil {
		return nil, err
	}
	now := e.now()
	if _, err := e.db.ExecContext(ctx, `UPDATE improvement_rules SET active = 0, deactivated_at = ?
		WHERE kind = ? AND active = 1`, now.Format(time.RFC3339), kind); err != nil {
		return nil, err
	}
	rule := Rule{ID: newID("RULE"), Kind: kind, Version: maxVersion + 1, Payload: payload,
		ImprovementID: improvementID, Active: true, CreatedAt: now}
	if _, err := e.db.ExecContext(ctx, `INSERT INTO improvement_rules
		(id, kind, version, payload, improvement_id, active, created_at)
		VALUES (?,?,?,?,?,1,?)`,
		rule.ID, rule.Kind, rule.Version, rule.Payload, rule.ImprovementID, rule.CreatedAt.Format(time.RFC3339)); err != nil {
		return nil, err
	}
	return &rule, nil
}

// deactivateRule turns off the active rule of a kind and reports what was active.
func (e *Engine) deactivateRule(ctx context.Context, kind string) (*Rule, error) {
	active, err := e.ActiveRule(ctx, kind)
	if err != nil || active == nil {
		return active, err
	}
	if _, err := e.db.ExecContext(ctx, `UPDATE improvement_rules SET active = 0, deactivated_at = ?
		WHERE id = ?`, e.now().Format(time.RFC3339), active.ID); err != nil {
		return nil, err
	}
	return active, nil
}

// ---------------------------------------------------------- improvements ----

// SaveImprovement upserts a proposal.
func (e *Engine) SaveImprovement(ctx context.Context, imp Improvement) error {
	if imp.CreatedAt.IsZero() {
		imp.CreatedAt = e.now()
	}
	imp.UpdatedAt = e.now()
	payload, err := json.Marshal(imp)
	if err != nil {
		return err
	}
	_, err = e.db.ExecContext(ctx, `INSERT INTO improvements (id, category, status, signature, payload, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET category=excluded.category, status=excluded.status,
		  signature=excluded.signature, payload=excluded.payload, updated_at=excluded.updated_at`,
		imp.ID, string(imp.Category), string(imp.Status), imp.Signature, string(payload),
		imp.CreatedAt.Format(time.RFC3339), imp.UpdatedAt.Format(time.RFC3339))
	return err
}

// GetImprovement loads one proposal.
func (e *Engine) GetImprovement(ctx context.Context, id string) (*Improvement, error) {
	var payload string
	err := e.db.QueryRowContext(ctx, `SELECT payload FROM improvements WHERE id = ?`, id).Scan(&payload)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var imp Improvement
	if err := json.Unmarshal([]byte(payload), &imp); err != nil {
		return nil, err
	}
	return &imp, nil
}

// ListImprovements returns proposals, newest first.
func (e *Engine) ListImprovements(ctx context.Context, limit int) ([]Improvement, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := e.db.QueryContext(ctx, `SELECT payload FROM improvements ORDER BY updated_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Improvement
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var imp Improvement
		if err := json.Unmarshal([]byte(payload), &imp); err != nil {
			continue
		}
		out = append(out, imp)
	}
	return out, rows.Err()
}

// FindBySignature returns the most recent proposal with a signature.
func (e *Engine) FindBySignature(ctx context.Context, signature string) (*Improvement, error) {
	row := e.db.QueryRowContext(ctx, `SELECT payload FROM improvements WHERE signature = ?
		ORDER BY updated_at DESC LIMIT 1`, signature)
	var payload string
	err := row.Scan(&payload)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var imp Improvement
	if err := json.Unmarshal([]byte(payload), &imp); err != nil {
		return nil, err
	}
	return &imp, nil
}

// AppendEvent records a lifecycle transition.
func (e *Engine) AppendEvent(ctx context.Context, ev Event) error {
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = e.now()
	}
	_, err := e.db.ExecContext(ctx, `INSERT INTO improvement_events
		(improvement_id, from_status, to_status, actor, note, created_at) VALUES (?,?,?,?,?,?)`,
		ev.ImprovementID, string(ev.From), string(ev.To), ev.Actor, ev.Note,
		ev.CreatedAt.Format(time.RFC3339))
	return err
}

// Events returns the audit trail for a proposal.
func (e *Engine) Events(ctx context.Context, improvementID string) ([]Event, error) {
	rows, err := e.db.QueryContext(ctx, `SELECT id, improvement_id, from_status, to_status, actor,
		COALESCE(note,''), created_at FROM improvement_events WHERE improvement_id = ? ORDER BY id`, improvementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var (
			ev      Event
			from    string
			to      string
			created string
		)
		if err := rows.Scan(&ev.ID, &ev.ImprovementID, &from, &to, &ev.Actor, &ev.Note, &created); err != nil {
			return nil, err
		}
		ev.From = Status(from)
		ev.To = Status(to)
		ev.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// CountByStatus returns how many proposals are in each state.
func (e *Engine) CountByStatus(ctx context.Context) (map[Status]int, error) {
	rows, err := e.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM improvements GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[Status]int{}
	for rows.Next() {
		var (
			s string
			n int
		)
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[Status(s)] = n
	}
	return out, rows.Err()
}

// deleteFeedbackForTest is used only by tests to simulate retention cleanup.
func (e *Engine) deleteFeedbackForTest(ctx context.Context, findingID string) error {
	_, err := e.db.ExecContext(ctx, `DELETE FROM finding_feedback WHERE finding_id = ?`, findingID)
	return err
}

// ensure model import is used even when callers only read types.
var _ = model.SeverityUnknown
