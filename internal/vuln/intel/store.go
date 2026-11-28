package intel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite (no cgo): the agent must cross-compile

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// Store is the local intelligence + history cache.
//
// SQLite is used because the agent must work offline and on Windows/macOS
// without a service. Schema is created idempotently on open.
type Store struct {
	db   *sql.DB
	Path string
}

const schema = `
CREATE TABLE IF NOT EXISTS advisories (
  source      TEXT NOT NULL,
  advisory_id TEXT NOT NULL,
  modified    TEXT,
  published   TEXT,
  payload     TEXT NOT NULL,
  fetched_at  TEXT NOT NULL,
  PRIMARY KEY (source, advisory_id)
);
CREATE TABLE IF NOT EXISTS advisory_packages (
  ecosystem   TEXT NOT NULL,
  package     TEXT NOT NULL,
  source      TEXT NOT NULL,
  advisory_id TEXT NOT NULL,
  PRIMARY KEY (ecosystem, package, source, advisory_id)
);
CREATE INDEX IF NOT EXISTS idx_advisory_packages_pkg ON advisory_packages(ecosystem, package);
CREATE TABLE IF NOT EXISTS kev (
  cve         TEXT PRIMARY KEY,
  date_added  TEXT,
  vendor      TEXT,
  product     TEXT,
  name        TEXT,
  ransomware  TEXT,
  url         TEXT,
  fetched_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS epss (
  cve         TEXT PRIMARY KEY,
  score       REAL NOT NULL,
  percentile  REAL NOT NULL,
  model       TEXT,
  score_date  TEXT
);
CREATE TABLE IF NOT EXISTS sync_state (
  source      TEXT PRIMARY KEY,
  last_sync   TEXT NOT NULL,
  records     INTEGER NOT NULL DEFAULT 0,
  detail      TEXT
);
CREATE TABLE IF NOT EXISTS scan_jobs (
  id           TEXT PRIMARY KEY,
  kind         TEXT NOT NULL,
  status       TEXT NOT NULL,
  host         TEXT,
  started_at   TEXT NOT NULL,
  finished_at  TEXT,
  stage        TEXT,
  stage_detail TEXT,
  percent      INTEGER NOT NULL DEFAULT 0,
  error        TEXT,
  report_id    TEXT,
  request      TEXT
);
CREATE TABLE IF NOT EXISTS settings (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  seq    INTEGER PRIMARY KEY AUTOINCREMENT,
  at     TEXT NOT NULL,
  actor  TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  remote TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, at);

CREATE TABLE IF NOT EXISTS runs (
  id          TEXT PRIMARY KEY,
  host        TEXT NOT NULL,
  started_at  TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  record      TEXT NOT NULL,
  report      TEXT NOT NULL
);
`

// OpenStore opens (and initialises) the cache at path.
func OpenStore(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("cache path is empty")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create cache dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite writer; keeps the file portable across OSes
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialise cache: %w", err)
	}
	// The cache holds hostnames, installed packages, findings and token hashes. Its files
	// are readable only by the account running the service; umask is not a security
	// boundary we should be relying on.
	for _, f := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(f, 0o600); err != nil && !os.IsNotExist(err) {
			db.Close()
			return nil, fmt.Errorf("restrict permissions on %s: %w", f, err)
		}
	}
	return &Store{db: db, Path: path}, nil
}

// AuditEntry is one durable record of who did what.
//
// Log lines rotate; this does not. Anything that changes ownership, workflow state,
// configuration or an external system goes here, so "who accepted this risk, and when"
// is answerable months later.
type AuditEntry struct {
	Seq    int64  `json:"seq"`
	At     string `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Detail string `json:"detail,omitempty"`
	Remote string `json:"remote,omitempty"`
}

// AppendAudit records one action. It never fails the caller's request: an audit write
// that cannot be stored is loud in the log, but refusing the work because the diary page
// is full would be worse.
func (s *Store) AppendAudit(ctx context.Context, e AuditEntry) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_log (at, actor, action, target, detail, remote)
		VALUES (?,?,?,?,?,?)`, e.At, e.Actor, e.Action, e.Target, e.Detail, e.Remote)
	return err
}

// ListAudit returns the newest entries first.
func (s *Store) ListAudit(ctx context.Context, limit int, action, actor string) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT seq, at, actor, action, target, detail, remote FROM audit_log`
	var (
		where []string
		args  []any
	)
	if action != "" {
		where = append(where, "action = ?")
		args = append(args, action)
	}
	if actor != "" {
		where = append(where, "actor = ?")
		args = append(args, actor)
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY seq DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Seq, &e.At, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.Remote); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AssessmentByID returns a stored assessment by its id (the receipt for a verification).
func (s *Store) AssessmentByID(ctx context.Context, id string) (model.RunRecord, model.Report, error) {
	var recPayload, reportPayload string
	err := s.db.QueryRowContext(ctx, `SELECT record, report FROM runs WHERE id = ?`, id).
		Scan(&recPayload, &reportPayload)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RunRecord{}, model.Report{}, fmt.Errorf("no assessment with id %q", id)
	}
	if err != nil {
		return model.RunRecord{}, model.Report{}, err
	}
	var rec model.RunRecord
	if err := json.Unmarshal([]byte(recPayload), &rec); err != nil {
		return model.RunRecord{}, model.Report{}, err
	}
	var rep model.Report
	if err := json.Unmarshal([]byte(reportPayload), &rep); err != nil {
		return model.RunRecord{}, model.Report{}, err
	}
	return rec, rep, nil
}

// LatestReportFor returns the newest stored assessment for a host.
func (s *Store) LatestReportFor(ctx context.Context, host string) (model.RunRecord, model.Report, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM runs WHERE host = ? ORDER BY finished_at DESC LIMIT 1`, host).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RunRecord{}, model.Report{}, fmt.Errorf("no assessment stored for %q", host)
	}
	if err != nil {
		return model.RunRecord{}, model.Report{}, err
	}
	return s.AssessmentByID(ctx, id)
}

// DB exposes the underlying handle for subsystems that own their own tables
// (the improvement engine). Sharing one connection keeps SQLite writes
// serialised across the whole process.
func (s *Store) DB() *sql.DB { return s.db }

// Close releases the database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// SaveAdvisories upserts advisories and their ecosystem/package index rows.
func (s *Store) SaveAdvisories(ctx context.Context, advs []Advisory) error {
	if len(advs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	upsert, err := tx.PrepareContext(ctx, `INSERT INTO advisories
		(source, advisory_id, modified, published, payload, fetched_at)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(source, advisory_id) DO UPDATE SET
		  modified=excluded.modified, published=excluded.published,
		  payload=excluded.payload, fetched_at=excluded.fetched_at`)
	if err != nil {
		return err
	}
	defer upsert.Close()
	index, err := tx.PrepareContext(ctx, `INSERT INTO advisory_packages
		(ecosystem, package, source, advisory_id) VALUES (?,?,?,?)
		ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}
	defer index.Close()

	for _, a := range advs {
		payload, err := json.Marshal(a)
		if err != nil {
			return err
		}
		modified := nullTime(a.Modified)
		published := nullTime(a.Published)
		if _, err := upsert.ExecContext(ctx, a.Source, a.ID, modified, published, string(payload), a.FetchedAt.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
		for _, aff := range a.Affected {
			if aff.Ecosystem == "" || aff.Name == "" {
				continue
			}
			if _, err := index.ExecContext(ctx, aff.Ecosystem, normalizeKey(aff.Name), a.Source, a.ID); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// AdvisoriesFor returns every cached advisory that mentions the package in the
// given ecosystem. Offline scans use this as their complete candidate set.
func (s *Store) AdvisoriesFor(ctx context.Context, ecosystem, name string) ([]Advisory, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.payload FROM advisory_packages p
		JOIN advisories a ON a.source = p.source AND a.advisory_id = p.advisory_id
		WHERE p.ecosystem = ? AND p.package = ?`, ecosystem, normalizeKey(name))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Advisory
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var a Advisory
		if err := json.Unmarshal([]byte(payload), &a); err != nil {
			continue
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AdvisoryByID loads a cached advisory.
func (s *Store) AdvisoryByID(ctx context.Context, id string) (Advisory, bool, error) {
	var payload string
	err := s.db.QueryRowContext(ctx, `SELECT payload FROM advisories WHERE advisory_id = ? LIMIT 1`, id).Scan(&payload)
	if err == sql.ErrNoRows {
		return Advisory{}, false, nil
	}
	if err != nil {
		return Advisory{}, false, err
	}
	var a Advisory
	if err := json.Unmarshal([]byte(payload), &a); err != nil {
		return Advisory{}, false, err
	}
	return a, true, nil
}

// AdvisoryCount returns the number of cached advisories.
func (s *Store) AdvisoryCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM advisories`).Scan(&n)
	return n, err
}

// KEVEntry is one CISA Known Exploited Vulnerabilities record.
type KEVEntry struct {
	CVEID      string
	DateAdded  string
	Vendor     string
	Product    string
	Name       string
	Ransomware string
	URL        string
}

// SaveKEV replaces the KEV catalog.
func (s *Store) SaveKEV(ctx context.Context, entries []KEVEntry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM kev`); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO kev
		(cve, date_added, vendor, product, name, ransomware, url, fetched_at)
		VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(cve) DO UPDATE SET
		date_added=excluded.date_added, vendor=excluded.vendor, product=excluded.product,
		name=excluded.name, ransomware=excluded.ransomware, url=excluded.url,
		fetched_at=excluded.fetched_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, e := range entries {
		if _, err := stmt.ExecContext(ctx, e.CVEID, e.DateAdded, e.Vendor, e.Product, e.Name, e.Ransomware, e.URL, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// KEVFor returns KEV metadata for a CVE.
func (s *Store) KEVFor(ctx context.Context, cve string) (*KEVEntry, bool, error) {
	var e KEVEntry
	err := s.db.QueryRowContext(ctx, `SELECT cve, COALESCE(date_added,''), COALESCE(vendor,''),
		COALESCE(product,''), COALESCE(name,''), COALESCE(ransomware,''), COALESCE(url,'')
		FROM kev WHERE cve = ?`, cve).Scan(&e.CVEID, &e.DateAdded, &e.Vendor, &e.Product, &e.Name, &e.Ransomware, &e.URL)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &e, true, nil
}

// KEVCount returns the number of cached KEV records.
func (s *Store) KEVCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM kev`).Scan(&n)
	return n, err
}

// EPSSEntry is one FIRST EPSS estimate.
type EPSSEntry struct {
	CVE        string
	Score      float64
	Percentile float64
	Model      string
	ScoreDate  string
}

// SaveEPSS bulk-replaces the EPSS table.
func (s *Store) SaveEPSS(ctx context.Context, entries []EPSSEntry, chunk int) error {
	if chunk <= 0 {
		chunk = 5000
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM epss`); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO epss (cve, score, percentile, model, score_date)
		VALUES (?,?,?,?,?) ON CONFLICT(cve) DO UPDATE SET
		score=excluded.score, percentile=excluded.percentile,
		model=excluded.model, score_date=excluded.score_date`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.ExecContext(ctx, e.CVE, e.Score, e.Percentile, e.Model, e.ScoreDate); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// EPSSFor returns the cached EPSS estimate for a CVE.
func (s *Store) EPSSFor(ctx context.Context, cve string) (*EPSSEntry, bool, error) {
	var e EPSSEntry
	err := s.db.QueryRowContext(ctx, `SELECT cve, score, percentile, COALESCE(model,''), COALESCE(score_date,'')
		FROM epss WHERE cve = ?`, cve).Scan(&e.CVE, &e.Score, &e.Percentile, &e.Model, &e.ScoreDate)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &e, true, nil
}

// EPSSCount returns the number of cached EPSS rows.
func (s *Store) EPSSCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM epss`).Scan(&n)
	return n, err
}

// SyncInfo describes the last successful sync of one source.
type SyncInfo struct {
	Source   string
	LastSync time.Time
	Records  int
	Detail   string
}

// RecordSync stores sync metadata for a source.
func (s *Store) RecordSync(ctx context.Context, source string, records int, detail string) error {
	return s.RecordSyncAt(ctx, source, records, detail, time.Now().UTC())
}

// RecordSyncAt stores sync metadata with an explicit timestamp (tests and
// migration backfills).
func (s *Store) RecordSyncAt(ctx context.Context, source string, records int, detail string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sync_state (source, last_sync, records, detail)
		VALUES (?,?,?,?) ON CONFLICT(source) DO UPDATE SET
		last_sync=excluded.last_sync, records=excluded.records, detail=excluded.detail`,
		source, at.UTC().Format(time.RFC3339), records, detail)
	return err
}

// SyncStates returns all sync metadata.
func (s *Store) SyncStates(ctx context.Context) ([]SyncInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source, last_sync, records, COALESCE(detail,'') FROM sync_state ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SyncInfo
	for rows.Next() {
		var si SyncInfo
		var last string
		if err := rows.Scan(&si.Source, &last, &si.Records, &si.Detail); err != nil {
			return nil, err
		}
		si.LastSync, _ = time.Parse(time.RFC3339, last)
		out = append(out, si)
	}
	return out, rows.Err()
}

// SaveRun stores a completed assessment for history and delta comparison.
func (s *Store) SaveRun(ctx context.Context, rec model.RunRecord, reportJSON []byte) error {
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO runs (id, host, started_at, finished_at, record, report)
		VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET record=excluded.record, report=excluded.report`,
		rec.ID, rec.Host, rec.StartedAt.UTC().Format(time.RFC3339),
		rec.FinishedAt.UTC().Format(time.RFC3339), string(payload), string(reportJSON))
	return err
}

// PreviousRun returns the most recent run for a host, excluding the given id.
func (s *Store) PreviousRun(ctx context.Context, host, excludeID string) (*model.RunRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT record FROM runs
		WHERE host = ? AND id <> ? ORDER BY finished_at DESC LIMIT 1`, host, excludeID)
	var payload string
	if err := row.Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	var rec model.RunRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// LatestRun returns the newest stored run for a host (empty host = any host).
func (s *Store) LatestRun(ctx context.Context, host string) (model.RunRecord, []byte, error) {
	row := s.db.QueryRowContext(ctx, `SELECT record, report FROM runs
		WHERE (? = '' OR host = ?) ORDER BY finished_at DESC LIMIT 1`, host, host)
	var recPayload, reportPayload string
	if err := row.Scan(&recPayload, &reportPayload); err != nil {
		return model.RunRecord{}, nil, err
	}
	var rec model.RunRecord
	if err := json.Unmarshal([]byte(recPayload), &rec); err != nil {
		return model.RunRecord{}, nil, err
	}
	return rec, []byte(reportPayload), nil
}

// normalizeKey lowercases package names for index lookups. Ecosystem-specific
// normalisation (PEP 503 etc.) happens in pkgurl; the store only needs a
// consistent case-insensitive key.
func normalizeKey(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// AuditActions lists the distinct actions recorded, for the filter menu.
func (s *Store) AuditActions(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT action FROM audit_log ORDER BY action`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// PruneRuns deletes stored assessments older than cutoff (RFC3339) and returns how many
// went. Findings already derived from them stay: history is pruned, evidence in the work
// items is not.
func (s *Store) PruneRuns(ctx context.Context, cutoff string) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM runs WHERE finished_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// BackupTo writes a consistent snapshot with VACUUM INTO.
//
// `cp` on a live SQLite database can capture a torn page; VACUUM INTO produces a file that
// is guaranteed to open. The snapshot is chmod 0600 because it contains the whole estate.
func (s *Store) BackupTo(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
