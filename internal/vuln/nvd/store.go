package nvd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/cpe"
)

// EnsureSchema creates the NVD tables in the shared cache database. It is
// idempotent and additive: existing tables are never altered destructively.
func EnsureSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS nvd_cves (
		  id           TEXT PRIMARY KEY,
		  published    TEXT,
		  modified     TEXT,
		  vuln_status  TEXT,
		  description  TEXT,
		  cvss_score   REAL,
		  cvss_vector  TEXT,
		  cvss_severity TEXT,
		  cvss_version TEXT,
		  configs      TEXT,
		  references_json TEXT,
		  weaknesses_json TEXT,
		  fetched_at   TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_nvd_cves_status ON nvd_cves(vuln_status)`,
		`CREATE TABLE IF NOT EXISTS nvd_cpe_matches (
		  cve_id        TEXT NOT NULL,
		  match_criteria_id TEXT NOT NULL DEFAULT '',
		  criteria      TEXT NOT NULL,
		  vendor        TEXT NOT NULL,
		  product       TEXT NOT NULL,
		  version       TEXT NOT NULL DEFAULT '*',
		  vulnerable    INTEGER NOT NULL,
		  start_incl    TEXT, start_excl TEXT, end_incl TEXT, end_excl TEXT,
		  PRIMARY KEY (cve_id, match_criteria_id, criteria)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_nvd_cpm_vp ON nvd_cpe_matches(vendor, product)`,
		`CREATE INDEX IF NOT EXISTS idx_nvd_cpm_cve ON nvd_cpe_matches(cve_id)`,
		`CREATE TABLE IF NOT EXISTS nvd_cpes (
		  cpe23         TEXT PRIMARY KEY,
		  vendor        TEXT NOT NULL,
		  product       TEXT NOT NULL,
		  version       TEXT NOT NULL DEFAULT '*',
		  deprecated    INTEGER NOT NULL DEFAULT 0,
		  deprecated_by TEXT,
		  titles_json   TEXT,
		  refs_json     TEXT,
		  last_modified TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_nvd_cpes_vp ON nvd_cpes(vendor, product)`,
		`CREATE TABLE IF NOT EXISTS nvd_sync_history (
		  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
		  source      TEXT NOT NULL,
		  started_at  TEXT NOT NULL,
		  finished_at TEXT,
		  status      TEXT NOT NULL,
		  mode        TEXT NOT NULL,
		  window_start TEXT,
		  window_end  TEXT,
		  total_seen  INTEGER NOT NULL DEFAULT 0,
		  imported    INTEGER NOT NULL DEFAULT 0,
		  updated     INTEGER NOT NULL DEFAULT 0,
		  failed      INTEGER NOT NULL DEFAULT 0,
		  detail      TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_nvd_sync_source ON nvd_sync_history(source, started_at)`,
		`CREATE TABLE IF NOT EXISTS nvd_eval_cache (
		  vendor    TEXT NOT NULL,
		  product   TEXT NOT NULL,
		  version   TEXT NOT NULL,
		  cve_id    TEXT NOT NULL,
		  verdict   TEXT NOT NULL,
		  details   TEXT,
		  checked_at TEXT NOT NULL,
		  PRIMARY KEY (vendor, product, version, cve_id)
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("nvd schema: %w", err)
		}
	}
	return nil
}

// Store persists NVD intelligence in the shared cache database.
type Store struct{ db *sql.DB }

// NewStore wraps an open database. EnsureSchema must have run first.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// SaveCVEs upserts CVE records and rebuilds their cpeMatch index rows inside
// one transaction, so a partial page can never leave a torn index.
func (s *Store) SaveCVEs(ctx context.Context, records []Record, fetchedAt time.Time) (imported, updated int, err error) {
	if len(records) == 0 {
		return 0, 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	upsert, err := tx.PrepareContext(ctx, `INSERT INTO nvd_cves
		(id, published, modified, vuln_status, description, cvss_score, cvss_vector,
		 cvss_severity, cvss_version, configs, references_json, weaknesses_json, fetched_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
		  published=excluded.published, modified=excluded.modified,
		  vuln_status=excluded.vuln_status, description=excluded.description,
		  cvss_score=excluded.cvss_score, cvss_vector=excluded.cvss_vector,
		  cvss_severity=excluded.cvss_severity, cvss_version=excluded.cvss_version,
		  configs=excluded.configs, references_json=excluded.references_json,
		  weaknesses_json=excluded.weaknesses_json, fetched_at=excluded.fetched_at`)
	if err != nil {
		return 0, 0, err
	}
	defer upsert.Close()

	delMatches, err := tx.PrepareContext(ctx, `DELETE FROM nvd_cpe_matches WHERE cve_id = ?`)
	if err != nil {
		return 0, 0, err
	}
	defer delMatches.Close()
	insMatch, err := tx.PrepareContext(ctx, `INSERT INTO nvd_cpe_matches
		(cve_id, match_criteria_id, criteria, vendor, product, version, vulnerable,
		 start_incl, start_excl, end_incl, end_excl)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(cve_id, match_criteria_id, criteria) DO NOTHING`)
	if err != nil {
		return 0, 0, err
	}
	defer insMatch.Close()

	now := fetchedAt.UTC().Format(time.RFC3339)
	insCVE, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO nvd_cves
		(id, published, modified, vuln_status, description, cvss_score, cvss_vector,
		 cvss_severity, cvss_version, configs, references_json, weaknesses_json, fetched_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, 0, err
	}
	defer insCVE.Close()
	for _, r := range records {
		cvss := r.PrimaryCVSS()
		var score sql.NullFloat64
		var vector, sev, ver string
		if cvss != nil {
			score = sql.NullFloat64{Float64: cvss.Score, Valid: true}
			vector, sev, ver = cvss.Vector, cvss.Severity, cvss.Version
		}
		configsJSON, err := json.Marshal(r.Configs)
		if err != nil {
			return 0, 0, fmt.Errorf("encode configs for %s: %w", r.ID, err)
		}
		refsJSON, _ := json.Marshal(r.References)
		weaksJSON, _ := json.Marshal(r.WeaknessIDs())
		res, err := insCVE.ExecContext(ctx, r.ID, nullTime(r.Published), nullTime(r.Modified),
			r.Status, r.Description, score, nullable(vector), nullable(sev), nullable(ver),
			string(configsJSON), string(refsJSON), string(weaksJSON), now)
		if err != nil {
			return 0, 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			imported++
		} else {
			// Already stored: refresh the record and rebuild its match index.
			if _, err := upsert.ExecContext(ctx, r.ID, nullTime(r.Published), nullTime(r.Modified),
				r.Status, r.Description, score, nullable(vector), nullable(sev), nullable(ver),
				string(configsJSON), string(refsJSON), string(weaksJSON), now); err != nil {
				return 0, 0, err
			}
			updated++
		}
		if _, err := delMatches.ExecContext(ctx, r.ID); err != nil {
			return 0, 0, err
		}
		matches, err := indexMatches(r.ID, r.Configs)
		if err != nil {
			return 0, 0, fmt.Errorf("index matches for %s: %w", r.ID, err)
		}
		for _, m := range matches {
			if _, err := insMatch.ExecContext(ctx, m.cve, m.mcID, m.criteria, m.vendor, m.product,
				m.version, m.vulnerable, m.startIncl, m.startExcl, m.endIncl, m.endExcl); err != nil {
				return 0, 0, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return imported, updated, nil
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

type matchRow struct {
	cve, mcID, criteria, vendor, product, version string
	vulnerable                                    bool
	startIncl, startExcl, endIncl, endExcl        string
}

// indexMatches flattens the configuration tree into lookup rows.
func indexMatches(cveID string, nodes []cpe.Node) ([]matchRow, error) {
	var out []matchRow
	var walk func(nodes []cpe.Node) error
	walk = func(nodes []cpe.Node) error {
		for _, n := range nodes {
			for _, m := range n.Matches {
				crit, err := cpe.Parse(m.Criteria)
				if err != nil {
					// Unparsable criteria cannot be looked up; skip it from
					// the index (the CVE itself is still stored).
					continue
				}
				out = append(out, matchRow{
					cve: cveID, mcID: m.MatchCriteriaID, criteria: m.Criteria,
					vendor: strings.ToLower(crit.Vendor), product: strings.ToLower(crit.Product),
					version:    crit.Version,
					vulnerable: m.Vulnerable,
					startIncl:  m.StartIncluding, startExcl: m.StartExcluding,
					endIncl: m.EndIncluding, endExcl: m.EndExcluding,
				})
			}
			if err := walk(n.Children); err != nil {
				return err
			}
		}
		return nil
	}
	return out, walk(nodes)
}

// SaveDictionary upserts dictionary entries in one transaction.
func (s *Store) SaveDictionary(ctx context.Context, entries []DictEntry) (imported, updated int, err error) {
	if len(entries) == 0 {
		return 0, 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	// Counting imported vs updated with a SELECT per entry costs a full
	// query per row — 1.9M of them for the dictionary. Two statements do it
	// in two passes: INSERT OR IGNORE reports the new rows directly, and
	// the upsert after it only ever updates.
	ins, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO nvd_cpes
		(cpe23, vendor, product, version, deprecated, deprecated_by, titles_json, refs_json, last_modified)
		VALUES (?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, 0, err
	}
	defer ins.Close()
	upd, err := tx.PrepareContext(ctx, `UPDATE nvd_cpes SET
		  vendor=?, product=?, version=?, deprecated=?, deprecated_by=?,
		  titles_json=?, refs_json=?, last_modified=? WHERE cpe23 = ?`)
	if err != nil {
		return 0, 0, err
	}
	defer upd.Close()
	for _, e := range entries {
		titles, _ := json.Marshal(e.Titles)
		refs, _ := json.Marshal(e.Refs)
		dep := 0
		if e.Deprecated {
			dep = 1
		}
		res, err := ins.ExecContext(ctx, e.CPE23, e.Vendor, e.Product, e.Version, dep,
			nullable(e.DeprecatedBy), string(titles), string(refs), nullTime(e.LastModified))
		if err != nil {
			return 0, 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			imported++
			continue
		}
		if _, err := upd.ExecContext(ctx, e.Vendor, e.Product, e.Version, dep,
			nullable(e.DeprecatedBy), string(titles), string(refs), nullTime(e.LastModified), e.CPE23); err != nil {
			return 0, 0, err
		}
		updated++
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return imported, updated, nil
}

// CVEByID loads one CVE record.
func (s *Store) CVEByID(ctx context.Context, id string) (Record, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, published, modified, vuln_status, description,
		cvss_score, cvss_vector, cvss_severity, cvss_version, configs, references_json, weaknesses_json
		FROM nvd_cves WHERE id = ?`, strings.ToUpper(id))
	r, err := scanCVE(row)
	if err == sql.ErrNoRows {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	return r, true, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanCVE(row rowScanner) (Record, error) {
	var (
		r                    Record
		pub, mod             sql.NullString
		score                sql.NullFloat64
		vector, sev, ver     sql.NullString
		configs, refs, weaks string
	)
	if err := row.Scan(&r.ID, &pub, &mod, &r.Status, &r.Description, &score, &vector, &sev, &ver, &configs, &refs, &weaks); err != nil {
		return Record{}, err
	}
	if pub.Valid {
		if t, err := time.Parse(time.RFC3339, pub.String); err == nil {
			r.Published = t
		}
	}
	if mod.Valid {
		if t, err := time.Parse(time.RFC3339, mod.String); err == nil {
			r.Modified = t
		}
	}
	if score.Valid {
		r.Metrics = append(r.Metrics, CVSSMetric{
			Version: ver.String, Score: score.Float64, Vector: vector.String,
			Severity: sev.String, Source: "NVD", Type: "Primary",
		})
	}
	if err := json.Unmarshal([]byte(configs), &r.Configs); err != nil {
		return Record{}, fmt.Errorf("decode configs for %s: %w", r.ID, err)
	}
	_ = json.Unmarshal([]byte(refs), &r.References)
	var weakIDs []string
	_ = json.Unmarshal([]byte(weaks), &weakIDs)
	for _, w := range weakIDs {
		r.Weaknesses = append(r.Weaknesses, Weakness{CWE: w})
	}
	return r, nil
}

// CVEsForProduct returns the distinct CVE ids whose configurations mention
// the vendor+product (case-insensitive, from the indexed cpeMatch rows).
func (s *Store) CVEsForProduct(ctx context.Context, vendor, product string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT cve_id FROM nvd_cpe_matches
		WHERE vendor = ? AND product = ?`, strings.ToLower(vendor), strings.ToLower(product))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// DictionaryFor returns non-deprecated dictionary entries for vendor+product,
// plus any deprecated ones (with their replacement), so callers can resolve
// deprecations explicitly.
func (s *Store) DictionaryFor(ctx context.Context, vendor, product string) ([]DictEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cpe23, vendor, product, version, deprecated,
		COALESCE(deprecated_by,''), COALESCE(titles_json,'[]'), COALESCE(refs_json,'[]'), COALESCE(last_modified,'')
		FROM nvd_cpes WHERE vendor = ? AND product = ?`, strings.ToLower(vendor), strings.ToLower(product))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DictEntry
	for rows.Next() {
		var (
			e                DictEntry
			dep              int
			titles, refs, lm string
		)
		if err := rows.Scan(&e.CPE23, &e.Vendor, &e.Product, &e.Version, &dep, &e.DeprecatedBy, &titles, &refs, &lm); err != nil {
			return nil, err
		}
		e.Deprecated = dep != 0
		_ = json.Unmarshal([]byte(titles), &e.Titles)
		_ = json.Unmarshal([]byte(refs), &e.Refs)
		if t, err := time.Parse(time.RFC3339, lm); err == nil {
			e.LastModified = t
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ResolveDeprecated maps a deprecated CPE name to its current replacement,
// following chains, bounded to avoid cycles. A name not present in the
// dictionary is treated as current (nothing to resolve).
func (s *Store) ResolveDeprecated(ctx context.Context, cpe23 string) (string, bool, error) {
	current := cpe23
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		if seen[current] {
			return "", false, nil // cycle
		}
		seen[current] = true
		var by sql.NullString
		err := s.db.QueryRowContext(ctx, `SELECT deprecated_by FROM nvd_cpes WHERE cpe23 = ?`, current).Scan(&by)
		if err == sql.ErrNoRows {
			// Not in the dictionary (or the chain ended): current is the name
			// to use.
			return current, true, nil
		}
		if err != nil {
			return "", false, err
		}
		if !by.Valid {
			return current, true, nil
		}
		current = by.String
	}
	return "", false, nil
}

// DictionaryStats returns total and deprecated entry counts.
func (s *Store) DictionaryStats(ctx context.Context) (total, deprecated int, err error) {
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(deprecated),0) FROM nvd_cpes`).Scan(&total, &deprecated); err != nil {
		return 0, 0, err
	}
	return total, deprecated, nil
}

// CVECount returns how many CVE records are stored, optionally excluding
// rejected ones.
func (s *Store) CVECount(ctx context.Context, excludeRejected bool) (int, error) {
	q := `SELECT COUNT(*) FROM nvd_cves`
	if excludeRejected {
		q += ` WHERE vuln_status IS NULL OR UPPER(vuln_status) <> 'REJECTED'`
	}
	var n int
	err := s.db.QueryRowContext(ctx, q).Scan(&n)
	return n, err
}

// EvalCacheGet returns a cached (product, version, CVE) verdict.
func (s *Store) EvalCacheGet(ctx context.Context, vendor, product, version, cve string) (verdict string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT verdict FROM nvd_eval_cache
		WHERE vendor=? AND product=? AND version=? AND cve_id=?`,
		strings.ToLower(vendor), strings.ToLower(product), version, strings.ToUpper(cve)).Scan(&verdict)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return verdict, true, nil
}

// EvalCachePut stores a (product, version, CVE) verdict. The verdict is only
// valid while the underlying CVE data is unchanged, so callers invalidate by
// CVE id when a sync updates it.
func (s *Store) EvalCachePut(ctx context.Context, vendor, product, version, cve, verdict, details string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO nvd_eval_cache
		(vendor, product, version, cve_id, verdict, details, checked_at)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(vendor, product, version, cve_id) DO UPDATE SET
		  verdict=excluded.verdict, details=excluded.details, checked_at=excluded.checked_at`,
		strings.ToLower(vendor), strings.ToLower(product), version, strings.ToUpper(cve), verdict, nullable(details), now.UTC().Format(time.RFC3339))
	return err
}

// InvalidateEvalCache drops cached verdicts for a CVE (after an update) or
// the whole table (after a full sync).
func (s *Store) InvalidateEvalCache(ctx context.Context, cveID string) error {
	if cveID == "" {
		_, err := s.db.ExecContext(ctx, `DELETE FROM nvd_eval_cache`)
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM nvd_eval_cache WHERE cve_id = ?`, strings.ToUpper(cveID))
	return err
}

// VendorsForProduct returns the distinct vendors that publish a dictionary
// product with this exact product name. Used for conservative identity
// resolution: multiple vendors means the name is ambiguous.
func (s *Store) VendorsForProduct(ctx context.Context, product string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT vendor FROM nvd_cpes WHERE product = ?
		ORDER BY vendor LIMIT 10`, strings.ToLower(product))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SyncState describes one completed synchronization, for admin visibility.
type SyncState struct {
	Source     string
	StartedAt  time.Time
	FinishedAt time.Time
	Status     string
	Mode       string
	TotalSeen  int
	Imported   int
	Updated    int
	Failed     int
	Detail     string
}

// RecordSyncStart opens a sync history row and returns its id.
func (s *Store) RecordSyncStart(ctx context.Context, source, mode string, windowStart, windowEnd time.Time, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO nvd_sync_history
		(source, started_at, status, mode, window_start, window_end)
		VALUES (?,?, 'running', ?, ?, ?)`,
		source, now.UTC().Format(time.RFC3339), mode,
		nullTime(windowStart), nullTime(windowEnd))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// RecordSyncFinish closes a sync history row.
func (s *Store) RecordSyncFinish(ctx context.Context, seq int64, status string, totalSeen, imported, updated, failed int, detail string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE nvd_sync_history SET
		finished_at=?, status=?, total_seen=?, imported=?, updated=?, failed=?, detail=?
		WHERE seq=?`, now.UTC().Format(time.RFC3339), status, totalSeen, imported, updated, failed, nullable(detail), seq)
	return err
}

// LastSuccessfulSync returns the newest successful sync for a source.
func (s *Store) LastSuccessfulSync(ctx context.Context, source string) (SyncState, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT source, started_at, COALESCE(finished_at,''), status, mode,
		total_seen, imported, updated, failed, COALESCE(detail,'')
		FROM nvd_sync_history WHERE source = ? AND status = 'ok'
		ORDER BY seq DESC LIMIT 1`, source)
	return scanSync(row)
}

// SyncHistory returns the newest sync rows for a source (or all when empty).
func (s *Store) SyncHistory(ctx context.Context, source string, limit int) ([]SyncState, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	q := `SELECT source, started_at, COALESCE(finished_at,''), status, mode,
		total_seen, imported, updated, failed, COALESCE(detail,'')
		FROM nvd_sync_history`
	var args []any
	if source != "" {
		q += ` WHERE source = ?`
		args = append(args, source)
	}
	q += ` ORDER BY seq DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SyncState
	for rows.Next() {
		st, ok, err := scanSync(rows)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, st)
		}
	}
	return out, rows.Err()
}

func scanSync(row rowScanner) (SyncState, bool, error) {
	var st SyncState
	var started, finished string
	err := row.Scan(&st.Source, &started, &finished, &st.Status, &st.Mode,
		&st.TotalSeen, &st.Imported, &st.Updated, &st.Failed, &st.Detail)
	if err == sql.ErrNoRows {
		return SyncState{}, false, nil
	}
	if err != nil {
		return SyncState{}, false, err
	}
	if t, err := time.Parse(time.RFC3339, started); err == nil {
		st.StartedAt = t
	}
	if t, err := time.Parse(time.RFC3339, finished); err == nil {
		st.FinishedAt = t
	}
	return st, true, nil
}
