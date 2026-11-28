package intel

import (
	"context"
	"database/sql"
	"time"
)

// SyncRun is one synchronization attempt for any intelligence source. It is
// the consolidated history row every source writes: KEV, EPSS, NVD, MSRC and
// OSV all land in the same table, so the dashboard can show one history with
// one filter, and a failed run is never mistaken for "never attempted".
type SyncRun struct {
	Source     string // kev | epss | nvd_cves | nvd_cpes | msrc | osv
	Status     string // running | ok | failed | cancelled
	Mode       string // full | incremental
	StartedAt  time.Time
	FinishedAt time.Time
	TotalSeen  int
	Imported   int
	Updated    int
	Failed     int
	Detail     string
	Trigger    string // manual | scheduled | scan
	Actor      string // operator name or "system"
}

// EnsureSyncRunSchema creates the consolidated sync history table. The DDL is
// shared with the nvd package (the table originated there); creating it here
// too is deliberately idempotent, and the added columns tolerate a table that
// already exists without them.
func EnsureSyncRunSchema(db *sql.DB) error {
	stmts := []string{
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
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	// Additive columns for the consolidated history (who/what triggered).
	// SQLite has no ADD COLUMN IF NOT EXISTS, so check first.
	for col, ddl := range map[string]string{
		"trigger_type": `ALTER TABLE nvd_sync_history ADD COLUMN trigger_type TEXT DEFAULT ''`,
		"actor":        `ALTER TABLE nvd_sync_history ADD COLUMN actor TEXT DEFAULT ''`,
	} {
		has, err := tableHasColumn(db, "nvd_sync_history", col)
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec(ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

func tableHasColumn(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// RecordSyncRun appends one history row and returns its id.
func RecordSyncRun(ctx context.Context, db *sql.DB, r SyncRun) (int64, error) {
	if err := EnsureSyncRunSchema(db); err != nil {
		return 0, err
	}
	finished := any(nil)
	if !r.FinishedAt.IsZero() {
		finished = r.FinishedAt.UTC().Format(time.RFC3339)
	}
	res, err := db.ExecContext(ctx, `INSERT INTO nvd_sync_history
		(source, started_at, finished_at, status, mode, total_seen, imported, updated, failed, detail, trigger_type, actor)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.Source, r.StartedAt.UTC().Format(time.RFC3339), finished, r.Status, r.Mode,
		r.TotalSeen, r.Imported, r.Updated, r.Failed, nullableString(r.Detail), r.Trigger, r.Actor)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishSyncRun closes a previously recorded run.
func FinishSyncRun(ctx context.Context, db *sql.DB, seq int64, status string, totalSeen, imported, updated, failed int, detail string) error {
	_, err := db.ExecContext(ctx, `UPDATE nvd_sync_history SET
		finished_at=?, status=?, total_seen=?, imported=?, updated=?, failed=?, detail=?
		WHERE seq=?`, time.Now().UTC().Format(time.RFC3339), status, totalSeen, imported, updated, failed, nullableString(detail), seq)
	return err
}

// SyncRunHistory lists consolidated sync history, newest first, optionally
// filtered by source and outcome.
type SyncRunFilter struct {
	Source  string // empty = all
	Outcome string // ok | failed | running | cancelled | empty = all
	Limit   int
}

type SyncRunRow struct {
	Seq        int64
	Source     string
	Status     string
	Mode       string
	StartedAt  time.Time
	FinishedAt time.Time
	TotalSeen  int
	Imported   int
	Updated    int
	Failed     int
	Detail     string
	Trigger    string
	Actor      string
}

// SyncRunHistory reads the consolidated history.
func SyncRunHistory(ctx context.Context, db *sql.DB, f SyncRunFilter) ([]SyncRunRow, error) {
	if err := EnsureSyncRunSchema(db); err != nil {
		return nil, err
	}
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	q := `SELECT seq, source, status, mode, started_at, COALESCE(finished_at,''),
		total_seen, imported, updated, failed, COALESCE(detail,''), COALESCE(trigger_type,''), COALESCE(actor,'')
		FROM nvd_sync_history WHERE 1=1`
	var args []any
	if f.Source != "" {
		q += ` AND source = ?`
		args = append(args, f.Source)
	}
	if f.Outcome != "" {
		q += ` AND status = ?`
		args = append(args, f.Outcome)
	}
	q += ` ORDER BY seq DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SyncRunRow
	for rows.Next() {
		var r SyncRunRow
		var started, finished string
		if err := rows.Scan(&r.Seq, &r.Source, &r.Status, &r.Mode, &started, &finished,
			&r.TotalSeen, &r.Imported, &r.Updated, &r.Failed, &r.Detail, &r.Trigger, &r.Actor); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, started); err == nil {
			r.StartedAt = t
		}
		if t, err := time.Parse(time.RFC3339, finished); err == nil {
			r.FinishedAt = t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// StaleRunningRuns returns running history rows older than maxAge — jobs
// whose worker died. Callers mark them failed so a restart never wedges.
// now is injectable so tests with a frozen clock reap consistently.
func StaleRunningRuns(ctx context.Context, db *sql.DB, maxAge time.Duration, now time.Time) ([]int64, error) {
	if err := EnsureSyncRunSchema(db); err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cutoff := now.Add(-maxAge).Format(time.RFC3339)
	rows, err := db.QueryContext(ctx, `SELECT seq FROM nvd_sync_history WHERE status = 'running' AND started_at < ?`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			return nil, err
		}
		out = append(out, seq)
	}
	return out, rows.Err()
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
