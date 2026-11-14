package intel

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// Job status values surfaced by the HTTP API and the UI.
const (
	JobQueued   = "queued"
	JobRunning  = "running"
	JobDone     = "completed"
	JobFailed   = "failed"
	JobCanceled = "canceled"
)

// Job is one scan request and its progress.
type Job struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"` // local | network | sbom
	Status      string     `json:"status"`
	Host        string     `json:"host,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	Stage       string     `json:"stage,omitempty"`
	StageDetail string     `json:"stage_detail,omitempty"`
	Percent     int        `json:"percent"`
	Error       string     `json:"error,omitempty"`
	ReportID    string     `json:"report_id,omitempty"`
	Request     string     `json:"request,omitempty"`
}

// CreateJob records a new scan job.
func (s *Store) CreateJob(ctx context.Context, j Job) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO scan_jobs
		(id, kind, status, host, started_at, finished_at, stage, stage_detail, percent, error, report_id, request)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		j.ID, j.Kind, j.Status, j.Host, ts(j.StartedAt), nullTimePtr(j.FinishedAt),
		j.Stage, j.StageDetail, j.Percent, j.Error, j.ReportID, j.Request)
	return err
}

// UpdateJobProgress writes a progress tick for a job that is still running.
// A cancelled or finished job must not receive further progress.
func (s *Store) UpdateJobProgress(ctx context.Context, id, stage, detail string, percent int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE scan_jobs
		SET stage = ?, stage_detail = ?, percent = ? WHERE id = ? AND status = ?`,
		stage, detail, percent, id, JobRunning)
	return err
}

// FinishJob marks a running job terminal.
//
// The update is conditional on the job still being 'running': a cancelled job
// must not be flipped back to 'completed' by the goroutine that was doing the
// work, which is exactly what happened before cancellation propagated.
func (s *Store) FinishJob(ctx context.Context, id, status, reportID, errMsg string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE scan_jobs
		SET status = ?, finished_at = ?, report_id = ?, error = ?, percent = CASE WHEN ? = 'completed' THEN 100 ELSE percent END
		WHERE id = ? AND status = ?`,
		status, ts(time.Now().UTC()), reportID, errMsg, status, id, JobRunning)
	return err
}

// GetJob loads one job.
func (s *Store) GetJob(ctx context.Context, id string) (*Job, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, kind, status, COALESCE(host,''), started_at,
		finished_at, COALESCE(stage,''), COALESCE(stage_detail,''), percent, COALESCE(error,''),
		COALESCE(report_id,''), COALESCE(request,'') FROM scan_jobs WHERE id = ?`, id)
	j, err := scanJob(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &j, nil
}

// ListJobs returns recent jobs, newest first.
func (s *Store) ListJobs(ctx context.Context, limit int) ([]Job, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, status, COALESCE(host,''), started_at,
		finished_at, COALESCE(stage,''), COALESCE(stage_detail,''), percent, COALESCE(error,''),
		COALESCE(report_id,''), COALESCE(request,'') FROM scan_jobs ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanJob(r rowScanner) (Job, error) {
	var (
		j        Job
		started  string
		finished sql.NullString
	)
	if err := r.Scan(&j.ID, &j.Kind, &j.Status, &j.Host, &started, &finished,
		&j.Stage, &j.StageDetail, &j.Percent, &j.Error, &j.ReportID, &j.Request); err != nil {
		return j, err
	}
	j.StartedAt, _ = time.Parse(time.RFC3339, started)
	if finished.Valid {
		t, err := time.Parse(time.RFC3339, finished.String)
		if err == nil {
			j.FinishedAt = &t
		}
	}
	return j, nil
}

func ts(t time.Time) string {
	if t.IsZero() {
		t = time.Now().UTC()
	}
	return t.UTC().Format(time.RFC3339)
}

func nullTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return ts(*t)
}

// RunSummary is one row of scan history.
type RunSummary struct {
	ID          string    `json:"id"`
	Host        string    `json:"host"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	Findings    int       `json:"findings"`
	Actionable  int       `json:"actionable"`
	KEVCount    int       `json:"kev_count"`
	ToolVersion string    `json:"tool_version,omitempty"`
	Mode        string    `json:"mode,omitempty"`
	Incomplete  bool      `json:"incomplete"`
	ReportID    string    `json:"report_id"`
	// FindingIDs are the stable fingerprints recorded for the run (not exposed
	// over the API; used to compute first-seen dates).
	FindingIDs []string `json:"-"`
}

// ListRuns returns stored assessments, newest first.
func (s *Store) ListRuns(ctx context.Context, limit int) ([]RunSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, host, started_at, finished_at, record FROM runs
		ORDER BY finished_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunSummary
	for rows.Next() {
		var (
			id, host, started, finished, record string
		)
		if err := rows.Scan(&id, &host, &started, &finished, &record); err != nil {
			return nil, err
		}
		var rec model.RunRecord
		if err := json.Unmarshal([]byte(record), &rec); err != nil {
			continue
		}
		rs := RunSummary{
			ID: id, Host: host, Findings: rec.FindingCount, Actionable: rec.Actionable,
			KEVCount: rec.KEVCount, ReportID: id, FindingIDs: rec.FindingIDs,
		}
		rs.StartedAt, _ = time.Parse(time.RFC3339, started)
		rs.FinishedAt, _ = time.Parse(time.RFC3339, finished)
		out = append(out, rs)
	}
	return out, rows.Err()
}

// LatestRunsPerHost returns the newest stored report per host.
func (s *Store) LatestRunsPerHost(ctx context.Context) ([]RunSummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.id, r.host, r.started_at, r.finished_at, r.record
		FROM runs r
		JOIN (SELECT host, MAX(finished_at) AS mx FROM runs GROUP BY host) latest
		  ON r.host = latest.host AND r.finished_at = latest.mx
		ORDER BY r.host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunSummary
	for rows.Next() {
		var id, host, started, finished, record string
		if err := rows.Scan(&id, &host, &started, &finished, &record); err != nil {
			return nil, err
		}
		var rec model.RunRecord
		if err := json.Unmarshal([]byte(record), &rec); err != nil {
			continue
		}
		rs := RunSummary{ID: id, Host: host, Findings: rec.FindingCount, Actionable: rec.Actionable,
			KEVCount: rec.KEVCount, ReportID: id, FindingIDs: rec.FindingIDs}
		rs.StartedAt, _ = time.Parse(time.RFC3339, started)
		rs.FinishedAt, _ = time.Parse(time.RFC3339, finished)
		out = append(out, rs)
	}
	return out, rows.Err()
}

// ReportByID returns the stored report JSON for a run.
func (s *Store) ReportByID(ctx context.Context, id string) ([]byte, error) {
	row := s.db.QueryRowContext(ctx, `SELECT report FROM runs WHERE id = ?`, id)
	var payload string
	if err := row.Scan(&payload); err != nil {
		return nil, err
	}
	return []byte(payload), nil
}

// SetSetting stores a UI preference.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings (k, v) VALUES (?,?)
		ON CONFLICT(k) DO UPDATE SET v = excluded.v`, key, value)
	return err
}

// Setting reads one UI preference.
func (s *Store) Setting(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT v FROM settings WHERE k = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// Settings returns all stored preferences.
func (s *Store) Settings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT k, v FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}
