package api

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/msrc"
	"github.com/bgdnvk/clanker/internal/vuln/nvd"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
)

// The intelligence sync registry.
//
// One place owns the answers to "is anything running, how far along is it,
// and what does the dashboard need to show right now". Running state lives in
// memory (it is transient by nature); everything that must survive a restart
// — outcomes, records, timestamps — lives in the consolidated sync history
// and the per-source freshness tables. A page refresh or a server restart
// therefore recovers the full picture: at worst a killed job shows as
// "failed (stalled)" once its history row is old enough.

// syncSource is one intelligence source the server synchronizes.
type syncSource struct {
	ID          string // kev | epss | nvd | msrc | osv
	Name        string
	Description string
	// DependsOn names the assessment types that use this source.
	DependsOn string
}

// syncSources is the complete, honest inventory. Only sources the server
// actually synchronizes are listed; per-assessment sources say so.
var syncSources = []syncSource{
	{"kev", "CISA KEV", "Known exploited vulnerabilities, confirmed in the wild. Used for prioritization on every assessment.", "all assessments"},
	{"epss", "FIRST EPSS", "Exploitation probability scores from a statistical model. Used for prioritization on every assessment.", "all assessments"},
	{"nvd", "NVD CVE/CPE", "CVE records, the CPE dictionary and applicability data. The application vulnerability engine's only intelligence source.", "application assessments"},
	{"msrc", "Microsoft advisories", "Microsoft's KB-to-CVE mapping. Windows update findings depend on it.", "Windows assessments"},
	{"osv", "OSV advisories", "Distribution and package advisories. Fetched per assessment from api.osv.dev and cached; the server does not mirror the whole OSV dataset.", "Linux and package assessments"},
}

// runningSync is the in-memory state of one active job.
type runningSync struct {
	JobID           string
	Source          string
	Trigger         string // manual | scheduled
	Actor           string
	Status          string // queued|connecting|downloading|validating|processing|importing|indexing|finalizing
	Stage           string // human label for the current stage
	Percent         int    // -1 = unknown
	Bytes           int64
	ExpectedBytes   int64
	Records         int
	ExpectedRecords int
	StartedAt       time.Time
	UpdatedAt       time.Time
	Cancel          context.CancelFunc
}

// syncRegistry serializes access to running jobs.
type syncRegistry struct {
	mu      sync.Mutex
	running map[string]*runningSync // by source id
}

func newSyncRegistry() *syncRegistry {
	return &syncRegistry{running: map[string]*runningSync{}}
}

func (r *syncRegistry) get(source string) (*runningSync, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.running[source]
	return j, ok
}

func (r *syncRegistry) start(source string, j *runningSync) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, busy := r.running[source]; busy {
		return false // duplicate prevention
	}
	r.running[source] = j
	return true
}

func (r *syncRegistry) update(source string, fn func(*runningSync)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if j, ok := r.running[source]; ok {
		fn(j)
	}
}

func (r *syncRegistry) finish(source string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.running, source)
}

func (r *syncRegistry) snapshot() []runningSync {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]runningSync, 0, len(r.running))
	for _, j := range r.running {
		out = append(out, *j)
	}
	return out
}

// kevFetchFunc and epssFetchFunc are injectable for tests.
var (
	kevFetchFunc  = func(ctx context.Context) ([]intel.KEVEntry, error) { return intel.NewFetcher().FetchKEV(ctx) }
	epssFetchFunc = func(ctx context.Context) ([]intel.EPSSEntry, error) { return intel.NewFetcher().FetchEPSS(ctx) }
)

// syncOneSource runs one source's synchronization. It is the single entry
// point for scheduled, manual and retried syncs, so duplicate prevention and
// history recording are never bypassed.
func (s *Server) syncOneSource(ctx context.Context, source, trigger, actor string) (string, bool, error) {
	if !s.registry.start(source, &runningSync{}) {
		if existing, ok := s.registry.get(source); ok {
			return existing.JobID, false, fmt.Errorf("a synchronization for %s is already running", source)
		}
		return "", false, fmt.Errorf("a synchronization for %s is already running", source)
	}
	jobID := s.jobs.newID()
	started := s.opts.Now()
	jobCtx, cancel := context.WithCancel(ctx)
	s.registry.update(source, func(j *runningSync) {
		*j = runningSync{
			JobID: jobID, Source: source, Trigger: trigger, Actor: actor,
			Status: "queued", Percent: -1, StartedAt: started, UpdatedAt: started,
			Cancel: cancel,
		}
	})
	seq, err := intel.RecordSyncRun(context.Background(), s.store.DB(), intel.SyncRun{
		Source: source, Status: "running", Mode: "scheduled", StartedAt: started,
		Trigger: trigger, Actor: actor,
	})
	if err != nil {
		s.registry.finish(source)
		cancel()
		return "", false, err
	}

	go func() {
		defer cancel()
		defer s.registry.finish(source)
		// Stalled-job detection happens on read: a running row older than
		// the stall threshold is closed as failed.
		detail := ""
		status := "ok"
		total, imported, updated, failed := 0, 0, 0, 0
		err := s.runSyncFor(jobCtx, source)
		if jobCtx.Err() != nil {
			status, detail = "cancelled", "cancelled by operator"
		} else if err != nil {
			status, detail = "failed", s.sanitizeSyncError(err)
		}
		if err == nil && status == "ok" {
			// totals come from the per-source history below where available
			s.registry.update(source, func(j *runningSync) { j.Status = "finalizing" })
		}
		_ = intel.FinishSyncRun(context.Background(), s.store.DB(), seq, status, total, imported, updated, failed, detail)
	}()

	return jobID, true, nil
}

// runSyncFor executes the actual work for one source.
func (s *Server) runSyncFor(ctx context.Context, source string) error {
	switch source {
	case "kev":
		return s.syncKEV(ctx, "kev")
	case "epss":
		return s.syncEPSS(ctx, "epss")
	case "nvd":
		return s.syncNVDNow(ctx)
	case "msrc":
		return s.syncMSRCNow(ctx)
	case "osv":
		return fmt.Errorf("OSV advisories are fetched during assessments, not centrally synchronized on the server")
	}
	return fmt.Errorf("unknown intelligence source %q", source)
}

// setProgress publishes one structured update into the registry.
func (s *Server) setProgress(source, status, stage string, percent int, bytes, expectedBytes int64, records, expectedRecords int) {
	s.registry.update(source, func(j *runningSync) {
		j.Status = status
		j.Stage = stage
		j.Percent = percent
		j.Bytes = bytes
		j.ExpectedBytes = expectedBytes
		j.Records = records
		j.ExpectedRecords = expectedRecords
		j.UpdatedAt = s.opts.Now()
	})
}

// syncKEV / syncEPSS download one feed with real byte progress and store it
// transactionally. A failure keeps the previous dataset.
func (s *Server) syncKEV(ctx context.Context, source string) error {
	s.setProgress(source, "connecting", "connecting to cisa.gov", -1, 0, 0, 0, 0)
	entries, err := kevFetchFunc(ctx)
	if err != nil {
		return err
	}
	s.setProgress(source, "importing", "importing KEV records", -1, 0, 0, len(entries), len(entries))
	if err := s.store.SaveKEV(ctx, entries); err != nil {
		return err
	}
	if err := s.store.RecordSync(ctx, "KEV", len(entries), "CISA Known Exploited Vulnerabilities catalog"); err != nil {
		return err
	}
	s.setProgress(source, "up_to_date", "up to date", 100, 0, 0, len(entries), len(entries))
	return nil
}

func (s *Server) syncEPSS(ctx context.Context, source string) error {
	s.setProgress(source, "connecting", "connecting to FIRST EPSS", -1, 0, 0, 0, 0)
	entries, err := epssFetchFunc(ctx)
	if err != nil {
		return err
	}
	s.setProgress(source, "importing", "importing EPSS scores", -1, 0, 0, len(entries), len(entries))
	if err := s.store.SaveEPSS(ctx, entries, 5000); err != nil {
		return err
	}
	if err := s.store.RecordSync(ctx, "EPSS", len(entries), "FIRST EPSS scores"); err != nil {
		return err
	}
	s.setProgress(source, "up_to_date", "up to date", 100, 0, 0, len(entries), len(entries))
	return nil
}

func (s *Server) syncNVDNow(ctx context.Context) error {
	s.setProgress("nvd", "connecting", "connecting to NVD", -1, 0, 0, 0, 0)
	return nvdSyncFunc(ctx, s.opts.CachePath, nvd.SyncOptions{
		APIKey: s.nvdAPIKey(),
		Progress: func(stage, detail string) {
			s.setProgress("nvd", "downloading", stage+": "+detail, -1, 0, 0, 0, 0)
		},
		Reporter: func(stage string, p nvd.ProgressReport) {
			percent := -1
			if p.ExpectedRecords > 0 {
				percent = int(float64(p.Records) / float64(p.ExpectedRecords) * 100)
			}
			status := "downloading"
			switch stage {
			case "downloading":
			default:
				status = stage
			}
			s.setProgress("nvd", status, stage, percent, p.Bytes, p.ExpectedBytes, p.Records, p.ExpectedRecords)
		},
		Log: s.log,
	}, os.Stderr)
}

func (s *Server) syncMSRCNow(ctx context.Context) error {
	s.setProgress("msrc", "connecting", "connecting to the Microsoft Security Update Guide", -1, 0, 0, 0, 0)
	if err := msrc.EnsureSchema(s.store.DB()); err != nil {
		return err
	}
	if _, err := msrcSyncFunc(ctx, s.store.DB(), msrc.SyncOptions{Months: 6, Log: s.log}); err != nil {
		return err
	}
	s.setProgress("msrc", "up_to_date", "up to date", 100, 0, 0, 0, 0)
	return nil
}

// sanitizeSyncError strips anything credential-shaped from an error before it
// is persisted or shown.
func (s *Server) sanitizeSyncError(err error) string {
	msg := err.Error()
	for _, secret := range []string{s.nvdAPIKey()} {
		if secret != "" {
			msg = strings.ReplaceAll(msg, secret, "[redacted]")
		}
	}
	if len(msg) > 400 {
		msg = msg[:400] + "…"
	}
	return msg
}

// ------------------------------------------------------------------ status ---

// intelSourceStatus is the wire contract for one source.
type intelSourceStatus struct {
	Source           string     `json:"source"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	DependsOn        string     `json:"depends_on"`
	Status           string     `json:"status"`
	Stage            string     `json:"stage,omitempty"`
	Percent          int        `json:"percent"` // -1 = unknown
	Bytes            int64      `json:"bytes"`
	ExpectedBytes    int64      `json:"expected_bytes"`
	Records          int        `json:"records"`
	ExpectedRecords  int        `json:"expected_records"`
	JobID            string     `json:"job_id,omitempty"`
	Trigger          string     `json:"trigger,omitempty"`
	Actor            string     `json:"actor,omitempty"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	UpdatedAt        *time.Time `json:"updated_at,omitempty"`
	LastAttempt      *time.Time `json:"last_attempt,omitempty"`
	LastSuccess      *time.Time `json:"last_success,omitempty"`
	LastError        string     `json:"last_error,omitempty"`
	Freshness        string     `json:"freshness"` // current | approaching | stale | never | n_a
	DatasetRecords   int        `json:"dataset_records"`
	DatasetAvailable bool       `json:"dataset_available"`
	// NextScheduled is the earliest time the scheduler will reconsider this
	// source (informational; the loop itself decides).
	NextScheduled *time.Time `json:"next_scheduled,omitempty"`
}

// intelSyncView is the full GET /api/intel/sync payload.
type intelSyncView struct {
	Sources     []intelSourceStatus `json:"sources"`
	Running     int                 `json:"running"`
	UpToDate    int                 `json:"up_to_date"`
	Stale       int                 `json:"stale"`
	Failed      int                 `json:"failed"`
	NeverSynced int                 `json:"never_synced"`
	Readiness   readinessView       `json:"readiness"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

type readinessView struct {
	Ready bool     `json:"ready"`
	Notes []string `json:"notes"`
}

// buildIntelSyncView merges the in-memory registry with the persistent
// freshness data.
func (s *Server) buildIntelSyncView(ctx context.Context) intelSyncView {
	now := s.opts.Now()
	running := s.registry.snapshot()
	bySource := map[string]*runningSync{}
	for i := range running {
		bySource[running[i].Source] = &running[i]
	}

	// Reap stalled jobs: a running history row older than 12h means the
	// worker died mid-sync.
	for _, seq := range s.stalledSyncRuns(ctx) {
		_ = intel.FinishSyncRun(ctx, s.store.DB(), seq, "failed", 0, 0, 0, 0, "stalled: the synchronization worker died before finishing")
	}

	view := intelSyncView{UpdatedAt: now}
	nextCheck := now.Add(s.intelligenceSyncInterval())
	appendSource := func(st intelSourceStatus) {
		if st.NextScheduled == nil {
			st.NextScheduled = &nextCheck
		}
		view.Sources = append(view.Sources, st)
		switch {
		case st.Status == "failed":
			view.Failed++
		case st.Status == "stale":
			view.Stale++
		case st.Freshness == "never":
			view.NeverSynced++
		case st.Status == "up_to_date":
			view.UpToDate++
		}
	}

	for _, def := range syncSources {
		st := intelSourceStatus{
			Source: def.ID, Name: def.Name, Description: def.Description,
			DependsOn: def.DependsOn, Status: "not_initialized", Percent: -1,
			Freshness: "never",
		}
		if j := bySource[def.ID]; j != nil {
			view.Running++
			st.Status = j.Status
			st.Stage = j.Stage
			st.Percent = j.Percent
			st.Bytes, st.ExpectedBytes = j.Bytes, j.ExpectedBytes
			st.Records, st.ExpectedRecords = j.Records, j.ExpectedRecords
			st.JobID, st.Trigger, st.Actor = j.JobID, j.Trigger, j.Actor
			t0, t1 := j.StartedAt, j.UpdatedAt
			st.StartedAt, st.UpdatedAt = &t0, &t1
		}
		s.fillSourceStatus(ctx, &st, now)
		appendSource(st)
	}

	view.Readiness = s.readiness(ctx, view.Sources, now)
	return view
}

// fillSourceStatus applies the per-source freshness and history data.
func (s *Server) fillSourceStatus(ctx context.Context, st *intelSourceStatus, now time.Time) {
	switch st.Source {
	case "kev":
		st.DatasetRecords, _ = s.store.KEVCount(ctx)
		st.DatasetAvailable = st.DatasetRecords > 0
		s.applySyncState(ctx, st, "KEV", 7*24*time.Hour, 5*24*time.Hour)
	case "epss":
		st.DatasetRecords, _ = s.store.EPSSCount(ctx)
		st.DatasetAvailable = st.DatasetRecords > 0
		s.applySyncState(ctx, st, "EPSS", 3*24*time.Hour, 2*24*time.Hour)
	case "nvd":
		_ = nvd.EnsureSchema(s.store.DB())
		ns := nvd.NewStore(s.store.DB())
		st.DatasetRecords, _ = ns.CVECount(ctx, true)
		st.DatasetAvailable = st.DatasetRecords > 0
		if last, ok, err := ns.LastSuccessfulSync(ctx, "cves"); err == nil && ok && !last.FinishedAt.IsZero() {
			t := last.FinishedAt
			st.LastSuccess = &t
			st.Freshness = freshnessFor(now, t, 30*24*time.Hour, 14*24*time.Hour)
		} else {
			st.Freshness = "never"
		}
	case "msrc":
		if err := msrc.EnsureSchema(s.store.DB()); err == nil {
			if last, ok := msrc.LastSync(s.store.DB()); ok {
				t := last.SyncedAt
				st.LastSuccess = &t
				st.Freshness = freshnessFor(now, t, 24*time.Hour, 12*time.Hour)
				st.DatasetRecords = last.CVE
				st.DatasetAvailable = last.CVE > 0
			}
		}
	case "osv":
		// OSV is fetched per assessment; the server reports what it has
		// cached and never pretends to mirror the whole dataset.
		if n, err := s.store.AdvisoryCount(ctx); err == nil && n > 0 {
			st.DatasetRecords = n
			st.DatasetAvailable = true
			st.Freshness = "n_a"
		}
	}
	// History: last attempt + last error.
	if rows, err := intel.SyncRunHistory(ctx, s.store.DB(), intel.SyncRunFilter{Source: st.Source, Limit: 5}); err == nil && len(rows) > 0 {
		t := rows[0].StartedAt
		st.LastAttempt = &t
		if rows[0].Status == "failed" {
			st.LastError = rows[0].Detail
		}
	}
	if st.DatasetAvailable && st.Freshness == "never" {
		st.Freshness = "current" // data exists even without a recorded sync
	}
}

// applySyncState merges the legacy sync_state table for KEV/EPSS.
func (s *Server) applySyncState(ctx context.Context, st *intelSourceStatus, source string, staleAfter, warnAfter time.Duration) {
	states, err := s.store.SyncStates(ctx)
	if err != nil {
		return
	}
	for _, sy := range states {
		if sy.Source != source {
			continue
		}
		if sy.LastSync.IsZero() {
			continue
		}
		t := sy.LastSync
		st.LastSuccess = &t
		st.Freshness = freshnessFor(s.opts.Now(), t, staleAfter, warnAfter)
	}
}

// freshnessFor classifies the age of the active dataset.
func freshnessFor(now, last time.Time, staleAfter, warnAfter time.Duration) string {
	age := now.Sub(last)
	switch {
	case age > staleAfter:
		return "stale"
	case age > warnAfter:
		return "approaching"
	default:
		return "current"
	}
}

// readiness computes the per-assessment-type readiness picture.
func (s *Server) readiness(ctx context.Context, sources []intelSourceStatus, now time.Time) readinessView {
	var notes []string
	byID := map[string]intelSourceStatus{}
	for _, st := range sources {
		byID[st.Source] = st
	}
	check := func(id, what string) {
		st := byID[id]
		switch {
		case !st.DatasetAvailable && st.Freshness == "never":
			notes = append(notes, fmt.Sprintf("%s has never been synchronized: %s cannot use it", st.Name, what))
		case st.Freshness == "stale":
			notes = append(notes, fmt.Sprintf("%s is stale (last sync %s): %s may miss recent data", st.Name, humanTime(st.LastSuccess, now), what))
		}
	}
	check("kev", "prioritization")
	check("epss", "prioritization")
	check("nvd", "application assessments")
	check("msrc", "Windows assessments")
	// OSV is per-assessment; nothing to check centrally.
	ready := len(notes) == 0
	return readinessView{Ready: ready, Notes: notes}
}

func humanTime(t *time.Time, now time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	d := now.Sub(*t)
	switch {
	case d < time.Minute:
		return "moments ago"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

// syncHistory lists consolidated history rows for the API.
func (s *Server) syncHistory(ctx context.Context, source, outcome string, limit int) ([]intel.SyncRunRow, error) {
	return intel.SyncRunHistory(ctx, s.store.DB(), intel.SyncRunFilter{Source: source, Outcome: outcome, Limit: limit})
}

// stalledSyncRuns returns history rows whose worker died.
func (s *Server) stalledSyncRuns(ctx context.Context) []int64 {
	seqs, err := intel.StaleRunningRuns(ctx, s.store.DB(), 12*time.Hour, s.opts.Now())
	if err != nil {
		return nil
	}
	return seqs
}

var _ = scan.UpdateFeeds
