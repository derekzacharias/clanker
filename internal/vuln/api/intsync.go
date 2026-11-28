package api

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/msrc"
	"github.com/bgdnvk/clanker/internal/vuln/nvd"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
)

// Intelligence synchronization runs by itself.
//
// A dashboard that only knows what it was told yesterday misprioritises today.
// The server therefore refreshes every intelligence source on a schedule, with
// the same rules as a manual run: a failure leaves the last known dataset in
// place and is recorded, and each source has its own freshness clock so one
// outage cannot stall the others. The sources are:
//
//	KEV    daily — the catalog is small and changes often
//	EPSS   daily — scores shift as exploitation data accumulates
//	NVD    daily incremental — the dataset is large, so only the changed
//	       window is fetched; the first run populates the full history
//
// The sync runs in its own goroutine and never blocks scans or maintenance.
// A mutex serialises it against the dashboard's "sync now" job so two syncs
// can never double-spend the NVD rate limit.

// feedSyncFunc, nvdSyncFunc and msrcSyncFunc are injectable for tests.
var (
	feedSyncFunc = scan.UpdateFeeds
	nvdSyncFunc  = scan.SyncNVD
	msrcSyncFunc = msrc.Sync
)

// startIntelligenceSync launches the scheduled sync loop.
func (s *Server) startIntelligenceSync() {
	if s.opts.DisableBackgroundJobs {
		return
	}
	interval := s.intelligenceSyncInterval()
	go func() {
		s.runIntelligenceSync(context.Background())
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			s.runIntelligenceSync(context.Background())
		}
	}()
	s.log.Info("intelligence sync loop started", "interval", interval.String())
}

// intelligenceSyncInterval is how often the loop wakes. Sources have their
// own cadence inside; this is just the heartbeat.
func (s *Server) intelligenceSyncInterval() time.Duration {
	raw := s.mustSettings()["intel.sync.hours"]
	if raw != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n >= 1 && n <= 168 {
			return time.Duration(n) * time.Hour
		}
	}
	return 6 * time.Hour
}

// runIntelligenceSync refreshes every due source. It is idempotent and safe
// to call concurrently (the mutex serialises against manual syncs).
func (s *Server) runIntelligenceSync(ctx context.Context) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	now := s.opts.Now()
	due := func(source string, maxAge time.Duration) bool {
		states, err := s.store.SyncStates(ctx)
		if err != nil {
			return true // unknown state: try, failures are recorded
		}
		for _, st := range states {
			if st.Source == source {
				return st.LastSync.IsZero() || now.Sub(st.LastSync) > maxAge
			}
		}
		return true // never synced
	}

	// Every source routes through the registry so the dashboard sees the
	// same state the scheduler does, and duplicate jobs cannot exist.
	if due("KEV", 24*time.Hour) {
		s.runScheduledSync(ctx, "kev")
	}
	if due("EPSS", 24*time.Hour) {
		s.runScheduledSync(ctx, "epss")
	}
	if s.nvdDue(ctx, now) {
		s.runScheduledSync(ctx, "nvd")
	}
	if s.msrcDue(ctx, now) {
		s.runScheduledSync(ctx, "msrc")
	}
}

// runScheduledSync starts one source's sync unless one is already running.
func (s *Server) runScheduledSync(ctx context.Context, source string) {
	if _, busy := s.registry.get(source); busy {
		return
	}
	s.log.Info("scheduled intelligence sync starting", "source", source)
	_, _, err := s.syncOneSource(ctx, source, "scheduled", "system")
	if err != nil {
		s.log.Warn("scheduled sync did not start", "source", source, "err", err)
	}
}

// msrcDue reports whether Microsoft advisories need their scheduled refresh.
// Scans also import them on demand when stale, so the threshold mirrors that.
func (s *Server) msrcDue(ctx context.Context, now time.Time) bool {
	if err := msrc.EnsureSchema(s.store.DB()); err != nil {
		return false
	}
	last, ok := msrc.LastSync(s.store.DB())
	if !ok {
		return true // never imported
	}
	return now.Sub(last.SyncedAt) > 24*time.Hour
}

// nvdDue reports whether the NVD dataset needs its scheduled refresh. The
// first population runs when no successful sync exists yet.
func (s *Server) nvdDue(ctx context.Context, now time.Time) bool {
	if err := nvd.EnsureSchema(s.store.DB()); err != nil {
		return false // cannot even inspect; a manual run will surface the error
	}
	st, ok, err := nvd.NewStore(s.store.DB()).LastSuccessfulSync(ctx, "cves")
	if err != nil || !ok {
		return true // never populated: the first full sync is due now
	}
	return now.Sub(st.FinishedAt) > 24*time.Hour
}

// nvdAPIKey resolves the NVD credential for scheduled syncs: the settings
// table first (set by the operator through the API), then the environment.
// The key is never logged.
func (s *Server) nvdAPIKey() string {
	if k := s.mustSettings()["nvd_api_key"]; k != "" {
		return k
	}
	return nvd.APIKeyFromEnv(os.Getenv)
}
