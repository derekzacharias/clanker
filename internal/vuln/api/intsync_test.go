package api

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/nvd"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
)

// TestScheduledIntelligenceSyncRunsWhenDue drives the due-decision logic with
// injected sync functions and no network.
func TestScheduledIntelligenceSyncRunsWhenDue(t *testing.T) {
	var feedsCalls, nvdCalls atomic.Int32
	oldFeeds, oldNVD := feedSyncFunc, nvdSyncFunc
	feedSyncFunc = func(ctx context.Context, path string, withOSV bool, w io.Writer) ([]intel.SyncInfo, error) {
		feedsCalls.Add(1)
		return nil, nil
	}
	nvdSyncFunc = func(ctx context.Context, path string, opts nvd.SyncOptions, w io.Writer) error {
		nvdCalls.Add(1)
		return nil
	}
	defer func() { feedSyncFunc, nvdSyncFunc = oldFeeds, oldNVD }()

	srv, _ := newTestServer(t)
	store := srv.store
	// Backdate KEV/EPSS so both are due (relative to the server's clock,
	// which tests freeze).
	old := srv.opts.Now().Add(-48 * time.Hour)
	if err := store.RecordSyncAt(context.Background(), "KEV", 1, "backdated for test", old); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordSyncAt(context.Background(), "EPSS", 1, "backdated for test", old); err != nil {
		t.Fatal(err)
	}

	srv.runIntelligenceSync(context.Background())

	if feedsCalls.Load() != 1 {
		t.Fatalf("KEV/EPSS sync must run when stale, calls=%d", feedsCalls.Load())
	}
	if nvdCalls.Load() != 1 {
		t.Fatalf("the first NVD population must run when nothing was ever synced, calls=%d", nvdCalls.Load())
	}

	// Now everything is fresh: the next run must be a no-op. (The injected
	// sync functions record nothing, so mark fresh state the way the real
	// implementations would.)
	now := srv.opts.Now()
	_ = store.RecordSyncAt(context.Background(), "KEV", 1, "fresh", now)
	_ = store.RecordSyncAt(context.Background(), "EPSS", 1, "fresh", now)
	_ = nvd.EnsureSchema(store.DB())
	seq, err := nvd.NewStore(store.DB()).RecordSyncStart(context.Background(), "cves", "full", time.Time{}, time.Time{}, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = nvd.NewStore(store.DB()).RecordSyncFinish(context.Background(), seq, "ok", 1, 1, 0, 0, "", now)

	srv.runIntelligenceSync(context.Background())
	if feedsCalls.Load() != 1 || nvdCalls.Load() != 1 {
		t.Fatalf("a fresh dataset must not re-sync: feeds=%d nvd=%d", feedsCalls.Load(), nvdCalls.Load())
	}
}

// TestFeedUpdateJobIncludesNVD drives the dashboard "sync now" path with the
// injected functions.
func TestFeedUpdateJobIncludesNVD(t *testing.T) {
	var feedsCalls, nvdCalls atomic.Int32
	oldFeeds, oldNVD := feedSyncFunc, nvdSyncFunc
	feedSyncFunc = func(ctx context.Context, path string, withOSV bool, w io.Writer) ([]intel.SyncInfo, error) {
		feedsCalls.Add(1)
		return nil, nil
	}
	nvdSyncFunc = func(ctx context.Context, path string, opts nvd.SyncOptions, w io.Writer) error {
		nvdCalls.Add(1)
		if opts.APIKey != "test-key" {
			t.Errorf("scheduled sync must pass the configured NVD key, got %q", opts.APIKey)
		}
		return nil
	}
	defer func() { feedSyncFunc, nvdSyncFunc = oldFeeds, oldNVD }()

	srv, cachePath := newTestServer(t)
	// Configure a key through the settings table, the way an operator would.
	store, err := intel.OpenStore(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(context.Background(), "nvd_api_key", "test-key"); err != nil {
		t.Fatal(err)
	}
	store.Close()

	rec := doJSON(t, srv.Handler(), "POST", "/api/feeds/update", nil, &struct {
		ID string `json:"id"`
	}{})
	if rec.Code != 202 {
		t.Fatalf("feed update: %d %s", rec.Code, rec.Body.String())
	}
	// Wait for the job to finish.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if feedsCalls.Load() >= 1 && nvdCalls.Load() >= 1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if feedsCalls.Load() != 1 || nvdCalls.Load() != 1 {
		t.Fatalf("sync now must run both sources: feeds=%d nvd=%d", feedsCalls.Load(), nvdCalls.Load())
	}
}

// TestIntelligenceSyncDisabledInTests guards the loop switch.
func TestIntelligenceSyncLoopRespectsDisableFlag(t *testing.T) {
	// newTestServer sets DisableBackgroundJobs; the loop must not launch.
	srv, _ := newTestServer(t)
	started := make(chan struct{}, 1)
	go func() {
		srv.startIntelligenceSync()
		started <- struct{}{}
	}()
	<-started
	// No assertion beyond "it returned immediately": the guard is the
	// same one maintenance uses, and a background sync would call the
	// real network functions.
}

var _ = scan.UpdateFeeds
