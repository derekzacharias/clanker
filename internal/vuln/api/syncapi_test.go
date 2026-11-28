package api

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/msrc"
	"github.com/bgdnvk/clanker/internal/vuln/nvd"
)

// fakeSyncFuncs replaces every network-bound sync function for tests.
type fakeSyncFuncs struct {
	kevCalls, epssCalls, nvdCalls, msrcCalls atomic.Int32
}

func (f *fakeSyncFuncs) install(t *testing.T) {
	t.Helper()
	oldKev, oldEpss, oldNVD, oldMSRC := kevFetchFunc, epssFetchFunc, nvdSyncFunc, msrcSyncFunc
	kevFetchFunc = func(ctx context.Context) ([]intel.KEVEntry, error) {
		f.kevCalls.Add(1)
		return []intel.KEVEntry{{CVEID: "CVE-2026-0001", DateAdded: "2026-11-01"}}, nil
	}
	epssFetchFunc = func(ctx context.Context) ([]intel.EPSSEntry, error) {
		f.epssCalls.Add(1)
		return []intel.EPSSEntry{{CVE: "CVE-2026-0001", Score: 0.5, Percentile: 0.9}}, nil
	}
	nvdSyncFunc = func(ctx context.Context, path string, opts nvd.SyncOptions, w io.Writer) error {
		f.nvdCalls.Add(1)
		if opts.Reporter != nil {
			opts.Reporter("downloading", nvd.ProgressReport{Bytes: 2048, Records: 1, ExpectedRecords: 1})
		}
		// The real sync records its success in the store; the fake must do
		// the same or the status view cannot see the dataset.
		store, err := intel.OpenStore(path)
		if err != nil {
			return err
		}
		defer store.Close()
		if err := nvd.EnsureSchema(store.DB()); err != nil {
			return err
		}
		now := time.Now().UTC()
		if _, _, err := nvd.NewStore(store.DB()).SaveCVEs(ctx, []nvd.Record{{
			ID: "CVE-2026-0001", Status: "Analyzed", Description: "fixture",
		}}, now); err != nil {
			return err
		}
		seq, err := nvd.NewStore(store.DB()).RecordSyncStart(ctx, "cves", "full", time.Time{}, time.Time{}, now)
		if err != nil {
			return err
		}
		return nvd.NewStore(store.DB()).RecordSyncFinish(ctx, seq, "ok", 1, 1, 0, 0, "", now)
	}
	msrcSyncFunc = func(ctx context.Context, db *sql.DB, opts msrc.SyncOptions) (msrc.SyncState, error) {
		f.msrcCalls.Add(1)
		return msrc.SyncState{}, nil
	}
	t.Cleanup(func() {
		kevFetchFunc, epssFetchFunc, nvdSyncFunc, msrcSyncFunc = oldKev, oldEpss, oldNVD, oldMSRC
	})
}

func TestScheduledIntelligenceSyncRunsWhenDue(t *testing.T) {
	fakes := &fakeSyncFuncs{}
	fakes.install(t)
	srv, _ := newTestServer(t)

	// Backdate KEV and EPSS so both are due.
	old := srv.opts.Now().Add(-48 * time.Hour)
	for _, src := range []string{"KEV", "EPSS"} {
		if err := srv.store.RecordSyncAt(context.Background(), src, 1, "backdated", old); err != nil {
			t.Fatal(err)
		}
	}

	srv.runIntelligenceSync(context.Background())
	waitFor(t, func() bool { return fakes.kevCalls.Load() >= 1 && fakes.epssCalls.Load() >= 1 })
	waitFor(t, func() bool { return fakes.nvdCalls.Load() >= 1 })
	waitFor(t, func() bool {
		_, busy := srv.registry.get("nvd")
		return !busy
	})
	if fakes.nvdCalls.Load() != 1 {
		t.Fatalf("first NVD population must run when never synced, calls=%d", fakes.nvdCalls.Load())
	}

	// The status view must reflect the outcomes, not just the calls.
	view := srv.buildIntelSyncView(context.Background())
	byID := map[string]intelSourceStatus{}
	for _, st := range view.Sources {
		byID[st.Source] = st
	}
	if byID["kev"].DatasetRecords != 1 || byID["kev"].LastSuccess == nil {
		t.Fatalf("kev status: %+v", byID["kev"])
	}
	if byID["epss"].DatasetRecords != 1 || byID["epss"].LastSuccess == nil {
		t.Fatalf("epss status: %+v", byID["epss"])
	}
	if !byID["nvd"].DatasetAvailable {
		t.Fatalf("nvd dataset must be marked available after a sync: %+v", byID["nvd"])
	}
}

func TestSyncRegistryPreventsDuplicates(t *testing.T) {
	fakes := &fakeSyncFuncs{}
	fakes.install(t)
	srv, _ := newTestServer(t)

	_, started, err := srv.syncOneSource(context.Background(), "kev", "manual", "tester")
	if err != nil || !started {
		t.Fatalf("first start: %v", err)
	}
	// Second start while running must be refused.
	if _, started, err := srv.syncOneSource(context.Background(), "kev", "manual", "tester"); err == nil || started {
		t.Fatalf("duplicate sync must be refused: started=%v err=%v", started, err)
	}
	waitFor(t, func() bool { return fakes.kevCalls.Load() >= 1 })
	// After completion a new run is allowed again.
	waitFor(t, func() bool {
		_, busy := srv.registry.get("kev")
		return !busy
	})
	if _, started, err := srv.syncOneSource(context.Background(), "kev", "manual", "tester"); err != nil || !started {
		t.Fatalf("retry after completion: %v", err)
	}
}

func TestIntelSyncEndpoints(t *testing.T) {
	fakes := &fakeSyncFuncs{}
	fakes.install(t)
	srv, _ := newTestServer(t)

	// Status view.
	var view intelSyncView
	if rec := doJSON(t, srv.Handler(), "GET", "/api/intel/sync", nil, &view); rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	if len(view.Sources) != 5 {
		t.Fatalf("sources = %d, want 5", len(view.Sources))
	}

	// Start one source.
	var start struct {
		JobID    string `json:"job_id"`
		Accepted bool   `json:"accepted"`
	}
	if rec := doJSON(t, srv.Handler(), "POST", "/api/intel/sync/kev", nil, &start); rec.Code != http.StatusAccepted || !start.Accepted {
		t.Fatalf("start: %d %+v", rec.Code, start)
	}
	// Duplicate while running → 409.
	rec := doJSON(t, srv.Handler(), "POST", "/api/intel/sync/kev", nil, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate must be 409, got %d", rec.Code)
	}
	// Unknown source → 400.
	if rec := doJSON(t, srv.Handler(), "POST", "/api/intel/sync/bogus", nil, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown source must be 400, got %d", rec.Code)
	}
	// Cancel a running job.
	if rec := doJSON(t, srv.Handler(), "POST", "/api/intel/sync/epss/cancel", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("cancel with nothing running must be 404, got %d", rec.Code)
	}

	// History reflects the attempt.
	waitFor(t, func() bool { return fakes.kevCalls.Load() >= 1 })
	var hist struct {
		Items []intel.SyncRunRow `json:"items"`
	}
	if rec := doJSON(t, srv.Handler(), "GET", "/api/intel/sync/history?source=kev", nil, &hist); rec.Code != http.StatusOK {
		t.Fatalf("history: %d", rec.Code)
	}
	if len(hist.Items) == 0 {
		t.Fatal("the run must appear in history")
	}
	foundOK := false
	for _, row := range hist.Items {
		if row.Status == "ok" {
			foundOK = true
		}
		if row.Actor != "api-token" && row.Actor != "" {
			// any actor is fine; the trigger must be manual
		}
		if row.Trigger != "manual" {
			t.Fatalf("manual trigger not recorded: %+v", row)
		}
	}
	if !foundOK {
		t.Fatalf("history has no successful row: %+v", hist.Items)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met within 10s")
}
