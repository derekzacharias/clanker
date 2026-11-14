package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
)

// TestCancelledScanStaysCancelled is the regression test for the defect found by
// the Playwright suite: cancelling a scan left the job goroutine running, which
// then tried to mark the job completed and record a report.
func TestCancelledScanStaysCancelled(t *testing.T) {
	srv, _ := newTestServer(t)

	started := make(chan struct{})
	srv.opts.RunScan = func(ctx context.Context, opts scan.Options) (scan.Result, error) {
		close(started)
		<-ctx.Done() // behave like a real scan: work until cancelled
		return scan.Result{}, ctx.Err()
	}

	var job intel.Job
	if rec := doJSON(t, srv.Handler(), "POST", "/api/scans", map[string]any{"kind": "local"}, &job); rec.Code != http.StatusAccepted {
		t.Fatalf("start status %d", rec.Code)
	}
	<-started

	if rec := doJSON(t, srv.Handler(), "POST", "/api/scans/"+job.ID+"/cancel", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("cancel status %d", rec.Code)
	}

	// Give the goroutine time to finish and attempt to overwrite the job.
	for i := 0; i < 20; i++ {
		stored, err := srv.store.GetJob(context.Background(), job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored != nil && stored.Status == intel.JobDone {
			t.Fatalf("cancelled job was overwritten as completed: %+v", stored)
		}
		if stored != nil && stored.ReportID != "" {
			t.Fatalf("cancelled job recorded a report: %s", stored.ReportID)
		}
		time.Sleep(25 * time.Millisecond)
	}
	stored, err := srv.store.GetJob(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil || stored.Status != intel.JobCanceled {
		t.Fatalf("expected a cancelled job, got %+v", stored)
	}
	runs, err := srv.store.ListRuns(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range runs {
		if run.ID == stored.ReportID {
			t.Fatal("cancelled scan was stored as an assessment")
		}
	}
}

// TestFinishJobCannotReviveTerminalStates covers the store-level guard.
func TestFinishJobCannotReviveTerminalStates(t *testing.T) {
	_, cachePath := newTestServer(t)
	store, err := intel.OpenStore(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()

	job := intel.Job{ID: "SCAN-guard", Kind: "local", Status: intel.JobRunning, StartedAt: time.Now()}
	if err := store.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishJob(ctx, job.ID, intel.JobCanceled, "", "canceled by user"); err != nil {
		t.Fatal(err)
	}
	// The worker goroutine now reports completion: it must be ignored.
	_ = store.FinishJob(ctx, job.ID, intel.JobDone, "SCAN-late", "")
	got, err := store.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != intel.JobCanceled || got.ReportID != "" {
		t.Fatalf("terminal state was overwritten: %+v", got)
	}
	// Progress ticks after the end must be ignored too.
	_ = store.UpdateJobProgress(ctx, job.ID, "matching", "late", 75)
	got, _ = store.GetJob(ctx, job.ID)
	if got.Percent != 0 || got.Stage != "" || got.StageDetail != "" {
		t.Fatalf("progress written after the job finished: %+v", got)
	}
}
