package nvd

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"time"
)

// SyncOptions controls one synchronization run.
type SyncOptions struct {
	// APIKey raises the rate limit; may be empty. Never logged.
	APIKey string
	// BaseURL overrides the API base (tests).
	BaseURL string
	// Since bounds the initial CVE population window by lastModified. Zero
	// means the whole history. A first sync is normally bounded; incremental
	// syncs keep the dataset moving forward.
	Since time.Time
	// Full forces a full re-population instead of an incremental update.
	Full bool
	// MaxPages bounds the number of pages fetched (safety valve; 0 =
	// unlimited).
	MaxPages int
	// Progress receives (stage, detail) updates; may be nil.
	Progress func(stage, detail string)
	// Log receives structured logs; may be nil.
	Log *slog.Logger
	// Now injects time (tests).
	Now func() time.Time
	// MinInterval overrides the request spacing (tests); 0 = computed from
	// the rate limits.
	MinInterval time.Duration
	// BackoffBase is the initial retry delay (tests); 0 = 6s default.
	BackoffBase time.Duration
	// MaxRetries bounds retries per request (tests); 0 = 5 default.
	MaxRetries int
}

// SyncResult summarises one run, for admin visibility and CLI output.
type SyncResult struct {
	Source     string
	Mode       string // full | incremental
	StartedAt  time.Time
	FinishedAt time.Time
	TotalSeen  int
	Imported   int
	Updated    int
	Failed     int
	Status     string // ok | failed
	Detail     string
}

func (o *SyncOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now().UTC()
}

func (o *SyncOptions) progress(stage, detail string) {
	if o.Progress != nil {
		o.Progress(stage, detail)
	}
}

func (o *SyncOptions) log() *slog.Logger {
	if o.Log != nil {
		return o.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// SyncCVEs populates or updates the local CVE dataset from NVD.
//
// Incremental mode re-fetches the window since the last successful sync
// (minus a two-day overlap so records modified several times are re-seen).
// Every page is stored transactionally; a failure aborts the run and leaves
// the last known valid dataset in place. Rejected CVEs are stored and marked
// so correlation can exclude them explicitly.
func SyncCVEs(ctx context.Context, db *sql.DB, opts SyncOptions) (SyncResult, error) {
	if err := EnsureSchema(db); err != nil {
		return SyncResult{}, err
	}
	store := NewStore(db)
	started := opts.now()
	mode := "incremental"
	windowStart := time.Time{}
	if opts.Full {
		mode = "full"
	} else if st, ok, err := store.LastSuccessfulSync(ctx, "cves"); err == nil && ok && !st.FinishedAt.IsZero() {
		windowStart = st.FinishedAt.Add(-48 * time.Hour)
	}
	if !opts.Since.IsZero() && (windowStart.IsZero() || opts.Since.After(windowStart)) {
		windowStart = opts.Since
	}
	seq, err := store.RecordSyncStart(ctx, "cves", mode, windowStart, time.Time{}, started)
	if err != nil {
		return SyncResult{}, fmt.Errorf("record sync start: %w", err)
	}
	res := SyncResult{Source: "cves", Mode: mode, StartedAt: started}

	client := NewClient(opts.APIKey)
	if opts.BaseURL != "" {
		client.BaseURL = opts.BaseURL
	}
	// Syncs are long-running; give the client a generous timeout.
	client.HTTP.Timeout = 5 * time.Minute
	client.Now = opts.now
	if opts.MinInterval > 0 {
		client.MinInterval = opts.MinInterval
	}
	if opts.BackoffBase > 0 {
		client.BackoffBase = opts.BackoffBase
	}
	if opts.MaxRetries > 0 {
		client.MaxRetries = opts.MaxRetries
	}

	startIndex := 0
	pages := 0
	lastTotal := -1
	for {
		if err := ctx.Err(); err != nil {
			res.Status = "failed"
			res.Detail = "cancelled: " + err.Error()
			res.FinishedAt = opts.now()
			_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
			return res, err
		}
		total, records, err := client.CVEPage(ctx, startIndex, windowStart, time.Time{})
		if err != nil {
			res.Status = "failed"
			res.Detail = fmt.Sprintf("page %d failed: %v", startIndex, err)
			res.FinishedAt = opts.now()
			_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
			return res, fmt.Errorf("NVD CVE sync failed at startIndex %d (existing data untouched): %w", startIndex, err)
		}
		if pages == 0 {
			// Feed integrity: the envelope's total must stay stable across
			// the run, or the dataset is being modified under us.
			lastTotal = total
			opts.progress("nvd", fmt.Sprintf("%d CVE records available", total))
		} else if total != lastTotal {
			res.Status = "failed"
			res.Detail = fmt.Sprintf("feed total changed mid-sync (%d -> %d); retry", lastTotal, total)
			res.FinishedAt = opts.now()
			_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
			return res, fmt.Errorf("NVD feed changed during sync; run again to get a consistent snapshot")
		}
		res.TotalSeen = total
		imported, updated, err := store.SaveCVEs(ctx, records, opts.now())
		if err != nil {
			res.Status = "failed"
			res.Detail = fmt.Sprintf("store page %d: %v", startIndex, err)
			res.FinishedAt = opts.now()
			_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
			return res, fmt.Errorf("store NVD page %d: %w", startIndex, err)
		}
		res.Imported += imported
		res.Updated += updated
		startIndex += len(records)
		pages++
		if len(records) == 0 || startIndex >= total {
			break
		}
		if opts.MaxPages > 0 && pages >= opts.MaxPages {
			res.Status = "failed"
			res.Detail = fmt.Sprintf("page limit %d reached before the feed was complete", opts.MaxPages)
			res.FinishedAt = opts.now()
			_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
			return res, fmt.Errorf("NVD sync stopped by page limit %d; raise or remove it", opts.MaxPages)
		}
	}
	// A page cap can silently truncate; the invariant below makes that loud.
	if startIndex < res.TotalSeen {
		res.Status = "failed"
		res.Detail = fmt.Sprintf("imported %d of %d records", startIndex, res.TotalSeen)
		res.FinishedAt = opts.now()
		_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
		return res, fmt.Errorf("NVD sync incomplete: %d of %d records imported", startIndex, res.TotalSeen)
	}
	res.Status = "ok"
	res.FinishedAt = opts.now()
	if err := store.RecordSyncFinish(ctx, seq, "ok", res.TotalSeen, res.Imported, res.Updated, res.Failed,
		fmt.Sprintf("%d pages", pages), res.FinishedAt); err != nil {
		return res, fmt.Errorf("record sync finish: %w", err)
	}
	return res, nil
}

// SyncDictionary populates or updates the CPE dictionary. Incremental mode
// re-fetches entries modified since the last successful dictionary sync.
func SyncDictionary(ctx context.Context, db *sql.DB, opts SyncOptions) (SyncResult, error) {
	if err := EnsureSchema(db); err != nil {
		return SyncResult{}, err
	}
	store := NewStore(db)
	started := opts.now()
	mode := "incremental"
	windowStart := time.Time{}
	if opts.Full {
		mode = "full"
	} else if st, ok, err := store.LastSuccessfulSync(ctx, "cpes"); err == nil && ok && !st.FinishedAt.IsZero() {
		windowStart = st.FinishedAt.Add(-48 * time.Hour)
	}
	seq, err := store.RecordSyncStart(ctx, "cpes", mode, windowStart, time.Time{}, started)
	if err != nil {
		return SyncResult{}, fmt.Errorf("record sync start: %w", err)
	}
	res := SyncResult{Source: "cpes", Mode: mode, StartedAt: started}

	client := NewClient(opts.APIKey)
	if opts.BaseURL != "" {
		client.BaseURL = opts.BaseURL
	}
	client.HTTP.Timeout = 5 * time.Minute
	client.Now = opts.now
	if opts.MinInterval > 0 {
		client.MinInterval = opts.MinInterval
	}
	if opts.BackoffBase > 0 {
		client.BackoffBase = opts.BackoffBase
	}
	if opts.MaxRetries > 0 {
		client.MaxRetries = opts.MaxRetries
	}

	startIndex := 0
	pages := 0
	lastTotal := -1
	for {
		if err := ctx.Err(); err != nil {
			res.Status = "failed"
			res.Detail = "cancelled: " + err.Error()
			res.FinishedAt = opts.now()
			_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
			return res, err
		}
		total, entries, err := client.CPEDictionaryPage(ctx, startIndex, windowStart)
		if err != nil {
			res.Status = "failed"
			res.Detail = fmt.Sprintf("page %d failed: %v", startIndex, err)
			res.FinishedAt = opts.now()
			_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
			return res, fmt.Errorf("NVD dictionary sync failed at startIndex %d (existing data untouched): %w", startIndex, err)
		}
		if pages == 0 {
			lastTotal = total
			opts.progress("nvd-cpe", fmt.Sprintf("%d CPE dictionary entries available", total))
		} else if total != lastTotal {
			res.Status = "failed"
			res.Detail = fmt.Sprintf("dictionary total changed mid-sync (%d -> %d); retry", lastTotal, total)
			res.FinishedAt = opts.now()
			_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
			return res, fmt.Errorf("NVD dictionary changed during sync; run again for a consistent snapshot")
		}
		res.TotalSeen = total
		imported, updated, err := store.SaveDictionary(ctx, entries)
		if err != nil {
			res.Status = "failed"
			res.Detail = fmt.Sprintf("store page %d: %v", startIndex, err)
			res.FinishedAt = opts.now()
			_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
			return res, fmt.Errorf("store dictionary page %d: %w", startIndex, err)
		}
		res.Imported += imported
		res.Updated += updated
		startIndex += len(entries)
		pages++
		if len(entries) == 0 || startIndex >= total {
			break
		}
		if opts.MaxPages > 0 && pages >= opts.MaxPages {
			res.Status = "failed"
			res.Detail = fmt.Sprintf("page limit %d reached before the dictionary was complete", opts.MaxPages)
			res.FinishedAt = opts.now()
			_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
			return res, fmt.Errorf("NVD dictionary sync stopped by page limit %d", opts.MaxPages)
		}
	}
	if startIndex < res.TotalSeen {
		res.Status = "failed"
		res.Detail = fmt.Sprintf("imported %d of %d entries", startIndex, res.TotalSeen)
		res.FinishedAt = opts.now()
		_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
		return res, fmt.Errorf("NVD dictionary sync incomplete: %d of %d entries", startIndex, res.TotalSeen)
	}
	res.Status = "ok"
	res.FinishedAt = opts.now()
	if err := store.RecordSyncFinish(ctx, seq, "ok", res.TotalSeen, res.Imported, res.Updated, res.Failed,
		fmt.Sprintf("%d pages", pages), res.FinishedAt); err != nil {
		return res, fmt.Errorf("record sync finish: %w", err)
	}
	return res, nil
}

// APIKeyFromEnv resolves the NVD API key from the environment. Empty string
// means "no key" (anonymous rate limits). Callers must never log the result.
func APIKeyFromEnv(getenv func(string) string) string {
	if getenv == nil {
		return ""
	}
	for _, name := range APIKeyEnvNames {
		if v := getenv(name); v != "" {
			return v
		}
	}
	return ""
}
