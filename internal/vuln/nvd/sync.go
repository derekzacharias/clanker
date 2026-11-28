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
	// SincePublished bounds the initial CVE population by publication date
	// instead (e.g. "everything published since 2024-01-01"). Publication
	// dates match the calendar a reviewer thinks in; lastModified clusters
	// around NVD's bulk re-analyses instead.
	SincePublished time.Time
	// Full forces a full re-population instead of an incremental update.
	Full bool
	// MaxPages bounds the number of pages fetched (safety valve; 0 =
	// unlimited).
	MaxPages int
	// SkipDictionary skips the CPE dictionary population. The correlation
	// engine does not require the dictionary (normalization rules carry the
	// priority applications); it exists for unknown-software identity
	// resolution. A full dictionary sync is ~1.9M entries and takes hours
	// without an API key, so deployments may choose to skip it.
	SkipDictionary bool
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

// maxDateRange is the largest lastModStartDate..lastModEndDate span the NVD
// API accepts for one request series (it answers 404 for longer ranges).
// Population windows wider than this are fetched as consecutive slices.
const maxDateRange = 120 * 24 * time.Hour

// dateWindow is one lastModified slice to fetch.
type dateWindow struct {
	start, end time.Time
}

// dateWindows slices a population window into API-acceptable ranges.
func dateWindows(start, end time.Time, max time.Duration) []dateWindow {
	if max <= 0 {
		max = maxDateRange
	}
	if start.IsZero() || end.IsZero() || !end.After(start) {
		return []dateWindow{{start: start, end: end}}
	}
	var out []dateWindow
	for s := start; s.Before(end); s = s.Add(max) {
		e := s.Add(max)
		if e.After(end) {
			e = end
		}
		out = append(out, dateWindow{start: s, end: e})
	}
	return out
}

// SyncCVEs populates or updates the local CVE dataset from NVD.
//
// Incremental mode re-fetches the window since the last successful sync
// (minus a two-day overlap so records modified several times are re-seen).
// Population windows wider than the API's 120-day limit are fetched as
// consecutive slices. Every page is stored transactionally; a failure aborts
// the run and leaves the last known valid dataset in place. Rejected CVEs are
// stored and marked so correlation can exclude them explicitly.
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
	published := !opts.SincePublished.IsZero()
	windows := []dateWindow{{start: windowStart}}
	if published {
		windows = dateWindows(opts.SincePublished, opts.now(), maxDateRange)
	} else if !windowStart.IsZero() {
		windows = dateWindows(windowStart, opts.now(), maxDateRange)
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

	pages := 0
	windowTotal := 0
	for wi, w := range windows {
		if err := ctx.Err(); err != nil {
			res.Status = "failed"
			res.Detail = "cancelled: " + err.Error()
			res.FinishedAt = opts.now()
			_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
			return res, err
		}
		startIndex := 0
		lastTotal := -1
		for {
			if err := ctx.Err(); err != nil {
				res.Status = "failed"
				res.Detail = "cancelled: " + err.Error()
				res.FinishedAt = opts.now()
				_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
				return res, err
			}
			var total int
			var records []Record
			var err error
			if published {
				total, records, err = client.CVEPagePublished(ctx, startIndex, w.start, w.end)
			} else {
				total, records, err = client.CVEPage(ctx, startIndex, w.start, w.end)
			}
			if err != nil {
				res.Status = "failed"
				res.Detail = fmt.Sprintf("window %d/%d page %d failed: %v", wi+1, len(windows), startIndex, err)
				res.FinishedAt = opts.now()
				_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
				return res, fmt.Errorf("NVD CVE sync failed at startIndex %d (existing data untouched): %w", startIndex, err)
			}
			if lastTotal == -1 {
				lastTotal = total
				windowTotal += total
				opts.progress("nvd", fmt.Sprintf("window %d/%d: %d CVE records", wi+1, len(windows), total))
			} else if total != lastTotal {
				// For a bounded window the total must stay stable: the
				// window boundary is fixed, so a changing count means the
				// dataset is being rewritten under us. The UNFILTERED full
				// sync is different — records are added continuously while
				// we page through the whole history, so the total grows and
				// that is normal. There the run continues and the next
				// incremental pass picks up whatever appeared mid-run.
				if !w.start.IsZero() {
					res.Status = "failed"
					res.Detail = fmt.Sprintf("feed total changed mid-window (%d -> %d); retry", lastTotal, total)
					res.FinishedAt = opts.now()
					_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
					return res, fmt.Errorf("NVD feed changed during sync; run again to get a consistent snapshot")
				}
				opts.progress("nvd", fmt.Sprintf("feed grew during the full pass (%d -> %d); the next incremental run covers the delta", lastTotal, total))
				lastTotal = total
				windowTotal = total
			}
			imported, updated, err := store.SaveCVEs(ctx, records, opts.now())
			if err != nil {
				res.Status = "failed"
				res.Detail = fmt.Sprintf("store window %d page %d: %v", wi+1, startIndex, err)
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
	}
	res.TotalSeen = windowTotal
	// A page cap can silently truncate; the invariant below makes that loud.
	// The full unfiltered pass is exempt: the feed grows while it runs, so
	// "imported less than the live total" is normal there — the next
	// incremental sync covers the delta.
	importedTotal := res.Imported + res.Updated
	if importedTotal < res.TotalSeen && !windows[0].start.IsZero() {
		res.Status = "failed"
		res.Detail = fmt.Sprintf("imported %d of %d records", importedTotal, res.TotalSeen)
		res.FinishedAt = opts.now()
		_ = store.RecordSyncFinish(ctx, seq, "failed", res.TotalSeen, res.Imported, res.Updated, res.Failed, res.Detail, res.FinishedAt)
		return res, fmt.Errorf("NVD sync incomplete: %d of %d records imported", importedTotal, res.TotalSeen)
	}
	if importedTotal < res.TotalSeen {
		res.TotalSeen = importedTotal
	}
	res.Status = "ok"
	res.FinishedAt = opts.now()
	if err := store.RecordSyncFinish(ctx, seq, "ok", res.TotalSeen, res.Imported, res.Updated, res.Failed,
		fmt.Sprintf("%d pages across %d window(s)", pages, len(windows)), res.FinishedAt); err != nil {
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
