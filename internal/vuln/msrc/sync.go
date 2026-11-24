package msrc

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Ingestion.
//
// Microsoft publishes one CVRF document per monthly security release. A Windows correlation
// needs the KB → CVE mapping for the months the fleet could plausibly be missing, which is a
// bounded window by default (six months) and configurable. The bound is *reported*: the sync
// record says how many documents were available, how many were imported and which were skipped,
// because a silent cap would make "no findings" mean "not looked at".

// DefaultIndexURL is Microsoft's Security Update Guide API.
const DefaultIndexURL = "https://api.msrc.microsoft.com/cvrf/v3.0"

// DefaultMonths is how far back a first sync reaches. Six months covers a typical patching
// window; anything older is almost always superseded by a cumulative update.
const DefaultMonths = 6

// MaxMonths bounds a single sync request, so a typo cannot ask for 200 documents.
const MaxMonths = 24

// SyncOptions configures one ingestion run.
type SyncOptions struct {
	Months   int
	IndexURL string
	HTTP     *http.Client
	Log      *slog.Logger
	// Now is injectable for tests.
	Now func() time.Time
}

// SyncState is what a sync recorded, for health reporting.
type SyncState struct {
	SyncedAt  time.Time `json:"synced_at"`
	Documents int       `json:"documents"`
	Available int       `json:"documents_available"`
	Skipped   []string  `json:"documents_skipped,omitempty"`
	CVE       int       `json:"cves"`
	Fixes     int       `json:"fixes"`
	Months    int       `json:"months"`
	Error     string    `json:"error,omitempty"`
}

// EnsureSchema creates the advisory tables (additive; safe on an existing cache).
func EnsureSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS msrc_products (
			product_id TEXT PRIMARY KEY,
			name       TEXT NOT NULL,
			family     TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS msrc_cves (
			cve       TEXT PRIMARY KEY,
			title     TEXT NOT NULL DEFAULT '',
			severity  TEXT NOT NULL DEFAULT '',
			cvss      REAL NOT NULL DEFAULT 0,
			document  TEXT NOT NULL DEFAULT '',
			updated   TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS msrc_fixes (
			cve        TEXT NOT NULL,
			kb         TEXT NOT NULL,
			product_id TEXT NOT NULL DEFAULT '',
			supersedes TEXT NOT NULL DEFAULT '',
			url        TEXT NOT NULL DEFAULT '',
			document   TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (cve, kb, product_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_msrc_fixes_kb ON msrc_fixes(kb)`,
		`CREATE TABLE IF NOT EXISTS msrc_sync (
			id         INTEGER PRIMARY KEY CHECK (id = 1),
			synced_at  TEXT NOT NULL,
			state      TEXT NOT NULL
		)`,
	}
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("prepare MSRC tables: %w", err)
		}
	}
	return nil
}

type indexEntry struct {
	ID          string `json:"ID"`
	Title       string `json:"DocumentTitle"`
	ReleaseDate string `json:"InitialReleaseDate"`
	CvrfURL     string `json:"CvrfUrl"`
}

var securityTitle = regexp.MustCompile(`(?i)security updates`)

// Sync imports the last N monthly security documents.
func Sync(ctx context.Context, db *sql.DB, opts SyncOptions) (SyncState, error) {
	if opts.Months <= 0 {
		opts.Months = DefaultMonths
	}
	if opts.Months > MaxMonths {
		opts.Months = MaxMonths
	}
	if opts.IndexURL == "" {
		opts.IndexURL = DefaultIndexURL
	}
	if opts.HTTP == nil {
		opts.HTTP = &http.Client{Timeout: 90 * time.Second}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if err := EnsureSchema(db); err != nil {
		return SyncState{}, err
	}
	state := SyncState{SyncedAt: opts.Now().UTC(), Months: opts.Months}

	entries, err := fetchIndex(ctx, opts)
	if err != nil {
		state.Error = err.Error()
		recordSync(db, state)
		return state, err
	}
	// Only security bundles: the index also lists release notes and out-of-band pages.
	var security []indexEntry
	for _, e := range entries {
		if securityTitle.MatchString(e.Title) {
			security = append(security, e)
		}
	}
	sort.Slice(security, func(i, j int) bool { return security[i].ReleaseDate > security[j].ReleaseDate })
	state.Available = len(security)
	if len(security) > opts.Months {
		for _, skipped := range security[opts.Months:] {
			state.Skipped = append(state.Skipped, skipped.ID)
		}
		security = security[:opts.Months]
	}

	for _, e := range security {
		if err := ctx.Err(); err != nil {
			state.Error = err.Error()
			recordSync(db, state)
			return state, err
		}
		doc, err := fetchDocument(ctx, opts, e)
		if err != nil {
			// One bad month must not throw away the others, but it is recorded.
			if opts.Log != nil {
				opts.Log.Warn("msrc document failed", "document", e.ID, "err", err)
			}
			state.Skipped = append(state.Skipped, e.ID+" (failed: "+err.Error()+")")
			continue
		}
		cves, fixes, err := storeDocument(db, doc)
		if err != nil {
			state.Error = err.Error()
			recordSync(db, state)
			return state, err
		}
		state.Documents++
		state.CVE += cves
		state.Fixes += fixes
	}
	if state.Documents == 0 {
		state.Error = "no MSRC documents were imported"
		recordSync(db, state)
		return state, fmt.Errorf("%s", state.Error)
	}
	recordSync(db, state)
	return state, nil
}

func fetchIndex(ctx context.Context, opts SyncOptions) ([]indexEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.IndexURL+"/updates", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := opts.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch MSRC index: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch MSRC index: HTTP %d", res.StatusCode)
	}
	var body struct {
		Value []indexEntry `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode MSRC index: %w", err)
	}
	if len(body.Value) == 0 {
		return nil, fmt.Errorf("MSRC index returned no updates")
	}
	return body.Value, nil
}

func fetchDocument(ctx context.Context, opts SyncOptions, e indexEntry) (Document, error) {
	url := strings.TrimSpace(e.CvrfURL)
	if url == "" {
		url = opts.IndexURL + "/cvrf/" + e.ID
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Document{}, err
	}
	req.Header.Set("Accept", "application/xml")
	res, err := opts.HTTP.Do(req)
	if err != nil {
		return Document{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return Document{}, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	// A monthly document is ~9 MB; the cap is generous but not unbounded.
	raw, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return Document{}, err
	}
	doc, err := ParseDocument(raw)
	if err != nil {
		return Document{}, err
	}
	if doc.ID == "" {
		doc.ID = e.ID
	}
	return doc, nil
}

// storeDocument upserts one parsed document. Returns how many CVEs and fixes it wrote.
func storeDocument(db *sql.DB, doc Document) (int, int, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	for id, p := range doc.Products {
		if _, err := tx.Exec(`INSERT INTO msrc_products (product_id, name, family) VALUES (?,?,?)
			ON CONFLICT(product_id) DO UPDATE SET name=excluded.name, family=excluded.family`,
			id, p.Name, strings.Join(p.Family, "/")); err != nil {
			return 0, 0, err
		}
	}
	cves, fixes := 0, 0
	for _, c := range doc.CVEs {
		if _, err := tx.Exec(`INSERT INTO msrc_cves (cve, title, severity, cvss, document, updated)
			VALUES (?,?,?,?,?,?)
			ON CONFLICT(cve) DO UPDATE SET
				title=CASE WHEN excluded.title <> '' THEN excluded.title ELSE title END,
				severity=CASE WHEN excluded.severity <> '' THEN excluded.severity ELSE severity END,
				cvss=MAX(cvss, excluded.cvss), document=excluded.document, updated=excluded.updated`,
			c.ID, c.Title, c.Severity, c.CVSS, doc.ID, now); err != nil {
			return 0, 0, err
		}
		cves++
		for _, f := range c.Fixes {
			if _, err := tx.Exec(`INSERT INTO msrc_fixes (cve, kb, product_id, supersedes, url, document)
				VALUES (?,?,?,?,?,?)
				ON CONFLICT(cve, kb, product_id) DO UPDATE SET
					supersedes=excluded.supersedes, url=excluded.url, document=excluded.document`,
				c.ID, f.KB, f.ProductID, strings.Join(f.Supersedes, ","), f.URL, doc.ID); err != nil {
				return 0, 0, err
			}
			fixes++
		}
	}
	return cves, fixes, tx.Commit()
}

func recordSync(db *sql.DB, state SyncState) {
	raw, _ := json.Marshal(state)
	_, _ = db.Exec(`INSERT INTO msrc_sync (id, synced_at, state) VALUES (1,?,?)
		ON CONFLICT(id) DO UPDATE SET synced_at=excluded.synced_at, state=excluded.state`,
		state.SyncedAt.Format(time.RFC3339), string(raw))
}

// LastSync returns the recorded state, when one exists.
func LastSync(db *sql.DB) (SyncState, bool) {
	var raw string
	if err := db.QueryRow(`SELECT state FROM msrc_sync WHERE id = 1`).Scan(&raw); err != nil {
		return SyncState{}, false
	}
	var st SyncState
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return SyncState{}, false
	}
	return st, true
}

// StoreDocumentForTest exposes one parsed document to other packages' tests.
func StoreDocumentForTest(db *sql.DB, doc Document) error {
	_, _, err := storeDocument(db, doc)
	return err
}
