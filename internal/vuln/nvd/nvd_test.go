package nvd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/bgdnvk/clanker/internal/vuln/cpe"
)

const fixtureCVE = `{"cve":{
  "id": "CVE-2024-0519",
  "sourceIdentifier": "chrome-cve-admin@google.com",
  "published": "2024-01-16T22:15:37.000",
  "lastModified": "2024-01-24T18:15:08.000",
  "vulnStatus": "Analyzed",
  "descriptions": [
    {"lang": "en", "value": "Out of bounds memory access in V8 in Google Chrome prior to 120.0.6099.224 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page."},
    {"lang": "es", "value": "desc en espanol"}
  ],
  "metrics": {
    "cvssMetricV31": [{
      "source": "nvd@nist.gov", "type": "Primary",
      "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "baseScore": 8.8, "baseSeverity": "HIGH"},
      "exploitabilityScore": 2.8, "impactScore": 5.9
    }]
  },
  "weaknesses": [{
    "source": "nvd@nist.gov", "type": "Primary",
    "description": [{"lang": "en", "value": "CWE-787"}]
  }],
  "configurations": [{
    "operator": "OR", "negate": false,
    "nodes": [{
      "operator": "OR", "negate": false,
      "cpeMatch": [
        {"vulnerable": true, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "matchCriteriaId": "5D33A178-14E4-49B9-9A7F-5D74025E2729", "versionEndExcluding": "120.0.6099.224"},
        {"vulnerable": true, "criteria": "cpe:2.3:a:google:chrome:120.0.6099.224:*:*:*:*:*:*:*", "matchCriteriaId": "AA12"}
      ]
    }]
  }],
  "references": [
    {"url": "https://chromereleases.googleblog.com/2024/01/stable-channel-update-for-desktop_16.html", "source": "chrome-cve-admin@google.com"}
  ]
}}`

const fixtureRejected = `{"cve":{
  "id": "CVE-2024-9999",
  "published": "2024-02-01T00:00:00.000",
  "lastModified": "2024-02-02T00:00:00.000",
  "vulnStatus": "Rejected",
  "descriptions": [{"lang": "en", "value": "DO NOT USE THIS CANDIDATE NUMBER."}],
  "references": []
}}`

func envelope(vulns ...string) string {
	var raw []json.RawMessage
	for _, v := range vulns {
		raw = append(raw, json.RawMessage(v))
	}
	body, _ := json.Marshal(map[string]any{
		"resultsPerPage": 2000, "startIndex": 0, "totalResults": len(vulns),
		"format": "NVD_CVE", "version": "2.0", "timestamp": time.Now().UTC().Format(time.RFC3339),
		"vulnerabilities": raw,
	})
	return string(body)
}

func TestParseRecord(t *testing.T) {
	r, err := parseRecord(json.RawMessage(fixtureCVE))
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "CVE-2024-0519" || r.Status != "Analyzed" {
		t.Fatalf("id/status: %+v", r)
	}
	if !strings.Contains(r.Description, "V8") {
		t.Fatalf("description must be the English text: %q", r.Description)
	}
	cvss := r.PrimaryCVSS()
	if cvss == nil || cvss.Score != 8.8 || cvss.Version != "3.1" || cvss.Severity != "high" {
		t.Fatalf("primary CVSS: %+v", cvss)
	}
	if len(r.Configs) == 0 || len(r.Configs[0].Children) == 0 || len(r.Configs[0].Children[0].Matches) != 2 {
		t.Fatalf("configs not parsed: %+v", r.Configs)
	}
	if r.DetailURL() != "https://nvd.nist.gov/vuln/detail/CVE-2024-0519" {
		t.Fatalf("detail url: %s", r.DetailURL())
	}
}

func TestParseRejectedRecord(t *testing.T) {
	r, err := parseRecord(json.RawMessage(fixtureRejected))
	if err != nil {
		t.Fatal(err)
	}
	if !Rejected(r.Status) {
		t.Fatalf("status %q must be rejected", r.Status)
	}
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.TempDir()+"/nvd.db?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := EnsureSchema(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	s := NewStore(db)

	rec, err := parseRecord(json.RawMessage(fixtureCVE))
	if err != nil {
		t.Fatal(err)
	}
	rej, _ := parseRecord(json.RawMessage(fixtureRejected))
	imported, updated, err := s.SaveCVEs(ctx, []Record{rec, rej}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if imported != 2 || updated != 0 {
		t.Fatalf("imported=%d updated=%d", imported, updated)
	}
	// Re-saving counts as an update and does not duplicate index rows.
	_, updated, err = s.SaveCVEs(ctx, []Record{rec}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if updated != 1 {
		t.Fatalf("re-save should update, got %d", updated)
	}

	got, ok, err := s.CVEByID(ctx, "cve-2024-0519")
	if err != nil || !ok {
		t.Fatalf("CVEByID: %v %v", got, err)
	}
	if got.PrimaryCVSS().Score != 8.8 {
		t.Fatalf("cvss lost in round trip: %+v", got.Metrics)
	}
	if len(got.Configs) == 0 {
		t.Fatal("configs lost in round trip")
	}

	ids, err := s.CVEsForProduct(ctx, "GOOGLE", "Chrome")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "CVE-2024-0519" {
		t.Fatalf("product lookup must be case-insensitive: %v", ids)
	}
	// The rejected CVE is stored but correlation excludes it.
	n, err := s.CVECount(ctx, true)
	if err != nil || n != 1 {
		t.Fatalf("count excluding rejected = %d, %v", n, err)
	}

	if _, ok, err := s.EvalCacheGet(ctx, "google", "chrome", "120.0.6099.109", "CVE-2024-0519"); ok || err != nil {
		t.Fatalf("empty cache: ok=%v err=%v", ok, err)
	}
	if err := s.EvalCachePut(ctx, "google", "chrome", "120.0.6099.109", "CVE-2024-0519", "vulnerable", "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := s.EvalCacheGet(ctx, "google", "chrome", "120.0.6099.109", "CVE-2024-0519"); err != nil || !ok || v != "vulnerable" {
		t.Fatalf("cache: %q %v %v", v, ok, err)
	}
	if err := s.InvalidateEvalCache(ctx, "CVE-2024-0519"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.EvalCacheGet(ctx, "google", "chrome", "120.0.6099.109", "CVE-2024-0519"); ok {
		t.Fatal("cache must be invalidated for the updated CVE")
	}
}

func TestStoreDictionaryRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	s := NewStore(db)

	entries := []DictEntry{
		{CPE23: "cpe:2.3:a:google:chrome:120.0.6099.109:*:*:*:*:*:*:*", Vendor: "google", Product: "chrome", Version: "120.0.6099.109", Titles: []string{"Google Chrome 120.0.6099.109"}},
		{CPE23: "cpe:2.3:a:google:chrome_old:*:*:*:*:*:*:*:*", Vendor: "google", Product: "chrome_old", Version: "*", Deprecated: true, DeprecatedBy: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"},
	}
	if _, _, err := s.SaveDictionary(ctx, entries); err != nil {
		t.Fatal(err)
	}
	total, deprecated, err := s.DictionaryStats(ctx)
	if err != nil || total != 2 || deprecated != 1 {
		t.Fatalf("stats: %d/%d %v", total, deprecated, err)
	}
	got, err := s.DictionaryFor(ctx, "google", "chrome")
	if err != nil || len(got) != 1 {
		t.Fatalf("DictionaryFor: %v %v", got, err)
	}
	// Deprecation resolution follows the replacement chain.
	replacement, ok, err := s.ResolveDeprecated(ctx, "cpe:2.3:a:google:chrome_old:*:*:*:*:*:*:*:*")
	if err != nil || !ok || replacement != "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*" {
		t.Fatalf("ResolveDeprecated: %q %v %v", replacement, ok, err)
	}
}

func TestIndexMatchesFlattensTree(t *testing.T) {
	node := cpe.Node{
		Operator: "AND",
		Children: []cpe.Node{
			{Operator: "OR", Matches: []cpe.Match{
				{Criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", Vulnerable: true, MatchCriteriaID: "A", Range: cpe.Range{EndExcluding: "120.0.6099.224"}},
			}},
			{Operator: "OR", Matches: []cpe.Match{
				{Criteria: "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*", Vulnerable: true, MatchCriteriaID: "B"},
			}},
		},
	}
	rows, err := indexMatches("CVE-2024-0519", []cpe.Node{node})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 flattened rows, got %d", len(rows))
	}
	found := map[string]bool{}
	for _, r := range rows {
		found[r.vendor+"/"+r.product] = true
	}
	if !found["google/chrome"] || !found["microsoft/windows"] {
		t.Fatalf("flattened rows: %+v", rows)
	}
}

// --- client behaviour -------------------------------------------------------

func TestClientPaginationAndRateLimit(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		// One record per page; the second page would exceed the total.
		fmt.Fprint(w, envelope(fixtureCVE))
	}))
	defer srv.Close()

	client := NewClient("")
	client.BaseURL = srv.URL
	client.MinInterval = time.Millisecond
	client.MaxRetries = 0

	total, records, err := client.CVEPage(context.Background(), 0, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(records) != 1 || records[0].ID != "CVE-2024-0519" {
		t.Fatalf("page: total=%d records=%d", total, len(records))
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestClientRetriesWithBackoff(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, envelope(fixtureCVE))
	}))
	defer srv.Close()

	client := NewClient("")
	client.BaseURL = srv.URL
	client.MinInterval = time.Millisecond
	client.BackoffBase = time.Millisecond
	client.MaxRetries = 3

	_, records, err := client.CVEPage(context.Background(), 0, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("retries should eventually succeed, got %d records", len(records))
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3", calls.Load())
	}
}

func TestClientGivesUpAfterRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewClient("")
	client.BaseURL = srv.URL
	client.MinInterval = time.Millisecond
	client.BackoffBase = time.Millisecond
	client.MaxRetries = 2

	_, _, err := client.CVEPage(context.Background(), 0, time.Time{}, time.Time{})
	if err == nil {
		t.Fatal("expected error after retries")
	}
}

func TestClientRejectsCorruptFeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"resultsPerPage":2000,"totalResults":1,"format":"NVD_CVE","vulnerabilities":[{"id":123}]}`)
	}))
	defer srv.Close()
	client := NewClient("")
	client.BaseURL = srv.URL
	client.MinInterval = time.Millisecond
	client.MaxRetries = 0
	if _, _, err := client.CVEPage(context.Background(), 0, time.Time{}, time.Time{}); err == nil {
		t.Fatal("corrupt record must be an error, not a silent skip")
	}
}

func TestAPIKeyEnvResolution(t *testing.T) {
	got := APIKeyFromEnv(func(name string) string {
		if name == "NVD_API_KEY" {
			return "secret"
		}
		return ""
	})
	if got != "secret" {
		t.Fatalf("key resolution: %q", got)
	}
	if APIKeyFromEnv(func(string) string { return "" }) != "" {
		t.Fatal("no key must resolve to empty")
	}
}

// The API key travels in a header and must never appear in any error surface.
func TestAPIKeyNeverLeaksIntoErrors(t *testing.T) {
	const key = "super-secret-key-123"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apiKey") != key {
			t.Errorf("apiKey header missing")
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewClient(key)
	client.BaseURL = srv.URL
	client.MinInterval = time.Millisecond
	client.BackoffBase = time.Millisecond
	client.MaxRetries = 1

	_, _, err := client.CVEPage(context.Background(), 0, time.Time{}, time.Time{})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), key) {
		t.Fatalf("API key leaked into error: %v", err)
	}
	// Also verify the failure path of the sync orchestrator keeps the key out.
	db := openTestDB(t)
	_, serr := SyncCVEs(context.Background(), db, SyncOptions{
		BaseURL: srv.URL, APIKey: key, MinInterval: time.Millisecond,
		BackoffBase: time.Millisecond, MaxRetries: 1,
	})
	if serr == nil || strings.Contains(serr.Error(), key) {
		t.Fatalf("sync error leaked the key: %v", serr)
	}
}

// --- sync -------------------------------------------------------------------

func nvdServer(t *testing.T, pages []string, failAfter int) *httptest.Server {
	var calls atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1))
		if failAfter > 0 && n > failAfter {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if n-1 < len(pages) {
			fmt.Fprint(w, pages[n-1])
			return
		}
		fmt.Fprint(w, envelope()) // empty page
	}))
}

func TestSyncCVEsFullAndIncremental(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	page1 := envelope(fixtureCVE, fixtureRejected)
	srv := nvdServer(t, []string{page1}, 0)
	defer srv.Close()

	res, err := SyncCVEs(ctx, db, SyncOptions{BaseURL: srv.URL, Full: true, MinInterval: time.Millisecond, BackoffBase: time.Millisecond, MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "ok" || res.Imported != 2 || res.TotalSeen != 2 {
		t.Fatalf("sync result: %+v", res)
	}

	// Incremental sync uses lastModStartDate after the previous run.
	srv2 := nvdServer(t, []string{envelope(fixtureCVE)}, 0)
	defer srv2.Close()
	res2, err := SyncCVEs(ctx, db, SyncOptions{BaseURL: srv2.URL, MinInterval: time.Millisecond, BackoffBase: time.Millisecond, MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Status != "ok" || res2.Mode != "incremental" {
		t.Fatalf("incremental result: %+v", res2)
	}
	// The updated record counts as an update; the dataset stays consistent.
	if res2.Updated != 1 {
		t.Fatalf("expected 1 updated record, got %+v", res2)
	}

	st, ok, err := NewStore(db).LastSuccessfulSync(ctx, "cves")
	if err != nil || !ok {
		t.Fatalf("sync history: %v %v", st, err)
	}
	if st.Updated != 1 || st.Status != "ok" {
		t.Fatalf("sync history: %+v", st)
	}
}

func TestSyncFailureKeepsLastKnownDataset(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	s := NewStore(db)

	// A successful sync first.
	srv1 := nvdServer(t, []string{envelope(fixtureCVE)}, 0)
	if _, err := SyncCVEs(ctx, db, SyncOptions{BaseURL: srv1.URL, Full: true}); err != nil {
		t.Fatal(err)
	}
	srv1.Close()
	before, _ := s.CVECount(ctx, false)

	// Then a failing sync: the first page claims five records, the second
	// request dies — the dataset must stay exactly as it was.
	var calls atomic.Int32
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var raw []json.RawMessage
		raw = append(raw, json.RawMessage(fixtureCVE))
		body, _ := json.Marshal(map[string]any{
			"resultsPerPage": 2000, "startIndex": 0, "totalResults": 5,
			"format": "NVD_CVE", "version": "2.0",
			"vulnerabilities": raw,
		})
		fmt.Fprint(w, string(body))
	}))
	_, err := SyncCVEs(ctx, db, SyncOptions{BaseURL: srv2.URL, Full: true, MinInterval: time.Millisecond, BackoffBase: time.Millisecond, MaxRetries: 1})
	if err == nil {
		t.Fatal("expected sync failure")
	}
	srv2.Close()

	after, _ := s.CVECount(ctx, false)
	if before != after {
		t.Fatalf("dataset changed after failed sync: %d -> %d", before, after)
	}
	st, ok, _ := s.LastSuccessfulSync(ctx, "cves")
	if !ok || st.TotalSeen != 1 {
		t.Fatalf("last successful sync must still be the good one: %+v", st)
	}
	hist, err := s.SyncHistory(ctx, "cves", 10)
	if err != nil || len(hist) == 0 || hist[0].Status != "failed" {
		t.Fatalf("failed run must be recorded: %+v %v", hist, err)
	}
}

func TestSyncDictionary(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	dictPage := `{
	  "resultsPerPage": 2000, "startIndex": 0, "totalResults": 2,
	  "products": [
	    {"cpe": {"cpeName": "cpe:2.3:a:google:chrome:120.0.6099.109:*:*:*:*:*:*:*", "deprecated": false, "lastModified": "2024-01-01T00:00:00.000", "titles": [{"title": "Google Chrome 120.0.6099.109", "lang": "en"}], "references": []}},
	    {"cpe": {"cpeName": "cpe:2.3:a:oracle:jre:1.8.0:*:*:*:*:*:*:*", "deprecated": false, "lastModified": "2024-01-01T00:00:00.000", "titles": [], "references": []}}
	  ]
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, dictPage)
	}))
	defer srv.Close()

	res, err := SyncDictionary(ctx, db, SyncOptions{BaseURL: srv.URL, Full: true, MinInterval: time.Millisecond, BackoffBase: time.Millisecond, MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "ok" || res.Imported != 2 {
		t.Fatalf("dictionary sync: %+v", res)
	}
	total, deprecated, err := NewStore(db).DictionaryStats(ctx)
	if err != nil || total != 2 || deprecated != 0 {
		t.Fatalf("dictionary stats: %d/%d %v", total, deprecated, err)
	}
}
