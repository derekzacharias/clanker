package msrc

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "intel.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

// Sync imports the requested number of monthly security bundles, records what it skipped, and
// refuses release notes and unrelated documents.
func TestSyncImportsSecurityBundlesAndReportsSkips(t *testing.T) {
	sv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/updates"):
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]string{
				{"ID": "2026-Dec", "DocumentTitle": "December 2026 Security Updates", "InitialReleaseDate": "2026-12-10", "CvrfUrl": sv_URL(r) + "/cvrf/2026-Dec"},
				{"ID": "2026-Nov", "DocumentTitle": "November 2026 Security Updates", "InitialReleaseDate": "2026-11-10", "CvrfUrl": sv_URL(r) + "/cvrf/2026-Nov"},
				{"ID": "2026-Oct", "DocumentTitle": "October 2026 Security Updates", "InitialReleaseDate": "2026-10-10", "CvrfUrl": sv_URL(r) + "/cvrf/2026-Oct"},
				{"ID": "2026-Sep", "DocumentTitle": "September 2026 Security Updates", "InitialReleaseDate": "2026-09-10", "CvrfUrl": sv_URL(r) + "/cvrf/2026-Sep"},
				{"ID": "1999-Sep", "DocumentTitle": "Mariner Release Notes", "InitialReleaseDate": "1999-09-02", "CvrfUrl": sv_URL(r) + "/cvrf/1999-Sep"},
			}})
		case strings.Contains(r.URL.Path, "/cvrf/2026-Dec"):
			_, _ = w.Write([]byte(strings.ReplaceAll(fixture, "2026-Dec", "2026-Dec")))
		case strings.Contains(r.URL.Path, "/cvrf/2026-Nov"):
			_, _ = w.Write([]byte(strings.ReplaceAll(fixture, "CVE-2026-40001", "CVE-2026-40009")))
		default:
			_, _ = w.Write([]byte(fixture))
		}
	}))
	defer sv.Close()

	db := testDB(t)
	state, err := Sync(context.Background(), db, SyncOptions{Months: 2, IndexURL: sv.URL})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if state.Documents != 2 || state.Available != 4 {
		t.Fatalf("documents = %d of %d available", state.Documents, state.Available)
	}
	// The bound must be stated, not silent.
	if len(state.Skipped) != 2 {
		t.Fatalf("skipped = %v, want the two older bundles named", state.Skipped)
	}
	if state.CVE < 2 {
		t.Fatalf("cves = %d", state.CVE)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM msrc_cves`).Scan(&n); err != nil || n < 2 {
		t.Fatalf("stored cves = %d, %v", n, err)
	}
	// The last sync is readable for health reporting.
	last, ok := LastSync(db)
	if !ok || last.Documents != 2 {
		t.Fatalf("last sync = %+v ok=%v", last, ok)
	}
}

// A failed document must not silently look like a successful import of "no vulnerabilities".
func TestSyncRecordsFailedDocuments(t *testing.T) {
	sv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/updates") {
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]string{
				{"ID": "2026-Dec", "DocumentTitle": "December 2026 Security Updates", "CvrfUrl": sv_URL(r) + "/cvrf/broken"},
			}})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer sv.Close()

	db := testDB(t)
	_, err := Sync(context.Background(), db, SyncOptions{Months: 1, IndexURL: sv.URL})
	if err == nil {
		t.Fatal("sync reported success while every document failed")
	}
	last, ok := LastSync(db)
	if !ok || last.Error == "" {
		t.Fatalf("failure was not recorded: %+v", last)
	}
}

// Windows product matching must separate releases and architectures, and must refuse to guess
// when the OS name is not one Microsoft publishes.
func TestWindowsProductMatch(t *testing.T) {
	match, notes := WindowsProductMatch("Windows 11 Pro", "24H2", "amd64")
	if len(notes) != 0 {
		t.Fatalf("notes = %v", notes)
	}
	positives := []string{
		"Windows 11 Version 24H2 for x64-based Systems",
		"Windows 11 Version 24H2 for 64-bit Systems",
	}
	for _, p := range positives {
		if !match(p) {
			t.Fatalf("%q should match a 24H2 x64 host", p)
		}
	}
	negatives := []string{
		"Windows 10 Version 22H2 for x64-based Systems",   // wrong family
		"Windows 11 Version 23H2 for x64-based Systems",   // wrong release
		"Windows 11 Version 24H2 for ARM64-based Systems", // wrong architecture
		"Windows Server 2022",
	}
	for _, p := range negatives {
		if match(p) {
			t.Fatalf("%q should not match a 24H2 x64 host", p)
		}
	}
	if _, notes := WindowsProductMatch("AcmeOS", "1.0", "amd64"); len(notes) == 0 {
		t.Fatal("an unsupported OS name must produce a coverage note")
	}
}

func TestNormalizeKB(t *testing.T) {
	cases := map[string]string{"5044284": "KB5044284", "KB5044284": "KB5044284", "kb 5044284": "KB5044284", "nope": "", "123": ""}
	for in, want := range cases {
		if got := NormalizeKB(in); got != want {
			t.Fatalf("NormalizeKB(%q) = %q, want %q", in, got, want)
		}
	}
}

func sv_URL(r *http.Request) string { return "http://" + r.Host }
