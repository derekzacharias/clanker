package ticketing

import (
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// fakeGitLab is a small stand-in for /api/v4. It records what it was asked, so a test can
// assert on the request (method, path, token header, body) and not only the result.
type fakeGitLab struct {
	mu       sync.Mutex
	requests []recorded
	version  string
	// project payload returned for GET /projects/{id}
	project map[string]any
	// issue created by POST /projects/{id}/issues
	issue map[string]any
	// forced responses
	versionStatus int
	createStatus  int
	createBody    string
	createDelay   time.Duration
	searchResults []map[string]any
}

type recorded struct {
	Method, Path, Token string
	Body                map[string]any
}

func newFake() *fakeGitLab {
	return &fakeGitLab{
		version: "19.5.5",
		project: map[string]any{
			"id":                  42,
			"name":                "security",
			"path_with_namespace": "platform/security",
			"web_url":             "http://gitlab.test.intra:8929/platform/security",
			"issues_enabled":      true,
			"permissions":         map[string]any{"project_access": map[string]any{"access_level": 40}},
		},
	}
}

func (f *fakeGitLab) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		f.mu.Lock()
		f.requests = append(f.requests, recorded{Method: r.Method, Path: r.URL.RequestURI(),
			Token: r.Header.Get("PRIVATE-TOKEN"), Body: body})
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v4/version"):
			if f.versionStatus != 0 {
				w.WriteHeader(f.versionStatus)
				_, _ = w.Write([]byte(`{"message":"401 Unauthorized"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"version": f.version})
		case strings.HasSuffix(r.URL.Path, "/api/v4/user"):
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 7, "username": "guard-bot", "name": "Guard Bot"})
		case strings.Contains(r.URL.Path, "/issues") && r.Method == http.MethodPost:
			if f.createDelay > 0 {
				time.Sleep(f.createDelay)
			}
			if f.createStatus != 0 {
				w.WriteHeader(f.createStatus)
				if f.createBody != "" {
					_, _ = w.Write([]byte(f.createBody))
					return
				}
				_, _ = w.Write([]byte(`{"message":"403 Forbidden"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			out := map[string]any{
				"id": 1001, "iid": 42, "project_id": 42, "title": body["title"],
				"state": "opened", "web_url": "http://gitlab.test.intra:8929/platform/security/-/issues/42",
				"description": body["description"], "labels": strings.Split(str(body["labels"]), ","),
			}
			if f.issue != nil {
				for k, v := range f.issue {
					out[k] = v
				}
			}
			_ = json.NewEncoder(w).Encode(out)
		case strings.Contains(r.URL.Path, "/issues") && r.Method == http.MethodGet:
			// The listing endpoint answers an array; /issues/{iid} answers one object.
			if strings.HasSuffix(r.URL.Path, "/issues") {
				results := f.searchResults
				if results == nil {
					results = []map[string]any{}
				}
				_ = json.NewEncoder(w).Encode(results)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"iid": 42, "state": "closed",
				"web_url": "http://gitlab.test.intra:8929/platform/security/-/issues/42"})
		case strings.Contains(r.URL.Path, "/issues/") && r.Method == http.MethodPut:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": 1001, "iid": 42, "project_id": 42, "title": body["title"],
				"state": "opened", "web_url": "http://gitlab.test.intra:8929/platform/security/-/issues/42",
				"description": body["description"],
			})
		case strings.Contains(r.URL.Path, "/projects/"):
			if f.project == nil {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"404 Project Not Found"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(f.project)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"404 Not Found"}`))
		}
	})
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func (f *fakeGitLab) last() recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		return recorded{}
	}
	return f.requests[len(f.requests)-1]
}

func (f *fakeGitLab) count(method, contains string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r.Method == method && strings.Contains(r.Path, contains) {
			n++
		}
	}
	return n
}

// newServerWithFake wires a Client at a fake GitLab over plain HTTP on loopback, which is
// exactly the "internal test instance" case the client must allow.
func newServerWithFake(t *testing.T, f *fakeGitLab) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	client, err := NewClient(Config{
		BaseURL: srv.URL, Token: "test-token", ProjectID: 42,
		Timeout: 2 * time.Second, AllowInsecureHTTP: true,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client, srv
}

func newTicketStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	st, err := New(db)
	if err != nil {
		t.Fatalf("New store: %v", err)
	}
	now := time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC)
	st.SetClock(func() time.Time { return now })
	return st, &now
}

func testFinding() Finding {
	cvss := 9.8
	return Finding{
		FindingKey: "ab12cd34ef56", Asset: "web01", Hostname: "web01.prod", OS: "Ubuntu", OSVersion: "22.04",
		Product: "openssl", InstalledVersion: "3.0.2", Ecosystem: "Ubuntu:22.04",
		VulnerabilityID: "CVE-2026-1234", Severity: "high", EffectiveSeverity: "critical",
		CVSS: &cvss, KEV: true, Explanation: "Installed version is inside the affected range.",
		RemediationText: "Upgrade to 3.0.13-1ubuntu1.", RemediationOrigin: "advisory",
		RemediationSource: "Ubuntu USN-6000-1", FixedVersion: "3.0.13-1ubuntu1",
		Evidence:   []Evidence{{Kind: "installed_version", Source: "dpkg", Detail: "openssl 3.0.2 installed"}},
		References: []Reference{{Label: "USN-6000-1", URL: "https://ubuntu.com/security/USN-6000-1"}},
		FirstSeen:  "2026-03-01", LastSeen: "2026-03-04", ReportID: "SCAN-1",
		Team: "Infrastructure", Owner: "dana", DueAt: "2026-03-11", Priority: "P1",
	}
}
