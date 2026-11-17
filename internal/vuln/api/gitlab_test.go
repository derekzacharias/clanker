package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/report"
)

// fakeGitLabAPI is the smallest GitLab that the integration talks to. It exists so these
// tests exercise the real client, the real renderer and the real store over HTTP.
type fakeGitLabAPI struct {
	mu        sync.Mutex
	createHit int
	searchHit int
	version   int
}

func (f *fakeGitLabAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v4/version"):
			_, _ = w.Write([]byte(`{"version":"19.5.5","revision":"abc"}`))
		case strings.HasSuffix(r.URL.Path, "/api/v4/user"):
			_, _ = w.Write([]byte(`{"id":7,"username":"guard-bot","name":"Guard Bot"}`))
		case strings.Contains(r.URL.Path, "/api/v4/users"):
			_, _ = w.Write([]byte(`[{"id":7,"username":"guard-bot","name":"Guard Bot"}]`))
		case strings.Contains(r.URL.Path, "/issues") && r.Method == http.MethodPost:
			f.createHit++
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			title, _ := body["title"].(string)
			out, _ := json.Marshal(map[string]any{
				"id": 5001, "iid": 42, "project_id": 42, "state": "opened",
				"title":       title,
				"web_url":     "http://gitlab.test.intra:8929/platform/security/-/issues/42",
				"description": body["description"],
				"labels":      strings.Split(asString(body["labels"]), ","),
			})
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(out)
		case strings.Contains(r.URL.Path, "/issues") && r.Method == http.MethodGet:
			f.searchHit++
			_, _ = w.Write([]byte(`[]`))
		case strings.Contains(r.URL.Path, "/api/v4/projects/42"):
			_, _ = w.Write([]byte(`{"id":42,"name":"security","path_with_namespace":"platform/security",
				"web_url":"http://gitlab.test.intra:8929/platform/security","issues_enabled":true,
				"permissions":{"project_access":{"access_level":40}}}`))
		case strings.Contains(r.URL.Path, "/api/v4/projects"):
			_, _ = w.Write([]byte(`[{"id":42,"name":"security","path_with_namespace":"platform/security",
				"web_url":"http://gitlab.test.intra:8929/platform/security","issues_enabled":true}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"404 Not Found"}`))
		}
	})
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

// gitlabServer is a dashboard server with an isolated GitLab config file and a fake
// GitLab instance behind it.
func gitlabServer(t *testing.T) (*Server, *fakeGitLabAPI, string) {
	t.Helper()
	fake := &fakeGitLabAPI{}
	gl := httptest.NewServer(fake.handler())
	t.Cleanup(gl.Close)
	srv, err := New(Options{DisableBackgroundJobs: true,
		CachePath:   filepath.Join(t.TempDir(), "intel.db"),
		ToolVersion: "0.1.0",
		Token:       "dash-token",
		GitLabPath:  filepath.Join(t.TempDir(), "gitlab.json"),
		// No inherited environment: a developer's real GITLAB_TOKEN must not leak in.
		Getenv: func(string) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, fake, gl.URL
}

// configureGitLab writes a working configuration pointing at the fake instance.
func configureGitLab(t *testing.T, srv *Server, baseURL string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"enabled": true, "url": baseURL, "token": "glpat-test-token",
		"project_id": 42, "labels": []string{"security", "team-infra"},
		"allow_insecure_http": true,
	})
	if rec := request(t, srv.Handler(), "PUT", "/api/integrations/gitlab", string(body), dash()); rec.Code != 200 {
		t.Fatalf("configure gitlab = %d: %s", rec.Code, rec.Body.String())
	}
}

// seedFinding stores one rich assessment and returns the dataset id of its only finding.
// It goes through the same ingest path the agent uses, so the ticket text is built from
// real stored evidence rather than a fixture shaped for the test.
func seedFinding(t *testing.T, srv *Server) string {
	t.Helper()
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	rep := model.Report{
		SchemaVersion: "1",
		ReportID:      "SCAN-GL-1",
		Metadata: model.ScanMetadata{
			ToolVersion: "test", StartedAt: now.Add(-time.Minute), FinishedAt: &now,
			Mode: "local", Host: "web01",
		},
		Inventory: model.Inventory{Asset: model.Asset{
			Hostname: "web01", OS: "Ubuntu", OSVersion: "22.04", Kernel: "5.15", Arch: "amd64",
		}},
		Findings: []model.Finding{{
			FindingID: "F-GL-1", Asset: "web01", Product: "openssl", InstalledVersion: "3.0.2",
			Ecosystem: "Ubuntu:22.04", VulnerabilityID: "CVE-2026-1234", Severity: "high",
			Source: "Ubuntu USN-6000-1", Affected: model.ApplicabilityConfirmed,
			Confidence:  model.ConfidenceHigh,
			Explanation: "Installed version is inside the affected range.",
			Remediation: "Upgrade to 3.0.13-1ubuntu1.", FixedVersion: "3.0.13-1ubuntu1",
			Evidence: []model.Evidence{{Kind: "installed_version", Source: "dpkg", Detail: "openssl 3.0.2 installed"}},
		}},
	}
	payload, err := report.MarshalJSON(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if err := srv.store.SaveRun(t.Context(), model.RunRecord{
		ID: rep.ReportID, Host: "web01", StartedAt: rep.Metadata.StartedAt, FinishedAt: now,
		FindingCount: 1, Actionable: 1,
	}, payload); err != nil {
		t.Fatalf("SaveRun: %v", err)
	}
	ds, err := srv.buildDataset(t.Context())
	if err != nil {
		t.Fatalf("buildDataset: %v", err)
	}
	if len(ds.Vulns) == 0 {
		t.Fatal("the seeded report produced no findings")
	}
	return ds.Vulns[0].ID
}

func TestGitLabConfigNeverReturnsTheTokenAndRejectsUnsafeURLs(t *testing.T) {
	srv, _, _ := gitlabServer(t)
	h := srv.Handler()

	var initial map[string]any
	dashGet(t, h, "/api/integrations/gitlab", &initial)
	if initial["token_set"] != false || initial["enabled"] != false || initial["ready"] != false {
		t.Fatalf("initial state = %+v", initial)
	}

	// A public host over plain HTTP would put the token on the wire.
	rec := request(t, h, "PUT", "/api/integrations/gitlab",
		`{"url":"http://gitlab.example.com","allow_insecure_http":true,"token":"glpat-x"}`, dash())
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "gitlab_url_rejected") {
		t.Fatalf("public http accepted: %d %s", rec.Code, rec.Body.String())
	}

	// A valid configuration saves, and the response still does not contain the token.
	configureGitLab(t, srv, "http://127.0.0.1:8929")
	var saved map[string]any
	dashGet(t, h, "/api/integrations/gitlab", &saved)
	if saved["token_set"] != true || saved["ready"] != true || saved["project_id"].(float64) != 42 {
		t.Fatalf("saved state = %+v", saved)
	}
	body := rec.Body.String()
	_ = body
	raw, _ := json.Marshal(saved)
	if strings.Contains(string(raw), "glpat-test-token") {
		t.Fatal("the API returned the access token")
	}
	if _, ok := saved["token"]; ok {
		t.Fatal("the API response has a token field")
	}
}

func TestGitLabTestConnectionReportsChecksWithoutCreatingIssues(t *testing.T) {
	srv, fake, baseURL := gitlabServer(t)
	configureGitLab(t, srv, baseURL)

	var res struct {
		OK              bool `json:"ok"`
		CanCreateIssues bool `json:"can_create_issues"`
		Version         string
		User            string
		Checks          []struct {
			Name string
			OK   bool
		}
		Summary string
	}
	rec := request(t, srv.Handler(), "POST", "/api/integrations/gitlab/test", "{}", dash())
	if rec.Code != 200 {
		t.Fatalf("test = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !res.OK || !res.CanCreateIssues || res.Version != "19.5.5" || res.User != "guard-bot" {
		t.Fatalf("test result = %+v", res)
	}
	if len(res.Checks) != 5 {
		t.Fatalf("checks = %+v", res.Checks)
	}
	if !strings.Contains(res.Summary, "no issue was created") {
		t.Fatalf("summary must not claim a creation test: %q", res.Summary)
	}
	if fake.createHit != 0 {
		t.Fatalf("Test Connection created %d issues", fake.createHit)
	}

	// The outcome is recorded, so the panel can say when it was last proven.
	var after map[string]any
	dashGet(t, srv.Handler(), "/api/integrations/gitlab", &after)
	if after["verified_at"] == nil || after["verify_ok"] != true {
		t.Fatalf("verification was not recorded: %+v", after)
	}
}

// The primary feature: one finding becomes one issue, and asking twice does not create a
// second one.
func TestGitLabCreateTicketStoresTheIssueAndPreventsDuplicates(t *testing.T) {
	srv, fake, baseURL := gitlabServer(t)
	configureGitLab(t, srv, baseURL)
	findingID := seedFinding(t, srv)

	body, _ := json.Marshal(map[string]any{"finding_id": findingID})
	rec := request(t, srv.Handler(), "POST", "/api/integrations/gitlab/tickets", string(body), dash())
	if rec.Code != 200 {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Created bool `json:"created"`
		Reused  bool `json:"reused"`
		Ticket  struct {
			ID         string `json:"id"`
			IssueIID   int    `json:"issue_iid"`
			IssueURL   string `json:"issue_url"`
			State      string `json:"state"`
			ProjectID  int    `json:"project_id"`
			CreatedBy  string `json:"created_by"`
			FindingKey string `json:"finding_key"`
		} `json:"ticket"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !created.Created || created.Reused {
		t.Fatalf("result = %+v", created)
	}
	if created.Ticket.IssueIID != 42 || !strings.Contains(created.Ticket.IssueURL, "/issues/42") {
		t.Fatalf("ticket = %+v", created.Ticket)
	}
	if created.Ticket.State != "opened" || created.Ticket.CreatedBy != "api-token" {
		t.Fatalf("ticket = %+v", created.Ticket)
	}

	// The second request must reuse, not create.
	rec = request(t, srv.Handler(), "POST", "/api/integrations/gitlab/tickets", string(body), dash())
	if rec.Code != 200 {
		t.Fatalf("second create = %d: %s", rec.Code, rec.Body.String())
	}
	var second struct {
		Reused bool `json:"reused"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &second)
	if !second.Reused {
		t.Fatalf("second create = %s", rec.Body.String())
	}
	if fake.createHit != 1 {
		t.Fatalf("GitLab received %d creation requests, want 1", fake.createHit)
	}

	// The finding detail now carries the ticket, so the panel shows the issue instead of
	// offering to create another.
	var detail struct {
		GitLabTickets []struct {
			IssueIID int    `json:"issue_iid"`
			IssueURL string `json:"issue_url"`
		} `json:"gitlab_tickets"`
	}
	dashGet(t, srv.Handler(), "/api/vulnerabilities/"+findingID, &detail)
	if len(detail.GitLabTickets) != 1 || detail.GitLabTickets[0].IssueIID != 42 {
		t.Fatalf("finding detail tickets = %+v", detail.GitLabTickets)
	}
}

func TestGitLabPreviewRendersWithoutContactingGitLab(t *testing.T) {
	srv, fake, baseURL := gitlabServer(t)
	configureGitLab(t, srv, baseURL)
	findingID := seedFinding(t, srv)

	body, _ := json.Marshal(map[string]any{"finding_id": findingID})
	var preview struct {
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Labels      []string `json:"labels"`
	}
	rec := request(t, srv.Handler(), "POST", "/api/integrations/gitlab/preview", string(body), dash())
	if rec.Code != 200 {
		t.Fatalf("preview = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &preview); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(preview.Title, "CVE-2026-1234") || !strings.Contains(preview.Title, "web01") {
		t.Fatalf("title = %q", preview.Title)
	}
	for _, want := range []string{"## Affected system", "Ubuntu 22.04", "openssl", "3.0.2", "## Step 3: Verify the fix", "Clanker Guard"} {
		if !strings.Contains(preview.Description, want) {
			t.Fatalf("description is missing %q:\n%s", want, preview.Description)
		}
	}
	if fake.createHit != 0 || fake.searchHit != 0 {
		t.Fatal("preview must not talk to GitLab")
	}
}

// Ticket creation is a state change and must be behind the dashboard credential.
func TestGitLabTicketEndpointsRequireAuthentication(t *testing.T) {
	srv, _, baseURL := gitlabServer(t)
	configureGitLab(t, srv, baseURL)
	findingID := seedFinding(t, srv)
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/integrations/gitlab", ""},
		{"PUT", "/api/integrations/gitlab", `{"enabled":true}`},
		{"POST", "/api/integrations/gitlab/test", "{}"},
		{"POST", "/api/integrations/gitlab/preview", `{"finding_id":"` + findingID + `"}`},
		{"POST", "/api/integrations/gitlab/tickets", `{"finding_id":"` + findingID + `"}`},
	} {
		rec := request(t, srv.Handler(), tc.method, tc.path, tc.body, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without credentials = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
}

// An unconfigured integration must fail closed with an actionable message, not 500.
func TestCreatingATicketBeforeConfigurationExplainsWhatIsMissing(t *testing.T) {
	srv, _, _ := gitlabServer(t)
	findingID := seedFinding(t, srv)
	body, _ := json.Marshal(map[string]any{"finding_id": findingID})
	rec := request(t, srv.Handler(), "POST", "/api/integrations/gitlab/tickets", string(body), dash())
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "gitlab_not_configured") {
		t.Fatalf("unconfigured create = %d %s", rec.Code, rec.Body.String())
	}
}

// A token in the environment is used without ever being written to the file, and the API
// says where it came from so the operator can find it again.
func TestTokenFromEnvironmentIsReportedWithoutBeingExposed(t *testing.T) {
	srv, _, baseURL := gitlabServer(t)
	srv.getenv = func(k string) string {
		switch k {
		case "GITLAB_TOKEN":
			return "glpat-from-env"
		case "GITLAB_URL":
			return baseURL
		case "GITLAB_PROJECT_ID":
			return "42"
		case "GITLAB_ALLOW_INSECURE_HTTP", "GITLAB_ENABLED":
			return "true"
		}
		return ""
	}
	var view map[string]any
	dashGet(t, srv.Handler(), "/api/integrations/gitlab", &view)
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), "glpat-from-env") {
		t.Fatal("the environment token leaked into the API response")
	}
	if view["token_source"] != "environment" || view["token_set"] != true || view["ready"] != true {
		t.Fatalf("view = %+v", view)
	}
}
