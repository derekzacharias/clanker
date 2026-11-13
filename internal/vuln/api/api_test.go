package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/inventory"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
)

// fixtureRoot is a fake Ubuntu endpoint with one vulnerable and one fixed package.
func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"etc", "var/lib/dpkg"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	osRelease := "PRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nID_LIKE=debian\n"
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(osRelease), 0o644); err != nil {
		t.Fatal(err)
	}
	status := "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nSource: openssl\nVersion: 3.0.11-0ubuntu3.1\n" +
		"\nPackage: curl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 8.5.0-2ubuntu10.16\n" +
		"\nPackage: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.2.21-2ubuntu4\n"
	if err := os.WriteFile(filepath.Join(root, "var/lib/dpkg/status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func seedCache(t *testing.T, cachePath string) {
	t.Helper()
	store, err := intel.OpenStore(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	adv := intel.Advisory{
		ID: "UBUNTU-CVE-2026-0001", Source: "Ubuntu",
		Affected: []intel.Affected{{
			Ecosystem: "Ubuntu:24.04:LTS", Name: "openssl",
			Versions: []string{"3.0.11-0ubuntu3.1", "3.0.11-0ubuntu3.2"},
		}},
		Severities: []intel.SeverityEntry{{Type: "Ubuntu", Score: "high"}},
		References: []intel.Reference{{Type: "ADVISORY", URL: "https://ubuntu.com/security/CVE-2026-0001"}},
		FetchedAt:  time.Now().UTC(),
	}
	if err := store.SaveAdvisories(ctx, []intel.Advisory{adv}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveKEV(ctx, []intel.KEVEntry{{CVEID: "CVE-2026-0001", DateAdded: "2026-11-01"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveEPSS(ctx, []intel.EPSSEntry{{CVE: "CVE-2026-0001", Score: 0.42, Percentile: 0.9}}, 10); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordSync(ctx, "KEV", 1, "test"); err != nil {
		t.Fatal(err)
	}
}

// seedRun performs a real (offline) assessment against the fixture endpoint so
// the API tests read genuine reports rather than hand-written JSON.
func seedRun(t *testing.T, cachePath, root string) {
	t.Helper()
	if _, err := scan.Run(context.Background(), scan.Options{
		Root:       root,
		CachePath:  cachePath,
		Offline:    true,
		Format:     "json",
		SkipRender: true,
		Collectors: []inventory.Collector{&inventory.OSPackageCollector{}},
		Stderr:     io.Discard,
		Now:        func() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) },
	}); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
}

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	cachePath := filepath.Join(t.TempDir(), "intel.db")
	seedCache(t, cachePath)
	srv, err := New(Options{CachePath: cachePath, ToolVersion: "test-1.0", Now: func() time.Time {
		return time.Date(2026, 11, 13, 13, 0, 0, 0, time.UTC)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, cachePath
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any, out any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if out != nil && rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s %s: response is not JSON: %v\n%s", method, path, err, rec.Body.String())
		}
	}
	return rec
}

func TestMetaAdvertisesCapabilitiesHonestly(t *testing.T) {
	srv, _ := newTestServer(t)
	var meta struct {
		Capabilities map[string]bool `json:"capabilities"`
		Release      struct {
			Published bool   `json:"published"`
			BaseURL   string `json:"base_url"`
		} `json:"release"`
	}
	if rec := doJSON(t, srv.Handler(), "GET", "/api/meta", nil, &meta); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if meta.Capabilities["network_scan"] || meta.Capabilities["sbom_scan"] || meta.Capabilities["llm"] {
		t.Fatalf("unimplemented capabilities must not be advertised as available: %+v", meta.Capabilities)
	}
	if !meta.Capabilities["local_scan"] {
		t.Fatal("local scanning should be advertised")
	}
	if meta.Release.Published {
		t.Fatal("no release base configured: published must be false so the UI never shows fake commands")
	}
}

func TestOverviewWithNoDataDoesNotFabricateMetrics(t *testing.T) {
	srv, _ := newTestServer(t)
	var ov overviewResponse
	if rec := doJSON(t, srv.Handler(), "GET", "/api/overview", nil, &ov); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if ov.HasData {
		t.Fatal("empty store must report no data")
	}
	if ov.Metrics.Assets != 0 || ov.Metrics.Critical != 0 || ov.Metrics.KEV != 0 {
		t.Fatalf("metrics must be zero without assessments: %+v", ov.Metrics)
	}
}

func TestOverviewAfterScan(t *testing.T) {
	srv, cachePath := newTestServer(t)
	seedRun(t, cachePath, fixtureRoot(t))

	var ov overviewResponse
	if rec := doJSON(t, srv.Handler(), "GET", "/api/overview", nil, &ov); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if !ov.HasData || ov.Metrics.Assets != 1 {
		t.Fatalf("unexpected overview: hasData=%v assets=%d", ov.HasData, ov.Metrics.Assets)
	}
	if ov.Metrics.Critical+ov.Metrics.High+ov.Metrics.Medium+ov.Metrics.Low == 0 {
		t.Fatalf("expected severity counts: %+v", ov.Metrics)
	}
	if ov.Metrics.KEV != 1 {
		t.Fatalf("KEV enrichment missing from overview: %+v", ov.Metrics)
	}
	if len(ov.Priority) == 0 {
		t.Fatal("priority findings missing")
	}
	if ov.Priority[0].Asset == "" || ov.Priority[0].CVE == "" {
		t.Fatalf("priority rows need asset and CVE: %+v", ov.Priority[0])
	}
	if ov.Coverage.Assessed != 1 || ov.Coverage.LastScanAt == "" {
		t.Fatalf("coverage wrong: %+v", ov.Coverage)
	}
	if len(ov.Severity) != 5 {
		t.Fatalf("severity distribution must include every bucket: %+v", ov.Severity)
	}
}

func TestVulnerabilityFilteringAndDetail(t *testing.T) {
	srv, cachePath := newTestServer(t)
	seedRun(t, cachePath, fixtureRoot(t))
	h := srv.Handler()

	var list vulnListResponse
	if rec := doJSON(t, h, "GET", "/api/vulnerabilities", nil, &list); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if list.Total == 0 || len(list.Items) == 0 {
		t.Fatal("expected findings")
	}
	for _, item := range list.Items {
		if item.Affected == "not_affected" {
			t.Fatal("not_affected records must be excluded by default")
		}
	}

	// severity filter
	if rec := doJSON(t, h, "GET", "/api/vulnerabilities?severity=high", nil, &list); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	for _, item := range list.Items {
		if item.Severity != "high" {
			t.Fatalf("severity filter leaked %q", item.Severity)
		}
	}

	// KEV filter
	doJSON(t, h, "GET", "/api/vulnerabilities?kev=true", nil, &list)
	if list.Total != 1 || !list.Items[0].KEV {
		t.Fatalf("KEV filter wrong: total=%d", list.Total)
	}

	// text search on the CVE
	doJSON(t, h, "GET", "/api/vulnerabilities?q=CVE-2026-0001", nil, &list)
	if list.Total != 1 {
		t.Fatalf("search failed: total=%d", list.Total)
	}

	// pagination
	doJSON(t, h, "GET", "/api/vulnerabilities?limit=1", nil, &list)
	if len(list.Items) != 1 || list.Total < 1 {
		t.Fatalf("pagination wrong: items=%d total=%d", len(list.Items), list.Total)
	}

	// detail carries evidence and authoritative links
	var detail vulnRow
	if rec := doJSON(t, h, "GET", "/api/vulnerabilities/"+list.Items[0].ID, nil, &detail); rec.Code != 200 {
		t.Fatalf("detail status %d", rec.Code)
	}
	if len(detail.Evidence) == 0 || detail.Explanation == "" {
		t.Fatalf("detail must expose evidence and explanation: %+v", detail)
	}
	var nvd, osv bool
	for _, ref := range detail.References {
		if strings.Contains(ref.URL, "nvd.nist.gov") {
			nvd = true
		}
		if strings.Contains(ref.URL, "osv.dev") {
			osv = true
		}
	}
	if !nvd || !osv {
		t.Fatalf("expected NVD and OSV references: %+v", detail.References)
	}

	if rec := doJSON(t, h, "GET", "/api/vulnerabilities/does-not-exist", nil, &detail); rec.Code != 404 {
		t.Fatalf("unknown finding should 404, got %d", rec.Code)
	}
}

func TestAssetEndpoints(t *testing.T) {
	srv, cachePath := newTestServer(t)
	seedRun(t, cachePath, fixtureRoot(t))
	h := srv.Handler()

	var assets struct {
		Items []assetRow `json:"items"`
	}
	if rec := doJSON(t, h, "GET", "/api/assets", nil, &assets); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if len(assets.Items) != 1 || assets.Items[0].Packages != 3 {
		t.Fatalf("unexpected assets: %+v", assets.Items)
	}

	var detail struct {
		Host     string             `json:"host"`
		Packages []packageRow       `json:"packages"`
		Findings []vulnRow          `json:"findings"`
		History  []intel.RunSummary `json:"history"`
		Coverage coverageView       `json:"coverage"`
	}
	if rec := doJSON(t, h, "GET", "/api/assets/"+assets.Items[0].Host, nil, &detail); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if detail.Host == "" || len(detail.Packages) != 3 || len(detail.Findings) == 0 || len(detail.History) == 0 {
		t.Fatalf("asset detail incomplete: %+v", detail)
	}
	if rec := doJSON(t, h, "GET", "/api/assets/nope", nil, &detail); rec.Code != 404 {
		t.Fatalf("unknown asset should 404, got %d", rec.Code)
	}
}

func TestScanWorkflowLocalAndRefusalForUnimplemented(t *testing.T) {
	srv, _ := newTestServer(t)
	root := fixtureRoot(t)
	// Stub the runner so the job exercises the API plumbing without touching
	// the real host.
	srv.opts.RunScan = func(ctx context.Context, opts scan.Options) (scan.Result, error) {
		opts.Root = root
		opts.Offline = true
		opts.SkipRender = true
		opts.Collectors = []inventory.Collector{&inventory.OSPackageCollector{}}
		opts.Stderr = io.Discard
		if opts.Progress != nil {
			opts.Progress(scan.Stage{Name: "matching", Percent: 70, Detail: "3 packages"})
		}
		return scan.Run(ctx, opts)
	}
	h := srv.Handler()

	// network and sbom must be refused with an explanation, not silently ignored
	for _, kind := range []string{"network", "sbom"} {
		rec := doJSON(t, h, "POST", "/api/scans", map[string]any{"kind": kind}, nil)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("%s scan should be 422, got %d", kind, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "not implemented") {
			t.Fatalf("%s refusal must explain itself: %s", kind, rec.Body.String())
		}
	}
	rec := doJSON(t, h, "POST", "/api/scans", map[string]any{"kind": "carrier-pigeon"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown kind should be 400, got %d", rec.Code)
	}

	var job intel.Job
	if rec := doJSON(t, h, "POST", "/api/scans", map[string]any{"kind": "local", "offline": true, "fail_on": "high"}, &job); rec.Code != http.StatusAccepted {
		t.Fatalf("start scan status %d: %s", rec.Code, rec.Body.String())
	}
	if job.ID == "" {
		t.Fatal("job id missing")
	}

	deadline := time.Now().Add(20 * time.Second)
	var detail struct {
		Job             *intel.Job      `json:"job"`
		ReportAvailable bool            `json:"report_available"`
		Report          json.RawMessage `json:"report"`
	}
	for {
		doJSON(t, h, "GET", "/api/scans/"+job.ID, nil, &detail)
		if detail.Job != nil && detail.Job.Status == intel.JobDone {
			break
		}
		if detail.Job != nil && detail.Job.Status == intel.JobFailed {
			t.Fatalf("job failed: %s", detail.Job.Error)
		}
		if time.Now().After(deadline) {
			t.Fatalf("job did not finish: %+v", detail.Job)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !detail.ReportAvailable || len(detail.Report) == 0 {
		t.Fatal("completed job should expose its report")
	}
	var rep struct {
		Findings []json.RawMessage `json:"findings"`
		Metadata struct {
			Host string `json:"host"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(detail.Report, &rep); err != nil {
		t.Fatalf("report unreadable: %v", err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("report has no findings")
	}
}

func TestReportsAndExport(t *testing.T) {
	srv, cachePath := newTestServer(t)
	seedRun(t, cachePath, fixtureRoot(t))
	h := srv.Handler()

	var reports struct {
		Items []intel.RunSummary `json:"items"`
	}
	if rec := doJSON(t, h, "GET", "/api/reports", nil, &reports); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if len(reports.Items) != 1 {
		t.Fatalf("expected one report, got %d", len(reports.Items))
	}
	id := reports.Items[0].ID

	req := httptest.NewRequest("GET", "/api/reports/"+id, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "schema_version") {
		t.Fatalf("report fetch failed: %d", rec.Code)
	}

	for _, format := range []string{"markdown", "sarif", "html"} {
		req := httptest.NewRequest("GET", "/api/reports/"+id+"/export?format="+format, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 || rec.Body.Len() < 100 {
			t.Fatalf("%s export failed: %d (%d bytes)", format, rec.Code, rec.Body.Len())
		}
		if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
			t.Fatalf("export should be a download: %q", cd)
		}
	}
	req = httptest.NewRequest("GET", "/api/reports/"+id+"/export?format=pdf", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported format should be 400, got %d", rec.Code)
	}
	if rec := doJSON(t, h, "GET", "/api/reports/nope", nil, nil); rec.Code != 404 {
		t.Fatalf("unknown report should 404, got %d", rec.Code)
	}
}

func TestAskIsGroundedAndCitesFindings(t *testing.T) {
	srv, cachePath := newTestServer(t)
	seedRun(t, cachePath, fixtureRoot(t))

	var resp struct {
		Answer    string `json:"answer"`
		Citations []struct {
			CVE string `json:"cve"`
			ID  string `json:"id"`
		} `json:"citations"`
		Grounding struct {
			LLMUsed bool   `json:"llm_used"`
			Report  string `json:"report_id"`
		} `json:"grounding"`
	}
	if rec := doJSON(t, srv.Handler(), "POST", "/api/ask", map[string]string{"question": "what should I patch first?"}, &resp); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if resp.Answer == "" || len(resp.Citations) == 0 {
		t.Fatalf("answer must cite findings: %+v", resp)
	}
	if resp.Grounding.LLMUsed || resp.Grounding.Report == "" {
		t.Fatalf("grounding must be explicit: %+v", resp.Grounding)
	}
	if rec := doJSON(t, srv.Handler(), "POST", "/api/ask", map[string]string{}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty question should be 400, got %d", rec.Code)
	}
}

func TestSettingsPersistAndValidate(t *testing.T) {
	srv, _ := newTestServer(t)
	h := srv.Handler()

	var got map[string]any
	doJSON(t, h, "GET", "/api/settings", nil, &got)
	if got["cache_path"] == "" {
		t.Fatal("settings must expose the cache path")
	}

	if rec := doJSON(t, h, "PUT", "/api/settings", map[string]any{
		"policy": map[string]any{"fail_on": "high", "fail_on_kev": true},
	}, &got); rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	policy := got["policy"].(map[string]any)
	if policy["fail_on"] != "high" || policy["fail_on_kev"] != true {
		t.Fatalf("policy not persisted: %+v", policy)
	}

	if rec := doJSON(t, h, "PUT", "/api/settings", map[string]any{
		"policy": map[string]any{"fail_on": "catastrophic"},
	}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid policy should be 400, got %d", rec.Code)
	}
	if rec := doJSON(t, h, "PUT", "/api/settings", map[string]any{
		"release_base": "ftp://example.invalid/artifacts",
	}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid release base should be 400, got %d", rec.Code)
	}
}

func TestTokenEnforcement(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.opts.Token = "s3cret"
	h := srv.Handler()

	rec := doJSON(t, h, "GET", "/api/overview", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token should be 401, got %d", rec.Code)
	}
	req := httptest.NewRequest("GET", "/api/overview", nil)
	req.Header.Set("X-Guard-Token", "s3cret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("valid token should pass, got %d", rec.Code)
	}
}

func TestNonLoopbackRequiresToken(t *testing.T) {
	srv, _ := newTestServer(t)
	if err := srv.Listen("0.0.0.0:0"); err == nil || !strings.Contains(err.Error(), "CLANKER_GUARD_TOKEN") {
		t.Fatalf("0.0.0.0 without token must be refused, got %v", err)
	}
}

func TestStaticFallbackExplainsBuildStep(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "npm run build") {
		t.Fatalf("missing build should render instructions: %d", rec.Code)
	}
}

func TestFeedsEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	var resp struct {
		Feeds  []feedRow `json:"feeds"`
		Counts struct {
			KEV int `json:"kev"`
		} `json:"counts"`
	}
	if rec := doJSON(t, srv.Handler(), "GET", "/api/feeds", nil, &resp); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if len(resp.Feeds) == 0 || resp.Counts.KEV != 1 {
		t.Fatalf("feed status wrong: %+v", resp)
	}
}
