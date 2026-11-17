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
	srv, err := New(Options{DisableBackgroundJobs: true, CachePath: cachePath, ToolVersion: "test-1.0", Now: func() time.Time {
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
	if meta.Capabilities["llm"] {
		t.Fatalf("unimplemented capabilities must not be advertised as available: %+v", meta.Capabilities)
	}
	// agent_push is implemented (agents enroll and upload reports), so it must be
	// advertised; when it was only a placeholder this assertion was the reverse.
	for _, cap := range []string{"local_scan", "network_scan", "sbom_scan", "agent_push"} {
		if !meta.Capabilities[cap] {
			t.Fatalf("%s is implemented and should be advertised: %+v", cap, meta.Capabilities)
		}
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

	// Network and SBOM modes are implemented, so the API now validates their
	// inputs instead of refusing the kind.
	rec := doJSON(t, h, "POST", "/api/scans", map[string]any{"kind": "network"}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "authorisation") {
		t.Fatalf("network scan without authorisation must be rejected: %d %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, "POST", "/api/scans", map[string]any{
		"kind": "network", "authorized": true,
		"scope_yaml": "name: t\nauthorized_by: x\nauthorized_at: 2026-01-01T00:00:00Z\ntargets: [127.0.0.1]\n",
		"targets":    []string{"10.9.9.9"},
	}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "outside the authorised scope") {
		t.Fatalf("out-of-scope target must be rejected: %d %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, "POST", "/api/scans", map[string]any{
		"kind": "network", "authorized": true,
		"scope_yaml": "name: old\nauthorized_by: x\nauthorized_at: 2026-01-01T00:00:00Z\nexpires_at: 2026-01-02T00:00:00Z\ntargets: [127.0.0.1]\n",
	}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("expired scope must be rejected: %d %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, "POST", "/api/scans", map[string]any{
		"kind": "sbom", "sbom_path": "/nonexistent/SBOM.json",
	}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not found") {
		t.Fatalf("missing SBOM must be rejected: %d %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, "POST", "/api/scans", map[string]any{
		"kind": "sbom", "sbom_path": t.TempDir(),
	}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "directory") {
		t.Fatalf("directory SBOM path must be rejected: %d %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, "POST", "/api/scans", map[string]any{"kind": "carrier-pigeon"}, nil)
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

// TestAgentInstallCommandsAreRealWhenAReleaseHostIsConfigured pins the contract
// the Settings → Agents screen relies on: with a release base configured, the
// commands must be copy-pasteable for every platform, and the Windows script
// must actually receive -Version (a plain `| iex` would drop it and fail).
func TestAgentInstallCommandsAreRealWhenAReleaseHostIsConfigured(t *testing.T) {
	const base = "https://github.com/derekzacharias/clanker-guard-agent/releases/download/v0.1.0"
	srv, err := New(Options{DisableBackgroundJobs: true,
		CachePath:   filepath.Join(t.TempDir(), "intel.db"),
		ToolVersion: "0.1.0",
		ReleaseBase: base,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	var out struct {
		Install struct {
			RequiresEnrollToken bool              `json:"requires_enroll_token"`
			MintEndpoint        string            `json:"mint_endpoint"`
			Published           bool              `json:"published"`
			Version             string            `json:"version"`
			BaseURL             string            `json:"base_url"`
			Commands            map[string]string `json:"commands"`
			OneoffCommands      map[string]string `json:"oneoff_commands"`
			KeepsAvailable      bool              `json:"keeps_available"`
			BuildSteps          []string          `json:"build_steps"`
		} `json:"install"`
		Fleet struct {
			ServerURL   string `json:"server_url"`
			EnrollToken string `json:"enroll_token"`
		} `json:"fleet"`
	}
	if rec := doJSON(t, srv.Handler(), "GET", "/api/agents", nil, &out); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	inst := out.Install
	if !inst.Published || inst.Version != "0.1.0" || inst.BaseURL != base {
		t.Fatalf("install block = %+v", inst)
	}
	// Commands are only rendered once a single-use token has been minted.
	if !inst.RequiresEnrollToken || inst.MintEndpoint == "" {
		t.Fatalf("install block should point at the mint endpoint: %+v", inst)
	}
	// No token yet: the command is still rendered, with a visible placeholder, so an
	// operator sees what they will paste before minting anything.
	if !strings.Contains(inst.Commands["linux"], "<enroll-token>") {
		t.Fatalf("command template is missing the token placeholder: %q", inst.Commands["linux"])
	}
	if strings.Contains(inst.Commands["linux"], "MINTED") {
		t.Fatalf("template must not carry a real token: %q", inst.Commands["linux"])
	}
	minted := request(t, srv.Handler(), "POST", inst.MintEndpoint, "", nil)
	if minted.Code != 200 {
		t.Fatalf("mint = %d: %s", minted.Code, minted.Body.String())
	}
	var mint struct {
		Token    string            `json:"enroll_token"`
		Commands map[string]string `json:"commands"`
	}
	if err := json.Unmarshal(minted.Body.Bytes(), &mint); err != nil {
		t.Fatal(err)
	}
	inst.Commands = mint.Commands
	// The command must also make the endpoint report back here: version, server
	// URL and the enrollment token, or "install" is only half the job.
	// The default command enrolls and installs the background service (no extra
	// flag), so an install from the dashboard leaves the endpoint reachable.
	want := "curl -fsSL " + base + "/install-agent.sh | bash -s -- --version 0.1.0 --server http://example.com --enroll-token " +
		mint.Token
	if inst.Commands["linux"] != want || inst.Commands["macos"] != want {
		t.Fatalf("linux/macos commands = %q / %q, want %q", inst.Commands["linux"], inst.Commands["macos"], want)
	}
	if mint.Token == "" || out.Fleet.ServerURL != "http://example.com" {
		t.Fatalf("fleet block = %+v mint=%+v", out.Fleet, mint)
	}
	win := inst.Commands["windows"]
	for _, needle := range []string{base + "/install-agent.ps1", "-Version 0.1.0", "install-agent.ps1", "-Server", "-EnrollToken", mint.Token} {
		if !strings.Contains(win, needle) {
			t.Fatalf("windows command %q is missing %q", win, needle)
		}
	}
	if strings.Contains(win, "| iex") {
		t.Fatalf("windows command pipes into iex, which cannot pass -Version: %q", win)
	}
	if !inst.KeepsAvailable {
		t.Fatal("an enrolled install should advertise that it keeps the endpoint available")
	}
	if len(inst.BuildSteps) != 0 {
		t.Fatalf("build_steps must be empty when a release host exists: %v", inst.BuildSteps)
	}
}

// TestAgentInstallShowsHowToPublishWithoutAReleaseHost keeps the honest empty
// state: no fabricated URL, and the exact build/publish steps instead.
func TestAgentInstallShowsHowToPublishWithoutAReleaseHost(t *testing.T) {
	srv, err := New(Options{DisableBackgroundJobs: true, CachePath: filepath.Join(t.TempDir(), "intel.db"), ToolVersion: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	var out struct {
		Install struct {
			Published  bool              `json:"published"`
			Commands   map[string]string `json:"commands"`
			BuildSteps []string          `json:"build_steps"`
		} `json:"install"`
	}
	if rec := doJSON(t, srv.Handler(), "GET", "/api/agents", nil, &out); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if out.Install.Published || len(out.Install.Commands) != 0 {
		t.Fatalf("no release host, but install block claims %+v", out.Install)
	}
	if len(out.Install.BuildSteps) != 3 || !strings.Contains(out.Install.BuildSteps[0], "build-agent-release.sh 0.1.0") {
		t.Fatalf("build_steps = %v", out.Install.BuildSteps)
	}
}

// --- software asset inventory exports ---------------------------------------

// TestReportExportSoftwareInventory covers the "what is installed on this host"
// export: CSV for asset registers and CycloneDX for SBOM consumers.
func TestReportExportSoftwareInventory(t *testing.T) {
	srv, cachePath := newTestServer(t)
	seedRun(t, cachePath, fixtureRoot(t))
	h := srv.Handler()

	runs, err := srv.store.ListRuns(t.Context(), 10)
	if err != nil || len(runs) == 0 {
		t.Fatalf("seeded server has no stored report: %v", err)
	}
	id := runs[0].ID

	// The stored report tells us how many packages the export must contain.
	var rep struct {
		Inventory struct {
			Packages []struct {
				Name string `json:"name"`
			} `json:"packages"`
		} `json:"inventory"`
	}
	if rec := doJSON(t, h, "GET", "/api/reports/"+id, nil, &rep); rec.Code != 200 {
		t.Fatalf("report = %d", rec.Code)
	}
	wantRows := len(rep.Inventory.Packages)
	if wantRows == 0 {
		t.Fatal("seeded report has no packages to export")
	}

	// CSV: one row per installed package plus the header.
	rec := request(t, h, "GET", "/api/reports/"+id+"/export?format=csv", "", nil)
	if rec.Code != 200 {
		t.Fatalf("csv export = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content-type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "-software.csv") {
		t.Fatalf("content-disposition = %q", cd)
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) != wantRows+1 {
		t.Fatalf("csv has %d lines, want %d packages + header", len(lines), wantRows)
	}
	if !strings.HasPrefix(lines[0], "host,os,os_version,") {
		t.Fatalf("csv header = %q", lines[0])
	}
	if !strings.Contains(lines[0], "known_findings,max_severity") {
		t.Fatalf("csv header is missing the derived assessment columns: %q", lines[0])
	}
	// The seeded endpoint is Ubuntu with an openssl advisory: that package must
	// carry the derived finding count rather than a bare row.
	if !strings.Contains(rec.Body.String(), "openssl") {
		t.Fatal("csv does not contain the seeded openssl package")
	}

	// CycloneDX: a valid 1.5 document with one component per package.
	rec = request(t, h, "GET", "/api/reports/"+id+"/export?format=cyclonedx", "", nil)
	if rec.Code != 200 {
		t.Fatalf("cyclonedx export = %d: %s", rec.Code, rec.Body.String())
	}
	var cdx struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Component struct {
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cdx); err != nil {
		t.Fatalf("cyclonedx is not valid JSON: %v", err)
	}
	if cdx.BOMFormat != "CycloneDX" || cdx.SpecVersion != "1.5" {
		t.Fatalf("bom = %q %q", cdx.BOMFormat, cdx.SpecVersion)
	}
	if len(cdx.Components) != wantRows {
		t.Fatalf("components = %d, want %d", len(cdx.Components), wantRows)
	}
	if cdx.Metadata.Component.Name == "" {
		t.Fatal("SBOM metadata.component does not name the host")
	}

	// An unknown format explains what is available instead of guessing.
	rec = request(t, h, "GET", "/api/reports/"+id+"/export?format=xlsx", "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown format = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "cyclonedx") || !strings.Contains(rec.Body.String(), "csv") {
		t.Fatalf("error does not advertise the inventory formats: %s", rec.Body.String())
	}
}

// TestSoftwareExportIsTheEnvironmentWideAssetList covers the fleet export: every
// host with a stored assessment, newest report only.
func TestSoftwareExportIsTheEnvironmentWideAssetList(t *testing.T) {
	srv, cachePath := newTestServer(t)
	seedRun(t, cachePath, fixtureRoot(t))
	h := srv.Handler()

	runs, err := srv.store.ListRuns(t.Context(), 10)
	if err != nil || len(runs) == 0 {
		t.Fatalf("seeded server has no stored report: %v", err)
	}
	host := runs[0].Host

	rec := request(t, h, "GET", "/api/software/export?format=csv", "", nil)
	if rec.Code != 200 {
		t.Fatalf("fleet csv = %d: %s", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "software-inventory.csv") {
		t.Fatalf("content-disposition = %q", cd)
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected a header and at least one package row, got %d lines", len(lines))
	}
	if !strings.Contains(lines[1], host) || !strings.Contains(lines[1], "SCAN-") {
		t.Fatalf("row does not carry its host and report: %q", lines[1])
	}

	// One host can be exported on its own, and then as an SBOM.
	rec = request(t, h, "GET", "/api/software/export?format=csv&host="+host, "", nil)
	if rec.Code != 200 {
		t.Fatalf("single-host csv = %d: %s", rec.Code, rec.Body.String())
	}
	rec = request(t, h, "GET", "/api/software/export?format=cyclonedx&host="+host, "", nil)
	if rec.Code != 200 {
		t.Fatalf("single-host cyclonedx = %d: %s", rec.Code, rec.Body.String())
	}
	var cdx struct {
		BOMFormat string `json:"bomFormat"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cdx); err != nil || cdx.BOMFormat != "CycloneDX" {
		t.Fatalf("single-host SBOM = %v (%v)", cdx, err)
	}

	// A merged SBOM across hosts would have to invent a component tree, so it is
	// refused with guidance instead.
	if len(runs) > 1 {
		if rec := request(t, h, "GET", "/api/software/export?format=cyclonedx", "", nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("multi-host cyclonedx = %d, want 400", rec.Code)
		}
	}

	rec = request(t, h, "GET", "/api/software/export?format=csv&host=no-such-host", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host = %d, want 404", rec.Code)
	}
	rec = request(t, h, "GET", "/api/software/export?format=xlsx", "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown fleet format = %d, want 400", rec.Code)
	}
}

func TestSoftwareExportWithoutAnyAssessment(t *testing.T) {
	srv, err := New(Options{DisableBackgroundJobs: true, CachePath: filepath.Join(t.TempDir(), "intel.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	rec := request(t, srv.Handler(), "GET", "/api/software/export?format=csv", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("empty cache = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "run a scan first") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestSoftwareExportRequiresDashboardAuth(t *testing.T) {
	clk := newClock()
	srv, _ := newAuthedServer(t, clk)
	rec := request(t, srv.Handler(), "GET", "/api/software/export?format=csv", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous fleet export = %d, want 401", rec.Code)
	}
}

// TestInstallCommandAdvertisesTheAgentReleaseVersion: the server's own version is
// not the agent release version. Using it makes the installer look for a tag that
// does not exist (server 0.2.2 vs release v0.1.7 → 404).
func TestInstallCommandAdvertisesTheAgentReleaseVersion(t *testing.T) {
	const base = "https://github.com/derekzacharias/clanker-guard-agent/releases/download/v0.1.7"
	srv, err := New(Options{DisableBackgroundJobs: true, CachePath: filepath.Join(t.TempDir(), "intel.db"), ToolVersion: "0.2.2", ReleaseBase: base})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if got := srv.AgentVersion(); got != "0.1.7" {
		t.Fatalf("AgentVersion from release base = %q, want 0.1.7", got)
	}

	// An explicit override wins.
	override, err := New(Options{DisableBackgroundJobs: true, CachePath: filepath.Join(t.TempDir(), "intel.db"), ToolVersion: "0.2.2", ReleaseBase: base, AgentVersion: "0.3.0"})
	if err != nil {
		t.Fatal(err)
	}
	defer override.Close()
	if got := override.AgentVersion(); got != "0.3.0" {
		t.Fatalf("explicit AgentVersion = %q", got)
	}

	// An unversioned base falls back to the build version (no tag to trust).
	plain, err := New(Options{DisableBackgroundJobs: true, CachePath: filepath.Join(t.TempDir(), "intel.db"), ToolVersion: "0.2.2", ReleaseBase: "https://example.test/releases"})
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if got := plain.AgentVersion(); got != "0.2.2" {
		t.Fatalf("fallback AgentVersion = %q", got)
	}
}
