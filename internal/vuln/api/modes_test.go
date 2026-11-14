package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/netscan"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
)

// waitJob polls until a job reaches a terminal state.
func waitJob(t *testing.T, h http.Handler, id string) (status string, report map[string]any) {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		var detail struct {
			Job    *intel.Job     `json:"job"`
			Report map[string]any `json:"report"`
		}
		doJSON(t, h, "GET", "/api/scans/"+id, nil, &detail)
		if detail.Job != nil {
			switch detail.Job.Status {
			case intel.JobDone, intel.JobFailed, intel.JobCanceled:
				return detail.Job.Status, detail.Report
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("job %s did not finish", id)
	return "", nil
}

// TestNetworkScanAgainstAuthorisedLoopback proves the whole network path: scope
// validation, discovery, fingerprinting, NVD correlation (stubbed) and reporting.
func TestNetworkScanAgainstAuthorisedLoopback(t *testing.T) {
	srv, _ := newTestServer(t)

	// A loopback service that identifies itself.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<title>demo</title>"))
	}))
	defer target.Close()
	port := target.Listener.Addr().(*net.TCPAddr).Port

	// Stub NVD so the test is deterministic and offline.
	srv.opts.RunScan = func(ctx context.Context, opts scan.Options) (scan.Result, error) {
		if opts.Scope != nil {
			opts.NVDFunc = func(context.Context, string) ([]netscan.CVEMatch, error) {
				return []netscan.CVEMatch{{
					ID: "CVE-2024-9999", Description: "Example nginx issue",
					CVSS:      &intel.CVSS{Score: 7.5, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", Source: "NVD"},
					Published: time.Now().Add(-24 * time.Hour),
					URL:       "https://nvd.nist.gov/vuln/detail/CVE-2024-9999",
				}}, nil
			}
		}
		return scan.Run(ctx, opts)
	}

	scopeYAML := strings.Join([]string{
		"name: loopback-test",
		"authorized_by: qa",
		"authorized_at: 2026-01-01T00:00:00Z",
		"expires_at: 2030-01-01T00:00:00Z",
		"targets: [127.0.0.1]",
		"ports: [" + strconv.Itoa(port) + "]",
		"max_hosts: 1",
		"allow_public_addresses: false",
	}, "\n")

	var job intel.Job
	rec := doJSON(t, h(t, srv), "POST", "/api/scans", map[string]any{
		"kind": "network", "authorized": true, "scope_yaml": scopeYAML,
	}, &job)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start status %d: %s", rec.Code, rec.Body.String())
	}

	status, report := waitJob(t, h(t, srv), job.ID)
	if status != intel.JobDone {
		t.Fatalf("network scan did not complete: %s", status)
	}
	meta, _ := report["metadata"].(map[string]any)
	if meta["mode"] != "network" {
		t.Fatalf("mode should be network: %v", meta["mode"])
	}
	scopeMeta, _ := meta["scope"].(map[string]any)
	if scopeMeta["name"] != "loopback-test" || scopeMeta["authorized_by"] != "qa" {
		t.Fatalf("scope must be recorded in the report: %v", scopeMeta)
	}

	inv, _ := report["inventory"].(map[string]any)
	pkgs, _ := inv["packages"].([]any)
	if len(pkgs) == 0 {
		t.Fatalf("expected a fingerprinted pseudo-package, got none")
	}
	found := false
	for _, p := range pkgs {
		pm := p.(map[string]any)
		if pm["name"] == "nginx:nginx" && pm["version"] == "1.24.0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("nginx fingerprint missing from inventory: %v", pkgs)
	}

	findings, _ := report["findings"].([]any)
	if len(findings) == 0 {
		t.Fatal("expected findings (CVE + version disclosure)")
	}
	var hasCVE, hasDisclosure bool
	for _, f := range findings {
		fm := f.(map[string]any)
		if fm["vulnerability_id"] == "CVE-2024-9999" {
			hasCVE = true
			// A CPE/version match is version-level evidence, not proof that the
			// vulnerable code path is reachable.
			if fm["affected"] != "probable" {
				t.Fatalf("NVD version match should be probable, got %v", fm["affected"])
			}
			if !strings.Contains(fm["explanation"].(string), "version-level evidence") {
				t.Fatalf("the explanation must state the limit of the evidence: %v", fm["explanation"])
			}
		}
		if strings.Contains(strings.ToLower(fm["product"].(string)), "discloses its software version") {
			hasDisclosure = true
		}
	}
	if !hasCVE || !hasDisclosure {
		t.Fatalf("expected the CVE and the version-disclosure finding, got %v", findings)
	}
}

// TestSBOMScanEndToEnd correlates a CycloneDX document from cache, offline.
func TestSBOMScanEndToEnd(t *testing.T) {
	srv, cachePath := newTestServer(t)
	store, err := intel.OpenStore(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	// Advisory for the component in the fixture.
	if err := store.SaveAdvisories(context.Background(), []intel.Advisory{{
		ID: "GHSA-test-paramiko", Source: "GitHub",
		Affected: []intel.Affected{{
			Ecosystem: "PyPI", Name: "paramiko",
			Ranges: []intel.Range{{Type: "ECOSYSTEM", Events: []intel.Event{{Introduced: "0"}, {Fixed: "3.4.0"}}}},
		}},
		Severities: []intel.SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"}},
		FetchedAt:  time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}
	store.Close()

	dir := t.TempDir()
	doc := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(doc, []byte(`{
	  "bomFormat": "CycloneDX", "specVersion": "1.5",
	  "metadata": {"component": {"type": "application", "name": "payments-api"}},
	  "components": [
	    {"type": "library", "name": "paramiko", "version": "2.12.0", "purl": "pkg:pypi/paramiko@2.12.0"},
	    {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}
	  ]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var job intel.Job
	if rec := doJSON(t, srv.Handler(), "POST", "/api/scans", map[string]any{
		"kind": "sbom", "sbom_path": doc, "offline": true,
	}, &job); rec.Code != http.StatusAccepted {
		t.Fatalf("start status %d: %s", rec.Code, rec.Body.String())
	}
	status, report := waitJob(t, srv.Handler(), job.ID)
	if status != intel.JobDone {
		t.Fatalf("sbom scan did not complete: %s", status)
	}
	meta, _ := report["metadata"].(map[string]any)
	if meta["mode"] != "sbom" {
		t.Fatalf("mode should be sbom: %v", meta["mode"])
	}
	findings, _ := report["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("expected exactly the paramiko finding, got %v", findings)
	}
	f := findings[0].(map[string]any)
	if f["product"] != "paramiko" || f["affected"] != "confirmed_applicability" {
		t.Fatalf("unexpected finding: %v", f)
	}
	if !strings.Contains(f["explanation"].(string), "3.4.0") {
		t.Fatalf("fixed version should be explained: %v", f["explanation"])
	}
}

// h is a tiny helper so tests can pass the handler without repeating.
func h(t *testing.T, srv *Server) http.Handler { t.Helper(); return srv.Handler() }
