package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/improve"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/inventory"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
)

// improvementFixture builds a server whose store contains:
//   - an upstream-only advisory that produced a finding (before the scan)
//   - a vendor advisory that arrives afterwards and says the build is fixed
//
// That is the realistic "intelligence changed after the scan" sequence the
// review workflow has to handle.
func improvementFixture(t *testing.T) (*Server, string) {
	t.Helper()
	cachePath := filepath.Join(t.TempDir(), "intel.db")
	store, err := intel.OpenStore(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	upstream := intel.Advisory{
		ID: "CVE-2026-0001", Source: "CVE",
		Affected: []intel.Affected{{
			Ecosystem: "Ubuntu:24.04:LTS", Name: "openssl",
			Ranges: []intel.Range{{Type: "ECOSYSTEM", Events: []intel.Event{{Introduced: "0"}, {Fixed: "3.0.14-1"}}}},
		}},
		Severities: []intel.SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		References: []intel.Reference{{Type: "ADVISORY", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"}},
		FetchedAt:  time.Now().UTC(),
	}
	if err := store.SaveAdvisories(ctx, []intel.Advisory{upstream}); err != nil {
		t.Fatal(err)
	}
	store.Close()

	root := t.TempDir()
	for _, dir := range []string{"etc", "var/lib/dpkg"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	osRelease := "PRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n"
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(osRelease), 0o644); err != nil {
		t.Fatal(err)
	}
	status := "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.11-0ubuntu3.1\n"
	if err := os.WriteFile(filepath.Join(root, "var/lib/dpkg/status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := scan.Run(ctx, scan.Options{
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

	// Vendor statement arrives after the scan (as a feed update would).
	store2, err := intel.OpenStore(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	vendor := intel.Advisory{
		ID: "UBUNTU-CVE-2026-0001", Source: "Ubuntu",
		Affected: []intel.Affected{{
			Ecosystem: "Ubuntu:24.04:LTS", Name: "openssl",
			Versions: []string{"3.0.10-1ubuntu1"},
		}},
		References: []intel.Reference{{Type: "ADVISORY", URL: "https://ubuntu.com/security/CVE-2026-0001"}},
		FetchedAt:  time.Now().UTC(),
	}
	if err := store2.SaveAdvisories(ctx, []intel.Advisory{vendor}); err != nil {
		t.Fatal(err)
	}
	store2.Close()

	srv, err := New(Options{CachePath: cachePath, ToolVersion: "test-1.0", Now: func() time.Time {
		return time.Date(2026, 11, 13, 13, 0, 0, 0, time.UTC)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, cachePath
}

func findOpenSSL(t *testing.T, h http.Handler) vulnRow {
	t.Helper()
	var list vulnListResponse
	if rec := doJSON(t, h, "GET", "/api/vulnerabilities?q=CVE-2026-0001", nil, &list); rec.Code != 200 {
		t.Fatalf("list status %d", rec.Code)
	}
	for _, v := range list.Items {
		if v.Product == "openssl" {
			return v
		}
	}
	t.Fatalf("openssl finding not found in %+v", list.Items)
	return vulnRow{}
}

func TestFeedbackVerifiesVendorPatchAndAppliesState(t *testing.T) {
	srv, _ := improvementFixture(t)
	h := srv.Handler()
	row := findOpenSSL(t, h)
	if row.Affected != string(model.ApplicabilityProbable) {
		t.Fatalf("upstream advisory on a distro build should start as probable, got %s", row.Affected)
	}

	var resp struct {
		Feedback struct {
			ID           string `json:"id"`
			Verification struct {
				Supported  bool   `json:"supported"`
				Changed    bool   `json:"changed"`
				Confidence string `json:"confidence"`
				Reassessed string `json:"reassessed_applicability"`
				Category   string `json:"category"`
				Evidence   []struct {
					Kind string `json:"kind"`
				} `json:"evidence"`
			} `json:"verification"`
		} `json:"feedback"`
		State *struct {
			Applicability string `json:"applicability"`
		} `json:"state"`
		ImprovementIDs []string `json:"improvement_ids"`
	}
	rec := doJSON(t, h, "POST", "/api/vulnerabilities/"+row.ID+"/feedback", map[string]any{
		"verdict": "false_positive", "reason_code": "vendor_patch_installed", "analyst": "tester",
	}, &resp)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("feedback status %d: %s", rec.Code, rec.Body.String())
	}
	if !resp.Feedback.Verification.Supported || !resp.Feedback.Verification.Changed {
		t.Fatalf("vendor advisory evidence should support the claim: %+v", resp.Feedback.Verification)
	}
	if resp.Feedback.Verification.Reassessed != string(model.ApplicabilityNotAffected) {
		t.Fatalf("expected not_affected, got %s", resp.Feedback.Verification.Reassessed)
	}
	if resp.State == nil || resp.State.Applicability != string(model.ApplicabilityNotAffected) {
		t.Fatalf("state not applied: %+v", resp.State)
	}
	if len(resp.Feedback.Verification.Evidence) == 0 {
		t.Fatal("verification evidence missing")
	}

	// The finding now exposes both the scanner verdict and the correction.
	var detail vulnRow
	doJSON(t, h, "GET", "/api/vulnerabilities/"+row.ID, nil, &detail)
	if detail.Affected != string(model.ApplicabilityProbable) {
		t.Fatalf("scanner verdict must be preserved, got %s", detail.Affected)
	}
	if detail.Analyst == nil || detail.Analyst.Applicability != string(model.ApplicabilityNotAffected) {
		t.Fatalf("analyst correction missing: %+v", detail.Analyst)
	}
	if detail.Effective != string(model.ApplicabilityNotAffected) {
		t.Fatalf("effective classification not updated: %q", detail.Effective)
	}

	// Overview counts must follow the effective classification.
	var ov overviewResponse
	doJSON(t, h, "GET", "/api/overview", nil, &ov)
	if ov.Reviewed < 1 {
		t.Fatalf("reviewed count missing: %+v", ov)
	}
	if ov.ImprovementsAvailable < 1 {
		t.Fatalf("improvement indicator not surfaced: %+v", ov.ImprovementsAvailable)
	}
}

func TestFeedbackRequiresReasonAndValidVerdict(t *testing.T) {
	srv, _ := improvementFixture(t)
	h := srv.Handler()
	row := findOpenSSL(t, h)

	rec := doJSON(t, h, "POST", "/api/vulnerabilities/"+row.ID+"/feedback",
		map[string]any{"verdict": "false_positive"}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "reason") {
		t.Fatalf("false positive without a reason must be rejected: %d %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, "POST", "/api/vulnerabilities/"+row.ID+"/feedback",
		map[string]any{"verdict": "ignore-this-finding", "reason_code": "other"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown verdict must be rejected, got %d", rec.Code)
	}
	rec = doJSON(t, h, "POST", "/api/vulnerabilities/does-not-exist/feedback",
		map[string]any{"verdict": "confirmed"}, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown finding must 404, got %d", rec.Code)
	}
}

func TestImprovementLifecycleOverHTTP(t *testing.T) {
	srv, _ := improvementFixture(t)
	h := srv.Handler()
	row := findOpenSSL(t, h)

	doJSON(t, h, "POST", "/api/vulnerabilities/"+row.ID+"/feedback", map[string]any{
		"verdict": "false_positive", "reason_code": "vendor_patch_installed", "analyst": "tester",
	}, nil)

	var list struct {
		Items []improve.Improvement `json:"items"`
	}
	if rec := doJSON(t, h, "GET", "/api/improvements", nil, &list); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if len(list.Items) == 0 {
		t.Fatal("expected an improvement proposal")
	}
	imp := list.Items[0]
	if imp.Status != improve.StatusAwaitingApproval {
		t.Fatalf("expected awaiting_approval, got %s (%s)", imp.Status, imp.RejectedReason)
	}
	if imp.Evaluation == nil || !imp.Evaluation.Passed {
		t.Fatalf("evaluation should pass: %+v", imp.Evaluation)
	}

	// Deploy before approval is refused.
	rec := doJSON(t, h, "POST", "/api/improvements/"+imp.ID+"/transition",
		map[string]any{"to": "deployed", "actor": "tester"}, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("deploy before approval must be 422, got %d", rec.Code)
	}

	if rec := doJSON(t, h, "POST", "/api/improvements/"+imp.ID+"/transition",
		map[string]any{"to": "approved", "actor": "tester", "note": "reviewed fixtures"}, nil); rec.Code != 200 {
		t.Fatalf("approve failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, h, "POST", "/api/improvements/"+imp.ID+"/transition",
		map[string]any{"to": "deployed", "actor": "tester"}, nil); rec.Code != 200 {
		t.Fatalf("deploy failed: %d %s", rec.Code, rec.Body.String())
	}

	// Detail exposes the audit trail and the active rule.
	var detail struct {
		Improvement improve.Improvement `json:"improvement"`
		Events      []improve.Event     `json:"events"`
		Active      struct {
			RuleID string   `json:"rule_id"`
			Notes  []string `json:"notes"`
		} `json:"active"`
	}
	if rec := doJSON(t, h, "GET", "/api/improvements/"+imp.ID, nil, &detail); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if detail.Improvement.Status != improve.StatusDeployed {
		t.Fatalf("expected deployed, got %s", detail.Improvement.Status)
	}
	if len(detail.Events) < 3 {
		t.Fatalf("audit trail too short: %+v", detail.Events)
	}
	if detail.Active.RuleID == "" {
		t.Fatal("deployed rule not active")
	}

	// Rollback restores defaults and is recorded.
	if rec := doJSON(t, h, "POST", "/api/improvements/"+imp.ID+"/transition",
		map[string]any{"to": "rolled_back", "actor": "tester", "note": "regression watch"}, nil); rec.Code != 200 {
		t.Fatalf("rollback failed: %d %s", rec.Code, rec.Body.String())
	}
	var after struct {
		Active struct {
			RuleID string `json:"rule_id"`
		} `json:"active"`
	}
	doJSON(t, h, "GET", "/api/improvements/"+imp.ID, nil, &after)
	if after.Active.RuleID != "" {
		t.Fatalf("rollback should leave no active rule, got %q", after.Active.RuleID)
	}
}

func TestQualityEndpointReportsReviewedSample(t *testing.T) {
	srv, _ := improvementFixture(t)
	h := srv.Handler()
	row := findOpenSSL(t, h)
	doJSON(t, h, "POST", "/api/vulnerabilities/"+row.ID+"/feedback", map[string]any{
		"verdict": "false_positive", "reason_code": "vendor_patch_installed",
	}, nil)

	var q struct {
		Metrics struct {
			Reviewed          int      `json:"reviewed"`
			FalsePositives    int      `json:"false_positives"`
			FalsePositiveRate *float64 `json:"false_positive_rate"`
			Notes             []string `json:"notes"`
		} `json:"metrics"`
		RecentFeedback []struct {
			CVE     string `json:"cve"`
			Verdict string `json:"verdict"`
		} `json:"recent_feedback"`
	}
	if rec := doJSON(t, h, "GET", "/api/quality", nil, &q); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if q.Metrics.Reviewed != 1 || q.Metrics.FalsePositives != 1 {
		t.Fatalf("unexpected metrics: %+v", q.Metrics)
	}
	if q.Metrics.FalsePositiveRate == nil || *q.Metrics.FalsePositiveRate != 1 {
		t.Fatalf("reviewed-sample rate wrong: %+v", q.Metrics.FalsePositiveRate)
	}
	if len(q.Metrics.Notes) == 0 {
		t.Fatal("small-sample caveat must be visible")
	}
	if len(q.RecentFeedback) != 1 || q.RecentFeedback[0].CVE != "CVE-2026-0001" {
		t.Fatalf("recent feedback missing: %+v", q.RecentFeedback)
	}
}

func TestFeedbackExportAndDelete(t *testing.T) {
	srv, _ := improvementFixture(t)
	h := srv.Handler()
	row := findOpenSSL(t, h)
	doJSON(t, h, "POST", "/api/vulnerabilities/"+row.ID+"/feedback", map[string]any{
		"verdict": "false_positive", "reason_code": "vendor_patch_installed",
	}, nil)

	rec := doJSON(t, h, "GET", "/api/feedback/export", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "CVE-2026-0001") {
		t.Fatalf("export failed: %d", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("export should be a download: %q", cd)
	}

	if rec := doJSON(t, h, "DELETE", "/api/vulnerabilities/"+row.ID+"/feedback", nil, nil); rec.Code != 200 {
		t.Fatalf("delete failed: %d", rec.Code)
	}
	var history struct {
		Feedback []improve.Feedback `json:"feedback"`
		State    *improve.State     `json:"state"`
	}
	doJSON(t, h, "GET", "/api/vulnerabilities/"+row.ID+"/history", nil, &history)
	if len(history.Feedback) != 0 || history.State != nil {
		t.Fatalf("history not deleted: %+v", history)
	}
}

func TestAskAnswersImprovementQuestions(t *testing.T) {
	srv, _ := improvementFixture(t)
	h := srv.Handler()
	row := findOpenSSL(t, h)
	doJSON(t, h, "POST", "/api/vulnerabilities/"+row.ID+"/feedback", map[string]any{
		"verdict": "false_positive", "reason_code": "vendor_patch_installed",
	}, nil)

	var resp struct {
		Answer    string `json:"answer"`
		Citations []struct {
			CVE string `json:"cve"`
		} `json:"citations"`
		Grounding struct {
			LLMUsed bool `json:"llm_used"`
		} `json:"grounding"`
	}
	rec := doJSON(t, h, "POST", "/api/ask", map[string]string{
		"question": "what did you learn from my false-positive reviews?",
	}, &resp)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(resp.Answer, "review") || !strings.Contains(resp.Answer, "supported") {
		t.Fatalf("answer should summarise the reviews: %q", resp.Answer)
	}
	if len(resp.Citations) == 0 || resp.Citations[0].CVE != "CVE-2026-0001" {
		t.Fatalf("citations missing: %+v", resp.Citations)
	}
	if resp.Grounding.LLMUsed {
		t.Fatal("answers must be deterministic")
	}

	rec = doJSON(t, h, "POST", "/api/ask", map[string]string{
		"question": "which scanning capabilities are missing?",
	}, &resp)
	if rec.Code != 200 || !strings.Contains(resp.Answer, "network assessment") {
		t.Fatalf("capability answer wrong: %q", resp.Answer)
	}

	rec = doJSON(t, h, "POST", "/api/ask", map[string]string{
		"question": "show me the tests supporting this proposed detection update",
	}, &resp)
	if rec.Code != 200 || !strings.Contains(resp.Answer, "fixture") {
		t.Fatalf("test answer wrong: %q", resp.Answer)
	}
}

// TestDeployedRuleChangesFindingsOverHTTP closes the loop through the API: the
// same finding is reported differently after an approved deployment.
func TestDeployedRuleChangesFindingsOverHTTP(t *testing.T) {
	srv, _ := improvementFixture(t)
	h := srv.Handler()
	row := findOpenSSL(t, h)

	var before vulnRow
	doJSON(t, h, "GET", "/api/vulnerabilities/"+row.ID, nil, &before)

	var resp struct {
		ImprovementIDs []string `json:"improvement_ids"`
	}
	doJSON(t, h, "POST", "/api/vulnerabilities/"+row.ID+"/feedback", map[string]any{
		"verdict": "false_positive", "reason_code": "vendor_patch_installed", "analyst": "tester",
	}, &resp)

	var list struct {
		Items []improve.Improvement `json:"items"`
	}
	doJSON(t, h, "GET", "/api/improvements", nil, &list)
	if len(list.Items) == 0 {
		t.Fatal("no proposal")
	}
	id := list.Items[0].ID
	doJSON(t, h, "POST", "/api/improvements/"+id+"/transition", map[string]any{"to": "approved", "actor": "tester"}, nil)
	if rec := doJSON(t, h, "POST", "/api/improvements/"+id+"/transition", map[string]any{"to": "deployed", "actor": "tester"}, nil); rec.Code != 200 {
		t.Fatalf("deploy failed: %d %s", rec.Code, rec.Body.String())
	}

	// A fresh scan uses the deployed rule; the report records which policy shaped it.
	root := t.TempDir()
	for _, dir := range []string{"etc", "var/lib/dpkg"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o644)
	os.WriteFile(filepath.Join(root, "var/lib/dpkg/status"), []byte("Package: bash\nStatus: install ok installed\nVersion: 5.2-1\n"), 0o644)

	res, err := scan.Run(context.Background(), scan.Options{
		Root: root, CachePath: srv.opts.CachePath, Offline: true, Format: "json", SkipRender: true,
		Collectors: []inventory.Collector{&inventory.OSPackageCollector{}}, Stderr: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Metadata.DetectionPolicy) == 0 {
		t.Fatal("report must record the deployed detection policy")
	}
	encoded, _ := json.Marshal(res.Report.Metadata.DetectionPolicy)
	if !strings.Contains(string(encoded), "backport") {
		t.Fatalf("expected the changed backport outcome in the policy notes: %s", encoded)
	}
}
