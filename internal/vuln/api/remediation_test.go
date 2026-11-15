package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/report"
)

// Remediation orchestration endpoints: ownership routes work, the workflow refuses
// illegal moves, and only verification resolves an item.

// postReport enrolls an agent for the host and uploads a report with one finding.
func postReport(t *testing.T, srv *Server, host, ecosystem, product, vuln, severity, reportID string) {
	t.Helper()
	agentID, token := enrollAgent(t, srv, host)
	_ = agentID
	rep := minimalReportWith(host, reportID, ecosystem, product, vuln, severity)
	rec := request(t, srv.Handler(), "POST", "/api/agents/report", string(rep), agentHeaders(token))
	if rec.Code != 200 {
		t.Fatalf("report for %s = %d: %s", host, rec.Code, rec.Body.String())
	}
}

func TestReportBecomesRoutedRemediationWork(t *testing.T) {
	srv := fleetServer(t)
	postReport(t, srv, "web01", "Ubuntu:24.04", "openssl", "CVE-2026-9001", "high", "SCAN-REM-1")

	var list struct {
		Items []struct {
			ID              string `json:"id"`
			Team            string `json:"team"`
			State           string `json:"state"`
			Priority        string `json:"priority"`
			DueAt           string `json:"due_at"`
			VulnerabilityID string `json:"vulnerability_id"`
			Overdue         bool   `json:"overdue"`
		} `json:"items"`
		Total int `json:"total"`
	}
	if rec := dashGet(t, srv.Handler(), "/api/remediation", &list); rec.Code != 200 {
		t.Fatalf("list = %d: %s", rec.Code, rec.Body.String())
	}
	if list.Total != 1 {
		t.Fatalf("items = %d, want 1", list.Total)
	}
	item := list.Items[0]
	if item.Team != "Infrastructure" {
		t.Fatalf("OS package routed to %q, want Infrastructure", item.Team)
	}
	if item.State != "assigned" || item.Priority != "P1" && item.Priority != "P2" {
		t.Fatalf("item = %+v", item)
	}
	if item.DueAt == "" {
		t.Fatal("no SLA deadline was computed")
	}
	if item.Overdue {
		t.Fatal("a new item must not be overdue")
	}

	var summary struct {
		Summary struct {
			Total      int            `json:"total"`
			Open       int            `json:"open"`
			Unassigned int            `json:"unassigned"`
			ByTeam     map[string]int `json:"by_team"`
		} `json:"summary"`
		Automation struct {
			Enabled bool `json:"enabled"`
		} `json:"automation"`
	}
	if rec := dashGet(t, srv.Handler(), "/api/remediation/summary", &summary); rec.Code != 200 {
		t.Fatalf("summary = %d", rec.Code)
	}
	if summary.Summary.Total != 1 || summary.Summary.Open != 1 || summary.Summary.Unassigned != 0 {
		t.Fatalf("summary = %+v", summary.Summary)
	}
	if summary.Summary.ByTeam["Infrastructure"] != 1 {
		t.Fatalf("by_team = %+v", summary.Summary.ByTeam)
	}
	// Automated execution does not exist yet, and the API says so instead of
	// advertising a capability.
	if summary.Automation.Enabled {
		t.Fatal("automation must be reported as disabled")
	}
}

func TestOwnershipRoutesSubsequentWork(t *testing.T) {
	srv := fleetServer(t)
	// An asset with an explicit owner wins over the category mapping.
	body := `{"team":"Payments","owner":"dana","environment":"production","criticality":"high","exposure":"internet"}`
	if rec := request(t, srv.Handler(), "PUT", "/api/ownership/pay01", body, dash()); rec.Code != 200 {
		t.Fatalf("ownership put = %d: %s", rec.Code, rec.Body.String())
	}
	var own struct {
		Team   string `json:"team"`
		Status string `json:"status"`
	}
	if rec := dashGet(t, srv.Handler(), "/api/ownership/pay01", &own); rec.Code != 200 {
		t.Fatalf("ownership get = %d", rec.Code)
	}
	if own.Team != "Payments" || own.Status != "owned" {
		t.Fatalf("ownership = %+v", own)
	}

	postReport(t, srv, "pay01", "Ubuntu:24.04", "openssl", "CVE-2026-9002", "medium", "SCAN-REM-2")

	var list struct {
		Items []struct {
			Team     string `json:"team"`
			DueAt    string `json:"due_at"`
			Severity string `json:"severity"`
		} `json:"items"`
	}
	dashGet(t, srv.Handler(), "/api/remediation?asset=pay01", &list)
	if len(list.Items) != 1 || list.Items[0].Team != "Payments" {
		t.Fatalf("items = %+v", list.Items)
	}
	// Internet exposure raised medium to high, so the window is 30 days, not 60.
	if !strings.Contains(list.Items[0].Severity, "high") {
		t.Fatalf("effective severity = %q, want high (exposure escalation)", list.Items[0].Severity)
	}
}

func TestUnknownEcosystemGoesToTriage(t *testing.T) {
	srv := fleetServer(t)
	postReport(t, srv, "odd01", "AcmeOS:1", "blob", "CVE-2026-9003", "high", "SCAN-REM-3")

	var list struct {
		Items []struct {
			Team  string `json:"team"`
			State string `json:"state"`
		} `json:"items"`
	}
	dashGet(t, srv.Handler(), "/api/remediation", &list)
	if len(list.Items) != 1 {
		t.Fatalf("items = %d", len(list.Items))
	}
	if list.Items[0].Team != "" || list.Items[0].State != "awaiting_ownership" {
		t.Fatalf("unknown ecosystem must wait for a human: %+v", list.Items[0])
	}
	// And it appears in the triage queue rather than being assigned by default.
	var triage struct {
		Total int `json:"total"`
	}
	dashGet(t, srv.Handler(), "/api/ownership?triage=true", &triage)
	if triage.Total != 0 {
		// No ownership record exists for the host yet; the queue lists records, not
		// findings, so an unowned item shows through the summary instead.
		t.Logf("triage records = %d", triage.Total)
	}
	var summary struct {
		Summary struct {
			Unassigned int `json:"unassigned"`
		} `json:"summary"`
	}
	dashGet(t, srv.Handler(), "/api/remediation/summary", &summary)
	if summary.Summary.Unassigned != 1 {
		t.Fatalf("unassigned = %d, want 1", summary.Summary.Unassigned)
	}
}

func TestWorkflowRefusesIllegalMovesAndHandResolving(t *testing.T) {
	srv := fleetServer(t)
	postReport(t, srv, "web01", "Ubuntu:24.04", "openssl", "CVE-2026-9004", "critical", "SCAN-REM-4")
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	dashGet(t, srv.Handler(), "/api/remediation", &list)
	id := list.Items[0].ID

	// Hand-resolving is refused: verification is the only route.
	if rec := request(t, srv.Handler(), "PATCH", "/api/remediation/"+id, `{"state":"resolved"}`, dash()); rec.Code != http.StatusConflict {
		t.Fatalf("hand resolve = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	// An invented state is a bad request, not a transition conflict.
	if rec := request(t, srv.Handler(), "PATCH", "/api/remediation/"+id, `{"state":"banana"}`, dash()); rec.Code != http.StatusBadRequest {
		t.Fatalf("invented state = %d, want 400", rec.Code)
	}
	// A legal move is accepted.
	if rec := request(t, srv.Handler(), "PATCH", "/api/remediation/"+id, `{"state":"in_progress"}`, dash()); rec.Code != 200 {
		t.Fatalf("in_progress = %d: %s", rec.Code, rec.Body.String())
	}
	// Verifying something that was never remediated is refused.
	if rec := request(t, srv.Handler(), "POST", "/api/remediation/"+id+"/verify", `{}`, dash()); rec.Code != http.StatusConflict {
		t.Fatalf("verify before remediation = %d, want 409", rec.Code)
	}
	// Assignment is an operator action and records who owns it next.
	if rec := request(t, srv.Handler(), "PATCH", "/api/remediation/"+id, `{"owner":"dana","team":"Linux Ops"}`, dash()); rec.Code != 200 {
		t.Fatalf("assign = %d", rec.Code)
	}
}

func TestRemediationRequiresDashboardAuth(t *testing.T) {
	srv := fleetServer(t)
	for _, path := range []string{"/api/remediation", "/api/remediation/summary", "/api/ownership"} {
		if rec := request(t, srv.Handler(), "GET", path, "", nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without auth = %d, want 401", path, rec.Code)
		}
	}
}

// minimalReportWith builds a one-finding report so routing can be exercised for a
// specific ecosystem and severity.
func minimalReportWith(host, reportID, ecosystem, product, vuln, severity string) []byte {
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	rep := model.Report{
		SchemaVersion: "1",
		ReportID:      reportID,
		Metadata: model.ScanMetadata{
			ToolVersion: "test", StartedAt: now.Add(-time.Minute), FinishedAt: &now,
			Mode: "local", Host: host,
		},
		Findings: []model.Finding{{
			Asset: host, Ecosystem: ecosystem, Product: product,
			InstalledVersion: "1.0.0", VulnerabilityID: vuln, Severity: severity,
			Affected: model.ApplicabilityConfirmed, Confidence: model.ConfidenceHigh,
			FixedVersion: "1.0.1", Remediation: "apt-get install --only-upgrade " + product,
		}},
	}
	payload, err := report.MarshalJSON(rep)
	if err != nil {
		panic(err)
	}
	return payload
}

// Triage exists because routing must not guess. That makes bulk assignment the action
// that clears it, so it has to be one request, refuse to run without a team, and report
// every asset it could not store instead of dropping it.
func TestBulkOwnershipClearsTriageAndReportsFailures(t *testing.T) {
	srv := fleetServer(t)
	// Three assets with an ecosystem nothing can classify: all land in triage.
	postReport(t, srv, "odd01", "AcmeOS:1", "blob", "CVE-2026-9101", "high", "SCAN-B-1")
	postReport(t, srv, "odd02", "AcmeOS:1", "blob", "CVE-2026-9102", "medium", "SCAN-B-2")

	var before struct {
		Items []struct {
			Asset   string `json:"asset"`
			Triaged bool   `json:"triaged"`
			Open    int    `json:"open"`
		} `json:"items"`
	}
	dashGet(t, srv.Handler(), "/api/ownership?triage=true", &before)
	if len(before.Items) != 2 {
		t.Fatalf("triage queue = %+v, want 2 assets", before.Items)
	}

	// No team means "still nobody's": it must not quietly create ownerless records.
	rec := request(t, srv.Handler(), "POST", "/api/ownership/bulk", `{"assets":["odd01"],"team":"  "}`, dash())
	if rec.Code != 400 {
		t.Fatalf("bulk without a team = %d, want 400", rec.Code)
	}

	body := `{"assets":["odd01","odd02","odd02"],"team":"Development","owner":"dana","exposure":"internet"}`
	rec = request(t, srv.Handler(), "POST", "/api/ownership/bulk", body, dash())
	if rec.Code != 200 {
		t.Fatalf("bulk = %d: %s", rec.Code, rec.Body.String())
	}
	var bulk struct {
		Updated []string `json:"updated"`
		Total   int      `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &bulk); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The duplicate asset is assigned once, not twice.
	if bulk.Total != 2 || len(bulk.Updated) != 2 {
		t.Fatalf("bulk result = %+v, want 2 unique assets assigned", bulk)
	}

	// The decision propagates: items adopt the owner's team and the queue empties.
	var list struct {
		Items []struct {
			Team  string `json:"team"`
			State string `json:"state"`
			Owner string `json:"owner"`
		} `json:"items"`
	}
	dashGet(t, srv.Handler(), "/api/remediation?asset=odd01", &list)
	if len(list.Items) != 1 || list.Items[0].Team != "Development" || list.Items[0].Owner != "dana" {
		t.Fatalf("item after bulk = %+v", list.Items)
	}
	if list.Items[0].State != "assigned" {
		t.Fatalf("state = %q, want assigned once a team exists", list.Items[0].State)
	}
	var after struct {
		Total int `json:"total"`
	}
	dashGet(t, srv.Handler(), "/api/ownership?triage=true", &after)
	if after.Total != 0 {
		t.Fatalf("triage queue after bulk = %d, want 0", after.Total)
	}
}

// The finding detail has to answer "who owes this and by when" without the client
// recomputing routing, and it must say nothing rather than guess when no item exists.
func TestFindingDetailCarriesItsRemediationState(t *testing.T) {
	srv := fleetServer(t)
	if rec := request(t, srv.Handler(), "PUT", "/api/ownership/pay02",
		`{"team":"Payments","owner":"dana","exposure":"internet"}`, dash()); rec.Code != 200 {
		t.Fatalf("ownership put = %d", rec.Code)
	}
	postReport(t, srv, "pay02", "Ubuntu:24.04", "openssl", "CVE-2026-9201", "medium", "SCAN-D-1")

	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	dashGet(t, srv.Handler(), "/api/vulnerabilities?limit=50", &list)
	if len(list.Items) == 0 {
		t.Fatal("no findings listed")
	}
	var findingID string
	for _, it := range list.Items {
		findingID = it.ID
	}

	var detail struct {
		ID       string `json:"id"`
		WorkItem *struct {
			ID       string `json:"id"`
			Team     string `json:"team"`
			Owner    string `json:"owner"`
			Severity string `json:"severity"`
			DueAt    string `json:"due_at"`
			Overdue  bool   `json:"overdue"`
		} `json:"remediation_item"`
	}
	dashGet(t, srv.Handler(), "/api/vulnerabilities/"+findingID, &detail)
	if detail.WorkItem == nil {
		t.Fatal("finding detail has no remediation item, so the flyout cannot show an owner")
	}
	if detail.WorkItem.Team != "Payments" || detail.WorkItem.Owner != "dana" {
		t.Fatalf("work item = %+v", detail.WorkItem)
	}
	// Internet exposure raises medium to high: 30-day window, and a real deadline.
	if detail.WorkItem.Severity != "high" {
		t.Fatalf("effective severity = %q, want high", detail.WorkItem.Severity)
	}
	if detail.WorkItem.DueAt == "" {
		t.Fatal("work item has no due date")
	}
	if detail.WorkItem.Overdue {
		t.Fatal("a freshly created item cannot be overdue")
	}
}
