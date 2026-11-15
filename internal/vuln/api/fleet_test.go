package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/report"
)

// fleetServer is a dashboard-token server with an empty cache, which is all the
// fleet flow needs.
func fleetServer(t *testing.T) *Server {
	t.Helper()
	srv, err := New(Options{
		CachePath:   filepath.Join(t.TempDir(), "intel.db"),
		ToolVersion: "0.1.0",
		Token:       "dash-token",
		ReleaseBase: "https://example.invalid/releases/download/v0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

// dashGet issues a dashboard-authenticated GET and decodes the body.
func dashGet(t *testing.T, h http.Handler, path string, out any) *httptest.ResponseRecorder {
	t.Helper()
	rec := request(t, h, "GET", path, "", dash())
	if out != nil && rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("GET %s: response is not JSON: %v\n%s", path, err, rec.Body.String())
		}
	}
	return rec
}

func dash() map[string]string { return map[string]string{"X-Guard-Token": "dash-token"} }

// enrollAgent runs the enrollment handshake and returns the agent id and token.
func enrollAgent(t *testing.T, srv *Server, host string) (string, string) {
	t.Helper()
	enrollToken, err := srv.fleet.EnrollToken(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	body := `{"host":"` + host + `","os":"Ubuntu 24.04","version":"0.1.0"}`
	rec := request(t, srv.Handler(), "POST", "/api/agents/enroll", body,
		map[string]string{"X-Guard-Enroll-Token": enrollToken})
	if rec.Code != 200 {
		t.Fatalf("enroll = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		AgentID string `json:"agent_id"`
		Token   string `json:"agent_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.AgentID == "" || out.Token == "" {
		t.Fatalf("enroll returned %+v", out)
	}
	return out.AgentID, out.Token
}

func agentHeaders(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func minimalReport(host, id string) []byte {
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	rep := model.Report{
		SchemaVersion: "1",
		ReportID:      id,
		Metadata: model.ScanMetadata{
			ToolVersion: "0.1.0",
			StartedAt:   now.Add(-2 * time.Minute),
			FinishedAt:  &now,
			Mode:        "local",
			Host:        host,
		},
		Findings: []model.Finding{{
			VulnerabilityID:  "CVE-2026-0001",
			Product:          "openssl",
			InstalledVersion: "3.0.1",
			Ecosystem:        "Debian:12",
			Severity:         "high",
			RiskScore:        33.5,
		}},
		// A wrong summary on purpose: the server must recompute it.
		Summary: model.Summary{Total: 99, Actionable: 99, KEVCount: 99},
	}
	payload, err := report.MarshalJSON(rep)
	if err != nil {
		panic(err)
	}
	return payload
}

func TestAgentEnrollNeedsTheEnrollmentToken(t *testing.T) {
	srv := fleetServer(t)
	h := srv.Handler()
	body := `{"host":"web01"}`

	if rec := request(t, h, "POST", "/api/agents/enroll", body, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("enroll without a token = %d, want 401", rec.Code)
	}
	if rec := request(t, h, "POST", "/api/agents/enroll", body,
		map[string]string{"X-Guard-Enroll-Token": "wrong"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("enroll with a wrong token = %d, want 401", rec.Code)
	}
	// Missing host is refused once the caller is authenticated.
	enrollToken, _ := srv.fleet.EnrollToken(t.Context())
	if rec := request(t, h, "POST", "/api/agents/enroll", `{"os":"linux"}`,
		map[string]string{"X-Guard-Enroll-Token": enrollToken}); rec.Code != http.StatusBadRequest {
		t.Fatalf("enroll without a host = %d, want 400", rec.Code)
	}

	enrollAgent(t, srv, "web01")
}

func TestAgentEnrollmentIsRateLimited(t *testing.T) {
	srv := fleetServer(t)
	h := srv.Handler()
	for i := 0; i < agentEnrollFailures; i++ {
		rec := request(t, h, "POST", "/api/agents/enroll", `{"host":"x"}`,
			map[string]string{"X-Guard-Enroll-Token": "wrong"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d", i+1, rec.Code)
		}
	}
	enrollToken, _ := srv.fleet.EnrollToken(t.Context())
	rec := request(t, h, "POST", "/api/agents/enroll", `{"host":"x"}`,
		map[string]string{"X-Guard-Enroll-Token": enrollToken})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("enroll after the limit = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
}

func TestAgentCheckinStatusIsVisibleToTheDashboard(t *testing.T) {
	srv := fleetServer(t)
	h := srv.Handler()
	_, token := enrollAgent(t, srv, "web01")

	rec := request(t, h, "POST", "/api/agents/checkin",
		`{"state":"scanning","phase":"correlation","percent":45,"message":"correlating advisories","version":"0.1.0"}`,
		agentHeaders(token))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("checkin = %d: %s", rec.Code, rec.Body.String())
	}

	var agents struct {
		Fleet struct {
			Count    int `json:"count"`
			Enrolled []struct {
				Host     string `json:"host"`
				State    string `json:"state"`
				Phase    string `json:"phase"`
				Percent  int    `json:"percent"`
				Online   bool   `json:"online"`
				LastSeen string `json:"last_seen"`
			} `json:"enrolled"`
			ServerURL   string `json:"server_url"`
			EnrollToken string `json:"enroll_token"`
		} `json:"fleet"`
	}
	if rec := dashGet(t, h, "/api/agents", &agents); rec.Code != 200 {
		t.Fatalf("GET /api/agents = %d", rec.Code)
	}
	if agents.Fleet.Count != 1 || len(agents.Fleet.Enrolled) != 1 {
		t.Fatalf("fleet = %+v", agents.Fleet)
	}
	got := agents.Fleet.Enrolled[0]
	if got.Host != "web01" || got.State != "scanning" || got.Phase != "correlation" || got.Percent != 45 {
		t.Fatalf("enrolled agent = %+v", got)
	}
	if !got.Online {
		t.Fatal("a just-checked-in agent must be online")
	}
	if got.LastSeen == "" {
		t.Fatal("last_seen is missing")
	}
	if agents.Fleet.EnrollToken == "" || agents.Fleet.ServerURL == "" {
		t.Fatalf("fleet block must expose the bootstrap secret and server URL: %+v", agents.Fleet)
	}

	// An invented state is refused rather than stored.
	if rec := request(t, h, "POST", "/api/agents/checkin", `{"state":"hacked"}`, agentHeaders(token)); rec.Code != http.StatusBadRequest {
		t.Fatalf("invented state = %d, want 400", rec.Code)
	}
	// A wrong bearer is refused.
	if rec := request(t, h, "POST", "/api/agents/checkin", `{"state":"idle"}`, agentHeaders("nope")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong agent token = %d, want 401", rec.Code)
	}
}

func TestAgentReportBecomesAnEndpointInTheDashboard(t *testing.T) {
	srv := fleetServer(t)
	h := srv.Handler()
	agentID, token := enrollAgent(t, srv, "web01")

	payload := minimalReport("web01", "SCAN-20261115T100000Z-aaaa1111")
	rec := request(t, h, "POST", "/api/agents/report", string(payload), agentHeaders(token))
	if rec.Code != 200 {
		t.Fatalf("report = %d: %s", rec.Code, rec.Body.String())
	}
	var ack struct {
		RunID    string `json:"run_id"`
		Findings int    `json:"findings"`
		Accepted bool   `json:"accepted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil {
		t.Fatal(err)
	}
	if !ack.Accepted || ack.Findings != 1 || ack.RunID != "SCAN-20261115T100000Z-aaaa1111" {
		t.Fatalf("ack = %+v", ack)
	}

	// The report is a run: the asset shows up in the existing overview.
	var overview struct {
		HasData bool `json:"has_data"`
		Metrics struct {
			Assets int `json:"assets"`
		} `json:"metrics"`
	}
	if rec := dashGet(t, h, "/api/overview", &overview); rec.Code != 200 {
		t.Fatalf("overview = %d", rec.Code)
	}
	if !overview.HasData || overview.Metrics.Assets != 1 {
		t.Fatalf("remote report did not become an asset: %+v", overview)
	}

	// The stored record is recomputed from the findings, not taken from the agent
	// (the fixture claims 99 findings).
	recs, err := srv.store.ListRuns(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("stored %d runs", len(recs))
	}
	if recs[0].Findings != 1 || recs[0].Host != "web01" {
		t.Fatalf("run record = %+v", recs[0])
	}
	stored, err := srv.store.ReportByID(t.Context(), recs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	var storedRep model.Report
	if err := json.Unmarshal(stored, &storedRep); err != nil {
		t.Fatal(err)
	}
	if storedRep.Summary.Total != 1 {
		t.Fatalf("stored summary.total = %d, want 1 recomputed from the findings", storedRep.Summary.Total)
	}

	// The agent row now points at the report and is idle.
	agent, err := srv.fleet.Get(t.Context(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if agent.State != "idle" || agent.Findings != 1 || agent.LastReport != "SCAN-20261115T100000Z-aaaa1111" {
		t.Fatalf("agent after report = %+v", agent)
	}

	// Re-sending the same report is idempotent: one run, not two.
	if rec := request(t, h, "POST", "/api/agents/report", string(payload), agentHeaders(token)); rec.Code != 200 {
		t.Fatalf("replayed report = %d", rec.Code)
	}
	if recs, _ := srv.store.ListRuns(t.Context(), 10); len(recs) != 1 {
		t.Fatalf("replay stored %d runs", len(recs))
	}
}

func TestAgentReportMustMatchItsEnrolledHostname(t *testing.T) {
	srv := fleetServer(t)
	h := srv.Handler()
	_, token := enrollAgent(t, srv, "web01")

	rec := request(t, h, "POST", "/api/agents/report",
		string(minimalReport("someone-elses-host", "SCAN-20261115T100000Z-bbbb2222")), agentHeaders(token))
	if rec.Code != http.StatusConflict {
		t.Fatalf("host mismatch = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "host_mismatch") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestAgentReportValidatesTheDocument(t *testing.T) {
	srv := fleetServer(t)
	h := srv.Handler()
	_, token := enrollAgent(t, srv, "web01")

	if rec := request(t, h, "POST", "/api/agents/report", "not json", agentHeaders(token)); rec.Code != http.StatusBadRequest {
		t.Fatalf("non-JSON report = %d, want 400", rec.Code)
	}
	if rec := request(t, h, "POST", "/api/agents/report", `{"metadata":{"host":"web01"}}`, agentHeaders(token)); rec.Code != http.StatusBadRequest {
		t.Fatalf("report without report_id = %d, want 400", rec.Code)
	}
	if rec := request(t, h, "POST", "/api/agents/report", `{"report_id":"x"}`, agentHeaders(token)); rec.Code != http.StatusBadRequest {
		t.Fatalf("report without metadata.host = %d, want 400", rec.Code)
	}
}

func TestAgentManagementNeedsTheDashboardCredential(t *testing.T) {
	srv := fleetServer(t)
	h := srv.Handler()
	agentID, _ := enrollAgent(t, srv, "web01")

	if rec := request(t, h, "GET", "/api/agents", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("agents list without dashboard auth = %d, want 401", rec.Code)
	}
	if rec := request(t, h, "POST", "/api/agents/"+agentID+"/revoke", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoke without dashboard auth = %d, want 401", rec.Code)
	}
	if rec := request(t, h, "POST", "/api/agents/enroll-token/rotate", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("rotate without dashboard auth = %d, want 401", rec.Code)
	}
}

func TestRevokingAnAgentStopsIt(t *testing.T) {
	srv := fleetServer(t)
	h := srv.Handler()
	agentID, token := enrollAgent(t, srv, "web01")

	if rec := request(t, h, "POST", "/api/agents/"+agentID+"/revoke", "", dash()); rec.Code != 200 {
		t.Fatalf("revoke = %d: %s", rec.Code, rec.Body.String())
	}
	rec := request(t, h, "POST", "/api/agents/checkin", `{"state":"idle"}`, agentHeaders(token))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("checkin after revoke = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "agent_revoked") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	// The record stays for attribution, marked revoked.
	var agents struct {
		Fleet struct {
			Enrolled []struct {
				Revoked bool `json:"revoked"`
				Online  bool `json:"online"`
			} `json:"enrolled"`
		} `json:"fleet"`
	}
	if rec := dashGet(t, h, "/api/agents", &agents); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	if len(agents.Fleet.Enrolled) != 1 || !agents.Fleet.Enrolled[0].Revoked || agents.Fleet.Enrolled[0].Online {
		t.Fatalf("agent after revoke = %+v", agents.Fleet.Enrolled)
	}
}

func TestRotatedEnrollTokenStopsNewEnrollments(t *testing.T) {
	srv := fleetServer(t)
	h := srv.Handler()
	old, err := srv.fleet.EnrollToken(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var rotated struct {
		EnrollToken string `json:"enroll_token"`
	}
	rec := request(t, h, "POST", "/api/agents/enroll-token/rotate", "", dash())
	if rec.Code != 200 {
		t.Fatalf("rotate = %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.EnrollToken == "" || rotated.EnrollToken == old {
		t.Fatal("rotation did not produce a new token")
	}
	if rec := request(t, h, "POST", "/api/agents/enroll", `{"host":"new"}`, map[string]string{"X-Guard-Enroll-Token": old}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old enrollment token = %d, want 401", rec.Code)
	}
	if rec := request(t, h, "POST", "/api/agents/enroll", `{"host":"new"}`, map[string]string{"X-Guard-Enroll-Token": rotated.EnrollToken}); rec.Code != 200 {
		t.Fatalf("new enrollment token = %d, want 200", rec.Code)
	}
}

func TestAgentEventsReportWhatTheEndpointDid(t *testing.T) {
	srv := fleetServer(t)
	h := srv.Handler()
	agentID, token := enrollAgent(t, srv, "web01")
	for _, st := range []string{
		`{"state":"scanning","phase":"discovery","percent":20}`,
		`{"state":"scanning","phase":"correlation","percent":60}`,
		`{"state":"idle","phase":"idle","percent":100}`,
	} {
		if rec := request(t, h, "POST", "/api/agents/checkin", st, agentHeaders(token)); rec.Code != http.StatusNoContent {
			t.Fatalf("checkin %s = %d", st, rec.Code)
		}
	}
	var out struct {
		Agent struct {
			ID string `json:"id"`
		} `json:"agent"`
		Events []struct {
			State   string `json:"state"`
			Phase   string `json:"phase"`
			Percent int    `json:"percent"`
		} `json:"events"`
	}
	if rec := dashGet(t, h, "/api/agents/"+agentID+"/events", &out); rec.Code != 200 {
		t.Fatalf("events = %d: %s", rec.Code, rec.Body.String())
	}
	if out.Agent.ID != agentID {
		t.Fatalf("agent = %+v", out.Agent)
	}
	if len(out.Events) != 3 || out.Events[0].Phase != "idle" {
		t.Fatalf("events = %+v (newest first expected)", out.Events)
	}
	if rec := request(t, h, "GET", "/api/agents/AGT-nope/events", "", dash()); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown agent events = %d, want 404", rec.Code)
	}
}

// TestEndpointScanRoundTrip covers the 4th scan type: the dashboard queues a scan
// for an enrolled endpoint, the agent pulls it, and the result comes back.
func TestEndpointScanRoundTrip(t *testing.T) {
	srv := fleetServer(t)
	h := srv.Handler()
	agentID, token := enrollAgent(t, srv, "web01")

	// Dashboard queues the work.
	rec := request(t, h, "POST", "/api/agents/"+agentID+"/scan", "", dash())
	if rec.Code != http.StatusAccepted {
		t.Fatalf("queue = %d: %s", rec.Code, rec.Body.String())
	}
	var queued struct {
		Created bool `json:"created"`
		Task    struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"task"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &queued); err != nil {
		t.Fatal(err)
	}
	if !queued.Created || queued.Task.Status != "queued" || queued.Task.ID == "" {
		t.Fatalf("queued = %+v", queued)
	}

	// Asking twice does not stack work for an endpoint that is not picking it up.
	rec = request(t, h, "POST", "/api/agents/"+agentID+"/scan", "", dash())
	if rec.Code != http.StatusOK {
		t.Fatalf("second queue = %d, want 200 (already queued)", rec.Code)
	}

	// The dashboard already shows the pending task.
	var view struct {
		Fleet struct {
			Enrolled []struct {
				Task *struct {
					ID     string `json:"id"`
					Status string `json:"status"`
				} `json:"task"`
			} `json:"enrolled"`
		} `json:"fleet"`
	}
	if rec := dashGet(t, h, "/api/agents", &view); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	if len(view.Fleet.Enrolled) != 1 || view.Fleet.Enrolled[0].Task == nil {
		t.Fatalf("agent view = %+v", view.Fleet)
	}
	if view.Fleet.Enrolled[0].Task.Status != "queued" {
		t.Fatalf("task status = %q", view.Fleet.Enrolled[0].Task.Status)
	}

	// The agent pulls the work with its own credential.
	rec = request(t, h, "POST", "/api/agents/tasks/claim", "", agentHeaders(token))
	if rec.Code != 200 {
		t.Fatalf("claim = %d: %s", rec.Code, rec.Body.String())
	}
	var claimed struct {
		Task struct {
			ID string `json:"id"`
		} `json:"task"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &claimed); err != nil {
		t.Fatal(err)
	}
	if claimed.Task.ID != queued.Task.ID {
		t.Fatalf("claimed %q, want %q", claimed.Task.ID, queued.Task.ID)
	}
	// Nothing else is waiting.
	if rec := request(t, h, "POST", "/api/agents/tasks/claim", "", agentHeaders(token)); rec.Code != http.StatusNoContent {
		t.Fatalf("second claim = %d, want 204", rec.Code)
	}

	// The agent reports the outcome.
	body, _ := json.Marshal(map[string]string{
		"task_id": claimed.Task.ID, "status": "done", "note": "scan finished", "report_id": "SCAN-9",
	})
	if rec := request(t, h, "POST", "/api/agents/tasks/complete", string(body), agentHeaders(token)); rec.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := dashGet(t, h, "/api/agents", &view); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	task := view.Fleet.Enrolled[0].Task
	if task == nil || task.Status != "done" {
		t.Fatalf("task after completion = %+v", task)
	}
}

func TestEndpointScanAuthorization(t *testing.T) {
	srv := fleetServer(t)
	h := srv.Handler()
	agentID, token := enrollAgent(t, srv, "web01")

	// Queueing is an operator action: no dashboard credential, no work.
	if rec := request(t, h, "POST", "/api/agents/"+agentID+"/scan", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous queue = %d, want 401", rec.Code)
	}
	// An agent token is not a dashboard credential either.
	if rec := request(t, h, "POST", "/api/agents/"+agentID+"/scan", "", agentHeaders(token)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("agent-token queue = %d, want 401", rec.Code)
	}
	// Claiming and completing need the agent's own token.
	if rec := request(t, h, "POST", "/api/agents/tasks/claim", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous claim = %d, want 401", rec.Code)
	}
	if rec := request(t, h, "POST", "/api/agents/tasks/complete", `{"task_id":"TASK-1","status":"done"}`, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous complete = %d, want 401", rec.Code)
	}
	// Invalid completion status is refused (checked before revoking, since a
	// revoked token is rejected earlier in the chain).
	if rec := request(t, h, "POST", "/api/agents/tasks/complete", `{"task_id":"T","status":"maybe"}`, agentHeaders(token)); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid status = %d, want 400", rec.Code)
	}
	// A revoked endpoint cannot be asked to scan.
	if rec := request(t, h, "POST", "/api/agents/"+agentID+"/revoke", "", dash()); rec.Code != 200 {
		t.Fatalf("revoke = %d", rec.Code)
	}
	if rec := request(t, h, "POST", "/api/agents/"+agentID+"/scan", "", dash()); rec.Code != http.StatusConflict {
		t.Fatalf("queue for revoked agent = %d, want 409", rec.Code)
	}
	// Unknown agent.
	if rec := request(t, h, "POST", "/api/agents/AGT-nope/scan", "", dash()); rec.Code != http.StatusNotFound {
		t.Fatalf("queue for unknown agent = %d, want 404", rec.Code)
	}
}

// TestEndpointScanDispatchesImmediatelyToAWatcher is the promise an administrator
// relies on: asking for a scan of an endpoint that is up starts it now, not at the
// next poll. The held claim request is what makes that immediate, and the same
// request is what proves the endpoint is reachable.
func TestEndpointScanDispatchesImmediatelyToAWatcher(t *testing.T) {
	srv := fleetServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	agentID, token := enrollAgent(t, srv, "web01")

	type claimResult struct {
		taskID  string
		status  int
		elapsed time.Duration
		err     error
	}
	claims := make(chan claimResult, 1)
	go func() {
		start := time.Now()
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/agents/tasks/claim?wait=5", nil)
		if err != nil {
			claims <- claimResult{err: err}
			return
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			claims <- claimResult{err: err}
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent {
			claims <- claimResult{status: resp.StatusCode, elapsed: time.Since(start)}
			return
		}
		var body struct {
			Task struct {
				ID string `json:"id"`
			} `json:"task"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		claims <- claimResult{taskID: body.Task.ID, status: resp.StatusCode, elapsed: time.Since(start)}
	}()

	// While the request is held the endpoint is online, and the dashboard says why.
	deadline := time.Now().Add(2 * time.Second)
	for {
		var view struct {
			Fleet struct {
				Enrolled []struct {
					Online   bool `json:"online"`
					Watching bool `json:"watching"`
				} `json:"enrolled"`
			} `json:"fleet"`
		}
		dashGet(t, srv.Handler(), "/api/agents", &view)
		if len(view.Fleet.Enrolled) == 1 && view.Fleet.Enrolled[0].Watching {
			if !view.Fleet.Enrolled[0].Online {
				t.Fatal("a held claim request must make the endpoint online")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the claim request never registered as held")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// An administrator asks for a scan: the held request must be answered at once.
	queuedAt := time.Now()
	rec := request(t, srv.Handler(), "POST", "/api/agents/"+agentID+"/scan", "", dash())
	if rec.Code != http.StatusAccepted {
		t.Fatalf("queue = %d: %s", rec.Code, rec.Body.String())
	}
	var got claimResult
	select {
	case got = <-claims:
	case <-time.After(2 * time.Second):
		t.Fatal("the held claim request was not answered within 2s of the request")
	}
	if got.err != nil {
		t.Fatalf("claim: %v", got.err)
	}
	if got.taskID == "" {
		t.Fatalf("claim returned no task (status %d) after %.0fms", got.status, float64(got.elapsed.Milliseconds()))
	}
	if dispatch := time.Since(queuedAt); dispatch > 2*time.Second {
		t.Fatalf("dispatch took %s; a reachable endpoint must start immediately", dispatch)
	}
	if got.elapsed > 3*time.Second {
		t.Fatalf("claim waited %s despite work being queued", got.elapsed)
	}

	// With no request held and nothing scanning, the endpoint is not reachable.
	if rec := request(t, srv.Handler(), "POST", "/api/agents/tasks/claim", "", agentHeaders(token)); rec.Code != http.StatusNoContent {
		t.Fatalf("claim after the task was taken = %d, want 204", rec.Code)
	}
}

// TestClaimWithoutWaitReturnsImmediately keeps the older callers working: no
// ?wait= means claim-and-return, which is also what an `--once` run uses.
func TestClaimWithoutWaitReturnsImmediately(t *testing.T) {
	srv := fleetServer(t)
	_, token := enrollAgent(t, srv, "web01")
	start := time.Now()
	rec := request(t, srv.Handler(), "POST", "/api/agents/tasks/claim", "", agentHeaders(token))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("claim with nothing queued = %d, want 204", rec.Code)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a claim without ?wait= must not block (took %s)", elapsed)
	}
}

// TestCancellingAQueuedScan covers the operator changing their mind: a request
// that no agent has claimed can be withdrawn, and the agent then finds nothing.
func TestCancellingAQueuedScan(t *testing.T) {
	srv := fleetServer(t)
	h := srv.Handler()
	agentID, token := enrollAgent(t, srv, "web01")

	if rec := request(t, h, "POST", "/api/agents/"+agentID+"/scan", "", dash()); rec.Code != http.StatusAccepted {
		t.Fatalf("queue = %d", rec.Code)
	}
	if rec := request(t, h, "POST", "/api/agents/"+agentID+"/scan/cancel", "", dash()); rec.Code != 200 {
		t.Fatalf("cancel = %d: %s", rec.Code, rec.Body.String())
	}
	// The withdrawn task is not claimable.
	if rec := request(t, h, "POST", "/api/agents/tasks/claim", "", agentHeaders(token)); rec.Code != http.StatusNoContent {
		t.Fatalf("claim after cancel = %d, want 204", rec.Code)
	}
	// Nothing left to cancel.
	if rec := request(t, h, "POST", "/api/agents/"+agentID+"/scan/cancel", "", dash()); rec.Code != http.StatusNotFound {
		t.Fatalf("second cancel = %d, want 404", rec.Code)
	}
	// A fresh request still works afterwards.
	if rec := request(t, h, "POST", "/api/agents/"+agentID+"/scan", "", dash()); rec.Code != http.StatusAccepted {
		t.Fatalf("queue after cancel = %d", rec.Code)
	}
	// Cancelling is an operator action.
	if rec := request(t, h, "POST", "/api/agents/"+agentID+"/scan/cancel", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous cancel = %d, want 401", rec.Code)
	}
}

// TestRunningScanCannotBeCancelled keeps the limitation explicit: there is no
// command channel, so the server must not claim it stopped a running scan.
func TestRunningScanCannotBeCancelled(t *testing.T) {
	srv := fleetServer(t)
	h := srv.Handler()
	agentID, token := enrollAgent(t, srv, "web01")
	request(t, h, "POST", "/api/agents/"+agentID+"/scan", "", dash())
	if rec := request(t, h, "POST", "/api/agents/tasks/claim", "", agentHeaders(token)); rec.Code != 200 {
		t.Fatalf("claim = %d", rec.Code)
	}
	if rec := request(t, h, "POST", "/api/agents/"+agentID+"/scan/cancel", "", dash()); rec.Code != http.StatusNotFound {
		t.Fatalf("cancel while running = %d, want 404 (cannot stop a running scan)", rec.Code)
	}
}

// TestEnrollmentCannotTakeOverAnExistingIdentity is the security property from the
// brief: a second machine that claims an enrolled hostname must not be able to
// rotate the existing agent's credential. Recovery is an explicit operator action.
func TestEnrollmentCannotTakeOverAnExistingIdentity(t *testing.T) {
	srv := fleetServer(t)
	h := srv.Handler()
	enrollToken, _ := srv.fleet.EnrollToken(t.Context())

	body := `{"host":"web01","os":"Ubuntu 24.04","version":"0.1.5"}`
	first := request(t, h, "POST", "/api/agents/enroll", body, map[string]string{"X-Guard-Enroll-Token": enrollToken})
	if first.Code != 200 {
		t.Fatalf("first enroll = %d", first.Code)
	}
	var enrolled struct {
		AgentID string `json:"agent_id"`
		Token   string `json:"agent_token"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &enrolled); err != nil {
		t.Fatal(err)
	}

	// Same hostname, no proof of possession: refused.
	second := request(t, h, "POST", "/api/agents/enroll", body, map[string]string{"X-Guard-Enroll-Token": enrollToken})
	if second.Code != http.StatusConflict {
		t.Fatalf("takeover attempt = %d, want 409: %s", second.Code, second.Body.String())
	}
	if !strings.Contains(second.Body.String(), "identity_conflict") {
		t.Fatalf("body = %s", second.Body.String())
	}

	// The original credential still works, so the real endpoint keeps reporting.
	if rec := request(t, h, "POST", "/api/agents/checkin", `{"state":"idle"}`, agentHeaders(enrolled.Token)); rec.Code != http.StatusNoContent {
		t.Fatalf("original agent lost access: %d", rec.Code)
	}

	// Proof of possession (the current credential) may re-attach the identity.
	third := request(t, h, "POST", "/api/agents/enroll", body, map[string]string{
		"X-Guard-Enroll-Token": enrollToken,
		"Authorization":        "Bearer " + enrolled.Token,
	})
	if third.Code != 200 {
		t.Fatalf("re-attach with proof = %d: %s", third.Code, third.Body.String())
	}
	var reattached struct {
		AgentID string `json:"agent_id"`
		Token   string `json:"agent_token"`
	}
	if err := json.Unmarshal(third.Body.Bytes(), &reattached); err != nil {
		t.Fatal(err)
	}
	if reattached.AgentID != enrolled.AgentID || reattached.Token == enrolled.Token {
		t.Fatalf("re-attach did not keep the identity and rotate the token: %+v", reattached)
	}
	if rec := request(t, h, "POST", "/api/agents/checkin", `{"state":"idle"}`, agentHeaders(enrolled.Token)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("superseded credential still works: %d", rec.Code)
	}

	// Operator recovery: revoke, then a fresh identity is allowed.
	if rec := request(t, h, "POST", "/api/agents/"+reattached.AgentID+"/revoke", "", dash()); rec.Code != 200 {
		t.Fatalf("revoke = %d", rec.Code)
	}
	fourth := request(t, h, "POST", "/api/agents/enroll", body, map[string]string{"X-Guard-Enroll-Token": enrollToken})
	if fourth.Code != 200 {
		t.Fatalf("enroll after revoke = %d: %s", fourth.Code, fourth.Body.String())
	}
}
