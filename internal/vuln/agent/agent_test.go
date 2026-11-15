package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clanker-guard", "agent.json")
	if _, err := LoadConfig(path); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("LoadConfig(missing) = %v, want ErrNotEnrolled", err)
	}
	want := Config{Server: "https://guard.example:8787", AgentID: "AGT-abc", Token: "tok", Host: "web01",
		EnrolledAt: time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)}
	if err := SaveConfig(path, want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config mode = %o, want 600", got)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got.Server != want.Server || got.AgentID != want.AgentID || got.Token != want.Token {
		t.Fatalf("round trip = %+v", got)
	}
	if err := RemoveConfig(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); !errors.Is(err, ErrNotEnrolled) {
		t.Fatal("config survived removal")
	}
}

func TestLoadConfigRejectsIncompleteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte(`{"server":"https://x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("an incomplete config must be an error, not silent local mode")
	}
}

func TestEnrollThenCheckinAndReport(t *testing.T) {
	var gotEnrollToken string
	var gotBearer []string
	var reportedBytes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agents/enroll":
			gotEnrollToken = r.Header.Get("X-Guard-Enroll-Token")
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["host"] != "web01" || body["os"] != "Ubuntu 24.04" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad body"}`))
				return
			}
			_, _ = w.Write([]byte(`{"agent_id":"AGT-123","agent_token":"agent-secret"}`))
		case "/api/agents/checkin":
			gotBearer = append(gotBearer, r.Header.Get("Authorization"))
			var st Status
			if err := json.NewDecoder(r.Body).Decode(&st); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if st.State != "scanning" || st.Phase != "correlation" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"unexpected status"}`))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/api/agents/report":
			gotBearer = append(gotBearer, r.Header.Get("Authorization"))
			buf := make([]byte, 0)
			chunk := make([]byte, 1024)
			for {
				n, err := r.Body.Read(chunk)
				buf = append(buf, chunk[:n]...)
				if err != nil {
					break
				}
			}
			reportedBytes = len(buf)
			_, _ = w.Write([]byte(`{"run_id":"SCAN-1","findings":7,"accepted":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := New(srv.URL+"/", "")
	if c.Server != srv.URL {
		t.Fatalf("New trimmed the URL wrong: %q", c.Server)
	}
	if !c.PlainHTTP() {
		t.Fatal("PlainHTTP should be true for an http:// test server")
	}

	cfg, err := c.Enroll(context.Background(), "enroll-secret", "web01", "Ubuntu 24.04", "0.1.0")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if gotEnrollToken != "enroll-secret" {
		t.Fatalf("enrollment token header = %q", gotEnrollToken)
	}
	if cfg.AgentID != "AGT-123" || cfg.Token != "agent-secret" || cfg.Server != srv.URL {
		t.Fatalf("enrollment result = %+v", cfg)
	}

	authed := New(cfg.Server, cfg.Token)
	if err := authed.Checkin(context.Background(), Status{State: "scanning", Phase: "correlation", Percent: 45}); err != nil {
		t.Fatalf("Checkin: %v", err)
	}

	report := []byte(`{"schema_version":"1","report_id":"SCAN-1","findings":[]}`)
	ack, err := authed.Report(context.Background(), report)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if !ack.Accepted || ack.RunID != "SCAN-1" || reportedBytes != len(report) {
		t.Fatalf("ack = %+v, sent %d bytes", ack, reportedBytes)
	}
	for _, h := range gotBearer {
		if h != "Bearer agent-secret" {
			t.Fatalf("bearer header = %q", h)
		}
	}
}

func TestClientSurfacesServerErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"agent token is not valid","code":"unauthorized"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "stale")
	err := c.Checkin(context.Background(), Status{State: "idle"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !contains(err.Error(), "agent token is not valid") {
		t.Fatalf("error did not carry the server message: %v", err)
	}

	// An empty report is refused before any request is made.
	if _, err := c.Report(context.Background(), nil); err == nil {
		t.Fatal("empty report accepted")
	}
}

func TestReporterThrottlesRepeatedStatuses(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	clock := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	rep := NewReporter(New(srv.URL, "tok"))
	rep.Now = func() time.Time { return clock }
	rep.MinInterval = time.Second

	ctx := context.Background()
	st := Status{State: "scanning", Phase: "discovery", Percent: 20}
	if err := rep.Send(ctx, st, false); err != nil {
		t.Fatal(err)
	}
	// Same bucket inside the window: dropped.
	if err := rep.Send(ctx, st, false); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("sent %d requests, want 1", calls)
	}
	// A later stage always goes out.
	if err := rep.Send(ctx, Status{State: "scanning", Phase: "correlation", Percent: 60}, false); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("sent %d requests, want 2", calls)
	}
	// force bypasses the throttle for the final update.
	clock = clock.Add(time.Hour)
	if err := rep.Send(ctx, Status{State: "idle", Phase: "idle", Percent: 100}, true); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("sent %d requests, want 3", calls)
	}
	if rep.LastError() != nil {
		t.Fatalf("LastError = %v", rep.LastError())
	}
}

func TestReporterRecordsTransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	rep := NewReporter(New(srv.URL, "tok"))
	err := rep.Send(context.Background(), Status{State: "scanning"}, true)
	srv.Close()
	if err == nil {
		t.Fatal("expected the failure to be returned")
	}
	if rep.LastError() == nil {
		t.Fatal("LastError did not remember the failure")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})())
}

func TestClaimAndCompleteTask(t *testing.T) {
	var completed map[string]string
	claimed := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/agents/tasks/claim":
			claimed++
			if claimed > 1 {
				w.WriteHeader(http.StatusNoContent) // nothing left to do
				return
			}
			_, _ = w.Write([]byte(`{"task":{"id":"TASK-1","agent_id":"AGT-1","kind":"scan","status":"running","requested_at":"2026-11-15T10:00:00Z"}}`))
		case "/api/agents/tasks/complete":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			completed = body
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	task, err := c.ClaimTask(context.Background())
	if err != nil {
		t.Fatalf("ClaimTask: %v", err)
	}
	if task == nil || task.ID != "TASK-1" || task.Kind != "scan" {
		t.Fatalf("task = %+v", task)
	}
	// An empty queue is a normal answer, not an error.
	if again, err := c.ClaimTask(context.Background()); err != nil || again != nil {
		t.Fatalf("second claim = %+v, %v (want nil, nil)", again, err)
	}

	if err := c.CompleteTask(context.Background(), "TASK-1", "done", "scan finished", "SCAN-1"); err != nil {
		t.Fatalf("CompleteTask: %v", err)
	}
	if completed["task_id"] != "TASK-1" || completed["status"] != "done" || completed["report_id"] != "SCAN-1" {
		t.Fatalf("completion body = %+v", completed)
	}
}

func TestClaimTaskSurfacesErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"this endpoint was revoked"}`))
	}))
	defer srv.Close()
	if _, err := New(srv.URL, "stale").ClaimTask(context.Background()); err == nil {
		t.Fatal("a revoked agent must see the error, not an empty queue")
	}
}

func TestValidateTransport(t *testing.T) {
	cases := []struct {
		name          string
		server        string
		allowInsecure bool
		wantErr       bool
	}{
		{"https", "https://guard.example:8787", false, false},
		{"loopback http", "http://127.0.0.1:8787", false, false},
		{"loopback localhost", "http://localhost:8787", false, false},
		{"lan http", "http://192.168.20.77:8787", false, true},
		{"lan http explicitly allowed", "http://192.168.20.77:8787", true, false},
		{"no scheme", "guard.example:8787", false, true},
		{"empty", "", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTransport(tc.server, tc.allowInsecure)
			if tc.wantErr && err == nil {
				t.Fatalf("%q must be refused", tc.server)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("%q: %v", tc.server, err)
			}
		})
	}
}

// TestEnrollSendsProofOfPossession pins the wire behaviour a reinstall relies on:
// when the client already holds a credential, the enrollment request carries it so
// the server can tell a legitimate reinstall from a hostname takeover.
func TestEnrollSendsProofOfPossession(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"agent_id":"AGT-1","agent_token":"new"}`))
	}))
	defer srv.Close()

	if _, err := New(srv.URL, "existing-token").Enroll(context.Background(), "enroll", "web01", "", ""); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if gotAuth != "Bearer existing-token" {
		t.Fatalf("enrollment did not present the existing credential: %q", gotAuth)
	}
}

// TestReportSendsSubmissionHeaders pins what the server's replay protection reads:
// a unique id, the digest of the exact bytes, and the sequence when one is given.
func TestReportSendsSubmissionHeaders(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = map[string]string{
			"id":       r.Header.Get("X-Guard-Submission-Id"),
			"digest":   r.Header.Get("X-Guard-Payload-SHA256"),
			"sequence": r.Header.Get("X-Guard-Sequence"),
		}
		_, _ = w.Write([]byte(`{"run_id":"SCAN-1","accepted":true}`))
	}))
	defer srv.Close()

	body := []byte(`{"report_id":"SCAN-1"}`)
	if _, err := New(srv.URL, "tok").ReportWithSequence(context.Background(), body, 7); err != nil {
		t.Fatalf("Report: %v", err)
	}
	sum := sha256.Sum256(body)
	if got["digest"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest = %q", got["digest"])
	}
	if got["sequence"] != "7" {
		t.Fatalf("sequence = %q", got["sequence"])
	}
	if len(got["id"]) < 16 {
		t.Fatalf("submission id = %q", got["id"])
	}

	// A second call must not reuse the submission id.
	first := got["id"]
	if _, err := New(srv.URL, "tok").ReportWithSequence(context.Background(), body, 8); err != nil {
		t.Fatal(err)
	}
	if got["id"] == first {
		t.Fatal("submission ids must be unique per upload")
	}
}
