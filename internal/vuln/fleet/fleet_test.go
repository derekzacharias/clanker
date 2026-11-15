package fleet

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "intel.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	// fleet tables live beside the scanner tables in the same cache database.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	st, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	st.SetClock(func() time.Time { return now })
	return st, &now
}

func TestEnrollTokenIsCreatedOnceAndRotatable(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()

	first, err := st.EnrollToken(ctx)
	if err != nil {
		t.Fatalf("EnrollToken: %v", err)
	}
	if len(first) < 40 {
		t.Fatalf("enrollment token is too short: %q", first)
	}
	again, err := st.EnrollToken(ctx)
	if err != nil {
		t.Fatalf("EnrollToken (second call): %v", err)
	}
	if again != first {
		t.Fatal("EnrollToken must be stable until rotated")
	}
	rotated, err := st.RotateEnrollToken(ctx)
	if err != nil {
		t.Fatalf("RotateEnrollToken: %v", err)
	}
	if rotated == first {
		t.Fatal("rotation returned the previous token")
	}
	if current, _ := st.EnrollToken(ctx); current != rotated {
		t.Fatal("EnrollToken did not return the rotated value")
	}
}

func TestEnrollStoresOnlyAHash(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()

	agent, token, err := st.Enroll(ctx, "web01.example.com", "Ubuntu 24.04", "0.1.0", "")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if !strings.HasPrefix(agent.ID, "AGT-") {
		t.Fatalf("id = %q", agent.ID)
	}
	if agent.State != StateEnrolled {
		t.Fatalf("state = %q", agent.State)
	}
	if token == "" || agent.LastSeen == nil {
		t.Fatal("enroll must return a token and record the time")
	}

	var stored string
	if err := st.db.QueryRowContext(ctx, `SELECT token_hash FROM agents WHERE id = ?`, agent.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token || strings.Contains(stored, token) {
		t.Fatal("the bearer token must never be stored in plaintext")
	}
	if stored != hashToken(token) {
		t.Fatal("token_hash is not the SHA-256 of the token")
	}

	got, err := st.Authenticate(ctx, token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != agent.ID || got.Host != "web01.example.com" {
		t.Fatalf("Authenticate returned %+v", got)
	}
	if _, err := st.Authenticate(ctx, "not-a-token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong token error = %v, want ErrNotFound", err)
	}
	if _, err := st.Authenticate(ctx, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty token error = %v, want ErrNotFound", err)
	}

	// Two enrollments must not share an id or a token.
	other, otherToken, err := st.Enroll(ctx, "web02", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if other.ID == agent.ID || otherToken == token {
		t.Fatal("enrollments reused an id or token")
	}
}

func TestCheckinUpdatesStatusAndKeepsHistory(t *testing.T) {
	st, now := newStore(t)
	ctx := context.Background()
	agent, token, err := st.Enroll(ctx, "db01", "Debian 12", "0.1.0", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Authenticate(ctx, token); err != nil {
		t.Fatal(err)
	}

	*now = now.Add(2 * time.Minute)
	if err := st.Checkin(ctx, agent.ID, Checkin{
		State: StateScanning, Phase: "correlation", Percent: 45,
		Message: "correlating advisories", Findings: 3, Version: "0.1.0", OS: "Debian 12",
	}); err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	got, err := st.Get(ctx, agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateScanning || got.Phase != "correlation" || got.Percent != 45 {
		t.Fatalf("status not recorded: %+v", got)
	}
	if got.Findings != 3 || got.Message != "correlating advisories" {
		t.Fatalf("status not recorded: %+v", got)
	}
	if got.LastSeen == nil || !got.LastSeen.Equal(*now) {
		t.Fatalf("last_seen = %v, want %v", got.LastSeen, *now)
	}
	if !got.Online(*now) {
		t.Fatal("a just-checked-in agent must be online")
	}
	if got.Online(now.Add(ReachableWindow + time.Minute)) {
		t.Fatal("an agent silent past the window must be offline")
	}

	events, err := st.Events(ctx, agent.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Phase != "correlation" || events[0].Percent != 45 {
		t.Fatalf("events = %+v", events)
	}

	if err := st.Checkin(ctx, agent.ID, Checkin{State: "made-up"}); err == nil {
		t.Fatal("an invented state must be refused")
	}
	if err := st.Checkin(ctx, "AGT-nope", Checkin{State: StateIdle}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown agent error = %v", err)
	}
	// Percent is clamped rather than trusted.
	if err := st.Checkin(ctx, agent.ID, Checkin{State: StateScanning, Percent: 900}); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get(ctx, agent.ID); got.Percent != 100 {
		t.Fatalf("percent = %d, want clamped 100", got.Percent)
	}
}

func TestEventHistoryIsBounded(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()
	agent, _, err := st.Enroll(ctx, "host1", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 130; i++ {
		if err := st.Checkin(ctx, agent.ID, Checkin{State: StateScanning, Percent: i % 100, Phase: "p"}); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_events WHERE agent_id = ?`, agent.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count > 100 {
		t.Fatalf("kept %d events, want at most 100", count)
	}
	events, err := st.Events(ctx, agent.ID, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 5 {
		t.Fatalf("Events(limit 5) returned %d", len(events))
	}
}

func TestMarkReportAndRevoke(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()
	keep, keepToken, _ := st.Enroll(ctx, "host-keep", "", "", "")
	gone, goneToken, _ := st.Enroll(ctx, "host-gone", "", "", "")

	if err := st.MarkReport(ctx, gone.ID, "SCAN-1", 42); err != nil {
		t.Fatalf("MarkReport: %v", err)
	}
	got, _ := st.Get(ctx, gone.ID)
	if got.Findings != 42 || got.LastReport != "SCAN-1" || got.State != StateIdle {
		t.Fatalf("report not recorded: %+v", got)
	}

	if err := st.Revoke(ctx, gone.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := st.Authenticate(ctx, goneToken); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked token error = %v, want ErrRevoked", err)
	}
	if err := st.Checkin(ctx, gone.ID, Checkin{State: StateIdle}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("check-in after revoke = %v, want ErrNotFound", err)
	}
	// Revocation is per endpoint: the rest of the fleet keeps reporting.
	if _, err := st.Authenticate(ctx, keepToken); err != nil {
		t.Fatalf("unrelated agent lost access: %v", err)
	}
	if err := st.Checkin(ctx, keep.ID, Checkin{State: StateIdle}); err != nil {
		t.Fatalf("unrelated agent check-in: %v", err)
	}
	// The record survives so its history stays attributable.
	list, err := st.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var sawRevoked bool
	for _, a := range list {
		if a.ID == gone.ID {
			sawRevoked = a.Revoked
		}
	}
	if !sawRevoked {
		t.Fatal("revoked agent disappeared from the list")
	}
	if err := st.Revoke(ctx, "AGT-nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking an unknown agent = %v", err)
	}
}

func TestListIsOrderedByActivity(t *testing.T) {
	st, now := newStore(t)
	ctx := context.Background()
	old, _, _ := st.Enroll(ctx, "old", "", "", "")
	*now = now.Add(time.Hour)
	recent, _, _ := st.Enroll(ctx, "recent", "", "", "")

	list, err := st.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d agents", len(list))
	}
	if list[0].ID != recent.ID || list[1].ID != old.ID {
		t.Fatalf("order = %s, %s; want %s, %s", list[0].Host, list[1].Host, "recent", "old")
	}
}

func TestTruncateKeepsUTF8(t *testing.T) {
	long := strings.Repeat("é", 300)
	got := truncate(long, 255)
	if len(got) > 255 {
		t.Fatalf("truncate returned %d bytes", len(got))
	}
	for _, r := range got {
		if r == '\uFFFD' {
			t.Fatal("truncate split a multi-byte rune")
		}
	}
}

func TestScanTaskLifecycle(t *testing.T) {
	st, now := newStore(t)
	ctx := context.Background()
	agent, _, err := st.Enroll(ctx, "web01", "", "0.1.2", "")
	if err != nil {
		t.Fatal(err)
	}

	task, created, err := st.QueueScan(ctx, agent.ID)
	if err != nil {
		t.Fatalf("QueueScan: %v", err)
	}
	if !created || task.Status != TaskQueued || task.Kind != TaskScan {
		t.Fatalf("task = %+v created=%v", task, created)
	}
	if !strings.HasPrefix(task.ID, "TASK-") {
		t.Fatalf("task id = %q", task.ID)
	}

	// Asking again while work is pending returns the same task instead of stacking.
	again, createdAgain, err := st.QueueScan(ctx, agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if createdAgain || again.ID != task.ID {
		t.Fatalf("re-queue returned %+v (created=%v), want the pending task", again, createdAgain)
	}

	// The agent pulls the work; a second claim finds nothing to do.
	claimed, err := st.ClaimTask(ctx, agent.ID)
	if err != nil || claimed == nil {
		t.Fatalf("ClaimTask = %v, %v", claimed, err)
	}
	if claimed.ID != task.ID || claimed.Status != TaskRunning || claimed.StartedAt == nil {
		t.Fatalf("claimed = %+v", claimed)
	}
	if second, err := st.ClaimTask(ctx, agent.ID); err != nil || second != nil {
		t.Fatalf("second claim = %+v, %v (want nil)", second, err)
	}

	// Completion records the report so the dashboard can link to it.
	*now = now.Add(45 * time.Second)
	if err := st.CompleteTask(ctx, agent.ID, task.ID, TaskDone, "scan finished", "SCAN-1"); err != nil {
		t.Fatalf("CompleteTask: %v", err)
	}
	got, err := st.LatestTask(ctx, agent.ID)
	if err != nil || got == nil {
		t.Fatalf("LatestTask = %v, %v", got, err)
	}
	if got.Status != TaskDone || got.ReportID != "SCAN-1" || got.FinishedAt == nil {
		t.Fatalf("completed task = %+v", got)
	}
	// Finishing twice is a stale-client error, not a silent overwrite.
	if err := st.CompleteTask(ctx, agent.ID, task.ID, TaskDone, "", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second completion = %v, want ErrNotFound", err)
	}
	// Work can be requested again once the previous task finished.
	if _, created, err := st.QueueScan(ctx, agent.ID); err != nil || !created {
		t.Fatalf("queue after completion = created=%v err=%v", created, err)
	}
}

func TestScanTaskRefusesUnknownAndRevokedAgents(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()
	if _, _, err := st.QueueScan(ctx, "AGT-nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("queue for unknown agent = %v", err)
	}
	agent, _, _ := st.Enroll(ctx, "web01", "", "", "")
	if err := st.Revoke(ctx, agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.QueueScan(ctx, agent.ID); !errors.Is(err, ErrRevoked) {
		t.Fatalf("queue for revoked agent = %v, want ErrRevoked", err)
	}
}

func TestScanTaskValidation(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()
	agent, _, _ := st.Enroll(ctx, "web01", "", "", "")
	task, _, _ := st.QueueScan(ctx, agent.ID)
	if err := st.CompleteTask(ctx, agent.ID, task.ID, "invented", "", ""); err == nil {
		t.Fatal("an invented task status must be refused")
	}
	// Another agent cannot complete someone else's task.
	other, _, _ := st.Enroll(ctx, "web02", "", "", "")
	if err := st.CompleteTask(ctx, other.ID, task.ID, TaskDone, "", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-agent completion = %v, want ErrNotFound", err)
	}
	tasks, err := st.Tasks(ctx, agent.ID, 5)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("Tasks = %v, %v", tasks, err)
	}
}

// TestReenrollingAHostRequiresProofOfPossession is the identity-binding rule: a
// hostname is not an identity. A second machine claiming the same name must not be
// able to take over the agent that already owns it.
func TestReenrollingAHostRequiresProofOfPossession(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()

	first, firstToken, err := st.Enroll(ctx, "web01", "Ubuntu 24.04", "0.1.4", "")
	if err != nil {
		t.Fatal(err)
	}

	// No credential: refused, and the existing agent keeps working untouched.
	if _, _, err := st.Enroll(ctx, "web01", "Ubuntu 24.04", "0.1.5", ""); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("re-enroll without proof = %v, want ErrIdentityConflict", err)
	}
	if got, err := st.Authenticate(ctx, firstToken); err != nil || got.ID != first.ID {
		t.Fatalf("existing agent lost its credential: %+v %v", got, err)
	}

	// A token belonging to a different endpoint proves nothing.
	if _, otherToken, err := st.Enroll(ctx, "web02", "", "", ""); err != nil {
		t.Fatal(err)
	} else if _, _, err := st.Enroll(ctx, "web01", "", "", otherToken); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("cross-agent proof = %v, want ErrIdentityConflict", err)
	}

	// Proof of possession re-attaches the same identity and rotates the token.
	again, newToken, err := st.Enroll(ctx, "web01", "Ubuntu 24.04", "0.1.5", firstToken)
	if err != nil {
		t.Fatalf("re-enroll with proof: %v", err)
	}
	if again.ID != first.ID {
		t.Fatalf("identity changed on re-attach: %s -> %s", first.ID, again.ID)
	}
	if newToken == firstToken {
		t.Fatal("re-attach must rotate the credential")
	}
	if _, err := st.Authenticate(ctx, firstToken); !errors.Is(err, ErrNotFound) {
		t.Fatal("the superseded credential still authenticates")
	}
	if got, err := st.Authenticate(ctx, newToken); err != nil || got.ID != first.ID {
		t.Fatalf("new credential invalid: %+v %v", got, err)
	}
	if list, _ := st.List(ctx); len(list) != 2 {
		t.Fatalf("fleet has %d rows, want 2 (web01 re-attached, web02)", len(list))
	}
}

// TestOperatorRevokeAllowsAFreshIdentity documents the supported recovery path when
// an endpoint has lost its credential: the operator revokes it, then enrollment
// creates a new identity instead of silently rotating the old one.
func TestOperatorRevokeAllowsAFreshIdentity(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()
	first, firstToken, err := st.Enroll(ctx, "web01", "", "0.1.4", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Revoke(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Authenticate(ctx, firstToken); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked credential = %v, want ErrRevoked", err)
	}
	replacement, replacementToken, err := st.Enroll(ctx, "web01", "", "0.1.5", "")
	if err != nil {
		t.Fatalf("enroll after revoke: %v", err)
	}
	if replacement.ID == first.ID {
		t.Fatal("a new identity must be issued after revocation")
	}
	if got, err := st.Authenticate(ctx, replacementToken); err != nil || got.ID != replacement.ID {
		t.Fatalf("replacement credential invalid: %+v %v", got, err)
	}
}
