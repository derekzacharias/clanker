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

// OpenStoreForTest opens an existing database file through the real migration path.
func OpenStoreForTest(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)`); err != nil {
		db.Close()
		return nil, err
	}
	st, err := New(db)
	if err != nil {
		db.Close()
		return nil, err
	}
	return st, nil
}

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

func TestEnrollTokensAreSingleUseExpiringAndHashed(t *testing.T) {
	st, now := newStore(t)
	ctx := context.Background()

	token, expires, err := st.MintEnrollToken(ctx, time.Hour, "laptop")
	if err != nil {
		t.Fatalf("MintEnrollToken: %v", err)
	}
	if len(token) < 40 {
		t.Fatalf("token is too short: %q", token)
	}
	if !expires.Equal(now.Add(time.Hour)) {
		t.Fatalf("expiry = %s", expires)
	}
	// Only the hash is stored.
	var stored string
	if err := st.db.QueryRowContext(ctx, `SELECT token_hash FROM agent_enroll_tokens`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token {
		t.Fatal("the enrollment token must not be stored in plaintext")
	}

	// First consumption wins; the second is refused as already used.
	if err := st.ConsumeEnrollToken(ctx, token, "web01"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := st.ConsumeEnrollToken(ctx, token, "web02"); !errors.Is(err, ErrEnrollTokenUsed) {
		t.Fatalf("second consume = %v, want ErrEnrollTokenUsed", err)
	}
	// An unknown token is indistinguishable from a wrong one.
	if err := st.ConsumeEnrollToken(ctx, "nope", ""); !errors.Is(err, ErrEnrollTokenInvalid) {
		t.Fatalf("unknown token = %v, want ErrEnrollTokenInvalid", err)
	}
	if err := st.ConsumeEnrollToken(ctx, "", ""); !errors.Is(err, ErrEnrollTokenInvalid) {
		t.Fatalf("empty token = %v", err)
	}

	// Expiry is enforced against the store clock.
	short, _, err := st.MintEnrollToken(ctx, time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(2 * time.Minute)
	if err := st.ConsumeEnrollToken(ctx, short, ""); !errors.Is(err, ErrEnrollTokenExpired) {
		t.Fatalf("expired token = %v, want ErrEnrollTokenExpired", err)
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

// A watching agent is in constant contact, so it must not read as stale. The bug this
// pins: presence said online while "last seen" said hours ago, because only check-ins
// moved the clock and a held claim request never does.
func TestTouchMakesAWatchingAgentReadAsJustSeen(t *testing.T) {
	st, clock := newStore(t)
	ctx := context.Background()
	ag, _, _ := st.Enroll(ctx, "host-watch", "", "", "")

	// Two hours of watching: the agent is reachable, but nothing has reported.
	*clock = clock.Add(2 * time.Hour)
	before, err := st.Get(ctx, ag.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if before.Online(*clock) {
		t.Fatal("an agent silent for two hours must not look reachable on the clock alone")
	}

	if err := st.Touch(ctx, ag.ID); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	got, err := st.Get(ctx, ag.ID)
	if err != nil {
		t.Fatalf("Get after touch: %v", err)
	}
	if v := got.Online(*clock); !v {
		t.Fatalf("agent still offline after contact: %+v", got)
	}
	if got.State != before.State {
		t.Fatalf("contact must not change what the agent is doing: %q -> %q", before.State, got.State)
	}
	if got.Findings != before.Findings || got.LastReport != before.LastReport {
		t.Fatalf("contact must not invent results: %+v", got)
	}
}

// Revoked endpoints are gone: contact from a token that no longer authenticates must
// not resurrect a last-seen timestamp.
func TestTouchIgnoresRevokedAgents(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()
	ag, _, _ := st.Enroll(ctx, "host-revoked", "", "", "")
	if err := st.Revoke(ctx, ag.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := st.Touch(ctx, ag.ID); err != nil {
		t.Fatalf("Touch on revoked agent: %v", err)
	}
	got, err := st.Get(ctx, ag.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.LastSeen.After(got.EnrolledAt.Add(time.Second)) {
		t.Fatalf("revoked agent's last_seen moved: %v", got.LastSeen)
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

// TestTaskLeaseReturnsWorkFromADeadAgent keeps a killed agent from wedging the
// queue: a claimed task that is never reported back becomes claimable again.
func TestTaskLeaseReturnsWorkFromADeadAgent(t *testing.T) {
	st, now := newStore(t)
	ctx := context.Background()
	agent, _, err := st.Enroll(ctx, "web01", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	task, _, err := st.QueueScan(ctx, agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := st.ClaimTask(ctx, agent.ID)
	if err != nil || claimed == nil {
		t.Fatalf("claim = %v %v", claimed, err)
	}

	// Inside the lease nothing changes: a slow scan is not punished.
	*now = now.Add(TaskLease / 2)
	if got, err := st.ClaimTask(ctx, agent.ID); err != nil || got != nil {
		t.Fatalf("claim inside the lease = %+v %v (want nil)", got, err)
	}
	if latest, _ := st.LatestTask(ctx, agent.ID); latest.Status != TaskRunning {
		t.Fatalf("task left the running state early: %+v", latest)
	}

	// Past the lease the work is requeued and can be claimed again.
	*now = now.Add(TaskLease + time.Minute)
	if got, err := st.ClaimTask(ctx, agent.ID); err != nil || got == nil {
		t.Fatalf("claim after lease expiry = %+v %v (want the requeued task)", got, err)
	} else if got.ID != task.ID {
		t.Fatalf("reclaimed a different task: %s", got.ID)
	}
	// Attempts are counted so a crash loop eventually stops retrying.
	stale, _ := st.LatestTask(ctx, agent.ID)
	if stale.Attempts < 2 {
		t.Fatalf("attempts = %d, want the retry to be counted", stale.Attempts)
	}
}

// TestTaskLeaseEventuallyGivesUp: after the retry budget the task fails with a
// reason instead of cycling forever.
func TestTaskLeaseEventuallyGivesUp(t *testing.T) {
	st, now := newStore(t)
	ctx := context.Background()
	agent, _, _ := st.Enroll(ctx, "web01", "", "", "")
	if _, _, err := st.QueueScan(ctx, agent.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxTaskAttempts+1; i++ {
		if _, err := st.ClaimTask(ctx, agent.ID); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(TaskLease + time.Minute)
	}
	// Trigger the reap explicitly (claim would do it, but nothing is claimable now).
	st.reapExpiredLeases(ctx)
	latest, err := st.LatestTask(ctx, agent.ID)
	if err != nil || latest == nil {
		t.Fatalf("latest = %v %v", latest, err)
	}
	if latest.Status != TaskFailed {
		t.Fatalf("status = %q, want failed after %d attempts", latest.Status, latest.Attempts)
	}
	if !strings.Contains(latest.Note, "lease expired") {
		t.Fatalf("note = %q", latest.Note)
	}
}

// TestMigratesADatabaseFromBeforeTheLeaseAndSequenceColumns is the upgrade path that
// matters in production: an existing fleet database must gain the new columns (and
// the indexes that depend on them) instead of failing to start.
func TestMigratesADatabaseFromBeforeTheLeaseAndSequenceColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intel.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// Old schema: no last_sequence, no attempts, no lease_expires_at.
	oldSchema := `
CREATE TABLE agents (
  id TEXT PRIMARY KEY, host TEXT NOT NULL, os TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '',
  token_hash TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'enrolled', phase TEXT NOT NULL DEFAULT '',
  percent INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL DEFAULT '', findings INTEGER NOT NULL DEFAULT 0,
  last_report_id TEXT NOT NULL DEFAULT '', enrolled_at TEXT NOT NULL, last_seen TEXT, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE agent_tasks (
  id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL,
  requested_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
  note TEXT NOT NULL DEFAULT '', report_id TEXT NOT NULL DEFAULT '');
CREATE TABLE agent_events (seq INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT NOT NULL, at TEXT NOT NULL,
  state TEXT NOT NULL, phase TEXT NOT NULL DEFAULT '', percent INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL DEFAULT '');
INSERT INTO agents (id, host, token_hash, enrolled_at) VALUES ('AGT-old','web01','x','2026-01-01T00:00:00Z');
`
	if _, err := db.Exec(oldSchema); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Opening through the store must migrate, not fail.
	st, err := OpenStoreForTest(path)
	if err != nil {
		t.Fatalf("open after upgrade: %v", err)
	}
	defer st.db.Close()
	if agents, err := st.List(context.Background()); err != nil || len(agents) != 1 {
		t.Fatalf("existing rows must survive the migration: %v %v", agents, err)
	}
	// And the new behaviour works on the migrated database.
	if _, err := st.db.Exec(`UPDATE agents SET last_sequence = 5`); err != nil {
		t.Fatalf("last_sequence column missing: %v", err)
	}
	if _, err := st.db.Exec(`UPDATE agent_tasks SET lease_expires_at = '2026-01-01T00:00:00Z', attempts = 1`); err != nil {
		t.Fatalf("task lease columns missing: %v", err)
	}
}

// TestFailedEnrollmentReleasesTheToken: a rejected attempt (identity conflict) must
// not cost a single-use token, or a mistyped hostname forces the operator to mint
// another one.
func TestFailedEnrollmentReleasesTheToken(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()

	token, _, err := st.MintEnrollToken(ctx, time.Hour, "retry")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ConsumeEnrollToken(ctx, token, "web01"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	// The enrollment that consumed it failed; hand it back.
	if err := st.ReleaseEnrollToken(ctx, token, "web01"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := st.ConsumeEnrollToken(ctx, token, "web01"); err != nil {
		t.Fatalf("retry after release: %v", err)
	}
	// Releasing someone else's consumption is refused.
	if err := st.ReleaseEnrollToken(ctx, token, "other-host"); !errors.Is(err, ErrEnrollTokenInvalid) {
		t.Fatalf("release for another host = %v, want ErrEnrollTokenInvalid", err)
	}
}
