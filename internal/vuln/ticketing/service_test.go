package ticketing

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func newCreator(t *testing.T, f *fakeGitLab) (*Creator, *Store) {
	t.Helper()
	client, _ := newServerWithFake(t, f)
	store, _ := newTicketStore(t)
	return &Creator{
		Store: store, Client: client, ProjectID: 42, ProjectPath: "platform/security",
		Labels: []string{"team-infra"}, CreatedBy: "admin",
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, store
}

func inputFor(f Finding) IssueInput {
	return IssueInput{Title: Title(f), Description: RenderDescription(f),
		Labels: LabelString(Labels([]string{"team-infra"}, f))}
}

func TestCreateStoresTheIssueReferenceAndSendsTheRenderedBody(t *testing.T) {
	f := newFake()
	creator, store := newCreator(t, f)
	finding := testFinding()

	res, err := creator.Create(context.Background(), finding, inputFor(finding))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !res.Created || res.Reused {
		t.Fatalf("result = %+v", res)
	}
	if res.Ticket.IssueIID != 42 || res.Ticket.IssueURL == "" {
		t.Fatalf("ticket did not record the issue reference: %+v", res.Ticket)
	}
	if res.Ticket.State != "opened" || res.Ticket.CreatedBy != "admin" || res.Ticket.ProjectID != 42 {
		t.Fatalf("ticket = %+v", res.Ticket)
	}
	if res.Ticket.LastSyncedAt == nil {
		t.Fatal("ticket has no last_synced_at")
	}

	// What GitLab received: the rendered markdown and the severity labels.
	sent := f.last()
	if sent.Method != http.MethodPost || !strings.Contains(sent.Path, "/projects/42/issues") {
		t.Fatalf("unexpected request: %+v", sent)
	}
	desc := str(sent.Body["description"])
	for _, want := range []string{"CVE-2026-1234", "web01.prod", "openssl", "## Verification", "## Source"} {
		if !strings.Contains(desc, want) {
			t.Fatalf("description sent to GitLab is missing %q", want)
		}
	}
	if labels := str(sent.Body["labels"]); !strings.Contains(labels, "critical") {
		t.Fatalf("labels sent = %q, want the effective severity", labels)
	}

	// The relationship is readable by finding key, which is what the finding detail uses.
	tickets, err := store.ForFinding(context.Background(), finding.FindingKey)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("ForFinding = %v, %v", tickets, err)
	}
}

func TestASecondCreateForTheSameFindingDoesNotTouchGitLab(t *testing.T) {
	f := newFake()
	creator, _ := newCreator(t, f)
	finding := testFinding()

	first, err := creator.Create(context.Background(), finding, inputFor(finding))
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	second, err := creator.Create(context.Background(), finding, inputFor(finding))
	if err != nil {
		t.Fatalf("second Create: %v", err)
	}
	if !second.Reused || second.Created {
		t.Fatalf("second result = %+v, want reused", second)
	}
	if second.Ticket.ID != first.Ticket.ID {
		t.Fatalf("second call returned a different ticket: %s vs %s", second.Ticket.ID, first.Ticket.ID)
	}
	if n := f.count(http.MethodPost, "/issues"); n != 1 {
		t.Fatalf("GitLab received %d creation requests, want 1", n)
	}
}

// Concurrent submissions are the realistic duplicate path: two operators, one finding.
func TestConcurrentCreatesProduceOneIssue(t *testing.T) {
	f := newFake()
	f.createDelay = 20 * time.Millisecond
	creator, store := newCreator(t, f)
	finding := testFinding()

	var wg sync.WaitGroup
	results := make([]CreateResult, 8)
	errs := make([]error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = creator.Create(context.Background(), finding, inputFor(finding))
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("create %d failed: %v", i, err)
		}
	}
	if n := f.count(http.MethodPost, "/issues"); n != 1 {
		t.Fatalf("GitLab received %d creation requests, want exactly 1", n)
	}
	tickets, err := store.ForFinding(context.Background(), finding.FindingKey)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("stored tickets = %d, %v", len(tickets), err)
	}
}

// A timeout must not become a duplicate on retry: the retry searches for the marker first.
func TestTimeoutThenRetryRecoversTheIssueInsteadOfDuplicating(t *testing.T) {
	f := newFake()
	creator, store := newCreator(t, f)
	finding := testFinding()

	// First attempt: GitLab accepts the issue but the answer never arrives.
	f.createStatus = http.StatusGatewayTimeout
	f.createBody = `{"message":"upstream timeout"}`
	if _, err := creator.Create(context.Background(), finding, inputFor(finding)); err == nil {
		t.Fatal("expected the ambiguous attempt to fail")
	}
	pending, err := store.ForFinding(context.Background(), finding.FindingKey)
	if err != nil || len(pending) != 1 {
		t.Fatalf("expected a pending reservation, got %v %v", pending, err)
	}
	if !pending[0].Pending || pending[0].Note == "" {
		t.Fatalf("reservation should be pending with an explanation: %+v", pending[0])
	}

	// The retry finds the issue that attempt created and adopts it.
	f.createStatus = 0
	f.createBody = ""
	f.searchResults = []map[string]any{{
		"id": 1001, "iid": 7, "state": "opened",
		"web_url":     "http://gitlab.test.intra:8929/platform/security/-/issues/7",
		"description": "body\n\n" + Marker(finding.FindingKey) + "\n",
	}}
	res, err := creator.Create(context.Background(), finding, inputFor(finding))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !res.Reused || res.Ticket.IssueIID != 7 {
		t.Fatalf("retry = %+v, want the recovered issue #7", res)
	}
	if n := f.count(http.MethodPost, "/issues"); n != 1 {
		t.Fatalf("the retry created a second issue (%d creation requests)", n)
	}
}

// A rejection is a definite answer: nothing was created, so the reservation is released
// and a corrected retry is allowed.
func TestPermissionRejectionReleasesTheReservation(t *testing.T) {
	f := newFake()
	creator, store := newCreator(t, f)
	finding := testFinding()

	f.createStatus = http.StatusForbidden
	f.createBody = `{"message":"403 Forbidden"}`
	_, err := creator.Create(context.Background(), finding, inputFor(finding))
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	tickets, _ := store.ForFinding(context.Background(), finding.FindingKey)
	if len(tickets) != 0 {
		t.Fatalf("a refused creation left a reservation behind: %+v", tickets)
	}

	// Fixed permissions: the same finding can be ticketed now.
	f.createStatus = 0
	f.createBody = ""
	res, err := creator.Create(context.Background(), finding, inputFor(finding))
	if err != nil || !res.Created {
		t.Fatalf("retry after fix = %+v, %v", res, err)
	}
}

func TestUnreachableGitLabCreatesNothingAndExplainsWhy(t *testing.T) {
	creator, store := newCreator(t, newFake())
	creator.Client, _ = NewClient(Config{BaseURL: "http://127.0.0.1:1", Token: "t", Timeout: time.Second,
		AllowInsecureHTTP: true}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	finding := testFinding()
	if _, err := creator.Create(context.Background(), finding, inputFor(finding)); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
	pending, _ := store.ForFinding(context.Background(), finding.FindingKey)
	if len(pending) != 1 || !pending[0].Pending {
		t.Fatalf("an unreachable GitLab must leave exactly one ambiguous reservation, got %+v", pending)
	}
}

// Refresh reads GitLab's current state; a closed issue does not touch the finding.
func TestRefreshRecordsGitLabState(t *testing.T) {
	f := newFake()
	creator, _ := newCreator(t, f)
	finding := testFinding()
	res, err := creator.Create(context.Background(), finding, inputFor(finding))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// The fake answers a single-issue read with state=closed.
	refreshed, err := creator.RefreshTicket(context.Background(), res.Ticket.ID)
	if err != nil {
		t.Fatalf("RefreshTicket: %v", err)
	}
	if refreshed.State != "closed" {
		t.Fatalf("state = %q, want closed", refreshed.State)
	}
	if refreshed.LastSyncedAt == nil || refreshed.LastSyncedAt.Before(res.Ticket.CreatedAt) {
		t.Fatalf("last_synced_at was not advanced: %+v", refreshed)
	}
}

func TestAssigneeIsResolvedAndSentAsAnID(t *testing.T) {
	f := newFake()
	creator, _ := newCreator(t, f)
	creator.AssigneeID, creator.AssigneeName = 7, "guard-bot"
	finding := testFinding()
	if _, err := creator.Create(context.Background(), finding, inputFor(finding)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ids, ok := f.last().Body["assignee_ids"].([]any)
	if !ok || len(ids) != 1 {
		t.Fatalf("assignee_ids = %#v", f.last().Body["assignee_ids"])
	}
	if int(ids[0].(float64)) != 7 {
		t.Fatalf("assignee id = %v", ids[0])
	}
}
