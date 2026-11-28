package ticketing

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestClient points a real Client at a test server.
//
// AllowInsecureHTTP is set because httptest serves plain HTTP on loopback, and the
// plain-HTTP guard (deliberately) does not count loopback as a private network. The
// guard itself is exercised by its own tests; weakening it here would hide a regression.
func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewClient(Config{
		BaseURL:           srv.URL,
		Token:             "test-token",
		ProjectID:         1,
		AllowInsecureHTTP: true,
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, srv
}

func TestCreateMergeRequestExpressesDraftAsATitlePrefix(t *testing.T) {
	var got map[string]any
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v4/projects/1/merge_requests" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"iid":3,"web_url":"https://gitlab.test/mr/3","state":"opened"}`))
	})

	mr, err := c.CreateMergeRequest(context.Background(), 1, MergeRequestInput{
		SourceBranch: "secfix/x", TargetBranch: "main", Title: "bump dep", Draft: true,
	})
	if err != nil {
		t.Fatalf("CreateMergeRequest: %v", err)
	}
	if mr.IID != 3 {
		t.Fatalf("unexpected MR %+v", mr)
	}
	if title, _ := got["title"].(string); title != "Draft: bump dep" {
		t.Fatalf("draft must be a title prefix, got %q", title)
	}
}

func TestCreateMergeRequestDoesNotDoubleTheDraftPrefix(t *testing.T) {
	var got map[string]any
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"iid":1}`))
	})
	if _, err := c.CreateMergeRequest(context.Background(), 1, MergeRequestInput{
		SourceBranch: "a", TargetBranch: "main", Title: "Draft: already", Draft: true,
	}); err != nil {
		t.Fatalf("CreateMergeRequest: %v", err)
	}
	if title, _ := got["title"].(string); strings.Count(strings.ToLower(title), "draft:") != 1 {
		t.Fatalf("prefix must appear once, got %q", title)
	}
}

func TestCreateMergeRequestRequiresBranches(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {})
	if _, err := c.CreateMergeRequest(context.Background(), 1, MergeRequestInput{Title: "x"}); err == nil {
		t.Fatal("a merge request without branches must be refused locally")
	}
}

func TestCommitFilesRejectsUnknownActionsWithoutCallingGitLab(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("no request should be made for an invalid commit")
	})
	_, err := c.CommitFiles(context.Background(), 1, "b", "msg", []FileAction{{Action: "append", FilePath: "requirements.txt"}})
	if err == nil {
		t.Fatal("an unsupported action must be refused")
	}
	if _, err := c.CommitFiles(context.Background(), 1, "b", "msg", nil); err == nil {
		t.Fatal("an empty commit must be refused")
	}
}

func TestCommitFilesSendsOneRequest(t *testing.T) {
	var got struct {
		Branch  string       `json:"branch"`
		Message string       `json:"commit_message"`
		Actions []FileAction `json:"actions"`
	}
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"id":"abc123"}`))
	})
	sha, err := c.CommitFiles(context.Background(), 1, "secfix/x", "msg", []FileAction{
		{Action: "update", FilePath: "requirements.txt", Content: "a==1"},
	})
	if err != nil {
		t.Fatalf("CommitFiles: %v", err)
	}
	if sha != "abc123" {
		t.Fatalf("unexpected commit id %q", sha)
	}
	if got.Branch != "secfix/x" || len(got.Actions) != 1 || got.Actions[0].FilePath != "requirements.txt" {
		t.Fatalf("unexpected commit payload %+v", got)
	}
}

func TestFileContentDecodesBase64(t *testing.T) {
	want := "paramiko==3.4.0\n"
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/repository/files/requirements.txt") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		payload := map[string]string{
			"content":  base64.StdEncoding.EncodeToString([]byte(want)),
			"encoding": "base64",
		}
		_ = json.NewEncoder(w).Encode(payload)
	})
	got, err := c.FileContent(context.Background(), 1, "requirements.txt", "main")
	if err != nil {
		t.Fatalf("FileContent: %v", err)
	}
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCreateNotePostsTheBody(t *testing.T) {
	var body map[string]string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/projects/1/issues/7/notes" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		_, _ = w.Write([]byte(`{"id":42}`))
	})
	n, err := c.CreateNote(context.Background(), 1, 7, "verdict: mitigated")
	if err != nil {
		t.Fatalf("CreateNote: %v", err)
	}
	if n.ID != 42 || body["body"] != "verdict: mitigated" {
		t.Fatalf("unexpected note %+v / %+v", n, body)
	}
}
