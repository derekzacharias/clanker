package autofix

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCompleteSendsTheExpectedRequest(t *testing.T) {
	var gotPath, gotAuth, gotModel string
	var gotMessages []chatMessage

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		var req chatRequest
		_ = json.Unmarshal(body, &req)
		gotModel = req.Model
		gotMessages = req.Messages
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"verdict\":\"mitigated\"}"}}]}`))
	}))
	defer srv.Close()

	c, err := NewOpenAICompatible(srv.URL+"/v1", "secret-key", "local-model")
	if err != nil {
		t.Fatalf("NewOpenAICompatible: %v", err)
	}
	out, err := c.Complete(context.Background(), "system text", "user text")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !strings.Contains(out, "mitigated") {
		t.Fatalf("unexpected answer %q", out)
	}
	if gotPath != "/v1/chat/completions" {
		t.Fatalf("unexpected path %q", gotPath)
	}
	if gotAuth != "Bearer secret-key" {
		t.Fatalf("token not sent: %q", gotAuth)
	}
	if gotModel != "local-model" {
		t.Fatalf("model not sent: %q", gotModel)
	}
	if len(gotMessages) != 2 || gotMessages[0].Role != "system" || gotMessages[1].Role != "user" {
		t.Fatalf("unexpected message shape: %+v", gotMessages)
	}
}

func TestCompleteAcceptsAFullEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/custom/chat/completions" {
			t.Errorf("path must not be doubled, got %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer srv.Close()

	c, _ := NewOpenAICompatible(srv.URL+"/custom/chat/completions", "", "m")
	if _, err := c.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}

func TestCompleteSurfacesErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"bad key"}}`))
	}))
	defer srv.Close()

	c, _ := NewOpenAICompatible(srv.URL+"/v1", "x", "m")
	_, err := c.Complete(context.Background(), "s", "u")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected an HTTP error, got %v", err)
	}
}

func TestNewOpenAICompatibleValidatesInput(t *testing.T) {
	if _, err := NewOpenAICompatible("", "", "m"); err == nil {
		t.Fatal("an empty endpoint must be refused")
	}
	if _, err := NewOpenAICompatible("ftp://example", "", "m"); err == nil {
		t.Fatal("a non-HTTP scheme must be refused")
	}
	if _, err := NewOpenAICompatible("http://example/v1", "", ""); err == nil {
		t.Fatal("a model name is required")
	}
}

func TestFuncAdapter(t *testing.T) {
	var l LLM = Func(func(context.Context, string, string) (string, error) { return "x", nil })
	if out, err := l.Complete(context.Background(), "", ""); err != nil || out != "x" {
		t.Fatalf("adapter: %q %v", out, err)
	}
}
