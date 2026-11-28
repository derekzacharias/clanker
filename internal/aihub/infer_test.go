package aihub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestInference(srv *httptest.Server, retries int) *Inference {
	return &Inference{HTTP: srv.Client(), MaxRetries: retries, Backoff: time.Millisecond}
}

func TestInferenceOpenAIShape(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		raw, _ := json.Marshal(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"content": "hello"}}},
			"usage":   map[string]any{"prompt_tokens": 11, "completion_tokens": 7},
		})
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	cfg := Settings{Provider: "openai", Model: "gpt-4o-mini", Endpoint: srv.URL}
	res, err := newTestInference(srv, 0).Complete(context.Background(), cfg, "sk-test",
		Request{System: "sys", User: "usr", JSON: true})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.Text != "hello" || res.Usage.InputTokens != 11 || res.Usage.OutputTokens != 7 {
		t.Fatalf("unexpected response: %+v", res)
	}
	if gotBody["model"] != "gpt-4o-mini" {
		t.Fatalf("model not sent: %+v", gotBody)
	}
	if _, ok := gotBody["response_format"]; !ok {
		t.Fatal("JSON mode must request a JSON response format")
	}
}

func TestInferenceAnthropicShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "sk-ant" {
			t.Errorf("missing x-api-key header")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]any{{"type": "text", "text": "claude says hi"}},
			"usage":   map[string]any{"input_tokens": 5, "output_tokens": 3},
		})
	}))
	defer srv.Close()

	cfg := Settings{Provider: "anthropic", Model: "claude-3-5-sonnet-latest"}
	p, _ := Lookup("anthropic")
	cfg.Endpoint = srv.URL
	// The provider path is /messages; the test server accepts anything.
	res, err := newTestInference(srv, 0).Complete(context.Background(), cfg, "sk-ant", Request{User: "hi"})
	if err != nil {
		t.Fatalf("Complete: %v (provider %s)", err, p.Label)
	}
	if !strings.Contains(res.Text, "claude") {
		t.Fatalf("unexpected text %q", res.Text)
	}
	if res.Usage.InputTokens != 5 {
		t.Fatalf("usage not parsed: %+v", res.Usage)
	}
}

func TestInferenceGoogleShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "AIza" {
			t.Errorf("google key must be a query parameter, got %q", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"candidates": []map[string]any{{
				"content": map[string]any{"parts": []map[string]any{{"text": "gemini says hi"}}},
			}},
			"usageMetadata": map[string]any{"promptTokenCount": 4, "candidatesTokenCount": 2},
		})
	}))
	defer srv.Close()

	cfg := Settings{Provider: "google", Model: "gemini-1.5-flash", Endpoint: srv.URL}
	res, err := newTestInference(srv, 0).Complete(context.Background(), cfg, "AIza", Request{User: "hi"})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !strings.Contains(res.Text, "gemini") || res.Usage.InputTokens != 4 {
		t.Fatalf("unexpected response: %+v", res)
	}
}

func TestInferenceRetriesRateLimitThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"content": "second try"}}},
		})
	}))
	defer srv.Close()

	cfg := Settings{Provider: "openai", Model: "gpt-4o-mini", Endpoint: srv.URL}
	res, err := newTestInference(srv, 2).Complete(context.Background(), cfg, "k", Request{User: "hi"})
	if err != nil {
		t.Fatalf("Complete after retry: %v", err)
	}
	if res.Attempts != 2 || !strings.Contains(res.Text, "second") {
		t.Fatalf("retry not reflected: %+v", res)
	}
}

func TestInferenceDoesNotRetryAuthFailures(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := Settings{Provider: "openai", Model: "gpt-4o-mini", Endpoint: srv.URL}
	_, err := newTestInference(srv, 3).Complete(context.Background(), cfg, "bad", Request{User: "hi"})
	if err == nil {
		t.Fatal("a 401 must be an error")
	}
	if calls.Load() != 1 {
		t.Fatalf("a 401 must not be retried, got %d calls", calls.Load())
	}
	if !strings.Contains(err.Error(), "rejected the credential") {
		t.Fatalf("error should explain the credential was rejected: %v", err)
	}
}

func TestInferenceRequiresCredentialAndModel(t *testing.T) {
	inf := &Inference{}
	if _, err := inf.Complete(context.Background(), Settings{Provider: "openai", Model: "gpt-4o"}, "", Request{User: "x"}); err == nil {
		t.Fatal("a provider with no credential must fail before any request")
	}
	if _, err := inf.Complete(context.Background(), Settings{Provider: "openai"}, "key", Request{User: "x"}); err == nil {
		t.Fatal("a missing model must fail")
	}
	if _, err := inf.Complete(context.Background(), Settings{Provider: "bedrock", Model: "x"}, "key", Request{User: "x"}); err == nil {
		t.Fatal("an unimplemented provider must fail with a clear error")
	}
}
