package aihub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeOpenAIShape(t *testing.T) {
	body := []byte(`{"object":"list","data":[
	  {"id":"gpt-4o-mini","object":"model"},
	  {"id":"text-embedding-3-large","object":"model"},
	  {"id":"dall-e-3","object":"model"},
	  {"id":"gpt-4o-2024-11-20","object":"model","context_length":128000}
	]}`)
	models, err := normalizeModels("openai", body)
	if err != nil {
		t.Fatal(err)
	}
	ids := idsOf(models)
	if contains(ids, "text-embedding-3-large") || contains(ids, "dall-e-3") {
		t.Fatalf("non-text models leaked into the catalog: %v", ids)
	}
	if !contains(ids, "gpt-4o-mini") || !contains(ids, "gpt-4o-2024-11-20") {
		t.Fatalf("expected text models missing: %v", ids)
	}
	for _, m := range models {
		if m.ID == "gpt-4o-2024-11-20" && m.ContextWindow != 128000 {
			t.Fatalf("context window not parsed: %+v", m)
		}
	}
}

func TestNormalizeAnthropicAndGoogleShapes(t *testing.T) {
	anthropic := []byte(`{"data":[{"id":"claude-3-5-sonnet-latest","display_name":"Claude 3.5 Sonnet"}]}`)
	models, err := normalizeModels("anthropic", anthropic)
	if err != nil || len(models) != 1 {
		t.Fatalf("anthropic: %v %v", models, err)
	}
	if models[0].Name != "Claude 3.5 Sonnet" {
		t.Fatalf("display name not used: %+v", models[0])
	}

	google := []byte(`{"models":[
	  {"name":"models/gemini-1.5-flash","displayName":"Gemini 1.5 Flash","inputTokenLimit":1048576,
	   "supportedGenerationMethods":["generateContent"]},
	  {"name":"models/text-embedding-004","supportedGenerationMethods":["embedContent"]}
	]}`)
	models, err = normalizeModels("google", google)
	if err != nil || len(models) != 1 {
		t.Fatalf("google: %v %v", models, err)
	}
	if models[0].ID != "gemini-1.5-flash" {
		t.Fatalf("the models/ prefix should be stripped, got %q", models[0].ID)
	}
	if models[0].ContextWindow != 1048576 {
		t.Fatalf("context window not parsed: %+v", models[0])
	}
}

func TestVisibleHidesRetiredAndPreviewModels(t *testing.T) {
	models := []Model{
		{ID: "gpt-4o", Status: StatusProduction},
		{ID: "gpt-4o-preview", Status: StatusPreview},
		{ID: "gpt-3.5-turbo-0301", Status: StatusRetired},
	}
	visible := Visible(models, false)
	if len(visible) != 1 || visible[0].ID != "gpt-4o" {
		t.Fatalf("preview/retired models must be hidden by default: %+v", visible)
	}
	withPreview := Visible(models, true)
	if len(withPreview) != 2 {
		t.Fatalf("preview models should appear when allowed: %+v", withPreview)
	}
	for _, m := range withPreview {
		if m.ID == "gpt-3.5-turbo-0301" {
			t.Fatal("retired models must never be offered")
		}
	}
}

func TestStatusClassification(t *testing.T) {
	cases := map[string]string{
		"gpt-4o":               StatusProduction,
		"gemini-2.0-flash-exp": StatusPreview,
		"gpt-3.5-turbo-0301":   StatusRetired,
		"claude-3-opus":        StatusProduction,
	}
	for id, want := range cases {
		if got := ClassifyStatus(id); got != want {
			t.Fatalf("ClassifyStatus(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestManagerCachesAndServesStaleOnFailure(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveSettings(Settings{Provider: "openai", Model: "gpt-4o-mini"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetCredential("openai", "sk-test"); err != nil {
		t.Fatal(err)
	}

	calls := 0
	failing := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer sk-test" {
			t.Errorf("credential not sent as a bearer token: %q", r.Header.Get("Authorization"))
		}
		if failing {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"id": "gpt-4o-mini"}, {"id": "gpt-4o"}},
		})
	}))
	defer srv.Close()

	// Point the provider at the test server.
	if _, err := store.SaveSettings(Settings{Provider: "openai", Model: "gpt-4o-mini", Endpoint: srv.URL}); err != nil {
		t.Fatal(err)
	}

	m := NewManager(store)
	first, err := m.Models(context.Background(), "openai", false)
	if err != nil {
		t.Fatalf("Models: %v", err)
	}
	if first.Source != "live" || len(first.Models) != 2 {
		t.Fatalf("unexpected discovery result: %+v", first)
	}

	// Second call is served from cache: no new request.
	m.Models(context.Background(), "openai", false)
	if calls != 1 {
		t.Fatalf("cache miss: %d provider calls", calls)
	}

	// A failed refresh keeps the list and labels it.
	failing = true
	stale, err := m.Models(context.Background(), "openai", true)
	if err != nil {
		t.Fatalf("a failed refresh must not be an error when a cache exists: %v", err)
	}
	if !stale.Stale || stale.Source != "cache" || stale.Warning == "" {
		t.Fatalf("stale result not marked: %+v", stale)
	}
	if len(stale.Models) != 2 {
		t.Fatal("stale refresh must keep the last known models")
	}
}

func TestManagerRejectsUnknownAndUnimplementedProviders(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(store)
	if _, err := m.Models(context.Background(), "nope", false); err == nil {
		t.Fatal("unknown provider must fail")
	}
	if _, err := m.Models(context.Background(), "bedrock", false); err == nil {
		t.Fatal("unimplemented provider must fail with a clear error")
	}
}

func TestProviderAuthPlacement(t *testing.T) {
	anthropic, _ := Lookup("anthropic")
	req := httptest.NewRequest(http.MethodGet, "https://example.test/v1/models", nil)
	applyAuth(req, anthropic, "sk-ant")
	if req.Header.Get("x-api-key") != "sk-ant" {
		t.Fatalf("anthropic key not placed in x-api-key: %v", req.Header)
	}
	if req.Header.Get("anthropic-version") == "" {
		t.Fatal("anthropic-version header missing")
	}

	google, _ := Lookup("google")
	req = httptest.NewRequest(http.MethodGet, "https://example.test/v1beta/models", nil)
	applyAuth(req, google, "AIza-key")
	if req.URL.Query().Get("key") != "AIza-key" {
		t.Fatalf("google key not placed in the query: %s", req.URL.RawQuery)
	}

	azure, _ := Lookup("azure-openai")
	req = httptest.NewRequest(http.MethodGet, "https://example.test", nil)
	applyAuth(req, azure, "azure-key")
	if req.Header.Get("api-key") != "azure-key" {
		t.Fatalf("azure key not placed in api-key: %v", req.Header)
	}
}

func idsOf(models []Model) []string {
	out := make([]string, 0, len(models))
	for _, m := range models {
		out = append(out, m.ID)
	}
	return out
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
