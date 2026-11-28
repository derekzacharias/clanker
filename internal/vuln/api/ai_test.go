package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/automation"
)

// newAIServer builds a server whose AI and automation state live in throwaway dirs.
func newAIServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "intel.db")
	seedCache(t, cachePath)
	srv, err := New(Options{
		DisableBackgroundJobs: true,
		CachePath:             cachePath,
		AIDir:                 filepath.Join(dir, "ai"),
		AutomationDir:         filepath.Join(dir, "automation"),
		ToolVersion:           "test-1.0",
		Now:                   func() time.Time { return time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

func TestAISettingsExposeProvidersWithoutSecrets(t *testing.T) {
	srv := newAIServer(t)
	var out struct {
		Providers  []map[string]any `json:"providers"`
		Settings   map[string]any   `json:"settings"`
		Credential map[string]any   `json:"credential"`
		Catalog    struct {
			Models []any `json:"models"`
		} `json:"catalog"`
	}
	rec := doJSON(t, srv.Handler(), http.MethodGet, "/api/settings/ai", nil, &out)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if len(out.Providers) < 10 {
		t.Fatalf("expected the provider catalog, got %d entries", len(out.Providers))
	}
	if out.Credential["configured"] != false {
		t.Fatalf("a fresh install must report no credential: %+v", out.Credential)
	}
	if strings.Contains(rec.Body.String(), `"api_key"`) || strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("the response must not advertise secret fields: %s", rec.Body.String())
	}
}

func TestCredentialIsStoredAndNeverReturned(t *testing.T) {
	srv := newAIServer(t)
	secret := "sk-live-abcdefghijklmnop"

	rec := doJSON(t, srv.Handler(), http.MethodPut, "/api/settings/ai/credential",
		map[string]string{"provider": "openai", "api_key": secret}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("store credential: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("the write response echoed the secret")
	}

	rec = doJSON(t, srv.Handler(), http.MethodGet, "/api/settings/ai", nil, nil)
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("the read response leaked the secret")
	}
	var out struct {
		Credential struct {
			Configured bool   `json:"configured"`
			Mask       string `json:"mask"`
			Source     string `json:"source"`
		} `json:"credential"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Credential.Configured || out.Credential.Source != "file" {
		t.Fatalf("credential not reported: %+v", out.Credential)
	}
	if !strings.HasPrefix(out.Credential.Mask, "••••") {
		t.Fatalf("mask should hide the key, got %q", out.Credential.Mask)
	}
}

func TestAISettingsRejectUnknownProvider(t *testing.T) {
	srv := newAIServer(t)
	rec := doJSON(t, srv.Handler(), http.MethodPut, "/api/settings/ai",
		map[string]string{"provider": "not-a-provider"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestModelsEndpointRequiresAProvider(t *testing.T) {
	srv := newAIServer(t)
	rec := doJSON(t, srv.Handler(), http.MethodGet, "/api/settings/ai/models", nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with no provider configured, got %d", rec.Code)
	}
}

func TestAutomationConfigRoundTripAndValidation(t *testing.T) {
	srv := newAIServer(t)

	var initial struct {
		Config automation.Config `json:"config"`
	}
	rec := doJSON(t, srv.Handler(), http.MethodGet, "/api/settings/automation", nil, &initial)
	if rec.Code != http.StatusOK {
		t.Fatalf("get automation: %d", rec.Code)
	}
	if initial.Config.Mode != automation.ModeManual {
		t.Fatalf("automation must default to manual, got %q", initial.Config.Mode)
	}

	cfg := initial.Config
	cfg.Mode = automation.ModeAssisted
	cfg.MinSeverity = "high"
	cfg.MaxPerRun = 5
	rec = doJSON(t, srv.Handler(), http.MethodPut, "/api/settings/automation", cfg, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put automation: %d %s", rec.Code, rec.Body.String())
	}

	var saved struct {
		Config automation.Config `json:"config"`
	}
	doJSON(t, srv.Handler(), http.MethodGet, "/api/settings/automation", nil, &saved)
	if saved.Config.Mode != automation.ModeAssisted || saved.Config.MaxPerRun != 5 {
		t.Fatalf("configuration did not persist: %+v", saved.Config)
	}

	bad := saved.Config
	bad.Mode = "yolo"
	rec = doJSON(t, srv.Handler(), http.MethodPut, "/api/settings/automation", bad, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown mode must be refused, got %d", rec.Code)
	}
}

func TestAutomationRunRequiresExplicitConfirmationForAuto(t *testing.T) {
	srv := newAIServer(t)
	rec := doJSON(t, srv.Handler(), http.MethodPost, "/api/settings/automation/run",
		map[string]any{"mode": "auto"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("auto mode without confirm must be refused, got %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "confirm") {
		t.Fatalf("the error must say what is missing: %s", body)
	}
}

func TestAutomationAuditStartsEmpty(t *testing.T) {
	srv := newAIServer(t)
	var out struct {
		Entries []any `json:"entries"`
	}
	rec := doJSON(t, srv.Handler(), http.MethodGet, "/api/settings/automation/audit", nil, &out)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit: %d", rec.Code)
	}
	if len(out.Entries) != 0 {
		t.Fatalf("a fresh install has no audit history, got %d entries", len(out.Entries))
	}
}

func TestCredentialDeleteChoosesWhatItDeletes(t *testing.T) {
	srv := newAIServer(t)
	doJSON(t, srv.Handler(), http.MethodPut, "/api/settings/ai/credential",
		map[string]string{"provider": "openai", "api_key": "sk-abcdefghijkl"}, nil)

	rec := doJSON(t, srv.Handler(), http.MethodDelete, "/api/settings/ai/credential?provider=openai", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Credential struct {
			Configured bool `json:"configured"`
		} `json:"credential"`
	}
	doJSON(t, srv.Handler(), http.MethodGet, "/api/settings/ai", nil, &out)
	if out.Credential.Configured {
		t.Fatal("the credential survived deletion")
	}
}

// httptest is used indirectly through doJSON; keep the import meaningful for future
// handler-level tests that need a recorder directly.
var _ = httptest.NewRecorder
