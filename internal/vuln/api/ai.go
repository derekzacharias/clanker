package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/aihub"
	"github.com/bgdnvk/clanker/internal/vuln/automation"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/ticketing"
)

// AI and issue automation settings.
//
// Every handler in this file obeys one rule: a credential goes in, never out. Responses
// carry a mask and a source, and no code path here returns the plaintext key.

// aiStore lazily opens the AI settings store.
func (s *Server) aiStore() (*aihub.Store, error) {
	s.aiMu.Lock()
	defer s.aiMu.Unlock()
	if s.ai != nil {
		return s.ai, nil
	}
	dir := strings.TrimSpace(s.opts.AIDir)
	if dir == "" {
		dir = aihub.DefaultDir()
	}
	store, err := aihub.Open(dir)
	if err != nil {
		return nil, err
	}
	s.ai = store
	return store, nil
}

// automationStore lazily opens the issue-automation store.
func (s *Server) automationStore() (*automation.Store, error) {
	s.automationMu.Lock()
	defer s.automationMu.Unlock()
	if s.issueAuto != nil {
		return s.issueAuto, nil
	}
	dir := strings.TrimSpace(s.opts.AutomationDir)
	if dir == "" {
		dir = automation.DefaultDir()
	}
	store, err := automation.Open(dir)
	if err != nil {
		return nil, err
	}
	s.issueAuto = store
	return store, nil
}

// ------------------------------------------------------------------ AI settings ---

func (s *Server) handleAISettingsGet(w http.ResponseWriter, r *http.Request) {
	store, err := s.aiStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ai_store_error", err.Error())
		return
	}
	settings, err := store.LoadSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ai_settings_error", err.Error())
		return
	}
	// A credential can exist before a provider is selected (the user saved a key first),
	// so report the credential of the selected provider, or of the first configured one.
	credProvider := settings.Provider
	if credProvider == "" {
		for _, p := range aihub.Providers() {
			if info, ierr := store.CredentialInfo(p.ID); ierr == nil && info.Configured {
				credProvider = p.ID
				break
			}
		}
	}
	cred, err := store.CredentialInfo(credProvider)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ai_credential_error", err.Error())
		return
	}

	// The catalog is served from cache here: a page load must not call six providers.
	var catalog aihub.Catalog
	if settings.Provider != "" {
		if cached, ok, err := store.LoadCatalog(settings.Provider); err == nil && ok {
			catalog = cached
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"providers":  providerList(),
		"settings":   settings,
		"credential": cred,
		"catalog": map[string]any{
			"models":     aihub.Visible(catalog.Models, settings.AllowPreview),
			"stale":      catalog.Stale,
			"fetched_at": catalog.FetchedAt,
			"warning":    catalog.Error,
			"total":      len(catalog.Models),
		},
		"store_dir": store.Dir(),
	})
}

func (s *Server) handleAISettingsPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Provider     *string `json:"provider"`
		Model        *string `json:"model"`
		Endpoint     *string `json:"endpoint"`
		APIVersion   *string `json:"api_version"`
		AllowPreview *bool   `json:"allow_preview"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	store, err := s.aiStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ai_store_error", err.Error())
		return
	}
	settings, err := store.LoadSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ai_settings_error", err.Error())
		return
	}
	changed := false
	if body.Provider != nil {
		settings.Provider = *body.Provider
		changed = true
	}
	if body.Model != nil {
		settings.Model = *body.Model
		changed = true
	}
	if body.Endpoint != nil {
		settings.Endpoint = *body.Endpoint
		changed = true
	}
	if body.APIVersion != nil {
		settings.APIVersion = *body.APIVersion
		changed = true
	}
	if body.AllowPreview != nil {
		settings.AllowPreview = *body.AllowPreview
		changed = true
	}
	if changed {
		// A configuration change invalidates a previous "connected" badge.
		settings = settings.ClearTest()
	}
	saved, err := store.SaveSettings(settings)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_settings", err.Error())
		return
	}
	cred, _ := store.CredentialInfo(saved.Provider)
	writeJSON(w, http.StatusOK, map[string]any{"settings": saved, "credential": cred})
}

// handleAICredentialPut stores a credential. The key is accepted, encrypted and never
// echoed; the response is the same mask the list endpoint returns.
func (s *Server) handleAICredentialPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Provider string `json:"provider"`
		APIKey   string `json:"api_key"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	store, err := s.aiStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ai_store_error", err.Error())
		return
	}
	if err := store.SetCredential(body.Provider, body.APIKey); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_credential", err.Error())
		return
	}
	// Saving a key is a configuration change: the old test result no longer describes it.
	// Saving the first key also selects the provider, because "key saved but nothing
	// selected" is a state no operator means to be in.
	if settings, err := store.LoadSettings(); err == nil {
		if strings.TrimSpace(settings.Provider) == "" {
			settings.Provider = strings.ToLower(strings.TrimSpace(body.Provider))
		}
		_, _ = store.SaveSettings(settings.ClearTest())
	}
	info, err := store.CredentialInfo(body.Provider)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ai_credential_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credential": info})
}

func (s *Server) handleAICredentialDelete(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimSpace(r.URL.Query().Get("provider"))
	if provider == "" {
		writeError(w, http.StatusBadRequest, "missing_provider", "provider is required")
		return
	}
	store, err := s.aiStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ai_store_error", err.Error())
		return
	}
	if err := store.DeleteCredential(provider); err != nil {
		writeError(w, http.StatusInternalServerError, "ai_credential_error", err.Error())
		return
	}
	info, _ := store.CredentialInfo(provider)
	writeJSON(w, http.StatusOK, map[string]any{"credential": info})
}

func (s *Server) handleAITest(w http.ResponseWriter, r *http.Request) {
	store, err := s.aiStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ai_store_error", err.Error())
		return
	}
	settings, err := store.LoadSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ai_settings_error", err.Error())
		return
	}
	secret, ok, err := store.QuerySecret(settings.Provider)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ai_credential_error", err.Error())
		return
	}
	if !ok && settings.Provider != "ollama" {
		writeError(w, http.StatusBadRequest, "no_credential", "save an API key for this provider first")
		return
	}
	manager := aihub.NewManager(store)
	detail, perr := manager.Probe(r.Context(), settings, secret)
	connected := perr == nil
	settings.LastTestOK = &connected
	now := time.Now().UTC()
	settings.LastTestAt = &now
	if perr != nil {
		settings.LastTestDetail = perr.Error()
	} else {
		settings.LastTestDetail = detail
	}
	if _, err := store.SaveSettings(settings); err != nil {
		s.log.Warn("could not persist the AI connection test result", "err", err)
	}
	if perr != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"connected": false, "detail": perr.Error(), "settings": settings,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connected": true, "detail": detail, "settings": settings})
}

func (s *Server) handleAIModels(w http.ResponseWriter, r *http.Request) {
	store, err := s.aiStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ai_store_error", err.Error())
		return
	}
	settings, err := store.LoadSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ai_settings_error", err.Error())
		return
	}
	provider := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider")))
	if provider == "" {
		provider = settings.Provider
	}
	if provider == "" {
		writeError(w, http.StatusBadRequest, "no_provider", "choose a provider first")
		return
	}
	refresh := r.URL.Query().Get("refresh") == "1" || r.URL.Query().Get("refresh") == "true"

	manager := aihub.NewManager(store)
	result, err := manager.Models(r.Context(), provider, refresh)
	if err != nil {
		writeError(w, http.StatusBadGateway, "model_discovery_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"provider":   result.Provider,
		"models":     aihub.Visible(result.Models, settings.AllowPreview),
		"total":      len(result.Models),
		"stale":      result.Stale,
		"source":     result.Source,
		"warning":    result.Warning,
		"fetched_at": result.FetchedAt,
	})
}

// ------------------------------------------------------------------ automation ---

func (s *Server) handleAutomationGet(w http.ResponseWriter, r *http.Request) {
	store, err := s.automationStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "automation_store_error", err.Error())
		return
	}
	cfg, err := store.LoadConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "automation_config_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":         cfg,
		"modes":          automation.Modes,
		"store_dir":      store.Dir(),
		"gitlab_project": s.currentGitLabProject(),
	})
}

func (s *Server) handleAutomationPut(w http.ResponseWriter, r *http.Request) {
	var body automation.Config
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	store, err := s.automationStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "automation_store_error", err.Error())
		return
	}
	saved, err := store.SaveConfig(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_config", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": saved})
}

// handleAutomationPreview renders the issue a finding would produce, without creating it.
func (s *Server) handleAutomationPreview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FindingID string `json:"finding_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	if strings.TrimSpace(body.FindingID) == "" {
		writeError(w, http.StatusBadRequest, "missing_finding", "finding_id is required")
		return
	}
	rep, err := s.latestReport(r)
	if err != nil {
		writeError(w, http.StatusConflict, "no_report", err.Error())
		return
	}
	var target model.Finding
	found := false
	for i := range rep.Findings {
		if rep.Findings[i].FindingID == body.FindingID {
			target = rep.Findings[i]
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "finding_not_found", "no finding with that id in the latest assessment")
		return
	}

	aiStore, err := s.aiStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ai_store_error", err.Error())
		return
	}
	aiSettings, _ := aiStore.LoadSettings()
	secret, _, _ := aiStore.QuerySecret(aiSettings.Provider)
	autoStore, err := s.automationStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "automation_store_error", err.Error())
		return
	}
	cfg, _ := autoStore.LoadConfig()

	engine := automation.New(automation.Deps{
		AI:         &aihub.Inference{HTTP: s.httpClientForAI()},
		AISettings: aiSettings,
		Secret:     secret,
		Store:      autoStore,
		Logger:     s.log,
	})
	res, err := engine.Preview(r.Context(), automation.ToGeneratorFinding(rep, target), cfg)
	if err != nil {
		writeError(w, http.StatusBadGateway, "preview_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleAutomationRun executes the workflow over the latest assessment.
func (s *Server) handleAutomationRun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode automation.Mode `json:"mode"`
		// Confirm is required for auto mode: creating issues is an outbound side effect
		// and must be an explicit act, not a side effect of a stray POST.
		Confirm bool `json:"confirm"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body)

	autoStore, err := s.automationStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "automation_store_error", err.Error())
		return
	}
	cfg, err := autoStore.LoadConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "automation_config_error", err.Error())
		return
	}
	mode := body.Mode
	if mode == "" {
		mode = cfg.Mode
	}
	if mode == automation.ModeAuto && !body.Confirm {
		writeError(w, http.StatusBadRequest, "confirm_required",
			"automatic issue creation requires {\"confirm\": true}: it writes to GitLab")
		return
	}
	rep, err := s.latestReport(r)
	if err != nil {
		writeError(w, http.StatusConflict, "no_report", err.Error())
		return
	}

	deps := automation.Deps{Store: autoStore, Logger: s.log}
	aiStore, aiErr := s.aiStore()
	if aiErr == nil && cfg.UseAI {
		aiSettings, _ := aiStore.LoadSettings()
		secret, _, _ := aiStore.QuerySecret(aiSettings.Provider)
		deps.AI = &aihub.Inference{HTTP: s.httpClientForAI()}
		deps.AISettings = aiSettings
		deps.Secret = secret
	}
	if mode == automation.ModeAuto {
		creator, cerr := s.ticketCreator()
		if cerr != nil {
			writeError(w, http.StatusConflict, "gitlab_not_configured", cerr.Error())
			return
		}
		deps.Creator = creator
	}
	engine := automation.New(deps)
	results, err := engine.Run(r.Context(), rep, cfg, mode)
	if err != nil {
		writeError(w, http.StatusBadRequest, "automation_failed", err.Error())
		return
	}
	created := 0
	for _, res := range results {
		if res.Action == "created" {
			created++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":    mode,
		"results": results,
		"created": created,
		"total":   len(results),
	})
}

func (s *Server) handleAutomationAudit(w http.ResponseWriter, r *http.Request) {
	store, err := s.automationStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "automation_store_error", err.Error())
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	entries, err := store.Audit(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit_error", err.Error())
		return
	}
	if entries == nil {
		// An empty trail is an empty list, not null: the UI iterates it.
		entries = []automation.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "total": len(entries)})
}

// ------------------------------------------------------------------ helpers ---

// providerList is the catalog shape the UI needs, without any server-only fields.
func providerList() []map[string]any {
	providers := aihub.Providers()
	out := make([]map[string]any, 0, len(providers))
	for _, p := range providers {
		out = append(out, map[string]any{
			"id": p.ID, "label": p.Label, "auth": string(p.Auth),
			"implemented": p.Implemented, "needs_endpoint": p.NeedsEndpoint,
			"needs_api_version": p.NeedsAPIVersion, "needs_deployment": p.NeedsDeployment,
			"default_model": p.DefaultModel, "key_hint": p.KeyHint,
			"docs_url": p.DocsURL, "notes": p.Notes,
		})
	}
	return out
}

// ticketCreator builds the existing ticketing service, so duplicate prevention and the
// issue renderer are shared with the manual flow.
func (s *Server) ticketCreator() (*ticketing.Creator, error) {
	if s.tickets == nil {
		return nil, errors.New("the ticket store is not initialised")
	}
	settings, err := s.gitlabSettings()
	if err != nil {
		return nil, err
	}
	client, err := s.gitlabClient(settings)
	if err != nil {
		return nil, err
	}
	if settings.ProjectID <= 0 {
		return nil, errors.New("no GitLab project is configured for tickets")
	}
	return &ticketing.Creator{
		Store:             s.tickets,
		Client:            client,
		ProjectID:         settings.ProjectID,
		Labels:            settings.Labels,
		CreatedBy:         "automation",
		RemediationStatus: "detected",
		Log:               s.log,
	}, nil
}

// currentGitLabProject reports the destination project for display.
func (s *Server) currentGitLabProject() int {
	settings, err := s.gitlabSettings()
	if err != nil {
		return 0
	}
	return settings.ProjectID
}

// httpClientForAI keeps a sane timeout on outbound model calls. A hung provider must not
// hold an HTTP handler open.
func (s *Server) httpClientForAI() *http.Client {
	return &http.Client{Timeout: 90 * time.Second}
}

// latestReport returns the most recent stored assessment.
func (s *Server) latestReport(r *http.Request) (model.Report, error) {
	_, payload, err := s.store.LatestRun(r.Context(), r.URL.Query().Get("host"))
	if err != nil {
		return model.Report{}, errors.New("no assessment is stored yet; run a scan first")
	}
	var rep model.Report
	if err := json.Unmarshal(payload, &rep); err != nil {
		return model.Report{}, errors.New("the stored assessment cannot be decoded")
	}
	return rep, nil
}
