package aihub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Manager is the AIProviderManager + ModelDiscoveryService: it owns the catalog, the
// cache policy and the connection probe.
type Manager struct {
	store *Store
	http  *http.Client
	now   func() time.Time
}

// NewManager builds a manager over a store.
func NewManager(store *Store) *Manager {
	return &Manager{
		store: store,
		http:  &http.Client{Timeout: 20 * time.Second},
		now:   func() time.Time { return time.Now().UTC() },
	}
}

// DiscoveryResult is what the API returns for a model list request.
type DiscoveryResult struct {
	Provider  string    `json:"provider"`
	Models    []Model   `json:"models"`
	FetchedAt time.Time `json:"fetched_at,omitempty"`
	// Stale is true when these models did not come from a fresh successful call.
	Stale bool `json:"stale"`
	// Source is "live" or "cache" so the UI can label the data honestly.
	Source string `json:"source"`
	// Warning explains a stale list or a partial lookup.
	Warning string `json:"warning,omitempty"`
}

// Models returns the catalog for a provider.
//
// Cache policy: a list younger than CatalogTTL is served without a network call unless
// refresh is set. A failed refresh never deletes the last good list: it is returned with
// Stale=true and the reason, because an empty dropdown is less useful than a labelled
// stale one.
func (m *Manager) Models(ctx context.Context, providerID string, refresh bool) (DiscoveryResult, error) {
	p, ok := Lookup(providerID)
	if !ok {
		return DiscoveryResult{}, fmt.Errorf("unknown provider %q", providerID)
	}
	if !p.Ready() {
		return DiscoveryResult{}, fmt.Errorf("%s is not supported by this build", p.Label)
	}

	cached, haveCache, err := m.store.LoadCatalog(p.ID)
	if err != nil {
		return DiscoveryResult{}, err
	}
	if haveCache && !refresh && !cached.Stale {
		return DiscoveryResult{
			Provider: p.ID, Models: cached.Models, FetchedAt: cached.FetchedAt,
			Source: "cache", Stale: false,
		}, nil
	}

	settings, err := m.store.LoadSettings()
	if err != nil {
		return DiscoveryResult{}, err
	}
	secret, hasSecret, err := m.store.Credential(p.ID)
	if err != nil {
		return DiscoveryResult{}, err
	}
	if hasSecret == false {
		secret = envCredential(p.ID)
	}
	if p.Auth != AuthNone && strings.TrimSpace(secret) == "" {
		if haveCache {
			stale, _ := m.store.MarkCatalogError(p.ID, "no credential is configured")
			return DiscoveryResult{Provider: p.ID, Models: stale.Models, FetchedAt: stale.FetchedAt,
				Stale: true, Source: "cache", Warning: "No credential is configured; showing the last known list."}, nil
		}
		return DiscoveryResult{}, fmt.Errorf("no credential is configured for %s", p.Label)
	}

	models, derr := m.discover(ctx, p, secret, settings)
	if derr != nil {
		if haveCache {
			stale, _ := m.store.MarkCatalogError(p.ID, derr.Error())
			return DiscoveryResult{Provider: p.ID, Models: stale.Models, FetchedAt: stale.FetchedAt,
				Stale: true, Source: "cache",
				Warning: "Model discovery failed (" + derr.Error() + "); showing the last known list."}, nil
		}
		return DiscoveryResult{}, derr
	}
	cat, err := m.store.SaveCatalog(p.ID, models)
	if err != nil {
		return DiscoveryResult{}, err
	}
	return DiscoveryResult{Provider: p.ID, Models: models, FetchedAt: cat.FetchedAt,
		Source: "live", Stale: false}, nil
}

// Visible applies the operator's preview preference and hides retired models. The API
// layer calls it so the dropdown only ever receives models it is allowed to show.
func Visible(models []Model, allowPreview bool) []Model {
	out := make([]Model, 0, len(models))
	for _, m := range models {
		if m.Status == StatusRetired {
			continue
		}
		if m.Status == StatusPreview && !allowPreview {
			continue
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Status != out[j].Status {
			return out[i].Status == StatusProduction
		}
		return strings.ToLower(out[i].ID) < strings.ToLower(out[j].ID)
	})
	return out
}

// Find returns one model from a catalog.
func Find(models []Model, id string) (Model, bool) {
	id = strings.TrimSpace(id)
	for _, m := range models {
		if strings.EqualFold(m.ID, id) {
			return m, true
		}
	}
	return Model{}, false
}

// discover performs the provider call and normalizes the answer.
func (m *Manager) discover(ctx context.Context, p Provider, secret string, s Settings) ([]Model, error) {
	base := strings.TrimSpace(s.Endpoint)
	if base == "" {
		base = p.BaseURL
	}

	// Azure has no /models endpoint; the deployments API needs a different credential
	// (a management token), so the configured deployment is the catalog here.
	if p.NeedsDeployment {
		if strings.TrimSpace(s.Model) == "" {
			return nil, errors.New("set the deployment name first: Azure lists deployments per resource, not models")
		}
		return []Model{{
			ID: s.Model, Name: s.Model, Provider: p.ID, Status: StatusProduction,
			Details: "deployment", SupportsJSON: true,
		}}, nil
	}

	modelsURL := p.ModelsURL(base)
	if modelsURL == "" {
		return nil, fmt.Errorf("%s has no model-listing API; set the model name manually", p.Label)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, modelsURL, nil)
	if err != nil {
		return nil, err
	}
	applyAuth(req, p, secret)

	res, err := m.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s: %w", p.Label, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", p.Label, err)
	}
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%s rejected the credential (HTTP %d)", p.Label, res.StatusCode)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("%s returned HTTP %d while listing models", p.Label, res.StatusCode)
	}
	models, err := normalizeModels(p.ID, body)
	if err != nil {
		return nil, err
	}
	if len(models) == 0 {
		return nil, fmt.Errorf("%s returned no usable text models for this account", p.Label)
	}
	return models, nil
}

// applyAuth places the credential the way the provider expects. One function, so a new
// provider cannot invent a fourth way of attaching a key.
func applyAuth(req *http.Request, p Provider, secret string) {
	req.Header.Set("Accept", "application/json")
	for k, v := range p.ExtraHeaders {
		req.Header.Set(k, v)
	}
	switch p.Auth {
	case AuthBearer:
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
	case AuthHeader:
		name := p.HeaderName
		if name == "" {
			name = "x-api-key"
		}
		req.Header.Set(name, secret)
	case AuthQuery:
		q := req.URL.Query()
		q.Set("key", secret)
		req.URL.RawQuery = q.Encode()
	case AuthAzure:
		req.Header.Set("api-key", secret)
	case AuthNone:
		// local runtime, nothing to send
	}
}

// normalizeModels maps every provider's listing shape onto Model.
//
// It is intentionally tolerant: OpenAI-compatible servers disagree about whether the list
// is `data` or `models`, and about whether the id is `id` or `name`. Being strict here
// would mean a new adapter for every compatible server.
func normalizeModels(provider string, body []byte) ([]Model, error) {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("model list is not JSON: %w", err)
	}
	rows := extractList(root)
	out := make([]Model, 0, len(rows))
	seen := map[string]bool{}

	for _, row := range rows {
		id := firstString(row, "id", "name", "model", "model_id")
		id = strings.TrimPrefix(id, "models/")
		if id == "" || seen[strings.ToLower(id)] {
			continue
		}
		// Google and Cohere advertise capabilities per model; a model that cannot do
		// text generation is not a candidate for security analysis.
		if provider == "google" && !hasString(row, "supportedGenerationMethods", "generateContent") {
			continue
		}
		if provider == "cohere" && !hasString(row, "endpoints", "chat") {
			continue
		}
		if !IsTextAnalysisModel(id) {
			continue
		}
		seen[strings.ToLower(id)] = true

		m := Model{
			ID:       id,
			Name:     firstString(row, "display_name", "displayName", "name", "id"),
			Provider: provider,
			Status:   ClassifyStatus(id),
		}
		if m.Name == "" {
			m.Name = id
		}
		if m.Name == "models/"+id {
			m.Name = id
		}
		m.ContextWindow = firstInt(row, "context_length", "context_window", "inputTokenLimit", "context_size", "max_context_length")
		m.SupportsTools = supportsCapability(provider, id, row, "tools", "tool_use", "function_calling")
		m.SupportsJSON = supportsCapability(provider, id, row, "json", "structured", "response_format")
		m.PricingHint = pricingHint(provider, id, row)
		out = append(out, m)
	}
	return out, nil
}

// extractList finds the array of model objects regardless of the envelope key.
func extractList(root map[string]any) []map[string]any {
	for _, key := range []string{"data", "models", "value", "items"} {
		raw, ok := root[key]
		if !ok {
			continue
		}
		arr, ok := raw.([]any)
		if !ok {
			continue
		}
		out := make([]map[string]any, 0, len(arr))
		for _, item := range arr {
			if obj, ok := item.(map[string]any); ok {
				out = append(out, obj)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

func firstString(row map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := row[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstInt(row map[string]any, keys ...string) int {
	for _, k := range keys {
		switch v := row[k].(type) {
		case float64:
			if v > 0 {
				return int(v)
			}
		case json.Number:
			if n, err := v.Int64(); err == nil && n > 0 {
				return int(n)
			}
		}
	}
	return 0
}

func hasString(row map[string]any, key, want string) bool {
	raw, ok := row[key]
	if !ok {
		return false
	}
	arr, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, item := range arr {
		if s, ok := item.(string); ok && strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// supportsCapability reads a capability flag if the provider states one, and otherwise
// infers it from families known to support tool use and JSON output. It never claims a
// capability the provider did not advertise or the model family is not known for.
func supportsCapability(provider, id string, row map[string]any, keys ...string) bool {
	for _, k := range keys {
		if b, ok := row[k].(bool); ok && b {
			return true
		}
		if s, ok := row[k].(string); ok && (s == "true" || s == "supported") {
			return true
		}
	}
	lower := strings.ToLower(id)
	switch provider {
	case "openai", "azure-openai", "deepseek", "xai", "openrouter", "mistral":
		return strings.Contains(lower, "gpt-4") || strings.Contains(lower, "gpt-4o") ||
			strings.HasPrefix(lower, "o1") || strings.HasPrefix(lower, "o3") ||
			strings.Contains(lower, "deepseek") || strings.Contains(lower, "grok") ||
			strings.Contains(lower, "mistral-large") || strings.Contains(lower, "mixtral")
	case "anthropic":
		return strings.Contains(lower, "claude-3") || strings.Contains(lower, "claude-sonnet") ||
			strings.Contains(lower, "claude-opus") || strings.Contains(lower, "claude-haiku")
	case "google":
		return strings.Contains(lower, "gemini-1.5") || strings.Contains(lower, "gemini-2")
	case "ollama":
		return true
	}
	return false
}

// pricingHint is a coarse bucket. Exact prices per token change far faster than this code
// will, and a stale precise number is worse than an honest category.
func pricingHint(provider, id string, row map[string]any) string {
	if s := firstString(row, "pricing_hint", "cost"); s != "" {
		return s
	}
	lower := strings.ToLower(id)
	switch provider {
	case "ollama":
		return "free"
	case "openrouter":
		if strings.Contains(lower, ":free") {
			return "free"
		}
	}
	if strings.Contains(lower, "mini") || strings.Contains(lower, "flash") || strings.Contains(lower, "haiku") ||
		strings.Contains(lower, "small") || strings.Contains(lower, "8b") {
		return "low"
	}
	if strings.Contains(lower, "opus") || strings.Contains(lower, "o1") || strings.Contains(lower, "large") ||
		strings.Contains(lower, "70b") || strings.Contains(lower, "405b") {
		return "high"
	}
	return "medium"
}

// Probe checks a configuration end to end: reachable, authenticated, and able to answer.
//
// It runs a one-token completion rather than only listing models, because a key can list
// models and still be denied inference (quota, region, deployment).
func (m *Manager) Probe(ctx context.Context, cfg Settings, secret string) (string, error) {
	p, ok := Lookup(cfg.Provider)
	if !ok {
		return "", fmt.Errorf("unknown provider %q", cfg.Provider)
	}
	if !p.Ready() {
		return "", fmt.Errorf("%s is not supported by this build", p.Label)
	}
	if p.Auth != AuthNone && strings.TrimSpace(secret) == "" {
		return "", errors.New("no API key is configured")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return "", errors.New("choose a model first")
	}
	client := &Inference{HTTP: m.http}
	// Reasoning models spend part of the budget on thinking before emitting
	// the final answer; a tiny cap (8) leaves no room for the answer itself
	// and the provider returns empty content. 512 tokens is still a trivial
	// probe, and it lets every supported model family finish.
	res, err := client.Complete(ctx, cfg, secret, Request{
		System:    "You are a connectivity probe.",
		User:      "Reply with the single word: ok",
		MaxTokens: 512,
	})
	if err != nil {
		return "", err
	}
	msg := strings.TrimSpace(res.Text)
	if msg == "" {
		return "", errors.New("the provider accepted the request but returned no text")
	}
	return fmt.Sprintf("%s answered (%s, %s)", p.Label, cfg.Model, firstLineOf(msg)), nil
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 40 {
		s = s[:40] + "…"
	}
	return s
}

// QuerySecret is a helper for callers that need a credential and want the environment
// fallback applied consistently.
func (s *Store) QuerySecret(provider string) (string, bool, error) {
	if secret, ok, err := s.Credential(provider); err != nil || ok {
		return secret, ok, err
	}
	if env := envCredential(provider); env != "" {
		return env, true, nil
	}
	return "", false, nil
}

// BaseURLFor resolves the effective endpoint for a provider.
func BaseURLFor(cfg Settings) string {
	p, ok := Lookup(cfg.Provider)
	if !ok {
		return ""
	}
	if strings.TrimSpace(cfg.Endpoint) != "" {
		return strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	}
	return p.BaseURL
}

var _ = url.Values{} // keep net/url imported for future query building
