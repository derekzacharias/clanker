// Package aihub is the single place where AI providers, credentials, model discovery
// and inference live.
//
// The rule that shapes the whole package: a provider is a configuration record, not a
// code path scattered through features. If a new provider needs a new `if`, it belongs in
// this file; if a feature needs a provider, it asks the hub.
package aihub

import "strings"

// AuthStyle is how a provider expects its credential to travel.
//
// Most services accept a bearer token, but assuming that is how integrations break:
// Anthropic wants a header of its own, Google wants a query parameter, Azure wants an
// endpoint, a deployment name and an api-version.
type AuthStyle string

const (
	// AuthBearer sends `Authorization: Bearer <key>`.
	AuthBearer AuthStyle = "bearer"
	// AuthHeader sends a provider-specific header (x-api-key, api-key).
	AuthHeader AuthStyle = "header"
	// AuthQuery appends ?key= (Google Generative Language).
	AuthQuery AuthStyle = "query"
	// AuthAzure sends the api-key header and needs an endpoint, a deployment and an
	// api-version in the URL.
	AuthAzure AuthStyle = "azure"
	// AuthNone is for a local runtime that has no credential (Ollama).
	AuthNone AuthStyle = "none"
)

// Provider describes one AI service.
//
// The fields are data on purpose: the discovery and inference code branches on these
// values, not on provider names, so adding a provider is a table entry plus (at most) a
// response-shape adapter.
type Provider struct {
	ID    string
	Label string
	Auth  AuthStyle
	// HeaderName is used when Auth is AuthHeader.
	HeaderName string
	// BaseURL is the default API root. Empty means the user must supply one.
	BaseURL string
	// ChatPath is appended to BaseURL for inference.
	ChatPath string
	// ModelsPath is appended to BaseURL for discovery. Empty means the provider has no
	// listing API and models are entered by hand.
	ModelsPath string
	// ExtraHeaders are always sent (Anthropic's anthropic-version, for example).
	ExtraHeaders map[string]string
	// NeedsEndpoint means BaseURL must come from the user (Azure, self-hosted Ollama).
	NeedsEndpoint bool
	// NeedsAPIVersion means Azure's api-version query parameter is required.
	NeedsAPIVersion bool
	// NeedsDeployment means the model id is a deployment name (Azure).
	NeedsDeployment bool
	// Implemented is false for a provider we cannot talk to yet. It is listed anyway so
	// the UI can say "not available" instead of silently omitting it.
	Implemented bool
	// DefaultModel is only a starting suggestion for a fresh install. It is never used
	// to validate a selection: the catalog decides what exists.
	DefaultModel string
	KeyHint      string
	DocsURL      string
	// Notes are shown in the provider picker when a provider needs special handling.
	Notes string
}

// providers is the catalog. Order is the order a person sees.
var providers = []Provider{
	{
		ID: "openai", Label: "OpenAI", Auth: AuthBearer, Implemented: true,
		BaseURL: "https://api.openai.com/v1", ChatPath: "/chat/completions", ModelsPath: "/models",
		DefaultModel: "gpt-4o-mini", KeyHint: "sk-...", DocsURL: "https://platform.openai.com/docs",
	},
	{
		ID: "anthropic", Label: "Anthropic (Claude)", Auth: AuthHeader, HeaderName: "x-api-key",
		Implemented: true, BaseURL: "https://api.anthropic.com/v1",
		ChatPath: "/messages", ModelsPath: "/models",
		ExtraHeaders: map[string]string{"anthropic-version": "2023-06-01"},
		DefaultModel: "claude-3-5-sonnet-latest", KeyHint: "sk-ant-...",
		DocsURL: "https://docs.anthropic.com",
	},
	{
		ID: "google", Label: "Google (Gemini)", Auth: AuthQuery, Implemented: true,
		BaseURL:  "https://generativelanguage.googleapis.com/v1beta",
		ChatPath: "/models/%s:generateContent", ModelsPath: "/models",
		DefaultModel: "gemini-1.5-flash", KeyHint: "AIza...",
		DocsURL: "https://ai.google.dev/gemini-api/docs",
	},
	{
		ID: "xai", Label: "xAI (Grok)", Auth: AuthBearer, Implemented: true,
		BaseURL: "https://api.x.ai/v1", ChatPath: "/chat/completions", ModelsPath: "/models",
		KeyHint: "xai-...", DocsURL: "https://docs.x.ai",
	},
	{
		ID: "deepseek", Label: "DeepSeek", Auth: AuthBearer, Implemented: true,
		BaseURL: "https://api.deepseek.com/v1", ChatPath: "/chat/completions", ModelsPath: "/models",
		DefaultModel: "deepseek-chat", DocsURL: "https://api-docs.deepseek.com",
	},
	{
		ID: "mistral", Label: "Mistral AI", Auth: AuthBearer, Implemented: true,
		BaseURL: "https://api.mistral.ai/v1", ChatPath: "/chat/completions", ModelsPath: "/models",
		DocsURL: "https://docs.mistral.ai",
	},
	{
		ID: "cohere", Label: "Cohere", Auth: AuthBearer, Implemented: true,
		BaseURL: "https://api.cohere.com", ChatPath: "/v2/chat", ModelsPath: "/v1/models",
		DefaultModel: "command-r-plus", DocsURL: "https://docs.cohere.com",
	},
	{
		ID: "openrouter", Label: "OpenRouter", Auth: AuthBearer, Implemented: true,
		BaseURL: "https://openrouter.ai/api/v1", ChatPath: "/chat/completions", ModelsPath: "/models",
		DocsURL: "https://openrouter.ai/docs",
		Notes:   "Routes to many upstream providers; upstream rate limits still apply.",
	},
	{
		ID: "azure-openai", Label: "Azure OpenAI", Auth: AuthAzure, Implemented: true,
		ChatPath:      "/openai/deployments/%s/chat/completions",
		NeedsEndpoint: true, NeedsAPIVersion: true, NeedsDeployment: true,
		KeyHint: "Azure key 1 or 2",
		DocsURL: "https://learn.microsoft.com/azure/ai-services/openai/",
		Notes:   "The model is your deployment name. Discovery uses the deployments API when reachable, otherwise the configured name.",
	},
	{
		ID: "ollama", Label: "Ollama (local)", Auth: AuthNone, Implemented: true,
		BaseURL: "http://127.0.0.1:11434", ChatPath: "/v1/chat/completions", ModelsPath: "/api/tags",
		NeedsEndpoint: true, DefaultModel: "llama3.1",
		DocsURL: "https://ollama.com",
		Notes:   "No credential. Traffic stays on the host or network you point it at.",
	},
	{
		ID: "bedrock", Label: "AWS Bedrock", Auth: AuthBearer, Implemented: false,
		BaseURL: "", ChatPath: "", ModelsPath: "",
		DocsURL: "https://docs.aws.amazon.com/bedrock/",
		Notes:   "Requires AWS SigV4 request signing, which this build does not implement yet. Use an OpenAI-compatible gateway instead.",
	},
}

// Providers returns a copy of the catalog.
func Providers() []Provider {
	out := make([]Provider, len(providers))
	copy(out, providers)
	return out
}

// Lookup finds a provider by id.
func Lookup(id string) (Provider, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, p := range providers {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

// Implemented reports whether the hub can actually talk to this provider.
func (p Provider) Ready() bool { return p.Implemented }

// ChatURL builds the inference URL for a model.
//
// It exists so no caller concatenates provider paths by hand: `%s` in a chat path is the
// model (or Azure deployment) and every provider gets its credential placement right in
// exactly one place.
func (p Provider) ChatURL(baseURL, model, apiVersion string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		base = strings.TrimRight(p.BaseURL, "/")
	}
	path := p.ChatPath
	if strings.Contains(path, "%s") {
		path = strings.Replace(path, "%s", pathEscape(model), 1)
	}
	u := base + path
	if p.NeedsAPIVersion {
		v := strings.TrimSpace(apiVersion)
		if v == "" {
			v = "2024-10-21"
		}
		u += "?api-version=" + pathEscape(v)
	}
	return u
}

// ModelsURL builds the discovery URL, or "" when the provider has no listing API.
func (p Provider) ModelsURL(baseURL string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		base = strings.TrimRight(p.BaseURL, "/")
	}
	if p.ModelsPath == "" || base == "" {
		return ""
	}
	return base + p.ModelsPath
}

// Statuses a model can carry in the normalized catalog.
const (
	StatusProduction   = "production"
	StatusPreview      = "preview"
	StatusRetired      = "retired"
	StatusInaccessible = "inaccessible"
)

// Model is the normalized shape every provider's listing is mapped onto.
type Model struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Provider is filled by the hub, never by the provider response.
	Provider      string `json:"provider"`
	ContextWindow int    `json:"context_window,omitempty"`
	SupportsTools bool   `json:"supports_tools,omitempty"`
	SupportsJSON  bool   `json:"supports_json,omitempty"`
	// PricingHint is a coarse bucket ("free", "low", "medium", "high") because exact
	// per-token prices change weekly and a stale number is worse than a category.
	PricingHint string `json:"pricing_hint,omitempty"`
	Status      string `json:"status"`
	// Details is a short human note ("deployment", "preview build").
	Details string `json:"details,omitempty"`
}

// excludedModelPatterns removes models that are valid identifiers but useless for text
// security analysis. A dropdown full of embedding and image models is a usability bug.
var excludedModelPatterns = []string{
	"embed", "embedding", "whisper", "tts", "dall-e", "moderation",
	"image", "vision-preview", "audio", "realtime", "rerank", "guard",
	"stable-diffusion", "sdxl", "clip", "sam-", "davinci", "babbage",
}

// previewModelPatterns marks models that are not production-ready.
var previewModelPatterns = []string{"preview", "experimental", "alpha", "beta", "canary", "nightly"}

// retiredModelPatterns marks identifiers providers keep returning after retirement.
var retiredModelPatterns = []string{":deprecated", "-deprecated", "-legacy", "-0301", "-0613", "-0314"}

// IsTextAnalysisModel reports whether a model identifier is plausibly useful for
// generating remediation text.
func IsTextAnalysisModel(id string) bool {
	lower := strings.ToLower(id)
	if strings.TrimSpace(lower) == "" {
		return false
	}
	for _, bad := range excludedModelPatterns {
		if strings.Contains(lower, bad) {
			return false
		}
	}
	return true
}

// ClassifyStatus derives a lifecycle status from the identifier when the provider does not
// state one. It is deliberately conservative: anything that looks like a preview is
// labelled preview so it is hidden unless the operator opts in.
func ClassifyStatus(id string) string {
	lower := strings.ToLower(id)
	for _, bad := range retiredModelPatterns {
		if strings.Contains(lower, bad) {
			return StatusRetired
		}
	}
	for _, bad := range previewModelPatterns {
		if strings.Contains(lower, bad) {
			return StatusPreview
		}
	}
	// Google marks experimental builds with a suffix ("gemini-2.0-flash-exp"). Matching a
	// bare "exp" substring would catch "export", so only the suffix forms count.
	if strings.HasSuffix(lower, "-exp") || strings.Contains(lower, "-exp-") {
		return StatusPreview
	}
	return StatusProduction
}

// pathEscape avoids importing net/url in a file that is otherwise data.
func pathEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.', r == '~', r == ':':
			b.WriteRune(r)
		default:
			b.WriteString("%" + strings.ToUpper(hex2(byte(r))))
		}
	}
	return b.String()
}

func hex2(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0x0f]})
}
