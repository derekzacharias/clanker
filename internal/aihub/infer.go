package aihub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Inference is the AIInferenceService: one call shape for every provider.
//
// Callers ask for text or for JSON and get a normalized answer. They never see a provider
// field name, a header, or a retry.
type Inference struct {
	HTTP *http.Client
	// MaxRetries defaults to 2. Retries only happen for rate limits and 5xx: retrying a
	// 401 is how a locked account becomes a locked account with more audit noise.
	MaxRetries int
	// Backoff is the base delay; tests set it to zero.
	Backoff time.Duration
}

// Request is one completion.
type Request struct {
	System      string
	User        string
	MaxTokens   int
	Temperature float64
	// JSON asks the provider to constrain its output to a JSON object where supported.
	JSON bool
}

// Usage is token accounting. It is reported, never estimated: a feature that guesses its
// own cost cannot be trusted to stay within a budget.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Response is one normalized completion.
type Response struct {
	Text     string
	Provider string
	Model    string
	Usage    Usage
	Elapsed  time.Duration
	// Attempts is 1 unless a retry happened.
	Attempts int
}

// Complete runs one inference call against the configured provider.
func (i *Inference) Complete(ctx context.Context, cfg Settings, secret string, req Request) (Response, error) {
	p, ok := Lookup(cfg.Provider)
	if !ok {
		return Response{}, fmt.Errorf("unknown provider %q", cfg.Provider)
	}
	if !p.Ready() {
		return Response{}, fmt.Errorf("%s is not supported by this build: %s", p.Label, p.Notes)
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return Response{}, errors.New("no model is selected")
	}
	if p.Auth != AuthNone && strings.TrimSpace(secret) == "" {
		return Response{}, fmt.Errorf("no credential is configured for %s", p.Label)
	}
	if req.MaxTokens <= 0 {
		req.MaxTokens = 700
	}

	payload, err := buildPayload(p, cfg, req)
	if err != nil {
		return Response{}, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Response{}, fmt.Errorf("encode request: %w", err)
	}

	endpoint := p.ChatURL(BaseURLFor(cfg), cfg.Model, cfg.APIVersion)
	attempts := 0
	maxRetries := i.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	start := time.Now()

	for {
		attempts++
		out, usage, retryAfter, err := i.doOnce(ctx, p, secret, endpoint, body)
		if err == nil {
			return Response{
				Text: out, Provider: p.ID, Model: cfg.Model, Usage: usage,
				Elapsed: time.Since(start), Attempts: attempts,
			}, err
		}
		if attempts > maxRetries || !isRetryable(err) {
			return Response{}, err
		}
		delay := i.Backoff
		if delay <= 0 {
			delay = 700 * time.Millisecond
		}
		delay *= time.Duration(attempts)
		if retryAfter > delay {
			delay = retryAfter
		}
		select {
		case <-ctx.Done():
			return Response{}, ctx.Err()
		case <-time.After(delay):
		}
	}
}

// retryableError marks an error that is worth another attempt.
type retryableError struct {
	status int
	msg    string
	after  time.Duration
}

func (e *retryableError) Error() string { return e.msg }

func isRetryable(err error) bool {
	var re *retryableError
	return errors.As(err, &re)
}

func (i *Inference) doOnce(ctx context.Context, p Provider, secret, endpoint string, body []byte) (string, Usage, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", Usage{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	applyAuth(req, p, secret)

	client := i.HTTP
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	res, err := client.Do(req)
	if err != nil {
		return "", Usage{}, 0, fmt.Errorf("could not reach %s: %w", p.Label, err)
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return "", Usage{}, 0, fmt.Errorf("read %s response: %w", p.Label, err)
	}

	switch {
	case res.StatusCode == http.StatusTooManyRequests:
		return "", Usage{}, parseRetryAfter(res.Header.Get("Retry-After")),
			&retryableError{status: res.StatusCode, msg: p.Label + " rate-limited the request"}
	case res.StatusCode >= 500:
		return "", Usage{}, parseRetryAfter(res.Header.Get("Retry-After")),
			&retryableError{status: res.StatusCode, msg: fmt.Sprintf("%s returned HTTP %d", p.Label, res.StatusCode)}
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		return "", Usage{}, 0, fmt.Errorf("%s rejected the credential (HTTP %d)", p.Label, res.StatusCode)
	case res.StatusCode < 200 || res.StatusCode > 299:
		return "", Usage{}, 0, fmt.Errorf("%s returned HTTP %d: %s", p.Label, res.StatusCode, firstLineOf(string(raw)))
	}

	text, usage, err := parseAnswer(p, raw)
	if err != nil {
		return "", Usage{}, 0, err
	}
	return text, usage, 0, nil
}

func parseRetryAfter(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if secs, err := strconv.Atoi(raw); err == nil && secs > 0 && secs < 300 {
		return time.Duration(secs) * time.Second
	}
	return 0
}

// buildPayload shapes the request per provider family. Four shapes cover every supported
// provider; a fifth would be a reason to add a field to Provider, not an `if` here.
func buildPayload(p Provider, cfg Settings, req Request) (map[string]any, error) {
	system := strings.TrimSpace(req.System)
	user := strings.TrimSpace(req.User)
	if user == "" {
		return nil, errors.New("an empty prompt is not useful")
	}

	switch p.ID {
	case "anthropic":
		payload := map[string]any{
			"model":      cfg.Model,
			"max_tokens": req.MaxTokens,
			"messages":   []map[string]any{{"role": "user", "content": user}},
		}
		if system != "" {
			payload["system"] = system
		}
		if req.Temperature > 0 {
			payload["temperature"] = req.Temperature
		}
		return payload, nil

	case "google":
		payload := map[string]any{
			"contents": []map[string]any{{"role": "user", "parts": []map[string]any{{"text": user}}}},
			"generationConfig": map[string]any{
				"maxOutputTokens": req.MaxTokens,
			},
		}
		if system != "" {
			payload["systemInstruction"] = map[string]any{"parts": []map[string]any{{"text": system}}}
		}
		if req.Temperature > 0 {
			payload["generationConfig"].(map[string]any)["temperature"] = req.Temperature
		}
		if req.JSON {
			payload["generationConfig"].(map[string]any)["responseMimeType"] = "application/json"
		}
		return payload, nil

	case "cohere":
		msgs := []map[string]any{}
		if system != "" {
			msgs = append(msgs, map[string]any{"role": "system", "content": system})
		}
		msgs = append(msgs, map[string]any{"role": "user", "content": user})
		payload := map[string]any{"model": cfg.Model, "messages": msgs, "max_tokens": req.MaxTokens}
		if req.Temperature > 0 {
			payload["temperature"] = req.Temperature
		}
		return payload, nil
	}

	// OpenAI-compatible: OpenAI, Azure, xAI, DeepSeek, Mistral, OpenRouter, Ollama /v1.
	msgs := []map[string]any{}
	if system != "" {
		msgs = append(msgs, map[string]any{"role": "system", "content": system})
	}
	msgs = append(msgs, map[string]any{"role": "user", "content": user})
	payload := map[string]any{"messages": msgs, "max_tokens": req.MaxTokens}
	// Azure takes the deployment from the URL, not the body; sending "model" there is
	// rejected by some api-versions.
	if !p.NeedsDeployment {
		payload["model"] = cfg.Model
	}
	if req.Temperature > 0 {
		payload["temperature"] = req.Temperature
	}
	if req.JSON {
		payload["response_format"] = map[string]any{"type": "json_object"}
	}
	return payload, nil
}

// parseAnswer normalizes the four response shapes.
func parseAnswer(p Provider, raw []byte) (string, Usage, error) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return "", Usage{}, fmt.Errorf("%s returned something that is not JSON", p.Label)
	}
	if e, ok := root["error"].(map[string]any); ok {
		msg := firstString(e, "message", "detail", "type")
		if msg == "" {
			msg = "provider reported an error"
		}
		return "", Usage{}, fmt.Errorf("%s: %s", p.Label, msg)
	}

	switch p.ID {
	case "anthropic":
		var text strings.Builder
		if parts, ok := root["content"].([]any); ok {
			for _, part := range parts {
				if obj, ok := part.(map[string]any); ok && firstString(obj, "type") == "text" {
					text.WriteString(firstString(obj, "text"))
				}
			}
		}
		usage := usageFrom(root, "usage", "input_tokens", "output_tokens")
		if text.Len() == 0 {
			return "", usage, fmt.Errorf("%s returned no text", p.Label)
		}
		return text.String(), usage, nil

	case "google":
		var text strings.Builder
		if cands, ok := root["candidates"].([]any); ok {
			for _, c := range cands {
				obj, ok := c.(map[string]any)
				if !ok {
					continue
				}
				if content, ok := obj["content"].(map[string]any); ok {
					if parts, ok := content["parts"].([]any); ok {
						for _, part := range parts {
							if po, ok := part.(map[string]any); ok {
								text.WriteString(firstString(po, "text"))
							}
						}
					}
				}
			}
		}
		usage := usageFrom(root, "usageMetadata", "promptTokenCount", "candidatesTokenCount")
		if text.Len() == 0 {
			return "", usage, fmt.Errorf("%s returned no text (the request may have been blocked)", p.Label)
		}
		return text.String(), usage, nil

	case "cohere":
		var text strings.Builder
		if msg, ok := root["message"].(map[string]any); ok {
			if parts, ok := msg["content"].([]any); ok {
				for _, part := range parts {
					if po, ok := part.(map[string]any); ok {
						text.WriteString(firstString(po, "text"))
					}
				}
			}
		}
		var usage Usage
		if u, ok := root["usage"].(map[string]any); ok {
			if t, ok := u["tokens"].(map[string]any); ok {
				usage.InputTokens = firstInt(t, "input_tokens")
				usage.OutputTokens = firstInt(t, "output_tokens")
			}
		}
		if text.Len() == 0 {
			return "", usage, fmt.Errorf("%s returned no text", p.Label)
		}
		return text.String(), usage, nil
	}

	// OpenAI-compatible
	var text strings.Builder
	if choices, ok := root["choices"].([]any); ok {
		for _, c := range choices {
			obj, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if msg, ok := obj["message"].(map[string]any); ok {
				text.WriteString(extractContent(msg["content"]))
			}
			if t := firstString(obj, "text"); t != "" {
				text.WriteString(t)
			}
		}
	}
	usage := usageFrom(root, "usage", "prompt_tokens", "completion_tokens")
	if text.Len() == 0 {
		return "", usage, fmt.Errorf("%s returned no text", p.Label)
	}
	return text.String(), usage, nil
}

// extractContent handles both the string form and the array-of-parts form that
// OpenAI-compatible servers use interchangeably.
func extractContent(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case []any:
		var b strings.Builder
		for _, part := range val {
			if obj, ok := part.(map[string]any); ok {
				b.WriteString(firstString(obj, "text"))
			}
		}
		return b.String()
	}
	return ""
}

func usageFrom(root map[string]any, section string, inKey, outKey string) Usage {
	obj, ok := root[section].(map[string]any)
	if !ok {
		return Usage{}
	}
	return Usage{InputTokens: firstInt(obj, inKey), OutputTokens: firstInt(obj, outKey)}
}
