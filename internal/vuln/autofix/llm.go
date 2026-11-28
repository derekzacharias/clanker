package autofix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OpenAICompatible talks to any server that implements the OpenAI chat-completions
// shape: llama.cpp, vLLM, Ollama's /v1, LM Studio, or a hosted provider.
//
// The endpoint is a parameter rather than a default because the intended deployment is a
// model on the operator's own network. Nothing here reaches out until it is given a URL.
type OpenAICompatible struct {
	// Endpoint is the API base, for example http://127.0.0.1:8080/v1.
	Endpoint string
	APIKey   string
	Model    string
	// HTTP is optional; a client with a sane timeout is created when nil.
	HTTP *http.Client
	// Temperature defaults to 0: triage is a classification task, not a writing task.
	Temperature float64
	// MaxTokens defaults to 1200.
	MaxTokens int
}

// NewOpenAICompatible validates the endpoint and returns a client.
func NewOpenAICompatible(endpoint, apiKey, model string) (*OpenAICompatible, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, errors.New("no model endpoint given")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid model endpoint: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("model endpoint must be http or https, got %q", u.Scheme)
	}
	if strings.TrimSpace(model) == "" {
		return nil, errors.New("no model name given")
	}
	return &OpenAICompatible{
		Endpoint: strings.TrimRight(endpoint, "/"),
		APIKey:   strings.TrimSpace(apiKey),
		Model:    strings.TrimSpace(model),
		HTTP:     &http.Client{Timeout: 120 * time.Second},
	}, nil
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Stream      bool          `json:"stream"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

// Complete sends one system/user pair and returns the assistant text.
func (c *OpenAICompatible) Complete(ctx context.Context, system, user string) (string, error) {
	if c == nil {
		return "", errors.New("no model client")
	}
	url := c.Endpoint
	if !strings.HasSuffix(url, "/chat/completions") {
		url += "/chat/completions"
	}
	payload := chatRequest{
		Model:       c.Model,
		Temperature: c.Temperature,
		MaxTokens:   c.MaxTokens,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode model request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("model request failed: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("read model answer: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return "", fmt.Errorf("model returned HTTP %d: %s", res.StatusCode, truncateForError(body))
	}
	var out chatResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decode model answer: %w", err)
	}
	if out.Error != nil && out.Error.Message != "" {
		return "", fmt.Errorf("model error: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return "", errors.New("model returned no choices")
	}
	return out.Choices[0].Message.Content, nil
}

func truncateForError(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

// Func adapts a function to LLM. It exists so tests and one-off callers can supply a
// deterministic answer without a server.
type Func func(ctx context.Context, system, user string) (string, error)

// Complete implements LLM.
func (f Func) Complete(ctx context.Context, system, user string) (string, error) {
	return f(ctx, system, user)
}
