// Package agent is the endpoint-side half of fleet reporting: where the agent
// keeps its enrollment, and how it talks to the Clanker Guard server.
//
// Enrollment is explicit and one-time: the operator passes the server URL and the
// enrollment token printed by the dashboard, the agent exchanges them for its own
// bearer token, and stores that in a 0600 file. Nothing is sent anywhere until
// both are supplied — an agent without a config never contacts a network.
package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrNotEnrolled means the agent has no config: purely local operation.
var ErrNotEnrolled = errors.New("agent is not enrolled; run: clanker-guard-agent enroll --server URL --token TOKEN")

// maxReportBytes bounds what the agent is willing to send in one request.
const maxReportBytes = 32 << 20

// Config is the on-disk enrollment. Token is a per-agent bearer credential.
type Config struct {
	Server  string `json:"server"`
	AgentID string `json:"agent_id"`
	Token   string `json:"token"`
	Host    string `json:"host,omitempty"`
	// AllowInsecureHTTP records an explicit operator decision to talk to a
	// non-loopback server over plain HTTP. Without it, plain HTTP is refused: the
	// agent bearer token and every report would otherwise cross the network in
	// clear text.
	AllowInsecureHTTP bool `json:"allow_insecure_http,omitempty"`
	// NextSequence is the next report sequence this agent will use. It is persisted
	// so a restart cannot replay an old sequence number, which the server would (and
	// should) reject.
	NextSequence int64     `json:"next_sequence,omitempty"`
	EnrolledAt   time.Time `json:"enrolled_at"`
}

// loopback reports whether the URL host is this machine.
func loopback(hostport string) bool {
	host := hostport
	if i := strings.LastIndex(hostport, ":"); i > 0 && !strings.Contains(hostport[i:], "]") {
		host = hostport[:i]
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1":
		return true
	}
	return strings.HasPrefix(host, "127.")
}

// ValidateTransport enforces encrypted agent traffic.
//
// HTTPS is required for every enrollment, check-in and report. Plain HTTP is
// tolerated only for loopback (a test or a co-located dashboard) or when the
// operator explicitly opted in, because the bearer token is the agent's entire
// identity and it travels in that request.
func ValidateTransport(server string, allowInsecure bool) error {
	raw := strings.TrimSpace(server)
	if raw == "" {
		return errors.New("server URL is empty")
	}
	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, "https://"):
		return nil
	case strings.HasPrefix(lower, "http://"):
		hostport := strings.TrimPrefix(raw, "http://")
		if i := strings.IndexAny(hostport, "/?#"); i >= 0 {
			hostport = hostport[:i]
		}
		if loopback(hostport) || allowInsecure {
			return nil
		}
		return fmt.Errorf("refusing plain HTTP to %s: agent credentials and reports would travel unencrypted; "+
			"use an https:// server URL (or pass --allow-insecure-http for an isolated lab network)", hostport)
	default:
		return fmt.Errorf("server URL must start with https:// (got %q)", raw)
	}
}

// ConfigPath is $CLANKER_GUARD_AGENT_CONFIG, else <config dir>/clanker-guard/agent.json.
func ConfigPath() string {
	if p := strings.TrimSpace(os.Getenv("CLANKER_GUARD_AGENT_CONFIG")); p != "" {
		return p
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "clanker-guard", "agent.json")
	}
	return filepath.Join(".", ".clanker-agent.json")
}

// LoadConfig reads the enrollment. A missing file is ErrNotEnrolled.
func LoadConfig(path string) (Config, error) {
	if path == "" {
		path = ConfigPath()
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, ErrNotEnrolled
	}
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return Config{}, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	if c.Server == "" || c.Token == "" || c.AgentID == "" {
		return Config{}, fmt.Errorf("%s is missing server, agent_id or token", path)
	}
	return c, nil
}

// SaveConfig writes the enrollment atomically with 0600 permissions.
func SaveConfig(path string, c Config) error {
	if path == "" {
		path = ConfigPath()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	payload, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".agent-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if _, err := tmp.Write(append(payload, '\n')); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}

// RemoveConfig deletes the enrollment (used by uninstall).
func RemoveConfig(path string) error {
	if path == "" {
		path = ConfigPath()
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Status is what the agent reports about itself.
type Status struct {
	State    string `json:"state"`
	Phase    string `json:"phase,omitempty"`
	Percent  int    `json:"percent"`
	Message  string `json:"message,omitempty"`
	Findings int    `json:"findings"`
	Version  string `json:"version,omitempty"`
	OS       string `json:"os,omitempty"`
}

// Ack is the server's answer to an ingested report.
type Ack struct {
	RunID    string `json:"run_id"`
	Findings int    `json:"findings"`
	Accepted bool   `json:"accepted"`
}

// Client talks to one Clanker Guard server with one agent token.
type Client struct {
	Server string
	Token  string
	HTTP   *http.Client
}

// New returns a client for server with a trimmed base URL.
func New(server, token string) *Client {
	return &Client{
		Server: strings.TrimRight(strings.TrimSpace(server), "/"),
		Token:  token,
		// A claim request is held open by the server, so the client timeout must
		// comfortably exceed the longest hold.
		HTTP: &http.Client{Timeout: 90 * time.Second},
	}
}

// PlainHTTP reports whether the server URL is unencrypted, so the CLI can be
// honest about it instead of silently shipping a token in clear text.
func (c *Client) PlainHTTP() bool { return strings.HasPrefix(c.Server, "http://") }

// Enroll exchanges the shared enrollment token for this agent's own credential.
func (c *Client) Enroll(ctx context.Context, enrollToken, host, osName, version string) (Config, error) {
	body := map[string]string{"host": host, "os": osName, "version": version}
	var out struct {
		AgentID string `json:"agent_id"`
		Token   string `json:"agent_token"`
	}
	if err := c.post(ctx, "/api/agents/enroll", body, map[string]string{"X-Guard-Enroll-Token": enrollToken}, &out); err != nil {
		return Config{}, err
	}
	if out.AgentID == "" || out.Token == "" {
		return Config{}, errors.New("server did not return an agent id and token")
	}
	return Config{
		Server:     c.Server,
		AgentID:    out.AgentID,
		Token:      out.Token,
		Host:       host,
		EnrolledAt: time.Now().UTC(),
	}, nil
}

// Checkin records what the agent is doing.
func (c *Client) Checkin(ctx context.Context, st Status) error {
	return c.post(ctx, "/api/agents/checkin", st, nil, nil)
}

// Report uploads a finished report document (the JSON the scan already writes).
//
// Every submission carries a unique id, a monotonic sequence and the digest of the
// exact bytes sent, so the server can tell a legitimate retry from a replayed or
// tampered upload without trusting anything inside the document.
func (c *Client) Report(ctx context.Context, report []byte) (Ack, error) {
	return c.ReportWithSequence(ctx, report, 0)
}

// ReportWithSequence is Report with an explicit sequence. sequence <= 0 lets the
// server behave as it did before replay protection existed (legacy clients).
func (c *Client) ReportWithSequence(ctx context.Context, report []byte, sequence int64) (Ack, error) {
	if len(report) == 0 {
		return Ack{}, errors.New("report is empty")
	}
	if len(report) > maxReportBytes {
		return Ack{}, fmt.Errorf("report is %d bytes, over the %d byte limit", len(report), maxReportBytes)
	}
	sum := sha256.Sum256(report)
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return Ack{}, fmt.Errorf("submission id: %w", err)
	}
	headers := map[string]string{
		"X-Guard-Submission-Id":  hex.EncodeToString(id),
		"X-Guard-Payload-SHA256": hex.EncodeToString(sum[:]),
	}
	if sequence > 0 {
		headers["X-Guard-Sequence"] = strconv.FormatInt(sequence, 10)
	}
	var ack Ack
	if err := c.postRaw(ctx, "/api/agents/report", report, &ack, headers); err != nil {
		return Ack{}, err
	}
	return ack, nil
}

// Reporter sends throttled status updates so the dashboard can show what the
// agent is doing without one request per pipeline stage.
type Reporter struct {
	Client      *Client
	MinInterval time.Duration
	Now         func() time.Time

	mu       sync.Mutex
	lastSent time.Time
	lastKey  string
	lastErr  error
}

// NewReporter wraps a client with a 1s throttle.
func NewReporter(c *Client) *Reporter {
	return &Reporter{Client: c, MinInterval: time.Second, Now: func() time.Time { return time.Now() }}
}

// Send posts a status unless an identical one was sent within MinInterval.
// force bypasses the throttle (final "done"/"error" updates).
func (r *Reporter) Send(ctx context.Context, st Status, force bool) error {
	if r == nil || r.Client == nil {
		return nil
	}
	key := fmt.Sprintf("%s|%s|%d", st.State, st.Phase, st.Percent/5)
	now := r.Now()
	r.mu.Lock()
	skip := !force && key == r.lastKey && now.Sub(r.lastSent) < r.MinInterval
	if !skip {
		r.lastSent = now
		r.lastKey = key
	}
	r.mu.Unlock()
	if skip {
		return nil
	}
	err := r.Client.Checkin(ctx, st)
	r.mu.Lock()
	r.lastErr = err
	r.mu.Unlock()
	return err
}

// LastError is the most recent transport failure, so the CLI can mention it once.
func (r *Reporter) LastError() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

func (c *Client) post(ctx context.Context, path string, body any, headers map[string]string, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return c.postRaw(ctx, path, payload, out, headers)
}

func (c *Client) postRaw(ctx context.Context, path string, payload []byte, out any, headers ...map[string]string) error {
	if c.Server == "" {
		return errors.New("server URL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Server+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	c.authorize(req)
	for _, set := range headers {
		for k, v := range set {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", c.Server, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var apiErr struct {
			Error        string `json:"error"`
			Code         string `json:"code"`
			LastSequence int64  `json:"last_sequence"`
		}
		_ = json.Unmarshal(raw, &apiErr)
		// A sequence reset is recoverable, and it is the one rejection that is worth
		// retrying automatically: the endpoint's own counter fell behind the server's.
		if apiErr.Code == "replay_detected" && apiErr.LastSequence > 0 {
			return &ReplayError{LastSequence: apiErr.LastSequence}
		}
		msg := strings.TrimSpace(apiErr.Error)
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		if apiErr.Code == "agent_revoked" || resp.StatusCode == http.StatusUnauthorized {
			return &RevokedError{Detail: msg}
		}
		return fmt.Errorf("%s %s: %s", http.MethodPost, path, msg)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%s returned invalid JSON: %w", path, err)
		}
	}
	return nil
}

// Task is a unit of work the server queued for this endpoint. The agent pulls it
// when it polls; the server never connects to the endpoint.
type Task struct {
	ID          string     `json:"id"`
	AgentID     string     `json:"agent_id"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	RequestedAt time.Time  `json:"requested_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	Note        string     `json:"note,omitempty"`
}

// ClaimTask returns the next queued task, or nil when there is nothing to do.
func (c *Client) ClaimTask(ctx context.Context) (*Task, error) {
	return c.ClaimTaskWait(ctx, 0)
}

// ClaimTaskWait asks for work and keeps the request open for up to wait, so the
// server can answer immediately when an administrator requests a scan. A held
// request is also how the server knows the endpoint is reachable; with wait > 0
// the client should call this in a loop.
func (c *Client) ClaimTaskWait(ctx context.Context, wait time.Duration) (*Task, error) {
	url := c.Server + "/api/agents/tasks/claim"
	if wait > 0 {
		secs := int(wait.Round(time.Second) / time.Second)
		url += fmt.Sprintf("?wait=%d", secs)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	c.authorize(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", c.Server, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var apiErr struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		_ = json.Unmarshal(raw, &apiErr)
		msg := strings.TrimSpace(apiErr.Error)
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		// A rejected credential is not a transient failure. The endpoint was revoked, or a
		// re-enrollment replaced its token; retrying with the same credential loops forever and
		// buries the one line the operator needs to see.
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || apiErr.Code == "agent_revoked" {
			return nil, &RevokedError{Detail: msg}
		}
		return nil, fmt.Errorf("claiming work failed: %s", msg)
	}
	var out struct {
		Task *Task `json:"task"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("claim returned invalid JSON: %w", err)
	}
	if out.Task == nil || out.Task.ID == "" {
		return nil, nil
	}
	return out.Task, nil
}

// CompleteTask reports the outcome of a claimed task.
func (c *Client) CompleteTask(ctx context.Context, taskID, status, note, reportID string) error {
	body := map[string]string{"task_id": taskID, "status": status, "note": note, "report_id": reportID}
	return c.post(ctx, "/api/agents/tasks/complete", body, nil, nil)
}

func (c *Client) authorize(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "clanker-guard-agent")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
}

// Health asks the server for its liveness document. It is unauthenticated on the
// server, so it doubles as a connectivity probe before an agent has credentials.
func (c *Client) Health(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Server+"/api/health", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "clanker-guard-agent")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot reach %s: %w", c.Server, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("health check returned %d", resp.StatusCode)
	}
	return strings.TrimSpace(string(raw)), nil
}

// ReplayError is returned when the server has accepted a higher sequence than this agent offered.
// It carries the server's value so the caller can jump past it instead of being stuck forever.
type ReplayError struct{ LastSequence int64 }

func (e *ReplayError) Error() string {
	return fmt.Sprintf("server has already accepted sequence %d; the local counter is behind", e.LastSequence)
}

// RevokedError means the server no longer accepts this endpoint's credential: the agent was
// revoked, or a re-enrollment replaced its token. Waiting cannot fix it, so a long-running
// caller should stop and tell the operator to enroll again rather than retry forever.
type RevokedError struct{ Detail string }

func (e *RevokedError) Error() string {
	if strings.TrimSpace(e.Detail) == "" {
		return "this endpoint's credential is no longer accepted; enroll it again to reconnect"
	}
	return e.Detail
}
