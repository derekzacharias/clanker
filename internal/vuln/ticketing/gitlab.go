// Package ticketing turns remediation work into tickets in an external tracker.
//
// The GitLab integration is the first (and currently only) provider. It is deliberately
// small: one client, one issue renderer, one table. Everything it needs about a finding
// is passed in, so the package never reaches into the store or the API for data and
// stays testable against a fake GitLab.
//
// Security rules enforced here rather than in the handlers, because they are properties
// of the client and not of one endpoint:
//
//   - the token is only ever sent to the configured origin, in a header, never in a URL;
//   - plain HTTP is refused unless it is explicitly allowed *and* the destination is a
//     private address, so the internal test instance works while a typo in the URL
//     cannot become an SSRF primitive or leak a token over the internet;
//   - redirects are not followed to another host (a redirect is how a token leaks);
//   - errors carry the HTTP status and GitLab's message, never the request headers.
package ticketing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config is everything the client needs. It is built from the credential file and the
// environment by the API layer; the client never reads configuration itself.
type Config struct {
	BaseURL           string
	Token             string
	ProjectID         int
	Timeout           time.Duration
	AllowInsecureHTTP bool
}

// Sentinel errors, so a handler can map one failure mode to one HTTP answer and one
// human sentence instead of forwarding GitLab's prose to the operator.
var (
	ErrNotConfigured  = errors.New("GitLab is not configured")
	ErrUnauthorized   = errors.New("GitLab rejected the access token")
	ErrForbidden      = errors.New("the token is not allowed to do that in this project")
	ErrProjectMissing = errors.New("the GitLab project was not found")
	ErrUnreachable    = errors.New("the GitLab server could not be reached")
	ErrInsecureURL    = errors.New("refusing to send an access token over plain HTTP to that host")
	ErrNoIssuePerms   = errors.New("the token cannot create issues in this project")
)

// APIError is a non-2xx answer from GitLab.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("gitlab returned %d: %s", e.Status, e.Message)
}

// Project is the subset of a GitLab project the dashboard needs.
type Project struct {
	ID                int    `json:"id"`
	Name              string `json:"name"`
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
	IssuesEnabled     bool   `json:"issues_enabled"`
	// Access level of the token's user in this project (GitLab >= 11.4). Zero when the
	// instance does not report it, which is why it is not used as the only signal.
	Permissions struct {
		ProjectAccess *struct {
			AccessLevel int `json:"access_level"`
		} `json:"project_access"`
		GroupAccess *struct {
			AccessLevel int `json:"access_level"`
		} `json:"group_access"`
	} `json:"permissions"`
}

// AccessLevel returns the token user's access level in the project, or 0 if unknown.
func (p Project) AccessLevel() int {
	if p.Permissions.ProjectAccess != nil {
		return p.Permissions.ProjectAccess.AccessLevel
	}
	if p.Permissions.GroupAccess != nil {
		return p.Permissions.GroupAccess.AccessLevel
	}
	return 0
}

// IssueInput is what the dashboard sends to POST /projects/:id/issues.
type IssueInput struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Labels      string `json:"labels,omitempty"`
	// AssigneeIDs is deprecated upstream but still accepted by the versions this
	// deployment targets; empty means "nobody", not "the token owner".
	AssigneeIDs []int `json:"assignee_ids,omitempty"`
}

// Issue is the subset of a created/read issue that gets stored.
type Issue struct {
	ID          int      `json:"id"`
	IID         int      `json:"iid"`
	ProjectID   int      `json:"project_id"`
	Title       string   `json:"title"`
	State       string   `json:"state"`
	WebURL      string   `json:"web_url"`
	Description string   `json:"description"`
	Labels      []string `json:"labels"`
	Assignees   []struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
		Name     string `json:"name"`
	} `json:"assignees"`
}

// AssigneeName is the display name of the first assignee, if any.
func (i Issue) AssigneeName() string {
	if len(i.Assignees) == 0 {
		return ""
	}
	if i.Assignees[0].Name != "" {
		return i.Assignees[0].Name
	}
	return i.Assignees[0].Username
}

// User is the token's own account, used by the connection test.
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
}

// Client talks to one GitLab instance.
type Client struct {
	base    *url.URL
	token   string
	http    *http.Client
	log     *slog.Logger
	timeout time.Duration
}

// NewClient validates the destination and builds a client. Validation lives here so a
// caller cannot skip it by constructing the struct directly.
func NewClient(cfg Config, log *slog.Logger) (*Client, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, ErrNotConfigured
	}
	base, err := ValidateBaseURL(cfg.BaseURL, cfg.AllowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if timeout > time.Minute {
		timeout = time.Minute
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	origin := base.Scheme + "://" + base.Host
	return &Client{
		base:    base,
		token:   cfg.Token,
		log:     log,
		timeout: timeout,
		http: &http.Client{
			Timeout: timeout,
			// A redirect to another host would take the token with it.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return errors.New("too many redirects")
				}
				if req.URL.Scheme+"://"+req.URL.Host != origin {
					return fmt.Errorf("refusing to follow a redirect to %s", req.URL.Host)
				}
				return nil
			},
		},
	}, nil
}

// DefaultTimeout is used when the configuration does not set one.
const DefaultTimeout = 15 * time.Second

// ValidateBaseURL rejects destinations that would leak a token or reach something that
// is not a GitLab instance.
//
// The rules: http or https; no embedded credentials (they end up in logs); no query or
// fragment; plain HTTP only when the operator allowed it and every address the host
// resolves to is private. Cloud metadata addresses are refused outright, in both schemes,
// because "it resolved to a private range" is not the same as "it is a GitLab server".
func ValidateBaseURL(raw string, allowInsecure bool) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrNotConfigured
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("GitLab URL is not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("GitLab URL must start with http:// or https://")
	}
	if u.Host == "" {
		return nil, errors.New("GitLab URL has no host")
	}
	if u.User != nil {
		return nil, errors.New("GitLab URL must not embed credentials; use the token field")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("GitLab URL must not include a query or fragment")
	}
	host := u.Hostname()
	if u.Scheme == "http" && !allowInsecure {
		return nil, fmt.Errorf("%w: use https:// or enable \"allow plain HTTP\" for an internal test instance", ErrInsecureURL)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		// Plain HTTP is only allowed when we can prove the destination is private, so an
		// unresolvable name is a refusal rather than a connection attempt that would put
		// the token on the wire.
		if u.Scheme == "http" {
			return nil, fmt.Errorf("%w: plain HTTP is only permitted for a private address and %s did not resolve",
				ErrInsecureURL, host)
		}
		return nil, fmt.Errorf("%w: cannot resolve %s", ErrUnreachable, host)
	}
	for _, addr := range addrs {
		if addr.IP.IsLinkLocalUnicast() || addr.IP.Equal(net.ParseIP("169.254.169.254")) {
			return nil, fmt.Errorf("refusing to use a link-local address (%s) as a GitLab server", addr.IP)
		}
	}
	if u.Scheme == "http" {
		for _, addr := range addrs {
			if !isPrivate(addr.IP) {
				return nil, fmt.Errorf("%w: %s resolves to the public address %s", ErrInsecureURL, host, addr.IP)
			}
		}
	}
	// Trim a trailing /api/v4 so both spellings of the URL work.
	u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/api/v4")
	u.RawPath = ""
	return u, nil
}

func isPrivate(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() {
		return true
	}
	return false
}

// apiURL builds an absolute URL for an API path, keeping any sub-path from the base.
func (c *Client) apiURL(path string) string {
	return c.base.String() + "/api/v4" + path
}

// do performs one API call. Every request has a timeout, a token header, and a log line
// that records the method, path, status and duration — never the token or the body.
func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.apiURL(path), reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}
	start := time.Now()
	res, err := c.http.Do(req)
	if err != nil {
		c.log.Warn("gitlab request failed", "method", method, "path", path,
			"duration_ms", time.Since(start).Milliseconds(), "err", redactError(err))
		return fmt.Errorf("%w: %s", ErrUnreachable, redactError(err))
	}
	defer res.Body.Close()
	// Cap the body: a proxy error page must not be able to exhaust memory.
	payload, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("%w: reading the response failed", ErrUnreachable)
	}
	c.log.Debug("gitlab request", "method", method, "path", path, "status", res.StatusCode,
		"duration_ms", time.Since(start).Milliseconds())

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return classify(res.StatusCode, payload)
	}
	if out != nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, out); err != nil {
			return fmt.Errorf("GitLab returned a response this client cannot read: %w", err)
		}
	}
	return nil
}

// classify maps GitLab's status and message onto the sentinels the API reports.
func classify(status int, payload []byte) error {
	msg := gitlabMessage(payload)
	apiErr := &APIError{Status: status, Message: msg}
	switch status {
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: %w", ErrUnauthorized, apiErr)
	case http.StatusForbidden:
		return fmt.Errorf("%w: %w", ErrForbidden, apiErr)
	case http.StatusNotFound:
		return fmt.Errorf("%w: %w", ErrProjectMissing, apiErr)
	default:
		return apiErr
	}
}

// gitlabMessage extracts GitLab's error text without echoing the request.
func gitlabMessage(payload []byte) string {
	var body struct {
		Message any    `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(payload, &body); err == nil {
		switch m := body.Message.(type) {
		case string:
			if m != "" {
				return truncate(m, 300)
			}
		case map[string]any:
			// {"message":{"title":["can't be blank"]}}
			parts := make([]string, 0, len(m))
			for k, v := range m {
				parts = append(parts, fmt.Sprintf("%s: %v", k, v))
			}
			return truncate(strings.Join(parts, "; "), 300)
		case []any:
			return truncate(fmt.Sprint(m), 300)
		}
		if body.Error != "" {
			return truncate(body.Error, 300)
		}
	}
	s := strings.TrimSpace(string(payload))
	if s == "" {
		return "no message"
	}
	return truncate(s, 300)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// redactError removes the token from transport errors, which can echo the request URL.
func redactError(err error) string {
	s := err.Error()
	if i := strings.Index(s, "PRIVATE-TOKEN"); i >= 0 {
		s = s[:i] + "PRIVATE-TOKEN=<redacted>"
	}
	return s
}

// Version returns the GitLab version string.
func (c *Client) Version(ctx context.Context) (string, string, error) {
	var out struct {
		Version  string `json:"version"`
		Revision string `json:"revision"`
	}
	if err := c.do(ctx, http.MethodGet, "/version", nil, &out); err != nil {
		return "", "", err
	}
	return out.Version, out.Revision, nil
}

// CurrentUser identifies the token, which is how "authenticated" is proven.
func (c *Client) CurrentUser(ctx context.Context) (User, error) {
	var out User
	err := c.do(ctx, http.MethodGet, "/user", nil, &out)
	return out, err
}

// Projects lists projects the token can see.
func (c *Client) Projects(ctx context.Context, search string, limit int) ([]Project, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	path := "/projects?membership=true&simple=true&order_by=path&sort=asc&per_page=" + strconv.Itoa(limit)
	if s := strings.TrimSpace(search); s != "" {
		path += "&search=" + url.QueryEscape(s)
	}
	var out []Project
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []Project{}
	}
	return out, nil
}

// Project fetches one project, which is also how the client checks that the token can
// see it and whether issues are enabled there.
func (c *Client) Project(ctx context.Context, id int) (Project, error) {
	var out Project
	err := c.do(ctx, http.MethodGet, "/projects/"+strconv.Itoa(id), nil, &out)
	return out, err
}

// CreateIssue opens an issue. This is the only write this integration performs.
func (c *Client) CreateIssue(ctx context.Context, projectID int, in IssueInput) (Issue, error) {
	if strings.TrimSpace(in.Title) == "" {
		return Issue{}, errors.New("an issue needs a title")
	}
	var out Issue
	err := c.do(ctx, http.MethodPost, "/projects/"+strconv.Itoa(projectID)+"/issues", in, &out)
	return out, err
}

// Issue reads one issue, for the manual "refresh status" action.
func (c *Client) Issue(ctx context.Context, projectID, iid int) (Issue, error) {
	var out Issue
	err := c.do(ctx, http.MethodGet, "/projects/"+strconv.Itoa(projectID)+"/issues/"+strconv.Itoa(iid), nil, &out)
	return out, err
}

// SearchIssues finds issues in a project by text. It is used to recover from a timeout:
// the description carries a marker, so a retry can adopt the issue GitLab already
// created instead of opening a second one.
func (c *Client) SearchIssues(ctx context.Context, projectID int, search string) ([]Issue, error) {
	path := "/projects/" + strconv.Itoa(projectID) + "/issues?scope=all&in=description&per_page=20&search=" +
		url.QueryEscape(search)
	var out []Issue
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// FindUser resolves a username to a GitLab account, used for the default assignee.
func (c *Client) FindUser(ctx context.Context, username string) (User, error) {
	username = strings.TrimSpace(strings.TrimPrefix(username, "@"))
	if username == "" {
		return User{}, errors.New("no username given")
	}
	var out []User
	if err := c.do(ctx, http.MethodGet, "/users?username="+url.QueryEscape(username), nil, &out); err != nil {
		return User{}, err
	}
	if len(out) == 0 {
		return User{}, fmt.Errorf("no GitLab user named %q is visible to this token", username)
	}
	return out[0], nil
}

// SearchUsers lists accounts the token can assign, for the ticket dialog's picker.
func (c *Client) SearchUsers(ctx context.Context, search string) ([]User, error) {
	path := "/users?per_page=25"
	if s := strings.TrimSpace(search); s != "" {
		path += "&search=" + url.QueryEscape(s)
	}
	var out []User
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []User{}
	}
	return out, nil
}

// UpdateIssue rewrites an existing issue's title and description.
//
// Used when a remediation action already has a ticket and a later assessment finds more CVEs it
// closes: updating the issue keeps one ticket per action instead of piling up duplicates.
func (c *Client) UpdateIssue(ctx context.Context, projectID, iid int, in IssueInput) (Issue, error) {
	var out Issue
	body := map[string]string{"title": in.Title, "description": in.Description}
	if in.Labels != "" {
		body["labels"] = in.Labels
	}
	err := c.do(ctx, http.MethodPut, "/projects/"+strconv.Itoa(projectID)+"/issues/"+strconv.Itoa(iid), body, &out)
	return out, err
}
