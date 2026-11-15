package ticketing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Settings is the GitLab integration configuration.
//
// It lives in its own 0600 file rather than in the settings table because it holds an
// access token: the settings table is served verbatim by /api/settings, and a secret that
// is one refactor away from an API response is a secret that will leak.
type Settings struct {
	Enabled   bool   `json:"enabled"`
	URL       string `json:"url"`
	Token     string `json:"token,omitempty"`
	ProjectID int    `json:"project_id,omitempty"`
	// Labels are added to every issue. Severity and KEV labels are added automatically.
	Labels []string `json:"labels,omitempty"`
	// Assignee is a GitLab username, resolved to an id at creation time when possible.
	Assignee          string     `json:"assignee,omitempty"`
	TimeoutSeconds    int        `json:"timeout_seconds,omitempty"`
	AllowInsecureHTTP bool       `json:"allow_insecure_http,omitempty"`
	VerifiedAt        *time.Time `json:"verified_at,omitempty"`
	VerifyOK          bool       `json:"verify_ok,omitempty"`
	VerifyDetail      string     `json:"verify_detail,omitempty"`
}

// DefaultConfigPath mirrors the auth file convention: a per-user file outside the scan
// cache, so clearing the cache never drops the integration.
func DefaultConfigPath() string {
	if p := strings.TrimSpace(os.Getenv("CLANKER_GUARD_GITLAB_FILE")); p != "" {
		return p
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "clanker-guard", "gitlab.json")
	}
	return filepath.Join(".", ".clanker-gitlab.json")
}

// Load reads the configuration. A missing file is not an error: it means "not
// configured", and the UI has to be able to say that.
func Load(path string) (Settings, error) {
	var s Settings
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return s, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("GitLab configuration at %s is not valid JSON: %w", path, err)
	}
	return s, nil
}

// Save writes the configuration atomically with 0600 permissions: it contains a token.
func Save(path string, s Settings) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	// Create with the final mode directly, so the token is never briefly world-readable.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// WithEnv overlays deployment environment variables, which take precedence over the file
// so a container can be configured without writing a token to disk at all.
func WithEnv(s Settings, getenv func(string) string) Settings {
	if getenv == nil {
		return s
	}
	if v := strings.TrimSpace(getenv("GITLAB_ENABLED")); v != "" {
		s.Enabled = v == "true" || v == "1" || v == "yes"
	}
	if v := strings.TrimSpace(getenv("GITLAB_URL")); v != "" {
		s.URL = v
	} else if v := strings.TrimSpace(getenv("GITLAB_API_URL")); v != "" {
		s.URL = strings.TrimSuffix(strings.TrimSuffix(v, "/"), "/api/v4")
	}
	if v := strings.TrimSpace(getenv("GITLAB_TOKEN")); v != "" {
		s.Token = v
	}
	if v := strings.TrimSpace(getenv("GITLAB_PROJECT_ID")); v != "" {
		if id, err := strconv.Atoi(v); err == nil {
			s.ProjectID = id
		}
	}
	if v := strings.TrimSpace(getenv("GITLAB_TIMEOUT_SECONDS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			s.TimeoutSeconds = n
		}
	}
	if v := strings.TrimSpace(getenv("GITLAB_ALLOW_INSECURE_HTTP")); v != "" {
		s.AllowInsecureHTTP = v == "true" || v == "1" || v == "yes"
	}
	return s
}

// TokenFromEnv reports whether the env supplied the token, so the UI can say where the
// credential comes from without ever showing it.
func TokenFromEnv(getenv func(string) string) bool {
	if getenv == nil {
		return false
	}
	return strings.TrimSpace(getenv("GITLAB_TOKEN")) != ""
}

// ClientConfig converts the settings into what the client needs.
func (s Settings) ClientConfig() Config {
	return Config{
		BaseURL:           s.URL,
		Token:             s.Token,
		ProjectID:         s.ProjectID,
		Timeout:           s.Timeout(),
		AllowInsecureHTTP: s.AllowInsecureHTTP,
	}
}

// Timeout is the request timeout, defaulting to 15 seconds.
func (s Settings) Timeout() time.Duration {
	if s.TimeoutSeconds <= 0 {
		return DefaultTimeout
	}
	if s.TimeoutSeconds > 60 {
		return time.Minute
	}
	return time.Duration(s.TimeoutSeconds) * time.Second
}

// Usable reports whether issues can be created: enabled, with a server, a token and a
// destination project.
func (s Settings) Usable() bool {
	return s.Enabled && strings.TrimSpace(s.URL) != "" && s.Token != "" && s.ProjectID > 0
}

// Check is one step of the connection test.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	// Warning marks a step that passed but with something the operator should read,
	// such as "access level looks low for issue creation".
	Warning bool `json:"warning,omitempty"`
}

// VerifyResult is the outcome of Test Connection.
type VerifyResult struct {
	OK      bool     `json:"ok"`
	Checks  []Check  `json:"checks"`
	Version string   `json:"version,omitempty"`
	User    string   `json:"user,omitempty"`
	Project *Project `json:"project,omitempty"`
	// CanCreateIssues is a permission check, not a creation test. The API reports it as
	// such so nobody reads a green tick as "a ticket was successfully created".
	CanCreateIssues bool   `json:"can_create_issues"`
	Summary         string `json:"summary"`
}

// Verify runs the checks behind the Test Connection button.
//
// It never creates anything: it reads the version, the token's own user, and the target
// project, then reasons about permissions. Live issue creation is proven by creating an
// issue, which the UI reports separately.
func (c *Client) Verify(ctx context.Context, projectID int) VerifyResult {
	res := VerifyResult{Checks: []Check{}}
	fail := func(name string, err error) VerifyResult {
		res.Checks = append(res.Checks, Check{Name: name, OK: false, Detail: humanError(err)})
		res.OK = false
		res.Summary = summaryFor(err)
		return res
	}

	version, _, err := c.Version(ctx)
	if err != nil {
		return fail("Server reachable and authenticated", err)
	}
	res.Version = version
	res.Checks = append(res.Checks, Check{Name: "Server reachable and authenticated",
		OK: true, Detail: "GitLab " + version})

	user, err := c.CurrentUser(ctx)
	if err != nil {
		return fail("Access token identifies a user", err)
	}
	res.User = user.Username
	res.Checks = append(res.Checks, Check{Name: "Access token identifies a user", OK: true,
		Detail: "@" + user.Username})

	if projectID <= 0 {
		res.Checks = append(res.Checks, Check{Name: "Project selected", OK: false,
			Detail: "no project configured yet"})
		res.Summary = "Choose a destination project to finish setup."
		return res
	}
	project, err := c.Project(ctx, projectID)
	if err != nil {
		return fail("Destination project is readable", err)
	}
	res.Project = &project
	res.Checks = append(res.Checks, Check{Name: "Destination project is readable", OK: true,
		Detail: project.PathWithNamespace})

	if !project.IssuesEnabled {
		res.Checks = append(res.Checks, Check{Name: "Issues are enabled in the project", OK: false,
			Detail: "issues are disabled for this project; enable them or choose another project"})
		res.Summary = "Issues are disabled in that project."
		return res
	}
	res.Checks = append(res.Checks, Check{Name: "Issues are enabled in the project", OK: true})

	// GitLab access levels: 20 Reporter can create issues in private projects; 10 Guest
	// normally cannot. 0 means the instance did not report a level, which is not a
	// failure, only something to say out loud.
	switch level := project.AccessLevel(); {
	case level == 0:
		res.Checks = append(res.Checks, Check{Name: "Token may create issues", OK: true, Warning: true,
			Detail: "GitLab did not report an access level for this token; issue creation itself is unproven until a ticket is created"})
		res.CanCreateIssues = true
	case level >= 20:
		res.Checks = append(res.Checks, Check{Name: "Token may create issues", OK: true,
			Detail: fmt.Sprintf("access level %d in %s", level, project.PathWithNamespace)})
		res.CanCreateIssues = true
	default:
		res.Checks = append(res.Checks, Check{Name: "Token may create issues", OK: false,
			Detail: fmt.Sprintf("access level %d is too low; a Reporter role (20) or higher is needed on a private project", level)})
		res.OK = false
		res.Summary = "The token can read the project but cannot create issues there."
		return res
	}

	res.OK = true
	res.Summary = "Connected and authenticated. Permissions look sufficient; no issue was created."
	return res
}

// humanError turns an internal error into a sentence an operator can act on.
func humanError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrUnauthorized):
		return "invalid or expired access token (401)"
	case errors.Is(err, ErrForbidden):
		return "the token is not allowed to do this (403)"
	case errors.Is(err, ErrProjectMissing):
		return "project not found, or the token cannot see it (404)"
	case errors.Is(err, ErrUnreachable):
		return "the GitLab server could not be reached: " + trimPrefixAll(err.Error())
	case errors.Is(err, ErrInsecureURL):
		return trimPrefixAll(err.Error())
	default:
		return trimPrefixAll(err.Error())
	}
}

// summaryFor is the one-line headline under a failed test.
func summaryFor(err error) string {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return "Connected, but the access token was rejected."
	case errors.Is(err, ErrForbidden):
		return "Connected and authenticated, but the token is not allowed to do this."
	case errors.Is(err, ErrProjectMissing):
		return "Connected and authenticated, but that project was not found."
	case errors.Is(err, ErrUnreachable):
		return "The GitLab server could not be reached from Clanker Guard."
	default:
		return "The connection test failed: " + trimPrefixAll(err.Error())
	}
}

func trimPrefixAll(s string) string {
	s = strings.TrimSpace(s)
	for _, prefix := range []string{
		ErrUnreachable.Error() + ": ",
		ErrUnauthorized.Error() + ": ",
		ErrForbidden.Error() + ": ",
		ErrProjectMissing.Error() + ": ",
		errInsecurePrefix,
	} {
		s = strings.TrimPrefix(s, prefix)
	}
	return s
}

const errInsecurePrefix = "refusing to send an access token over plain HTTP to that host: "
