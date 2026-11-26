package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/remediate"
	"github.com/bgdnvk/clanker/internal/vuln/ticketing"
)

// GitLab ticketing.
//
// The finding stays the source of truth for evidence; the ticket is an outbound copy and
// a link. Everything that touches the token stays in this file and in the ticketing
// package: the token is never in a response, never in a log line, and never in a URL.

// gitlabSettings resolves the effective configuration: the 0600 file, overlaid with the
// deployment environment so a container can inject the token without writing it down.
func (s *Server) gitlabSettings() (ticketing.Settings, error) {
	path := s.opts.GitLabPath
	if strings.TrimSpace(path) == "" {
		path = ticketing.DefaultConfigPath()
	}
	file, err := ticketing.Load(path)
	if err != nil {
		// Running the server as a different user than owns the file is the most likely
		// cause, and the raw "permission denied" does not say what to do about it.
		return ticketing.Settings{}, fmt.Errorf("%w (the server must be able to read %s; "+
			"if the server was ever started as root, run `chown <server user> %s` and `chmod 600 %s`)",
			err, path, path, path)
	}
	return ticketing.WithEnv(file, s.getenv), nil
}

func (s *Server) gitlabPath() string {
	if p := strings.TrimSpace(s.opts.GitLabPath); p != "" {
		return p
	}
	return ticketing.DefaultConfigPath()
}

// gitlabClient builds a client from the saved settings, or reports why it cannot.
func (s *Server) gitlabClient(settings ticketing.Settings) (*ticketing.Client, error) {
	if !settings.Enabled {
		return nil, fmt.Errorf("%w: ticketing is disabled", ticketing.ErrNotConfigured)
	}
	if strings.TrimSpace(settings.URL) == "" {
		return nil, fmt.Errorf("%w: no GitLab server URL is set", ticketing.ErrNotConfigured)
	}
	if settings.Token == "" {
		return nil, fmt.Errorf("%w: no access token is set", ticketing.ErrNotConfigured)
	}
	return ticketing.NewClient(settings.ClientConfig(), s.log)
}

// gitlabTokenSource tells the operator where the credential came from without showing it.
func (s *Server) gitlabTokenSource() string {
	if ticketing.TokenFromEnv(s.getenv) {
		return "environment"
	}
	return "file"
}

// handleGitLabGet returns the integration state. The token is reported as a boolean.
func (s *Server) handleGitLabGet(w http.ResponseWriter, r *http.Request) {
	settings, err := s.gitlabSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "gitlab_config_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.gitlabView(settings))
}

func (s *Server) gitlabView(settings ticketing.Settings) map[string]any {
	ready := settings.Usable()
	reason := ""
	switch {
	case !settings.Enabled:
		reason = "GitLab ticketing is disabled."
	case strings.TrimSpace(settings.URL) == "":
		reason = "No GitLab server URL is configured."
	case settings.Token == "":
		reason = "No access token is configured."
	case settings.ProjectID <= 0:
		reason = "No destination project is selected."
	}
	return map[string]any{
		"enabled":             settings.Enabled,
		"url":                 settings.URL,
		"project_id":          settings.ProjectID,
		"labels":              settings.Labels,
		"assignee":            settings.Assignee,
		"timeout_seconds":     int(settings.Timeout().Seconds()),
		"allow_insecure_http": settings.AllowInsecureHTTP,
		// token_set is the only thing about the token that leaves the server.
		"token_set":    settings.Token != "",
		"token_source": s.gitlabTokenSource(),
		"ready":        ready,
		"blocked":      reason,
		"verified_at":  settings.VerifiedAt,
		"verify_ok":    settings.VerifyOK,
		"verify_note":  settings.VerifyDetail,
		"config_file":  s.gitlabPath(),
	}
}

// handleGitLabPut updates the integration configuration.
//
// A blank token field means "leave the stored one alone": the UI cannot show the token, so
// it cannot send it back, and requiring a re-entry on every save would push operators
// towards storing it somewhere worse.
func (s *Server) handleGitLabPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled           *bool     `json:"enabled"`
		URL               *string   `json:"url"`
		Token             *string   `json:"token"`
		ClearToken        bool      `json:"clear_token"`
		ProjectID         *int      `json:"project_id"`
		Labels            *[]string `json:"labels"`
		Assignee          *string   `json:"assignee"`
		TimeoutSeconds    *int      `json:"timeout_seconds"`
		AllowInsecureHTTP *bool     `json:"allow_insecure_http"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	settings, err := s.gitlabSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "gitlab_config_error", err.Error())
		return
	}
	if body.AllowInsecureHTTP != nil {
		settings.AllowInsecureHTTP = *body.AllowInsecureHTTP
	}
	if body.URL != nil {
		settings.URL = strings.TrimSpace(*body.URL)
	}
	if settings.URL != "" {
		if _, err := ticketing.ValidateBaseURL(settings.URL, settings.AllowInsecureHTTP); err != nil {
			writeError(w, http.StatusBadRequest, "gitlab_url_rejected", err.Error())
			return
		}
	}
	if body.Token != nil {
		token := strings.TrimSpace(*body.Token)
		if token != "" {
			settings.Token = token
		}
	}
	if body.ClearToken {
		settings.Token = ""
	}
	if body.ProjectID != nil {
		settings.ProjectID = *body.ProjectID
	}
	if body.Labels != nil {
		settings.Labels = cleanLabels(*body.Labels)
	}
	if body.Assignee != nil {
		settings.Assignee = strings.TrimSpace(strings.TrimPrefix(*body.Assignee, "@"))
	}
	if body.TimeoutSeconds != nil {
		if *body.TimeoutSeconds < 1 || *body.TimeoutSeconds > 60 {
			writeError(w, http.StatusBadRequest, "invalid_request", "timeout must be between 1 and 60 seconds")
			return
		}
		settings.TimeoutSeconds = *body.TimeoutSeconds
	}
	if body.Enabled != nil {
		settings.Enabled = *body.Enabled
	}
	// Saving new connection details invalidates the previous verification.
	if body.URL != nil || body.Token != nil || body.ProjectID != nil || body.AllowInsecureHTTP != nil || body.ClearToken {
		settings.VerifiedAt = nil
		settings.VerifyOK = false
		settings.VerifyDetail = ""
	}
	if err := ticketing.Save(s.gitlabPath(), settings); err != nil {
		writeError(w, http.StatusInternalServerError, "gitlab_config_error",
			"could not save the GitLab configuration: "+err.Error())
		return
	}
	s.audit(r, "gitlab.config", settings.URL,
		fmt.Sprintf("enabled=%t project=%d token_set=%t", settings.Enabled, settings.ProjectID, settings.Token != ""))
	s.log.Info("gitlab configuration updated", "enabled", settings.Enabled, "url", settings.URL,
		"project_id", settings.ProjectID, "token_set", settings.Token != "", "remote", s.clientIP(r))
	writeJSON(w, http.StatusOK, s.gitlabView(settings))
}

func cleanLabels(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, raw := range in {
		for _, l := range strings.Split(raw, ",") {
			l = strings.TrimSpace(l)
			if l == "" || seen[strings.ToLower(l)] {
				continue
			}
			seen[strings.ToLower(l)] = true
			out = append(out, l)
		}
	}
	return out
}

// handleGitLabTest runs the Test Connection checks.
//
// It accepts overrides so an operator can validate a token or URL before saving it; a
// token typed into the form should not have to be written to disk before it is proven.
func (s *Server) handleGitLabTest(w http.ResponseWriter, r *http.Request) {
	var over struct {
		URL               *string `json:"url"`
		Token             *string `json:"token"`
		ProjectID         *int    `json:"project_id"`
		AllowInsecureHTTP *bool   `json:"allow_insecure_http"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&over)
	}
	settings, err := s.gitlabSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "gitlab_config_error", err.Error())
		return
	}
	if over.URL != nil && strings.TrimSpace(*over.URL) != "" {
		settings.URL = strings.TrimSpace(*over.URL)
	}
	if over.Token != nil && strings.TrimSpace(*over.Token) != "" {
		settings.Token = strings.TrimSpace(*over.Token)
	}
	if over.ProjectID != nil {
		settings.ProjectID = *over.ProjectID
	}
	if over.AllowInsecureHTTP != nil {
		settings.AllowInsecureHTTP = *over.AllowInsecureHTTP
	}
	// The test is about connecting, so "enabled" must not be a precondition: an operator
	// configures first and switches ticketing on once it works.
	settings.Enabled = true

	client, err := s.gitlabClient(settings)
	if err != nil {
		writeJSON(w, http.StatusOK, ticketing.VerifyResult{
			OK:      false,
			Checks:  []ticketing.Check{{Name: "Configuration is complete", OK: false, Detail: err.Error()}},
			Summary: "The configuration is incomplete: " + strings.TrimPrefix(err.Error(), ticketing.ErrNotConfigured.Error()+": "),
		})
		return
	}
	res := client.Verify(r.Context(), settings.ProjectID)

	// Record the outcome, but only when the tested values are the saved ones.
	saved, _ := ticketing.Load(s.gitlabPath())
	saved = ticketing.WithEnv(saved, s.getenv)
	now := s.opts.Now().UTC()
	if saved.URL == settings.URL && saved.ProjectID == settings.ProjectID && saved.Token == settings.Token {
		saved.VerifiedAt = &now
		saved.VerifyOK = res.OK
		saved.VerifyDetail = res.Summary
		if err := ticketing.Save(s.gitlabPath(), saved); err != nil {
			s.log.Warn("could not record GitLab verification", "err", err)
		}
	}
	s.log.Info("gitlab connection test", "ok", res.OK, "version", res.Version,
		"can_create_issues", res.CanCreateIssues, "remote", s.clientIP(r))
	writeJSON(w, http.StatusOK, res)
}

// handleGitLabProjects lists candidate destination projects.
func (s *Server) handleGitLabProjects(w http.ResponseWriter, r *http.Request) {
	settings, err := s.gitlabSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "gitlab_config_error", err.Error())
		return
	}
	client, err := s.gitlabClient(settings)
	if err != nil {
		writeError(w, http.StatusConflict, "gitlab_not_configured", err.Error())
		return
	}
	projects, err := client.Projects(r.Context(), r.URL.Query().Get("search"), 50)
	if err != nil {
		writeError(w, gitlabStatus(err), "gitlab_error", humanGitLabError(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": projects, "total": len(projects)})
}

// handleGitLabUsers lists accounts that can be assigned issues.
func (s *Server) handleGitLabUsers(w http.ResponseWriter, r *http.Request) {
	settings, err := s.gitlabSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "gitlab_config_error", err.Error())
		return
	}
	client, err := s.gitlabClient(settings)
	if err != nil {
		writeError(w, http.StatusConflict, "gitlab_not_configured", err.Error())
		return
	}
	users, err := client.SearchUsers(r.Context(), r.URL.Query().Get("search"))
	if err != nil {
		writeError(w, gitlabStatus(err), "gitlab_error", humanGitLabError(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": users, "total": len(users)})
}

// gitlabFinding assembles the ticket content from the finding, its asset and its work item.
func (s *Server) gitlabFinding(host assetInfo, hostFallback string, row *vulnRow, item *remediate.Item) ticketing.Finding {
	f := ticketing.Finding{
		Asset:            row.Asset,
		Hostname:         firstNonEmpty(host.Hostname, hostFallback, row.Asset),
		OS:               host.OS,
		OSVersion:        host.OSVersion,
		Product:          row.Product,
		InstalledVersion: row.InstalledVersion,
		Ecosystem:        row.Ecosystem,
		VulnerabilityID:  row.CVE,
		Aliases:          row.Aliases,
		Severity:         row.Severity,
		CVSS:             row.CVSS,
		CVSSVector:       row.CVSSVector,
		EPSS:             row.EPSS,
		KEV:              row.KEV,
		Explanation:      row.Explanation,
		FixedVersion:     row.FixedVersion,
		RemediationText:  row.Remediation,
		ReportID:         row.ReportID,
		FirstSeen:        row.FirstSeen,
		LastSeen:         row.LastSeen,
	}
	for _, e := range row.Evidence {
		f.Evidence = append(f.Evidence, ticketing.Evidence{Kind: e.Kind, Source: e.Source, Detail: e.Detail, URL: e.URL})
	}
	for _, ref := range row.References {
		f.References = append(f.References, ticketing.Reference{Label: ref.Label, URL: ref.URL})
	}
	// The advisory text is what the scanner quoted; label where it came from rather than
	// passing it off as verified instructions.
	if strings.TrimSpace(row.Remediation) != "" {
		f.RemediationOrigin = "advisory"
		f.RemediationSource = firstNonEmpty(row.Source, row.AdvisoryID)
	}
	// Access details come from the asset's ownership record; the runbook from that record or
	// the organisation's template. Both are references only — no credentials.
	if own, err := s.remediate.Ownership(row.Asset); err == nil {
		f.Access = ticketing.AccessBlock{
			Host: row.Asset, SSHUser: own.SSHUser, SSHHost: own.SSHHost,
			SSHJump: own.SSHJump, SSHPort: own.SSHPort, Runbook: own.RunbookURL,
		}
	}
	if item != nil {
		f.FindingKey = item.FindingKey
		f.EffectiveSeverity = item.Severity
		f.Priority = item.Priority
		f.Team = item.Team
		f.Owner = item.Owner
		if item.DueAt != nil {
			f.DueAt = item.DueAt.UTC().Format("2006-01-02")
		}
	}
	// The key must exist even when the finding has no work item yet: it is the duplicate
	// guard, and it is derived exactly as remediation derives it.
	if f.FindingKey == "" {
		f.FindingKey = remediate.FindingKey(row.Asset, modelFindingFor(row))
	}
	f.Runbook = s.renderRunbook(f)
	return f
}

// renderRunbook expands the organisation's remediation template for this finding.
//
// The template is operator-authored markdown stored in settings; the placeholders are replaced
// with values from the finding, and unknown placeholders are left visible rather than dropped
// so a broken template is obvious in the preview instead of silently producing a hole.
func (s *Server) renderRunbook(f ticketing.Finding) string {
	raw := strings.TrimSpace(s.mustSettings()["runbook.template"])
	if raw == "" {
		return ""
	}
	pairs := [][2]string{
		{"{{asset}}", firstNonEmpty(f.Asset, f.Hostname)},
		{"{{hostname}}", firstNonEmpty(f.Hostname, f.Asset)},
		{"{{team}}", f.Team},
		{"{{owner}}", f.Owner},
		{"{{product}}", f.Product},
		{"{{installed_version}}", f.InstalledVersion},
		{"{{fixed_version}}", f.FixedVersion},
		{"{{cve}}", f.VulnerabilityID},
		{"{{severity}}", strings.ToUpper(firstNonEmpty(f.EffectiveSeverity, f.Severity))},
		{"{{ssh_command}}", f.Access.SSHCommand()},
		{"{{runbook_url}}", f.Access.Runbook},
	}
	out := raw
	for _, p := range pairs {
		out = strings.ReplaceAll(out, p[0], p[1])
	}
	return out
}

// handleGitLabPreview renders the issue body without contacting GitLab.
func (s *Server) handleGitLabPreview(w http.ResponseWriter, r *http.Request) {
	f, settings, ok := s.gitlabFindingFromRequest(w, r)
	if !ok {
		return
	}
	labels := ticketing.Labels(settings.Labels, f)
	plan, description := ticketing.Compose(f)
	writeJSON(w, http.StatusOK, map[string]any{
		"title":       ticketing.Title(f),
		"description": description,
		// The same plan the markdown came from, so the preview can render the work order
		// (system table, numbered steps, copy buttons) without re-parsing Markdown.
		"plan":        plan,
		"labels":      labels,
		"label_field": ticketing.LabelString(labels),
		"project_id":  settings.ProjectID,
		"finding_key": f.FindingKey,
	})
}

// gitlabFindingFromRequest resolves the {} body's finding_id into a Finding.
func (s *Server) gitlabFindingFromRequest(w http.ResponseWriter, r *http.Request) (ticketing.Finding, ticketing.Settings, bool) {
	var body struct {
		FindingID string `json:"finding_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return ticketing.Finding{}, ticketing.Settings{}, false
	}
	settings, err := s.gitlabSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "gitlab_config_error", err.Error())
		return ticketing.Finding{}, settings, false
	}
	ds, err := s.buildDataset(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dataset_error", err.Error())
		return ticketing.Finding{}, settings, false
	}
	row, ok := ds.ByID[strings.TrimSpace(body.FindingID)]
	if !ok {
		writeError(w, http.StatusNotFound, "finding_not_found", "no finding with that identifier in the stored assessments")
		return ticketing.Finding{}, settings, false
	}
	var (
		host     assetInfo
		fallback string
	)
	if hv, ok := ds.Hosts[row.Asset]; ok {
		host, fallback = hv.Asset, hv.Host
	}
	var item *remediate.Item
	if s.remediate != nil {
		if it, err := s.remediate.FindForFinding(r.Context(), row.Asset, row.CVE, row.Product, row.InstalledVersion); err == nil {
			item = it
		}
	}
	return s.gitlabFinding(host, fallback, row, item), settings, true
}

// handleGitLabCreateTicket is the primary action: create the issue in GitLab.
func (s *Server) handleGitLabCreateTicket(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FindingID   string   `json:"finding_id"`
		ProjectID   int      `json:"project_id"`
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Labels      []string `json:"labels"`
		AssigneeID  int      `json:"assignee_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	settings, err := s.gitlabSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "gitlab_config_error", err.Error())
		return
	}
	if !settings.Usable() {
		writeError(w, http.StatusConflict, "gitlab_not_configured",
			"GitLab ticketing is not ready: enable it in Settings → Integrations → GitLab and set a server, token and project")
		return
	}
	projectID := settings.ProjectID
	if body.ProjectID > 0 && body.ProjectID != settings.ProjectID {
		// Creating in a project other than the configured destination is allowed, but it
		// still has to be one the token can see.
		projectID = body.ProjectID
	}
	client, err := s.gitlabClient(settings)
	if err != nil {
		writeError(w, http.StatusConflict, "gitlab_not_configured", err.Error())
		return
	}

	ds, err := s.buildDataset(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dataset_error", err.Error())
		return
	}
	row, ok := ds.ByID[strings.TrimSpace(body.FindingID)]
	if !ok {
		writeError(w, http.StatusNotFound, "finding_not_found", "no finding with that identifier in the stored assessments")
		return
	}
	var (
		host     assetInfo
		fallback string
	)
	if hv, ok := ds.Hosts[row.Asset]; ok {
		host, fallback = hv.Asset, hv.Host
	}
	var item *remediate.Item
	if s.remediate != nil {
		if it, err := s.remediate.FindForFinding(r.Context(), row.Asset, row.CVE, row.Product, row.InstalledVersion); err == nil {
			item = it
		}
	}
	f := s.gitlabFinding(host, fallback, row, item)

	// Confirm the destination before creating anything: a project the token cannot see must
	// produce "project not found" rather than a rejected creation, and the issue message
	// should name the project the way a human refers to it.
	project, err := client.Project(r.Context(), projectID)
	if err != nil {
		writeError(w, gitlabStatus(err), "gitlab_error", humanGitLabError(err))
		return
	}

	labels := ticketing.Labels(settings.Labels, f)
	if len(body.Labels) > 0 {
		labels = ticketing.Labels(append(settings.Labels, body.Labels...), f)
	}
	plan, _ := ticketing.Compose(f)
	creator := &ticketing.Creator{
		Store:             s.tickets,
		RemediationStatus: string(plan.Status),
		Client:            client,
		ProjectID:         projectID,
		ProjectPath:       project.PathWithNamespace,
		Labels:            settings.Labels,
		CreatedBy:         s.actorName(r),
		AssigneeName:      settings.Assignee,
		Log:               s.log,
	}
	assigneeID := body.AssigneeID
	assigneeName := settings.Assignee
	if assigneeID <= 0 && settings.Assignee != "" {
		user, err := client.FindUser(r.Context(), settings.Assignee)
		if err != nil {
			writeError(w, http.StatusBadRequest, "gitlab_assignee_unknown",
				"the default assignee is not a GitLab account this token can see: "+err.Error())
			return
		}
		assigneeID, assigneeName = user.ID, user.Username
	}
	creator.AssigneeID = assigneeID
	creator.AssigneeName = assigneeName

	input := ticketing.IssueInput{
		Title:       strings.TrimSpace(body.Title),
		Description: body.Description,
		Labels:      ticketing.LabelString(labels),
	}
	if input.Title == "" {
		input.Title = ticketing.Title(f)
	}
	if strings.TrimSpace(input.Description) == "" {
		input.Description = ticketing.RenderDescription(f)
	}
	res, err := creator.Create(r.Context(), f, input)
	if err != nil {
		writeError(w, gitlabStatus(err), "gitlab_error", humanGitLabError(err))
		return
	}
	s.audit(r, "ticket.create", res.Ticket.ID,
		fmt.Sprintf("issue=#%d created=%t reused=%t asset=%s vuln=%s", res.Ticket.IssueIID, res.Created, res.Reused, f.Asset, f.VulnerabilityID))
	s.log.Info("gitlab ticket request completed", "ticket", res.Ticket.ID, "issue_iid", res.Ticket.IssueIID,
		"created", res.Created, "reused", res.Reused, "asset", f.Asset, "vulnerability", f.VulnerabilityID,
		"remote", s.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"ticket":  res.Ticket,
		"created": res.Created,
		"reused":  res.Reused,
		"message": res.Message,
	})
}

// handleGitLabTickets lists tracked tickets.
func (s *Server) handleGitLabTickets(w http.ResponseWriter, r *http.Request) {
	if s.tickets == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []ticketing.Ticket{}, "total": 0})
		return
	}
	if key := strings.TrimSpace(r.URL.Query().Get("finding_key")); key != "" {
		items, err := s.tickets.ForFinding(r.Context(), key)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "ticket_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
		return
	}
	items, err := s.tickets.List(r.Context(), 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ticket_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// handleGitLabTicketRefresh reads the issue state from GitLab.
func (s *Server) handleGitLabTicketRefresh(w http.ResponseWriter, r *http.Request) {
	if s.tickets == nil {
		writeError(w, http.StatusNotFound, "not_found", "no such ticket")
		return
	}
	settings, err := s.gitlabSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "gitlab_config_error", err.Error())
		return
	}
	client, err := s.gitlabClient(settings)
	if err != nil {
		writeError(w, http.StatusConflict, "gitlab_not_configured", err.Error())
		return
	}
	creator := &ticketing.Creator{Store: s.tickets, Client: client, ProjectID: settings.ProjectID, Log: s.log}
	t, err := creator.RefreshTicket(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ticketing.ErrTicketNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "no such ticket")
			return
		}
		writeError(w, gitlabStatus(err), "gitlab_error", humanGitLabError(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ticket": t})
}

// gitlabStatus maps a ticketing error onto the HTTP status the dashboard shows.
func gitlabStatus(err error) int {
	switch {
	case errors.Is(err, ticketing.ErrNotConfigured):
		return http.StatusConflict
	case errors.Is(err, ticketing.ErrUnauthorized), errors.Is(err, ticketing.ErrForbidden),
		errors.Is(err, ticketing.ErrProjectMissing):
		return http.StatusBadGateway
	case errors.Is(err, ticketing.ErrUnreachable):
		return http.StatusGatewayTimeout
	case errors.Is(err, ticketing.ErrTicketNotFound):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

// humanGitLabError is the message shown in the UI: actionable, without internals.
func humanGitLabError(err error) string {
	switch {
	case errors.Is(err, ticketing.ErrUnauthorized):
		return "GitLab rejected the access token. Update it in Settings → Integrations → GitLab."
	case errors.Is(err, ticketing.ErrForbidden):
		return "The access token is not allowed to create issues in that project. A Reporter role or higher is required on a private project."
	case errors.Is(err, ticketing.ErrProjectMissing):
		return "The GitLab project was not found, or the token cannot see it."
	case errors.Is(err, ticketing.ErrUnreachable):
		return "GitLab could not be reached from Clanker Guard. Check the server URL and that the instance is running."
	case errors.Is(err, ticketing.ErrInsecureURL):
		return err.Error()
	case errors.Is(err, ticketing.ErrNotConfigured):
		return strings.TrimPrefix(err.Error(), ticketing.ErrNotConfigured.Error()+": ")
	default:
		return err.Error()
	}
}

// actorName is who to attribute a ticket to.
func (s *Server) actorName(r *http.Request) string {
	if method, sess := s.authenticate(r); method == authViaCookie && sess.Username != "" {
		return sess.Username
	}
	return "api-token"
}

// ensureGitLabClient is used by handlers that only need a validated client.
func (s *Server) ensureGitLabClient(w http.ResponseWriter, r *http.Request) (*ticketing.Client, ticketing.Settings, bool) {
	settings, err := s.gitlabSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "gitlab_config_error", err.Error())
		return nil, settings, false
	}
	client, err := s.gitlabClient(settings)
	if err != nil {
		writeError(w, http.StatusConflict, "gitlab_not_configured", err.Error())
		return nil, settings, false
	}
	return client, settings, true
}

// modelFindingFor rebuilds the identity tuple the scanner uses, so a finding without a
// work item still gets the same stable key (and therefore the same duplicate guard).
func modelFindingFor(row *vulnRow) model.Finding {
	return model.Finding{
		Asset:            row.Asset,
		Ecosystem:        row.Ecosystem,
		Product:          row.Product,
		InstalledVersion: row.InstalledVersion,
		VulnerabilityID:  row.CVE,
	}
}

// handleGitLabCreateGroupTicket files one ticket for a remediation action (a Windows KB, or a
// product upgrade) instead of one per CVE.
//
// The individual findings stay exactly as they are: this endpoint only changes what goes into the
// tracker. A thousand CVEs behind one cumulative update become one actionable issue.
func (s *Server) handleGitLabCreateGroupTicket(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Asset   string `json:"asset"`
		Product string `json:"product"`
		Fixed   string `json:"fixed_version"`
		Project int    `json:"project_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	if strings.TrimSpace(body.Asset) == "" || strings.TrimSpace(body.Fixed) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "asset and fixed_version are required")
		return
	}
	settings, err := s.gitlabSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "gitlab_config_error", err.Error())
		return
	}
	if !settings.Usable() {
		writeError(w, http.StatusConflict, "gitlab_not_configured",
			"GitLab ticketing is not ready: enable it in Settings → Integrations → GitLab and set a server, token and project")
		return
	}
	projectID := settings.ProjectID
	if body.Project > 0 {
		projectID = body.Project
	}
	client, err := s.gitlabClient(settings)
	if err != nil {
		writeError(w, http.StatusConflict, "gitlab_not_configured", err.Error())
		return
	}
	project, err := client.Project(r.Context(), projectID)
	if err != nil {
		writeError(w, gitlabStatus(err), "gitlab_error", humanGitLabError(err))
		return
	}

	// Collect the open findings this action closes.
	items, err := s.remediate.List(r.Context(), remediate.Filter{Asset: body.Asset}, s.currentPolicy(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "remediation_error", err.Error())
		return
	}
	group := ticketing.Group{
		Asset: body.Asset, Product: body.Product, Fixed: body.Fixed,
		Action: body.Fixed, Kind: "package_upgrade",
	}
	if strings.HasPrefix(strings.ToUpper(body.Fixed), "KB") {
		group.Kind = "windows_update"
	}
	ds, dsErr := s.buildDataset(r.Context())
	kevByVuln := map[string]bool{}
	if dsErr == nil {
		for _, row := range ds.Vulns {
			if row.KEV {
				kevByVuln[row.Asset+"|"+row.CVE] = true
			}
		}
	}
	var reboot bool
	for _, it := range items {
		if it.State == remediate.StateResolved || it.State == remediate.StateRiskAccepted || it.State == remediate.StateFalsePositive {
			continue
		}
		if it.FixedVersion != body.Fixed || !strings.EqualFold(it.Product, body.Product) {
			continue
		}
		group.Findings = append(group.Findings, ticketing.Finding{
			VulnerabilityID: it.VulnerabilityID, Severity: it.Severity, EffectiveSeverity: it.Severity,
			Asset: it.Asset, Product: it.Product, FixedVersion: it.FixedVersion,
			KEV: kevByVuln[it.Asset+"|"+it.VulnerabilityID],
		})
		if it.State != "" {
			// Windows update findings carry the reboot note in their remediation text.
			if strings.Contains(strings.ToLower(it.Remediation), "restart is required") {
				reboot = true
			}
		}
	}
	if len(group.Findings) == 0 {
		writeError(w, http.StatusConflict, "nothing_to_close",
			"no open findings are closed by that action on this asset")
		return
	}
	group.Reboot = reboot
	if own, err := s.remediate.Ownership(body.Asset); err == nil {
		group.OS, group.OSVersion = "", ""
		group.Access = ticketing.AccessBlock{Host: body.Asset, SSHUser: own.SSHUser, SSHHost: own.SSHHost,
			SSHJump: own.SSHJump, SSHPort: own.SSHPort, Runbook: own.RunbookURL}
	}
	if hv, ok := ds.Hosts[body.Asset]; ok {
		group.Hostname = firstNonEmpty(hv.Asset.Hostname, body.Asset)
		group.OS, group.OSVersion = hv.Asset.OS, hv.Asset.OSVersion
		group.Installed = ""
	}
	for _, it := range items {
		if it.Product == body.Product && it.InstalledVersion != "" {
			group.Installed = it.InstalledVersion
			break
		}
	}

	creator := &ticketing.Creator{
		Store: s.tickets, Client: client, ProjectID: projectID, ProjectPath: project.PathWithNamespace,
		CreatedBy: s.actorName(r), Log: s.log,
	}
	if settings.Assignee != "" {
		if user, err := client.FindUser(r.Context(), settings.Assignee); err == nil {
			creator.AssigneeID, creator.AssigneeName = user.ID, user.Username
		}
	}
	res, err := creator.CreateGroup(r.Context(), group)
	if err != nil {
		writeError(w, gitlabStatus(err), "gitlab_error", humanGitLabError(err))
		return
	}
	s.audit(r, "ticket.group", firstNonEmpty(group.Action, group.Fixed),
		fmt.Sprintf("asset=%s action=%s cves=%d issue=#%d created=%t", group.Asset, group.Action, len(group.Findings), res.Ticket.IssueIID, res.Created))
	writeJSON(w, http.StatusOK, map[string]any{
		"ticket": res.Ticket, "created": res.Created, "reused": res.Reused,
		"message": res.Message, "cves": len(group.Findings),
	})
}
