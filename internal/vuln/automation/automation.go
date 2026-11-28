// Package automation implements the "Create Issues for Me" workflow.
//
// Three modes, one engine:
//
//	manual    — nothing happens; findings stay in the UI.
//	assisted  — drafts are prepared and returned for approval; nothing is created.
//	auto      — qualifying drafts are submitted to the configured GitLab project.
//
// The auto mode is opt-in, bounded per run, and refuses to publish a draft that the
// generator flagged for review. Automation that cannot stop itself is not automation,
// it is an incident waiting for a trigger.
package automation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/aihub"
	"github.com/bgdnvk/clanker/internal/configdir"
	"github.com/bgdnvk/clanker/internal/vuln/issuegen"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/ticketing"
)

// Mode is the automation level.
type Mode string

const (
	ModeManual   Mode = "manual"
	ModeAssisted Mode = "assisted"
	ModeAuto     Mode = "auto"
)

// Modes lists the valid values.
var Modes = []Mode{ModeManual, ModeAssisted, ModeAuto}

// ParseMode validates a mode, defaulting to manual.
func ParseMode(raw string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(raw))); m {
	case "":
		return ModeManual, nil
	case ModeManual, ModeAssisted, ModeAuto:
		return m, nil
	default:
		return "", fmt.Errorf("unknown mode %q (want manual, assisted or auto)", raw)
	}
}

// Config is the persisted policy for issue creation.
type Config struct {
	Mode         Mode     `json:"mode"`
	MinSeverity  string   `json:"min_severity"`
	MaxPerRun    int      `json:"max_per_run"`
	Labels       []string `json:"labels,omitempty"`
	Assignee     string   `json:"assignee,omitempty"`
	ReopenClosed bool     `json:"reopen_closed"`
	AutoSync     bool     `json:"auto_sync"`
	// UseAI lets the operator disable model-written drafts even when a model is configured.
	UseAI bool `json:"use_ai"`
	// ProjectID overrides the ticketing default destination.
	ProjectID int        `json:"project_id,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// DefaultConfig is deliberately conservative: manual, high and above, ten issues a run.
func DefaultConfig() Config {
	return Config{Mode: ModeManual, MinSeverity: "high", MaxPerRun: 10, UseAI: true}
}

// Normalize validates and fills defaults.
func (c Config) Normalize() (Config, error) {
	mode, err := ParseMode(string(c.Mode))
	if err != nil {
		return c, err
	}
	c.Mode = mode
	c.MinSeverity = strings.ToLower(strings.TrimSpace(c.MinSeverity))
	switch c.MinSeverity {
	case "", "critical", "high", "medium", "low":
		if c.MinSeverity == "" {
			c.MinSeverity = "high"
		}
	default:
		return c, fmt.Errorf("min_severity must be critical, high, medium or low")
	}
	if c.MaxPerRun <= 0 {
		c.MaxPerRun = 10
	}
	if c.MaxPerRun > 200 {
		c.MaxPerRun = 200
	}
	c.Assignee = strings.TrimSpace(c.Assignee)
	c.Labels = dedupe(c.Labels)
	return c, nil
}

// ------------------------------------------------------------------ store ---

// Store persists automation settings and the audit trail.
type Store struct{ dir string }

// DefaultDir is where automation settings and the audit trail live. It follows the same
// writability-first resolution as the AI store, because a container has no usable home directory.
func DefaultDir() string {
	if p := strings.TrimSpace(os.Getenv("CLANKER_AUTOMATION_DIR")); p != "" {
		return p
	}
	return configdir.Resolve("automation", "CLANKER_AUTOMATION_DIR")
}

// Open prepares the automation directory.
func Open(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		dir = DefaultDir()
	}
	if err := configdir.EnsureDir(dir); err != nil {
		return nil, fmt.Errorf("create automation dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

// Dir reports the storage location.
func (s *Store) Dir() string { return s.dir }

func (s *Store) configPath() string { return filepath.Join(s.dir, "config.json") }
func (s *Store) auditPath() string  { return filepath.Join(s.dir, "audit.jsonl") }

// LoadConfig reads the policy, returning defaults when nothing is saved.
func (s *Store) LoadConfig() (Config, error) {
	cfg := DefaultConfig()
	raw, err := os.ReadFile(s.configPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse automation config: %w", err)
	}
	return cfg.Normalize()
}

// SaveConfig writes the policy.
func (s *Store) SaveConfig(cfg Config) (Config, error) {
	cfg, err := cfg.Normalize()
	if err != nil {
		return cfg, err
	}
	now := time.Now().UTC()
	cfg.UpdatedAt = &now
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return cfg, err
	}
	if err := os.WriteFile(s.configPath(), append(raw, '\n'), 0o600); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// AuditEntry is one decision. It answers: what was created, why, by which model.
type AuditEntry struct {
	At         time.Time `json:"at"`
	Action     string    `json:"action"`
	Mode       string    `json:"mode"`
	FindingKey string    `json:"finding_key,omitempty"`
	CVE        string    `json:"cve,omitempty"`
	Asset      string    `json:"asset,omitempty"`
	Product    string    `json:"product,omitempty"`
	Severity   string    `json:"severity,omitempty"`
	Generator  string    `json:"generator,omitempty"`
	Provider   string    `json:"provider,omitempty"`
	Model      string    `json:"model,omitempty"`
	IssueIID   int       `json:"issue_iid,omitempty"`
	IssueURL   string    `json:"issue_url,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Actor      string    `json:"actor,omitempty"`
}

// Append writes one audit line. It is append-only on purpose: an audit trail that can be
// edited by the process it audits is not an audit trail.
func (s *Store) Append(e AuditEntry) error {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.auditPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(raw, '\n'))
	return err
}

// Audit returns the most recent entries, newest last, capped.
func (s *Store) Audit(limit int) ([]AuditEntry, error) {
	raw, err := os.ReadFile(s.auditPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if limit <= 0 || limit > len(lines) {
		limit = len(lines)
	}
	out := make([]AuditEntry, 0, limit)
	for _, line := range lines[len(lines)-limit:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue // a corrupt line must not hide the rest of the trail
		}
		out = append(out, e)
	}
	return out, nil
}

// ------------------------------------------------------------------ engine ---

// TicketCreator is the existing ticketing service. Reusing it means duplicate prevention,
// marker recovery and body rendering are not reimplemented here.
type TicketCreator interface {
	Create(ctx context.Context, f ticketing.Finding, input ticketing.IssueInput) (ticketing.CreateResult, error)
}

// Deps is everything the engine needs.
type Deps struct {
	Creator TicketCreator
	AI      *aihub.Inference
	// AISettings and Secret are used only when Config.UseAI is true and Creator exists.
	AISettings aihub.Settings
	Secret     string
	Store      *Store
	Logger     *slog.Logger
	Now        func() time.Time
}

// Result is one decision, returned to the caller and written to the audit trail.
type Result struct {
	FindingKey string          `json:"finding_key"`
	CVE        string          `json:"cve"`
	Asset      string          `json:"asset"`
	Product    string          `json:"product"`
	Severity   string          `json:"severity"`
	Action     string          `json:"action"`
	Reason     string          `json:"reason,omitempty"`
	IssueIID   int             `json:"issue_iid,omitempty"`
	IssueURL   string          `json:"issue_url,omitempty"`
	Draft      *issuegen.Draft `json:"draft,omitempty"`
	Title      string          `json:"title,omitempty"`
	Body       string          `json:"body,omitempty"`
}

// Engine runs the workflow.
type Engine struct {
	deps Deps
}

// New builds an engine.
func New(deps Deps) *Engine {
	if deps.Now == nil {
		deps.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Engine{deps: deps}
}

// severityRank orders severities for the threshold comparison.
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// Run evaluates a report against the policy.
//
// mode overrides the saved configuration so the UI can preview without changing settings.
func (e *Engine) Run(ctx context.Context, rep model.Report, cfg Config, modeOverride Mode) ([]Result, error) {
	normalized, err := cfg.Normalize()
	if err != nil {
		return nil, err
	}
	mode := normalized.Mode
	if modeOverride != "" {
		m, err := ParseMode(string(modeOverride))
		if err != nil {
			return nil, err
		}
		mode = m
	}
	if mode == ModeManual {
		return nil, nil
	}

	threshold := severityRank(normalized.MinSeverity)
	candidates := make([]model.Finding, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		if f.Affected == model.ApplicabilityNotAffected {
			continue
		}
		if severityRank(f.Severity) < threshold {
			continue
		}
		if strings.TrimSpace(f.VulnerabilityID) == "" || strings.TrimSpace(f.Asset) == "" {
			continue
		}
		candidates = append(candidates, f)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		ri, rj := severityRank(candidates[i].Severity), severityRank(candidates[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if candidates[i].CISAKEV != candidates[j].CISAKEV {
			return candidates[i].CISAKEV
		}
		return candidates[i].RiskScore > candidates[j].RiskScore
	})
	if len(candidates) > normalized.MaxPerRun {
		candidates = candidates[:normalized.MaxPerRun]
	}

	results := make([]Result, 0, len(candidates))
	for _, f := range candidates {
		results = append(results, e.evaluate(ctx, rep, f, normalized, mode))
	}
	return results, nil
}

// Preview generates a draft for one finding without creating anything.
func (e *Engine) Preview(ctx context.Context, f issuegen.Finding, cfg Config) (Result, error) {
	draft := e.draft(ctx, f, cfg)
	title, body := issuegen.Render(draft, f)
	return Result{
		FindingKey: f.FindingKey, CVE: f.VulnerabilityID, Asset: f.Asset,
		Product: f.Product, Severity: f.Severity, Action: "preview",
		Draft: &draft, Title: title, Body: body,
	}, nil
}

func (e *Engine) evaluate(ctx context.Context, rep model.Report, f model.Finding, cfg Config, mode Mode) Result {
	res := Result{
		FindingKey: findingKey(f), CVE: f.VulnerabilityID, Asset: f.Asset,
		Product: f.Product, Severity: f.Severity,
	}
	input := toIssueFinding(rep, f, cfg)
	genInput := ToGeneratorFinding(rep, f)

	draft := e.draft(ctx, genInput, cfg)
	title, body := issuegen.Render(draft, genInput)
	res.Draft = &draft
	res.Title = title
	res.Body = body

	// A flagged draft never reaches GitLab automatically. It goes back to a person.
	if draft.RequiresReview {
		res.Action = "needs_review"
		res.Reason = strings.Join(draft.ReviewReasons, "; ")
		e.audit(res, cfg, mode, "needs_review", res.Reason)
		return res
	}
	if mode == ModeAssisted {
		res.Action = "proposed"
		e.audit(res, cfg, mode, "proposed", "awaiting approval")
		return res
	}
	if e.deps.Creator == nil {
		res.Action = "unavailable"
		res.Reason = "GitLab ticketing is not configured"
		e.audit(res, cfg, mode, "unavailable", res.Reason)
		return res
	}

	created, err := e.deps.Creator.Create(ctx, input, ticketing.IssueInput{
		Title:       title,
		Description: body,
		Labels:      strings.Join(mergeLabels(cfg.Labels, draft.Labels), ","),
	})
	if err != nil {
		res.Action = "failed"
		res.Reason = err.Error()
		e.audit(res, cfg, mode, "failed", res.Reason)
		return res
	}
	res.IssueIID = created.Ticket.IssueIID
	res.IssueURL = created.Ticket.IssueURL
	if created.Reused {
		res.Action = "duplicate"
		res.Reason = created.Message
		e.audit(res, cfg, mode, "duplicate", res.Reason)
		return res
	}
	res.Action = "created"
	e.audit(res, cfg, mode, "created", "")
	return res
}

// draft produces an AI draft when allowed, and falls back to the deterministic one.
//
// The fallback is not a degraded mode: it is the same ticket minus prose, built entirely
// from scanner facts. A model outage must not stop a security team from filing work.
func (e *Engine) draft(ctx context.Context, f issuegen.Finding, cfg Config) issuegen.Draft {
	if cfg.UseAI && e.deps.AI != nil && strings.TrimSpace(e.deps.AISettings.Model) != "" {
		gen := issuegen.Generator{AI: e.deps.AI, Settings: e.deps.AISettings, Secret: e.deps.Secret, Now: e.deps.Now}
		if d, err := gen.Generate(ctx, f); err == nil {
			return d
		} else if e.deps.Logger != nil {
			e.deps.Logger.Warn("AI draft failed, using the deterministic draft", "err", err)
		}
	}
	return issuegen.Deterministic(f)
}

func (e *Engine) audit(res Result, cfg Config, mode Mode, action, reason string) {
	if e.deps.Store == nil {
		return
	}
	entry := AuditEntry{
		At: e.deps.Now(), Action: action, Mode: string(mode),
		FindingKey: res.FindingKey, CVE: res.CVE, Asset: res.Asset,
		Product: res.Product, Severity: res.Severity,
		IssueIID: res.IssueIID, IssueURL: res.IssueURL, Reason: reason,
		Actor: "automation",
	}
	if res.Draft != nil {
		entry.Generator = res.Draft.Generator
		entry.Provider = res.Draft.Provider
		entry.Model = res.Draft.Model
	}
	if err := e.deps.Store.Append(entry); err != nil && e.deps.Logger != nil {
		e.deps.Logger.Error("could not write the automation audit trail", "err", err)
	}
}

// ------------------------------------------------------------------ mapping ---

func findingKey(f model.Finding) string {
	return f.Asset + "|" + strings.ToLower(f.Product) + "|" + f.InstalledVersion + "|" + strings.ToUpper(f.VulnerabilityID)
}

// toIssueFinding maps a scan finding onto the generator input and the existing renderer.
func toIssueFinding(rep model.Report, f model.Finding, cfg Config) ticketing.Finding {
	key := findingKey(f)
	evidence := make([]ticketing.Evidence, 0, len(f.Evidence))
	for _, e := range f.Evidence {
		evidence = append(evidence, ticketing.Evidence{Kind: e.Kind, Source: e.Source, Detail: e.Detail})
	}
	var cvss *float64
	if f.CVSS != nil {
		v := f.CVSS.Score
		cvss = &v
	}
	var epss *float64
	if f.EPSS != nil {
		v := f.EPSS.Score
		epss = &v
	}
	return ticketing.Finding{
		FindingKey:        key,
		Asset:             f.Asset,
		Hostname:          rep.Metadata.Host,
		OS:                f.Ecosystem,
		Product:           f.Product,
		InstalledVersion:  f.InstalledVersion,
		Ecosystem:         f.Ecosystem,
		VulnerabilityID:   f.VulnerabilityID,
		Aliases:           f.Aliases,
		Severity:          f.Severity,
		EffectiveSeverity: f.Severity,
		CVSS:              cvss,
		CVSSVector:        cvssVector(f),
		EPSS:              epss,
		KEV:               f.CISAKEV,
		Explanation:       f.Explanation,
		RemediationText:   f.Remediation,
		RemediationSource: f.Source,
		FixedVersion:      f.FixedVersion,
		Evidence:          evidence,
		ReportID:          rep.ReportID,
		Priority:          cfg.MinSeverity,
	}
}

func cvssVector(f model.Finding) string {
	if f.CVSS == nil {
		return ""
	}
	return f.CVSS.Vector
}

// ToGeneratorFinding is the projection used by the generator and the preview endpoint.
func ToGeneratorFinding(rep model.Report, f model.Finding) issuegen.Finding {
	in := toIssueFinding(rep, f, Config{})
	ev := make([]string, 0, len(f.Evidence))
	for _, e := range f.Evidence {
		line := strings.TrimSpace(e.Kind + ": " + e.Detail)
		if line != "" {
			ev = append(ev, line)
		}
	}
	var cvss *float64
	if f.CVSS != nil {
		v := f.CVSS.Score
		cvss = &v
	}
	return issuegen.Finding{
		FindingKey: in.FindingKey, Asset: f.Asset, Hostname: rep.Metadata.Host,
		OS: f.Ecosystem, Product: f.Product, InstalledVersion: f.InstalledVersion,
		Ecosystem: f.Ecosystem, VulnerabilityID: f.VulnerabilityID, Aliases: f.Aliases,
		Severity: f.Severity, CVSS: cvss, KEV: f.CISAKEV, FixedVersion: f.FixedVersion,
		Explanation: f.Explanation, Evidence: ev, Team: in.Team, Owner: in.Owner,
	}
}

func mergeLabels(a, b []string) []string {
	out := append([]string{}, a...)
	out = append(out, b...)
	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		key := strings.ToLower(s)
		if s == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}
