// Package autofix turns a stored vulnerability finding into either a reviewable change
// or a documented verdict.
//
// The design is deliberately asymmetric:
//
//   - The model writes prose and, at most, a patch. It never picks a version, never
//     touches a protected file, never merges and never closes a ticket.
//   - The database writes versions. If a finding has a fixed_version, the upgrade is
//     deterministic and no model is consulted at all.
//   - The scanner is the only authority on whether something is fixed. A merge request
//     is evidence of work; a later assessment that stops reporting the finding is
//     evidence of remediation.
package autofix

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/remediate"
	"github.com/bgdnvk/clanker/internal/vuln/ticketing"
)

// Phase is one step of the remediation loop. Each one is useful on its own.
type Phase string

const (
	// PhaseTriage comments a verdict on findings that have no upstream fix. It never
	// writes to a repository.
	PhaseTriage Phase = "triage"
	// PhaseUpgrade opens a merge request that moves a package to its fixed version.
	// Deterministic: it does not call a model.
	PhaseUpgrade Phase = "upgrade"
	// PhaseInvestigate produces an evidence-backed applicability verdict for findings
	// the scanner could not resolve on its own.
	PhaseInvestigate Phase = "investigate"
	// PhasePatch asks the model for a file-level fix (config or code) and opens it as a
	// draft merge request, strictly validated.
	PhasePatch Phase = "patch"
	// PhaseVerify closes the loop: a finding absent from a later report resolves the
	// work item, and the absence — not the merge — is the receipt.
	PhaseVerify Phase = "verify"
	// PhaseAll runs every phase in that order.
	PhaseAll Phase = "all"
)

// AllPhases is the closed set, in pipeline order.
var AllPhases = []Phase{PhaseTriage, PhaseUpgrade, PhaseInvestigate, PhasePatch, PhaseVerify}

// ParsePhase validates a phase name, accepting "all" and "".
func ParsePhase(raw string) (Phase, error) {
	switch p := Phase(strings.ToLower(strings.TrimSpace(raw))); p {
	case "", PhaseAll:
		return PhaseAll, nil
	case PhaseTriage, PhaseUpgrade, PhaseInvestigate, PhasePatch, PhaseVerify:
		return p, nil
	default:
		return "", fmt.Errorf("unknown phase %q (want one of triage, upgrade, investigate, patch, verify, all)", raw)
	}
}

// Class is what the deterministic classifier decides about a finding.
type Class string

const (
	// ClassSkip means the finding is not actionable: not affected, already suppressed,
	// or an advisory the scanner discounted.
	ClassSkip Class = "skip"
	// ClassUpgrade means a fixed version exists, so the remedy is known.
	ClassUpgrade Class = "upgrade"
	// ClassTriage means no fixed version is known and a human or model verdict is
	// needed before anything is changed.
	ClassTriage Class = "triage"
)

// DefaultAllowPaths is the set of files an automated fix may touch.
//
// It is an allow-list, not a deny-list, and it exists for one reason: a bot that can
// edit .gitlab-ci.yml with a project token can exfiltrate every variable in the project.
// If a fix needs a file that is not here, a person makes the change.
var DefaultAllowPaths = []string{
	"requirements.txt",
	"requirements-dev.txt",
	"requirements-test.txt",
	"constraints.txt",
	"pyproject.toml",
	"Pipfile",
	"poetry.lock",
	"setup.py",
	"setup.cfg",
	"package.json",
	"package-lock.json",
	"yarn.lock",
	"pnpm-lock.yaml",
	"go.mod",
	"go.sum",
	"Gemfile",
	"Gemfile.lock",
	"pom.xml",
	"build.gradle",
	"composer.json",
	"composer.lock",
	"Dockerfile",
	"Dockerfile.clankerbox",
	"Dockerfile.sre",
	"docker-compose.yml",
	"docker-compose.yaml",
	"nginx.conf",
	"redis.conf",
	"sshd_config",
	".clanker.yaml",
}

// Config is the runner configuration. Zero values are safe: a runner with no LLM does
// deterministic work only, and a runner with DryRun set writes nothing anywhere.
type Config struct {
	Phase Phase
	// ProjectID is the GitLab project that receives branches and merge requests.
	ProjectID int
	// TargetBranch is what fix branches are cut from and merge into.
	TargetBranch string
	// DryRun computes every decision and reports it without writing to GitLab or the
	// workflow store. It is the default when neither is configured explicitly.
	DryRun bool
	// Limit caps how many findings one phase handles in a run.
	Limit int
	// AllowPaths restricts writable files; empty means DefaultAllowPaths.
	AllowPaths []string
	// MaxPatchBytes caps the size of a single generated file.
	MaxPatchBytes int
	// ApplyVerdicts lets a triage verdict move a work item to a terminal state
	// (false_positive, risk_accepted). Off by default: automated conclusions are
	// comments until a person agrees.
	ApplyVerdicts bool
	// AcceptedBy is recorded on a risk acceptance the model proposed.
	AcceptedBy string
	// ContextFiles are repository paths whose content is offered to the model for
	// applicability questions (for example a Dockerfile and the service config).
	ContextFiles []string
	// Labels are added to every merge request opened by this package.
	Labels []string
	// LLM is optional. When nil, only deterministic phases do work.
	LLM LLM
	// Now is injectable for tests.
	Now func() time.Time
	// Logger is optional; a discard logger is used when nil.
	Logger *slog.Logger
}

func (c Config) allowPaths() []string {
	if len(c.AllowPaths) > 0 {
		return c.AllowPaths
	}
	return DefaultAllowPaths
}

func (c Config) targetBranch() string {
	if strings.TrimSpace(c.TargetBranch) != "" {
		return strings.TrimSpace(c.TargetBranch)
	}
	return "main"
}

func (c Config) maxPatchBytes() int {
	if c.MaxPatchBytes > 0 {
		return c.MaxPatchBytes
	}
	return 200 << 10 // 200 KiB per file
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Config) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// Tracker is the GitLab write surface. It is an interface so the runner can be tested
// without a GitLab instance, and so a future tracker (GitHub, Forgejo) needs no rewrite.
type Tracker interface {
	SearchIssues(ctx context.Context, projectID int, search string) ([]ticketing.Issue, error)
	CreateNote(ctx context.Context, projectID, iid int, body string) (ticketing.Note, error)
	BranchExists(ctx context.Context, projectID int, name string) (bool, error)
	CreateBranch(ctx context.Context, projectID int, name, ref string) (ticketing.Branch, error)
	CommitFiles(ctx context.Context, projectID int, branch, message string, actions []ticketing.FileAction) (string, error)
	CreateMergeRequest(ctx context.Context, projectID int, in ticketing.MergeRequestInput) (ticketing.MergeRequest, error)
	MergeRequestsFor(ctx context.Context, projectID int, sourceBranch string) ([]ticketing.MergeRequest, error)
	FileContent(ctx context.Context, projectID int, filePath, ref string) ([]byte, error)
}

// Workflow is the subset of the remediation store this package uses. Keeping it narrow
// means the runner cannot invent workflow transitions the store does not allow.
type Workflow interface {
	FindForFinding(ctx context.Context, asset, vulnerabilityID, product, version string) (*remediate.Item, error)
	Update(ctx context.Context, id string, patch remediate.Patch) (remediate.Item, error)
	AcceptRisk(ctx context.Context, id, reason, acceptedBy string, until time.Time) (remediate.Item, error)
	MarkVerified(ctx context.Context, id, reportID string) (remediate.Item, error)
	List(ctx context.Context, f remediate.Filter, policy remediate.Policy) ([]remediate.Item, error)
}

// LLM is the only model seam. Implementations must be side-effect free and must not
// receive secrets; the runner never sends issue bodies, only structured findings.
type LLM interface {
	Complete(ctx context.Context, system, user string) (string, error)
}

// Verdict is the model's answer to "does this finding actually apply here?".
type Verdict struct {
	// Kind is one of not_applicable, mitigated, exposed, uncertain.
	Kind        string   `json:"verdict"`
	Rationale   string   `json:"rationale"`
	Evidence    []string `json:"evidence"`
	Control     string   `json:"compensating_control,omitempty"`
	ExpiresDays int      `json:"expires_in_days,omitempty"`
	Confidence  string   `json:"confidence,omitempty"`
}

// Verdict kinds.
const (
	VerdictNotApplicable = "not_applicable"
	VerdictMitigated     = "mitigated"
	VerdictExposed       = "exposed"
	VerdictUncertain     = "uncertain"
)

// FileChange is one file the model wants to write.
type FileChange struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// PatchProposal is the model's answer to "how would you fix this in the repository?".
type PatchProposal struct {
	Rationale string       `json:"rationale"`
	Files     []FileChange `json:"files"`
	Tests     []string     `json:"tests,omitempty"`
	Risk      string       `json:"risk,omitempty"`
	Rollback  string       `json:"rollback,omitempty"`
}

// Result is one decision the runner made. It is the audit line: every run produces one
// per finding, whether or not anything was written.
type Result struct {
	Phase     Phase  `json:"phase"`
	FindingID string `json:"finding_id"`
	StableID  string `json:"stable_id,omitempty"`
	VulnID    string `json:"vulnerability_id,omitempty"`
	Product   string `json:"product,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Class     Class  `json:"class,omitempty"`
	// Action is what happened: noted, verdict, mr_opened, skipped, rejected, verified.
	Action string `json:"action"`
	// Detail is a one-line human summary.
	Detail string `json:"detail,omitempty"`
	// Branch, MRURL and NoteURL point at what was written, when something was.
	Branch  string `json:"branch,omitempty"`
	MRURL   string `json:"mr_url,omitempty"`
	NoteURL string `json:"note_url,omitempty"`
	// Rejected carries the validation failure that stopped a write.
	Rejected string `json:"rejected,omitempty"`
}

// ErrNoProject means a write phase was requested without a destination project.
var ErrNoProject = errors.New("no GitLab project configured: set project_id or --project before running a write phase")

// Run dispatches to the configured phase.
func (r *Runner) Run(ctx context.Context, rep model.Report) ([]Result, error) {
	switch r.cfg.Phase {
	case PhaseTriage:
		return r.Triage(ctx, rep)
	case PhaseUpgrade:
		return r.Upgrade(ctx, rep)
	case PhaseInvestigate:
		return r.Investigate(ctx, rep)
	case PhasePatch:
		return r.Patch(ctx, rep)
	case PhaseVerify:
		return r.Verify(ctx, rep)
	case PhaseAll, "":
		var all []Result
		for _, fn := range []func(context.Context, model.Report) ([]Result, error){
			r.Triage, r.Upgrade, r.Investigate, r.Patch, r.Verify,
		} {
			res, err := fn(ctx, rep)
			all = append(all, res...)
			if err != nil {
				return all, fmt.Errorf("phase %s: %w", r.cfg.Phase, err)
			}
		}
		return all, nil
	default:
		return nil, fmt.Errorf("unknown phase %q", r.cfg.Phase)
	}
}
