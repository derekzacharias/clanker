package autofix

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/remediate"
	"github.com/bgdnvk/clanker/internal/vuln/ticketing"
)

// Runner executes the remediation phases. It holds no state between runs: idempotency
// comes from GitLab (branch and MR names derived from the finding id) and from the
// workflow store, not from memory.
type Runner struct {
	cfg Config
	tr  Tracker
	wf  Workflow
}

// New builds a runner. A nil tracker or workflow is allowed at construction time so
// dry-run and classification use cases do not need them, but any phase that writes will
// fail loudly rather than silently skipping.
func New(cfg Config, tr Tracker, wf Workflow) *Runner {
	return &Runner{cfg: cfg, tr: tr, wf: wf}
}

// ------------------------------------------------------------------ helpers ---

func findingKey(f model.Finding) string { return remediate.FindingKey(f.Asset, f) }

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// actionable filters, ranks and caps the findings for one phase.
func actionable(findings []model.Finding, want Class, limit int) []model.Finding {
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if Classify(f) == want {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return Priority(out[i]) > Priority(out[j]) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (r *Runner) requireTracker() error {
	if r.tr == nil {
		return fmt.Errorf("no GitLab tracker configured: set the integration up or pass --gitlab-config")
	}
	if r.cfg.ProjectID <= 0 {
		return ErrNoProject
	}
	return nil
}

// trackerReady reports whether writes are possible at all.
func (r *Runner) trackerReady() bool { return r.tr != nil && r.cfg.ProjectID > 0 }

// preview renders what a phase would do when there is nowhere to write yet.
//
// A dry run that fails because GitLab is not configured is useless: the point of a dry
// run is to see the decisions first. This keeps the offline path honest by naming the
// action that was NOT taken.
func preview(findings []model.Finding, phase Phase, describe func(model.Finding) string) []Result {
	out := make([]Result, 0, len(findings))
	for _, f := range findings {
		detail := "would run this phase"
		if describe != nil {
			detail = describe(f)
		}
		out = append(out, Result{
			Phase: phase, FindingID: f.FindingID, StableID: f.StableID,
			VulnID: f.VulnerabilityID, Product: f.Product, Severity: f.Severity,
			Class:  Classify(f),
			Action: "dry_run",
			Detail: detail + " (no GitLab configured)",
		})
	}
	return out
}

// issue finds the ticket that carries this finding's marker.
//
// Search is fuzzy, so the result is filtered on the exact marker: adopting the wrong
// ticket is worse than not finding one.
func (r *Runner) issue(ctx context.Context, f model.Finding) (*ticketing.Issue, error) {
	key := findingKey(f)
	found, err := r.tr.SearchIssues(ctx, r.cfg.ProjectID, ticketing.MarkerSearch(key))
	if err != nil {
		return nil, err
	}
	marker := ticketing.Marker(key)
	for i := range found {
		if strings.Contains(found[i].Description, marker) {
			return &found[i], nil
		}
	}
	return nil, nil
}

// note posts a comment unless this is a dry run. It returns the URL when one exists.
func (r *Runner) note(ctx context.Context, issue *ticketing.Issue, body string) (string, error) {
	if r.cfg.DryRun {
		return "", nil
	}
	n, err := r.tr.CreateNote(ctx, r.cfg.ProjectID, issue.IID, body)
	if err != nil {
		return "", err
	}
	if issue.WebURL == "" {
		return "", nil
	}
	return issue.WebURL + "#note_" + strconv.Itoa(n.ID), nil
}

// fetchContext reads the configured repository excerpts. Missing files are ignored: a
// context file that does not exist is a configuration opinion, not an error.
func (r *Runner) fetchContext(ctx context.Context) map[string]string {
	out := make(map[string]string, len(r.cfg.ContextFiles))
	const perFile = 16 << 10
	for _, name := range r.cfg.ContextFiles {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		raw, err := r.tr.FileContent(ctx, r.cfg.ProjectID, name, r.cfg.targetBranch())
		if err != nil {
			r.cfg.logger().Debug("context file unavailable", "path", name, "err", err)
			continue
		}
		if len(raw) > perFile {
			raw = raw[:perFile]
		}
		out[name] = string(raw)
	}
	return out
}

func (r *Runner) branchName(f model.Finding) string {
	id := strings.ToLower(f.FindingID)
	if id == "" {
		id = strings.ToLower(f.StableID)
	}
	if id == "" {
		id = "unknown"
	}
	var b strings.Builder
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			b.WriteRune(c)
		default:
			b.WriteByte('-')
		}
	}
	return "secfix/" + strings.Trim(b.String(), "-")
}

func (r *Runner) labels() string {
	base := []string{"security", "automated"}
	base = append(base, r.cfg.Labels...)
	return strings.Join(base, ",")
}

// ------------------------------------------------------------------ P1 ---

// Triage comments a verdict on findings that have no published fix.
//
// It writes only comments. A verdict becomes a workflow state change only when
// ApplyVerdicts is set, because "the model says this does not apply" is a claim that a
// person has to be able to disagree with.
func (r *Runner) Triage(ctx context.Context, rep model.Report) ([]Result, error) {
	findings := actionable(rep.Findings, ClassTriage, r.cfg.Limit)
	if !r.trackerReady() {
		if !r.cfg.DryRun {
			return nil, r.requireTracker()
		}
		return preview(findings, PhaseTriage, func(model.Finding) string {
			return "would comment a triage verdict"
		}), nil
	}
	var out []Result
	for _, f := range findings {
		out = append(out, r.triageOne(ctx, f))
	}
	return out, nil
}

func (r *Runner) triageOne(ctx context.Context, f model.Finding) Result {
	res := Result{
		Phase: PhaseTriage, FindingID: f.FindingID, StableID: f.StableID,
		VulnID: f.VulnerabilityID, Product: f.Product, Severity: f.Severity, Class: ClassTriage,
	}

	issue, err := r.issue(ctx, f)
	if err != nil {
		res.Action = "error"
		res.Detail = "ticket lookup failed: " + err.Error()
		return res
	}
	if issue == nil {
		res.Action = "no_ticket"
		res.Detail = "no open ticket carries this finding's marker"
		return res
	}

	body := VerdictSummary(f)
	res.Action = "noted"
	res.Detail = "no model configured; posted the facts"

	if r.cfg.LLM != nil {
		files := map[string]string{}
		if r.tr != nil && r.cfg.ProjectID > 0 {
			files = r.fetchContext(ctx)
		}
		raw, err := r.cfg.LLM.Complete(ctx, triageSystemPrompt, triageUserPrompt(f, files))
		if err != nil {
			res.Detail = "model unavailable, posted the facts: " + firstLine(err.Error())
		} else if v, perr := ParseVerdict(raw); perr != nil {
			res.Detail = "model answer rejected, posted the facts: " + firstLine(perr.Error())
			body = VerdictSummary(f) + "\n\n_Model answer rejected: " + perr.Error() + "_\n"
		} else {
			body = verdictNote(f, v)
			res.Action = "verdict"
			res.Detail = v.Kind + " — " + firstLine(v.Rationale)
			if r.cfg.ApplyVerdicts {
				if detail := r.applyVerdict(ctx, f, v); detail != "" {
					res.Detail += " (" + detail + ")"
				}
			}
		}
	}

	if r.cfg.DryRun {
		res.Action = "dry_run"
		// Name the ticket: a preview that only says "would comment" cannot be checked
		// against the tracker before the operator turns writes on.
		if issue != nil && issue.IID > 0 {
			res.Detail = fmt.Sprintf("would comment on issue #%d (project %d): %s", issue.IID, r.cfg.ProjectID, res.Detail)
		}
		return res
	}
	url, err := r.note(ctx, issue, body)
	if err != nil {
		res.Action = "error"
		res.Detail = "could not comment on the ticket: " + err.Error()
		return res
	}
	res.NoteURL = url
	return res
}

// applyVerdict maps a verdict onto the workflow. It never resolves anything: only a
// later assessment can do that.
func (r *Runner) applyVerdict(ctx context.Context, f model.Finding, v Verdict) string {
	if r.wf == nil {
		return ""
	}
	item, err := r.wf.FindForFinding(ctx, f.Asset, f.VulnerabilityID, f.Product, f.InstalledVersion)
	if err != nil || item == nil {
		return ""
	}
	switch v.Kind {
	case VerdictNotApplicable:
		st := remediate.StateFalsePositive
		if _, err := r.wf.Update(ctx, item.ID, remediate.Patch{State: &st}); err != nil {
			return "state change failed: " + firstLine(err.Error())
		}
		return "marked false_positive"
	case VerdictMitigated, VerdictExposed, VerdictUncertain:
		if v.Kind != VerdictMitigated || strings.TrimSpace(v.Control) == "" {
			return ""
		}
		days := v.ExpiresDays
		if days <= 0 {
			days = 90
		}
		by := r.cfg.AcceptedBy
		if by == "" {
			by = "automated-triage"
		}
		reason := v.Control + " — " + v.Rationale
		until := r.cfg.now().Add(time.Duration(days) * 24 * time.Hour)
		if _, err := r.wf.AcceptRisk(ctx, item.ID, reason, by, until); err != nil {
			return "risk acceptance failed: " + firstLine(err.Error())
		}
		return fmt.Sprintf("risk accepted for %d days", days)
	}
	return ""
}

// ------------------------------------------------------------------ P2 ---

// Upgrade opens a merge request that moves a package to the version the advisory names.
//
// No model participates. The version comes from the finding, the file edit is a string
// substitution against a known manifest, and the guard refuses anything older than the
// fix.
func (r *Runner) Upgrade(ctx context.Context, rep model.Report) ([]Result, error) {
	findings := actionable(rep.Findings, ClassUpgrade, r.cfg.Limit)
	if !r.trackerReady() {
		if !r.cfg.DryRun {
			return nil, r.requireTracker()
		}
		return preview(findings, PhaseUpgrade, func(f model.Finding) string {
			if Bumpable(f) {
				return fmt.Sprintf("would open a draft merge request: %s → %s", f.InstalledVersion, f.FixedVersion)
			}
			return "would post an upgrade command for " + f.Product
		}), nil
	}
	var out []Result
	for _, f := range findings {
		out = append(out, r.upgradeOne(ctx, f))
	}
	return out, nil
}

func (r *Runner) upgradeOne(ctx context.Context, f model.Finding) Result {
	res := Result{
		Phase: PhaseUpgrade, FindingID: f.FindingID, StableID: f.StableID,
		VulnID: f.VulnerabilityID, Product: f.Product, Severity: f.Severity, Class: ClassUpgrade,
	}
	if err := ValidateUpgrade(f.FixedVersion, f.InstalledVersion, f.FixedVersion); err != nil {
		res.Action = "rejected"
		res.Rejected = err.Error()
		return res
	}
	if !Bumpable(f) {
		// An OS package is not a repository change. Post the exact command instead of
		// pretending a patch exists.
		res.Action = "noted"
		res.Detail = "not a repository change; upgrade command posted"
		issue, err := r.issue(ctx, f)
		if err != nil || issue == nil {
			res.Action = "no_ticket"
			return res
		}
		if r.cfg.DryRun {
			res.Action = "dry_run"
			return res
		}
		if url, err := r.note(ctx, issue, upgradeNote(f)); err == nil {
			res.NoteURL = url
		} else {
			res.Action = "error"
			res.Detail = err.Error()
		}
		return res
	}

	actions, manifest, err := r.planBump(ctx, f)
	if err != nil {
		res.Action = "error"
		res.Detail = err.Error()
		return res
	}
	if len(actions) == 0 {
		res.Action = "no_manifest"
		res.Detail = "no allow-listed manifest pins " + f.Product
		issue, ierr := r.issue(ctx, f)
		if ierr == nil && issue != nil && !r.cfg.DryRun {
			if url, nerr := r.note(ctx, issue, upgradeNote(f)+fmt.Sprintf("\n_No allow-listed manifest pins `%s`; the change needs a person._\n", f.Product)); nerr == nil {
				res.NoteURL = url
			}
		}
		return res
	}

	branch := r.branchName(f)
	res.Branch = branch
	if r.cfg.DryRun {
		res.Action = "dry_run"
		res.Detail = fmt.Sprintf("would bump %s to %s in %s", f.Product, f.FixedVersion, manifest)
		return res
	}

	exists, err := r.tr.BranchExists(ctx, r.cfg.ProjectID, branch)
	if err != nil {
		res.Action = "error"
		res.Detail = "branch check failed: " + err.Error()
		return res
	}
	if !exists {
		if _, err := r.tr.CreateBranch(ctx, r.cfg.ProjectID, branch, r.cfg.targetBranch()); err != nil {
			res.Action = "error"
			res.Detail = "branch creation failed: " + err.Error()
			return res
		}
	}
	msg := fmt.Sprintf("fix(deps): bump %s to %s for %s", f.Product, f.FixedVersion, f.VulnerabilityID)
	if _, err := r.tr.CommitFiles(ctx, r.cfg.ProjectID, branch, msg, actions); err != nil {
		res.Action = "error"
		res.Detail = "commit failed: " + err.Error()
		return res
	}

	mr, err := r.ensureMR(ctx, branch, upgradeMRTitle(f), upgradeMRBody(f, manifest))
	if err != nil {
		res.Action = "error"
		res.Detail = "merge request failed: " + err.Error()
		return res
	}
	res.Action = "mr_opened"
	res.MRURL = mr.WebURL
	res.Detail = fmt.Sprintf("%s %s → %s", f.Product, f.InstalledVersion, f.FixedVersion)

	if issue, ierr := r.issue(ctx, f); ierr == nil && issue != nil {
		body := fmt.Sprintf("Opened %s to upgrade `%s` from `%s` to `%s`.\n\n"+
			"Closes nothing automatically: the finding resolves when a later assessment stops reporting it.",
			mr.WebURL, f.Product, f.InstalledVersion, f.FixedVersion)
		if url, nerr := r.note(ctx, issue, body); nerr == nil {
			res.NoteURL = url
		}
	}
	return res
}

// planBump rewrites the manifest that pins the package. It only ever changes the one
// dependency named in the finding.
func (r *Runner) planBump(ctx context.Context, f model.Finding) ([]ticketing.FileAction, string, error) {
	for _, candidate := range r.cfg.allowPaths() {
		raw, err := r.tr.FileContent(ctx, r.cfg.ProjectID, candidate, r.cfg.targetBranch())
		if err != nil {
			continue
		}
		updated, ok := bumpManifest(candidate, string(raw), f.Product, f.FixedVersion)
		if !ok || updated == string(raw) {
			continue
		}
		return []ticketing.FileAction{{
			Action:   "update",
			FilePath: candidate,
			Content:  updated,
		}}, candidate, nil
	}
	return nil, "", nil
}

// ensureMR returns the existing merge request for the branch, or opens one.
func (r *Runner) ensureMR(ctx context.Context, branch, title, body string) (ticketing.MergeRequest, error) {
	if existing, err := r.tr.MergeRequestsFor(ctx, r.cfg.ProjectID, branch); err == nil {
		for _, mr := range existing {
			if mr.State == "opened" || mr.State == "merged" {
				return mr, nil
			}
		}
	}
	return r.tr.CreateMergeRequest(ctx, r.cfg.ProjectID, ticketing.MergeRequestInput{
		SourceBranch:       branch,
		TargetBranch:       r.cfg.targetBranch(),
		Title:              title,
		Description:        body,
		Labels:             r.labels(),
		Draft:              true,
		RemoveSourceBranch: false,
	})
}

// bumpManifest applies a single-dependency version change.
//
// Supported shapes cover the ecosystems the scanner actually reports for application
// dependencies. Anything else returns ok=false so the caller falls back to a note rather
// than guessing at a file format.
func bumpManifest(name, content, pkg, version string) (string, bool) {
	base := name
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	switch {
	case strings.HasPrefix(base, "requirements") || base == "constraints.txt":
		return bumpRequirements(content, pkg, version)
	case base == "pyproject.toml":
		return bumpPyproject(content, pkg, version)
	case base == "package.json":
		return bumpPackageJSON(content, pkg, version)
	case base == "go.mod":
		return bumpGoMod(content, pkg, version)
	default:
		return "", false
	}
}

func bumpRequirements(content, pkg, version string) (string, bool) {
	lines := strings.Split(content, "\n")
	changed := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
			continue
		}
		name, spec, ok := splitRequirement(trimmed)
		if !ok || !samePackage(name, pkg) {
			continue
		}
		if alreadyAtLeast(spec, version) {
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		comment := ""
		if idx := strings.Index(trimmed, "#"); idx >= 0 {
			comment = "  " + strings.TrimSpace(trimmed[idx:])
			trimmed = strings.TrimSpace(trimmed[:idx])
			name, _, _ = splitRequirement(trimmed)
		}
		lines[i] = indent + name + "==" + version + comment
		changed = true
	}
	if !changed {
		return content, false
	}
	return strings.Join(lines, "\n"), true
}

// alreadyAtLeast reports whether a declared constraint is already at or above the version
// we were about to write.
//
// This is the "do not fix a host problem by downgrading a repository" rule. A scan of a
// host reports the version *installed there*; the repository may already require
// something newer (a locked image, a newer pin). Lowering that constraint to satisfy a
// host finding would be a regression introduced by a remediation tool, which is the worst
// possible trade.
func alreadyAtLeast(spec, version string) bool {
	current := specVersion(spec)
	if current == "" {
		return false
	}
	return CompareVersions(current, version) >= 0
}

// specVersion extracts the version from a constraint such as "^1.2.3", ">=2.0", "==2.12.0"
// or "~1.4".
func specVersion(spec string) string {
	s := strings.TrimSpace(spec)
	s = strings.TrimLeft(s, "=<>!~^ 	")
	if s == "" {
		return ""
	}
	// A compound constraint (>=1.0,<2.0) keeps only the lower bound.
	if i := strings.IndexAny(s, ",; "); i >= 0 {
		s = s[:i]
	}
	s = strings.Trim(s, "\"'")
	return s
}

// splitRequirement pulls the package name out of a PEP 508-ish requirement line.
func splitRequirement(line string) (name, spec string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	end := len(line)
	for i, r := range line {
		if r == '=' || r == '<' || r == '>' || r == '~' || r == '!' || r == ';' || r == '[' || r == ' ' {
			end = i
			break
		}
	}
	name = strings.TrimSpace(line[:end])
	if name == "" {
		return "", "", false
	}
	return name, strings.TrimSpace(line[end:]), true
}

func bumpPackageJSON(content, pkg, version string) (string, bool) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		return content, false
	}
	changed := false
	for _, section := range []string{"dependencies", "devDependencies", "peerDependencies", "optionalDependencies"} {
		raw, ok := doc[section]
		if !ok {
			continue
		}
		deps, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if _, exists := deps[pkg]; !exists {
			continue
		}
		if current, ok := deps[pkg].(string); ok && alreadyAtLeast(current, version) {
			continue
		}
		deps[pkg] = version
		changed = true
	}
	if !changed {
		return content, false
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return content, false
	}
	return string(out) + "\n", true
}

func bumpGoMod(content, pkg, version string) (string, bool) {
	v := version
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	lines := strings.Split(content, "\n")
	changed := false
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != pkg {
			continue
		}
		if alreadyAtLeast(fields[1], v) {
			continue
		}
		lines[i] = "\t" + pkg + " " + v
		changed = true
	}
	if !changed {
		return content, false
	}
	return strings.Join(lines, "\n"), true
}

// ------------------------------------------------------------------ P3 ---

// Investigate produces an evidence-backed applicability verdict for findings the scanner
// could not resolve. It is Triage restricted to the ambiguous cases, with the repository
// context that makes an answer possible.
func (r *Runner) Investigate(ctx context.Context, rep model.Report) ([]Result, error) {
	var findings []model.Finding
	for _, f := range rep.Findings {
		if NeedsInvestigation(f) {
			findings = append(findings, f)
		}
	}
	sort.SliceStable(findings, func(i, j int) bool { return Priority(findings[i]) > Priority(findings[j]) })
	if r.cfg.Limit > 0 && len(findings) > r.cfg.Limit {
		r.cfg.logger().Info("investigate phase hit its limit", "skipped", len(findings)-r.cfg.Limit)
		findings = findings[:r.cfg.Limit]
	}
	if !r.trackerReady() {
		if !r.cfg.DryRun {
			return nil, r.requireTracker()
		}
		return preview(findings, PhaseInvestigate, func(model.Finding) string {
			return "would produce an applicability verdict"
		}), nil
	}
	var out []Result
	for _, f := range findings {
		out = append(out, r.investigateOne(ctx, f))
	}
	return out, nil
}

func (r *Runner) investigateOne(ctx context.Context, f model.Finding) Result {
	res := Result{
		Phase: PhaseInvestigate, FindingID: f.FindingID, StableID: f.StableID,
		VulnID: f.VulnerabilityID, Product: f.Product, Severity: f.Severity, Class: Classify(f),
	}
	issue, err := r.issue(ctx, f)
	if err != nil {
		res.Action = "error"
		res.Detail = "ticket lookup failed: " + err.Error()
		return res
	}
	if issue == nil {
		res.Action = "no_ticket"
		return res
	}
	if r.cfg.LLM == nil {
		res.Action = "needs_model"
		res.Detail = "the scanner could not decide applicability and no model is configured"
		if !r.cfg.DryRun {
			if url, err := r.note(ctx, issue, applicabilityNote(f, nil, errNoModel)); err == nil {
				res.NoteURL = url
			}
		}
		return res
	}

	files := r.fetchContext(ctx)
	raw, err := r.cfg.LLM.Complete(ctx, triageSystemPrompt, triageUserPrompt(f, files))
	if err != nil {
		res.Action = "error"
		res.Detail = "model unavailable: " + firstLine(err.Error())
		return res
	}
	v, perr := ParseVerdict(raw)
	if perr != nil {
		res.Action = "rejected"
		res.Rejected = perr.Error()
		if !r.cfg.DryRun {
			if url, nerr := r.note(ctx, issue, applicabilityNote(f, nil, perr)); nerr == nil {
				res.NoteURL = url
			}
		}
		return res
	}
	res.Action = "verdict"
	res.Detail = v.Kind + " — " + firstLine(v.Rationale)
	if r.cfg.ApplyVerdicts {
		if detail := r.applyVerdict(ctx, f, v); detail != "" {
			res.Detail += " (" + detail + ")"
		}
	}
	if r.cfg.DryRun {
		res.Action = "dry_run"
		if issue != nil && issue.IID > 0 {
			res.Detail = fmt.Sprintf("%s (issue #%d)", res.Detail, issue.IID)
		}
		return res
	}
	if url, err := r.note(ctx, issue, applicabilityNote(f, &v, nil)); err == nil {
		res.NoteURL = url
	}
	return res
}

var errNoModel = fmt.Errorf("no model configured")

// ------------------------------------------------------------------ P4 ---

// Patch asks the model for a file-level fix and opens it as a draft merge request.
//
// This is the only phase where model output reaches a repository, so it is the phase with
// the strictest gates: allow-listed paths only, no secrets, size limits, a mandatory
// rationale, and a draft MR that a person has to promote and merge.
func (r *Runner) Patch(ctx context.Context, rep model.Report) ([]Result, error) {
	candidates := actionable(rep.Findings, ClassTriage, r.cfg.Limit)
	patchable := make([]model.Finding, 0, len(candidates))
	for _, f := range candidates {
		if Patchable(f) {
			patchable = append(patchable, f)
		}
	}
	if !r.trackerReady() {
		if !r.cfg.DryRun {
			return nil, r.requireTracker()
		}
		return preview(patchable, PhasePatch, func(model.Finding) string {
			return "would propose a guarded file-level fix"
		}), nil
	}
	if r.cfg.LLM == nil {
		return nil, fmt.Errorf("phase patch needs a model: configure --model and --model-endpoint")
	}
	var out []Result
	for _, f := range patchable {
		out = append(out, r.patchOne(ctx, f))
	}
	return out, nil
}

func (r *Runner) patchOne(ctx context.Context, f model.Finding) Result {
	res := Result{
		Phase: PhasePatch, FindingID: f.FindingID, StableID: f.StableID,
		VulnID: f.VulnerabilityID, Product: f.Product, Severity: f.Severity, Class: Classify(f),
	}
	issue, err := r.issue(ctx, f)
	if err != nil {
		res.Action = "error"
		res.Detail = "ticket lookup failed: " + err.Error()
		return res
	}
	if issue == nil {
		res.Action = "no_ticket"
		return res
	}

	allow := r.cfg.allowPaths()
	files := r.fetchContext(ctx)
	raw, err := r.cfg.LLM.Complete(ctx, patchSystemPrompt, patchUserPrompt(f, files, allow))
	if err != nil {
		res.Action = "error"
		res.Detail = "model unavailable: " + firstLine(err.Error())
		return res
	}
	proposal, perr := ParsePatch(raw)
	if perr == nil {
		perr = ValidatePatch(proposal, allow, r.cfg.maxPatchBytes())
	}
	if perr != nil {
		res.Action = "rejected"
		res.Rejected = perr.Error()
		if !r.cfg.DryRun {
			body := fmt.Sprintf("An automated fix was proposed for `%s` and **rejected by the guard** before anything was written.\n\n"+
				"Reason: `%s`\n\nNo repository change was made.", f.VulnerabilityID, perr.Error())
			if url, nerr := r.note(ctx, issue, body); nerr == nil {
				res.NoteURL = url
			}
		}
		return res
	}
	if len(proposal.Files) == 0 {
		res.Action = "no_fix"
		res.Detail = "the model declined: " + firstLine(proposal.Rationale)
		if !r.cfg.DryRun {
			if url, nerr := r.note(ctx, issue, "No safe automated fix: "+proposal.Rationale); nerr == nil {
				res.NoteURL = url
			}
		}
		return res
	}

	branch := r.branchName(f)
	res.Branch = branch
	if r.cfg.DryRun {
		res.Action = "dry_run"
		res.Detail = fmt.Sprintf("would change %d file(s): %s", len(proposal.Files), proposal.Rationale)
		return res
	}

	actions := make([]ticketing.FileAction, 0, len(proposal.Files))
	for _, fc := range proposal.Files {
		action := "create"
		if _, err := r.tr.FileContent(ctx, r.cfg.ProjectID, fc.Path, r.cfg.targetBranch()); err == nil {
			action = "update"
		}
		actions = append(actions, ticketing.FileAction{Action: action, FilePath: fc.Path, Content: fc.Content})
	}

	exists, err := r.tr.BranchExists(ctx, r.cfg.ProjectID, branch)
	if err != nil {
		res.Action = "error"
		res.Detail = "branch check failed: " + err.Error()
		return res
	}
	if !exists {
		if _, err := r.tr.CreateBranch(ctx, r.cfg.ProjectID, branch, r.cfg.targetBranch()); err != nil {
			res.Action = "error"
			res.Detail = "branch creation failed: " + err.Error()
			return res
		}
	}
	msg := fmt.Sprintf("fix(security): remediate %s in %s", f.VulnerabilityID, f.Product)
	if _, err := r.tr.CommitFiles(ctx, r.cfg.ProjectID, branch, msg, actions); err != nil {
		res.Action = "error"
		res.Detail = "commit failed: " + err.Error()
		return res
	}
	mr, err := r.ensureMR(ctx, branch,
		fmt.Sprintf("fix(security): %s in %s", f.VulnerabilityID, f.Product),
		patchMRBody(f, proposal))
	if err != nil {
		res.Action = "error"
		res.Detail = "merge request failed: " + err.Error()
		return res
	}
	res.Action = "mr_opened"
	res.MRURL = mr.WebURL
	res.Detail = fmt.Sprintf("%d file(s) changed: %s", len(proposal.Files), firstLine(proposal.Rationale))

	if url, nerr := r.note(ctx, issue, fmt.Sprintf("Proposed a fix in %s (draft). Guard checks passed: %d file(s), allow-listed paths only.\n\n%s",
		mr.WebURL, len(proposal.Files), proposal.Rationale)); nerr == nil {
		res.NoteURL = url
	}
	return res
}

// ------------------------------------------------------------------ P5 ---

// Verify resolves work items whose finding is absent from a later assessment.
//
// The absence is the receipt. A merged merge request is not: code can be merged and not
// deployed, and a package can be upgraded on one host out of five.
func (r *Runner) Verify(ctx context.Context, rep model.Report) ([]Result, error) {
	if r.wf == nil {
		return nil, fmt.Errorf("phase verify needs the remediation store")
	}
	present := make(map[string]bool, len(rep.Findings))
	for _, f := range rep.Findings {
		present[findingKey(f)] = true
	}
	items, err := r.wf.List(ctx, remediate.Filter{}, remediate.DefaultPolicy())
	if err != nil {
		return nil, fmt.Errorf("list remediation items: %w", err)
	}
	var out []Result
	for _, item := range items {
		if present[item.FindingKey] || remediate.IsTerminal(item.State) {
			continue
		}
		res := Result{
			Phase: PhaseVerify, FindingID: item.ID, StableID: item.FindingKey,
			VulnID: item.VulnerabilityID, Product: item.Product, Severity: item.Severity,
			Class: Classify(model.Finding{Product: item.Product, VulnerabilityID: item.VulnerabilityID}),
		}
		if r.cfg.DryRun {
			res.Action = "dry_run"
			res.Detail = "would resolve: absent from report " + rep.ReportID
			out = append(out, res)
			continue
		}
		updated, err := r.wf.MarkVerified(ctx, item.ID, rep.ReportID)
		if err != nil {
			res.Action = "error"
			res.Detail = "could not mark verified: " + firstLine(err.Error())
			out = append(out, res)
			continue
		}
		res.Action = "verified"
		res.Detail = fmt.Sprintf("absent from report %s; state %s", rep.ReportID, updated.State)
		if r.tr != nil && r.cfg.ProjectID > 0 {
			if issue, ierr := r.issueFor(ctx, item.FindingKey); ierr == nil && issue != nil {
				body := fmt.Sprintf("Verified absent in assessment `%s`.\n\n"+
					"This is the receipt: the finding is no longer reported for this asset, so the work item is `%s`.",
					rep.ReportID, updated.State)
				if url, nerr := r.note(ctx, issue, body); nerr == nil {
					res.NoteURL = url
				}
			}
		}
		out = append(out, res)
	}
	return out, nil
}

// issueFor finds a ticket by finding key alone, for the verify phase where only the
// stored item is available.
func (r *Runner) issueFor(ctx context.Context, key string) (*ticketing.Issue, error) {
	found, err := r.tr.SearchIssues(ctx, r.cfg.ProjectID, ticketing.MarkerSearch(key))
	if err != nil {
		return nil, err
	}
	marker := ticketing.Marker(key)
	for i := range found {
		if strings.Contains(found[i].Description, marker) {
			return &found[i], nil
		}
	}
	return nil, nil
}

// ------------------------------------------------------------------ notes ---

func verdictNote(f model.Finding, v Verdict) string {
	var b strings.Builder
	b.WriteString("### Automated triage verdict: `" + v.Kind + "`\n\n")
	b.WriteString(v.Rationale + "\n\n")
	if len(v.Evidence) > 0 {
		b.WriteString("**Evidence**\n")
		for _, e := range v.Evidence {
			b.WriteString("- " + e + "\n")
		}
		b.WriteString("\n")
	}
	if v.Control != "" {
		b.WriteString("**Compensating control:** " + v.Control + "\n\n")
	}
	if v.ExpiresDays > 0 {
		b.WriteString(fmt.Sprintf("**Suggested review:** %d days\n\n", v.ExpiresDays))
	}
	b.WriteString("Confidence: `" + v.Confidence + "`\n\n")
	b.WriteString("_This verdict is a comment, not a resolution. The finding resolves only when a later " +
		"assessment stops reporting it. " + markerFooter(f) + "_\n")
	return b.String()
}

func applicabilityNote(f model.Finding, v *Verdict, problem error) string {
	if v == nil {
		var b strings.Builder
		b.WriteString("### Applicability needs a human\n\n")
		b.WriteString("The scanner could not decide whether this advisory applies, and no verdict was produced.\n\n")
		if problem != nil {
			b.WriteString("Reason: `" + problem.Error() + "`\n\n")
		}
		b.WriteString("Scanner state: `" + string(f.Affected) + "`. ")
		if f.Explanation != "" {
			b.WriteString("Scanner explanation: " + f.Explanation + "\n")
		}
		b.WriteString("\n" + markerFooter(f) + "\n")
		return b.String()
	}
	return verdictNote(f, *v)
}

func upgradeNote(f model.Finding) string {
	var b strings.Builder
	b.WriteString("### Upgrade available\n\n")
	b.WriteString("`" + f.Product + "` " + f.InstalledVersion + " → " + f.FixedVersion + "\n\n")
	b.WriteString("```\n" + upgradeCommand(f) + "\n```\n\n")
	b.WriteString("Then rescan: the finding resolves when the next assessment stops reporting it.\n\n")
	b.WriteString(markerFooter(f))
	return b.String()
}

// upgradeCommand is the platform-appropriate one-liner. It is a suggestion on a ticket,
// never something this package executes.
func upgradeCommand(f model.Finding) string {
	switch {
	case strings.Contains(strings.ToLower(f.Ecosystem), "ubuntu"), strings.Contains(strings.ToLower(f.Ecosystem), "debian"):
		return "sudo apt-get install --only-upgrade " + f.Product
	case strings.Contains(strings.ToLower(f.Ecosystem), "pypi"), strings.Contains(strings.ToLower(f.Ecosystem), "pip"):
		return "pip install --upgrade '" + f.Product + "==" + f.FixedVersion + "'"
	case strings.Contains(strings.ToLower(f.Ecosystem), "npm"):
		return "npm install " + f.Product + "@" + f.FixedVersion
	case strings.Contains(strings.ToLower(f.Ecosystem), "go"):
		return "go get " + f.Product + "@v" + strings.TrimPrefix(f.FixedVersion, "v")
	default:
		return "upgrade " + f.Product + " to " + f.FixedVersion
	}
}

func upgradeMRTitle(f model.Finding) string {
	return fmt.Sprintf("fix(deps): bump %s to %s (%s)", f.Product, f.FixedVersion, f.VulnerabilityID)
}

func upgradeMRBody(f model.Finding, manifest string) string {
	var b strings.Builder
	b.WriteString("## What\n\n")
	b.WriteString(fmt.Sprintf("`%s` `%s` → `%s` in `%s`.\n\n", f.Product, f.InstalledVersion, f.FixedVersion, manifest))
	b.WriteString("## Why\n\n")
	b.WriteString(fmt.Sprintf("%s (severity **%s**", f.VulnerabilityID, f.Severity))
	if f.CVSS != nil {
		b.WriteString(fmt.Sprintf(", CVSS %.1f", f.CVSS.Score))
	}
	if f.CISAKEV {
		b.WriteString(", **CISA KEV**")
	}
	b.WriteString(")\n\n")
	if f.Explanation != "" {
		b.WriteString(f.Explanation + "\n\n")
	}
	b.WriteString("## Verification\n\n")
	b.WriteString("1. CI on this branch.\n")
	b.WriteString("2. Deploy, then rescan the asset. The finding resolves only when a later assessment stops reporting it.\n\n")
	b.WriteString("## Rollback\n\nRevert this merge request and redeploy.\n\n")
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("_Automated by clanker-guard autofix. Version taken from the advisory (fixed: `%s`), not from a model._\n", f.FixedVersion))
	b.WriteString("\n" + markerFooter(f) + "\n")
	return b.String()
}

func patchMRBody(f model.Finding, p PatchProposal) string {
	var b strings.Builder
	b.WriteString("## What\n\n" + p.Rationale + "\n\n")
	b.WriteString(fmt.Sprintf("Fixes %s in `%s %s`.\n\n", f.VulnerabilityID, f.Product, f.InstalledVersion))
	if len(p.Files) > 0 {
		b.WriteString("## Files\n\n")
		for _, fc := range p.Files {
			b.WriteString("- `" + fc.Path + "`\n")
		}
		b.WriteString("\n")
	}
	if len(p.Tests) > 0 {
		b.WriteString("## Suggested verification\n\n")
		for _, t := range p.Tests {
			b.WriteString("- `" + t + "`\n")
		}
		b.WriteString("\n")
	}
	if p.Risk != "" {
		b.WriteString("## Risk\n\n" + p.Risk + "\n\n")
	}
	if p.Rollback != "" {
		b.WriteString("## Rollback\n\n" + p.Rollback + "\n\n")
	}
	b.WriteString("---\n")
	b.WriteString("_Draft: proposed by a model, then checked against the writable allow-list, a version guard and a secret scan. " +
		"A person must review and merge. " + markerFooter(f) + "_\n")
	return b.String()
}

func markerFooter(f model.Finding) string {
	return ticketing.Marker(findingKey(f))
}

// bumpPyproject rewrites one dependency in a pyproject.toml, supporting both styles that
// appear in the wild:
//
//	[tool.poetry.dependencies]      paramiko = "^4.0.0"
//	                                uvicorn = {version = "^0.30.0", extras = ["standard"]}
//	[project]                       dependencies = ["paramiko>=4.0", "fastapi"]
//
// It edits text rather than re-encoding the TOML: a decode/encode round trip would
// reformat the whole file and turn a one-line fix into an unreviewable diff.
func bumpPyproject(content, pkg, version string) (string, bool) {
	lines := strings.Split(content, "\n")
	section := ""
	inArray := false
	changed := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.Trim(trimmed, "[]"))
			inArray = false
			continue
		}
		switch {
		case isPoetryDependencySection(section):
			if rewritten, ok := bumpPoetryAssignment(line, pkg, version); ok {
				lines[i] = rewritten
				changed = true
			}
		case section == "project":
			// PEP 621 arrays may span lines; track the bracket state so a dependency
			// listed on its own line is still found.
			if inArray {
				if rewritten, ok := bumpQuotedRequirement(line, pkg, version); ok {
					lines[i] = rewritten
					changed = true
				}
				if strings.Contains(trimmed, "]") {
					inArray = false
				}
				continue
			}
			if strings.HasPrefix(trimmed, "dependencies") && strings.Contains(trimmed, "[") {
				if rewritten, ok := bumpQuotedRequirement(line, pkg, version); ok {
					lines[i] = rewritten
					changed = true
				}
				if !strings.Contains(trimmed, "]") {
					inArray = true
				}
			}
		}
	}
	if !changed {
		return content, false
	}
	return strings.Join(lines, "\n"), true
}

func isPoetryDependencySection(section string) bool {
	if section == "tool.poetry.dependencies" || section == "tool.poetry.dev-dependencies" {
		return true
	}
	// tool.poetry.group.<name>.dependencies
	return strings.HasPrefix(section, "tool.poetry.group.") && strings.HasSuffix(section, ".dependencies")
}

// bumpPoetryAssignment handles `name = "spec"` and `name = {version = "spec", ...}`.
func bumpPoetryAssignment(line, pkg, version string) (string, bool) {
	eq := strings.Index(line, "=")
	if eq < 0 {
		return line, false
	}
	name := strings.TrimSpace(line[:eq])
	if !samePackage(name, pkg) {
		return line, false
	}
	rest := line[eq+1:]
	// The version is the first quoted string on the right-hand side, whether it stands
	// alone or sits inside an inline table.
	start := strings.IndexAny(rest, `"'`)
	if start < 0 {
		return line, false
	}
	quote := rest[start]
	end := strings.IndexByte(rest[start+1:], quote)
	if end < 0 {
		return line, false
	}
	end += start + 1
	if alreadyAtLeast(rest[start+1:end], version) {
		return line, false
	}
	return line[:eq+1] + rest[:start+1] + version + rest[end:], true
}

// bumpQuotedRequirement rewrites one requirement inside a quoted array element.
func bumpQuotedRequirement(line, pkg, version string) (string, bool) {
	for i := 0; i < len(line); i++ {
		q := line[i]
		if q != '"' && q != '\'' {
			continue
		}
		end := strings.IndexByte(line[i+1:], q)
		if end < 0 {
			return line, false
		}
		end += i + 1
		inner := line[i+1 : end]
		name, spec, ok := splitRequirement(inner)
		if ok && samePackage(name, pkg) {
			if alreadyAtLeast(spec, version) {
				return line, false
			}
			return line[:i+1] + name + "==" + version + line[end:], true
		}
		i = end
	}
	return line, false
}

// samePackage compares names the way the packaging ecosystems do: case-insensitively,
// with hyphen, underscore and dot interchangeable.
func samePackage(a, b string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.NewReplacer("_", "-", ".", "-").Replace(s)
		return s
	}
	return norm(a) == norm(b)
}
