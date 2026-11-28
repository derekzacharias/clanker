package autofix

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/remediate"
	"github.com/bgdnvk/clanker/internal/vuln/ticketing"
)

// ---------------------------------------------------------------- fakes ---

type fakeTracker struct {
	issues   []ticketing.Issue
	files    map[string]string
	branches map[string]bool
	mrs      []ticketing.MergeRequest

	notes            int
	branchesCreated  int
	commits          int
	mrsCreated       int
	lastActions      []ticketing.FileAction
	lastCommitBranch string
	lastMR           ticketing.MergeRequestInput
}

func newFakeTracker() *fakeTracker {
	return &fakeTracker{files: map[string]string{}, branches: map[string]bool{}}
}

func (f *fakeTracker) SearchIssues(_ context.Context, _ int, _ string) ([]ticketing.Issue, error) {
	return f.issues, nil
}

func (f *fakeTracker) CreateNote(_ context.Context, _, iid int, body string) (ticketing.Note, error) {
	f.notes++
	return ticketing.Note{ID: 100 + f.notes, Body: body}, nil
}

func (f *fakeTracker) BranchExists(_ context.Context, _ int, name string) (bool, error) {
	return f.branches[name], nil
}

func (f *fakeTracker) CreateBranch(_ context.Context, _ int, name, ref string) (ticketing.Branch, error) {
	if f.branches[name] {
		return ticketing.Branch{}, fmt.Errorf("branch %s exists", name)
	}
	f.branches[name] = true
	f.branchesCreated++
	return ticketing.Branch{Name: name}, nil
}

func (f *fakeTracker) CommitFiles(_ context.Context, _ int, branch, _ string, actions []ticketing.FileAction) (string, error) {
	f.commits++
	f.lastActions = actions
	f.lastCommitBranch = branch
	for _, a := range actions {
		if a.Action == "delete" {
			delete(f.files, a.FilePath)
			continue
		}
		f.files[a.FilePath] = a.Content
	}
	return "sha", nil
}

func (f *fakeTracker) CreateMergeRequest(_ context.Context, _ int, in ticketing.MergeRequestInput) (ticketing.MergeRequest, error) {
	f.mrsCreated++
	f.lastMR = in
	mr := ticketing.MergeRequest{
		IID:          f.mrsCreated,
		WebURL:       fmt.Sprintf("https://gitlab.test/mr/%d", f.mrsCreated),
		State:        "opened",
		SourceBranch: in.SourceBranch,
		Title:        in.Title,
	}
	f.mrs = append(f.mrs, mr)
	return mr, nil
}

func (f *fakeTracker) MergeRequestsFor(_ context.Context, _ int, sourceBranch string) ([]ticketing.MergeRequest, error) {
	var out []ticketing.MergeRequest
	for _, mr := range f.mrs {
		if mr.SourceBranch == sourceBranch {
			out = append(out, mr)
		}
	}
	return out, nil
}

func (f *fakeTracker) FileContent(_ context.Context, _ int, filePath, _ string) ([]byte, error) {
	if c, ok := f.files[filePath]; ok {
		return []byte(c), nil
	}
	return nil, fmt.Errorf("file %s not found", filePath)
}

type fakeWorkflow struct {
	items    []remediate.Item
	verified []string
	updated  map[string]string
	accepted map[string]time.Time
}

func (f *fakeWorkflow) FindForFinding(_ context.Context, _, vulnID, product, _ string) (*remediate.Item, error) {
	for i := range f.items {
		if f.items[i].VulnerabilityID == vulnID && f.items[i].Product == product {
			return &f.items[i], nil
		}
	}
	return nil, nil
}

func (f *fakeWorkflow) Update(_ context.Context, id string, patch remediate.Patch) (remediate.Item, error) {
	if f.updated == nil {
		f.updated = map[string]string{}
	}
	if patch.State != nil {
		f.updated[id] = string(*patch.State)
	}
	return remediate.Item{ID: id}, nil
}

func (f *fakeWorkflow) AcceptRisk(_ context.Context, id, _, _ string, until time.Time) (remediate.Item, error) {
	if f.accepted == nil {
		f.accepted = map[string]time.Time{}
	}
	f.accepted[id] = until
	return remediate.Item{ID: id, State: remediate.StateRiskAccepted}, nil
}

func (f *fakeWorkflow) MarkVerified(_ context.Context, id, _ string) (remediate.Item, error) {
	f.verified = append(f.verified, id)
	return remediate.Item{ID: id, State: remediate.StateResolved}, nil
}

func (f *fakeWorkflow) List(_ context.Context, _ remediate.Filter, _ remediate.Policy) ([]remediate.Item, error) {
	return f.items, nil
}

func issueFor(f model.Finding) ticketing.Issue {
	return ticketing.Issue{
		IID:         7,
		WebURL:      "https://gitlab.test/issues/7",
		State:       "opened",
		Description: "body\n\n" + ticketing.Marker(remediate.FindingKey(f.Asset, f)),
	}
}

func triageable() model.Finding {
	return model.Finding{
		FindingID: "FINDING-0056", StableID: "abc", Asset: "openclaw",
		Product: "thunderbird", InstalledVersion: "2:1snap1-0ubuntu3", Ecosystem: "Ubuntu:24.04:LTS",
		VulnerabilityID: "CVE-2022-25236", Severity: "high",
		Affected: model.ApplicabilityConfirmed,
	}
}

func upgradable() model.Finding {
	return model.Finding{
		FindingID: "FINDING-0001", StableID: "def", Asset: "openclaw",
		Product: "paramiko", InstalledVersion: "2.12.0", Ecosystem: "PyPI",
		VulnerabilityID: "CVE-2023-48795", Severity: "medium",
		Affected: model.ApplicabilityConfirmed, FixedVersion: "3.4.0",
	}
}

func testConfig() Config {
	return Config{Phase: PhaseAll, ProjectID: 1, TargetBranch: "main", Now: time.Now}
}

// ---------------------------------------------------------------- P1 ---

func TestTriageCommentsAVerdictButDoesNotCloseTheTicketByDefault(t *testing.T) {
	f := triageable()
	tr := newFakeTracker()
	tr.issues = []ticketing.Issue{issueFor(f)}
	wf := &fakeWorkflow{}
	llm := Func(func(context.Context, string, string) (string, error) {
		return `{"verdict":"mitigated","rationale":"no service binds a socket","evidence":["ss -tln shows no listener"],"compensating_control":"package present but unreachable","expires_in_days":90,"confidence":"high"}`, nil
	})
	cfg := testConfig()
	cfg.LLM = llm

	res, err := New(cfg, tr, wf).Triage(context.Background(), model.Report{ReportID: "SCAN-1", Findings: []model.Finding{f}})
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if len(res) != 1 || res[0].Action != "verdict" {
		t.Fatalf("expected one verdict result, got %+v", res)
	}
	if tr.notes != 1 {
		t.Fatalf("expected exactly one ticket comment, got %d", tr.notes)
	}
	if len(wf.updated) != 0 || len(wf.accepted) != 0 {
		t.Fatal("a verdict must not change workflow state unless ApplyVerdicts is set")
	}
}

func TestTriageAppliesVerdictOnlyWhenAsked(t *testing.T) {
	f := triageable()
	tr := newFakeTracker()
	tr.issues = []ticketing.Issue{issueFor(f)}
	wf := &fakeWorkflow{items: []remediate.Item{{ID: "ITEM-1", Product: f.Product, VulnerabilityID: f.VulnerabilityID}}}
	cfg := testConfig()
	cfg.ApplyVerdicts = true
	cfg.LLM = Func(func(context.Context, string, string) (string, error) {
		return `{"verdict":"not_applicable","rationale":"package is not installed for the running service","evidence":["docker image lacks it"],"confidence":"high"}`, nil
	})

	if _, err := New(cfg, tr, wf).Triage(context.Background(), model.Report{Findings: []model.Finding{f}}); err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if wf.updated["ITEM-1"] != string(remediate.StateFalsePositive) {
		t.Fatalf("expected false_positive, got %q", wf.updated["ITEM-1"])
	}
}

func TestTriageWithoutModelPostsTheFacts(t *testing.T) {
	f := triageable()
	tr := newFakeTracker()
	tr.issues = []ticketing.Issue{issueFor(f)}

	res, err := New(testConfig(), tr, &fakeWorkflow{}).Triage(context.Background(), model.Report{Findings: []model.Finding{f}})
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if res[0].Action != "noted" {
		t.Fatalf("expected a deterministic note, got %q", res[0].Action)
	}
	if tr.notes != 1 {
		t.Fatal("the facts should still be recorded on the ticket")
	}
}

func TestTriageDryRunWritesNothing(t *testing.T) {
	f := triageable()
	tr := newFakeTracker()
	tr.issues = []ticketing.Issue{issueFor(f)}
	cfg := testConfig()
	cfg.DryRun = true
	cfg.LLM = Func(func(context.Context, string, string) (string, error) {
		return `{"verdict":"uncertain","rationale":"insufficient evidence","evidence":[],"confidence":"low"}`, nil
	})
	res, _ := New(cfg, tr, wfForTest()).Triage(context.Background(), model.Report{Findings: []model.Finding{f}})
	if tr.notes != 0 {
		t.Fatal("dry run must not comment")
	}
	if res[0].Action != "dry_run" {
		t.Fatalf("expected dry_run, got %q", res[0].Action)
	}
}

func wfForTest() *fakeWorkflow { return &fakeWorkflow{} }

func TestTriageSkipsFindingsWithoutATicket(t *testing.T) {
	f := triageable()
	tr := newFakeTracker() // no issues
	res, err := New(testConfig(), tr, wfForTest()).Triage(context.Background(), model.Report{Findings: []model.Finding{f}})
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if res[0].Action != "no_ticket" {
		t.Fatalf("expected no_ticket, got %q", res[0].Action)
	}
	if tr.notes != 0 {
		t.Fatal("nothing to comment on")
	}
}

// ---------------------------------------------------------------- P2 ---

func TestUpgradeBumpsTheManifestAndOpensADraftMR(t *testing.T) {
	f := upgradable()
	tr := newFakeTracker()
	tr.files["requirements.txt"] = "# deps\nparamiko==2.12.0\nflask==3.0.1\n"

	res, err := New(testConfig(), tr, wfForTest()).Upgrade(context.Background(), model.Report{Findings: []model.Finding{f}})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if res[0].Action != "mr_opened" {
		t.Fatalf("expected mr_opened, got %+v", res[0])
	}
	if tr.commits != 1 || len(tr.lastActions) != 1 {
		t.Fatalf("expected one commit with one file, got commits=%d actions=%d", tr.commits, len(tr.lastActions))
	}
	if !strings.Contains(tr.lastActions[0].Content, "paramiko==3.4.0") {
		t.Fatalf("version not bumped:\n%s", tr.lastActions[0].Content)
	}
	if !strings.Contains(tr.lastActions[0].Content, "flask==3.0.1") {
		t.Fatal("an unrelated dependency was modified")
	}
	if tr.lastCommitBranch != "secfix/finding-0001" {
		t.Fatalf("unexpected branch %q", tr.lastCommitBranch)
	}
	if !tr.lastMR.Draft {
		t.Fatal("the merge request must be a draft")
	}
	// The "Draft:" prefix is the transport's job (GitLab expresses drafts as a title
	// prefix); the runner only states the intent. Asserting the prefix here would test
	// the wrong layer, so it is covered in the ticketing package instead.
	if strings.HasPrefix(strings.ToLower(tr.lastMR.Title), "draft:") {
		t.Fatalf("the runner must not pre-prefix the title: %q", tr.lastMR.Title)
	}
}

func TestUpgradeIsIdempotent(t *testing.T) {
	f := upgradable()
	tr := newFakeTracker()
	tr.files["requirements.txt"] = "paramiko==2.12.0\n"
	r := New(testConfig(), tr, wfForTest())

	if _, err := r.Upgrade(context.Background(), model.Report{Findings: []model.Finding{f}}); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if _, err := r.Upgrade(context.Background(), model.Report{Findings: []model.Finding{f}}); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if tr.branchesCreated != 1 {
		t.Fatalf("a re-run must not create a second branch, created %d", tr.branchesCreated)
	}
	if tr.mrsCreated != 1 {
		t.Fatalf("a re-run must adopt the open merge request, created %d", tr.mrsCreated)
	}
}

func TestUpgradeRefusesAFixThatDoesNotMove(t *testing.T) {
	f := upgradable()
	f.InstalledVersion = "3.4.0" // already at the fixed version
	tr := newFakeTracker()
	tr.files["requirements.txt"] = "paramiko==3.4.0\n"

	res, err := New(testConfig(), tr, wfForTest()).Upgrade(context.Background(), model.Report{Findings: []model.Finding{f}})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if res[0].Action != "rejected" {
		t.Fatalf("expected rejection, got %+v", res[0])
	}
	if tr.commits != 0 {
		t.Fatal("nothing should be committed when the guard rejects the version")
	}
}

func TestUpgradePostsACommandForOSPackages(t *testing.T) {
	f := upgradable()
	f.Ecosystem = "Ubuntu:24.04:LTS" // not a repository change
	tr := newFakeTracker()
	tr.issues = []ticketing.Issue{issueFor(f)}

	res, err := New(testConfig(), tr, wfForTest()).Upgrade(context.Background(), model.Report{Findings: []model.Finding{f}})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if res[0].Action != "noted" {
		t.Fatalf("an OS package must become a note, got %q", res[0].Action)
	}
	if tr.commits != 0 {
		t.Fatal("an OS package is not a repository change")
	}
	if tr.notes != 1 {
		t.Fatal("the upgrade command should be posted on the ticket")
	}
}

// ---------------------------------------------------------------- P4 ---

func TestPatchRejectsForbiddenFileAndWritesNothing(t *testing.T) {
	f := triageable()
	f.Ecosystem = "PyPI"
	f.Product = "flask"
	f.InstalledVersion = "3.0.0"
	tr := newFakeTracker()
	tr.issues = []ticketing.Issue{issueFor(f)}
	cfg := testConfig()
	cfg.LLM = Func(func(context.Context, string, string) (string, error) {
		return `{"rationale":"disable debugging","files":[{"path":".gitlab-ci.yml","content":"stages: [deploy]\n"}],"tests":[],"risk":"","rollback":""}`, nil
	})

	res, err := New(cfg, tr, wfForTest()).Patch(context.Background(), model.Report{Findings: []model.Finding{f}})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if res[0].Action != "rejected" {
		t.Fatalf("expected rejection, got %+v", res[0])
	}
	if tr.commits != 0 || tr.branchesCreated != 0 {
		t.Fatal("a rejected proposal must not touch the repository")
	}
	if tr.notes != 1 {
		t.Fatal("the rejection must be visible on the ticket")
	}
}

func TestPatchOpensADraftMRWithTheGeneratedChange(t *testing.T) {
	f := triageable()
	f.Ecosystem = "PyPI"
	f.Product = "flask"
	f.InstalledVersion = "3.0.0"
	tr := newFakeTracker()
	tr.issues = []ticketing.Issue{issueFor(f)}
	tr.files["requirements.txt"] = "flask==3.0.0\n"
	cfg := testConfig()
	cfg.LLM = Func(func(context.Context, string, string) (string, error) {
		return `{"rationale":"pin the fixed version","files":[{"path":"requirements.txt","content":"flask==3.0.5\n"}],"tests":["pytest -q"],"risk":"low","rollback":"revert"}`, nil
	})

	res, err := New(cfg, tr, wfForTest()).Patch(context.Background(), model.Report{Findings: []model.Finding{f}})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if res[0].Action != "mr_opened" {
		t.Fatalf("expected mr_opened, got %+v", res[0])
	}
	if len(tr.lastActions) != 1 || tr.lastActions[0].Action != "update" {
		t.Fatalf("an existing file must be committed as an update, got %+v", tr.lastActions)
	}
	if !tr.lastMR.Draft {
		t.Fatal("generated code must arrive as a draft")
	}
}

func TestPatchRequiresAModel(t *testing.T) {
	if _, err := New(testConfig(), newFakeTracker(), wfForTest()).Patch(context.Background(), model.Report{}); err == nil {
		t.Fatal("the patch phase must refuse to run without a model")
	}
}

// ---------------------------------------------------------------- P5 ---

func TestVerifyResolvesOnlyAbsentFindings(t *testing.T) {
	present := upgradable()
	absent := triageable()
	terminal := model.Finding{Asset: "openclaw", Product: "zlib", InstalledVersion: "1", VulnerabilityID: "CVE-9"}

	wf := &fakeWorkflow{items: []remediate.Item{
		{ID: "ITEM-PRESENT", FindingKey: remediate.FindingKey(present.Asset, present), State: remediate.StateInProgress},
		{ID: "ITEM-ABSENT", FindingKey: remediate.FindingKey(absent.Asset, absent), State: remediate.StateInProgress},
		{ID: "ITEM-DONE", FindingKey: remediate.FindingKey(terminal.Asset, terminal), State: remediate.StateResolved},
	}}
	tr := newFakeTracker()

	res, err := New(testConfig(), tr, wf).Verify(context.Background(), model.Report{ReportID: "SCAN-2", Findings: []model.Finding{present}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(wf.verified) != 1 || wf.verified[0] != "ITEM-ABSENT" {
		t.Fatalf("only the absent, non-terminal item should resolve, got %v", wf.verified)
	}
	if res[0].Action != "verified" {
		t.Fatalf("expected verified, got %+v", res[0])
	}
}

func TestPhasesRequireAProjectBeforeWriting(t *testing.T) {
	cfg := testConfig()
	cfg.ProjectID = 0
	if _, err := New(cfg, newFakeTracker(), wfForTest()).Triage(context.Background(), model.Report{}); err == nil {
		t.Fatal("a write phase without a project must fail loudly")
	}
}

func TestDryRunPreviewsWithoutGitLabConfigured(t *testing.T) {
	f := triageable()
	cfg := testConfig()
	cfg.DryRun = true

	// No tracker at all: the preview must still say what it would do.
	res, err := New(cfg, nil, nil).Triage(context.Background(), model.Report{Findings: []model.Finding{f}})
	if err != nil {
		t.Fatalf("an offline dry run must not fail: %v", err)
	}
	if len(res) != 1 || res[0].Action != "dry_run" {
		t.Fatalf("expected a preview row, got %+v", res)
	}
	if !strings.Contains(res[0].Detail, "would comment") {
		t.Fatalf("the preview must name the action it did not take: %q", res[0].Detail)
	}
}

func TestApplyingWithoutGitLabFailsInsteadOfSilentlyDoingNothing(t *testing.T) {
	f := triageable()
	if _, err := New(testConfig(), nil, nil).Triage(context.Background(), model.Report{Findings: []model.Finding{f}}); err == nil {
		t.Fatal("applying with no tracker must be an error, not a no-op")
	}
}
