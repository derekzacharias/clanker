package remediate

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

func newStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "intel.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	st, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC)
	st.SetClock(func() time.Time { return now })
	return st, &now
}

func finding(host, eco, product, version, vuln, sev string) model.Finding {
	return model.Finding{
		Asset: host, Ecosystem: eco, Product: product, InstalledVersion: version,
		VulnerabilityID: vuln, Severity: sev, Affected: model.ApplicabilityConfirmed,
		Confidence: model.ConfidenceHigh, FixedVersion: version + "-fixed",
		Remediation: "apt-get install --only-upgrade " + product,
	}
}

func report(host string, findings ...model.Finding) model.Report {
	return model.Report{
		ReportID: "SCAN-1",
		Metadata: model.ScanMetadata{Host: host, Mode: "local"},
		Findings: findings,
	}
}

// TestRoutingPrecedence pins the ownership rules from the requirements: an explicit
// asset owner wins, then the category mapping, and an unknown category goes to
// triage rather than to an arbitrary team (never to Security by default).
func TestRoutingPrecedence(t *testing.T) {
	policy := DefaultPolicy()

	t.Run("explicit owner wins over the mapping", func(t *testing.T) {
		own := Ownership{Status: "owned", Team: "Payments Team"}
		team, category, triaged := policy.Route(finding("web01", "Ubuntu:24.04", "openssl", "3.0.1", "CVE-1", "high"), own)
		if triaged || team != "Payments Team" || category != "os_package" {
			t.Fatalf("route = %q %q triaged=%v", team, category, triaged)
		}
	})

	t.Run("mapping routes OS packages to infrastructure", func(t *testing.T) {
		team, category, triaged := policy.Route(finding("web01", "Ubuntu:24.04", "openssl", "3.0.1", "CVE-1", "high"), Ownership{})
		if triaged || team != "Infrastructure" || category != "os_package" {
			t.Fatalf("route = %q %q triaged=%v", team, category, triaged)
		}
	})

	t.Run("application dependencies route to development", func(t *testing.T) {
		team, category, _ := policy.Route(finding("web01", "PyPI", "django", "4.2.0", "CVE-2", "high"), Ownership{})
		if team != "Development" || category != "app_dependency" {
			t.Fatalf("route = %q %q", team, category)
		}
	})

	t.Run("container images route to platform engineering", func(t *testing.T) {
		team, category, _ := policy.Route(finding("api", "container:debian", "zlib", "1.2", "CVE-3", "high"), Ownership{})
		if team != "Platform Engineering" || category != "container_image" {
			t.Fatalf("route = %q %q", team, category)
		}
	})

	t.Run("unknown ecosystem goes to triage", func(t *testing.T) {
		team, category, triaged := policy.Route(finding("odd", "unknown:thing", "blob", "1", "CVE-4", "high"), Ownership{})
		if !triaged || team != "" || category != "" {
			t.Fatalf("route = %q %q triaged=%v (must not default to a team)", team, category, triaged)
		}
	})

	t.Run("organisations can override the mapping", func(t *testing.T) {
		custom := DefaultPolicy()
		custom.Teams = map[string]string{"os_package": "Linux Ops"}
		if team, _, _ := custom.Route(finding("web01", "Debian:12", "openssl", "3", "CVE-1", "high"), Ownership{}); team != "Linux Ops" {
			t.Fatalf("override ignored: %q", team)
		}
	})
}

// TestDueAtFromPolicy covers the SLA rules: severity windows, KEV acceleration and
// internet exposure, all configurable, and no deadline invented when none is set.
func TestDueAtFromPolicy(t *testing.T) {
	now := time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC)
	policy := DefaultPolicy()

	cases := []struct {
		name  string
		f     model.Finding
		own   Ownership
		days  int
		sevIn string
	}{
		{"critical", finding("a", "Ubuntu:24.04", "p", "1", "CVE-1", "critical"), Ownership{}, 7, "critical"},
		{"high", finding("a", "Ubuntu:24.04", "p", "1", "CVE-1", "high"), Ownership{}, 30, "high"},
		{"medium", finding("a", "Ubuntu:24.04", "p", "1", "CVE-1", "medium"), Ownership{}, 60, "medium"},
		{"low", finding("a", "Ubuntu:24.04", "p", "1", "CVE-1", "low"), Ownership{}, 90, "low"},
		{"kev accelerates to critical", model.Finding{Asset: "a", VulnerabilityID: "CVE-1", Severity: "medium", CISAKEV: true}, Ownership{}, 7, "critical"},
		{"internet exposure raises one step", finding("a", "Ubuntu:24.04", "p", "1", "CVE-1", "medium"), Ownership{Exposure: "internet"}, 30, "high"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			due, sev := policy.DueAt(now, tc.f, tc.own)
			if due == nil {
				t.Fatalf("no deadline computed for %s", tc.sevIn)
			}
			if sev != tc.sevIn {
				t.Fatalf("effective severity = %q, want %q", sev, tc.sevIn)
			}
			want := now.AddDate(0, 0, tc.days)
			if !due.Equal(want) {
				t.Fatalf("due = %s, want %s", due, want)
			}
		})
	}

	t.Run("no window configured means no deadline", func(t *testing.T) {
		custom := DefaultPolicy()
		custom.Days = map[string]int{"critical": 0}
		if due, _ := custom.DueAt(now, finding("a", "Ubuntu:24.04", "p", "1", "CVE-1", "critical"), Ownership{}); due != nil {
			t.Fatalf("invented a deadline: %s", due)
		}
	})
}

// TestReconcileCreatesOwnedItems: a reconciled report produces one item per
// actionable finding, routed and scheduled.
func TestReconcileCreatesOwnedItems(t *testing.T) {
	st, now := newStore(t)
	if _, _, _, err := st.Reconcile(report("web01",
		finding("web01", "Ubuntu:24.04", "openssl", "3.0.1", "CVE-1", "critical"),
		finding("web01", "PyPI", "django", "4.2", "CVE-2", "medium"),
	), DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	items, err := st.List(context.Background(), Filter{}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2", len(items))
	}
	byVuln := map[string]Item{}
	for _, it := range items {
		byVuln[it.VulnerabilityID] = it
	}
	os := byVuln["CVE-1"]
	if os.Team != "Infrastructure" || os.State != StateAssigned || os.Priority != "P1" {
		t.Fatalf("os item = %+v", os)
	}
	if os.DueAt == nil || !os.DueAt.Equal(now.AddDate(0, 0, 7)) {
		t.Fatalf("critical due = %v", os.DueAt)
	}
	if byVuln["CVE-2"].Team != "Development" {
		t.Fatalf("dependency item team = %q", byVuln["CVE-2"].Team)
	}
}

// TestReconcileIsIdempotent: the same report twice creates nothing new; a later
// report updates the existing item rather than duplicating it.
func TestReconcileIsIdempotent(t *testing.T) {
	st, _ := newStore(t)
	rep := report("web01", finding("web01", "Ubuntu:24.04", "openssl", "3.0.1", "CVE-1", "high"))

	created, _, _, err := st.Reconcile(rep, DefaultPolicy())
	if err != nil || created != 1 {
		t.Fatalf("first reconcile created=%d err=%v", created, err)
	}
	created, updated, _, err := st.Reconcile(rep, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if created != 0 || updated != 1 {
		t.Fatalf("second reconcile created=%d updated=%d, want 0/1", created, updated)
	}
	items, _ := st.List(context.Background(), Filter{}, DefaultPolicy())
	if len(items) != 1 {
		t.Fatalf("duplicate items: %d", len(items))
	}
}

// TestReconcileSkipsNotAffectedAndUnidentified: evidence that is not actionable must
// not become work.
func TestReconcileSkipsNotAffectedAndUnidentified(t *testing.T) {
	st, _ := newStore(t)
	na := finding("web01", "Ubuntu:24.04", "openssl", "3", "CVE-1", "high")
	na.Affected = model.ApplicabilityNotAffected
	noID := finding("web01", "Ubuntu:24.04", "zlib", "1", "", "high")
	if _, _, _, err := st.Reconcile(report("web01", na, noID), DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	items, _ := st.List(context.Background(), Filter{}, DefaultPolicy())
	if len(items) != 0 {
		t.Fatalf("created %d items from non-actionable evidence", len(items))
	}
}

// TestUnassignedGoesToTriageThenAdoptsOwnership: an unknown asset waits for a human,
// and assigning an owner adopts the waiting items instead of leaving them stranded.
func TestUnassignedGoesToTriageThenAdoptsOwnership(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()
	if _, _, _, err := st.Reconcile(report("mystery", finding("mystery", "AcmeOS:1", "pkg", "1", "CVE-9", "high")), DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	items, _ := st.List(ctx, Filter{}, DefaultPolicy())
	if len(items) != 1 || items[0].State != StateAwaitingOwnership || items[0].Team != "" {
		t.Fatalf("unknown asset did not go to triage: %+v", items)
	}
	if _, err := st.SetOwnership(ctx, Ownership{Asset: "mystery", Team: "Linux Ops", Owner: "dana"}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Get(items[0].ID)
	if got.Team != "Linux Ops" || got.State != StateAssigned || got.Owner != "dana" {
		t.Fatalf("ownership not adopted: %+v", got)
	}
	// The triage queue is now empty.
	triage, _ := st.ListOwnership(ctx, true)
	if len(triage) != 0 {
		t.Fatalf("triage queue still has %d assets", len(triage))
	}
}

// TestWorkflowTransitions: legal moves are allowed, invented ones are refused, and
// nothing can be hand-marked resolved.
func TestWorkflowTransitions(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()
	if _, _, _, err := st.Reconcile(report("web01", finding("web01", "Ubuntu:24.04", "openssl", "3", "CVE-1", "high")), DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	items, _ := st.List(ctx, Filter{}, DefaultPolicy())
	id := items[0].ID

	next := StateInProgress
	if _, err := st.Update(ctx, id, Patch{State: &next}); err != nil {
		t.Fatalf("assigned -> in_progress: %v", err)
	}
	applied := StateApplied
	if _, err := st.Update(ctx, id, Patch{State: &applied}); err != nil {
		t.Fatalf("in_progress -> applied: %v", err)
	}
	// Skipping verification is rejected.
	resolved := StateResolved
	if _, err := st.Update(ctx, id, Patch{State: &resolved}); err == nil {
		t.Fatal("hand-resolving must be refused")
	}
	// An impossible edge is rejected.
	detected := StateDetected
	if _, err := st.Update(ctx, id, Patch{State: &detected}); err == nil {
		t.Fatal("applied -> detected must be refused")
	}
	// Verification is the only route to resolved.
	item, err := st.MarkVerified(ctx, id, "SCAN-2")
	if err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}
	if item.State != StateResolved {
		t.Fatalf("state = %s", item.State)
	}
	if _, err := st.MarkVerified(ctx, id, "SCAN-3"); err == nil {
		t.Fatal("resolving an already resolved item must be refused")
	}
}

// TestReappearanceReopensAResolvedItem: a closed item is reopened by evidence, not
// left silently resolved.
func TestReappearanceReopensAResolvedItem(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()
	rep := report("web01", finding("web01", "Ubuntu:24.04", "openssl", "3", "CVE-1", "high"))
	if _, _, _, err := st.Reconcile(rep, DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	items, _ := st.List(ctx, Filter{}, DefaultPolicy())
	// The legal path to "applied" goes through in_progress; the workflow is the
	// contract, so the test walks it rather than skipping a state.
	progress, applied, pending := StateInProgress, StateApplied, StatePendingVerification
	if _, err := st.Update(ctx, items[0].ID, Patch{State: &progress}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Update(ctx, items[0].ID, Patch{State: &applied}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Update(ctx, items[0].ID, Patch{State: &pending}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.MarkVerified(ctx, items[0].ID, "SCAN-2"); err != nil {
		t.Fatal(err)
	}
	// Same finding shows up again in a later report.
	later := report("web01", finding("web01", "Ubuntu:24.04", "openssl", "3", "CVE-1", "high"))
	later.ReportID = "SCAN-3"
	_, _, reopened, err := st.Reconcile(later, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if reopened != 1 {
		t.Fatalf("reopened = %d, want 1", reopened)
	}
	got, _ := st.Get(items[0].ID)
	if got.State != StateDetected {
		t.Fatalf("state = %s, want detected", got.State)
	}
	if !strings.Contains(got.Notes, "reopened") {
		t.Fatalf("reopen is not recorded: %q", got.Notes)
	}
}

// TestFalsePositiveStaysClosed: an analyst verdict must not be undone by a rescan.
func TestFalsePositiveStaysClosed(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()
	rep := report("web01", finding("web01", "Ubuntu:24.04", "openssl", "3", "CVE-1", "high"))
	if _, _, _, err := st.Reconcile(rep, DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	items, _ := st.List(ctx, Filter{}, DefaultPolicy())
	fp := StateFalsePositive
	if _, err := st.Update(ctx, items[0].ID, Patch{State: &fp}); err != nil {
		t.Fatal(err)
	}
	if _, _, reopened, err := st.Reconcile(rep, DefaultPolicy()); err != nil || reopened != 0 {
		t.Fatalf("reopened=%d err=%v", reopened, err)
	}
	if got, _ := st.Get(items[0].ID); got.State != StateFalsePositive {
		t.Fatalf("state = %s, want false_positive", got.State)
	}
}

// TestSummaryAndOverdue feeds the dashboard numbers from SQL.
func TestSummaryAndOverdue(t *testing.T) {
	st, now := newStore(t)
	ctx := context.Background()
	if _, _, _, err := st.Reconcile(report("web01",
		finding("web01", "Ubuntu:24.04", "openssl", "3", "CVE-1", "critical"),
		finding("web01", "PyPI", "django", "4", "CVE-2", "low"),
	), DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := st.Reconcile(report("mystery", finding("mystery", "Acme:1", "x", "1", "CVE-3", "high")), DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	sum, err := st.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Total != 3 || sum.Open != 3 || sum.Unassigned != 1 {
		t.Fatalf("summary = %+v", sum)
	}
	if sum.ByTeam["Infrastructure"] != 1 || sum.ByTeam["Development"] != 1 || sum.ByTeam["(unassigned)"] != 1 {
		t.Fatalf("by team = %+v", sum.ByTeam)
	}
	if sum.ByPriority["P1"] != 1 {
		t.Fatalf("by priority = %+v", sum.ByPriority)
	}
	// Move the clock past the critical window: the item is overdue, the others are not.
	*now = now.AddDate(0, 0, 8)
	overdue, err := st.List(ctx, Filter{Overdue: true}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if len(overdue) != 1 || overdue[0].VulnerabilityID != "CVE-1" {
		t.Fatalf("overdue = %+v", overdue)
	}
	sum, _ = st.Summary(ctx)
	if sum.Overdue != 1 {
		t.Fatalf("summary overdue = %d", sum.Overdue)
	}
}

// TestPolicyFromSettings: SLA windows and team overrides come from configuration,
// and malformed configuration falls back to the documented defaults.
func TestPolicyFromSettings(t *testing.T) {
	policy := PolicyFromSettings(map[string]string{
		"remediation.policy": `{"days":{"critical":1,"high":2,"medium":3,"low":4},"teams":{"os_package":"Linux Ops"}}`,
	})
	if policy.days()["critical"] != 1 || policy.teams()["os_package"] != "Linux Ops" {
		t.Fatalf("policy = %+v", policy)
	}
	if PolicyFromSettings(map[string]string{"remediation.policy": "{not json"}).Days["critical"] != 7 {
		t.Fatal("malformed policy must fall back to defaults")
	}
}

// TestOwnershipValidation rejects an ownership record with no asset.
func TestOwnershipValidation(t *testing.T) {
	st, _ := newStore(t)
	if _, err := st.SetOwnership(context.Background(), Ownership{Team: "x"}); err == nil {
		t.Fatal("ownership without an asset must be refused")
	}
}

// A team mapping that no finding can reach is configuration that looks enforced but
// never fires, which is worse than not having it: an operator reading DefaultTeams
// would believe accepted risks route to Security and source findings to Development.
func TestDefaultTeamsAreAllReachable(t *testing.T) {
	producible := map[string]model.Finding{
		"os_package":          {Ecosystem: "Ubuntu 22.04", VulnerabilityID: "CVE-2026-1"},
		"app_dependency":      {Ecosystem: "PyPI", VulnerabilityID: "CVE-2026-1"},
		"desktop_application": {Ecosystem: "Windows", Source: "NVD", VulnerabilityID: "CVE-2026-1"},
		"container_image":     {Ecosystem: "container-image", VulnerabilityID: "CVE-2026-1"},
		"cloud_config":        {Ecosystem: "terraform", VulnerabilityID: "CVE-2026-1"},
		"infrastructure":      {Ecosystem: "firmware", VulnerabilityID: "CVE-2026-1"},
	}
	for _, category := range []string{"os_package", "app_dependency", "desktop_application", "container_image", "cloud_config", "infrastructure"} {
		f, ok := producible[category]
		if !ok {
			t.Fatalf("category %q is in the routing model with no sample ecosystem to prove it", category)
		}
		if got := Category(f); got != category {
			t.Fatalf("Category(%+v) = %q, want %q", f, got, category)
		}
		if _, ok := DefaultTeams[category]; !ok {
			t.Fatalf("Classifiable category %q has no team in DefaultTeams", category)
		}
	}
	for category := range DefaultTeams {
		if _, ok := producible[category]; !ok {
			t.Fatalf("DefaultTeams has %q but no finding can ever be classified into it", category)
		}
	}
}

// The two teams that used to be unreachable now have signals, and ambiguous ecosystems
// still go to triage rather than to a guessed team.
func TestCategorySeparatesCloudAndFirmwareFromTriaged(t *testing.T) {
	cases := map[string]string{
		"Terraform":       "cloud_config",
		"Kubernetes":      "cloud_config",
		"AWS ECS":         "cloud_config",
		"Azure":           "cloud_config",
		"Firmware":        "infrastructure",
		"Linux kernel":    "infrastructure",
		"VMware ESXi":     "infrastructure",
		"NVD":             "", // a feed, not an ecosystem: a human decides
		"unknown-vendorx": "",
	}
	for eco, want := range cases {
		if got := Category(model.Finding{Ecosystem: eco, VulnerabilityID: "CVE-2026-2"}); got != want {
			t.Fatalf("Category(%q) = %q, want %q", eco, got, want)
		}
	}
}

// The inventory has to answer three questions in one row: is it owned, how much work is
// there, and is anything past its deadline. An asset with a record but no findings must
// stay visible, or the record cannot be edited after the finding is fixed.
func TestAssetOverviewMergesOwnershipWithWork(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()
	rep := model.Report{
		ReportID: "SCAN-1",
		Metadata: model.ScanMetadata{Host: "web01", Mode: "local"},
		Findings: []model.Finding{
			{Ecosystem: "Ubuntu", Product: "openssl", InstalledVersion: "3.0.1", VulnerabilityID: "CVE-1", Severity: "critical"},
			{Ecosystem: "Ubuntu", Product: "bash", InstalledVersion: "5.1", VulnerabilityID: "CVE-2", Severity: "low"},
			{Ecosystem: "NVD", Product: "openssh", InstalledVersion: "8.9", VulnerabilityID: "CVE-3", Severity: "high"},
		},
	}
	if _, _, _, err := st.Reconcile(rep, DefaultPolicy()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, err := st.SetOwnership(ctx, Ownership{Asset: "no-findings.example", Team: "Development"}); err != nil {
		t.Fatalf("SetOwnership: %v", err)
	}

	rows, err := st.AssetOverview(ctx)
	if err != nil {
		t.Fatalf("AssetOverview: %v", err)
	}
	byAsset := map[string]AssetRow{}
	for _, r := range rows {
		byAsset[r.Asset] = r
	}
	web, ok := byAsset["web01"]
	if !ok {
		t.Fatal("asset with findings is missing from the inventory")
	}
	if web.Items != 3 || web.Open != 3 {
		t.Fatalf("web01 items/open = %d/%d, want 3/3", web.Items, web.Open)
	}
	if web.Critical != 1 {
		t.Fatalf("web01 critical = %d, want 1", web.Critical)
	}
	if !web.Triaged {
		t.Fatal("web01 has an unroutable finding, so it must be marked triaged")
	}
	// The OS packages route by mapping even though nobody accepted the asset: the
	// inventory must be able to show both facts without presenting one as the other.
	if len(web.RoutedTeams) != 1 || web.RoutedTeams[0] != "Infrastructure" {
		t.Fatalf("routed teams = %v, want [Infrastructure]", web.RoutedTeams)
	}
	// The NVD finding has no ecosystem, so the asset keeps one unowned item even after
	// the OS packages are routed by the mapping.
	if web.Team != "" {
		t.Fatalf("no ownership recorded, team = %q", web.Team)
	}
	if _, ok := byAsset["no-findings.example"]; !ok {
		t.Fatal("an asset with an ownership record but no findings disappeared from the inventory")
	}
	if got := byAsset["no-findings.example"]; got.Items != 0 || got.Triaged {
		t.Fatalf("record-only asset = %+v, want 0 items and not triaged", got)
	}
}

// The sweep is what makes an exception temporary: past its date the finding comes back
// instead of disappearing.
func TestExpiredAcceptanceReopensTheFinding(t *testing.T) {
	st, clock := newStore(t)
	ctx := context.Background()
	item := Item{
		ID: "REM-1", Asset: "web01", FindingKey: "k1", VulnerabilityID: "CVE-2026-1",
		Product: "openssl", InstalledVersion: "1.0", Ecosystem: "Ubuntu", Severity: "high",
		State: StateAssigned, Priority: "P2", FirstSeen: *clock, LastSeen: *clock, UpdatedAt: *clock,
	}
	if err := st.insert(item); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := st.AcceptRisk(ctx, item.ID, "waiting on the vendor patch window", "dana", clock.AddDate(0, 0, 10)); err != nil {
		t.Fatalf("AcceptRisk: %v", err)
	}
	// Nothing due yet.
	if expired, err := st.ExpireAcceptances(ctx); err != nil || len(expired) != 0 {
		t.Fatalf("premature expiry: %v %v", expired, err)
	}
	*clock = clock.AddDate(0, 0, 11)
	expired, err := st.ExpireAcceptances(ctx)
	if err != nil {
		t.Fatalf("ExpireAcceptances: %v", err)
	}
	if len(expired) != 1 || expired[0].State != StateDetected {
		t.Fatalf("expired = %+v, want the item reopened as detected", expired)
	}
	got, _ := st.Get(item.ID)
	if got.AcceptReason != "" || got.AcceptExpiresAt != nil {
		t.Fatalf("cleared acceptance still carries its fields: %+v", got)
	}
}

// Work is per upgrade, not per finding: three findings closed by one package update are one
// unit, and the earliest deadline in the group is the unit's deadline.
func TestGroupsFoldFindingsIntoOneRemediationUnit(t *testing.T) {
	st, clock := newStore(t)
	ctx := context.Background()
	rep := model.Report{
		ReportID: "SCAN-G-1",
		Metadata: model.ScanMetadata{Host: "web01", Mode: "local"},
		Findings: []model.Finding{
			{Ecosystem: "Ubuntu", Product: "openssl", InstalledVersion: "3.0.1", VulnerabilityID: "CVE-1", Severity: "high", FixedVersion: "3.0.13"},
			{Ecosystem: "Ubuntu", Product: "openssl", InstalledVersion: "3.0.1", VulnerabilityID: "CVE-2", Severity: "critical", FixedVersion: "3.0.13"},
			{Ecosystem: "Ubuntu", Product: "openssl", InstalledVersion: "3.0.1", VulnerabilityID: "CVE-3", Severity: "medium", FixedVersion: "3.0.13"},
			{Ecosystem: "Ubuntu", Product: "bash", InstalledVersion: "5.1", VulnerabilityID: "CVE-4", Severity: "low", FixedVersion: "5.2"},
			{Ecosystem: "Ubuntu", Product: "tar", InstalledVersion: "1.34", VulnerabilityID: "CVE-5", Severity: "medium", FixedVersion: ""},
		},
	}
	if _, _, _, err := st.Reconcile(rep, DefaultPolicy()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	groups, err := st.Groups(ctx, DefaultPolicy())
	if err != nil {
		t.Fatalf("Groups: %v", err)
	}
	// openssl, bash and tar: three units, not five findings.
	if len(groups) != 3 {
		t.Fatalf("groups = %d, want 3: %+v", len(groups), groups)
	}
	var openssl Group
	for _, g := range groups {
		if g.Product == "openssl" {
			openssl = g
		}
	}
	if openssl.Items != 3 || len(openssl.Advisories) != 3 {
		t.Fatalf("openssl group = %+v", openssl)
	}
	// The group carries the worst severity, so it is not sorted by the mildest member.
	if openssl.Severity != "critical" {
		t.Fatalf("group severity = %q, want critical", openssl.Severity)
	}
	_ = clock
}

// Desktop applications group into ONE remediation unit even when each CVE
// names a different fixed version: the remedy is the same action (upgrade the
// application to the newest vendor-supported version), so it must be one
// ticket, not one per CVE.
func TestDesktopApplicationFindingsFoldIntoOneUpgrade(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()
	rep := model.Report{
		ReportID: "SCAN-APP-1",
		Metadata: model.ScanMetadata{Host: "win01", Mode: "local"},
		Findings: []model.Finding{
			{Ecosystem: "Windows", Source: "NVD", Product: "google/chrome", InstalledVersion: "120.0.6099.109",
				VulnerabilityID: "CVE-2024-0519", Severity: "high", FixedVersion: "120.0.6099.224"},
			{Ecosystem: "Windows", Source: "NVD", Product: "google/chrome", InstalledVersion: "120.0.6099.109",
				VulnerabilityID: "CVE-2024-4671", Severity: "critical", FixedVersion: "124.0.6367.201"},
			{Ecosystem: "Windows", Source: "NVD", Product: "mozilla/firefox", InstalledVersion: "123.0",
				VulnerabilityID: "CVE-2024-1546", Severity: "medium", FixedVersion: "124.0"},
		},
	}
	if _, _, _, err := st.Reconcile(rep, DefaultPolicy()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	groups, err := st.Groups(ctx, DefaultPolicy())
	if err != nil {
		t.Fatalf("Groups: %v", err)
	}
	// Two applications: two remediation units, not three CVE-sized tickets.
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2: %+v", len(groups), groups)
	}
	for _, g := range groups {
		switch g.Product {
		case "google/chrome":
			if g.Items != 2 || len(g.Advisories) != 2 {
				t.Fatalf("chrome group = %+v", g)
			}
			// The highest fixed version wins: upgrading once satisfies both.
			if g.FixedVersion != "124.0.6367.201" {
				t.Fatalf("chrome group fixed version = %q, want the highest (124.0.6367.201)", g.FixedVersion)
			}
			if g.Severity != "critical" {
				t.Fatalf("chrome group severity = %q, want critical", g.Severity)
			}
		case "mozilla/firefox":
			if g.Items != 1 {
				t.Fatalf("firefox group = %+v", g)
			}
		default:
			t.Fatalf("unexpected group %+v", g)
		}
	}
}

// The full application lifecycle: detected → fixed → rescan → resolved, and a
// reappearing vulnerability reopens the item instead of staying resolved.
func TestDesktopApplicationLifecycle(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()
	finding := model.Finding{
		Ecosystem: "Windows", Source: "NVD", Product: "google/chrome", InstalledVersion: "120.0.6099.109",
		VulnerabilityID: "CVE-2024-0519", Severity: "high", FixedVersion: "120.0.6099.224",
	}
	rep1 := model.Report{ReportID: "S1", Metadata: model.ScanMetadata{Host: "win01"}, Findings: []model.Finding{finding}}
	if _, _, _, err := st.Reconcile(rep1, DefaultPolicy()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	items, err := st.List(ctx, Filter{}, DefaultPolicy())
	if err != nil || len(items) != 1 {
		t.Fatalf("items: %d %v", len(items), err)
	}
	// The application is upgraded: the next report no longer contains the
	// finding, so reconciliation marks it resolved — verified by the rescan.
	resolved, err := st.ReconcileAbsences(ctx, "S2", []string{"win01"}, DefaultPolicy())
	if err != nil {
		t.Fatalf("ReconcileAbsences: %v", err)
	}
	if len(resolved) != 1 || resolved[0].State != StatePendingVerification {
		t.Fatalf("upgrade + rescan must move the item to pending verification: %+v", resolved)
	}
	// The operator independently verifies the fix against the rescan report.
	verified, err := st.MarkVerified(ctx, resolved[0].ID, "S2")
	if err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}
	if verified.State != StateResolved || verified.VerifiedReport != "S2" {
		t.Fatalf("resolution must carry the verifying report: %+v", verified)
	}
	// Reappearance: a later scan reports it again (rollback, another install).
	var reopens int
	if _, _, n, err := st.Reconcile(rep1, DefaultPolicy()); err != nil {
		t.Fatal(err)
	} else {
		reopens = n
	}
	if reopens != 1 {
		t.Fatalf("reappearing vulnerability must reopen the item, reopened=%d", reopens)
	}
	items, _ = st.List(ctx, Filter{}, DefaultPolicy())
	if items[0].State != StateDetected {
		t.Fatalf("state after reappearance = %s, want detected", items[0].State)
	}
	if !strings.Contains(items[0].Notes, "reopened") {
		t.Fatalf("reopen must preserve history in notes: %+v", items[0])
	}
}

// Business criticality changes how soon work is picked up, never what the severity says.
func TestCriticalAssetsArePrioritisedWithoutInflatingSeverity(t *testing.T) {
	policy := DefaultPolicy()
	f := model.Finding{Severity: "medium", VulnerabilityID: "CVE-9"}
	plain := Ownership{}
	critical := Ownership{Status: "owned", Team: "Platform", Criticality: "critical"}

	if got := policy.Priority(f, plain); got != "P3" {
		t.Fatalf("plain medium priority = %q, want P3", got)
	}
	if got := policy.Priority(f, critical); got != "P2" {
		t.Fatalf("critical-asset medium priority = %q, want P2", got)
	}
	// The severity itself is unchanged: severity describes the vulnerability, priority
	// describes when this organisation gets to it.
	if got := policy.EffectiveSeverity(f, critical); got != "medium" {
		t.Fatalf("effective severity = %q, want medium", got)
	}
}

// An existing database must gain the access columns on open. The bug this pins: the columns
// were added to the wrong table, so every ownership write failed with "no column named
// ssh_user" only on databases created before the feature existed.
func TestOpenMigratesAssetOwnerAccessColumns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intel.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// The schema as it existed before access details were added.
	legacy := `CREATE TABLE asset_owners (
		asset TEXT PRIMARY KEY, team TEXT NOT NULL DEFAULT '', owner TEXT NOT NULL DEFAULT '',
		service TEXT NOT NULL DEFAULT '', environment TEXT NOT NULL DEFAULT '',
		criticality TEXT NOT NULL DEFAULT '', exposure TEXT NOT NULL DEFAULT '',
		contact TEXT NOT NULL DEFAULT '', mechanism TEXT NOT NULL DEFAULT '',
		maintenance_window TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'manual',
		status TEXT NOT NULL DEFAULT 'owned', updated_at TEXT NOT NULL
	);`
	if _, err := db.Exec(legacy); err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, err := New(db2Open(t, path))
	if err != nil {
		t.Fatalf("New on legacy database: %v", err)
	}
	own, err := st.SetOwnership(context.Background(), Ownership{
		Asset: "web01", Team: "Infrastructure", SSHUser: "deploy", SSHJump: "bastion.prod",
		RunbookURL: "https://wiki.example/x",
	})
	if err != nil {
		t.Fatalf("SetOwnership after migration: %v", err)
	}
	if own.SSHUser != "deploy" || own.SSHJump != "bastion.prod" {
		t.Fatalf("access fields not stored: %+v", own)
	}
	got, err := st.Ownership("web01")
	if err != nil {
		t.Fatalf("Ownership: %v", err)
	}
	if got.SSHUser != "deploy" || got.RunbookURL != "https://wiki.example/x" {
		t.Fatalf("access fields not read back: %+v", got)
	}
}

// db2Open opens a database file with the same pragmas the store uses.
func db2Open(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}
