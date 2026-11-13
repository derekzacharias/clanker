package improve_test

// This test lives in an external package because it exercises the scanner, which
// itself imports the improvement engine (the scanner loads the deployed rule).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/improve"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/inventory"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
)

const snapCVE = "CVE-2022-25236"

func snapFinding() improve.FindingRef {
	return improve.FindingRef{
		ID: "abc123", ReportID: "SCAN-1", Host: "host1", CVE: snapCVE,
		AdvisoryID: "UBUNTU-" + snapCVE, Product: "thunderbird", Version: "2:1snap1-0ubuntu3",
		Ecosystem: "Ubuntu:24.04:LTS", Severity: "high",
		Applicability: string(model.ApplicabilityConfirmed), Confidence: "high",
	}
}

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"etc", "var/lib/dpkg"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	osRelease := "PRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n"
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(osRelease), 0o644); err != nil {
		t.Fatal(err)
	}
	status := "Package: thunderbird\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2:1snap1-0ubuntu3\n"
	if err := os.WriteFile(filepath.Join(root, "var/lib/dpkg/status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// TestDeployedRuleChangesScanOutput is the acceptance-criteria proof: same host,
// same advisory, different reported classification, attributable to one rule.
func TestDeployedRuleChangesScanOutput(t *testing.T) {
	ctx := context.Background()
	cachePath := filepath.Join(t.TempDir(), "intel.db")

	store, err := intel.OpenStore(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	snap := intel.Advisory{
		ID: "UBUNTU-" + snapCVE, Source: "Ubuntu",
		References: []intel.Reference{{Type: "ADVISORY", URL: "https://ubuntu.com/security/" + snapCVE}},
		Affected: []intel.Affected{{
			Ecosystem: "Ubuntu:24.04:LTS", Name: "thunderbird",
			Versions: []string{"1snap1-0ubuntu2", "1snap1-0ubuntu3"},
			Binaries: []intel.Binary{{Name: "thunderbird", Version: "2:1snap1-0ubuntu3"}},
		}},
		FetchedAt: time.Now().UTC(),
	}
	if err := store.SaveAdvisories(ctx, []intel.Advisory{snap}); err != nil {
		t.Fatal(err)
	}
	eng, err := improve.New(store)
	if err != nil {
		t.Fatal(err)
	}
	eng.Now(func() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) })

	runScan := func() model.Report {
		res, err := scan.Run(context.Background(), scan.Options{
			Root:       fixtureRoot(t),
			CachePath:  cachePath,
			Offline:    true,
			Format:     "json",
			SkipRender: true,
			Collectors: []inventory.Collector{&inventory.OSPackageCollector{}},
			Stderr:     discard{},
			Now:        func() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) },
		})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		return res.Report
	}

	before := runScan()
	if len(before.Findings) != 1 {
		t.Fatalf("expected one finding before the rule, got %d", len(before.Findings))
	}
	if before.Findings[0].Affected != model.ApplicabilityConfirmed {
		t.Fatalf("baseline should confirm the snap stub, got %s", before.Findings[0].Affected)
	}

	if _, err := eng.ApplyFeedback(ctx, improve.Feedback{
		Finding: snapFinding(), Verdict: improve.VerdictFalsePositive,
		ReasonCode: improve.ReasonIdentification, Analyst: "derek",
	}); err != nil {
		t.Fatal(err)
	}
	imps, err := eng.Analyze(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(imps) != 1 {
		t.Fatalf("expected a proposal, got %d", len(imps))
	}
	id := imps[0].ID
	if _, err := eng.Transition(ctx, id, improve.StatusApproved, "derek", "fixtures reviewed"); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Transition(ctx, id, improve.StatusDeployed, "derek", "deployed"); err != nil {
		t.Fatal(err)
	}

	after := runScan()
	if len(after.Findings) != 1 {
		t.Fatalf("the finding must not disappear (detection preservation), got %d", len(after.Findings))
	}
	if after.Findings[0].Affected != model.ApplicabilityNeedsInvestigation {
		t.Fatalf("deployed rule should downgrade the snap stub, got %s", after.Findings[0].Affected)
	}
	if !strings.Contains(strings.Join(after.Metadata.DetectionPolicy, " "), "snap stub") {
		t.Fatalf("report must record the detection policy: %v", after.Metadata.DetectionPolicy)
	}

	if _, err := eng.Transition(ctx, id, improve.StatusRolledBack, "derek", "rollback test"); err != nil {
		t.Fatal(err)
	}
	restored := runScan()
	if restored.Findings[0].Affected != model.ApplicabilityConfirmed {
		t.Fatalf("rollback should restore the baseline classification, got %s", restored.Findings[0].Affected)
	}
	store.Close()
}
