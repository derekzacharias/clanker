package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/remediate"
	"github.com/bgdnvk/clanker/internal/vuln/report"
)

// The restore drill, as a test: write real data, snapshot it, verify the snapshot, install
// it somewhere else, and confirm the server's own code can read it back. A backup that has
// never been restored is a hope.
func TestBackupVerifyRestoreRoundTrip(t *testing.T) {
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "intel.db")
	st, err := intel.OpenStore(src)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	rep := model.Report{
		SchemaVersion: report.SchemaVersion,
		ReportID:      "SCAN-1",
		Metadata:      model.ScanMetadata{ToolVersion: "t", StartedAt: now, FinishedAt: &now, Mode: "local", Host: "web01"},
		Findings: []model.Finding{{
			Asset: "web01", Ecosystem: "Ubuntu", Product: "openssl", InstalledVersion: "3.0.1",
			VulnerabilityID: "CVE-2026-1", Severity: "high", Affected: model.ApplicabilityConfirmed,
		}},
	}
	payload, err := report.MarshalJSON(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveRun(context.Background(), model.RunRecord{
		ID: rep.ReportID, Host: "web01", StartedAt: now, FinishedAt: now, FindingCount: 1, Actionable: 1,
	}, payload); err != nil {
		t.Fatalf("SaveRun: %v", err)
	}
	if err := st.AppendAudit(context.Background(), intel.AuditEntry{At: now.Format(time.RFC3339), Action: "test", Actor: "tester"}); err != nil {
		t.Fatal(err)
	}
	rem, err := remediate.New(st.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := rem.Reconcile(rep, remediate.DefaultPolicy()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	st.Close()

	// 1. Snapshot.
	backups := t.TempDir()
	dst := filepath.Join(backups, "snapshot.db")
	st2, err := intel.OpenStore(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.BackupTo(context.Background(), dst); err != nil {
		st2.Close()
		t.Fatalf("BackupTo: %v", err)
	}
	st2.Close()
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode = %#o, want 0600", info.Mode().Perm())
	}

	// 2. Verify — the same checks the CLI runs.
	if err := verifySnapshot(dst); err != nil {
		t.Fatalf("verifySnapshot: %v", err)
	}

	// 3. Restore into a fresh location and read it with the real store.
	restored := filepath.Join(t.TempDir(), "restored.db")
	if err := copyFile(dst, restored); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	if err := os.Chmod(restored, 0o600); err != nil {
		t.Fatal(err)
	}
	back, err := intel.OpenStore(restored)
	if err != nil {
		t.Fatalf("open restored: %v", err)
	}
	defer back.Close()
	if _, rep, err := back.LatestReportFor(context.Background(), "web01"); err != nil || rep.ReportID != "SCAN-1" {
		t.Fatalf("restored report = %+v, %v", rep, err)
	}
	items, err := remediate.New(back.DB())
	if err != nil {
		t.Fatal(err)
	}
	groups, err := items.Groups(context.Background(), remediate.DefaultPolicy())
	if err != nil || len(groups) != 1 {
		t.Fatalf("restored remediation = %+v, %v", groups, err)
	}
	audit, err := back.ListAudit(context.Background(), 10, "", "")
	if err != nil || len(audit) != 1 {
		t.Fatalf("restored audit = %+v, %v", audit, err)
	}
}

// A snapshot without assessments is not a backup, and verifying must say so rather than
// reporting "ok" because the file opens.
func TestVerifyRejectsAnEmptyOrBrokenSnapshot(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.db")
	st, err := intel.OpenStore(empty)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := verifySnapshot(empty); err == nil {
		t.Fatal("an empty database passed verification")
	}

	garbage := filepath.Join(dir, "garbage.db")
	if err := os.WriteFile(garbage, []byte("this is not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySnapshot(garbage); err == nil {
		t.Fatal("a non-database passed verification")
	}
	if err := verifySnapshot(filepath.Join(dir, "missing.db")); err == nil {
		t.Fatal("a missing file passed verification")
	}
}
