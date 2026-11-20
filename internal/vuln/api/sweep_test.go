package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/report"
)

// A report that lists the same package twice (dpkg + distro-managed Python path) must not leave
// a work item telling anyone to upgrade it with pip.
func TestSweepClosesDistroPythonDuplicates(t *testing.T) {
	srv := fleetServer(t)
	now := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	rep := model.Report{
		SchemaVersion: "1",
		ReportID:      "SCAN-DUP-1",
		Metadata:      model.ScanMetadata{ToolVersion: "test", StartedAt: now, FinishedAt: &now, Mode: "local", Host: "web01"},
		Inventory: model.Inventory{
			Asset: model.Asset{Hostname: "web01", OS: "Ubuntu", OSVersion: "22.04"},
			Packages: []model.Package{
				{Name: "python3-jwt", Version: "2.3.0-1ubuntu0.6", Ecosystem: "Ubuntu:22.04:LTS", Source: model.OriginDpkg},
				{Name: "PyJWT", Version: "2.3.0", Ecosystem: model.EcosystemPyPI, Source: model.OriginPip,
					Origin: "/usr/lib/python3/dist-packages/PyJWT-2.3.0.egg-info"},
			},
		},
		Findings: []model.Finding{
			{FindingID: "F1", Asset: "web01", Product: "PyJWT", InstalledVersion: "2.3.0", Ecosystem: model.EcosystemPyPI,
				VulnerabilityID: "CVE-2022-29217", Severity: "high", Affected: model.ApplicabilityConfirmed},
			{FindingID: "F2", Asset: "web01", Product: "python3-jwt", InstalledVersion: "2.3.0-1ubuntu0.6",
				Ecosystem: "Ubuntu:22.04:LTS", VulnerabilityID: "CVE-2022-29217", Severity: "high", Affected: model.ApplicabilityConfirmed},
		},
	}
	payload, err := report.MarshalJSON(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.store.SaveRun(t.Context(), model.RunRecord{
		ID: rep.ReportID, Host: "web01", StartedAt: now, FinishedAt: now, FindingCount: 2, Actionable: 2,
	}, payload); err != nil {
		t.Fatal(err)
	}
	// The work items as they were created before suppression existed.
	if _, _, _, err := srv.remediate.Reconcile(rep, srv.currentPolicy(nil)); err != nil {
		t.Fatal(err)
	}
	var before struct {
		Items []struct {
			ID      string `json:"id"`
			Product string `json:"product"`
			State   string `json:"state"`
		} `json:"items"`
	}
	dashGet(t, srv.Handler(), "/api/remediation?asset=web01", &before)
	if len(before.Items) != 2 {
		t.Fatalf("setup: items = %+v", before.Items)
	}

	srv.sweepDistroPythonDuplicates(t.Context())

	var after struct {
		Items []struct {
			Product string `json:"product"`
			State   string `json:"state"`
			Notes   string `json:"notes"`
		} `json:"items"`
	}
	dashGet(t, srv.Handler(), "/api/remediation?asset=web01", &after)
	for _, it := range after.Items {
		if it.Product == "PyJWT" {
			if it.State != "false_positive" {
				t.Fatalf("duplicate still open: %+v", it)
			}
			if it.Notes == "" {
				t.Fatal("superseded item has no explanation")
			}
		}
		if it.Product == "python3-jwt" && it.State == "false_positive" {
			t.Fatalf("the OS package was closed by mistake: %+v", it)
		}
	}

	// The decision is in the diary.
	var audit struct {
		Items []struct {
			Action string `json:"action"`
		} `json:"items"`
	}
	dashGet(t, srv.Handler(), "/api/audit?action=remediation.superseded", &audit)
	if len(audit.Items) != 1 {
		t.Fatalf("audit = %+v", audit.Items)
	}
	_ = json.Marshal
}
