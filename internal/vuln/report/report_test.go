package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

func fixtureReport() model.Report {
	now := time.Now().UTC()
	finished := now.Add(time.Minute)
	findings := []model.Finding{
		{
			FindingID: "FINDING-0001", Asset: "host1", Product: "openssl", InstalledVersion: "3.0.11-1",
			Ecosystem: "Debian:12", VulnerabilityID: "CVE-2023-5678", Aliases: []string{"CVE-2023-5678"},
			Source: "Debian", Affected: model.ApplicabilityConfirmed, Confidence: model.ConfidenceHigh,
			Severity: "high", CISAKEV: true, FixedVersion: "3.0.13-1~deb12u1", RiskScore: 78.5,
			Explanation: "Installed version is inside the affected range.", Remediation: "Upgrade openssl.",
			Evidence:       []model.Evidence{{Kind: "installed_version", Detail: "openssl 3.0.11-1 installed"}},
			VendorAdvisory: &model.VendorAdvisory{Vendor: "Debian", URL: "https://example.invalid/adv"},
			CVSS:           &model.CVSS{Score: 7.5, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
			EPSS:           &model.EPSS{Score: 0.42, Percentile: 0.97},
		},
		{
			FindingID: "FINDING-0002", Asset: "host1", Product: "bash", InstalledVersion: "5.2-1",
			Ecosystem: "Debian:12", VulnerabilityID: "CVE-2024-0001", Source: "OSV",
			Affected: model.ApplicabilityNeedsInvestigation, Confidence: model.ConfidenceLow,
			Severity: "unknown", RiskScore: 2,
			Explanation: "Advisory enumeration does not cover this build.", Remediation: "Investigate manually.",
		},
	}
	return Build(BuildOptions{
		ToolVersion: "0.1.0",
		Mode:        "local",
		Inventory: model.Inventory{
			Asset:    model.Asset{Hostname: "host1", OS: "Debian 12", OSVersion: "12", Kernel: "6.1.0", Arch: "amd64"},
			Packages: []model.Package{{Name: "openssl", Version: "3.0.11-1", Ecosystem: "Debian:12"}},
			Skipped:  []model.SkippedCheck{{Check: "ruby_gems", Reason: "gem not found"}},
		},
		Findings: findings,
		Started:  now,
		Finished: finished,
		Policy:   model.Policy{FailOnSeverity: "high"},
		Coverage: model.Coverage{Sources: []string{"OSV", "CISA KEV", "EPSS"}, PackagesInspected: 2},
		ReportID: "SCAN-TEST",
	})
}

func TestBuildSummaryAndSchema(t *testing.T) {
	rep := fixtureReport()
	if rep.Summary.Total != 2 || rep.Summary.Actionable != 1 || rep.Summary.KEVCount != 1 {
		t.Fatalf("summary wrong: %+v", rep.Summary)
	}
	if rep.Summary.BySeverity["high"] != 1 || rep.Summary.BySeverity["unknown"] != 1 {
		t.Fatalf("severity buckets wrong: %+v", rep.Summary.BySeverity)
	}

	var buf bytes.Buffer
	if err := Render(&buf, rep, "json"); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	for _, key := range []string{"schema_version", "report_id", "metadata", "inventory", "findings", "summary"} {
		if _, ok := doc[key]; !ok {
			t.Fatalf("report missing required key %q", key)
		}
	}
	findings := doc["findings"].([]any)
	f0 := findings[0].(map[string]any)
	// The documented finding contract.
	for _, key := range []string{
		"finding_id", "asset", "product", "installed_version", "ecosystem", "vulnerability_id",
		"source", "affected", "validation_status", "confidence", "severity", "cvss",
		"epss", "cisa_kev", "evidence", "vendor_advisory", "fixed_version", "remediation", "last_checked",
	} {
		if _, ok := f0[key]; !ok {
			t.Fatalf("finding missing required key %q", key)
		}
	}
	meta := doc["metadata"].(map[string]any)
	for _, key := range []string{"tool_version", "started_at", "mode", "offline", "coverage", "policy", "skipped_checks"} {
		if _, ok := meta[key]; !ok {
			t.Fatalf("metadata missing required key %q", key)
		}
	}
}

func TestRenderMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, fixtureReport(), "markdown"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"# Clanker Guard assessment", "## Executive summary", "## Coverage", "## Findings",
		"CVE-2023-5678", "Known exploited", "does **not** mean the asset is free of vulnerabilities",
		"gem not found", "Why this classification",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("markdown missing %q\n---\n%s", want, out)
		}
	}
}

func TestRenderSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, fixtureReport(), "sarif"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Fatalf("unexpected SARIF envelope: %+v", doc)
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "clanker-guard" || len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("unexpected SARIF tool/rules: %+v", run.Tool)
	}
	if len(run.Results) != 2 || run.Results[0].Level != "error" {
		t.Fatalf("unexpected SARIF results: %+v", run.Results)
	}
}

func TestRenderHTML(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, fixtureReport(), "html"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "<title>Clanker Guard") || !strings.Contains(out, "CVE-2023-5678") {
		t.Fatalf("html output incomplete")
	}
	if strings.Contains(out, "<script>") {
		t.Fatal("report HTML must not embed scripts")
	}
}

func TestRenderRejectsUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, fixtureReport(), "pdf"); err == nil {
		t.Fatal("unsupported format must return an error, not silently fall back")
	}
}

func TestExitCodePolicy(t *testing.T) {
	rep := fixtureReport()
	if code := ExitCode(rep, false); code != 2 {
		t.Fatalf("expected policy failure (2) with a high finding, got %d", code)
	}
	rep.Metadata.Policy = model.Policy{FailOnSeverity: "critical"}
	if code := ExitCode(rep, false); code != 0 {
		t.Fatalf("expected 0 when only high findings exist under a critical policy, got %d", code)
	}
	rep.Metadata.Policy = model.Policy{FailOnKEV: true}
	if code := ExitCode(rep, false); code != 2 {
		t.Fatalf("expected 2 for KEV policy, got %d", code)
	}
	if code := ExitCode(rep, true); code != 4 {
		t.Fatalf("incomplete assessment must return 4, got %d", code)
	}
	// needs_investigation findings must never fail a policy gate on their own
	rep2 := fixtureReport()
	rep2.Findings = []model.Finding{{
		FindingID: "FINDING-0001", Severity: "critical", Affected: model.ApplicabilityNeedsInvestigation,
	}}
	rep2.Metadata.Policy = model.Policy{FailOnSeverity: "low"}
	if code := ExitCode(rep2, false); code != 0 {
		t.Fatalf("unresolved findings must not fail the gate, got %d", code)
	}
}

func TestDelta(t *testing.T) {
	rep := fixtureReport()
	prev := &model.RunRecord{ID: "SCAN-PREV", FindingIDs: []string{"stale-fingerprint"}}
	rep2 := Build(BuildOptions{
		Inventory: rep.Inventory, Findings: rep.Findings, Started: time.Now(), Previous: prev, ReportID: "SCAN-NEW",
	})
	if rep2.Delta == nil {
		t.Fatal("delta missing")
	}
	if len(rep2.Delta.NewFindings) != 2 {
		t.Fatalf("expected 2 new findings, got %d", len(rep2.Delta.NewFindings))
	}
	if len(rep2.Delta.ResolvedFindings) != 1 {
		t.Fatalf("expected 1 resolved finding, got %d", len(rep2.Delta.ResolvedFindings))
	}
}
