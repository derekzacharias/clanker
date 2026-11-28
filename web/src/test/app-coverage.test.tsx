import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import Vulnerabilities from "../pages/Vulnerabilities";
import Overview from "../pages/Overview";
import AssetDetail from "../pages/AssetDetail";
import { mockApi } from "./helpers";

const appVulnFixture = {
  total: 1,
  items: [
    {
      id: "vuln-app-1",
      finding_id: "FINDING-0100",
      report_id: "SCAN-APP",
      cve: "CVE-2024-0519",
      asset: "win01",
      product: "google/chrome",
      installed_version: "120.0.6099.109",
      ecosystem: "Windows",
      severity: "high",
      affected: "confirmed_applicability",
      confidence: "high",
      validation_status: "version_correlation",
      kev: true,
      epss: 0.5,
      epss_percentile: 0.9,
      cvss: 8.8,
      fixed_version: "120.0.6099.224",
      remediation: "Upgrade google/chrome to 120.0.6099.224 or later, then rescan.",
      source: "NVD",
      advisory_id: "CVE-2024-0519",
      risk_score: 61.2,
      first_seen: "2026-11-01T00:00:00Z",
      last_seen: "2026-11-13T00:00:00Z",
      explanation: "NVD's own applicability data matches the installed version.",
      evidence: [{ kind: "nvd_cpe_match", detail: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*" }],
      references: [{ label: "NVD", url: "https://nvd.nist.gov/vuln/detail/CVE-2024-0519" }],
      risk_factors: [{ name: "cisa_kev", weight: 30, detail: "listed in KEV" }],
      package_ref: "Google Chrome (64-bit)@120.0.6099.109",
    },
  ],
  facets: {
    severity: [
      { key: "critical", count: 0 },
      { key: "high", count: 1 },
      { key: "medium", count: 0 },
      { key: "low", count: 0 },
      { key: "unknown", count: 0 },
    ],
    applicability: [{ key: "confirmed_applicability", count: 1 }],
    assets: [{ key: "win01", count: 1 }],
    category: [{ key: "application", count: 1 }],
    kev: 1,
    fix_available: 1,
  },
  applied: {},
};

const overviewFixture = {
  has_data: true,
  metrics: {
    assets: 1,
    critical: 0,
    high: 1,
    medium: 0,
    low: 0,
    kev: 1,
    actionable: 1,
    needs_investigation: 0,
    total: 1,
    app_findings: 1,
    app_actionable: 1,
    app_kev: 1,
    os_findings: 0,
    os_actionable: 0,
  },
  severity: [
    { key: "critical", count: 0 },
    { key: "high", count: 1 },
  ],
  priority: [],
  coverage: { assessed: 1, stale: 0, failed_recent: 0, stale_after_days: 14, last_scan_at: "2026-11-13T12:00:00Z" },
  apps: { apps_discovered: 2, apps_evaluated: 1, apps_unmapped: 1, apps_with_findings: 1, nvd_missing: 0 },
  activity: [],
  feeds: [{ source: "NVD CVEs", last_sync: "2026-11-13T12:00:00Z", records: 250000, stale: false }],
  limitations: [],
  errors: [],
  improvements_available: 0,
  reviewed_findings: 0,
};

const assetFixture = {
  host: "win01",
  asset: { hostname: "win01", os: "Windows", os_version: "11", arch: "x64" },
  report_id: "SCAN-APP",
  last_scan: "2026-11-13T12:00:00Z",
  mode: "local",
  offline: false,
  agent: { version: "test", last_scan: "2026-11-13T12:00:00Z" },
  packages: [
    {
      name: "Google Chrome (64-bit)",
      version: "120.0.6099.109",
      ecosystem: "Windows",
      source: "manifest",
      publisher: "Google LLC",
      evidence_sources: ["registry/machine/x64", "winget"],
    },
  ],
  package_count: 1,
  packages_truncated: false,
  findings: [appVulnFixture.items[0]],
  coverage: {
    packages_inspected: 1,
    packages_matched: 0,
    advisories_checked: 1,
    sources_used: ["NVD CVE/CPE dataset"],
    notes: ["1 installed applications discovered; 1 evaluated"],
    apps: {
      discovered: 1,
      normalized: 1,
      mapped: 1,
      evaluated: 1,
      skipped: 0,
      unrecognized: [],
      candidate_cves: 1,
      confirmed_matches: 1,
      potential_matches: 0,
      excluded_cves: 0,
      errors: 0,
      intel_freshness: "2026-11-13T12:00:00Z",
      duration_millis: 12,
    },
  },
  skipped: [],
  errors: [],
  policy: { fail_on: "high", fail_on_kev: false },
  history: [{ id: "SCAN-APP", finished_at: "2026-11-13T12:00:00Z", actionable: 1 }],
};

describe("Application vulnerability UI", () => {
  it("offers a category filter that distinguishes applications from OS findings", async () => {
    const fetchMock = mockApi([
      ["/api/vulnerabilities?", appVulnFixture],
      ["/api/vulnerabilities/", appVulnFixture.items[0]],
    ]);
    render(<Vulnerabilities />);
    await screen.findByRole("table");

    await userEvent.click(screen.getByRole("button", { name: /^Filters/ }));
    const chip = screen.getByRole("button", { name: /^Application/ });
    expect(chip).toBeInTheDocument();
    await userEvent.click(chip);
    expect(chip).toHaveAttribute("aria-pressed", "true");

    await waitFor(() => {
      const urls = fetchMock.mock.calls.map((c) => String(c[0]));
      expect(urls.some((u) => u.includes("category=application"))).toBe(true);
    });
  });

  it("shows the application assessment card on the overview", async () => {
    mockApi([
      ["/api/overview", overviewFixture],
      ["/api/remediation/summary", { open: 1 }],
      ["/api/remediation/groups", { total: 1 }],
      ["/api/metrics", {}],
    ]);
    render(<Overview />);
    const heading = await screen.findByText("Application assessment");
    expect(heading).toBeInTheDocument();
    expect(screen.getByText("Applications discovered")).toBeInTheDocument();
    expect(screen.getByText("Applications evaluated")).toBeInTheDocument();
    expect(screen.getByText("Applications without a mapping")).toBeInTheDocument();
    expect(screen.getByText("Applications with vulnerabilities")).toBeInTheDocument();
    expect(screen.getByText(/patched OS never hides vulnerable applications/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open application findings" })).toHaveAttribute(
      "href",
      "/vulnerabilities?category=application",
    );
  });

  it("explains unevaluated applications on the asset page and links packages to findings", async () => {
    const fixture = {
      ...assetFixture,
      coverage: {
        ...assetFixture.coverage,
        apps: { ...assetFixture.coverage.apps!, evaluated: 0, intel_freshness: "never synchronized" },
      },
    };
    mockApi([["/api/assets/win01", fixture]]);
    render(<AssetDetail host="win01" />);

    // Open the installed software section and confirm the findings link.
    await userEvent.click(await screen.findByRole("button", { name: /Installed software/ }));
    const link = screen.getByRole("link", { name: "1 finding" });
    expect(link).toHaveAttribute("href", "/vulnerabilities?q=google%2Fchrome");

    // The coverage panel must not claim evaluation that did not happen.
    expect(screen.getByText(/NOT evaluated for known vulnerabilities/i)).toBeInTheDocument();
  });

  it("warns on the overview when applications were inventoried but never assessed", async () => {
    const fixture = {
      ...overviewFixture,
      apps: { ...overviewFixture.apps!, nvd_missing: 2 },
    };
    mockApi([
      ["/api/overview", fixture],
      ["/api/remediation/summary", { open: 1 }],
      ["/api/remediation/groups", { total: 1 }],
      ["/api/metrics", {}],
    ]);
    render(<Overview />);
    expect(await screen.findByText(/Installed applications are not being assessed/)).toBeInTheDocument();
    expect(screen.getByText(/feeds update --with-nvd/)).toBeInTheDocument();
  });
});
