import type { ReactElement } from "react";
import { render } from "@testing-library/react";
import { vi } from "vitest";

/** Route-based fetch mock: handlers match a path prefix. */
export function mockApi(routes: Array<[string, unknown]>) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    for (const [prefix, payload] of routes) {
      if (url.startsWith(prefix)) {
        return new Response(JSON.stringify(payload), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
    }
    return new Response(JSON.stringify({ error: "not found", code: "not_found" }), { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

export function renderPage(ui: ReactElement) {
  return render(ui);
}

export const overviewFixture = {
  has_data: true,
  metrics: { assets: 1, critical: 2, high: 3, medium: 4, low: 1, kev: 2, actionable: 9, needs_investigation: 1, total: 10 },
  severity: [
    { key: "critical", count: 2 },
    { key: "high", count: 3 },
    { key: "medium", count: 4 },
    { key: "low", count: 1 },
    { key: "unknown", count: 0 },
  ],
  priority: [
    {
      id: "abc123",
      finding_id: "FINDING-0001",
      report_id: "SCAN-1",
      cve: "CVE-2026-0001",
      asset: "host1",
      product: "openssl",
      installed_version: "3.0.11-1",
      ecosystem: "Debian:12",
      severity: "critical",
      affected: "confirmed_applicability",
      confidence: "high",
      validation_status: "version_correlation",
      kev: true,
      epss: 0.9,
      epss_percentile: 0.99,
      cvss: 9.8,
      fixed_version: "3.0.13-1",
      remediation: "Upgrade openssl.",
      source: "Debian",
      advisory_id: "DEBIAN-CVE-2026-0001",
      risk_score: 78.5,
      first_seen: "2026-11-01T00:00:00Z",
      last_seen: "2026-11-13T00:00:00Z",
    },
  ],
  coverage: { assessed: 1, stale: 0, failed_recent: 0, stale_after_days: 7, last_scan_at: "2026-11-13T00:00:00Z" },
  activity: [
    { id: "SCAN-1", kind: "local", host: "host1", status: "completed", percent: 100, finished_at: "2026-11-13T00:00:00Z", findings: 10, actionable: 9, kev: 2 },
  ],
  feeds: [
    { source: "KEV", last_sync: "2026-11-12T00:00:00Z", records: 1779, stale: false },
    { source: "EPSS", last_sync: "2026-10-01T00:00:00Z", records: 400000, stale: true },
  ],
  limitations: ["version-correlation only: no network validation"],
  errors: [],
};

export const emptyOverviewFixture = {
  has_data: false,
  metrics: { assets: 0, critical: 0, high: 0, medium: 0, low: 0, kev: 0, actionable: 0, needs_investigation: 0, total: 0 },
  severity: [],
  priority: [],
  coverage: { assessed: 0, stale: 0, failed_recent: 0, stale_after_days: 7 },
  activity: [],
  feeds: [],
  limitations: [],
  errors: [],
};

export const vulnFixture = {
  total: 1,
  items: [
    {
      id: "vuln-1",
      finding_id: "FINDING-0001",
      report_id: "SCAN-1",
      cve: "CVE-2026-0001",
      asset: "host1",
      product: "openssl",
      installed_version: "3.0.11-1",
      ecosystem: "Debian:12",
      severity: "critical",
      affected: "confirmed_applicability",
      confidence: "high",
      validation_status: "version_correlation",
      kev: true,
      epss: 0.9,
      epss_percentile: 0.99,
      cvss: 9.8,
      fixed_version: "3.0.13-1",
      remediation: "Upgrade openssl to 3.0.13-1.",
      source: "Debian",
      advisory_id: "DEBIAN-CVE-2026-0001",
      risk_score: 78.5,
      first_seen: "2026-11-01T00:00:00Z",
      last_seen: "2026-11-13T00:00:00Z",
      explanation: "Installed version is inside the affected range.",
      evidence: [{ kind: "installed_version", detail: "openssl 3.0.11-1 installed" }],
      references: [{ label: "NVD", url: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001" }],
      risk_factors: [{ name: "cisa_kev", weight: 30, detail: "listed in KEV" }],
    },
  ],
  facets: {
    severity: [
      { key: "critical", count: 1 },
      { key: "high", count: 0 },
      { key: "medium", count: 0 },
      { key: "low", count: 0 },
      { key: "unknown", count: 0 },
    ],
    applicability: [{ key: "confirmed_applicability", count: 1 }],
    assets: [{ key: "host1", count: 1 }],
    kev: 1,
    fix_available: 1,
  },
  applied: {},
};
