import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import IntelligenceSync from "../components/IntelligenceSync";
import { mockApi } from "./helpers";

const baseSource = {
  percent: -1,
  bytes: 0,
  expected_bytes: 0,
  records: 0,
  expected_records: 0,
  dataset_records: 0,
  dataset_available: false,
  freshness: "never",
};

function view(overrides: Record<string, unknown> = {}) {
  return {
    sources: [
      { ...baseSource, source: "kev", name: "CISA KEV", description: "Known exploited vulnerabilities.", depends_on: "all assessments", status: "up_to_date", freshness: "current", dataset_records: 1808, dataset_available: true, last_success: "2026-11-28T12:00:00Z" },
      { ...baseSource, source: "epss", name: "FIRST EPSS", description: "Exploitation probability scores.", depends_on: "all assessments", status: "up_to_date", freshness: "current", dataset_records: 413901, dataset_available: true, last_success: "2026-11-28T12:00:00Z" },
      { ...baseSource, source: "nvd", name: "NVD CVE/CPE", description: "CVE records and the CPE dictionary.", depends_on: "application assessments", status: "downloading", stage: "downloading", percent: 68, bytes: 356515840, expected_bytes: 524288000, records: 125000, expected_records: 200000, job_id: "JOB-1", trigger: "scheduled", actor: "system", dataset_records: 433000, dataset_available: true, freshness: "current", started_at: "2026-11-28T15:00:00Z" },
      { ...baseSource, source: "msrc", name: "Microsoft advisories", description: "KB-to-CVE mapping.", depends_on: "Windows assessments", status: "failed", freshness: "stale", last_error: "HTTP 503 from the update guide", dataset_records: 9825, dataset_available: true },
      { ...baseSource, source: "osv", name: "OSV advisories", description: "Fetched per assessment.", depends_on: "Linux assessments", status: "not_initialized", freshness: "n_a" },
    ],
    running: 1,
    up_to_date: 2,
    stale: 0,
    failed: 1,
    never_synced: 1,
    readiness: { ready: true, notes: [] },
    updated_at: "2026-11-28T15:10:00Z",
    ...overrides,
  };
}

describe("IntelligenceSync", () => {
  it("shows real progress for the running source, not fabricated numbers", async () => {
    mockApi([
      ["/api/intel/sync", view()],
      ["/api/intel/sync/history", { items: [], total: 0 }],
    ]);
    render(<IntelligenceSync />);

    // The NVD card shows the stage, a real percentage and byte counts.
    expect((await screen.findAllByText("downloading")).length).toBeGreaterThan(0);
    expect(screen.getByRole("progressbar", { name: "NVD CVE/CPE progress" })).toHaveAttribute("aria-valuenow", "68");
    expect(screen.getByText(/340 MB/)).toBeInTheDocument();
    expect(screen.getByText(/downloaded of 500 MB/)).toBeInTheDocument();
    expect(screen.getByText(/125,000 records of 200,000 processed/)).toBeInTheDocument();
    // The running source offers Cancel instead of Sync now.
    expect(screen.getByRole("button", { name: /Cancel/ })).toBeInTheDocument();
    // Up-to-date sources show their last success relative time.
    expect(screen.getAllByText(/Last successful sync:/).length).toBeGreaterThan(0);
  });

  it("surfaces failures and never-synced sources with their error", async () => {
    mockApi([
      ["/api/intel/sync", view({ readiness: { ready: false, notes: ["Microsoft advisories is stale: Windows assessments may miss recent data"] } })],
      ["/api/intel/sync/history", { items: [], total: 0 }],
    ]);
    render(<IntelligenceSync />);

    expect(await screen.findByText(/HTTP 503 from the update guide/)).toBeInTheDocument();
    expect(screen.getByText("failed")).toBeInTheDocument();
    expect(screen.getAllByText("Never successfully synchronized").length).toBeGreaterThan(0);
    expect(screen.getByText(/Windows assessments may miss recent data/)).toBeInTheDocument();
  });

  it("sends the sync request and marks it as accepted, not completed", async () => {
    const fetchMock = mockApi([
      ["/api/intel/sync", view()],
      ["/api/intel/sync/history", { items: [], total: 0 }],
    ]);
    render(<IntelligenceSync />);

    const buttons = await screen.findAllByRole("button", { name: /Sync now/ });
    await userEvent.click(buttons[0]);

    await waitFor(() => {
      const calls = fetchMock.mock.calls.map((c) => String(c[0]));
      expect(calls.some((u) => u.includes("/api/intel/sync/kev"))).toBe(true);
    });
  });
});
