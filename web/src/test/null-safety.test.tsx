import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import Overview from "../pages/Overview";
import AssetDetail from "../pages/AssetDetail";
import { AppShell } from "../components/AppShell";
import { mockApi } from "./helpers";

// The server used to serialise empty Go slices as null. That crashed the
// Overview on `data.errors.length`. These fixtures reproduce the old payloads so
// the UI cannot regress into a blank page.
const overviewWithNulls = {
  has_data: true,
  metrics: { assets: 1, critical: 0, high: 0, medium: 0, low: 0, kev: 0, actionable: 0, needs_investigation: 0, total: 0 },
  severity: null,
  priority: null,
  coverage: { assessed: 1, stale: 0, failed_recent: 0, stale_after_days: 7, last_scan_at: "2026-11-13T00:00:00Z" },
  activity: null,
  feeds: null,
  limitations: null,
  errors: null,
  improvements_available: 0,
  reviewed_findings: 0,
};

const assetWithNulls = {
  host: "host1",
  asset: { hostname: "host1", os: "Ubuntu", os_version: "24.04" },
  report_id: "SCAN-1",
  last_scan: "2026-11-13T00:00:00Z",
  mode: "local",
  offline: true,
  agent: { version: "dev", last_scan: "2026-11-13T00:00:00Z" },
  packages: [],
  package_count: 0,
  packages_truncated: false,
  findings: null,
  coverage: { packages_inspected: 0, packages_matched: 0, advisories_checked: 0, sources_used: [] },
  skipped: null,
  errors: null,
  policy: { fail_on: "", fail_on_kev: false },
  history: null,
};

describe("null-safe rendering", () => {
  it("renders the overview even when list fields arrive as null", async () => {
    mockApi([["/api/overview", overviewWithNulls]]);
    render(<Overview />);
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(screen.getByText(/No actionable findings in the assessed scope/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Overview" })).toBeInTheDocument();
  });

  it("renders an asset with null finding lists", async () => {
    mockApi([["/api/assets/host1", assetWithNulls]]);
    render(<AssetDetail host="host1" />);
    expect(await screen.findByRole("heading", { name: "host1" })).toBeInTheDocument();
    expect(screen.getByText(/No findings recorded for this asset/i)).toBeInTheDocument();
  });

  it("shows a recoverable card instead of a blank page when a screen crashes", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    function Boom(): JSX.Element {
      throw new Error("synthetic render failure");
    }
    render(
      <AppShell>
        <Boom />
      </AppShell>,
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(/could not be displayed/i);
    expect(screen.getByText(/synthetic render failure/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Try this screen again/i })).toBeInTheDocument();
  });
});
