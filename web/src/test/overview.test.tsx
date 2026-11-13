import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Overview from "../pages/Overview";
import { mockApi, overviewFixture, emptyOverviewFixture } from "./helpers";

function renderOverview() {
  return render(<Overview />);
}

describe("Overview", () => {
  it("shows real metrics, priority findings and coverage from the API", async () => {
    mockApi([["/api/overview", overviewFixture]]);
    renderOverview();

    expect(await screen.findByText("Security overview")).toBeInTheDocument();
    expect(await screen.findByText("Known exploited")).toBeInTheDocument();
    expect(screen.getByText("CVE-2026-0001")).toBeInTheDocument();
    expect(screen.getByText("openssl")).toBeInTheDocument();
    // severity distribution exposes counts as text, not only as chart colour
    expect(screen.getByRole("img", { name: /Findings by severity/i })).toBeInTheDocument();
    expect(screen.getByText("Coverage limitations")).toBeInTheDocument();
    expect(screen.getByText(/version-correlation only/i)).toBeInTheDocument();
  });

  it("warns prominently when intelligence is stale", async () => {
    mockApi([["/api/overview", overviewFixture]]);
    renderOverview();
    const banner = await screen.findByText(/Vulnerability intelligence is stale/i);
    expect(banner).toBeInTheDocument();
    expect(screen.getByText(/EPSS last synced/i)).toBeInTheDocument();
  });

  it("never fabricates metrics before a scan has run", async () => {
    mockApi([["/api/overview", emptyOverviewFixture]]);
    renderOverview();
    expect(await screen.findByRole("heading", { name: /Run your first scan/i })).toBeInTheDocument();
    expect(screen.queryByText("Known exploited")).not.toBeInTheDocument();
    expect(screen.queryByText("Critical")).not.toBeInTheDocument();
  });

  it("surfaces API failures with a retry action", async () => {
    mockApi([]); // every request 404s
    renderOverview();
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /try again/i })).toBeInTheDocument();
  });

  it("reports unresolved findings without calling them exploitable", async () => {
    mockApi([
      [
        "/api/overview",
        {
          ...overviewFixture,
          metrics: { ...overviewFixture.metrics, needs_investigation: 4 },
        },
      ],
    ]);
    renderOverview();
    await waitFor(() => expect(screen.getByText(/need investigation/i)).toBeInTheDocument());
    expect(screen.getByText(/excluded from the actionable count/i)).toBeInTheDocument();
  });
});
