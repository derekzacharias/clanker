import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Remediation from "../pages/Remediation";

/**
 * The remediation queue answers "who owes what, by when". These assertions pin the
 * parts an operator relies on: triage is visible as unassigned (never silently
 * routed), overdue is called out, assignment posts the change, and the page never
 * implies automated execution exists.
 */
const summary = {
  summary: {
    total: 3,
    open: 2,
    unassigned: 1,
    overdue: 1,
    triage_assets: 1,
    resolved: 1,
    by_state: { assigned: 1, awaiting_ownership: 1, resolved: 1 },
    by_team: { Infrastructure: 1, "(unassigned)": 1 },
    by_priority: { P1: 1, P2: 1 },
    automation_eligible: 0,
  },
  teams: ["Infrastructure"],
  generated: new Date().toISOString(),
  automation: { enabled: false, reason: "automated remediation is not implemented in this build" },
};

const items = [
  {
    id: "REM-1", asset: "web01", finding_key: "k1", vulnerability_id: "CVE-2026-1", product: "openssl",
    installed_version: "3.0.1", ecosystem: "Ubuntu:24.04", severity: "critical", category: "os_package",
    team: "Infrastructure", owner: "", state: "assigned" as const, priority: "P1",
    due_at: new Date(Date.now() + 864e5).toISOString(), fixed_version: "3.0.2", remediation: "apt",
    evidence: "critical · fixed in 3.0.2", report_id: "SCAN-1", first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(), updated_at: new Date().toISOString(), overdue: false,
  },
  {
    id: "REM-2", asset: "mystery", finding_key: "k2", vulnerability_id: "CVE-2026-2", product: "blob",
    installed_version: "1", ecosystem: "AcmeOS:1", severity: "high", category: "", team: "",
    owner: "", state: "awaiting_ownership" as const, priority: "P2",
    due_at: new Date(Date.now() - 864e5).toISOString(), fixed_version: "", remediation: "",
    evidence: "high · no fixed version published", report_id: "SCAN-1", first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(), updated_at: new Date().toISOString(), overdue: true,
  },
];

function mockApi() {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });
    if (url.startsWith("/api/remediation/summary")) return json(summary);
    if (url.startsWith("/api/remediation/") && init?.method === "PATCH") return json({ item: items[0] });
    if (url.startsWith("/api/remediation")) return json({ items, total: items.length });
    return json({});
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

beforeEach(() => {
  window.history.replaceState({}, "", "/remediation");
});

describe("remediation queue", () => {
  it("shows owners, states, overdue work and the triage item", async () => {
    mockApi();
    render(<Remediation />);

    const table = await screen.findByRole("table", { name: /Remediation work items/i });
    const routed = within(table).getByRole("row", { name: /CVE-2026-1/ });
    expect(within(routed).getAllByText("Infrastructure").length).toBeGreaterThan(0);
    expect(within(routed).getAllByText(/^assigned$/i).length).toBeGreaterThan(0);

    const triage = within(table).getByRole("row", { name: /CVE-2026-2/ });
    expect(within(triage).getAllByText(/unassigned/i).length).toBeGreaterThan(0);
    expect(within(triage).getByText(/overdue/i)).toBeInTheDocument();

    // The page must not imply that automated execution exists.
    expect(screen.getByText(/Automated remediation is not available in this build/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Remediate$/i })).not.toBeInTheDocument();
  });

  it("assigns an item to a team and refreshes the queue", async () => {
    const fetchMock = mockApi();
    render(<Remediation />);
    const table = await screen.findByRole("table", { name: /Remediation work items/i });
    const triage = within(table).getByRole("row", { name: /CVE-2026-2/ });

    await userEvent.selectOptions(within(triage).getByLabelText(/Assign CVE-2026-2/), "DevOps");

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/remediation/REM-2",
        expect.objectContaining({ method: "PATCH", body: JSON.stringify({ team: "DevOps" }) }),
      ),
    );
  });

  it("explains an empty queue instead of showing a blank table", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) =>
        String(input).startsWith("/api/remediation/summary")
          ? new Response(JSON.stringify({ ...summary, teams: [] }), { status: 200 })
          : new Response(JSON.stringify({ items: [], total: 0 }), { status: 200 }),
      ),
    );
    render(<Remediation />);
    expect(await screen.findByText(/No remediation work matches these filters/i)).toBeInTheDocument();
  });
});
