import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { VulnerabilityDetail } from "../pages/VulnerabilityDetail";
import { ToastProvider } from "../components/ui/Toast";

/**
 * The flyout has to answer "who owes this, and by when" without making the operator
 * leave the finding, because that is where the decision is actually made.
 */
const FINDING = {
  id: "f1",
  finding_id: "F1",
  report_id: "SCAN-1",
  cve: "CVE-2026-9201",
  asset: "pay02",
  product: "openssl",
  installed_version: "3.0.1",
  ecosystem: "Ubuntu:24.04",
  severity: "medium",
  affected: "affected",
  confidence: "high",
  validation_status: "validated",
  kev: false,
  epss: 0.1,
  epss_percentile: 0.5,
  cvss: 7.5,
  risk_score: 61,
  explanation: "A version match.",
  source: "NVD",
  advisory_id: "AV-1",
  first_seen: "2026-03-01T00:00:00Z",
  last_seen: "2026-03-04T00:00:00Z",
  remediation: "Upgrade openssl.",
  fixed_version: "3.0.2",
  evidence: [],
  references: [],
  confidence_increase: [],
  confidence_reduction: [],
  risk_factors: [],
  remediation_item: {
    id: "REM-abc",
    asset: "pay02",
    team: "Payments",
    owner: "",
    state: "assigned",
    priority: "P2",
    severity: "high",
    category: "os_package",
    due_at: "2026-04-03T09:00:00Z",
    overdue: true,
  },
};

function mockFetch(patchCalls: unknown[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "/api/auth/session") {
        return new Response(JSON.stringify({ authenticated: true, required: true, username: "dana" }), { status: 200 });
      }
      if (url.startsWith("/api/remediation/") && (init?.method ?? "GET").toUpperCase() === "PATCH") {
        patchCalls.push(JSON.parse(String(init?.body)));
        return new Response(JSON.stringify({ item: FINDING.remediation_item }), { status: 200 });
      }
      if (url.startsWith("/api/vulnerabilities/")) {
        return new Response(JSON.stringify(FINDING), { status: 200 });
      }
      return new Response("{}", { status: 200 });
    }),
  );
}

function renderDetail() {
  return render(
    <ToastProvider>
      <VulnerabilityDetail id="f1" onClose={() => {}} />
    </ToastProvider>,
  );
}

describe("finding ownership", () => {
  it("shows the owning team and the deadline, and flags an overdue item", async () => {
    mockFetch([]);
    renderDetail();
    await waitFor(() => expect(screen.getByText("Owner and deadline")).toBeInTheDocument());
    expect(screen.getByText("Payments")).toBeInTheDocument();
    expect(screen.getByText(/overdue/)).toBeInTheDocument();
    // The effective severity is the escalated one, next to the routing category.
    expect(screen.getByText(/os_package/)).toBeInTheDocument();
  });

  it("claims the work item for the signed-in operator", async () => {
    const patches: unknown[] = [];
    mockFetch(patches);
    renderDetail();
    await waitFor(() => expect(screen.getByRole("button", { name: /Assign to me/ })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /Assign to me/ }));
    await waitFor(() => expect(patches).toHaveLength(1));
    expect(patches[0]).toEqual({ owner: "dana" });
  });

  it("reassigns the team on the work item", async () => {
    const patches: unknown[] = [];
    mockFetch(patches);
    renderDetail();
    await waitFor(() => expect(screen.getByLabelText("Team for CVE-2026-9201 on pay02")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Team for CVE-2026-9201 on pay02"), { target: { value: "Development" } });
    await waitFor(() => expect(patches).toHaveLength(1));
    expect(patches[0]).toEqual({ team: "Development" });
  });
});
