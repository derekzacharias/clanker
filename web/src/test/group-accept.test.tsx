import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import Remediation from "../pages/Remediation";
import { ToastProvider } from "../components/ui/Toast";

/**
 * Regression test for the defect this cycle targeted: group risk acceptance used `window.prompt`,
 * which blocks the page, cannot be labelled, cannot validate, and returns "" on cancel — leaving the
 * operator with a 409 after confirming. The dialog must be in-app, must require a reason, and must
 * post the chosen review period.
 */
const GROUP = {
  key: "win01|windows 11 pro|KB5127648",
  asset: "win01",
  product: "Windows 11 Pro",
  fixed_version: "KB5127648",
  team: "Infrastructure",
  severity: "critical",
  priority: "P1",
  items: 1067,
  critical: 1067,
  overdue: 0,
  advisories: ["CVE-2026-1"],
  item_ids: ["REM-1"],
};

type Call = { url: string; method: string; body?: string };

function mock() {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      calls.push({ url, method, body: typeof init?.body === "string" ? init.body : undefined });
      if (url.startsWith("/api/remediation/summary")) {
        return new Response(JSON.stringify({ summary: { total: 1067, open: 1067, unassigned: 0, overdue: 0, triage_assets: 0, resolved: 0, by_state: {}, by_team: {}, by_priority: {} }, teams: [], generated: "2026-01-01T00:00:00Z", automation: { enabled: false, reason: "not implemented" } }), { status: 200 });
      }
      if (url.startsWith("/api/remediation/groups")) {
        return new Response(JSON.stringify({ items: [GROUP], total: 1, findings: 1067 }), { status: 200 });
      }
      if (url.startsWith("/api/remediation/groups/action")) {
        return new Response(JSON.stringify({ changed: 1067, action: "accept" }), { status: 200 });
      }
      if (url.startsWith("/api/metrics")) {
        return new Response(JSON.stringify({ open: 1067, overdue: 0, unassigned: 0, acceptances_due: 0, age_buckets: [], time_to_fix: [], reopened: 0, verified: 0, units: 1, findings: 1067 }), { status: 200 });
      }
      if (url.startsWith("/api/access/me")) {
        return new Response(JSON.stringify({ authenticated: true, username: "dana", role: "operator", permissions: { read: true, write: true, admin: false }, accounts: 1 }), { status: 200 });
      }
      if (url.startsWith("/api/remediation")) {
        return new Response(JSON.stringify({ items: [], total: 0 }), { status: 200 });
      }
      return new Response("{}", { status: 200 });
    }),
  );
  return calls;
}

function renderPage() {
  return render(
    <ToastProvider>
      <Remediation />
    </ToastProvider>,
  );
}

describe("group risk acceptance", () => {
  it("asks in the app, requires a reason, and posts the chosen review period", async () => {
    const calls = mock();
    renderPage();
    fireEvent.click(await screen.findByRole("tab", { name: /By upgrade/ }));
    await screen.findByText("KB5127648", { exact: false });

    fireEvent.click(screen.getAllByRole("button", { name: "Accept risk" })[0]);
    const dialog = await screen.findByRole("dialog");
    const submit = screen.getByRole("button", { name: /Accept risk until the review date/ });
    // No reason yet: the control is disabled rather than letting the server reject it.
    expect(submit).toBeDisabled();

    fireEvent.change(within(dialog).getByLabelText("Reason"), {
      target: { value: "vendor patch lands in Q3; host is isolated by a network rule" },
    });
    fireEvent.change(within(dialog).getByLabelText("Review in"), { target: { value: "60" } });
    expect(submit).toBeEnabled();
    fireEvent.click(submit);

    await waitFor(() => {
      const post = calls.find((c) => c.url === "/api/remediation/groups/action" && c.method === "POST");
      expect(post).toBeDefined();
      expect(JSON.parse(String(post?.body))).toMatchObject({
        asset: "win01",
        product: "Windows 11 Pro",
        fixed_version: "KB5127648",
        action: "accept",
        days: 60,
      });
    });
  });

  it("sends nothing when the dialog is cancelled", async () => {
    const calls = mock();
    renderPage();
    fireEvent.click(await screen.findByRole("tab", { name: /By upgrade/ }));
    await screen.findByText("KB5127648", { exact: false });
    fireEvent.click(screen.getAllByRole("button", { name: "Accept risk" })[0]);
    await screen.findByRole("dialog");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(calls.some((c) => c.url === "/api/remediation/groups/action")).toBe(false);
  });
});
