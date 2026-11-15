import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import Ownership from "../pages/Ownership";
import { ToastProvider } from "../components/ui/Toast";

/**
 * Triage exists so routing never guesses, which means the UI must make recording
 * ownership the easy action. These tests cover the two ways an operator does that:
 * one asset at a time, and several at once.
 */
const ROWS = [
  { asset: "web01", team: "Infrastructure", owner: "dana", exposure: "internal", items: 12, open: 12, critical: 2, overdue: 1, triaged: false, status: "owned", updated_at: "2026-03-04T09:00:00Z" },
  { asset: "odd01", team: "", owner: "", items: 3, open: 3, critical: 0, overdue: 0, triaged: true, status: "", updated_at: "" },
  { asset: "odd02", team: "", owner: "", items: 1, open: 1, critical: 0, overdue: 0, triaged: true, status: "", updated_at: "" },
];

function mockFetch(onBulk?: (body: unknown) => void) {
  const calls: { url: string; method: string; body?: string }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      calls.push({ url, method, body: typeof init?.body === "string" ? init.body : undefined });
      if (url.startsWith("/api/ownership/bulk")) {
        onBulk?.(JSON.parse(String(init?.body)));
        return new Response(JSON.stringify({ updated: ["odd01", "odd02"], failed: {}, total: 2 }), { status: 200 });
      }
      if (url.startsWith("/api/ownership/")) {
        return new Response(JSON.stringify({ asset: "odd01", team: "Development", status: "owned" }), { status: 200 });
      }
      if (url.startsWith("/api/ownership")) {
        return new Response(JSON.stringify({ items: ROWS, total: ROWS.length }), { status: 200 });
      }
      return new Response(JSON.stringify({ authenticated: true, required: true, username: "dana" }), { status: 200 });
    }),
  );
  return calls;
}

describe("ownership inventory", () => {
  it("assigns several assets in one request and reports the count", async () => {
    let sent: unknown = null;
    const calls = mockFetch((body) => {
      sent = body;
    });
    render(
      <ToastProvider>
        <Ownership />
      </ToastProvider>,
    );
    await waitFor(() => expect(screen.getByText("odd01")).toBeInTheDocument());

    fireEvent.click(screen.getByLabelText("Select odd01"));
    fireEvent.click(screen.getByLabelText("Select odd02"));
    expect(screen.getByText("2 selected")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Team for selected assets"), { target: { value: "Development" } });
    fireEvent.click(screen.getByRole("button", { name: "Assign 2" }));

    await waitFor(() => expect(sent).not.toBeNull());
    expect(sent).toEqual({ assets: ["odd01", "odd02"], team: "Development", owner: "" });
    // One request, not one per asset.
    expect(calls.filter((c) => c.url === "/api/ownership/bulk")).toHaveLength(1);
    await waitFor(() => expect(screen.getByText(/2 assets assigned to Development/)).toBeInTheDocument());
  });

  it("refuses to bulk-assign without a team instead of creating ownerless records", async () => {
    const calls = mockFetch();
    render(
      <ToastProvider>
        <Ownership />
      </ToastProvider>,
    );
    await waitFor(() => expect(screen.getByText("odd01")).toBeInTheDocument());
    fireEvent.click(screen.getByLabelText("Select odd01"));
    const assignButton = screen.getByRole("button", { name: /Assign 1/ });
    expect(assignButton).toBeDisabled();
    fireEvent.click(assignButton);
    expect(calls.some((c) => c.url === "/api/ownership/bulk")).toBe(false);
  });

  it("keeps unowned assets in a filter of their own and marks them", async () => {
    mockFetch();
    render(
      <ToastProvider>
        <Ownership />
      </ToastProvider>,
    );
    await waitFor(() => expect(screen.getByText("web01")).toBeInTheDocument());
    const row = screen.getByText("odd01").closest("tr")!;
    expect(within(row).getByText("needs an owner")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Needs an owner/ }));
    await waitFor(() => expect(screen.queryByText("web01")).not.toBeInTheDocument());
    expect(screen.getByText("odd02")).toBeInTheDocument();
  });

  it("records a single asset's team on the row that changed", async () => {
    const calls = mockFetch();
    render(
      <ToastProvider>
        <Ownership />
      </ToastProvider>,
    );
    await waitFor(() => expect(screen.getByText("odd01")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Team for odd01"), { target: { value: "Development" } });

    await waitFor(() => {
      const put = calls.find((c) => c.method === "PUT" && c.url === "/api/ownership/odd01");
      expect(put).toBeDefined();
      expect(JSON.parse(String(put?.body))).toMatchObject({ team: "Development" });
    });
  });
});
