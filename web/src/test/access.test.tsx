import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AccessPanel } from "../components/AccessPanel";
import { ToastProvider } from "../components/ui/Toast";

/**
 * Roles in the UI are only a mirror of what the server enforces. These tests pin the two
 * things that matter for a person: an administrator can see and use the controls, and a
 * non-administrator is told why they cannot rather than shown buttons that fail.
 */
const ACCOUNTS = [
  { username: "admin", role: "admin", disabled: false, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
  { username: "dana", role: "operator", disabled: false, created_at: "2026-02-01T00:00:00Z", updated_at: "2026-02-01T00:00:00Z" },
];

type Call = { url: string; method: string; body?: string };

function mock(role: "admin" | "operator" | "viewer") {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      calls.push({ url, method, body: typeof init?.body === "string" ? init.body : undefined });
      if (url === "/api/access/me") {
        return new Response(
          JSON.stringify({
            authenticated: true,
            username: role === "admin" ? "admin" : "dana",
            role,
            permissions: { read: true, write: role !== "viewer", admin: role === "admin" },
            accounts: ACCOUNTS.length,
          }),
          { status: 200 },
        );
      }
      if (url === "/api/users" && method === "GET") {
        return new Response(JSON.stringify({ items: ACCOUNTS, total: ACCOUNTS.length }), { status: 200 });
      }
      if (url === "/api/users" && method === "POST") {
        return new Response(JSON.stringify({ user: { ...ACCOUNTS[1] } }), { status: 200 });
      }
      if (url.startsWith("/api/users/")) {
        return new Response(JSON.stringify({ user: { ...ACCOUNTS[1], role: "viewer" } }), { status: 200 });
      }
      return new Response("{}", { status: 200 });
    }),
  );
  return calls;
}

function renderPanel() {
  return render(
    <ToastProvider>
      <AccessPanel />
    </ToastProvider>,
  );
}

describe("accounts and roles", () => {
  it("lists accounts with their role for an administrator", async () => {
    mock("admin");
    renderPanel();
    await waitFor(() => expect(screen.getByText("dana")).toBeInTheDocument());
    expect(screen.getByRole("combobox", { name: "Role for dana" })).toHaveValue("operator");
    expect(screen.getByRole("button", { name: /Create account/ })).toBeInTheDocument();
  });

  it("creates an account with the chosen role", async () => {
    const calls = mock("admin");
    renderPanel();
    await waitFor(() => expect(screen.getByLabelText("Username")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "sam" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "another-long-password" } });
    fireEvent.change(screen.getByLabelText("Role"), { target: { value: "viewer" } });
    fireEvent.click(screen.getByRole("button", { name: /Create account/ }));
    await waitFor(() => {
      const post = calls.find((c) => c.url === "/api/users" && c.method === "POST");
      expect(post).toBeDefined();
      expect(JSON.parse(String(post?.body))).toMatchObject({ username: "sam", role: "viewer" });
    });
  });

  it("changes a role through the row control", async () => {
    const calls = mock("admin");
    renderPanel();
    const select = await screen.findByRole("combobox", { name: "Role for dana" });
    fireEvent.change(select, { target: { value: "viewer" } });
    await waitFor(() => {
      const patch = calls.find((c) => c.method === "PATCH" && c.url === "/api/users/dana");
      expect(JSON.parse(String(patch?.body))).toEqual({ role: "viewer" });
    });
  });

  it("shows a non-administrator why the controls are missing", async () => {
    mock("operator");
    renderPanel();
    await waitFor(() => expect(screen.getByText(/Managing accounts needs the administrator role/)).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /Create account/ })).not.toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Role for dana" })).toBeDisabled();
  });

  it("disables self-deletion so an administrator cannot remove themselves", async () => {
    mock("admin");
    renderPanel();
    await waitFor(() => expect(screen.getByText("admin")).toBeInTheDocument());
    // The first row is the signed-in account; its Delete button is disabled.
    const adminRow = screen.getByText("(you)").closest("tr")!;
    const del = Array.from(adminRow.querySelectorAll("button")).find((b) => /Delete/.test(b.textContent ?? ""));
    expect(del).toBeDisabled();
  });
});
