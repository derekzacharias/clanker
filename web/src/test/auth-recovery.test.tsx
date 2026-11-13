import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AppShell } from "../components/AppShell";

const TOKEN = "correct-token";

function fetchWithToken() {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (!url.startsWith("/api/")) return new Response("", { status: 200 });
    const headers = new Headers(init?.headers);
    if (headers.get("X-Guard-Token") !== TOKEN) {
      return new Response(JSON.stringify({ error: "missing or invalid X-Guard-Token", code: "unauthorized" }), {
        status: 401,
      });
    }
    return new Response(JSON.stringify({ tool: "clanker-guard", capabilities: {} }), { status: 200 });
  });
}

describe("token recovery", () => {
  it("keeps the dialog open when a stale token was stored", async () => {
    localStorage.setItem("clanker-guard.token", "stale-wrong-token");
    vi.stubGlobal("fetch", fetchWithToken());

    render(
      <AppShell>
        <p>page</p>
      </AppShell>,
    );

    await screen.findByRole("dialog");
    // It must not disappear on its own while the token is still wrong.
    await new Promise((r) => setTimeout(r, 150));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText(/stored token was rejected/i)).toBeInTheDocument();
    expect(localStorage.getItem("clanker-guard.token")).toBeNull();
  });

  it("offers the token dialog from the header even without a 401", async () => {
    vi.stubGlobal("fetch", fetchWithToken());
    render(
      <AppShell>
        <p>page</p>
      </AppShell>,
    );
    await screen.findByRole("dialog");
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: /^API token$/i }));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("CLANKER_GUARD_TOKEN value")).toBeInTheDocument();
  });

  it("unlocks, persists the token and reloads the page data", async () => {
    vi.stubGlobal("fetch", fetchWithToken());
    render(
      <AppShell>
        <p>page</p>
      </AppShell>,
    );
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(screen.getByPlaceholderText("CLANKER_GUARD_TOKEN value"), TOKEN);
    await userEvent.click(screen.getByRole("button", { name: /Unlock/i }));

    await waitFor(() => expect(localStorage.getItem("clanker-guard.token")).toBe(TOKEN));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(dialog).not.toBeInTheDocument();
  });
});
