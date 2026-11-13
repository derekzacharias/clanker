import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AppShell } from "../components/AppShell";

const TOKEN = "s3cret-token";

describe("authentication gate", () => {
  it("asks for the token when the server rejects unauthenticated requests", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      const url = String(input);
      if (url.startsWith("/api/")) {
        if (headers.get("X-Guard-Token") !== TOKEN) {
          return new Response(JSON.stringify({ error: "unauthorized", code: "unauthorized" }), { status: 401 });
        }
        return new Response(JSON.stringify({ tool: "clanker-guard", capabilities: {} }), { status: 200 });
      }
      return new Response("", { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(
      <AppShell>
        <p>protected content</p>
      </AppShell>,
    );

    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent(/requires an API token/i);
    const tokenInput = screen.getByPlaceholderText("CLANKER_GUARD_TOKEN value");
    expect(tokenInput).toBeInTheDocument();

    await userEvent.type(tokenInput, TOKEN);
    await userEvent.click(screen.getByRole("button", { name: /Unlock/i }));

    await waitFor(() => expect(localStorage.getItem("clanker-guard.token")).toBe(TOKEN));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(screen.getByText("protected content")).toBeInTheDocument();
  });

  it("does not gate a loopback server that needs no token", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).startsWith("/api/")) {
        return new Response(JSON.stringify({ tool: "clanker-guard", capabilities: {} }), { status: 200 });
      }
      return new Response("", { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(
      <AppShell>
        <p>open content</p>
      </AppShell>,
    );
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
