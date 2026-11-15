import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import Login from "../pages/Login";

/**
 * The version must come from the server, not from the bundle: it answers "what is
 * deployed here", and a stale tab should report the server it is talking to.
 */
describe("deployed version", () => {
  it("shows the server's version on the sign-in page", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === "/api/health") {
          return new Response(JSON.stringify({ status: "ok", version: "9.9.9-test", uptime: "1s" }), { status: 200 });
        }
        if (url === "/api/auth/session") {
          return new Response(
            JSON.stringify({ authenticated: false, required: true, methods: { password: true, token: false } }),
            { status: 200 },
          );
        }
        return new Response("{}", { status: 200 });
      }),
    );
    window.history.replaceState({}, "", "/login");
    render(<Login />);
    await waitFor(() => expect(screen.getByText("v9.9.9-test")).toBeInTheDocument());
  });

  it("renders a placeholder instead of a fake version when the server does not answer", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    window.history.replaceState({}, "", "/login");
    render(<Login />);
    // No invented version: the placeholder is visibly not a release number.
    await waitFor(() => expect(screen.getByText("v…")).toBeInTheDocument());
  });
});
