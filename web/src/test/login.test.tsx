import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AppShell } from "../components/AppShell";
import Login, { humanizeTTL } from "../pages/Login";

const TOKEN_KEY = "clanker-guard.token";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const passwordSession = {
  authenticated: false,
  required: true,
  methods: { password: true, token: true },
  session_ttl: "720h0m0s",
};

function at(path: string) {
  window.history.replaceState({}, "", path);
}

beforeEach(() => {
  at("/login");
});

describe("sign-in page", () => {
  it("signs in with the password and continues to the requested page", async () => {
    const seen: { body?: unknown; credentials?: RequestCredentials } = {};
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "/api/auth/session") return json(passwordSession);
      if (url === "/api/auth/login") {
        seen.body = JSON.parse(String(init?.body));
        seen.credentials = init?.credentials;
        return json({ ...passwordSession, authenticated: true, username: "admin" });
      }
      return json({ error: "not found" }, 404);
    });
    vi.stubGlobal("fetch", fetchMock);
    localStorage.setItem(TOKEN_KEY, "an-old-token");
    at("/login?next=%2Fvulnerabilities%3Fq%3Dopenssl");

    render(<Login />);

    const username = await screen.findByLabelText("Username");
    await userEvent.type(username, "admin");
    await userEvent.type(screen.getByLabelText("Password"), "correct-horse-battery");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => expect(window.location.pathname).toBe("/vulnerabilities"));
    expect(window.location.search).toBe("?q=openssl");
    expect(seen.body).toEqual({ username: "admin", password: "correct-horse-battery" });
    // The session cookie must ride along, and the legacy token must be dropped so
    // the browser does not send two credentials.
    expect(seen.credentials).toBe("same-origin");
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });

  it("shows the server's rejection without leaving the page", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === "/api/auth/session") return json(passwordSession);
        if (url === "/api/auth/login") return json({ error: "invalid username or password", code: "unauthorized" }, 401);
        return json({}, 404);
      }),
    );

    render(<Login />);
    await userEvent.type(await screen.findByLabelText("Username"), "admin");
    await userEvent.type(screen.getByLabelText("Password"), "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/invalid username or password/i);
    expect(window.location.pathname).toBe("/login");
    // The password is cleared but the username is kept for a second attempt.
    expect((screen.getByLabelText("Password") as HTMLInputElement).value).toBe("");
    expect((screen.getByLabelText("Username") as HTMLInputElement).value).toBe("admin");
    expect((screen.getByLabelText("Password") as HTMLInputElement).getAttribute("aria-invalid")).toBe("true");
  });

  it("explains a rate-limited sign-in", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === "/api/auth/session") return json(passwordSession);
        if (url === "/api/auth/login") return json({ error: "too many failed attempts", code: "too_many_attempts" }, 429);
        return json({}, 404);
      }),
    );

    render(<Login />);
    await userEvent.type(await screen.findByLabelText("Username"), "admin");
    await userEvent.type(screen.getByLabelText("Password"), "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/too many failed attempts/i);
  });

  it("falls back to the token form when no password is configured", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "/api/auth/session") {
        return json({ authenticated: false, required: true, methods: { password: false, token: true } });
      }
      return json({}, 404);
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<Login />);

    expect(await screen.findByRole("heading", { name: /Enter the API token/i })).toBeInTheDocument();
    expect(screen.getByText(/auth set-password/)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("API token"), "  s3cret-token  ");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await waitFor(() => expect(localStorage.getItem(TOKEN_KEY)).toBe("s3cret-token"));
    expect(window.location.pathname).toBe("/");
    expect(fetchMock).not.toHaveBeenCalledWith("/api/auth/login", expect.anything());
  });

  it("renders nothing to unlock on an open loopback server", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) =>
        String(input) === "/api/auth/session"
          ? json({ authenticated: false, required: false, methods: { password: false, token: false } })
          : json({}, 404),
      ),
    );

    render(<Login />);
    expect(await screen.findByRole("heading", { name: /No sign-in required/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Back to overview/i })).toHaveAttribute("href", "/");
  });

  it("refuses a next= that points at another origin", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === "/api/auth/session") return json(passwordSession);
        if (url === "/api/auth/login") return json({ ...passwordSession, authenticated: true, username: "admin" });
        return json({}, 404);
      }),
    );
    at("/login?next=%2F%2Fevil.example%2Fsteal");

    render(<Login />);
    await userEvent.type(await screen.findByLabelText("Username"), "admin");
    await userEvent.type(screen.getByLabelText("Password"), "correct-horse-battery");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => expect(window.location.pathname).toBe("/"));
  });

  it("surfaces an unreachable API instead of an empty form", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );

    render(<Login />);
    expect(await screen.findByRole("heading", { name: /Cannot reach the API/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});

describe("shell authentication routing", () => {
  it("redirects to the sign-in page instead of painting dashboard data", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) =>
        String(input) === "/api/auth/session" ? json(passwordSession) : json({}, 401),
      ),
    );
    at("/vulnerabilities?q=openssl");

    render(
      <AppShell>
        <p>protected findings</p>
      </AppShell>,
    );

    await waitFor(() => expect(window.location.pathname).toBe("/login"));
    expect(window.location.search).toBe(`?next=${encodeURIComponent("/vulnerabilities?q=openssl")}`);
    expect(screen.queryByText("protected findings")).not.toBeInTheDocument();
  });

  it("sends an expired session to the sign-in page rather than the token dialog", async () => {
    let authenticated = true;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (String(input) !== "/api/auth/session") return json({}, 401);
        return json({
          authenticated,
          required: true,
          username: "admin",
          methods: { password: true, token: false },
        });
      }),
    );
    at("/");

    render(
      <AppShell>
        <p>dashboard</p>
      </AppShell>,
    );
    await waitFor(() => expect(screen.getByText("dashboard")).toBeInTheDocument());

    authenticated = false;
    act(() => {
      window.dispatchEvent(new CustomEvent("guard:unauthorized"));
    });

    await waitFor(() => expect(window.location.pathname).toBe("/login"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("session length copy", () => {
  it("renders the server TTL in human units", () => {
    expect(humanizeTTL("720h0m0s")).toBe("30 days");
    expect(humanizeTTL("24h0m0s")).toBe("1 day");
    expect(humanizeTTL("48h0m0s")).toBe("2 days");
    expect(humanizeTTL("6h0m0s")).toBe("6 hours");
    expect(humanizeTTL("1h0m0s")).toBe("1 hour");
    expect(humanizeTTL("nonsense")).toBe("the configured session length");
  });
});
