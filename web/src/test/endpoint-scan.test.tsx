import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import NewScan from "../pages/NewScan";

/**
 * The 4th scan type: ask agents that are installed on other machines to assess
 * themselves. The request is queued server-side, so what the UI must get right is
 * showing *which* endpoints were asked and that nothing happened yet.
 */
const agents = {
  fleet: {
    server_url: "http://guard:8787",
    enroll_token: "SECRET",
    reachable_window: "1m0s",
    count: 2,
    enrolled: [
      {
        id: "AGT-1",
        host: "web01",
        os: "Ubuntu 24.04",
        version: "0.1.2",
        state: "idle",
        phase: "idle",
        percent: 100,
        message: "",
        findings: 12,
        last_report_id: "SCAN-1",
        enrolled_at: "2026-11-15T09:00:00Z",
        last_seen: "2026-11-15T10:00:00Z",
        seconds_since_seen: 5,
        online: true,
        watching: true,
        revoked: false,
      },
      {
        id: "AGT-2",
        host: "db01",
        os: "Debian 12",
        version: "0.1.2",
        state: "idle",
        phase: "idle",
        percent: 100,
        message: "",
        findings: 0,
        last_report_id: "",
        enrolled_at: "2026-11-14T09:00:00Z",
        seconds_since_seen: 90000,
        online: false,
        watching: false,
        revoked: false,
      },
    ],
  },
};

function mockApi(options: { watching?: boolean } = {}) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/scan/cancel")) {
      return new Response(JSON.stringify({ cancelled: 1 }), { status: 200 });
    }
    if (url.startsWith("/api/agents/") && url.endsWith("/scan")) {
      const body = {
        task: { id: "TASK-1", agent_id: "AGT-1", kind: "scan", status: "queued", requested_at: "2026-11-15T10:05:00Z" },
        created: true,
      };
      return new Response(JSON.stringify(body), { status: 202, headers: { "Content-Type": "application/json" } });
    }
    if (url.startsWith("/api/agents")) {
      const withTask = JSON.parse(JSON.stringify(agents));
      if (options.watching === false) {
        withTask.fleet.enrolled[0].watching = false;
        withTask.fleet.enrolled[0].online = false;
      }
      withTask.fleet.enrolled[0].task = {
        id: "TASK-1",
        agent_id: "AGT-1",
        kind: "scan",
        status: "queued",
        requested_at: "2026-11-15T10:05:00Z",
      };
      return new Response(JSON.stringify(withTask), { status: 200 });
    }
    if (url.startsWith("/api/meta")) {
      return new Response(JSON.stringify({ tool: "clanker-guard", capabilities: {} }), { status: 200 });
    }
    void init;
    return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

beforeEach(() => {
  window.history.replaceState({}, "", "/scans/new");
});

describe("endpoint scan", () => {
  it("offers the fourth tile and lists enrolled endpoints", async () => {
    mockApi();
    render(<NewScan />);

    expect(screen.getByRole("button", { name: /Local System/i })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Endpoint Scan/i }));
    await userEvent.click(screen.getByRole("button", { name: /^Continue$/ }));

    expect(await screen.findByText("web01")).toBeInTheDocument();
    expect(screen.getByText(/offline \(unreachable\)/i)).toBeInTheDocument();
    // Nothing selected yet, so the review step cannot start anything.
    await userEvent.click(screen.getByRole("button", { name: /^Continue$/ }));
    expect(screen.getByRole("button", { name: /Start Scan/i })).toBeDisabled();
  });

  it("queues the scan for the selected endpoint and says it is waiting", async () => {
    const fetchMock = mockApi();
    render(<NewScan />);

    await userEvent.click(screen.getByRole("button", { name: /Endpoint Scan/i }));
    await userEvent.click(screen.getByRole("button", { name: /^Continue$/ }));
    await screen.findByText("web01");
    await userEvent.click(screen.getByRole("checkbox", { name: /web01/ }));
    await userEvent.click(screen.getByRole("button", { name: /^Continue$/ }));

    expect(screen.getByText(/Endpoint scan/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Start Scan/i }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/agents/AGT-1/scan", expect.objectContaining({ method: "POST" })),
    );
    expect(await screen.findByRole("heading", { name: /Endpoint scan queued/i })).toBeInTheDocument();
    // Pull-based work must not look like it started: the row says it is waiting,
    // and the per-endpoint status badge reads "queued".
    expect(await screen.findByText(/dispatched — starting now|endpoint unreachable — queued until it reconnects/i)).toBeTruthy();
    expect(screen.getByText(/A reachable endpoint starts the scan immediately/i)).toBeInTheDocument();
  });

  it("offers to withdraw the request and to make the endpoint reachable", async () => {
    // The case that matters: nobody is watching there, so the request would
    // otherwise wait forever with no way out.
    const fetchMock = mockApi({ watching: false });
    render(<NewScan />);
    await userEvent.click(screen.getByRole("button", { name: /Endpoint Scan/i }));
    await userEvent.click(screen.getByRole("button", { name: /^Continue$/ }));
    await screen.findByText("web01");
    await userEvent.click(screen.getByRole("checkbox", { name: /web01/ }));
    await userEvent.click(screen.getByRole("button", { name: /^Continue$/ }));
    await userEvent.click(screen.getByRole("button", { name: /Start Scan/i }));
    await screen.findByRole("heading", { name: /Endpoint scan queued/i });

    // The operator can change their mind instead of being stuck with a request
    // that waits for an endpoint nobody is running a watcher on.
    await userEvent.click(await screen.findByRole("button", { name: /Cancel request/i }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/agents/AGT-1/scan/cancel", expect.objectContaining({ method: "POST" })),
    );
    // And the panel says exactly what to run on the endpoint to fix it.
    expect(screen.getByRole("button", { name: /Copy the command that makes this endpoint reachable/i })).toBeInTheDocument();
  });

  it("explains the empty fleet instead of offering a dead action", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.startsWith("/api/agents")) {
          return new Response(JSON.stringify({ fleet: { ...agents.fleet, count: 0, enrolled: [] } }), { status: 200 });
        }
        return new Response(JSON.stringify({}), { status: 200 });
      }),
    );
    render(<NewScan />);
    await userEvent.click(screen.getByRole("button", { name: /Endpoint Scan/i }));
    await userEvent.click(screen.getByRole("button", { name: /^Continue$/ }));
    expect(await screen.findByText(/No endpoints are enrolled yet/i)).toBeInTheDocument();
  });
});
