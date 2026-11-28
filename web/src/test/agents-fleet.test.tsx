import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Settings from "../pages/Settings";

/**
 * The Agents tab is where an operator answers "is my fleet reporting, and what is
 * each endpoint doing right now". These assertions pin the parts that make it
 * useful: live activity, honest online/offline, and a revoke that is only
 * offered where it can work.
 */
const BASE = "http://guard.example:8787";

function agentsFixture() {
  return {
    local: { host: "guard", version: "0.1.1", cache_path: "/tmp/intel.db", platform: "linux/amd64", installed: true },
    endpoints: [],
    install: {
      published: true,
      version: "0.1.1",
      base_url: `${BASE}/releases/download/v0.1.1`,
      keeps_available: true,
      requires_enroll_token: true,
      mint_endpoint: "/api/agents/enroll-token",
      commands: {
        linux: `curl -fsSL ${BASE}/releases/download/v0.1.1/install-agent.sh | bash -s -- --version 0.1.1 --server ${BASE} --enroll-token <enroll-token>`,
        macos: `curl -fsSL ${BASE}/releases/download/v0.1.1/install-agent.sh | bash -s -- --version 0.1.1 --server ${BASE} --enroll-token <enroll-token>`,
        windows: "iwr ... -EnrollToken <enroll-token>",
      },
      oneoff_commands: {
        linux: `curl -fsSL ${BASE}/releases/download/v0.1.1/install-agent.sh | bash -s -- --version 0.1.1 --server ${BASE} --enroll-token ENROLL-SECRET --no-service`,
        macos: `curl -fsSL ${BASE}/releases/download/v0.1.1/install-agent.sh | bash -s -- --version 0.1.1 --server ${BASE} --enroll-token ENROLL-SECRET --no-service`,
        windows: "iwr ... -NoService",
      },
    },
    fleet: {
      server_url: BASE,
      enroll_token: "ENROLL-SECRET",
      reachable_window: "1m0s",
      count: 3,
      enrolled: [
        {
          id: "AGT-1",
          host: "web01",
          os: "Ubuntu 24.04",
          version: "0.1.1",
          state: "scanning",
          phase: "correlation",
          percent: 45,
          message: "correlating advisories",
          findings: 12,
          last_report_id: "",
          enrolled_at: "2026-11-15T09:00:00Z",
          last_seen: "2026-11-15T10:00:00Z",
          seconds_since_seen: 8,
          online: true,
          watching: true,
          revoked: false,
        },
        {
          id: "AGT-2",
          host: "db01",
          os: "Debian 12",
          version: "0.1.1",
          state: "idle",
          phase: "idle",
          percent: 100,
          message: "reported 3 findings",
          findings: 3,
          last_report_id: "SCAN-1",
          enrolled_at: "2026-11-14T09:00:00Z",
          last_seen: "2026-11-14T09:30:00Z",
          seconds_since_seen: 90000,
          online: false,
          watching: false,
          revoked: false,
        },
        {
          id: "AGT-3",
          host: "old01",
          os: "",
          version: "",
          state: "error",
          phase: "",
          percent: 0,
          message: "revoked by operator",
          findings: 0,
          last_report_id: "",
          enrolled_at: "2026-11-10T09:00:00Z",
          online: false,
          watching: false,
          revoked: true,
        },
      ],
    },
    managed_mode: true,
    managed_note:
      "Endpoints enroll with a per-agent token and report findings and status to this server only. There is no remote command channel.",
  };
}

function mockAgents(overrides?: { enrolled?: unknown[] }) {
  const payload = agentsFixture();
  if (overrides?.enrolled) payload.fleet.enrolled = overrides.enrolled as typeof payload.fleet.enrolled;
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.startsWith("/api/agents/enroll-token")) {
      const linux = `curl -fsSL ${BASE}/releases/download/v0.1.1/install-agent.sh | bash -s -- --version 0.1.1 --server ${BASE} --enroll-token MINTED-SECRET`;
      return new Response(
        JSON.stringify({
          enroll_token: "MINTED-SECRET",
          expires_at: new Date(Date.now() + 86_400_000).toISOString(),
          single_use: true,
          commands: { linux, macos: linux, windows: "iwr ... -EnrollToken MINTED-SECRET" },
          oneoff_commands: { linux: `${linux} --no-service`, macos: `${linux} --no-service`, windows: "iwr ... -NoService" },
        }),
        { status: 200 },
      );
    }
    if (url.startsWith("/api/agents/")) {
      return new Response(JSON.stringify({ revoked: "AGT-2" }), { status: 200 });
    }
    if (url.startsWith("/api/agents")) {
      return new Response(JSON.stringify(payload), { status: 200 });
    }
    if (url.startsWith("/api/settings")) {
      return new Response(
        JSON.stringify({
          policy: { fail_on: "", fail_on_kev: false },
          offline_default: false,
          release_base: "",
          cache_path: "/tmp/intel.db",
          tool_version: "0.1.1",
          token_required: false,
          capabilities: {},
        }),
        { status: 200 },
      );
    }
    return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

beforeEach(() => {
  window.history.replaceState({}, "", "/settings?tab=agents");
});

describe("enrolled endpoint fleet", () => {
  it("shows each endpoint's live state and activity", async () => {
    mockAgents();
    render(<Settings />);

    const table = await screen.findByRole("table", { name: /Enrolled endpoints/i });
    const web01 = within(table).getByRole("row", { name: /web01/ });
    expect(within(web01).getByText("scanning")).toBeInTheDocument();
    expect(within(web01).getByText("correlation · 45%")).toBeInTheDocument();
    expect(within(web01).getByText("8s ago")).toBeInTheDocument();
    expect(within(web01).getByText("12")).toBeInTheDocument();
    // The hostname and the agent that owns it are in the same row, so an enrollment error that
    // names an agent ID can be traced to its endpoint without guessing.
    expect(within(web01).getByText("AGT-1")).toBeInTheDocument();

    const db01 = within(table).getByRole("row", { name: /db01/ });
    expect(within(db01).getByText("offline")).toBeInTheDocument();
    expect(within(db01).getByText("reported 3 findings")).toBeInTheDocument();
    expect(within(db01).getByText("AGT-2")).toBeInTheDocument();

    const old01 = within(table).getByRole("row", { name: /old01/ });
    expect(within(old01).getByText("revoked")).toBeInTheDocument();
    // A revoked identity keeps its ID on screen: that is the record holding the hostname.
    expect(within(old01).getByText("AGT-3")).toBeInTheDocument();
    // A revoked endpoint keeps its record but offers no revoke action.
    expect(within(old01).queryByRole("button", { name: /Revoke/i })).not.toBeInTheDocument();
  });

  it("hands the operator a command that enrolls the endpoint with this server", async () => {
    mockAgents();
    render(<Settings />);
    await screen.findByRole("table", { name: /Enrolled endpoints/i });

    // The command is visible before minting, with a placeholder token.
    expect(screen.getAllByText(/install-agent\.sh \| bash -s/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/<enroll-token>/).length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole("button", { name: /New enrollment token/i }));

    // Linux and macOS share the same shell one-liner, so both cards match.
    const commands = await screen.findAllByText(/install-agent\.sh \| bash -s/);
    expect(commands.length).toBeGreaterThanOrEqual(1);
    expect(commands[0]).toHaveTextContent(`--server ${BASE}`);
    expect(commands[0]).toHaveTextContent("--enroll-token MINTED-SECRET");
    // The operator can see the token the command embeds, and that it expires.
    expect(screen.getAllByText(/MINTED-SECRET/).length).toBeGreaterThan(0);
    expect(screen.getByText(/expires/i)).toBeInTheDocument();
  });

  it("revokes an endpoint and refreshes the list", async () => {
    const fetchMock = mockAgents();
    render(<Settings />);
    const table = await screen.findByRole("table", { name: /Enrolled endpoints/i });
    const db01 = within(table).getByRole("row", { name: /db01/ });

    await userEvent.click(within(db01).getByRole("button", { name: /Revoke/i }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/agents/AGT-2/revoke", expect.objectContaining({ method: "POST" })),
    );
    // The list is refetched so the row cannot keep claiming to be live.
    await waitFor(() => expect(fetchMock.mock.calls.filter(([u]) => String(u) === "/api/agents").length).toBeGreaterThan(1));
  });

  it("explains the empty fleet instead of showing an empty table", async () => {
    mockAgents({ enrolled: [] });
    render(<Settings />);
    expect(await screen.findByText(/No endpoints enrolled yet/i)).toBeInTheDocument();
  });
});
