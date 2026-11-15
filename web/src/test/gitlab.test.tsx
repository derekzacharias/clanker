import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { GitLabTicketPanel } from "../components/GitLabTicketPanel";
import { GitLabSettings } from "../components/GitLabSettings";
import { ToastProvider } from "../components/ui/Toast";

/**
 * The GitLab integration from the operator's side: create a ticket, see it, refresh it,
 * and configure it without ever handling the token back from the server.
 */
const CONFIG = {
  enabled: true,
  url: "http://gitlab.test.intra:8929",
  project_id: 42,
  labels: ["security"],
  assignee: "",
  timeout_seconds: 15,
  allow_insecure_http: true,
  token_set: true,
  token_source: "file" as const,
  ready: true,
  blocked: "",
  verified_at: "2026-11-15T18:00:00Z",
  verify_ok: true,
  verify_note: "Connected and authenticated.",
  config_file: "/home/guard/.config/clanker-guard/gitlab.json",
};

const TICKET = {
  id: "TKT-1",
  finding_key: "abc123",
  asset: "web01",
  vulnerability_id: "CVE-2026-1234",
  project_id: 42,
  project_path: "platform/security",
  issue_iid: 42,
  issue_url: "http://gitlab.test.intra:8929/platform/security/-/issues/42",
  title: "[HIGH] CVE-2026-1234 | openssl | web01",
  labels: "security,high",
  state: "opened",
  assignee: "",
  created_by: "admin",
  created_at: "2026-11-15T18:00:00Z",
  last_synced_at: "2026-11-15T18:00:00Z",
  pending: false,
};

type Call = { url: string; method: string; body?: string };

function mockFetch(opts: { config?: Partial<typeof CONFIG>; createStatus?: number; createBody?: string } = {}) {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      const body = typeof init?.body === "string" ? init.body : undefined;
      calls.push({ url, method, body });

      if (url === "/api/integrations/gitlab" && method === "GET") {
        return new Response(JSON.stringify({ ...CONFIG, ...opts.config }), { status: 200 });
      }
      if (url === "/api/integrations/gitlab" && method === "PUT") {
        return new Response(JSON.stringify({ ...CONFIG, ...opts.config }), { status: 200 });
      }
      if (url === "/api/integrations/gitlab/test") {
        return new Response(
          JSON.stringify({
            ok: true,
            checks: [
              { name: "Server reachable and authenticated", ok: true, detail: "GitLab 19.5.5" },
              { name: "Access token identifies a user", ok: true, detail: "@guard-bot" },
              { name: "Destination project is readable", ok: true, detail: "platform/security" },
              { name: "Issues are enabled in the project", ok: true },
              { name: "Token may create issues", ok: true, detail: "access level 40" },
            ],
            version: "19.5.5",
            user: "guard-bot",
            can_create_issues: true,
            summary: "Connected and authenticated. Permissions look sufficient; no issue was created.",
          }),
          { status: 200 },
        );
      }
      if (url.startsWith("/api/integrations/gitlab/projects")) {
        return new Response(
          JSON.stringify({ items: [{ id: 42, name: "security", path_with_namespace: "platform/security", web_url: "", issues_enabled: true }], total: 1 }),
          { status: 200 },
        );
      }
      if (url.startsWith("/api/integrations/gitlab/users")) {
        return new Response(JSON.stringify({ items: [{ id: 7, username: "guard-bot", name: "Guard Bot" }], total: 1 }), { status: 200 });
      }
      if (url === "/api/integrations/gitlab/preview") {
        return new Response(
          JSON.stringify({
            title: "[HIGH] CVE-2026-1234 | openssl | web01",
            description: "# Security Vulnerability\n\n## Vulnerability Information\n\n- **CVE:** CVE-2026-1234\n",
            labels: ["security", "high"],
            label_field: "security,high",
            project_id: 42,
            finding_key: "abc123",
          }),
          { status: 200 },
        );
      }
      if (url === "/api/integrations/gitlab/tickets" && method === "POST") {
        if (opts.createStatus) {
          return new Response(opts.createBody ?? `{"error":"boom","code":"gitlab_error"}`, { status: opts.createStatus });
        }
        return new Response(JSON.stringify({ ticket: TICKET, created: true, reused: false, message: "Created issue #42 in platform/security" }), { status: 200 });
      }
      if (url.endsWith("/refresh")) {
        return new Response(JSON.stringify({ ticket: { ...TICKET, state: "closed" } }), { status: 200 });
      }
      return new Response("{}", { status: 200 });
    }),
  );
  return calls;
}

function renderPanel(initialTickets: (typeof TICKET)[] = []) {
  return render(
    <ToastProvider>
      <GitLabTicketPanel findingId="f1" initialTickets={initialTickets} />
    </ToastProvider>,
  );
}

describe("GitLab ticket creation", () => {
  it("previews the issue, creates it, and links to it", async () => {
    const calls = mockFetch();
    renderPanel();

    const create = await screen.findByRole("button", { name: /Create GitLab Ticket/ });
    fireEvent.click(create);

    // The preview comes from the server, so the operator sees exactly what will be sent.
    await waitFor(() => expect(screen.getByLabelText("Description")).toHaveValue(CONFIG_TITLE_DESCRIPTION));
    expect(screen.getByLabelText("Title")).toHaveValue("[HIGH] CVE-2026-1234 | openssl | web01");

    fireEvent.click(screen.getByRole("button", { name: /^Create Ticket$/ }));

    await waitFor(() => expect(screen.getByText("Created issue #42 in platform/security")).toBeInTheDocument());
    const link = screen.getByRole("link", { name: /View GitLab ticket #42/ });
    expect(link).toHaveAttribute("href", TICKET.issue_url);

    const post = calls.find((c) => c.url === "/api/integrations/gitlab/tickets" && c.method === "POST");
    expect(post).toBeDefined();
    const body = JSON.parse(String(post?.body));
    expect(body.finding_id).toBe("f1");
    expect(body.project_id).toBe(42);
    expect(body.title).toContain("CVE-2026-1234");
  });

  it("shows the existing ticket instead of a create action", async () => {
    const calls = mockFetch();
    renderPanel([TICKET]);
    await waitFor(() => expect(screen.getByText("GitLab ticket #42")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /Create GitLab Ticket/ })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /View GitLab ticket #42/ })).toHaveAttribute("href", TICKET.issue_url);

    fireEvent.click(screen.getByRole("button", { name: /Refresh status/ }));
    await waitFor(() => expect(screen.getByText("Closed")).toBeInTheDocument());
    expect(calls.some((c) => c.url.endsWith("/refresh") && c.method === "POST")).toBe(true);
  });

  it("surfaces GitLab's refusal without pretending a ticket exists", async () => {
    mockFetch({
      createStatus: 502,
      createBody: JSON.stringify({
        error: "The access token is not allowed to create issues in that project.",
        code: "gitlab_error",
      }),
    });
    renderPanel();
    fireEvent.click(await screen.findByRole("button", { name: /Create GitLab Ticket/ }));
    await waitFor(() => expect(screen.getByLabelText("Title")).toHaveValue("[HIGH] CVE-2026-1234 | openssl | web01"));
    fireEvent.click(screen.getByRole("button", { name: /^Create Ticket$/ }));

    await waitFor(() =>
      expect(screen.getByText("The access token is not allowed to create issues in that project.")).toBeInTheDocument(),
    );
    expect(screen.queryByRole("link", { name: /View GitLab ticket/ })).not.toBeInTheDocument();
  });

  it("stays out of the way when GitLab is not configured", async () => {
    mockFetch({ config: { url: "", enabled: false, ready: false, token_set: false } });
    renderPanel();
    // No panel at all: a finding flyout on an unconfigured install should not advertise
    // an integration that cannot work.
    await waitFor(() => expect(screen.queryByText("Ticketing")).not.toBeInTheDocument());
  });

  it("disables creation and explains what is missing when configuration is incomplete", async () => {
    mockFetch({ config: { ready: false, blocked: "No access token is configured." } });
    renderPanel();
    const button = await screen.findByRole("button", { name: /Create GitLab Ticket/ });
    expect(button).toBeDisabled();
    expect(screen.getByText("No access token is configured.")).toBeInTheDocument();
  });
});

const CONFIG_TITLE_DESCRIPTION =
  "# Security Vulnerability\n\n## Vulnerability Information\n\n- **CVE:** CVE-2026-1234\n";

describe("GitLab settings", () => {
  it("tests the connection and shows every check", async () => {
    const calls = mockFetch();
    render(
      <ToastProvider>
        <GitLabSettings />
      </ToastProvider>,
    );
    await waitFor(() => expect(screen.getByLabelText("GitLab server URL")).toHaveValue(CONFIG.url));

    fireEvent.click(screen.getByRole("button", { name: /Test connection/ }));
    await waitFor(() => expect(screen.getByText(/Permissions look sufficient; no issue was created/)).toBeInTheDocument());
    expect(screen.getByText(/Destination project is readable/)).toBeInTheDocument();
    // The test must not claim an issue was created.
    expect(screen.getByText(/It does not create an issue/)).toBeInTheDocument();
    expect(calls.find((c) => c.url === "/api/integrations/gitlab/test")).toBeDefined();
  });

  it("never asks the browser to send a stored token back", async () => {
    const calls = mockFetch();
    render(
      <ToastProvider>
        <GitLabSettings />
      </ToastProvider>,
    );
    await waitFor(() => expect(screen.getByLabelText("Access token")).toHaveValue(""));
    expect(screen.getByLabelText("Access token")).toHaveAttribute("placeholder", "•••••••• (stored)");

    fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));
    await waitFor(() => expect(calls.some((c) => c.url === "/api/integrations/gitlab" && c.method === "PUT")).toBe(true));
    const put = calls.find((c) => c.url === "/api/integrations/gitlab" && c.method === "PUT");
    const body = JSON.parse(String(put?.body));
    expect(body.token).toBeUndefined();
    expect(body.project_id).toBe(42);
  });

  it("sends a newly typed token exactly once", async () => {
    const calls = mockFetch();
    render(
      <ToastProvider>
        <GitLabSettings />
      </ToastProvider>,
    );
    const input = await screen.findByLabelText("Access token");
    fireEvent.change(input, { target: { value: "glpat-new-token" } });
    fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));
    await waitFor(() => expect(input).toHaveValue(""));
    const put = calls.find((c) => c.url === "/api/integrations/gitlab" && c.method === "PUT");
    expect(JSON.parse(String(put?.body)).token).toBe("glpat-new-token");
  });
});
