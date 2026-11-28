import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AISettings } from "../components/AISettings";
import { IssueAutomation } from "../components/IssueAutomation";
import { ToastProvider } from "../components/ui/Toast";
import { mockApi } from "./helpers";

/**
 * Settings → AI & Models and Settings → Issue automation, from the operator's side.
 *
 * The assertions that matter are the security ones: a saved key is never rendered back,
 * a stale model list says so, and automation defaults to doing nothing.
 */

const AI_STATE = {
  providers: [
    {
      id: "openai",
      label: "OpenAI",
      auth: "bearer",
      implemented: true,
      needs_endpoint: false,
      needs_api_version: false,
      needs_deployment: false,
      default_model: "gpt-4o-mini",
      key_hint: "sk-...",
      docs_url: "https://platform.openai.com/docs",
    },
    {
      id: "bedrock",
      label: "AWS Bedrock",
      auth: "bearer",
      implemented: false,
      needs_endpoint: false,
      needs_api_version: false,
      needs_deployment: false,
      notes: "Requires AWS SigV4 signing.",
    },
  ],
  settings: {
    provider: "openai",
    model: "gpt-4o-mini",
    allow_preview: false,
    last_test_ok: true,
    last_test_detail: "OpenAI answered (gpt-4o-mini, ok)",
    last_test_at: "2026-11-22T12:00:00Z",
  },
  credential: { provider: "openai", configured: true, mask: "••••cdef", source: "file" },
  catalog: {
    models: [
      { id: "gpt-4o-mini", name: "gpt-4o-mini", provider: "openai", status: "production", pricing_hint: "low", context_window: 128000 },
      { id: "gpt-4o", name: "gpt-4o", provider: "openai", status: "production", pricing_hint: "medium" },
    ],
    stale: false,
    total: 2,
  },
  store_dir: "/var/lib/clanker-guard/ai",
};

const AUTOMATION = {
  config: {
    mode: "manual",
    min_severity: "high",
    max_per_run: 10,
    labels: ["security"],
    assignee: "",
    reopen_closed: false,
    auto_sync: false,
    use_ai: true,
  },
  modes: ["manual", "assisted", "auto"],
  store_dir: "/var/lib/clanker-guard/automation",
  gitlab_project: 42,
};

describe("AI settings", () => {
  it("shows the saved credential as a mask, never the key", async () => {
    mockApi([["/api/settings/ai", AI_STATE]]);
    render(
      <ToastProvider>
        <AISettings />
      </ToastProvider>,
    );

    expect(await screen.findByText("AI provider")).toBeInTheDocument();
    expect(screen.getByText("••••cdef")).toBeInTheDocument();
    // The password field must be empty: a saved key is never sent to the browser.
    const keyInput = screen.getByLabelText("API key") as HTMLInputElement;
    expect(keyInput.value).toBe("");
    expect(keyInput.type).toBe("password");
  });

  it("marks unsupported providers instead of hiding them", async () => {
    mockApi([["/api/settings/ai", AI_STATE]]);
    render(
      <ToastProvider>
        <AISettings />
      </ToastProvider>,
    );
    expect(await screen.findByText(/AWS Bedrock — not supported yet/)).toBeInTheDocument();
  });

  it("renders a stale model catalog as stale", async () => {
    mockApi([
      [
        "/api/settings/ai",
        { ...AI_STATE, catalog: { ...AI_STATE.catalog, stale: true, warning: "Discovery failed (HTTP 500)" } },
      ],
    ]);
    render(
      <ToastProvider>
        <AISettings />
      </ToastProvider>,
    );
    expect(await screen.findByText(/Showing a cached model list/)).toBeInTheDocument();
    expect(screen.getByText(/Discovery failed/)).toBeInTheDocument();
  });

  it("offers only the models the API returned", async () => {
    mockApi([["/api/settings/ai", AI_STATE]]);
    render(
      <ToastProvider>
        <AISettings />
      </ToastProvider>,
    );
    const select = (await screen.findByLabelText("AI model")) as HTMLSelectElement;
    const options = Array.from(select.options).map((o) => o.value);
    expect(options).toContain("gpt-4o-mini");
    expect(options).toContain("gpt-4o");
    expect(options).not.toContain("text-embedding-3-large");
  });

  it("loads the model list as soon as a credential is saved", async () => {
    // Longer paths first: mockApi matches by prefix and "/api/settings/ai" would swallow
    // the credential and model routes.
    mockApi([
      [
        "/api/settings/ai/models",
        {
          provider: "openai",
          models: [{ id: "gpt-5.2", name: "gpt-5.2", provider: "openai", status: "production" }],
          total: 1,
          stale: false,
          source: "live",
          fetched_at: "2026-11-22T12:01:00Z",
        },
      ],
      [
        "/api/settings/ai/credential",
        { credential: { provider: "openai", configured: true, mask: "••••9999", source: "file" } },
      ],
      ["/api/settings/ai", { ...AI_STATE, catalog: { models: [], stale: false, total: 0 } }],
    ]);
    render(
      <ToastProvider>
        <AISettings />
      </ToastProvider>,
    );

    const key = (await screen.findByLabelText("API key")) as HTMLInputElement;
    fireEvent.change(key, { target: { value: "sk-test" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => {
      const select = screen.getByLabelText("AI model") as HTMLSelectElement;
      expect(Array.from(select.options).map((o) => o.value)).toContain("gpt-5.2");
    });
  });

  it("explains an empty model list instead of showing a silent dropdown", async () => {
    mockApi([["/api/settings/ai", { ...AI_STATE, catalog: { models: [], stale: false, total: 0 } }]]);
    render(
      <ToastProvider>
        <AISettings />
      </ToastProvider>,
    );
    expect(await screen.findByText(/No models loaded yet\. Press Refresh models/)).toBeInTheDocument();
  });
});

describe("Issue automation", () => {
  it("defaults to manual and disables 'Run now'", async () => {
    mockApi([
      ["/api/settings/automation/audit", { entries: [], total: 0 }],
      ["/api/settings/automation", AUTOMATION],
    ]);
    render(
      <ToastProvider>
        <IssueAutomation />
      </ToastProvider>,
    );

    expect(await screen.findByText("Create Issues for Me")).toBeInTheDocument();
    const run = screen.getByRole("button", { name: /run now/i });
    expect(run).toBeDisabled();
  });

  it("saves the mode when the operator switches to assisted", async () => {
    const fetchMock = mockApi([
      ["/api/settings/automation/audit", { entries: [], total: 0 }],
      ["/api/settings/automation", AUTOMATION],
    ]);
    render(
      <ToastProvider>
        <IssueAutomation />
      </ToastProvider>,
    );

    const assisted = await screen.findByRole("radio", { name: /AI-assisted/i });
    fireEvent.click(assisted);

    await waitFor(() => {
      // mockApi types the mock with one parameter, so the init object is read positionally.
      const calls = fetchMock.mock.calls as unknown as Array<[unknown, RequestInit | undefined]>;
      const put = calls.find(([, init]) => init?.method === "PUT");
      expect(put).toBeTruthy();
      expect(String(put?.[1]?.body)).toContain('"assisted"');
    });
  });

  it("explains that assisted mode never writes to GitLab", async () => {
    mockApi([
      ["/api/settings/automation/audit", { entries: [], total: 0 }],
      ["/api/settings/automation", AUTOMATION],
    ]);
    render(
      <ToastProvider>
        <IssueAutomation />
      </ToastProvider>,
    );
    expect(await screen.findByText(/Issues are drafted for you to review/)).toBeInTheDocument();
    expect(screen.getByText(/Qualifying findings become issues/)).toBeInTheDocument();
  });

  it("shows the audit trail when there is one", async () => {
    mockApi([
      [
        "/api/settings/automation/audit",
        {
          entries: [
            {
              at: "2026-11-22T12:00:00Z",
              action: "created",
              mode: "auto",
              cve: "CVE-2023-48795",
              asset: "openclaw",
              generator: "ai",
              provider: "openai",
              model: "gpt-4o-mini",
              issue_iid: 42,
              issue_url: "https://gitlab.test/issues/42",
            },
          ],
          total: 1,
        },
      ],
      ["/api/settings/automation", AUTOMATION],
    ]);
    render(
      <ToastProvider>
        <IssueAutomation />
      </ToastProvider>,
    );
    expect(await screen.findByText("CVE-2023-48795")).toBeInTheDocument();
    expect(screen.getByText("openai/gpt-4o-mini")).toBeInTheDocument();
  });
});
