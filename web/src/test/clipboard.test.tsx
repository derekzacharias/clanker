import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Settings from "../pages/Settings";
import { copyText } from "../lib/clipboard";

/**
 * Regression tests for the Copy buttons on plain-HTTP deployments.
 *
 * The dashboard is served over http://<lan-ip>:8787, which is NOT a secure
 * context, so `navigator.clipboard` is undefined there. Calling it threw, the
 * empty catch hid the failure, and the button looked dead. These tests pin the
 * fallback chain and the visible feedback.
 */
function setSecureContext(secure: boolean) {
  Object.defineProperty(window, "isSecureContext", { value: secure, configurable: true });
}

function removeClipboardApi() {
  Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
}

function agentsPayload() {
  return {
    local: { host: "guard", version: "0.1.1", cache_path: "/tmp/intel.db", platform: "linux/amd64", installed: true },
    endpoints: [],
    install: {
      published: true,
      version: "0.1.1",
      base_url: "https://example.test/v0.1.1",
      requires_enroll_token: true,
      mint_endpoint: "/api/agents/enroll-token",
    },
    fleet: { server_url: "http://guard:8787", enroll_token: "SECRET", online_window: "15m0s", count: 0, enrolled: [] },
    managed_mode: true,
    managed_note: "Endpoints report to this server only. There is no remote command channel.",
  };
}

function mockAgentsApi() {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.startsWith("/api/agents/enroll-token")) {
        const linux = "curl -fsSL https://example.test/v0.1.1/install-agent.sh | bash -s -- --version 0.1.1 --server http://guard:8787 --enroll-token MINTED";
        return new Response(
          JSON.stringify({
            enroll_token: "MINTED",
            expires_at: new Date(Date.now() + 86_400_000).toISOString(),
            single_use: true,
            commands: { linux, macos: linux, windows: "iwr ..." },
            oneoff_commands: { linux: `${linux} --no-service`, macos: linux, windows: "iwr ..." },
          }),
          { status: 200 },
        );
      }
      if (url.startsWith("/api/agents")) {
        return new Response(JSON.stringify(agentsPayload()), { status: 200 });
      }
      if (url.startsWith("/api/settings")) {
        return new Response(
          JSON.stringify({
            policy: { fail_on: "", fail_on_kev: false },
            offline_default: false,
            release_base: "https://example.test/v0.1.1",
            cache_path: "/tmp/intel.db",
            tool_version: "0.1.1",
            token_required: false,
            capabilities: {},
          }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
    }),
  );
}

beforeEach(() => {
  window.history.replaceState({}, "", "/settings?tab=agents");
  setSecureContext(true);
});

describe("copyText", () => {
  it("uses the async clipboard API in a secure context", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });

    await expect(copyText("hello")).resolves.toBe("copied");
    expect(writeText).toHaveBeenCalledWith("hello");
  });

  it("falls back to execCommand when the clipboard API is missing (plain HTTP)", async () => {
    setSecureContext(false);
    removeClipboardApi();
    const execCommand = vi.fn(() => true);
    Object.defineProperty(document, "execCommand", { value: execCommand, configurable: true });

    await expect(copyText("curl ... --enroll-token SECRET")).resolves.toBe("copied");
    expect(execCommand).toHaveBeenCalledWith("copy");
  });

  it("reports manual when both paths are blocked", async () => {
    setSecureContext(false);
    removeClipboardApi();
    Object.defineProperty(document, "execCommand", { value: vi.fn(() => false), configurable: true });

    await expect(copyText("text")).resolves.toBe("manual");
  });

  it("does not attempt a copy for empty text", async () => {
    await expect(copyText("")).resolves.toBe("manual");
  });
});

describe("install command copy button", () => {
  it("copies on plain HTTP instead of silently doing nothing", async () => {
    setSecureContext(false);
    removeClipboardApi();
    const execCommand = vi.fn(() => true);
    Object.defineProperty(document, "execCommand", { value: execCommand, configurable: true });
    mockAgentsApi();

    render(<Settings />);
    await userEvent.click(await screen.findByRole("button", { name: /New enrollment token/i }));
    const button = await screen.findByRole("button", { name: /Copy Linux install command/i });
    await userEvent.click(button);

    await waitFor(() => expect(screen.getAllByText("Copied").length).toBeGreaterThan(0));
    expect(execCommand).toHaveBeenCalledWith("copy");
  });

  it("also copies the enrollment token on plain HTTP", async () => {
    setSecureContext(false);
    removeClipboardApi();
    const execCommand = vi.fn(() => true);
    Object.defineProperty(document, "execCommand", { value: execCommand, configurable: true });
    mockAgentsApi();

    render(<Settings />);
    await userEvent.click(await screen.findByRole("button", { name: /New enrollment token/i }));
    const button = await screen.findByRole("button", { name: /Copy enrollment token/i });
    await userEvent.click(button);

    await waitFor(() => expect(execCommand).toHaveBeenCalledWith("copy"));
    await waitFor(() => expect(button).toHaveTextContent("Copied"));
  });

  it("tells the operator to press Ctrl+C when the browser refuses to copy", async () => {
    setSecureContext(false);
    removeClipboardApi();
    Object.defineProperty(document, "execCommand", { value: vi.fn(() => false), configurable: true });
    mockAgentsApi();

    render(<Settings />);
    await userEvent.click(await screen.findByRole("button", { name: /New enrollment token/i }));
    const button = await screen.findByRole("button", { name: /Copy Linux install command/i });
    await userEvent.click(button);

    // The visible explanation (the sr-only live region says it too).
    expect(await screen.findByText(/This browser blocks clipboard access over plain HTTP/i)).toBeInTheDocument();
    // The command stays visible and is selected, so the keyboard shortcut works.
    expect(screen.getAllByText(/install-agent\.sh/).length).toBeGreaterThan(0);
  });
});
