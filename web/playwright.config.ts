import { defineConfig, devices } from "@playwright/test";

const PORT = Number(process.env.E2E_PORT ?? 8789);
const TOKEN = process.env.CLANKER_GUARD_TOKEN ?? "e2e-token";
const BASE_URL = `http://127.0.0.1:${PORT}`;

/**
 * E2E configuration.
 *
 * The server runs against a disposable copy of the cache and the token is
 * injected as localStorage, so the suite exercises the real auth path without
 * touching the developer's data.
 */
export default defineConfig({
  testDir: "./e2e",
  outputDir: "./.e2e/artifacts",
  timeout: 45_000,
  expect: { timeout: 10_000 },
  // One worker: the suite mutates one database (feedback, approvals, scans).
  workers: 1,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [["list"], ["html", { outputFolder: "./.e2e/report", open: "never" }]],
  use: {
    baseURL: BASE_URL,
    storageState: {
      cookies: [],
      origins: [{ origin: BASE_URL, localStorage: [{ name: "clanker-guard.token", value: TOKEN }] }],
    },
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    actionTimeout: 10_000,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } },
    { name: "firefox", use: { ...devices["Desktop Firefox"], viewport: { width: 1440, height: 900 } } },
    { name: "webkit", use: { ...devices["Desktop Safari"], viewport: { width: 1440, height: 900 } } },
  ],
  webServer: {
    command: "bash e2e/start-server.sh",
    url: `${BASE_URL}/api/health`,
    reuseExistingServer: false,
    timeout: 60_000,
    stdout: "pipe",
    stderr: "pipe",
    env: { CLANKER_GUARD_TOKEN: TOKEN, E2E_PORT: String(PORT) },
  },
});
