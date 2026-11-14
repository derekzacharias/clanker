import { test, expect } from "@playwright/test";
import { apiGet, trackIssues, expectNoIssues } from "./helpers";

type Settings = { policy: { fail_on: string; fail_on_kev: boolean }; offline_default: boolean; cache_path: string; token_required: boolean };
type Agents = { install: { published: boolean; commands?: Record<string, string>; build_steps?: string[] }; endpoints: unknown[]; managed_note: string };

test.describe("settings", () => {
  test("all four tabs render their content", async ({ page }) => {
    const issues = trackIssues(page);
    await page.goto("/settings");
    await expect(page.getByText(/Assessment policy/i)).toBeVisible();

    await page.getByRole("tab", { name: /Intelligence/i }).click();
    await expect(page.getByText(/Vulnerability intelligence/i)).toBeVisible();
    await expect(page.getByRole("table").first()).toBeVisible();

    await page.getByRole("tab", { name: /Endpoint agents/i }).click();
    await expect(page.getByText(/This endpoint/i)).toBeVisible();

    await page.getByRole("tab", { name: /Continuous improvement/i }).click();
    await expect(page.getByText(/How this loop works/i)).toBeVisible();

    await page.getByRole("tab", { name: /^Access$/ }).click();
    await expect(page.getByText(/API access/i)).toBeVisible();
    expectNoIssues(issues);
  });

  test("policy changes persist and are returned by the API", async ({ page }) => {
    await page.goto("/settings");
    await page.getByLabel(/Failure threshold/i).selectOption("medium");
    await page.getByRole("switch", { name: /known-exploited finding is actionable/i }).click();
    await page.getByRole("button", { name: /Save changes/i }).click();
    await expect(page.getByText("Settings saved")).toBeVisible();

    await page.reload();
    await expect(page.getByLabel(/Failure threshold/i)).toHaveValue("medium");
    await expect(page.getByRole("switch", { name: /known-exploited finding is actionable/i })).toHaveAttribute("aria-checked", "true");

    const api = await apiGet<Settings>(page, "/api/settings");
    expect(api.policy.fail_on).toBe("medium");
    expect(api.policy.fail_on_kev).toBe(true);

    // Restore the default so later tests see a predictable scanner policy.
    await page.getByLabel(/Failure threshold/i).selectOption("");
    await page.getByRole("switch", { name: /known-exploited finding is actionable/i }).click();
    await page.getByRole("button", { name: /Save changes/i }).click();
    await expect(page.getByText("Settings saved")).toBeVisible();
  });

  test("intelligence shows freshness and never fabricates a clean feed", async ({ page }) => {
    await page.goto("/settings?tab=intelligence");
    const rows = page.getByRole("row");
    expect(await rows.count()).toBeGreaterThan(1);
    const body = await page.locator("main").innerText();
    // Either real timestamps or an explicit "no intelligence" statement.
    expect(/ago|stale|fresh|No intelligence/i.test(body)).toBeTruthy();
  });

  test("agent install section never shows fabricated release commands", async ({ page }) => {
    const api = await apiGet<Agents>(page, "/api/agents");
    await page.goto("/settings?tab=agents");
    if (api.install.published) {
      await expect(page.getByText(/curl -fsSL/).first()).toBeVisible();
    } else {
      await expect(page.getByText(/No agent artifacts have been published yet/i)).toBeVisible();
      await expect(page.getByText(/curl -fsSL https:\/\/github.com/)).toHaveCount(0);
      await expect(page.getByText(/build-agent-release\.sh/).first()).toBeVisible();
    }
    await expect(page.getByText(/no agent-to-server channel/i)).toBeVisible();
  });

  test("access tab reports token enforcement and the cache path", async ({ page }) => {
    const api = await apiGet<Settings>(page, "/api/settings");
    await page.goto("/settings?tab=access");
    await expect(page.getByText(api.cache_path)).toBeVisible();
    await expect(page.getByText(api.token_required ? /token required/i : /loopback only/i)).toBeVisible();
    await expect(page.getByText(/network_scan/)).toBeVisible();
    await expect(page.getByText(/not in this build/).first()).toBeVisible();
  });

  test("unknown tab value falls back to general settings", async ({ page }) => {
    await page.goto("/settings?tab=nonsense");
    await expect(page.getByText(/Assessment policy/i)).toBeVisible();
  });
});
