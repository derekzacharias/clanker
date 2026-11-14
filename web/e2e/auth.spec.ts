import { test, expect } from "@playwright/test";

const BASE = `http://127.0.0.1:${process.env.E2E_PORT ?? 8789}`;
const TOKEN = process.env.CLANKER_GUARD_TOKEN ?? "e2e-token";

test.describe("authentication", () => {
  // No stored token: exercise the gate exactly as a first-time visitor would.
  test.use({ storageState: { cookies: [], origins: [{ origin: BASE, localStorage: [] }] } });

  test("the token dialog appears and rejects a wrong token", async ({ page }) => {
    await page.goto("/");
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText(/requires an API token/i)).toBeVisible();

    await dialog.getByPlaceholder("CLANKER_GUARD_TOKEN value").fill("definitely-wrong");
    await dialog.getByRole("button", { name: /Unlock/i }).click();

    // A rejected token is reported and cleared so retries cannot loop silently.
    await expect(dialog.getByText(/stored token was rejected/i)).toBeVisible();
    expect(await page.evaluate(() => localStorage.getItem("clanker-guard.token"))).toBeNull();
  });

  test("the correct token unlocks the interface", async ({ page }) => {
    await page.goto("/");
    const dialog = page.getByRole("dialog");
    await dialog.getByPlaceholder("CLANKER_GUARD_TOKEN value").fill(TOKEN);
    await dialog.getByRole("button", { name: /Unlock/i }).click();
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(page.getByRole("heading", { level: 1, name: /Security overview/i })).toBeVisible();
  });

  test("protected routes are not readable without a token", async ({ request }) => {
    const res = await request.get("/api/assets");
    expect(res.status()).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/X-Guard-Token/);
  });

  test("tokens never appear in the UI", async ({ page }) => {
    await page.goto("/");
    await page.getByPlaceholder("CLANKER_GUARD_TOKEN value").fill(TOKEN);
    await page.getByRole("button", { name: /Unlock/i }).click();
    await expect(page.getByRole("heading", { level: 1, name: /Security overview/i })).toBeVisible();
    const html = await page.content();
    expect(html.includes(TOKEN)).toBe(false);
    await page.goto("/settings?tab=access");
    const value = await page.getByPlaceholder("CLANKER_GUARD_TOKEN value").inputValue();
    expect(value).toBe(TOKEN); // password field, never rendered as text
    const type = await page.getByPlaceholder("CLANKER_GUARD_TOKEN value").getAttribute("type");
    expect(type).toBe("password");
  });
});
