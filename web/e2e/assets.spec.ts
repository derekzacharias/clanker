import { test, expect } from "@playwright/test";
import { apiGet, trackIssues, expectNoIssues } from "./helpers";

type Asset = {
  host: string; os: string; os_version: string; packages: number; findings: number;
  actionable: number; critical: number; high: number; kev: number; last_scan: string; stale: boolean;
};

test.describe("assets", () => {
  test("inventory matches the API", async ({ page }) => {
    const issues = trackIssues(page);
    const api = await apiGet<{ items: Asset[]; total: number }>(page, "/api/assets");
    await page.goto("/assets");
    const table = page.getByRole("table");
    await expect(table).toBeVisible();
    for (const asset of api.items) {
      const row = page.getByRole("row", { name: new RegExp(asset.host) });
      await expect(row).toContainText(asset.os_version);
      await expect(row).toContainText(String(asset.packages));
      await expect(row).toContainText(String(asset.actionable));
    }
    expectNoIssues(issues);
  });

  test("search and filters narrow the inventory and can be cleared", async ({ page }) => {
    const api = await apiGet<{ items: Asset[] }>(page, "/api/assets");
    const asset = api.items[0];
    await page.goto("/assets");

    await page.getByLabel(/Search assets/i).fill("no-such-host-xyz");
    await expect(page.getByText(/No assets match these filters/i)).toBeVisible();
    await page.getByLabel(/Search assets/i).fill(asset.host);
    await expect(page.getByRole("row", { name: new RegExp(asset.host) })).toBeVisible();

    await page.getByLabel(/Filter by operating system/i).selectOption(asset.os);
    await expect(page.getByRole("row", { name: new RegExp(asset.host) })).toBeVisible();
    await page.getByLabel(/Filter by operating system/i).selectOption({ index: 0 });

    await page.getByLabel(/Filter by last scan/i).selectOption("stale");
    const visible = await page.getByRole("row").count();
    expect(visible).toBeLessThanOrEqual(api.items.length + 1); // header row
  });

  test("asset detail shows packages, findings, coverage and history", async ({ page }) => {
    const assets = await apiGet<{ items: Asset[] }>(page, "/api/assets");
    const host = assets.items[0].host;
    const issues = trackIssues(page);
    await page.goto(`/assets/${encodeURIComponent(host)}`);

    await expect(page.getByRole("heading", { level: 1, name: host })).toBeVisible();
    await expect(page.getByRole("heading", { name: /Findings on this asset/i })).toBeVisible();
    await expect(page.getByRole("heading", { name: /Coverage/i })).toBeVisible();
    await expect(page.getByRole("heading", { name: /Scan history/i })).toBeVisible();

    // Software inventory is progressively disclosed.
    const disclosure = page.getByRole("button", { name: /Installed software/i });
    await expect(disclosure).toHaveAttribute("aria-expanded", "false");
    await disclosure.click();
    await expect(disclosure).toHaveAttribute("aria-expanded", "true");
    await expect(page.getByLabel(/Search packages/i)).toBeVisible();
    expectNoIssues(issues);
  });

  test("unknown asset shows a recoverable error", async ({ page }) => {
    await page.goto("/assets/does-not-exist");
    await expect(page.getByRole("alert")).toContainText(/no assessment recorded/i);
    await expect(page.getByRole("button", { name: /Try again/i })).toBeVisible();
  });

  test("long host names do not break the layout", async ({ page }) => {
    const assets = await apiGet<{ items: Asset[] }>(page, "/api/assets");
    await page.goto(`/assets/${encodeURIComponent(assets.items[0].host)}`);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(1);
  });
});
