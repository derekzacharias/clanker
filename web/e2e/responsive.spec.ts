import { test, expect } from "@playwright/test";

const VIEWPORTS = [
  { name: "desktop", width: 1920, height: 1080 },
  { name: "laptop", width: 1366, height: 768 },
  { name: "tablet", width: 768, height: 1024 },
  { name: "mobile", width: 390, height: 844 },
  { name: "small-mobile", width: 320, height: 568 },
];

const PAGES = [
  { path: "/", name: "overview" },
  { path: "/vulnerabilities", name: "vulnerabilities" },
  { path: "/scans/new", name: "new-scan" },
  { path: "/settings?tab=improvement", name: "improvement" },
  { path: "/reports", name: "reports" },
];

/** Horizontal overflow of the page itself (tables are allowed to scroll internally). */
async function pageOverflow(page: import("@playwright/test").Page): Promise<number> {
  return page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
}

for (const viewport of VIEWPORTS) {
  test.describe(`${viewport.name} ${viewport.width}x${viewport.height}`, () => {
    test.use({ viewport: { width: viewport.width, height: viewport.height } });

    for (const target of PAGES) {
      test(`${target.name} fits without page-level overflow`, async ({ page }) => {
        await page.goto(target.path);
        await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
        expect(await pageOverflow(page)).toBeLessThanOrEqual(1);
        await page.screenshot({
          path: `.e2e/screenshots/${viewport.name}-${target.name}.png`,
          fullPage: false,
        });
      });
    }

    test("navigation adapts to the viewport", async ({ page }) => {
      await page.goto("/");
      const desktopNav = page.getByRole("navigation", { name: /Primary/i });
      if (viewport.width >= 1024) {
        await expect(desktopNav).toBeVisible();
        await expect(page.getByRole("button", { name: /Open navigation/i })).toHaveCount(0);
      } else {
        await expect(page.getByRole("button", { name: /Open navigation/i })).toBeVisible();
        await page.getByRole("button", { name: /Open navigation/i }).click();
        await expect(page.getByRole("navigation", { name: /Primary/i })).toBeVisible();
        await page.getByRole("navigation", { name: /Primary/i }).getByRole("link", { name: "Assets" }).click();
        await expect(page).toHaveURL(/\/assets$/);
        expect(await pageOverflow(page)).toBeLessThanOrEqual(1);
      }
    });
  });
}

test("wide tables scroll inside their container, not the page", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/vulnerabilities");
  const wrap = page.locator(".scroll-x").first();
  await expect(wrap).toBeVisible();
  const { scrollWidth, clientWidth } = await wrap.evaluate((el) => ({
    scrollWidth: el.scrollWidth,
    clientWidth: el.clientWidth,
  }));
  expect(scrollWidth).toBeGreaterThan(clientWidth);
  expect(await pageOverflow(page)).toBeLessThanOrEqual(1);
});

test("mobile dialog does not overflow the viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/vulnerabilities?q=CVE-2023-48795");
  await page.locator("tbody tr button").first().click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  const box = await dialog.boundingBox();
  expect(box!.width).toBeLessThanOrEqual(390 + 1);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});

test("dark mode keeps text readable and does not overflow", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Switch to dark theme/i }).click();
  await expect(page.locator("html")).toHaveClass(/dark/);
  expect(await pageOverflow(page)).toBeLessThanOrEqual(1);
  await page.screenshot({ path: ".e2e/screenshots/dark-overview.png" });
  // Preference survives a reload.
  await page.reload();
  await expect(page.locator("html")).toHaveClass(/dark/);
});
