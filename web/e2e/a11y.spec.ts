import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

/**
 * Automated accessibility checks. These catch a subset of WCAG 2.2 AA issues;
 * the keyboard tests below cover behaviour axe cannot see.
 */
const PAGES: { path: string; name: string }[] = [
  { path: "/", name: "overview" },
  { path: "/assets", name: "assets" },
  { path: "/assets/openclaw", name: "asset detail" },
  { path: "/vulnerabilities?q=CVE-2023-48795", name: "vulnerabilities" },
  { path: "/scans", name: "scans" },
  { path: "/scans/new", name: "new scan" },
  { path: "/reports", name: "reports" },
  { path: "/settings", name: "settings general" },
  { path: "/settings?tab=intelligence", name: "settings intelligence" },
  { path: "/settings?tab=agents", name: "settings agents" },
  { path: "/settings?tab=improvement", name: "settings improvement" },
  { path: "/settings?tab=access", name: "settings access" },
];

for (const p of PAGES) {
  test(`axe: ${p.name} has no serious or critical violations`, async ({ page }) => {
    await page.goto(p.path);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
      .analyze();
    const bad = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
    if (bad.length > 0) {
      console.log(
        JSON.stringify(
          bad.map((v) => ({ id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.slice(0, 4).map((n) => n.target) })),
          null,
          2,
        ),
      );
    }
    expect(bad).toEqual([]);
  });
}

test("axe: finding detail panel meets the same bar", async ({ page }) => {
  await page.goto("/vulnerabilities");
  await page.locator("tbody tr button").first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  const bad = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  if (bad.length > 0) console.log(JSON.stringify(bad.map((v) => ({ id: v.id, nodes: v.nodes.slice(0, 3).map((n) => n.target) })), null, 2));
  expect(bad).toEqual([]);
});

test.describe("keyboard workflows", () => {
  test("skip link is first and moves focus to main content", async ({ page }) => {
    await page.goto("/");
    await page.keyboard.press("Tab");
    const skip = page.getByRole("link", { name: /Skip to content/i });
    await expect(skip).toBeFocused();
    await expect(skip).toBeVisible();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/#main$/);
  });

  test("the whole sidebar is reachable with the keyboard", async ({ page }) => {
    await page.goto("/");
    const nav = page.getByRole("navigation", { name: /Primary/i });
    await nav.getByRole("link", { name: "Vulnerabilities" }).focus();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/vulnerabilities/);
  });

  test("dialogs trap focus, close on Escape and restore focus", async ({ page }) => {
    await page.goto("/");
    const trigger = page.getByRole("button", { name: /Ask Guard/i }).first();
    await trigger.click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();

    // Focus starts inside the dialog and never escapes while tabbing.
    for (let i = 0; i < 6; i++) {
      await page.keyboard.press("Tab");
      const inside = await page.evaluate(() => {
        const active = document.activeElement;
        const panel = document.querySelector('[role="dialog"]');
        return Boolean(active && panel && panel.contains(active));
      });
      expect(inside).toBe(true);
    }

    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(trigger).toBeFocused();
  });

  test("filters are operable without a mouse", async ({ page }) => {
    await page.goto("/vulnerabilities");
    const critical = page.getByRole("button", { name: /^Critical/ });
    await critical.focus();
    await page.keyboard.press("Enter");
    await expect(critical).toHaveAttribute("aria-pressed", "true");
  });

  test("tables expose column headers to assistive technology", async ({ page }) => {
    await page.goto("/vulnerabilities?q=CVE-2023-48795");
    await expect(page.getByRole("table").first()).toBeVisible();
    const headers = page.getByRole("table").first().getByRole("columnheader");
    expect(await headers.count()).toBeGreaterThan(4);
    const caption = await page.getByRole("table").first().locator("caption").textContent();
    expect(caption?.length ?? 0).toBeGreaterThan(3);
  });
});
