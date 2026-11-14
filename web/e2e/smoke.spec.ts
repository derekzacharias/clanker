import { test, expect } from "@playwright/test";
import { trackIssues, expectNoIssues } from "./helpers";

/**
 * Route inventory: every reachable screen must render, be titled, and produce no
 * console errors, page errors or failed requests.
 */
const ROUTES: { path: string; heading: RegExp }[] = [
  { path: "/", heading: /Security overview|Run your first scan/i },
  { path: "/assets", heading: /^Assets$/i },
  { path: "/assets/openclaw", heading: /openclaw/i },
  { path: "/vulnerabilities", heading: /^Vulnerabilities$/i },
  { path: "/scans", heading: /^Scans$/i },
  { path: "/scans/new", heading: /^New scan$/i },
  { path: "/reports", heading: /^Reports$/i },
  { path: "/settings", heading: /^Settings$/i },
  { path: "/settings?tab=intelligence", heading: /^Settings$/i },
  { path: "/settings?tab=agents", heading: /^Settings$/i },
  { path: "/settings?tab=improvement", heading: /^Settings$/i },
  { path: "/settings?tab=access", heading: /^Settings$/i },
];

for (const route of ROUTES) {
  test(`route ${route.path} renders cleanly`, async ({ page }) => {
    const issues = trackIssues(page);
    await page.goto(route.path);
    await expect(page.getByRole("heading", { level: 1, name: route.heading })).toBeVisible();
    // No crash card, no auth prompt with a valid token.
    await expect(page.getByRole("alert").filter({ hasText: /could not be displayed/i })).toHaveCount(0);
    await expect(page.getByRole("dialog")).toHaveCount(0);
    expectNoIssues(issues);
  });
}

test("unknown route shows a recoverable 404 screen", async ({ page }) => {
  const issues = trackIssues(page);
  await page.goto("/does-not-exist");
  await expect(page.getByRole("heading", { name: /Page not found/i })).toBeVisible();
  await expect(page.getByRole("link", { name: /Back to overview/i })).toBeVisible();
  expectNoIssues(issues);
});

test("sidebar navigation reaches every section", async ({ page }) => {
  await page.goto("/");
  const nav = page.getByRole("navigation", { name: /Primary/i });
  for (const [label, url] of [
    ["Assets", /\/assets$/],
    ["Vulnerabilities", /\/vulnerabilities/],
    ["Scans", /\/scans$/],
    ["Reports", /\/reports$/],
    ["Settings", /\/settings/],
    ["Overview", /\/$/],
  ] as const) {
    await nav.getByRole("link", { name: label }).click();
    await expect(page).toHaveURL(url);
  }
});

test("active navigation item is marked for assistive technology", async ({ page }) => {
  await page.goto("/vulnerabilities");
  await expect(page.getByRole("navigation", { name: /Primary/i }).getByRole("link", { name: "Vulnerabilities" })).toHaveAttribute(
    "aria-current",
    "page",
  );
});
