import { test, expect } from "@playwright/test";
import { apiGet, trackIssues, expectNoIssues } from "./helpers";

type Overview = {
  has_data: boolean;
  metrics: { assets: number; critical: number; high: number; medium: number; low: number; kev: number; actionable: number; needs_investigation: number };
  severity: { key: string; count: number }[];
  priority: { id: string; cve: string; product: string; severity: string; risk_score: number }[];
  coverage: { assessed: number; stale: number; last_scan_at: string };
  improvements_available: number;
  reviewed_findings: number;
};

test.describe("overview", () => {
  test("metrics match the API exactly", async ({ page }) => {
    const issues = trackIssues(page);
    const api = await apiGet<Overview>(page, "/api/overview");
    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1, name: /Security overview/i })).toBeVisible();

    const cards = page.locator("section.card", { has: page.locator("p", { hasText: /^Assets$/ }) });
    await expect(cards.first()).toContainText(String(api.metrics.assets));
    await expect(page.getByText("Known exploited").locator("..").locator("..")).toContainText(String(api.metrics.kev));

    // Severity legend carries the numbers as text.
    const severityCard = page.locator("section.card", {
      has: page.getByRole("heading", { name: "Severity distribution" }),
    });
    for (const row of api.severity) {
      if (row.key === "unknown") continue;
      const label = row.key.charAt(0).toUpperCase() + row.key.slice(1);
      const legend = severityCard.locator("li", { hasText: label }).first();
      await expect(legend).toContainText(String(row.count));
    }
    expectNoIssues(issues);
  });

  test("priority findings are ordered by risk and open the matching finding", async ({ page }) => {
    const api = await apiGet<Overview>(page, "/api/overview");
    await page.goto("/");
    const priority = page.getByRole("link", { name: new RegExp(api.priority[0].cve) });
    await expect(priority).toBeVisible();

    const scores = api.priority.map((p) => p.risk_score);
    expect([...scores].sort((a, b) => b - a)).toEqual(scores);

    await priority.click();
    await expect(page).toHaveURL(new RegExp(`/vulnerabilities\\?q=${encodeURIComponent(api.priority[0].cve).replace(/%/g, "%")}`));
    await expect(page.getByRole("table")).toContainText(api.priority[0].cve);
  });

  test("coverage and limitations are stated, never claimed as 'secure'", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByText(/Latest completed/i)).toBeVisible();
    await expect(page.getByRole("heading", { name: /Coverage limitations/i })).toBeVisible();
    await expect(page.getByText(/A completed scan is not proof the environment is secure/i)).toBeVisible();
  });

  test("improvement indicator links to the proposals", async ({ page }) => {
    const api = await apiGet<Overview>(page, "/api/overview");
    test.skip(api.improvements_available === 0, "no proposals in this fixture");
    await page.goto("/");
    await page.getByRole("link", { name: /Review proposals/i }).click();
    await expect(page).toHaveURL(/settings\?tab=improvement/);
    await expect(page.getByRole("tab", { name: /Continuous improvement/i })).toHaveAttribute("aria-selected", "true");
  });

  test("reloading preserves the view", async ({ page }) => {
    await page.goto("/");
    const before = await page.getByRole("heading", { level: 1 }).textContent();
    await page.reload();
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(before ?? "");
  });
});
