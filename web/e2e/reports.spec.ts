import { test, expect } from "@playwright/test";
import { apiGet, trackIssues, expectNoIssues } from "./helpers";

type Run = { id: string; host: string; findings: number; actionable: number; kev_count: number };
type Report = {
  schema_version: string;
  report_id: string;
  metadata: { host: string; mode: string; coverage: { packages_inspected: number } };
  summary: { total: number; actionable: number; kev_count: number };
  findings: unknown[];
};

test.describe("reports", () => {
  test("list matches the API and opens the selected report", async ({ page }) => {
    const issues = trackIssues(page);
    const api = await apiGet<{ items: Run[] }>(page, "/api/reports");
    test.skip(api.items.length === 0, "no stored reports");
    await page.goto("/reports");
    const row = page.getByRole("row", { name: new RegExp(api.items[0].id) });
    await expect(row).toBeVisible();

    await row.getByRole("button", { name: api.items[0].id }).click();
    await expect(page).toHaveURL(new RegExp(`/reports/${api.items[0].id}`));
    await expect(page.getByRole("heading", { level: 1, name: new RegExp(`Report ${api.items[0].id}`) })).toBeVisible();

    const report = await apiGet<Report>(page, `/api/reports/${api.items[0].id}`);
    await expect(page.getByText(String(report.summary.kev_count)).first()).toBeVisible();
    await expect(page.getByText(new RegExp(`${report.metadata.host}`)).first()).toBeVisible();
    expectNoIssues(issues);
  });

  test("exports are valid in every advertised format", async ({ page }) => {
    const api = await apiGet<{ items: Run[] }>(page, "/api/reports");
    test.skip(api.items.length === 0, "no stored reports");
    const id = api.items[0].id;
    const token = process.env.CLANKER_GUARD_TOKEN ?? "e2e-token";

    const json = await page.request.get(`/api/reports/${id}/export?format=json`, { headers: { "X-Guard-Token": token } });
    expect(json.headers()["content-disposition"]).toContain("attachment");
    const doc = (await json.json()) as Report;
    expect(doc.report_id).toBe(id);
    expect(doc.schema_version).toBe("1.0");

    const sarif = await page.request.get(`/api/reports/${id}/export?format=sarif`, { headers: { "X-Guard-Token": token } });
    const sarifDoc = (await sarif.json()) as { version: string; runs: { tool: { driver: { name: string } }; results: unknown[] }[] };
    expect(sarifDoc.version).toBe("2.1.0");
    expect(sarifDoc.runs[0].tool.driver.name).toBe("clanker-guard");
    expect(sarifDoc.runs[0].results.length).toBeGreaterThan(0);

    const md = await page.request.get(`/api/reports/${id}/export?format=markdown`, { headers: { "X-Guard-Token": token } });
    expect(await md.text()).toContain("# Clanker Guard assessment");

    const html = await page.request.get(`/api/reports/${id}/export?format=html`, { headers: { "X-Guard-Token": token } });
    expect((await html.text()).toLowerCase()).toContain("<!doctype html>");

    const bad = await page.request.get(`/api/reports/${id}/export?format=pdf`, { headers: { "X-Guard-Token": token } });
    expect(bad.status()).toBe(400);
  });

  test("export buttons download without leaving the app", async ({ page }) => {
    const api = await apiGet<{ items: Run[] }>(page, "/api/reports");
    test.skip(api.items.length === 0, "no stored reports");
    const id = api.items[0].id;
    await page.goto(`/reports/${id}`);

    // Regression: these used to be plain <a href> navigations, which the browser
    // sent without X-Guard-Token and landed on a 401 page.
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("button", { name: "json", exact: true }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/^clanker-guard-SCAN-.*\.json$/);
    const stream = await download.createReadStream();
    let body = "";
    for await (const chunk of stream) body += chunk.toString();
    const parsed = JSON.parse(body) as { report_id: string };
    expect(parsed.report_id).toBe(id);

    await expect(page).toHaveURL(new RegExp(`/reports/${id}$`));
    await expect(page.getByText(/Downloaded clanker-guard-/)).toBeVisible();
  });

  test("the reports list exports rows without navigating away", async ({ page }) => {
    const api = await apiGet<{ items: Run[] }>(page, "/api/reports");
    test.skip(api.items.length === 0, "no stored reports");
    await page.goto("/reports");
    const row = page.getByRole("row", { name: new RegExp(api.items[0].id) });
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      row.getByRole("button", { name: "sarif", exact: true }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/\.sarif$/);
    await expect(page).toHaveURL(/\/reports$/);
  });

  test("unknown report id shows a recoverable error", async ({ page }) => {
    await page.goto("/reports/SCAN-does-not-exist");
    await expect(page.getByRole("alert")).toContainText(/no stored assessment/i);
    await expect(page.getByRole("button", { name: /Try again/i })).toBeVisible();
  });

  test("report states coverage limits instead of claiming security", async ({ page }) => {
    const api = await apiGet<{ items: Run[] }>(page, "/api/reports");
    test.skip(api.items.length === 0, "no stored reports");
    await page.goto(`/reports/${api.items[0].id}`);
    await expect(page.getByText(/not a statement that the environment is secure/i)).toBeVisible();
  });
});
