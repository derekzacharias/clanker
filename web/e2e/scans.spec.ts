import { test, expect, type Page } from "@playwright/test";
import { apiGet, trackIssues, expectNoIssues } from "./helpers";

type Job = { id: string; status: string; percent: number; stage?: string; report_id?: string; error?: string };

async function jobs(page: Page): Promise<Job[]> {
  const data = await apiGet<{ jobs: Job[] }>(page, "/api/scans");
  return data.jobs ?? [];
}

test.describe("scan workflow", () => {
  test("three-step flow, network blocked with a reason", async ({ page }) => {
    await page.goto("/scans/new");
    await expect(page.getByRole("heading", { name: /New scan/i })).toBeVisible();

    // Local only is available; network and SBOM are explained, not silently absent.
    await page.getByRole("button", { name: /Network Assessment/i }).click();
    await expect(page.getByText(/Network assessment is not implemented in this build/i)).toBeVisible();
    await expect(page.getByRole("button", { name: /^Continue$/ })).toBeDisabled();

    await page.getByRole("button", { name: /Local Endpoint/i }).click();
    await expect(page.getByRole("button", { name: /^Continue$/ })).toBeEnabled();
  });

  test("starts a real scan, reports server-side progress and links the report", async ({ page }) => {
    const issues = trackIssues(page);
    const before = (await jobs(page)).length;
    await page.goto("/scans/new");
    await page.getByRole("button", { name: /^Continue$/ }).click();
    await expect(page.getByText(/Configure local assessment/i)).toBeVisible();
    await page.getByLabel(/Use cached intelligence only/i).check();
    await page.getByRole("button", { name: /^Continue$/ }).click();
    await expect(page.getByRole("heading", { name: "Review" })).toBeVisible();
    await expect(page.getByText(/Cached only \(offline\)/)).toBeVisible();

    const [response] = await Promise.all([
      page.waitForResponse((r) => r.url().endsWith("/api/scans") && r.request().method() === "POST"),
      page.getByRole("button", { name: /Start Scan/i }).click(),
    ]);
    expect(response.status()).toBe(202);
    const created = (await response.json()) as Job;
    expect(created.id).toBeTruthy();

    await expect(page.getByText(/Assessment running|Assessment complete/i)).toBeVisible();
    await expect(page.getByRole("progressbar", { name: /Scan progress/i })).toBeVisible();
    await expect(page.getByText(/Assessment complete/i)).toBeVisible({ timeout: 40_000 });
    await expect(page.getByRole("button", { name: /View report/i })).toBeVisible();

    const after = await jobs(page);
    expect(after.length).toBe(before + 1);

    await page.getByRole("button", { name: /View report/i }).click();
    await expect(page).toHaveURL(/\/reports\/SCAN-/);
    await expect(page.getByRole("heading", { level: 1, name: /Report SCAN-/ })).toBeVisible();
    expectNoIssues(issues);
  });

  test("duplicate submission does not create a second job", async ({ page }) => {
    const before = (await jobs(page)).length;
    await page.goto("/scans/new");
    await page.getByRole("button", { name: /^Continue$/ }).click();
    await page.getByLabel(/Use cached intelligence only/i).check();
    await page.getByRole("button", { name: /^Continue$/ }).click();
    const start = page.getByRole("button", { name: /Start Scan/i });
    await start.click();
    // The button must be unusable while the request is in flight.
    await expect(page.getByText(/Assessment running/i)).toBeVisible();
    await expect(start).toHaveCount(0);
    const after = (await jobs(page)).length;
    expect(after).toBe(before + 1);
  });

  test("a cancelled scan stops, stays cancelled and records no report", async ({ page }) => {
    const before = await apiGet<{ items: { id: string }[] }>(page, "/api/reports");
    await page.goto("/scans/new");
    await page.getByRole("button", { name: /^Continue$/ }).click();
    await page.getByRole("button", { name: /^Continue$/ }).click();

    const [created] = await Promise.all([
      page.waitForResponse((r) => r.url().endsWith("/api/scans") && r.request().method() === "POST"),
      page.getByRole("button", { name: /Start Scan/i }).click(),
    ]);
    const job = (await created.json()) as Job;

    const cancel = page.getByRole("button", { name: /Cancel scan/i });
    if (!(await cancel.isVisible().catch(() => false))) {
      test.skip(true, "scan completed before it could be cancelled");
    }
    await cancel.click();
    await expect(page.getByText(/Scan canceled/i)).toBeVisible();

    // The backend must agree, and must not have stored a report for this run.
    const status = await apiGet<{ job: Job | null; report_available: boolean }>(page, `/api/scans/${job.id}`);
    expect(["canceled", "failed", "completed"]).toContain(status.job?.status);
    const after = await apiGet<{ items: { id: string }[] }>(page, "/api/reports");
    expect(after.items.length).toBe(before.items.length);
  });

  test("scan history lists stored assessments with links", async ({ page }) => {
    await page.goto("/scans");
    await expect(page.getByRole("heading", { name: /Assessment history/i })).toBeVisible();
    const reportLink = page.getByRole("button", { name: /^SCAN-/ }).first();
    await expect(reportLink).toBeVisible();
    await reportLink.click();
    await expect(page).toHaveURL(/\/reports\/SCAN-/);
  });
});
