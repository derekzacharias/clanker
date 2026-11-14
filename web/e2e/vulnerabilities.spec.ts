import { test, expect } from "@playwright/test";
import { apiGet, trackIssues, expectNoIssues } from "./helpers";

type VulnList = {
  total: number;
  items: {
    id: string; cve: string; product: string; installed_version: string; severity: string;
    affected: string; confidence: string; kev: boolean; epss: number | null; fixed_version?: string;
    risk_score: number; evidence?: unknown[]; references?: { url: string }[]; explanation?: string;
    analyst?: { applicability: string };
  }[];
  facets: { severity: { key: string; count: number }[]; kev: number; fix_available: number };
};

test.describe("vulnerabilities", () => {
  test("table matches the API and is sorted by risk", async ({ page }) => {
    const issues = trackIssues(page);
    const api = await apiGet<VulnList>(page, "/api/vulnerabilities?limit=100");
    await page.goto("/vulnerabilities");
    await expect(page.getByRole("table")).toBeVisible();
    await expect(page.getByRole("table")).toContainText(api.items[0].cve);
    await expect(page.getByRole("table")).toContainText(api.items[0].product);

    const riskCells = await page.locator("tbody tr td:last-child").allTextContents();
    const risks = riskCells.map((t) => Number(t));
    expect(risks.length).toBeGreaterThan(1);
    expect([...risks].sort((a, b) => b - a)).toEqual(risks);
    expectNoIssues(issues);
  });

  test("severity filter narrows results and is reflected in the URL", async ({ page }) => {
    const api = await apiGet<VulnList>(page, "/api/vulnerabilities?severity=critical&limit=100");
    await page.goto("/vulnerabilities");
    await page.getByRole("button", { name: /^Critical/ }).click();
    await expect(page.getByRole("button", { name: /^Critical/ })).toHaveAttribute("aria-pressed", "true");
    await expect(page).toHaveURL(/severity=critical/);
    await expect(page.locator("tbody tr")).toHaveCount(Math.min(api.total, 100));
    const severities = await page.locator("tbody tr td:nth-child(4)").allTextContents();
    for (const s of severities) expect(s.toLowerCase()).toContain("critical");
  });

  test("KEV filter shows only known-exploited findings", async ({ page }) => {
    const kev = await apiGet<VulnList>(page, "/api/vulnerabilities?kev=true&limit=100");
    await page.goto("/vulnerabilities");
    await page.getByRole("button", { name: /Known exploited \(KEV\)/ }).click();
    if (kev.total === 0) {
      await expect(page.getByText(/No findings match these filters/i)).toBeVisible();
      return;
    }
    await expect(page.getByRole("table")).toBeVisible();
    const rows = page.locator("tbody tr");
    await expect(rows).toHaveCount(Math.min(kev.total, 100));
    await expect(rows.first()).toContainText("KEV");
  });

  test("the result cap is disclosed when more findings exist than are shown", async ({ page }) => {
    const api = await apiGet<VulnList>(page, "/api/vulnerabilities?limit=100");
    test.skip(api.total <= 100, "fixture has fewer than the page cap");
    await page.goto("/vulnerabilities");
    await expect(page.getByText(new RegExp(`Showing 100 of ${api.total} findings`))).toBeVisible();
    await expect(page.locator("tbody tr")).toHaveCount(100);
  });

  test("deep link with ?q= filters on first paint", async ({ page }) => {
    const api = await apiGet<VulnList>(page, "/api/vulnerabilities?q=CVE-2023-48795");
    await page.goto("/vulnerabilities?q=CVE-2023-48795");
    await expect(page.getByLabel(/Search by CVE/i)).toHaveValue("CVE-2023-48795");
    await expect(page.getByRole("table")).toContainText("CVE-2023-48795");
    await expect(page.getByRole("table").locator("tbody tr")).toHaveCount(api.total);
  });

  test("detail panel shows evidence, uncertainty and authoritative references", async ({ page }) => {
    const api = await apiGet<VulnList>(page, "/api/vulnerabilities?limit=5");
    await page.goto("/vulnerabilities");
    await page.getByRole("button", { name: api.items[0].cve }).first().click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole("heading", { name: new RegExp(api.items[0].cve) })).toBeVisible();
    await expect(dialog.getByText(/What this means/i)).toBeVisible();
    await expect(dialog.getByText(/not a validated vulnerability/i)).toBeVisible();
    await expect(dialog.getByRole("link", { name: /NVD/i })).toHaveAttribute(
      "href",
      `https://nvd.nist.gov/vuln/detail/${api.items[0].cve}`,
    );
    // Version-correlation findings must never be presented as validated.
    if (api.items[0].affected !== "validated_behavior") {
      await expect(dialog.getByText(/Validation status: version_correlation/i)).toBeVisible();
    }
  });

  test("false-positive feedback is verified, and an unsupported claim changes nothing", async ({ page }) => {
    const api = await apiGet<VulnList>(page, "/api/vulnerabilities?applicability=confirmed_applicability&limit=100");
    test.skip(api.items.length === 0, "no confirmed findings in this fixture");
    const target = api.items[0];

    await page.goto("/vulnerabilities?q=" + encodeURIComponent(target.cve));
    await page.getByRole("button", { name: target.cve }).first().click();
    const dialog = page.getByRole("dialog");
    await dialog.getByRole("button", { name: /Mark false positive/i }).click();
    // A false positive without a reason cannot be submitted.
    await expect(dialog.getByRole("button", { name: /Submit feedback/i })).toBeDisabled();
    await dialog.getByRole("radio", { name: /Vendor patch already installed/i }).check();
    await dialog.getByLabel(/Your name/i).fill("e2e-analyst");

    const [response] = await Promise.all([
      page.waitForResponse((r) => r.url().endsWith("/feedback") && r.request().method() === "POST"),
      dialog.getByRole("button", { name: /Submit feedback/i }).click(),
    ]);
    expect(response.status()).toBe(202);
    const payload = (await response.json()) as {
      verification: { supported: boolean; changed: boolean; confidence: string; explanation: string };
      state: { applicability: string } | null;
    };
    await expect(dialog.getByText(/Feedback recorded/i)).toBeVisible();

    if (payload.verification.supported && payload.verification.changed) {
      await expect(dialog.getByText(/Classification updated/i)).toBeVisible();
    } else {
      // Feedback alone is never proof: the scanner verdict must be untouched.
      await expect(dialog.getByText(/The scanner classification was not changed/i)).toBeVisible();
    }

    // History survives a reload.
    await page.reload();
    await page.getByRole("button", { name: target.cve }).first().click();
    await page.getByRole("dialog").getByRole("button", { name: /Review history/i }).click();
    await expect(page.getByRole("dialog").getByText(/e2e-analyst/)).toBeVisible();
  });

  test("confirming a finding records a review without rewriting the verdict", async ({ page }) => {
    const api = await apiGet<VulnList>(page, "/api/vulnerabilities?limit=1");
    const target = api.items[0];
    await page.goto("/vulnerabilities?q=" + encodeURIComponent(target.cve));
    await page.getByRole("button", { name: target.cve }).first().click();
    const dialog = page.getByRole("dialog");
    await dialog.getByRole("button", { name: /Confirm finding/i }).click();
    await dialog.getByLabel(/Your name/i).fill("e2e-confirmer");
    await dialog.getByRole("button", { name: /Submit feedback/i }).click();
    await expect(dialog.getByText(/Feedback recorded/i)).toBeVisible();
    await expect(dialog.getByText(/does not assert inapplicability/i)).toBeVisible();
  });
});
