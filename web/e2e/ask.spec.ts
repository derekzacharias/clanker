import { test, expect } from "@playwright/test";
import { trackIssues, expectNoIssues } from "./helpers";

test.describe("Ask Guard", () => {
  test("answers from stored evidence and never triggers a scan or deployment", async ({ page }) => {
    const issues = trackIssues(page);
    const privileged: string[] = [];
    page.on("request", (req) => {
      const url = new URL(req.url());
      const method = req.method();
      if (method === "POST" && (url.pathname === "/api/scans" || url.pathname.includes("/transition"))) {
        privileged.push(`${method} ${url.pathname}`);
      }
    });

    await page.goto("/");
    await page.getByRole("button", { name: /Ask Guard/i }).first().click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText(/No model is consulted/i)).toBeVisible();

    await dialog.getByLabel(/^Question$/).fill("what should I patch first?");
    const [response] = await Promise.all([
      page.waitForResponse((r) => r.url().endsWith("/api/ask")),
      dialog.getByRole("button", { name: /^Ask$/ }).click(),
    ]);
    expect(response.status()).toBe(200);
    await expect(dialog.getByText(/Based on report SCAN-/)).toBeVisible();
    await expect(dialog.getByText(/Grounded in stored evidence/i)).toBeVisible();
    await expect(dialog.getByText(/Cited findings/i)).toBeVisible();

    expect(privileged, "Ask Guard must not trigger privileged actions").toEqual([]);
    expectNoIssues(issues);
  });

  test("answers improvement questions from proposals and reviews", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: /Ask Guard/i }).first().click();
    const dialog = page.getByRole("dialog");
    await dialog.getByRole("button", { name: /What did you learn from my false-positive reviews\?/ }).click();
    await expect(dialog.getByText(/review|No analyst reviews/i).first()).toBeVisible();
  });

  test("closes with Escape and returns focus to the trigger", async ({ page }) => {
    await page.goto("/");
    const trigger = page.getByRole("button", { name: /Ask Guard/i }).first();
    await trigger.click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(trigger).toBeFocused();
  });
});
