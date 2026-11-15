import { expect, test } from "@playwright/test";
import { expectNoIssues, trackIssues } from "./helpers";

/**
 * Password sign-in, driven in a real browser against a dedicated server started
 * with `E2E_MODE=password` (see playwright.config.ts).
 *
 * These assertions are the whole point of the feature: a first-time visitor is
 * sent to /login instead of being asked for a token, the session cookie carries
 * the hardening attributes, and it keeps working across a page reload.
 */
const AUTH_PORT = Number(process.env.E2E_AUTH_PORT ?? 8791);
const BASE = `http://127.0.0.1:${AUTH_PORT}`;
const PASSWORD = process.env.E2E_PASSWORD ?? "e2e-dashboard-password";

test.describe("password sign-in", () => {
  // Fresh browser: no session cookie, no stored token.
  test.use({ baseURL: BASE, storageState: { cookies: [], origins: [] } });

  test("an unauthenticated visitor is sent to the sign-in page", async ({ page }) => {
    const issues = trackIssues(page);
    await page.goto(BASE + "/vulnerabilities?q=openssl");

    await expect(page).toHaveURL(/\/login\?next=/);
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await expect(page.getByLabel("Username")).toBeVisible();
    await expect(page.getByLabel("Password")).toBeVisible();
    // The dashboard data never renders while unauthenticated.
    await expect(page.getByRole("heading", { name: /Security overview/i })).toHaveCount(0);
    expectNoIssues(issues);
  });

  test("a wrong password is reported without leaving the page", async ({ page }) => {
    await page.goto(BASE + "/login");
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("definitely-the-wrong-password");
    await page.getByRole("button", { name: "Sign in" }).click();

    await expect(page.getByRole("alert")).toHaveText(/invalid username or password/i);
    await expect(page).toHaveURL(/\/login/);
    await expect(page.getByLabel("Password")).toHaveValue("");
  });

  test("the right password signs in, hardens the cookie and survives a reload", async ({ page, context }) => {
    const issues = trackIssues(page);
    await page.goto(BASE + "/login?next=%2Fvulnerabilities");
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill(PASSWORD);
    await page.getByRole("button", { name: "Sign in" }).click();

    // Back to the page that was originally requested.
    await expect(page).toHaveURL(`${BASE}/vulnerabilities`);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();

    const cookie = (await context.cookies()).find((c) => c.name === "guard_session");
    expect(cookie, "session cookie was not set").toBeTruthy();
    expect(cookie?.httpOnly).toBe(true);
    expect(cookie?.sameSite).toBe("Strict");
    expect(cookie?.path).toBe("/");

    // A reload must not send the user back to /login.
    await page.reload();
    await expect(page).toHaveURL(`${BASE}/vulnerabilities`);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    expectNoIssues(issues);
  });

  test("signing out ends the session", async ({ page, context }) => {
    await page.goto(BASE + "/login");
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill(PASSWORD);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(BASE + "/");

    await page.getByRole("button", { name: /Sign out/i }).click();
    await expect(page).toHaveURL(/\/login/);

    // The cookie is gone and the API refuses the browser again.
    const cookies = await context.cookies();
    expect(cookies.find((c) => c.name === "guard_session")).toBeFalsy();
    const res = await page.request.get(BASE + "/api/overview");
    expect(res.status()).toBe(401);
  });

  test("a cross-site state change carrying the cookie is refused", async ({ page }) => {
    await page.goto(BASE + "/login");
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill(PASSWORD);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(BASE + "/");

    const body = { policy: { fail_on: "high", fail_on_kev: false }, offline_default: false, release_base: "" };
    const crossSite = await page.request.put(BASE + "/api/settings", {
      headers: { Origin: "http://evil.example" },
      data: body,
    });
    expect(crossSite.status()).toBe(403);

    const sameSite = await page.request.put(BASE + "/api/settings", {
      headers: { Origin: BASE },
      data: body,
    });
    expect(sameSite.status()).toBe(200);
  });
});
