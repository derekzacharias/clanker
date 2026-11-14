import { expect, type Page } from "@playwright/test";

/** Console errors and failed responses collected for one page. */
export type PageIssues = {
  consoleErrors: string[];
  pageErrors: string[];
  badResponses: string[];
  failedRequests: string[];
};

/**
 * Attach listeners that record genuine client-side problems. 401s are excluded
 * because the auth tests provoke them deliberately.
 */
export function trackIssues(page: Page): PageIssues {
  const issues: PageIssues = { consoleErrors: [], pageErrors: [], badResponses: [], failedRequests: [] };
  page.on("console", (msg) => {
    if (msg.type() === "error") issues.consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => issues.pageErrors.push(err.message));
  page.on("response", (res) => {
    const status = res.status();
    if (status >= 400 && status !== 401) {
      issues.badResponses.push(`${status} ${res.request().method()} ${new URL(res.url()).pathname}`);
    }
  });
  page.on("requestfailed", (req) => {
    // Aborted navigations are part of normal SPA behaviour.
    if (req.failure()?.errorText === "net::ERR_ABORTED") return;
    issues.failedRequests.push(`${req.method()} ${new URL(req.url()).pathname}: ${req.failure()?.errorText}`);
  });
  return issues;
}

/** Fail the test if any tracked client-side problem was recorded. */
export function expectNoIssues(issues: PageIssues) {
  expect(issues.pageErrors, "unhandled page errors").toEqual([]);
  expect(issues.consoleErrors, "console errors").toEqual([]);
  expect(issues.badResponses, "HTTP responses >= 400").toEqual([]);
  expect(issues.failedRequests, "failed requests").toEqual([]);
}

/** Fetch from the API with the E2E token, from inside the page context. */
export async function apiGet<T>(page: Page, path: string): Promise<T> {
  const token = process.env.CLANKER_GUARD_TOKEN ?? "e2e-token";
  const res = await page.request.get(path, { headers: { "X-Guard-Token": token } });
  expect(res.ok(), `GET ${path} -> ${res.status()}`).toBeTruthy();
  return (await res.json()) as T;
}
