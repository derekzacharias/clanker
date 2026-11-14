import { test, expect } from "@playwright/test";
import { apiGet, trackIssues, expectNoIssues } from "./helpers";

type Evaluation = { passed: boolean; cases: { fixture: string; pass: boolean }[]; regressions?: string[] };
type Improvement = {
  id: string;
  status: string;
  title: string;
  risk_level: string;
  affected_findings: string[];
  evaluation?: Evaluation;
  rule_id?: string;
  rejected_reason?: string;
};
type Quality = {
  metrics: { reviewed: number; false_positives: number; false_positive_rate: number | null; open_improvements: number; deployed_improvements: number; notes?: string[] };
};

/**
 * Return a proposal awaiting approval, creating one through the API if needed.
 *
 * The suite must behave the same on a fresh fixture and on a second browser run,
 * so it cannot depend on whatever proposal happens to exist.
 */
async function ensurePendingProposal(page: import("@playwright/test").Page): Promise<Improvement | null> {
  const existing = await apiGet<{ items: Improvement[] }>(page, "/api/improvements");
  const ready = existing.items.find((i) => i.status === "awaiting_approval" && i.evaluation?.passed);
  if (ready) return ready;

  const token = process.env.CLANKER_GUARD_TOKEN ?? "e2e-token";
  const snap = await apiGet<{ items: { id: string; product: string }[] }>(
    page,
    "/api/vulnerabilities?q=thunderbird&applicability=needs_investigation&limit=5",
  );
  const finding = snap.items[0];
  if (!finding) return null;
  // A snap transition package resolves deterministically to needs_investigation,
  // which produces a proposal with fixtures.
  await page.request.post(`/api/vulnerabilities/${finding.id}/feedback`, {
    headers: { "X-Guard-Token": token, "Content-Type": "application/json" },
    data: { verdict: "false_positive", reason_code: "incorrect_identification", analyst: "e2e" },
  });
  const after = await apiGet<{ items: Improvement[] }>(page, "/api/improvements");
  return after.items.find((i) => i.status === "awaiting_approval" && i.evaluation?.passed) ?? null;
}

test.describe("continuous improvement", () => {
  test("quality metrics match the API and state their sample caveats", async ({ page }) => {
    const api = await apiGet<Quality>(page, "/api/quality");
    const issues = trackIssues(page);
    await page.goto("/settings?tab=improvement");
    await expect(page.getByText(/How this loop works/i)).toBeVisible();
    await expect(page.getByText(String(api.metrics.reviewed)).first()).toBeVisible();
    if (api.metrics.false_positive_rate === null) {
      await expect(page.getByText(/no reviews yet — no rate can be computed/i)).toBeVisible();
    }
    if (api.metrics.reviewed < 5) {
      await expect(page.getByText(/anecdotal until at least 5/i)).toBeVisible();
    }
    expectNoIssues(issues);
  });

  test("a proposal exposes its evidence, fixtures and audit trail", async ({ page }) => {
    const api = await apiGet<{ items: Improvement[] }>(page, "/api/improvements");
    test.skip(api.items.length === 0, "no proposals in this fixture");
    const target = api.items[0];

    await page.goto("/settings?tab=improvement");
    const card = page.locator("li", { hasText: target.id });
    await expect(card).toContainText(target.title);
    await expect(card).toContainText(target.status.replace(/_/g, " "));

    await card.getByRole("button", { name: /View changes/i }).click();
    const drawer = page.getByRole("dialog");
    await expect(drawer.getByRole("heading", { name: target.id })).toBeVisible();
    await expect(drawer.getByText(/^Problem$/i)).toBeVisible();
    await expect(drawer.getByText(/^Proposed change$/i)).toBeVisible();

    if (target.evaluation) {
      const rows = drawer.locator("table tbody tr");
      await expect(rows).toHaveCount(target.evaluation.cases.length);
      await expect(drawer.getByText(/candidate precision/i)).toBeVisible();
    }
    await expect(drawer.getByText(/^Lifecycle$/i)).toBeVisible();
    await expect(drawer.getByText(/Affected findings/i)).toBeVisible();
  });

  test("approve, deploy and roll back a proposal through the UI", async ({ page }) => {
    const pending = await ensurePendingProposal(page);
    test.skip(!pending, "could not produce a pending proposal");
    const id = pending!.id;

    // Remember which rule (if any) is active before this deployment so the
    // rollback assertion checks "previous known-good", not "nothing".
    const beforeState = await apiGet<{ active: { rule_id: string } }>(page, `/api/improvements/${id}`);
    const previouslyActive = beforeState.active.rule_id;

    await page.goto("/settings?tab=improvement");
    const card = page.locator("li", { hasText: id });
    await card.getByRole("button", { name: /^Approve$/ }).click();
    await expect(page.getByText(/Improvement approved/i)).toBeVisible();

    let current = await apiGet<{ improvement: Improvement }>(page, `/api/improvements/${id}`);
    expect(current.improvement.status).toBe("approved");

    await page.locator("li", { hasText: id }).getByRole("button", { name: /^Deploy$/ }).click();
    await expect(page.getByText(/Improvement deployed/i)).toBeVisible();
    current = await apiGet<{ improvement: Improvement }>(page, `/api/improvements/${id}`);
    expect(current.improvement.status).toBe("deployed");
    expect(current.improvement.rule_id).toBeTruthy();

    // The UI must reflect the backend's rule, not claim success on its own.
    const detail = await apiGet<{ active: { rule_id: string } }>(page, `/api/improvements/${id}`);
    expect(detail.active.rule_id).toBe(current.improvement.rule_id);

    await page.locator("li", { hasText: id }).getByRole("button", { name: /Roll back/i }).click();
    await expect(page.getByText(/Improvement rolled back/i)).toBeVisible();
    current = await apiGet<{ improvement: Improvement }>(page, `/api/improvements/${id}`);
    expect(current.improvement.status).toBe("rolled_back");
    const after = await apiGet<{ active: { rule_id: string } }>(page, `/api/improvements/${id}`);
    // Rollback restores the previously deployed rule (or defaults if none).
    expect(after.active.rule_id).toBe(previouslyActive);
  });

  test("rejection requires a written reason", async ({ page }) => {
    const pending = await ensurePendingProposal(page);
    test.skip(!pending, "could not produce a pending proposal");

    await page.goto("/settings?tab=improvement");
    const card = page.locator("li", { hasText: pending!.id });
    await card.getByRole("button", { name: /^Reject$/ }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByRole("heading", { name: /Reject this proposal/i })).toBeVisible();
    const confirm = dialog.getByRole("button", { name: /Reject proposal/i });
    await expect(confirm).toBeDisabled();
    await dialog.getByLabel(/^Reason$/).fill("duplicate of the deployed rule");
    await expect(confirm).toBeEnabled();
    await confirm.click();
    await expect(page.getByText(/Improvement rejected/i)).toBeVisible();

    const stored = await apiGet<{ improvement: Improvement }>(page, `/api/improvements/${pending!.id}`);
    expect(stored.improvement.status).toBe("rejected");
    expect(stored.improvement.rejected_reason).toBe("duplicate of the deployed rule");
  });
});
