import { test, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { apiGet, trackIssues, expectNoIssues } from "./helpers";

type Job = { id: string; status: string; stage?: string; report_id?: string };

async function waitForJob(page: Page, id: string) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const detail = await apiGet<{ job: Job | null; report_available: boolean; report?: Record<string, unknown> }>(
      page,
      `/api/scans/${id}`,
    );
    const status = detail.job?.status;
    if (status === "completed" || status === "failed" || status === "canceled") {
      return { status, report: detail.report as ReportShape | undefined };
    }
    await page.waitForTimeout(400);
  }
  throw new Error(`job ${id} did not finish`);
}

type ReportShape = {
  metadata: {
    mode: string;
    scope?: { name: string; authorized_by: string; expires_at?: string; targets: string[] };
    coverage: { sources_used: string[]; limitations: string[] };
    errors?: string[];
  };
  inventory: { packages: { name: string; version: string; ecosystem: string }[]; warnings?: string[] };
  findings: {
    vulnerability_id: string;
    product: string;
    affected: string;
    severity: string;
    evidence?: { kind: string }[];
  }[];
};

const scopeYaml = (port?: number) => `name: e2e-loopback
authorized_by: e2e
authorized_at: 2026-01-01T00:00:00Z
expires_at: 2030-01-01T00:00:00Z
targets: [127.0.0.1]
ports: [${port ?? 22}]
max_hosts: 1
allow_public_addresses: false`;

test.describe("network assessment", () => {
  test("the form requires authorisation and reports the scope it will use", async ({ page }) => {
    await page.goto("/scans/new");
    await page.getByRole("button", { name: /Network Assessment/i }).click();
    await page.getByRole("button", { name: /^Continue$/ }).click();

    await expect(page.getByText(/Only scan what you are authorised to scan/i)).toBeVisible();
    await expect(page.getByLabel(/Scope document/i)).toBeVisible();

    // The wizard advances, but starting is refused until authorisation is given.
    await page.getByRole("button", { name: /^Continue$/ }).click();
    await expect(page.getByRole("heading", { name: "Review" })).toBeVisible();
    await expect(page.getByText("Network assessment")).toBeVisible();
    await expect(page.getByRole("button", { name: /Start Scan/i })).toBeDisabled();
    await expect(page.getByText(/Confirm the authorisation checkbox/i)).toBeVisible();

    await page.getByRole("button", { name: /Back/i }).click();
    await page.getByLabel(/I confirm I am authorised/i).check();
    await page.getByRole("button", { name: /^Continue$/ }).click();
    await expect(page.getByRole("button", { name: /Start Scan/i })).toBeEnabled();
    await expect(page.getByText(/e2e|my-scope/)).toBeVisible();
  });

  test("scans an authorised loopback scope and reports services honestly", async ({ page }) => {
    const issues = trackIssues(page);
    const created = await page.request.post("/api/scans", {
      headers: {
        "X-Guard-Token": process.env.CLANKER_GUARD_TOKEN ?? "e2e-token",
        "Content-Type": "application/json",
      },
      data: { kind: "network", authorized: true, scope_yaml: scopeYaml(22), offline: true },
    });
    expect(created.status()).toBe(202);
    const job = (await created.json()) as Job;
    const { status } = await waitForJob(page, job.id);
    expect(status).toBe("completed");

    const detail = await apiGet<{ report_available: boolean; report: ReportShape }>(page, `/api/scans/${job.id}`);
    const report = detail.report;
    expect(report.metadata.mode).toBe("network");
    expect(report.metadata.scope?.name).toBe("e2e-loopback");
    expect(report.metadata.scope?.authorized_by).toBe("e2e");
    expect(report.metadata.scope?.expires_at).toBeTruthy();
    expect(report.metadata.coverage.limitations.join(" ")).toMatch(/non-destructive|fingerprint/i);

    // A service was found (sshd on loopback in this environment) and any
    // distro-build finding must never be presented as confirmed.
    for (const f of report.findings) {
      if (f.product === "openssh") {
        expect(f.affected, "distribution builds must not be confirmed from upstream versions").toBe(
          "needs_investigation",
        );
        expect(f.evidence?.some((e) => e.kind === "distro_build")).toBe(true);
      }
    }
    expectNoIssues(issues);
  });

  test("rejects an expired scope with a clear message", async ({ page }) => {
    const res = await page.request.post("/api/scans", {
      headers: {
        "X-Guard-Token": process.env.CLANKER_GUARD_TOKEN ?? "e2e-token",
        "Content-Type": "application/json",
      },
      data: {
        kind: "network",
        authorized: true,
        scope_yaml: `name: old\nauthorized_by: x\nauthorized_at: 2026-01-01T00:00:00Z\nexpires_at: 2026-01-02T00:00:00Z\ntargets: [127.0.0.1]`,
      },
    });
    expect(res.status()).toBe(400);
    expect((await res.json()).error).toMatch(/expired/i);
  });
});

test.describe("software assessment", () => {
  const fixture = readFileSync(new URL("./fixtures/sbom.json", import.meta.url).pathname, "utf8");

  test("the form accepts a document path and scans it offline", async ({ page }) => {
    const fixturePath = new URL("./fixtures/sbom.json", import.meta.url).pathname;
    await page.goto("/scans/new");
    await page.getByRole("button", { name: /Software \/ Container/i }).click();
    await page.getByRole("button", { name: /^Continue$/ }).click();

    await page.getByLabel(/Document path on the server/i).fill(fixturePath);
    await page.getByRole("button", { name: /^Continue$/ }).click();
    await expect(page.getByRole("heading", { name: "Review" })).toBeVisible();
    await expect(page.getByText(fixturePath)).toBeVisible();

    const [created] = await Promise.all([
      page.waitForResponse((r) => r.url().endsWith("/api/scans") && r.request().method() === "POST"),
      page.getByRole("button", { name: /Start Scan/i }).click(),
    ]);
    const job = (await created.json()) as Job;
    const { status } = await waitForJob(page, job.id);
    expect(status).toBe("completed");
    await expect(page.getByRole("button", { name: /View report/i })).toBeVisible();
  });

  test("correlates SBOM components against cached advisories", async ({ page }) => {
    const fixturePath = new URL("./fixtures/sbom.json", import.meta.url).pathname;
    expect(fixture).toContain("paramiko");
    const res = await page.request.post("/api/scans", {
      headers: {
        "X-Guard-Token": process.env.CLANKER_GUARD_TOKEN ?? "e2e-token",
        "Content-Type": "application/json",
      },
      data: { kind: "sbom", sbom_path: fixturePath, offline: true },
    });
    expect(res.status()).toBe(202);
    const job = (await res.json()) as Job;
    const { status } = await waitForJob(page, job.id);
    expect(status).toBe("completed");

    const detail = await apiGet<{ report: ReportShape }>(page, `/api/scans/${job.id}`);
    const report = detail.report;
    expect(report.metadata.mode).toBe("sbom");
    const names = report.inventory.packages.map((p) => p.name);
    expect(names).toContain("paramiko");
    const paramiko = report.findings.find((f) => f.product === "paramiko");
    if (paramiko) {
      expect(paramiko.affected).toBe("confirmed_applicability");
      expect(paramiko.severity).not.toBe("unknown");
    }
  });

  test("an unsupported document is rejected with a useful message", async ({ page }) => {
    const res = await page.request.post("/api/scans", {
      headers: {
        "X-Guard-Token": process.env.CLANKER_GUARD_TOKEN ?? "e2e-token",
        "Content-Type": "application/json",
      },
      data: { kind: "sbom", sbom_path: "/etc/hostname" },
    });
    expect(res.status()).toBe(400);
    expect((await res.json()).error).toMatch(/unrecognised|not a supported/i);
  });
});
