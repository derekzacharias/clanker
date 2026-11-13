import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { VulnerabilityDetail } from "../pages/VulnerabilityDetail";
import Improvement from "../pages/Improvement";
import Overview from "../pages/Overview";
import { mockApi, overviewFixture, vulnFixture } from "./helpers";

const findingWithAnalyst = {
  ...vulnFixture.items[0],
  affected: "probable",
  analyst: {
    verdict: "false_positive",
    applicability: "not_affected",
    confidence: "high",
    explanation: "Ubuntu advisory confirms the installed build contains the fix.",
    verified_at: "2026-11-13T12:00:00Z",
  },
  effective_affected: "not_affected",
};

const improvementFixture = {
  id: "IMP-0001",
  category: "detection_accuracy",
  status: "awaiting_approval",
  title: "Stop resolving snap transition packages from vendor version data",
  problem: "Snap transition packages carry no application code.",
  proposed_change: "Treat snap markers as unresolved.",
  expected_benefit: "Removes a class of false positives.",
  risk_level: "low",
  signature: "fp:snap_stub",
  affected_findings: ["abc123"],
  evidence: [{ kind: "analyst_review", detail: "thunderbird 2:1snap1-0ubuntu3" }],
  policy_notes: ["snap stub unresolved true"],
  evaluation: {
    passed: true,
    baseline: { available: true, cases: 2, true_positives: 1, false_positives: 0, true_negatives: 1, false_negatives: 0, precision: 1, recall: 1, accuracy: 1 },
    candidate: { available: true, cases: 2, true_positives: 1, false_positives: 0, true_negatives: 1, false_negatives: 0, precision: 1, recall: 1, accuracy: 1 },
    cases: [
      { fixture: "snap-transition-stub", label: "unresolved", expected: "unresolved", baseline: "confirmed_applicability", candidate: "needs_investigation", pass: true },
      { fixture: "snap-real-build", label: "affected", expected: "affected", baseline: "confirmed_applicability", candidate: "confirmed_applicability", pass: true },
    ],
    fixed_cases: ["snap-transition-stub"],
    evaluated_at: "2026-11-13T12:00:00Z",
  },
  created_at: "2026-11-13T12:00:00Z",
  updated_at: "2026-11-13T12:00:00Z",
};

const qualityFixture = {
  metrics: {
    reviewed: 1,
    confirmed: 0,
    false_positives: 1,
    needs_investigation: 0,
    remediated: 0,
    verification_supported: 1,
    verification_contradicted: 0,
    verification_inconclusive: 0,
    false_positive_rate: 1,
    reviewed_rate: 0.001,
    findings_considered: 713,
    actionable: 620,
    needs_investigation_findings: 93,
    open_improvements: 1,
    deployed_improvements: 0,
    rejected_improvements: 0,
    notes: ["1 reviewed finding(s): the false-positive rate is anecdotal until at least 5 are reviewed"],
  },
  improvement_counts: { awaiting_approval: 1 },
  recent_feedback: [
    {
      finding_id: "abc123",
      cve: "CVE-2022-25236",
      product: "thunderbird",
      verdict: "false_positive",
      reason: "incorrect_identification",
      analyst: "derek",
      created_at: "2026-11-13T12:00:00Z",
      supported: true,
      explanation: "snap transition package",
    },
  ],
};

describe("finding feedback", () => {
  it("shows both the scanner verdict and the analyst correction", async () => {
    mockApi([
      ["/api/vulnerabilities/vuln-1", findingWithAnalyst],
      ["/api/vulnerabilities/", findingWithAnalyst],
    ]);
    render(<VulnerabilityDetail id="vuln-1" onClose={() => {}} />);

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/verified by analyst/i)).toBeInTheDocument();
    expect(within(dialog).getAllByText(/not affected/i).length).toBeGreaterThan(0);
    expect(within(dialog).getByText(/scanner verdict remains/i)).toBeInTheDocument();
  });

  it("requires a reason before submitting a false positive and posts structured feedback", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/feedback") && init?.method === "POST") {
        return new Response(
          JSON.stringify({
            feedback: { id: "FB1", verdict: "false_positive", analyst: "tester", created_at: "2026-11-13T12:00:00Z" },
            verification: {
              supported: true,
              confidence: "high",
              changed: true,
              explanation: "Ubuntu confirms the installed build is not affected.",
              original_applicability: "probable",
              reassessed_applicability: "not_affected",
              evidence: [{ kind: "vendor_advisory_not_affected", detail: "UBUNTU-CVE-1" }],
            },
            state: { finding_id: "vuln-1", verdict: "false_positive", applicability: "not_affected", confidence: "high", explanation: "ok", verified_at: "2026-11-13T12:00:00Z" },
            improvement_ids: ["IMP-0001"],
            note: "recorded",
          }),
          { status: 202 },
        );
      }
      return new Response(JSON.stringify(vulnFixture.items[0]), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<VulnerabilityDetail id="vuln-1" onClose={() => {}} />);
    await screen.findByRole("dialog");

    await userEvent.click(screen.getByRole("button", { name: /Mark false positive/i }));
    const submit = screen.getByRole("button", { name: /Submit feedback/i });
    expect(submit).toBeDisabled();

    await userEvent.click(screen.getByRole("radio", { name: /Vendor patch already installed/i }));
    expect(submit).toBeEnabled();
    await userEvent.click(submit);

    await waitFor(() => expect(screen.getByText(/verification supported/i)).toBeInTheDocument());
    expect(screen.getByText(/Classification updated/i)).toBeInTheDocument();

    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    const body = JSON.parse(String(post?.[1]?.body));
    expect(body.verdict).toBe("false_positive");
    expect(body.reason_code).toBe("vendor_patch_installed");
  });
});

describe("continuous improvement page", () => {
  it("lists proposals with test results and quality caveats", async () => {
    mockApi([
      ["/api/improvements", { items: [improvementFixture], counts: { awaiting_approval: 1 }, total: 1 }],
      ["/api/quality", qualityFixture],
    ]);
    render(<Improvement />);

    expect(await screen.findByText(/Stop resolving snap transition packages/i)).toBeInTheDocument();
    expect(screen.getByText(/tests passed/i)).toBeInTheDocument();
    expect(screen.getByText(/anecdotal until at least 5/i)).toBeInTheDocument();
    expect(screen.getByText(/CVE-2022-25236/)).toBeInTheDocument();
    // The rate is presented as a reviewed-sample rate, never as population precision.
    expect(screen.getByText(/of reviewed findings/i)).toBeInTheDocument();
  });

  it("approves a proposal through the lifecycle endpoint", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      void init;
      if (url.endsWith("/transition")) {
        return new Response(JSON.stringify({ improvement: { ...improvementFixture, status: "approved" } }), { status: 200 });
      }
      if (url.startsWith("/api/improvements/")) {
        return new Response(
          JSON.stringify({ improvement: improvementFixture, events: [], rules: [], active: { rule_id: "", notes: [] } }),
          { status: 200 },
        );
      }
      if (url.startsWith("/api/improvements")) {
        return new Response(JSON.stringify({ items: [improvementFixture], counts: { awaiting_approval: 1 }, total: 1 }), { status: 200 });
      }
      return new Response(JSON.stringify(qualityFixture), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<Improvement />);
    await screen.findByText(/Stop resolving snap transition packages/i);
    await userEvent.click(screen.getByRole("button", { name: /^Approve$/ }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(([url]) => String(url).endsWith("/transition"));
      expect(call).toBeTruthy();
      const body = JSON.parse(String(call?.[1]?.body));
      expect(body.to).toBe("approved");
    });
  });

  it("shows no rate when nothing has been reviewed", async () => {
    mockApi([
      ["/api/improvements", { items: [], counts: {}, total: 0 }],
      [
        "/api/quality",
        {
          metrics: {
            reviewed: 0, confirmed: 0, false_positives: 0, needs_investigation: 0, remediated: 0,
            verification_supported: 0, verification_contradicted: 0, verification_inconclusive: 0,
            false_positive_rate: null, reviewed_rate: null, findings_considered: 0, actionable: 0,
            needs_investigation_findings: 0, open_improvements: 0, deployed_improvements: 0, rejected_improvements: 0,
            notes: ["no findings reviewed yet: no false-positive rate can be computed"],
          },
          improvement_counts: {},
        },
      ],
    ]);
    render(<Improvement />);
    expect(await screen.findByText(/no reviews yet — no rate can be computed/i)).toBeInTheDocument();
    expect(screen.getByText(/No improvement proposals yet/i)).toBeInTheDocument();
  });
});

describe("overview improvement indicator", () => {
  it("surfaces proposals available for review", async () => {
    mockApi([
      ["/api/overview", { ...overviewFixture, improvements_available: 2, reviewed_findings: 1 }],
    ]);
    render(<Overview />);
    expect(await screen.findByText(/2 detection improvement\(s\) available for review/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Review proposals/i })).toHaveAttribute("href", "/settings?tab=improvement");
  });
});
