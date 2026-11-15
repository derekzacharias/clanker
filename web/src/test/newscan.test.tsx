import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import NewScan from "../pages/NewScan";
import { mockApi } from "./helpers";

const runningJob = {
  id: "SCAN-abc",
  kind: "local",
  status: "running",
  started_at: "2026-11-13T12:00:00Z",
  stage: "intelligence",
  stage_detail: "412 advisories fetched",
  percent: 60,
};

const completedJob = {
  ...runningJob,
  status: "completed",
  stage: "done",
  percent: 100,
  report_id: "SCAN-20261113T120000Z-1",
};

describe("New scan workflow", () => {
  it("offers a three-step flow and marks unimplemented scan types", async () => {
    mockApi([]);
    render(<NewScan />);
    expect(screen.getByRole("heading", { name: /New scan/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Local System/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Network Assessment/i })).toHaveAttribute("aria-pressed", "false");
    expect(screen.getByRole("button", { name: /Software \/ Container/i })).toBeInTheDocument();
  });

  it("requires an explicit authorisation before a network scan can start", async () => {
    mockApi([]);
    render(<NewScan />);
    await userEvent.click(screen.getByRole("button", { name: /Network Assessment/i }));
    await userEvent.click(screen.getByRole("button", { name: /^Continue$/ }));
    expect(await screen.findByText(/Only scan what you are authorised to scan/i)).toBeInTheDocument();
    // The wizard advances; starting is what requires authorisation.
    await userEvent.click(screen.getByRole("button", { name: /^Continue$/ }));
    const start = screen.getByRole("button", { name: /Start Scan/i });
    expect(start).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: /^Back$/ }));
    await userEvent.click(screen.getByLabelText(/I confirm I am authorised/i));
    await userEvent.click(screen.getByRole("button", { name: /^Continue$/ }));
    expect(screen.getByRole("button", { name: /Start Scan/i })).toBeEnabled();
  });

  it("walks through configure, review and start, then shows real progress", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "/api/scans" && init?.method === "POST") {
        return new Response(JSON.stringify(runningJob), { status: 202 });
      }
      if (url.startsWith("/api/scans/")) {
        return new Response(JSON.stringify({ job: completedJob, report_available: true }), { status: 200 });
      }
      return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<NewScan />);
    await userEvent.click(screen.getByRole("button", { name: /^Continue$/ }));

    // step 2: configuration
    expect(await screen.findByText(/Configure local assessment/i)).toBeInTheDocument();
    expect(screen.getByText(/read-only, unprivileged, no uploads/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^Continue$/ }));

    // step 3: review
    expect(await screen.findByRole("heading", { name: "Review" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Start Scan/i }));

    // progress comes from the server-reported stage
    expect(await screen.findByText(/Assessment running|Assessment complete/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("button", { name: /View report/i })).toBeInTheDocument());

    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(post).toBeTruthy();
    const body = JSON.parse(String(post?.[1]?.body));
    expect(body.kind).toBe("local");
    expect(body.fail_on).toBe("high");
  });

  it("shows a cancel action while the scan runs", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "/api/scans" && init?.method === "POST") {
        return new Response(JSON.stringify(runningJob), { status: 202 });
      }
      if (url.endsWith("/cancel")) {
        return new Response(JSON.stringify({ id: runningJob.id, status: "canceled" }), { status: 200 });
      }
      return new Response(JSON.stringify({ job: runningJob, report_available: false }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<NewScan />);
    await userEvent.click(screen.getByRole("button", { name: /^Continue$/ }));
    await userEvent.click(await screen.findByRole("button", { name: /^Continue$/ }));
    await userEvent.click(await screen.findByRole("button", { name: /Start Scan/i }));

    const cancel = await screen.findByRole("button", { name: /Cancel scan/i });
    await userEvent.click(cancel);
    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith("/cancel"))).toBe(true),
    );
  });
});
