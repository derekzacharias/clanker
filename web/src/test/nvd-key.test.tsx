import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import Settings from "../pages/Settings";
import { mockApi } from "./helpers";

const feedsFixture = {
  feeds: [
    { source: "KEV", last_sync: "2026-11-28T12:00:00Z", records: 1808, stale: false },
    { source: "EPSS", last_sync: "2026-11-28T12:00:00Z", records: 413901, stale: false },
    { source: "NVD CVEs", last_sync: "2026-11-28T12:00:00Z", records: 198756, stale: false },
  ],
  counts: { advisories: 0, kev: 1808, epss: 413901 },
  nvd_api_key_configured: false,
};

describe("Intelligence tab: NVD API key", () => {
  it("saves a key and never displays it again", async () => {
    const putMock = mockApi([
      ["/api/feeds", feedsFixture],
      ["/api/settings/nvd-key", { configured: true }],
    ]);
    render(<Settings initialTab="intelligence" />);

    expect(await screen.findByRole("heading", { name: "NVD API key" })).toBeInTheDocument();
    expect(screen.getByText("not configured")).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText("NVD API key"), "DDA309D5-8843-4FCB-B738-BE3557C94031");
    await userEvent.click(screen.getByRole("button", { name: "Save key" }));

    await waitFor(() => {
      const calls = putMock.mock.calls.map((c) => String(c[0]));
      expect(calls.some((u) => u.includes("/api/settings/nvd-key"))).toBe(true);
    });
    // The input clears after saving: the key is not redisplayed.
    expect(screen.getByLabelText("NVD API key")).toHaveValue("");
    // The request link is the operator's entry point.
    expect(screen.getByRole("link", { name: /request-an-api-key/ })).toHaveAttribute(
      "href",
      "https://nvd.nist.gov/developers/request-an-api-key",
    );
  });

  it("offers removal when a key is already configured", async () => {
    const putMock = mockApi([
      ["/api/feeds", { ...feedsFixture, nvd_api_key_configured: true }],
      ["/api/settings/nvd-key", { configured: false }],
    ]);
    render(<Settings initialTab="intelligence" />);

    expect(await screen.findByText("configured")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Remove key" }));
    // Clearing sends the empty key; the saved state flips in the response.
    await waitFor(() => {
      const calls = putMock.mock.calls.map((c) => String(c[0]));
      expect(calls.some((u) => u.includes("/api/settings/nvd-key"))).toBe(true);
    });
  });
});
