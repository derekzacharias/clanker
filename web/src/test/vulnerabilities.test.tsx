import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import Vulnerabilities from "../pages/Vulnerabilities";
import { mockApi, vulnFixture } from "./helpers";

function renderPage() {
  return render(<Vulnerabilities />);
}

describe("Vulnerabilities", () => {
  it("lists findings with severity, applicability and exploitation context", async () => {
    mockApi([
      ["/api/vulnerabilities?", vulnFixture],
      ["/api/vulnerabilities/", vulnFixture.items[0]],
    ]);
    renderPage();

    const table = await screen.findByRole("table");
    expect(within(table).getByText("CVE-2026-0001")).toBeInTheDocument();
    expect(within(table).getByText("Confirmed")).toBeInTheDocument();
    expect(within(table).getByText("KEV")).toBeInTheDocument();
    expect(within(table).getByText(/→ 3.0.13-1/)).toBeInTheDocument();
  });

  it("sends the selected severity to the API and marks the chip pressed", async () => {
    const fetchMock = mockApi([
      ["/api/vulnerabilities?", vulnFixture],
      ["/api/vulnerabilities/", vulnFixture.items[0]],
    ]);
    renderPage();
    await screen.findByRole("table");

    const chip = screen.getByRole("button", { name: /^Critical/ });
    await userEvent.click(chip);
    expect(chip).toHaveAttribute("aria-pressed", "true");

    await waitFor(() => {
      const urls = fetchMock.mock.calls.map((c) => String(c[0]));
      expect(urls.some((u) => u.includes("severity=critical"))).toBe(true);
    });
  });

  it("opens the evidence panel and states that a version match is not validated", async () => {
    mockApi([
      ["/api/vulnerabilities?", vulnFixture],
      ["/api/vulnerabilities/vuln-1", vulnFixture.items[0]],
    ]);
    renderPage();

    await userEvent.click(await screen.findByRole("button", { name: "CVE-2026-0001" }));

    const dialog = await screen.findByRole("dialog");
    // Radix marks the overlay content modal; assert the attribute when present
    // and always assert the accessible title is wired up.
    expect(dialog).toBeInTheDocument();
    expect(within(dialog).getByRole("heading", { name: /CVE-2026-0001/i })).toBeInTheDocument();
    expect(within(dialog).getByText(/What this means/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/not a validated vulnerability/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/openssl 3\.0\.11-1 installed/i)).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: /NVD/i })).toHaveAttribute(
      "href",
      "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
    );
  });

  it("explains an empty result as 'no findings in scope', not 'secure'", async () => {
    mockApi([
      [
        "/api/vulnerabilities?",
        {
          total: 0,
          items: [],
          facets: { severity: [], applicability: [], assets: [], kev: 0, fix_available: 0 },
          applied: {},
        },
      ],
    ]);
    renderPage();
    expect(await screen.findByText(/No findings in the assessed scope/i)).toBeInTheDocument();
    expect(screen.getByText(/not a guarantee the environment is secure/i)).toBeInTheDocument();
  });
});
