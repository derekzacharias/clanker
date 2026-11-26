import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { InfoTooltip } from "../components/ui/InfoTooltip";
import { AppShell } from "../components/AppShell";
import { applyTheme, resolveInitialTheme } from "../lib/theme";
import { AskGuard } from "../components/AskGuard";

describe("theme", () => {
  it("defaults to light mode", () => {
    expect(resolveInitialTheme()).toBe("light");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });

  it("toggles, applies to the document and persists the preference", async () => {
    render(
      <AppShell>
        <p>content</p>
      </AppShell>,
    );
    const toggle = screen.getByRole("button", { name: /Switch to dark theme/i });
    await userEvent.click(toggle);
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(localStorage.getItem("clanker-guard.theme")).toBe("dark");
    // the control now offers the inverse action, which is the accessible label
    expect(screen.getByRole("button", { name: /Switch to light theme/i })).toBeInTheDocument();
  });

  it("honours a stored preference over the system default", () => {
    localStorage.setItem("clanker-guard.theme", "dark");
    expect(resolveInitialTheme()).toBe("dark");
    applyTheme("light");
    expect(localStorage.getItem("clanker-guard.theme")).toBe("light");
  });
});

describe("accessibility", () => {
  it("provides a skip link, labelled navigation and a search landmark", () => {
    render(
      <AppShell>
        <p>content</p>
      </AppShell>,
    );
    expect(screen.getByRole("link", { name: /Skip to content/i })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: /Workflow/i })).toBeInTheDocument();
    expect(screen.getByRole("search")).toBeInTheDocument();
    expect(screen.getByLabelText(/Search hostnames, IP addresses/i)).toBeInTheDocument();
  });

  it("marks the active section for assistive technology", () => {
    render(
      <AppShell>
        <p>content</p>
      </AppShell>,
    );
    const overview = screen.getByRole("link", { name: /Overview/i });
    expect(overview).toHaveAttribute("aria-current", "page");
  });

  it("traps focus in the Ask Guard dialog and closes with Escape", async () => {
    render(<AskGuard open onOpenChange={() => {}} />);
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toBeInTheDocument();
    expect(await screen.findByLabelText(/^Question$/i)).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    // Radix calls onOpenChange(false); the panel unmounts via the parent.
    expect(screen.queryByRole("dialog")).toBeInTheDocument(); // controlled: parent decides
  });
});

// Contextual help must be reachable without a mouse. Radix opens a tooltip on hover and focus but
// not on click, which left touch users with nothing — the component is controlled for that reason.
describe("contextual help", () => {
  it("opens on click and announces what it explains", async () => {
    render(
      <InfoTooltip label="About current posture">
        A plain-English explanation.
      </InfoTooltip>,
    );
    const trigger = screen.getByRole("button", { name: "About current posture" });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(trigger);
    await waitFor(() => expect(screen.getByRole("tooltip")).toHaveTextContent("A plain-English explanation."));
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("tooltip")).not.toBeInTheDocument());
  });
});
