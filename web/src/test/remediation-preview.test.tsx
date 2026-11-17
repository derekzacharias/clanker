import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RemediationPreview } from "../components/RemediationPreview";
import type { RemediationPlan } from "../lib/api";

/**
 * The preview is what the administrator trusts before the ticket is filed, so it must show the
 * same work order the issue will contain: system, connection, commands with copy buttons,
 * verification, rollback and warnings.
 */
const base: RemediationPlan = {
  status: "verified",
  confidence: "high",
  system: {
    hostname: "web01",
    asset_id: "web01",
    ip: "192.0.2.25",
    os: "Ubuntu",
    os_version: "22.04",
    ssh_managed: true,
  },
  access: { host: "web01", ssh_user: "deploy", ssh_jump: "bastion.prod" },
  cve: "CVE-2026-1234",
  severity: "HIGH",
  package: "openssl",
  installed_version: "3.0.2",
  fixed_version: "3.0.13-1ubuntu1",
  manager: "apt",
  steps: [
    {
      title: "Apply the fix on the host",
      detail: "Installs the fixed build of openssl.",
      commands: [{ lang: "bash", lines: ["sudo apt-get update", "sudo apt-get install --only-upgrade openssl=3.0.13-1ubuntu1"] }],
    },
  ],
  verify: [{ lang: "bash", lines: ["dpkg-query -W -f='${Version}\\n' openssl"] }],
  verify_note: "A version check is local evidence, not proof.",
  rollback: [{ lang: "bash", lines: ["sudo apt-get install openssl=3.0.2"] }],
  prerequisites: ["Root or sudo on the host"],
  warnings: ["openssl backs running services."],
  disruptive: false,
};

describe("remediation preview", () => {
  it("shows the affected system, the connection line and the commands", () => {
    render(<RemediationPreview plan={base} />);
    expect(screen.getByText("Affected system")).toBeInTheDocument();
    expect(screen.getByText("192.0.2.25")).toBeInTheDocument();
    expect(screen.getByText("3.0.13-1ubuntu1")).toBeInTheDocument();
    // The connection line is the one the administrator pastes first.
    expect(screen.getByText("ssh -J bastion.prod deploy@web01")).toBeInTheDocument();
    // Commands are in code blocks with a copy control each.
    const blocks = screen.getAllByRole("button", { name: /Copy/ });
    expect(blocks.length).toBeGreaterThanOrEqual(3); // connect + fix + verify + rollback
    expect(screen.getByText(/sudo apt-get install --only-upgrade openssl=3.0.13-1ubuntu1/)).toBeInTheDocument();
  });

  it("keeps local verification separate from scanner confirmation", () => {
    render(<RemediationPreview plan={base} />);
    expect(screen.getByText(/Local check ≠ resolved/)).toBeInTheDocument();
    expect(screen.getByText(/closes only after a later scan/)).toBeInTheDocument();
  });

  it("flags a disruptive change and lists the warnings", () => {
    render(<RemediationPreview plan={{ ...base, disruptive: true, status: "requires_review" }} />);
    expect(screen.getByText(/disruptive change/)).toBeInTheDocument();
    expect(screen.getByText("openssl backs running services.")).toBeInTheDocument();
    expect(screen.getByText(/Review before running/)).toBeInTheDocument();
  });

  it("does not invent an SSH line for a container image", () => {
    render(
      <RemediationPreview
        plan={{
          ...base,
          status: "requires_review",
          system: { hostname: "image:acme/api", asset_id: "image:acme/api", ssh_managed: false },
          access: { host: "image:acme/api" },
          steps: [{ title: "Rebuild the image", commands: [{ lang: "dockerfile", lines: ["RUN apk add --upgrade openssl"] }] }],
        }}
      />,
    );
    expect(screen.queryByText(/^ssh /)).not.toBeInTheDocument();
    expect(screen.getByText("dockerfile")).toBeInTheDocument();
  });

  it("says a fix is unavailable instead of showing a command", () => {
    render(
      <RemediationPreview
        plan={{
          ...base,
          status: "no_fix",
          fixed_version: "",
          reason: "The advisory publishes no fixed version.",
          steps: [{ title: "Check the package", commands: [{ lang: "bash", lines: ["dpkg-query -W openssl"] }] }],
          rollback: [],
        }}
      />,
    );
    expect(screen.getByText(/No confirmed fix/)).toBeInTheDocument();
    expect(screen.queryByText(/--only-upgrade/)).not.toBeInTheDocument();
    expect(screen.getByText(/Restore a snapshot|No validated rollback/)).toBeInTheDocument();
  });
});
