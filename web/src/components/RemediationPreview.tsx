import { AlertTriangle, CheckCircle2, ShieldAlert, Terminal } from "lucide-react";
import type { RemediationCommand, RemediationPlan } from "../lib/api";
import { CopyButton } from "./ui/CopyButton";
import { Badge } from "./ui/Badge";

/**
 * The work order, as the administrator will see it in GitLab.
 *
 * Rendered from the structured plan rather than by re-parsing Markdown, so the preview and the
 * issue body cannot disagree. Every command block carries a copy button: the point of the ticket
 * is that somebody pastes these lines into a shell.
 */

const STATUS_TONE: Record<RemediationPlan["status"], { label: string; className: string; icon: typeof ShieldAlert }> = {
  verified: {
    label: "Verified remediation",
    className: "border-low/30 bg-low-soft text-low",
    icon: CheckCircle2,
  },
  requires_review: {
    label: "Review before running",
    className: "border-high/30 bg-high-soft text-high",
    icon: AlertTriangle,
  },
  no_fix: {
    label: "No confirmed fix",
    className: "border-high/30 bg-high-soft text-high",
    icon: AlertTriangle,
  },
  unsupported: {
    label: "Not patchable by command",
    className: "border-border bg-surface-2 text-muted",
    icon: ShieldAlert,
  },
  needs_investigation: {
    label: "Manual investigation",
    className: "border-border bg-surface-2 text-muted",
    icon: ShieldAlert,
  },
};

export function remediationStatusLabel(status: RemediationPlan["status"]): string {
  return STATUS_TONE[status]?.label ?? status;
}

export function RemediationPreview({ plan }: { plan: RemediationPlan }) {
  const tone = STATUS_TONE[plan.status] ?? STATUS_TONE.needs_investigation;
  const Icon = tone.icon;
  const system = [
    ["Hostname", plan.system.hostname],
    ["IP address", plan.system.ip || "not recorded"],
    ["Operating system", [plan.system.os, plan.system.os_version].filter(Boolean).join(" ") || "not recorded"],
    ["Package", plan.package || "not recorded"],
    ["Installed version", plan.installed_version || "not recorded"],
    ["Fixed version", plan.fixed_version || "none published"],
    ["CVE", plan.cve],
    ["Severity", plan.severity],
  ];

  return (
    <div className="space-y-3">
      <div className={`flex flex-wrap items-center gap-2 rounded-md border px-2.5 py-2 text-xs ${tone.className}`}>
        <Icon className="h-4 w-4" aria-hidden="true" />
        <span className="font-medium">{tone.label}</span>
        <span className="opacity-80">confidence: {plan.confidence}</span>
        {plan.manager ? <span className="mono opacity-80">{plan.manager}</span> : null}
        {plan.disruptive ? (
          <span className="ml-auto rounded border border-critical/40 bg-critical-soft px-1.5 py-0.5 text-critical">
            disruptive change
          </span>
        ) : null}
      </div>
      {plan.reason ? <p className="text-xs text-muted">{plan.reason}</p> : null}

      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">Affected system</h4>
        <dl className="mt-1 grid grid-cols-1 gap-x-4 gap-y-1 text-xs sm:grid-cols-2">
          {system.map(([label, value]) => (
            <div key={label} className="flex justify-between gap-3 border-b border-border/60 py-0.5">
              <dt className="text-muted">{label}</dt>
              <dd className="mono truncate text-right" title={value}>
                {value}
              </dd>
            </div>
          ))}
        </dl>
      </div>

      {plan.system.ssh_managed ? (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">Step 1 · Connect</h4>
          <CommandBlock
            command={{
              lang: "bash",
              lines: [
                plan.access.ssh_user
                  ? `ssh ${plan.access.ssh_jump ? `-J ${plan.access.ssh_jump} ` : ""}${plan.access.ssh_user}@${
                      plan.access.ssh_host || plan.system.hostname
                    }`
                  : `ssh <admin-user>@${plan.system.hostname}`,
              ],
            }}
            caption={plan.access.ssh_user ? undefined : "No SSH user is recorded for this asset."}
          />
          {plan.access.runbook ? (
            <p className="mt-1 text-xs text-muted">
              Runbook:{" "}
              <a href={plan.access.runbook} target="_blank" rel="noreferrer" className="text-accent underline underline-offset-2">
                {plan.access.runbook}
              </a>
            </p>
          ) : null}
        </div>
      ) : null}

      {(plan.warnings ?? []).length > 0 ? (
        <div className="rounded-md border border-high/30 bg-high-soft p-2">
          <p className="text-xs font-semibold text-high">Before you start</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs text-high/90">
            {(plan.warnings ?? []).map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {(plan.prerequisites ?? []).length > 0 ? (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">Prerequisites</h4>
          <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs text-muted">
            {(plan.prerequisites ?? []).map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {plan.steps.map((step, i) => (
        <div key={step.title}>
          <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            <Terminal className="h-3.5 w-3.5" aria-hidden="true" />
            Step {i + 1} · {step.title}
            {step.disruptive ? <Badge className="border-critical/40 bg-critical-soft text-critical">disruptive</Badge> : null}
          </h4>
          {step.detail ? <p className="mt-0.5 text-xs text-muted">{step.detail}</p> : null}
          {(step.commands ?? []).map((c, j) => (
            <CommandBlock key={`${step.title}-${j}`} command={c} />
          ))}
        </div>
      ))}

      {(plan.verify ?? []).length > 0 ? (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">
            Step {plan.steps.length + 1} · Verify the fix
          </h4>
          {(plan.verify ?? []).map((c, i) => (
            <CommandBlock key={`verify-${i}`} command={c} />
          ))}
          {plan.verify_note ? <p className="mt-1 text-xs text-muted">Local check ≠ resolved. {plan.verify_note}</p> : null}
          <p className="mt-1 text-xs text-muted">
            The finding closes only after a later scan stops reporting it.
          </p>
        </div>
      ) : null}

      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">
          Step {plan.steps.length + 2} · Roll back if something breaks
        </h4>
        {(plan.rollback ?? []).length > 0 ? (
          (plan.rollback ?? []).map((c, i) => <CommandBlock key={`rollback-${i}`} command={c} />)
        ) : (
          <p className="mt-1 text-xs text-muted">
            {plan.rollback_note || "No validated rollback procedure is known. Restore a snapshot or follow the vendor's procedure."}
          </p>
        )}
      </div>
    </div>
  );
}

/** One command block: gray surface, monospace, copy button. */
export function CommandBlock({ command, caption }: { command: RemediationCommand; caption?: string }) {
  const text = command.lines.join("\n");
  return (
    <div className="mt-1.5">
      <div className="flex items-center justify-between rounded-t-md border border-b-0 border-border bg-surface-2 px-2 py-1">
        <span className="mono text-[0.625rem] uppercase tracking-wide text-subtle">{command.lang || "bash"}</span>
        <CopyButton value={text} label="Copy" />
      </div>
      <pre className="scroll-x m-0 rounded-b-md rounded-t-none border border-border p-2 text-[0.6875rem] leading-relaxed">
        <code>{text}</code>
      </pre>
      {caption ? <p className="mt-1 text-xs text-muted">{caption}</p> : null}
    </div>
  );
}
