import { Check } from "lucide-react";
import { Link } from "../lib/router";
import { cn } from "../lib/cn";

/**
 * Where you are in the process, and what is left.
 *
 * The steps are the actual workflow this application supports: discover endpoints, assess
 * them, review what came back, decide who owes the fix, do the work, prove it is gone. Each
 * step carries a live count and links to the screen that resolves it, so the strip is
 * navigation and status at the same time — not decoration.
 */
export type ProcessStep = {
  key: string;
  label: string;
  /** Count that decides whether this step is done, outstanding, or informational. */
  count?: number;
  /** How to read the count: "ready", "left", "done". */
  tone?: "done" | "action" | "info";
  to: string;
  hint?: string;
};

export function ProcessStrip({ steps }: { steps: ProcessStep[] }) {
  return (
    <nav aria-label="Security workflow" className="rounded-lg border border-border bg-surface">
      <ol className="grid grid-cols-2 divide-x divide-y divide-border sm:grid-cols-3 sm:divide-y-0 lg:flex lg:divide-y-0">
        {steps.map((step, i) => {
          const action = step.tone === "action";
          return (
            <li key={step.key} className="min-w-0 lg:min-w-[8.5rem] lg:flex-1">
              <Link
                to={step.to}
                className={cn(
                  "flex h-full flex-col gap-1 px-3 py-2.5 hover:bg-surface-2",
                  "focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent",
                )}
              >
                <span className="flex items-center gap-1.5 text-[0.6875rem] uppercase tracking-wide text-subtle">
                  {step.tone === "done" ? (
                    <Check className="h-3 w-3 text-low" aria-hidden="true" />
                  ) : (
                    <span
                      className={cn(
                        "inline-flex h-4 w-4 items-center justify-center rounded-full border text-[0.625rem]",
                        action ? "border-high/40 text-high" : "border-border-strong text-subtle",
                      )}
                      aria-hidden="true"
                    >
                      {i + 1}
                    </span>
                  )}
                  {step.label}
                </span>
                <span className={cn("num text-lg font-semibold leading-none", action && "text-high")}>
                  {step.count ?? "—"}
                </span>
                {step.hint ? <span className="text-[0.6875rem] text-muted">{step.hint}</span> : null}
              </Link>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
