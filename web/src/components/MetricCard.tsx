import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "../lib/router";
import { cn } from "../lib/cn";
import { InfoTooltip } from "./ui/InfoTooltip";

/**
 * One headline number, its meaning, and the way to act on it.
 *
 * The tile is deliberately neutral except for a thin accent rule at the top: on a security
 * dashboard colour has to keep meaning "this is dangerous", so a card is only tinted when its
 * number is a problem (see `tone`).
 *
 * A trend is shown only when a real comparison exists. Passing nothing is better than inventing
 * a percentage from a snapshot.
 */
export function MetricCard({
  label,
  value,
  hint,
  help,
  icon: Icon,
  to,
  tone = "neutral",
  trend,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  /** Plain-English explanation behind the ⓘ. */
  help: ReactNode;
  icon: LucideIcon;
  to?: string;
  tone?: "neutral" | "critical" | "high" | "positive";
  /** Only pass this when the comparison is computed from stored history. */
  trend?: { label: string; direction: "up" | "down" | "flat" };
}) {
  const rule = {
    neutral: "bg-border-strong",
    critical: "bg-critical",
    high: "bg-high",
    positive: "bg-low",
  }[tone];
  const iconTone = {
    neutral: "bg-surface-2 text-muted",
    critical: "bg-critical-soft text-critical",
    high: "bg-high-soft text-high",
    positive: "bg-low-soft text-low",
  }[tone];
  const valueTone = {
    neutral: "text-fg",
    critical: "text-critical",
    high: "text-high",
    positive: "text-low",
  }[tone];

  const body = (
    <>
      <span className={cn("absolute inset-x-0 top-0 h-[3px]", rule)} aria-hidden="true" />
      <div className="flex items-start justify-between gap-2">
        <span className={cn("grid h-9 w-9 place-items-center rounded-lg", iconTone)}>
          <Icon className="h-4 w-4" aria-hidden="true" />
        </span>
        <InfoTooltip label={`About ${label}`}>{help}</InfoTooltip>
      </div>
      <p className={cn("num mt-3 text-3xl font-semibold leading-none tracking-tight", valueTone)}>{value}</p>
      <p className="mt-1.5 text-xs font-medium text-fg">{label}</p>
      {hint ? <p className="mt-0.5 text-xs text-subtle">{hint}</p> : null}
      {trend ? (
        <p className="mt-2 text-xs text-muted">
          <span aria-hidden="true">{trend.direction === "up" ? "↑" : trend.direction === "down" ? "↓" : "→"}</span>{" "}
          {trend.label}
        </p>
      ) : null}
    </>
  );

  const className =
    "relative block overflow-hidden rounded-card border border-border bg-surface p-4 transition-colors duration-150 hover:border-border-strong";

  return to ? (
    <Link to={to} className={cn(className, "focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent")}>
      {body}
    </Link>
  ) : (
    <div className={className}>{body}</div>
  );
}
