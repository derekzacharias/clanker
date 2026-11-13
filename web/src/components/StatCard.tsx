import type { ReactNode } from "react";
import { Card } from "./ui/Card";
import { cn } from "../lib/cn";

export function StatCard({
  label,
  value,
  hint,
  tone = "default",
  icon,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "default" | "critical" | "high" | "low";
  icon?: ReactNode;
}) {
  const toneClass = {
    default: "text-fg",
    critical: "text-critical",
    high: "text-high",
    low: "text-low",
  }[tone];
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs font-medium uppercase tracking-wide text-muted">{label}</p>
        {icon ? <span className="text-muted" aria-hidden="true">{icon}</span> : null}
      </div>
      <p className={cn("num mt-2 text-3xl font-semibold tracking-tight", toneClass)}>{value}</p>
      {hint ? <p className="mt-1 text-xs text-muted">{hint}</p> : null}
    </Card>
  );
}
