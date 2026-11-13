import type { CountRow } from "../lib/api";
import { severityLabel } from "../lib/format";
import { cn } from "../lib/cn";

const barTone: Record<string, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  unknown: "bg-unknown",
};

/**
 * One horizontal distribution bar plus a labelled legend. The legend carries
 * the counts as text, so the chart is not the only way to read the data.
 */
export function SeverityBar({ rows }: { rows: CountRow[] }) {
  const total = rows.reduce((sum, r) => sum + r.count, 0);
  if (total === 0) {
    return <p className="text-sm text-muted">No findings recorded in the assessed scope.</p>;
  }
  return (
    <div className="space-y-3">
      <div
        className="flex h-2.5 w-full overflow-hidden rounded-full bg-surface-3"
        role="img"
        aria-label={`Findings by severity: ${rows.map((r) => `${severityLabel[r.key as keyof typeof severityLabel] ?? r.key} ${r.count}`).join(", ")}`}
      >
        {rows.map((row) => {
          if (row.count === 0) return null;
          return (
            <div
              key={row.key}
              className={cn(barTone[row.key] ?? "bg-unknown")}
              style={{ width: `${(row.count / total) * 100}%` }}
            />
          );
        })}
      </div>
      <ul className="flex flex-wrap gap-x-5 gap-y-1.5">
        {rows.map((row) => (
          <li key={row.key} className="flex items-center gap-1.5 text-xs">
            <span
              className={cn("h-2 w-2 rounded-full", barTone[row.key] ?? "bg-unknown")}
              aria-hidden="true"
            />
            <span className="text-muted">{severityLabel[row.key as keyof typeof severityLabel] ?? row.key}</span>
            <span className="num font-semibold text-fg">{row.count}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
