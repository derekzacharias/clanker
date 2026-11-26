import { severityLabel } from "../../lib/format";
import { cn } from "../../lib/cn";

/**
 * Severity distribution as a ring with the total in the middle.
 *
 * Pure SVG, no charting dependency: a ring and a legend are a few hundred bytes, while a chart
 * library is tens of kilobytes plus a licence and an audit to keep. Every segment is also a
 * labelled row in the legend, so meaning never depends on distinguishing colours — the numbers
 * are present as text for screen readers too.
 */
export type SeverityRow = { key: string; count: number };

const COLOURS: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  unknown: "var(--unknown)",
};

export function SeverityDonut({
  rows,
  onSelect,
  active,
  label = "Findings by severity",
}: {
  rows: SeverityRow[];
  onSelect?: (severity: string) => void;
  active?: string;
  label?: string;
}) {
  const total = rows.reduce((n, r) => n + r.count, 0);
  const radius = 56;
  const circumference = 2 * Math.PI * radius;

  let offset = 0;
  const arcs = rows
    .filter((r) => r.count > 0)
    .map((r) => {
      const dash = (total === 0 ? 0 : r.count / total) * circumference;
      const arc = { ...r, dash, offset };
      offset += dash;
      return arc;
    });

  return (
    <div className="flex flex-wrap items-center gap-5">
      <div className="relative h-36 w-36 shrink-0">
        <svg viewBox="0 0 140 140" className="h-full w-full -rotate-90" role="img" aria-label={`${label}: ${total} total`}>
          <circle cx="70" cy="70" r={radius} fill="none" stroke="var(--surface-3)" strokeWidth="14" />
          {arcs.map((arc) => (
            <circle
              key={arc.key}
              cx="70"
              cy="70"
              r={radius}
              fill="none"
              stroke={COLOURS[arc.key] ?? "var(--unknown)"}
              strokeWidth={active && active !== arc.key ? 9 : 14}
              strokeDasharray={`${arc.dash} ${circumference - arc.dash}`}
              strokeDashoffset={-arc.offset}
              className="transition-all duration-500"
              style={{ opacity: active && active !== arc.key ? 0.35 : 1 }}
            />
          ))}
        </svg>
        <div className="pointer-events-none absolute inset-0 grid place-content-center text-center">
          <span className="num text-2xl font-semibold leading-none">{total}</span>
          <span className="mt-1 text-[0.625rem] uppercase tracking-wide text-subtle">findings</span>
        </div>
      </div>

      <ul className="min-w-[9rem] flex-1 space-y-1">
        {rows.map((r) => {
          const pct = total === 0 ? 0 : Math.round((r.count / total) * 100);
          const inner = (
            <>
              <span className="flex items-center gap-2 truncate">
                <span
                  className="h-2 w-2 shrink-0 rounded-full"
                  style={{ background: COLOURS[r.key] ?? "var(--unknown)" }}
                  aria-hidden="true"
                />
                {severityLabel[r.key as keyof typeof severityLabel] ?? r.key}
              </span>
              <span className="num text-right text-xs text-muted">
                {r.count} <span className="text-subtle">({pct}%)</span>
              </span>
            </>
          );
          return (
            <li key={r.key}>
              {onSelect ? (
                <button
                  type="button"
                  onClick={() => onSelect(r.key)}
                  aria-pressed={active === r.key}
                  className={cn(
                    "flex w-full items-center justify-between gap-3 rounded-md px-1.5 py-1 text-left text-xs transition-colors",
                    active === r.key ? "bg-accent-soft text-accent" : "hover:bg-surface-2",
                  )}
                >
                  {inner}
                </button>
              ) : (
                <span className="flex items-center justify-between gap-3 px-1.5 py-1 text-xs">{inner}</span>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
