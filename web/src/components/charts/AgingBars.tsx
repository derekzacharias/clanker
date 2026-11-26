import { cn } from "../../lib/cn";

/**
 * Age of open work, as bars.
 *
 * The question this answers is "is the queue stalling?" — a shape, not a total. Bars are scaled to
 * the largest bucket so the shape stays readable when every count is small, and each number is
 * printed beside its bar so nothing depends on judging a length by eye.
 */
export function AgingBars({
  buckets,
  label = "Age of open findings",
}: {
  buckets: { label: string; count: number }[];
  label?: string;
}) {
  const max = Math.max(1, ...buckets.map((b) => b.count));
  const total = buckets.reduce((n, b) => n + b.count, 0);
  const oldest = buckets.length - 1;

  return (
    <ul className="space-y-2" aria-label={label}>
      {buckets.map((b, i) => {
        const pct = total === 0 ? 0 : Math.round((b.count / total) * 100);
        const width = b.count === 0 ? 0 : Math.max(4, Math.round((b.count / max) * 100));
        const worrying = i === oldest && b.count > 0;
        return (
          <li key={b.label} className="text-xs">
            <div className="flex items-baseline justify-between gap-2">
              <span className={cn("text-muted", worrying && "text-high")}>{b.label}</span>
              <span className="num text-fg">
                {b.count}
                {total > 0 ? <span className="ml-1 text-subtle">({pct}%)</span> : null}
              </span>
            </div>
            <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-3">
              <div
                className={cn("h-full rounded-full transition-all duration-500", worrying ? "bg-high" : "bg-accent")}
                style={{ width: `${width}%` }}
                aria-hidden="true"
              />
            </div>
          </li>
        );
      })}
    </ul>
  );
}
