import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "../../lib/cn";

export function Card({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <section className={cn("card", className)} {...rest} />;
}

export function CardHeader({
  title,
  description,
  actions,
  id,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  id?: string;
}) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-4 py-3">
      {/* min-w-0 + flex-1 lets a long description wrap instead of pushing the
          card's action onto its own line, so the button stays aligned with the
          title it belongs to. */}
      <div className="min-w-0 flex-1">
        <h2 id={id} className="text-sm font-semibold tracking-tight">
          {title}
        </h2>
        {description ? <p className="mt-0.5 text-xs text-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </header>
  );
}

export function CardBody({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("p-4", className)} {...rest} />;
}
