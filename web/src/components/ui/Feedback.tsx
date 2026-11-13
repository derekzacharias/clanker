import { AlertTriangle, CheckCircle2, Inbox, Loader2, RefreshCw } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "../../lib/cn";
import { Button } from "./Button";

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-md bg-surface-3", className)} aria-hidden="true" />;
}

export function LoadingBlock({ label = "Loading" }: { label?: string }) {
  return (
    <div role="status" aria-live="polite" className="flex items-center gap-2 p-6 text-sm text-muted">
      <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
      <span>{label}…</span>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
  icon,
}: {
  title: string;
  description: ReactNode;
  action?: ReactNode;
  icon?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-14 text-center">
      <div className="rounded-full bg-surface-2 p-3 text-muted" aria-hidden="true">
        {icon ?? <Inbox className="h-5 w-5" />}
      </div>
      <h3 className="text-sm font-semibold">{title}</h3>
      <p className="max-w-md text-sm text-muted">{description}</p>
      {action}
    </div>
  );
}

export function ErrorState({
  title = "Something went wrong",
  message,
  onRetry,
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div role="alert" className="m-4 rounded-lg border border-critical/30 bg-critical-soft p-4">
      <div className="flex items-start gap-2">
        <AlertTriangle className="mt-0.5 h-4 w-4 text-critical" aria-hidden="true" />
        <div className="flex-1">
          <p className="text-sm font-semibold text-critical">{title}</p>
          <p className="mt-1 text-sm text-fg">{message}</p>
          {onRetry ? (
            <Button size="sm" className="mt-3" onClick={onRetry}>
              <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" /> Try again
            </Button>
          ) : null}
        </div>
      </div>
    </div>
  );
}

export function Banner({
  tone = "info",
  title,
  children,
}: {
  tone?: "info" | "warn" | "success" | "danger";
  title?: ReactNode;
  children?: ReactNode;
}) {
  const styles = {
    info: "border-accent/25 bg-accent-soft",
    warn: "border-high/35 bg-high-soft",
    success: "border-low/30 bg-low-soft",
    danger: "border-critical/30 bg-critical-soft",
  }[tone];
  const Icon = tone === "success" ? CheckCircle2 : tone === "info" ? Inbox : AlertTriangle;
  return (
    <div className={cn("flex items-start gap-2 rounded-lg border p-3 text-sm", styles)}>
      <Icon className="mt-0.5 h-4 w-4 shrink-0 opacity-80" aria-hidden="true" />
      <div className="min-w-0">
        {title ? <p className="font-semibold">{title}</p> : null}
        {children ? <div className={cn(title && "mt-0.5", "text-muted")}>{children}</div> : null}
      </div>
    </div>
  );
}
