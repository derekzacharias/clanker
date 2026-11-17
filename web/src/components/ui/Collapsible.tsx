import { ChevronRight } from "lucide-react";
import { useId, useState, type ReactNode } from "react";
import { cn } from "../../lib/cn";

/**
 * A disclosure section: the heading is always visible, the body is one click away.
 *
 * Progressive disclosure is the main tool for this application: a finding has to show its
 * verdict and its owner immediately, and its raw evidence only when somebody is checking
 * the verdict. Using the native button + region pattern keeps keyboard and screen-reader
 * behaviour correct without a dependency.
 */
export function Collapsible({
  title,
  summary,
  children,
  defaultOpen = false,
  count,
  className,
}: {
  title: string;
  /** One line shown next to the title while collapsed, so the closed state still informs. */
  summary?: ReactNode;
  children: ReactNode;
  defaultOpen?: boolean;
  count?: number;
  className?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const id = useId();
  return (
    <section className={cn("border-t border-border pt-3", className)}>
      <h3 className="m-0">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-controls={id}
          className="flex w-full items-center gap-2 rounded-md py-1 text-left text-xs font-semibold uppercase tracking-wide text-muted hover:text-fg focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
        >
          <ChevronRight
            className={cn("h-3.5 w-3.5 shrink-0 transition-transform", open && "rotate-90")}
            aria-hidden="true"
          />
          <span>{title}</span>
          {typeof count === "number" ? <span className="text-subtle">({count})</span> : null}
          {!open && summary ? <span className="ml-1 truncate font-normal normal-case tracking-normal text-subtle">{summary}</span> : null}
        </button>
      </h3>
      <div id={id} hidden={!open} className="mt-2">
        {children}
      </div>
    </section>
  );
}

/**
 * A named region inside a page, with a stable heading level.
 *
 * Sections replace "one more card": they carry the hierarchy the eye needs (title →
 * description → content) without inventing borders or background per page.
 */
export function Section({
  title,
  description,
  actions,
  children,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("space-y-2", className)}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold">{title}</h2>
          {description ? <p className="text-xs text-muted">{description}</p> : null}
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}
