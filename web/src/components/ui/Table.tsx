import type { HTMLAttributes, ReactNode, ThHTMLAttributes } from "react";
import { cn } from "../../lib/cn";

export function TableWrap({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("scroll-x w-full", className)} {...rest} />;
}

export function Table({ children, caption }: { children: ReactNode; caption?: string }) {
  return (
    <table className="w-full min-w-[46rem] border-collapse text-sm">
      {caption ? <caption className="sr-only">{caption}</caption> : null}
      {children}
    </table>
  );
}

export function Th({ className, scope = "col", ...rest }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      scope={scope}
      className={cn(
        "sticky top-0 z-10 border-b border-border bg-surface-2 px-3 py-2 text-left text-[0.6875rem] font-semibold uppercase tracking-wide text-muted",
        className,
      )}
      {...rest}
    />
  );
}

export function Td({ className, ...rest }: HTMLAttributes<HTMLTableCellElement>) {
  return <td className={cn("border-b border-border px-3 py-2.5 align-top", className)} {...rest} />;
}

export function Tr({ className, ...rest }: HTMLAttributes<HTMLTableRowElement>) {
  return <tr className={cn("hover:bg-surface-2/60", className)} {...rest} />;
}
