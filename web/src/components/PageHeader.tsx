import type { ReactNode } from "react";
import { InfoTooltip } from "./ui/InfoTooltip";

export function PageHeader({
  title,
  description,
  help,
  actions,
}: {
  title: string;
  description?: ReactNode;
  /** Plain-English help behind the ⓘ beside the title. Never a substitute for a required warning. */
  help?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        <div className="flex items-center gap-1.5">
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          {help ? <InfoTooltip label={`About ${title}`}>{help}</InfoTooltip> : null}
        </div>
        {description ? <p className="mt-1 max-w-3xl text-sm text-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
