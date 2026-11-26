import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { Info } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";

/**
 * The one contextual-help control used across the application.
 *
 * Why a real button rather than a hover-only icon: keyboard and touch users must be able to
 * reach the same explanation. Radix's trigger makes it focusable and gives it a description that
 * screen readers announce; clicking it opens the same text on touch devices, where hover does not
 * exist.
 *
 * The rule this enforces: help must add information. It never repeats the heading, and it never
 * hides a prerequisite, a warning or an instruction that the user needs before acting — those stay
 * visible in the page itself.
 */
export function InfoTooltip({
  label,
  children,
  side = "top",
}: {
  /** Accessible name of the control, e.g. "About current posture". */
  label: string;
  /** The explanation itself, in plain English. */
  children: ReactNode;
  side?: "top" | "right" | "bottom" | "left";
}) {
  // Controlled on purpose. Radix opens a tooltip on hover and on focus, but not on click — which
  // leaves touch users with no way to read the text. Taking control means hover, keyboard
  // (Enter/Space) and tap all work, and Escape closes it everywhere.
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open) return;
    const close = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", close);
    return () => document.removeEventListener("keydown", close);
  }, [open]);
  return (
    <TooltipPrimitive.Provider delayDuration={150}>
      <TooltipPrimitive.Root open={open} onOpenChange={setOpen}>
        <TooltipPrimitive.Trigger asChild>
          <button
            type="button"
            aria-label={label}
            aria-expanded={open}
            // Open, never toggle: focus has already opened it when a keyboard user arrives, so a
            // toggle would close the very text Enter was pressed to reveal. Escape or a click
            // elsewhere closes it.
            onClick={(e) => {
              e.preventDefault();
              setOpen(true);
            }}
            className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-subtle hover:text-fg focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
          >
            <Info className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        </TooltipPrimitive.Trigger>
        <TooltipPrimitive.Portal>
          <TooltipPrimitive.Content
            side={side}
            sideOffset={6}
            collisionPadding={12}
            className="z-[60] max-w-sm rounded-md border border-border bg-surface px-3 py-2 text-xs leading-relaxed text-fg shadow-lg"
          >
            {children}
            <TooltipPrimitive.Arrow className="fill-[var(--surface)]" />
          </TooltipPrimitive.Content>
        </TooltipPrimitive.Portal>
      </TooltipPrimitive.Root>
    </TooltipPrimitive.Provider>
  );
}
