import { Check, ClipboardCopy } from "lucide-react";
import { useEffect, useRef, useState, type RefObject } from "react";
import { copyText, selectElementText, type CopyOutcome } from "../../lib/clipboard";
import { Button } from "./Button";

/**
 * Copy control used everywhere the dashboard hands out a command or a secret.
 *
 * It exists because the plain `navigator.clipboard.writeText` call is not
 * available on the deployments this app runs on: plain HTTP on a LAN address is
 * not a secure context, so the API is undefined and a naive call silently does
 * nothing. `copyText` falls back to execCommand, and when even that is blocked the
 * referenced element is selected so Ctrl+C still works — with the outcome
 * announced instead of swallowed.
 */
export function CopyButton({
  value,
  label,
  selectRef,
  onOutcome,
  size = "sm",
  variant = "ghost",
}: {
  value: string;
  /** Accessible name, e.g. "Copy Linux install command". */
  label: string;
  /** Element whose text is selected when the clipboard is unavailable. */
  selectRef?: RefObject<HTMLElement | null>;
  onOutcome?: (outcome: CopyOutcome) => void;
  size?: "sm" | "md";
  variant?: "primary" | "secondary" | "ghost" | "danger";
}) {
  const [outcome, setOutcome] = useState<CopyOutcome | null>(null);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
    };
  }, []);

  async function handleClick() {
    const result = await copyText(value);
    setOutcome(result);
    onOutcome?.(result);
    if (result === "manual" && selectRef?.current) {
      selectElementText(selectRef.current);
    }
    if (result === "copied") {
      if (timer.current !== null) window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setOutcome(null), 1500);
    }
  }

  return (
    <>
      <Button size={size} variant={variant} onClick={handleClick} aria-label={label} title={label}>
        {outcome === "copied" ? (
          <Check className="h-3.5 w-3.5" aria-hidden="true" />
        ) : (
          <ClipboardCopy className="h-3.5 w-3.5" aria-hidden="true" />
        )}
        {outcome === "copied" ? "Copied" : "Copy"}
      </Button>
      <span role="status" aria-live="polite" className="sr-only">
        {outcome === "copied"
          ? "Copied to the clipboard."
          : outcome === "manual"
            ? "The browser blocked clipboard access; the text is selected — press Ctrl+C."
            : ""}
      </span>
    </>
  );
}
