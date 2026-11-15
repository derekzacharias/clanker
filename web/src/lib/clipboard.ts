/**
 * Clipboard access that works on the deployments this dashboard actually has.
 *
 * `navigator.clipboard` only exists in a secure context: HTTPS, or plain HTTP on
 * localhost. The dashboard is normally served over plain HTTP on a LAN address
 * (http://192.168.20.77:8787), where `navigator.clipboard` is `undefined` — so a
 * bare `navigator.clipboard.writeText(...)` throws and a `catch {}` around it
 * makes the Copy button look broken.
 *
 * Order of attempts:
 *   1. the async Clipboard API (needs a secure context);
 *   2. a hidden textarea + document.execCommand("copy"), which still works on
 *      insecure origins because it is tied to the click gesture;
 *   3. give up and let the caller select the text so Ctrl+C works.
 */
export type CopyOutcome = "copied" | "manual";

export async function copyText(text: string): Promise<CopyOutcome> {
  if (!text) return "manual";

  if (typeof navigator !== "undefined" && window.isSecureContext && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return "copied";
    } catch {
      // Permission denied or a policy block: fall through to the legacy path.
    }
  }
  return legacyCopy(text) ? "copied" : "manual";
}

function legacyCopy(text: string): boolean {
  if (typeof document === "undefined" || typeof document.execCommand !== "function") {
    return false;
  }
  const area = document.createElement("textarea");
  area.value = text;
  // readonly keeps mobile keyboards from appearing; the off-screen position keeps
  // the page from scrolling to it.
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.top = "0";
  area.style.left = "-9999px";
  area.style.opacity = "0";

  const previous = document.activeElement as HTMLElement | null;
  document.body.appendChild(area);
  let ok = false;
  try {
    area.focus();
    area.select();
    area.setSelectionRange(0, text.length);
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  } finally {
    document.body.removeChild(area);
    previous?.focus?.();
  }
  return ok;
}

/** Select an element's text so the user can copy it with Ctrl+C. */
export function selectElementText(el: HTMLElement | null): void {
  if (!el || typeof window.getSelection !== "function") return;
  const range = document.createRange();
  range.selectNodeContents(el);
  const selection = window.getSelection();
  if (!selection) return;
  selection.removeAllRanges();
  selection.addRange(range);
}
