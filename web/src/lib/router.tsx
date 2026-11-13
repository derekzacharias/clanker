import { useSyncExternalStore, type AnchorHTMLAttributes, type MouseEvent } from "react";

/**
 * Minimal history-API router. A dependency-free router keeps the bundle small
 * and the behaviour easy to test; there is no nested routing to justify a
 * library here.
 */
const listeners = new Set<() => void>();

function emit() {
  for (const l of listeners) l();
}

export function navigate(to: string, options: { replace?: boolean } = {}): void {
  if (typeof window === "undefined") return;
  if (options.replace) window.history.replaceState({}, "", to);
  else window.history.pushState({}, "", to);
  emit();
  window.scrollTo({ top: 0 });
}

if (typeof window !== "undefined") {
  window.addEventListener("popstate", emit);
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function useLocation(): string {
  return useSyncExternalStore(
    subscribe,
    () => (typeof window === "undefined" ? "/" : window.location.pathname + window.location.search),
    () => "/",
  );
}

export function usePathname(): string {
  const loc = useLocation();
  return loc.split("?")[0];
}

export function useQueryParam(name: string): string | null {
  const loc = useLocation();
  const idx = loc.indexOf("?");
  if (idx === -1) return null;
  return new URLSearchParams(loc.slice(idx + 1)).get(name);
}

interface LinkProps extends AnchorHTMLAttributes<HTMLAnchorElement> {
  to: string;
}

export function Link({ to, onClick, children, ...rest }: LinkProps) {
  function handleClick(e: MouseEvent<HTMLAnchorElement>) {
    onClick?.(e);
    if (e.defaultPrevented) return;
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    navigate(to);
  }
  return (
    <a href={to} onClick={handleClick} {...rest}>
      {children}
    </a>
  );
}

/** Route matcher: "/assets/:host" → params or null. */
export function matchRoute(pattern: string, pathname: string): Record<string, string> | null {
  const p = pattern.split("/").filter(Boolean);
  const s = pathname.split("/").filter(Boolean);
  if (p.length !== s.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < p.length; i++) {
    if (p[i].startsWith(":")) params[p[i].slice(1)] = decodeURIComponent(s[i]);
    else if (p[i] !== s[i]) return null;
  }
  return params;
}
