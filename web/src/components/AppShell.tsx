import {
  FileBarChart2,
  KeyRound,
  LayoutDashboard,
  Menu,
  Moon,
  Plus,
  Radar,
  Search,
  Server,
  Settings as SettingsIcon,
  ShieldAlert,
  Sparkles,
  Sun,
  X,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Link, navigate, usePathname } from "../lib/router";
import { applyTheme, resolveInitialTheme, type Theme } from "../lib/theme";
import { cn } from "../lib/cn";
import { Button } from "./ui/Button";
import { AskGuard } from "./AskGuard";
import { AuthGate } from "./AuthGate";
import { ErrorBoundary } from "./ErrorBoundary";
import { ApiError, api, getToken, setToken } from "../lib/api";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/assets", label: "Assets", icon: Server },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
  { to: "/scans", label: "Scans", icon: Radar },
  { to: "/reports", label: "Reports", icon: FileBarChart2 },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
];

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const [theme, setTheme] = useState<Theme>(() => resolveInitialTheme());
  const [mobileNav, setMobileNav] = useState(false);
  const [askOpen, setAskOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [authNeeded, setAuthNeeded] = useState(false);
  const [authReason, setAuthReason] = useState<"required" | "rejected" | "manual">("required");
  const [authVersion, setAuthVersion] = useState(0);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    setMobileNav(false);
  }, [pathname]);

  // Detect "token required" up front and react to any 401 from a data call.
  useEffect(() => {
    let cancelled = false;
    const onUnauthorized = () => {
      // A rejected token must not stay in place: leaving it stored means every
      // retry fails silently with the same 401.
      const hadToken = Boolean(getToken());
      if (hadToken) setToken("");
      // Later unauthenticated retries must not overwrite the explanation: once a
      // token was rejected, that is what the user needs to see.
      setAuthReason((current) => (hadToken || current === "rejected" ? "rejected" : "required"));
      setAuthNeeded(true);
    };
    window.addEventListener("guard:unauthorized", onUnauthorized);
    // Probe an authenticated endpoint: a 401 means the server wants a token.
    api
      .meta()
      .then(() => {
        if (!cancelled) setAuthNeeded(false);
      })
      .catch((err: unknown) => {
        // ApiError 401 already dispatched the event; other failures are shown by
        // the pages themselves.
        if (!cancelled && !(err instanceof ApiError && err.status === 401)) return;
      });
    return () => {
      cancelled = true;
      window.removeEventListener("guard:unauthorized", onUnauthorized);
    };
  }, [authVersion]);



  function submitSearch(e: React.FormEvent) {
    e.preventDefault();
    const q = query.trim();
    navigate(q ? `/vulnerabilities?q=${encodeURIComponent(q)}` : "/vulnerabilities");
  }

  const nav = (
    <nav aria-label="Primary" className="flex flex-1 flex-col gap-0.5">
      {NAV.map((item) => {
        const active =
          item.to === "/" ? pathname === "/" : pathname === item.to || pathname.startsWith(item.to + "/");
        const Icon = item.icon;
        return (
          <Link
            key={item.to}
            to={item.to}
            aria-current={active ? "page" : undefined}
            className={cn(
              "flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm",
              active
                ? "bg-accent-soft font-medium text-accent"
                : "text-muted hover:bg-surface-2 hover:text-fg",
            )}
          >
            <Icon className="h-4 w-4" aria-hidden="true" />
            {item.label}
          </Link>
        );
      })}
    </nav>
  );

  return (
    <div className="min-h-screen bg-bg">
      <a href="#main" className="skip-link">
        Skip to content
      </a>

      {/* Sidebar (desktop) */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r border-border bg-surface px-3 py-4 lg:flex">
        <Link to="/" className="mb-5 flex items-center gap-2 px-1.5" aria-label="Clanker Guard home">
          <span className="grid h-7 w-7 place-items-center rounded-md bg-accent text-accent-fg" aria-hidden="true">
            <ShieldAlert className="h-4 w-4" />
          </span>
          <span className="text-sm font-semibold tracking-tight">Clanker Guard</span>
        </Link>
        {nav}
        <div className="mt-4 border-t border-border pt-3">
          <Button variant="primary" className="w-full" onClick={() => navigate("/scans/new")}>
            <Plus className="h-4 w-4" aria-hidden="true" />
            New Scan
          </Button>
        </div>
      </aside>

      {/* Mobile nav */}
      {mobileNav ? (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/40" onClick={() => setMobileNav(false)} aria-hidden="true" />
          <div className="absolute inset-y-0 left-0 w-64 border-r border-border bg-surface p-3">
            <div className="mb-4 flex items-center justify-between">
              <span className="text-sm font-semibold">Clanker Guard</span>
              <button
                className="rounded-md p-1.5 text-muted hover:bg-surface-2"
                onClick={() => setMobileNav(false)}
                aria-label="Close navigation"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>
            {nav}
            <Button variant="primary" className="mt-4 w-full" onClick={() => navigate("/scans/new")}>
              <Plus className="h-4 w-4" aria-hidden="true" /> New Scan
            </Button>
          </div>
        </div>
      ) : null}

      <div className="lg:pl-60">
        <header className="sticky top-0 z-20 border-b border-border bg-surface/85 backdrop-blur">
          <div className="flex h-14 items-center gap-2 px-3 sm:px-5">
            <Button
              variant="ghost"
              size="sm"
              className="lg:hidden"
              onClick={() => setMobileNav(true)}
              aria-label="Open navigation"
            >
              <Menu className="h-4 w-4" aria-hidden="true" />
            </Button>

            <form onSubmit={submitSearch} role="search" className="flex min-w-0 flex-1 items-center">
              <label htmlFor="global-search" className="sr-only">
                Search hostnames, IP addresses, packages or CVE identifiers
              </label>
              <div className="relative w-full max-w-md">
                <Search
                  className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-subtle"
                  aria-hidden="true"
                />
                <input
                  id="global-search"
                  type="search"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search host, IP, package or CVE…"
                  className="h-9 w-full rounded-md border border-border bg-surface-2 pl-8 pr-3 text-sm placeholder:text-subtle focus-visible:border-accent focus-visible:bg-surface"
                />
              </div>
            </form>

            <Button variant="ghost" size="sm" onClick={() => setAskOpen(true)} className="hidden sm:inline-flex">
              <Sparkles className="h-4 w-4" aria-hidden="true" />
              Ask Guard
            </Button>

            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setAuthReason("manual");
                setAuthNeeded(true);
              }}
              aria-label="API token"
              title="API token"
            >
              <KeyRound className="h-4 w-4" aria-hidden="true" />
            </Button>

            <Button
              variant="ghost"
              size="sm"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
              title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
            >
              {theme === "dark" ? (
                <Sun className="h-4 w-4" aria-hidden="true" />
              ) : (
                <Moon className="h-4 w-4" aria-hidden="true" />
              )}
            </Button>

            <Button variant="primary" size="sm" className="hidden md:inline-flex" onClick={() => navigate("/scans/new")}>
              <Plus className="h-4 w-4" aria-hidden="true" />
              New Scan
            </Button>
          </div>
        </header>

        <main id="main" className="mx-auto w-full max-w-[100rem] px-3 py-5 sm:px-5">
          {/* keyed so pages refetch after unlocking; isolated so one bad screen
              cannot blank the whole application */}
          <ErrorBoundary resetKey={pathname + ":" + authVersion}>
            <div key={authVersion}>{children}</div>
          </ErrorBoundary>
        </main>
      </div>

      <AskGuard open={askOpen} onOpenChange={setAskOpen} />

      {authNeeded ? (
        <AuthGate
          reason={authReason}
          onClose={() => setAuthNeeded(false)}
          onAuthenticated={() => {
            setAuthNeeded(false);
            setAuthVersion((v) => v + 1);
          }}
        />
      ) : null}
    </div>
  );
}
