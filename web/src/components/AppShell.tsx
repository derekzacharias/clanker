import {
  FileBarChart2,
  KeyRound,
  LayoutDashboard,
  LogOut,
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
import { ApiError, api, getToken, setToken, type AuthSession } from "../lib/api";

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
  const [session, setSession] = useState<AuthSession | null>(null);
  // Pages only mount once the auth model is known: an unauthenticated deep link
  // must redirect before it fires a request that would 401.
  const [sessionReady, setSessionReady] = useState(false);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    setMobileNav(false);
  }, [pathname]);

  // Resolve the authentication model before painting data: a password-protected
  // server redirects to /login, a token-only server keeps the unlock dialog, and
  // a loopback server with no credential renders as before.
  useEffect(() => {
    let cancelled = false;
    const here = window.location.pathname + window.location.search;
    (async () => {
      try {
        const s = await api.session();
        if (cancelled) return;
        setSession(s);
        setSessionReady(true);
        if (s.required && !s.authenticated) {
          if (s.methods.password) {
            navigate(`/login?next=${encodeURIComponent(here)}`, { replace: true });
            return;
          }
          setAuthNeeded(true);
          return;
        }
        setAuthNeeded(false);
      } catch {
        // A server built before password sign-in answers /api/auth/session with
        // the SPA shell rather than JSON; fall back to the token probe so those
        // deployments keep their unlock dialog.
        if (cancelled) return;
        setSessionReady(true);
        try {
          await api.meta();
          if (!cancelled) {
            setSession(null);
            setAuthNeeded(false);
          }
        } catch (err) {
          if (!cancelled && err instanceof ApiError && err.status === 401) {
            setAuthReason("rejected");
            setAuthNeeded(true);
          }
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [authVersion]);

  // React to any 401 from a data call: ask the server which credential it wants
  // before choosing a UI. A password deployment redirects to /login; a
  // token-only one opens the dialog. Probing here (rather than re-running the
  // effect above) is what keeps a 401 from re-triggering itself.
  useEffect(() => {
    let probing = false;
    const onUnauthorized = async () => {
      if (probing) return;
      probing = true;
      // A rejected token must not stay in place: leaving it stored means every
      // retry fails silently with the same 401.
      const hadToken = Boolean(getToken());
      if (hadToken) setToken("");
      // Later unauthenticated retries must not overwrite the explanation: once a
      // token was rejected, that is what the user needs to see.
      setAuthReason((current) => (hadToken || current === "rejected" ? "rejected" : "required"));
      try {
        const s = await api.session();
        setSession(s);
        if (s.required && !s.authenticated && s.methods.password) {
          const here = window.location.pathname + window.location.search;
          navigate(`/login?next=${encodeURIComponent(here)}`, { replace: true });
          return;
        }
      } catch {
        // Older server without the session endpoint: the token dialog is the
        // only way in.
      } finally {
        probing = false;
      }
      setAuthNeeded(true);
    };
    window.addEventListener("guard:unauthorized", onUnauthorized);
    return () => window.removeEventListener("guard:unauthorized", onUnauthorized);
  }, []);

  async function signOut() {
    try {
      await api.logout();
    } catch {
      // The cookie may already be gone; clearing local state is still correct.
    }
    setToken("");
    setSession(null);
    navigate("/login", { replace: true });
  }


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

            {/* A password session shows who is signed in and offers sign-out;
                a token-authenticated browser keeps the key button so the token
                can be replaced or cleared. */}
            {session?.authenticated && session.username ? (
              <div className="flex items-center gap-1">
                <span className="hidden max-w-32 truncate text-xs text-muted sm:inline" title={session.username}>
                  {session.username}
                </span>
                <Button variant="ghost" size="sm" onClick={signOut} aria-label="Sign out" title="Sign out">
                  <LogOut className="h-4 w-4" aria-hidden="true" />
                </Button>
              </div>
            ) : (
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
            )}

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

            {/* The sidebar carries the primary action from lg up; below that this
                is the only visible entry point. */}
            <Button variant="primary" size="sm" className="md:inline-flex lg:hidden" onClick={() => navigate("/scans/new")}>
              <Plus className="h-4 w-4" aria-hidden="true" />
              New Scan
            </Button>
          </div>
        </header>

        <main id="main" className="mx-auto w-full max-w-[100rem] px-3 py-5 sm:px-5">
          {/* Nothing renders until the auth model is known, and a
              password-protected server must not paint data before the redirect
              to /login lands. Token-only servers keep rendering the pages so
              their 401 drives the unlock dialog, exactly as before. */}
          {!sessionReady ? (
            <p role="status" className="py-10 text-sm text-muted">
              Checking access…
            </p>
          ) : session?.required && !session.authenticated && session.methods?.password ? (
            <p role="status" className="py-10 text-sm text-muted">
              Sign-in required — taking you to the sign-in page…
            </p>
          ) : (
            /* keyed so pages refetch after unlocking; isolated so one bad screen
               cannot blank the whole application */
            <ErrorBoundary resetKey={pathname + ":" + authVersion}>
              <div key={authVersion}>{children}</div>
            </ErrorBoundary>
          )}
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
