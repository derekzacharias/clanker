import { KeyRound, Loader2, LockKeyhole, ShieldAlert } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { ApiError, api, getToken, setToken, type AuthSession } from "../lib/api";
import { useAppVersion } from "../lib/version";
import { navigate, useQueryParam } from "../lib/router";
import { Button } from "../components/ui/Button";
import { Field, Input } from "../components/ui/Field";

/**
 * Sign-in screen.
 *
 * The dashboard used to ask for CLANKER_GUARD_TOKEN in a modal on every new
 * browser, which meant digging the secret out of a shell each time. A password
 * sign-in replaces that: the server sets an HttpOnly session cookie, so the
 * browser stays signed in for `--session-ttl` (30 days by default) across
 * reloads and server restarts.
 *
 * Token-only deployments still work: if no password is configured, this screen
 * renders the token form instead of pretending a password exists.
 */
function safeNext(raw: string | null): string {
  // Only same-origin paths: "//host" and "https://host" would turn a crafted
  // ?next= into an open redirect after a successful sign-in.
  if (!raw) return "/";
  if (!raw.startsWith("/") || raw.startsWith("//")) return "/";
  return raw;
}

export default function Login() {
  const next = safeNext(useQueryParam("next"));
  const [session, setSession] = useState<AuthSession | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [token, setTokenValue] = useState(() => getToken());
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const version = useAppVersion();

  useEffect(() => {
    let cancelled = false;
    api
      .session()
      .then((s) => {
        if (!cancelled) setSession(s);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setLoadError(err instanceof ApiError ? err.message : "Cannot reach the Clanker Guard API.");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Already signed in (a back button, or a second tab): go straight through.
  useEffect(() => {
    if (session?.authenticated) navigate(next, { replace: true });
  }, [session, next]);

  async function submitPassword(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    if (!username.trim() || !password) {
      setError("Enter your username and password.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.login(username.trim(), password);
      // A password session makes a stored token pointless; dropping it keeps the
      // browser from sending two credentials at once.
      setToken("");
      navigate(next, { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(
          err.status === 429
            ? "Too many failed attempts. Wait a few minutes, then try again."
            : err.status === 0
              ? "Cannot reach the Clanker Guard API. Is `clanker vuln serve` running?"
              : err.message || "Sign-in failed.",
        );
      } else {
        setError("Sign-in failed.");
      }
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  function submitToken(e: FormEvent) {
    e.preventDefault();
    const trimmed = token.trim();
    if (!trimmed) {
      setError("Paste the token printed by `clanker vuln serve`.");
      return;
    }
    setToken(trimmed);
    navigate(next, { replace: true });
  }

  const signInHint = session?.session_ttl
    ? `You will stay signed in on this browser for ${humanizeTTL(session.session_ttl)}.`
    : "You will stay signed in on this browser.";

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-2.5">
          <span className="grid h-8 w-8 place-items-center rounded-md bg-accent text-accent-fg" aria-hidden="true">
            <ShieldAlert className="h-4 w-4" />
          </span>
          <span className="text-base font-semibold tracking-tight">Clanker Guard</span>
        </div>

        <div className="rounded-lg border border-border bg-surface p-5 shadow-sm">
          {loadError ? (
            <div className="space-y-3">
              <h1 className="text-base font-semibold">Cannot reach the API</h1>
              <p role="alert" className="text-sm text-muted">
                {loadError}
              </p>
              <Button onClick={() => window.location.reload()}>Retry</Button>
            </div>
          ) : session === null ? (
            <div className="flex items-center gap-2 text-sm text-muted" role="status">
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Checking authentication…
            </div>
          ) : !session.required ? (
            <div className="space-y-3">
              <h1 className="text-base font-semibold">No sign-in required</h1>
              <p className="text-sm text-muted">
                This server is bound to localhost with no password or token configured, so the dashboard is open.
              </p>
              <a href="/" className="text-sm text-accent underline underline-offset-2">
                Back to overview
              </a>
            </div>
          ) : session.methods.password ? (
            <form onSubmit={submitPassword} className="space-y-4" aria-busy={busy}>
              <div>
                <h1 className="flex items-center gap-2 text-base font-semibold">
                  <LockKeyhole className="h-4 w-4 text-accent" aria-hidden="true" /> Sign in
                </h1>
                <p className="mt-1 text-sm text-muted">{signInHint}</p>
              </div>

              <Field label="Username" htmlFor="login-username">
                <Input
                  id="login-username"
                  name="username"
                  autoComplete="username"
                  autoFocus
                  required
                  disabled={busy}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
              </Field>

              <Field label="Password" htmlFor="login-password">
                <Input
                  id="login-password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  disabled={busy}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  aria-invalid={error ? true : undefined}
                  aria-describedby={error ? "login-error" : undefined}
                />
              </Field>

              {error ? (
                <p id="login-error" role="alert" className="text-sm text-critical">
                  {error}
                </p>
              ) : null}

              <Button type="submit" variant="primary" className="w-full" disabled={busy}>
                {busy ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Signing in…
                  </>
                ) : (
                  "Sign in"
                )}
              </Button>

              {session.methods.token ? (
                <p className="text-xs text-subtle">
                  Scripts and the endpoint agent can keep using <span className="mono">X-Guard-Token</span>.
                </p>
              ) : null}
            </form>
          ) : (
            <form onSubmit={submitToken} className="space-y-4">
              <div>
                <h1 className="flex items-center gap-2 text-base font-semibold">
                  <KeyRound className="h-4 w-4 text-accent" aria-hidden="true" /> Enter the API token
                </h1>
                <p className="mt-1 text-sm text-muted">
                  This server has no dashboard password yet, so it asks for the token that{" "}
                  <span className="mono">clanker vuln serve</span> requires.
                </p>
              </div>
              <Field
                label="API token"
                htmlFor="login-token"
                hint={
                  <>
                    Stored in this browser only. Replace it with a password sign-in:{" "}
                    <span className="mono">clanker vuln auth set-password</span>
                  </>
                }
              >
                <Input
                  id="login-token"
                  type="password"
                  autoComplete="off"
                  autoFocus
                  value={token}
                  onChange={(e) => setTokenValue(e.target.value)}
                  aria-invalid={error ? true : undefined}
                  aria-describedby={error ? "login-error" : undefined}
                />
              </Field>
              {error ? (
                <p id="login-error" role="alert" className="text-sm text-critical">
                  {error}
                </p>
              ) : null}
              <Button type="submit" variant="primary" className="w-full">
                Continue
              </Button>
            </form>
          )}
        </div>

        <p className="mt-4 text-center text-xs text-subtle">
          Clanker Guard keeps vulnerability data on this machine only.
        </p>
        <p className="mt-1 text-center text-xs text-subtle">v{version}</p>
      </div>
    </div>
  );
}

/** "720h0m0s" → "30 days"; the server reports seconds-friendly strings. */
export function humanizeTTL(ttl: string): string {
  const match = /^(\d+)h(\d+)m/.exec(ttl);
  if (!match) return "the configured session length";
  const hours = Number(match[1]);
  if (hours >= 24 && hours % 24 === 0) {
    const days = hours / 24;
    return days === 1 ? "1 day" : `${days} days`;
  }
  return hours === 1 ? "1 hour" : `${hours} hours`;
}
