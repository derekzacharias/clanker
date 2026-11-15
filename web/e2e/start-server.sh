#!/usr/bin/env bash
# Boot the Clanker Guard API + built UI against an isolated copy of the cache.
#
# Tests mutate this database (feedback, approvals, deployments), so it must never
# be the developer's real cache. A fresh copy is taken on every start.
#
# Two modes:
#   token (default)  CLANKER_GUARD_TOKEN is required; the suite injects it as
#                    localStorage. E2E_MODE=password runs a password-protected
#                    server instead so the sign-in screen can be driven end to end.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${E2E_MODE:-token}"
STATE="$ROOT/web/.e2e/$MODE"
SRC="${E2E_SOURCE_CACHE:-$HOME/.cache/clanker-guard/intel.db}"
TOKEN="${CLANKER_GUARD_TOKEN:-e2e-token}"
PORT="${E2E_PORT:-8789}"

mkdir -p "$STATE"
rm -rf "$STATE/cache" && mkdir -p "$STATE/cache"
if [ -f "$SRC" ]; then
  # The scanner database runs in WAL mode, so a plain copy would silently lose
  # the most recent commits (feedback, proposals, rules). VACUUM INTO produces a
  # consistent single-file snapshot.
  python3 - "$SRC" "$STATE/cache/intel.db" <<'PY'
import sqlite3, sys
src, dst = sys.argv[1], sys.argv[2]
# mode=ro + VACUUM INTO gives a consistent snapshot including WAL content.
con = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
con.execute("VACUUM INTO ?", (dst,))
con.close()
PY
else
  echo "warning: no source cache at $SRC; starting empty" >&2
fi

if [ "$MODE" = "password" ]; then
  : "${E2E_PASSWORD:?E2E_PASSWORD is required when E2E_MODE=password}"
  AUTH_FILE="$STATE/auth.json"
  rm -f "$AUTH_FILE"
  printf '%s' "$E2E_PASSWORD" | "$ROOT/bin/clanker" vuln auth set-password \
    --file "$AUTH_FILE" --password-stdin --username admin >/dev/null
  # No token: this server must be reachable only through the sign-in screen.
  exec "$ROOT/bin/clanker" vuln serve \
    --listen "127.0.0.1:$PORT" \
    --cache "$STATE/cache/intel.db" \
    --auth-file "$AUTH_FILE" \
    --web-dir "$ROOT/web/dist"
fi

export CLANKER_GUARD_TOKEN="$TOKEN"
# Token-only on purpose: the suite exercises the token path, and a password on the
# developer's machine must not change what the harness tests.
exec "$ROOT/bin/clanker" vuln serve \
  --listen "127.0.0.1:$PORT" \
  --cache "$STATE/cache/intel.db" \
  --auth-file "" \
  --web-dir "$ROOT/web/dist"
