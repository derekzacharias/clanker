#!/usr/bin/env bash
# Boot the Clanker Guard API + built UI against an isolated copy of the cache.
#
# Tests mutate this database (feedback, approvals, deployments), so it must never
# be the developer's real cache. A fresh copy is taken on every start.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE="$ROOT/web/.e2e"
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

export CLANKER_GUARD_TOKEN="$TOKEN"
exec "$ROOT/bin/clanker" vuln serve \
  --listen "127.0.0.1:$PORT" \
  --cache "$STATE/cache/intel.db" \
  --web-dir "$ROOT/web/dist"
