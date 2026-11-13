#!/usr/bin/env bash
# uninstall-agent.sh — remove clanker-guard-agent and its local cache.
#
#   ./uninstall-agent.sh [--keep-cache] [--yes]
#
# Removes only: the agent binary and ~/.cache/clanker-guard (or $XDG_CACHE_HOME).
# The agent installs no service and no scheduled task, so nothing else to undo.
set -euo pipefail

KEEP_CACHE=0
ASSUME_YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --keep-cache) KEEP_CACHE=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; exit 3 ;;
  esac
done

BIN="$(command -v clanker-guard-agent || true)"
if [ -z "$BIN" ]; then
  for candidate in "$HOME/.local/bin/clanker-guard-agent" /usr/local/bin/clanker-guard-agent; do
    [ -x "$candidate" ] && BIN="$candidate" && break
  done
fi
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/clanker-guard"

if [ "$ASSUME_YES" != "1" ]; then
  echo "This will remove:"
  echo "  - ${BIN:-<agent binary not found>}"
  [ "$KEEP_CACHE" = "1" ] || echo "  - $CACHE_DIR (intelligence cache and scan history)"
  echo "Re-run with --yes to confirm."
  exit 3
fi

if [ -n "$BIN" ]; then
  rm -f "$BIN"
  echo "removed $BIN"
else
  echo "agent binary not found on PATH; nothing to remove"
fi

if [ "$KEEP_CACHE" != "1" ]; then
  rm -rf "$CACHE_DIR"
  echo "removed $CACHE_DIR"
fi

echo "uninstall complete (no services or scheduled tasks were installed)"
