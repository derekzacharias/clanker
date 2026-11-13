#!/usr/bin/env bash
# install-agent.sh — install clanker-guard-agent with verified artifact integrity.
#
#   curl -fsSL <base-url>/install-agent.sh | bash -s -- --version 0.1.0
#
# Options:
#   --version VERSION   release version to install (required unless CLANKER_GUARD_VERSION)
#   --base-url URL      release base URL (default: CLANKER_GUARD_BASE_URL or GitHub releases)
#   --bin-dir DIR       install directory (default: $HOME/.local/bin, or /usr/local/bin when writable)
#   --scan              run a local assessment immediately after installing
#   --yes               non-interactive (accepted for scripted use; this installer never prompts)
#
# Security properties:
#   * Never executes an unverified download: the artifact is checked against the
#     published SHA-256 before it is moved into place.
#   * No service, no scheduled task, no auto-update, no telemetry.
#   * Uninstall with: clanker-guard-agent uninstall --yes
set -euo pipefail

REPO="bgdnvk/clanker"
DEFAULT_BASE="https://github.com/${REPO}/releases/download"
VERSION="${CLANKER_GUARD_VERSION:-}"
BASE_URL="${CLANKER_GUARD_BASE_URL:-$DEFAULT_BASE}"
BIN_DIR="${CLANKER_GUARD_BIN_DIR:-}"
RUN_SCAN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --base-url) BASE_URL="${2:?--base-url needs a value}"; shift 2 ;;
    --bin-dir) BIN_DIR="${2:?--bin-dir needs a value}"; shift 2 ;;
    --scan) RUN_SCAN=1; shift ;;
    --yes) shift ;;
    -h|--help)
      sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; exit 3 ;;
  esac
done

if [ -z "$VERSION" ]; then
  echo "error: --version is required (or set CLANKER_GUARD_VERSION)" >&2
  echo "       releases: https://github.com/${REPO}/releases" >&2
  exit 3
fi

case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  *) echo "error: unsupported operating system: $(uname -s) (Windows: use install-agent.ps1)" >&2; exit 3 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) echo "error: unsupported architecture: $(uname -m)" >&2; exit 3 ;;
esac

ARTIFACT="clanker-guard-agent_${OS}_${ARCH}"
if [ -n "$VERSION" ] && [ "$BASE_URL" = "$DEFAULT_BASE" ]; then
  URL_BASE="${BASE_URL}/v${VERSION}"
else
  URL_BASE="${BASE_URL}"
fi

if [ -z "$BIN_DIR" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null; then
    BIN_DIR=/usr/local/bin
  else
    BIN_DIR="$HOME/.local/bin"
  fi
fi
mkdir -p "$BIN_DIR"

TMPDIR_GUARD="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_GUARD"' EXIT

fetch() {
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$dest" "$url" 2>/dev/null || curl -fsSL -o "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url"
  else
    echo "error: neither curl nor wget is available" >&2
    exit 3
  fi
}

verify() {
  local artifact="$1" sums="$2" name="$3"
  local expected actual
  expected="$(awk -v n="$name" '$2 == n {print $1}' "$sums" | head -n1)"
  if [ -z "$expected" ]; then
    # support the "<hash>  <file>" form directly next to the artifact
    expected="$(awk '{print $1}' "$sums" | head -n1)"
  fi
  if [ -z "$expected" ]; then
    echo "error: no checksum found for ${name}; refusing to install" >&2
    exit 3
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$artifact" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "$artifact" | awk '{print $1}')"
  fi
  if [ "$expected" != "$actual" ]; then
    echo "error: SHA-256 mismatch for ${name}" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    echo "refusing to install a corrupted or tampered artifact" >&2
    exit 3
  fi
  echo "verified SHA-256 ${actual}"
}

echo "clanker-guard-agent ${VERSION} (${OS}/${ARCH})"
echo "downloading: ${URL_BASE}/${ARTIFACT}"
fetch "${URL_BASE}/${ARTIFACT}" "$TMPDIR_GUARD/$ARTIFACT"
fetch "${URL_BASE}/${ARTIFACT}.sha256" "$TMPDIR_GUARD/$ARTIFACT.sha256" || true
if [ ! -s "$TMPDIR_GUARD/$ARTIFACT.sha256" ]; then
  fetch "${URL_BASE}/SHA256SUMS" "$TMPDIR_GUARD/SHA256SUMS"
  verify "$TMPDIR_GUARD/$ARTIFACT" "$TMPDIR_GUARD/SHA256SUMS" "$ARTIFACT"
else
  verify "$TMPDIR_GUARD/$ARTIFACT" "$TMPDIR_GUARD/$ARTIFACT.sha256" "$ARTIFACT"
fi

install -m 0755 "$TMPDIR_GUARD/$ARTIFACT" "$BIN_DIR/clanker-guard-agent"
echo "installed: $BIN_DIR/clanker-guard-agent"
"$BIN_DIR/clanker-guard-agent" version

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "note: $BIN_DIR is not on your PATH; add it with: export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

echo
echo "Next steps (nothing runs automatically):"
echo "  clanker-guard-agent scan --local --format json --output findings.json"
echo "  clanker-guard-agent feeds update --with-osv   # enables offline scans"
echo "  clanker-guard-agent uninstall --yes           # remove binary and cache"

if [ "$RUN_SCAN" = "1" ]; then
  echo
  echo "running: clanker-guard-agent scan --local"
  exec "$BIN_DIR/clanker-guard-agent" scan --local
fi
