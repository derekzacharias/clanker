#!/usr/bin/env bash
# install-agent.sh — install clanker-guard-agent with verified artifact integrity.
#
#   curl -fsSL <base-url>/install-agent.sh | bash -s -- --version 0.1.0
#
# Options:
#   --version VERSION   release version to install (required unless CLANKER_GUARD_VERSION)
#   --base-url URL      release base URL (default: CLANKER_GUARD_BASE_URL or GitHub releases)
#   --bin-dir DIR       install directory (default: $HOME/.local/bin, or /usr/local/bin when writable)
#   --server URL        Clanker Guard server to report to (enrolls the endpoint)
#   --enroll-token T    enrollment token from Settings → Agents (needed for --server)
#   --no-scan           install and enroll, but do not run the first assessment
#   --watch             keep watching in the foreground instead of installing a
#                       background service (containers, debugging)
#   --no-service        do not install the background service; the endpoint will
#                       only be reachable while you run `watch` yourself
#   --scan              run a local assessment immediately after installing
#   --yes               non-interactive (accepted for scripted use; this installer never prompts)
#
# Security properties:
#   * Never executes an unverified download: the artifact is checked against the
#     published SHA-256 before it is moved into place.
#   * With --server, the endpoint enrolls and reports its findings and status to
#     that server only, and installs a background service so the dashboard can
#     ask it for scans (--no-service opts out). Without --server nothing is
#     uploaded anywhere and no service is installed.
#   * The service is removed by: clanker-guard-agent uninstall --yes
#   * Uninstall with: clanker-guard-agent uninstall --yes
set -euo pipefail

# Public half of the release signing key. Pinned here on purpose: if this key is
# wrong, every install fails loudly instead of silently trusting a swapped checksum.
# Rotation: ship an installer that trusts both keys, then drop the old one.
SIGNING_PUBKEY='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAddak3m8jw7qjzUpeyOrogWrFP6NxuF5MHv7Dj56fqx8=
-----END PUBLIC KEY-----'
SIGNING_AVAILABLE=0
REPO="derekzacharias/clanker-guard-agent"
DEFAULT_BASE="https://github.com/${REPO}/releases/download"
VERSION="${CLANKER_GUARD_VERSION:-}"
BASE_URL="${CLANKER_GUARD_BASE_URL:-$DEFAULT_BASE}"
BIN_DIR="${CLANKER_GUARD_BIN_DIR:-}"
RUN_SCAN=0
REPORT_SCAN=0
SERVER=""
ENROLL_TOKEN=""
NO_SCAN=0
WATCH=0
SERVICE=1

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --base-url) BASE_URL="${2:?--base-url needs a value}"; shift 2 ;;
    --bin-dir) BIN_DIR="${2:?--bin-dir needs a value}"; shift 2 ;;
    --scan) RUN_SCAN=1; shift ;;
    --server) SERVER="${2:?--server needs a value}"; shift 2 ;;
    --enroll-token) ENROLL_TOKEN="${2:?--enroll-token needs a value}"; shift 2 ;;
    --no-scan) NO_SCAN=1; shift ;;
    --watch) WATCH=1; shift ;;
    --no-service) SERVICE=0; shift ;;
    --yes) shift ;;
    -h|--help)
      sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
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

agent_config_path() {
  # Mirrors internal/vuln/agent.ConfigPath so `service install` watches the same
  # file `enroll` just wrote.
  if [ -n "${CLANKER_GUARD_AGENT_CONFIG:-}" ]; then
    printf '%s' "$CLANKER_GUARD_AGENT_CONFIG"
    return
  fi
  printf '%s' "${XDG_CONFIG_HOME:-$HOME/.config}/clanker-guard/agent.json"
}

verify_manifest_signature() {
  local dir="$1"
  if [ ! -s "$dir/SHA256SUMS.sig" ]; then
    echo "warning: this release publishes no SHA256SUMS.sig; only SHA-256 integrity is verified." >&2
    echo "warning: obtain the installer and checksums over a trusted channel if that matters here." >&2
    return 0
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    echo "error: openssl is required to verify the release signature; refusing to install" >&2
    return 3
  fi
  printf '%s\n' "$SIGNING_PUBKEY" > "$dir/.signing.pub"
  if ! openssl pkeyutl -verify -pubin -inkey "$dir/.signing.pub" -rawin \
      -in "$dir/SHA256SUMS" -sigfile "$dir/SHA256SUMS.sig" >/dev/null 2>&1; then
    echo "error: SHA256SUMS signature does not match the pinned release key; refusing to install" >&2
    return 3
  fi
  echo "verified release signature (Ed25519)"
  return 0
}

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
# Trust order matters: the aggregate manifest, when signed, is the only source of
# truth. A per-artifact .sha256 next to a signed manifest would let a compromised
# origin swap the artifact and its local checksum together.
fetch "${URL_BASE}/SHA256SUMS" "$TMPDIR_GUARD/SHA256SUMS" || true
fetch "${URL_BASE}/SHA256SUMS.sig" "$TMPDIR_GUARD/SHA256SUMS.sig" || true
if [ -s "$TMPDIR_GUARD/SHA256SUMS" ] && [ -s "$TMPDIR_GUARD/SHA256SUMS.sig" ]; then
  verify_manifest_signature "$TMPDIR_GUARD" || exit 3
  verify "$TMPDIR_GUARD/$ARTIFACT" "$TMPDIR_GUARD/SHA256SUMS" "$ARTIFACT"
elif [ -s "$TMPDIR_GUARD/SHA256SUMS" ]; then
  verify_manifest_signature "$TMPDIR_GUARD" || exit 3
  verify "$TMPDIR_GUARD/$ARTIFACT" "$TMPDIR_GUARD/SHA256SUMS" "$ARTIFACT"
else
  # Unsigned release: fall back to the per-artifact checksum, which the warning
  # above already framed as integrity-only, not authenticity.
  fetch "${URL_BASE}/${ARTIFACT}.sha256" "$TMPDIR_GUARD/$ARTIFACT.sha256" || true
  if [ -s "$TMPDIR_GUARD/$ARTIFACT.sha256" ]; then
    verify "$TMPDIR_GUARD/$ARTIFACT" "$TMPDIR_GUARD/$ARTIFACT.sha256" "$ARTIFACT"
  else
    echo "error: no checksums published for ${ARTIFACT}; refusing to install" >&2
    exit 3
  fi
fi

install -m 0755 "$TMPDIR_GUARD/$ARTIFACT" "$BIN_DIR/clanker-guard-agent"
echo "installed: $BIN_DIR/clanker-guard-agent"
"$BIN_DIR/clanker-guard-agent" version

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "note: $BIN_DIR is not on your PATH; add it with: export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

if [ -n "$SERVER" ]; then
  if [ -z "$ENROLL_TOKEN" ]; then
    echo "error: --server needs --enroll-token (Settings → Agents shows both)" >&2
    exit 3
  fi
  echo
  echo "enrolling with ${SERVER}"
  echo "  findings and status will be sent to that server only; nothing to a third party"
  "$BIN_DIR/clanker-guard-agent" enroll --server "$SERVER" --enroll-token "$ENROLL_TOKEN" || {
    echo "error: enrollment failed; the agent is installed but not reporting" >&2
    exit 4
  }
  REPORT_SCAN=1
fi

echo
echo "Next steps:"
echo "  clanker-guard-agent scan --local --format json --output findings.json"
echo "  clanker-guard-agent feeds update --with-osv   # enables offline scans"
echo "  clanker-guard-agent status                    # enrollment + server"
echo "  clanker-guard-agent uninstall --yes           # remove binary, config and cache"

if [ "$RUN_SCAN" = "1" ] || { [ "$REPORT_SCAN" = "1" ] && [ "$NO_SCAN" = "0" ]; }; then
  echo
  if [ "$REPORT_SCAN" = "1" ]; then
    echo "running: clanker-guard-agent scan --local   (reports to ${SERVER})"
  else
    echo "running: clanker-guard-agent scan --local"
  fi
  # Keep the scan's exit code for the no-watch path, but do not let findings (2)
  # or reduced coverage (4) look like an install failure when we continue below.
  set +e
  "$BIN_DIR/clanker-guard-agent" scan --local
  SCAN_CODE=$?
  set -e
  # Only stop here when nothing else was asked for. The service install below is
  # the default, so exiting on "not --watch" used to skip it entirely and leave
  # an endpoint that reports once and then goes dark.
  if [ "$WATCH" = "0" ] && [ "$SERVICE" = "0" ]; then
    exit "$SCAN_CODE"
  fi
fi

if [ "$WATCH" = "1" ]; then
  if [ "$REPORT_SCAN" = "0" ]; then
    echo "error: --watch needs --server and --enroll-token (the agent must be enrolled to receive scans)" >&2
    exit 3
  fi
  echo
  echo "staying available: clanker-guard-agent watch (foreground)"
  exec "$BIN_DIR/clanker-guard-agent" watch
fi

if [ "$SERVICE" = "1" ] && [ "$REPORT_SCAN" = "1" ]; then
  # Installing the service is what makes the endpoint stay reachable; asking an
  # operator to write a unit file is exactly the kind of work this avoids.
  echo
  echo "installing the background service"
  if "$BIN_DIR/clanker-guard-agent" service install --config "$(agent_config_path)"; then
    echo "  the endpoint will report as online while the service runs"
  else
    echo "  warning: could not install a service on this system" >&2
    echo "  the endpoint stays offline until you run: $BIN_DIR/clanker-guard-agent watch" >&2
  fi
else
  echo
  echo "note: no service installed (--no-service); this endpoint is reachable only while" >&2
  echo "      you run: $BIN_DIR/clanker-guard-agent watch" >&2
fi

# Findings (2) and reduced coverage (4) are scan outcomes, not install failures,
# but the exit code must still carry them for scripted callers.
exit "${SCAN_CODE:-0}"
