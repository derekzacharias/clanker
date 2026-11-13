#!/usr/bin/env bash
# Build clanker-guard-agent release artifacts plus SHA-256 checksums.
#
#   ./scripts/build-agent-release.sh <version> [output-dir]
#
# Produces, for each supported platform:
#   clanker-guard-agent_<os>_<arch>[.exe]
#   clanker-guard-agent_<os>_<arch>[.exe].sha256
# plus install-agent.sh / install-agent.ps1 and SHA256SUMS, which is exactly the
# layout the installers expect.
set -euo pipefail

VERSION="${1:?usage: build-agent-release.sh <version> [output-dir]}"
OUT="${2:-dist/v${VERSION}}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$OUT"

PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
)

for platform in "${PLATFORMS[@]}"; do
  os="${platform%/*}"
  arch="${platform#*/}"
  name="clanker-guard-agent_${os}_${arch}"
  [ "$os" = "windows" ] && name="${name}.exe"
  echo "building ${name}"
  (
    cd "$ROOT"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
      go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o "$OUT/$name" ./cmd/clanker-guard-agent
  )
  (
    cd "$OUT"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$name" > "$name.sha256"
    else
      shasum -a 256 "$name" > "$name.sha256"
    fi
  )
done

cp "$ROOT/scripts/install-agent.sh" "$OUT/install-agent.sh"
cp "$ROOT/scripts/install-agent.ps1" "$OUT/install-agent.ps1"
cp "$ROOT/scripts/uninstall-agent.sh" "$OUT/uninstall-agent.sh"
(
  cd "$OUT"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum clanker-guard-agent_* install-agent.sh install-agent.ps1 uninstall-agent.sh > SHA256SUMS
  else
    shasum -a 256 clanker-guard-agent_* install-agent.sh install-agent.ps1 uninstall-agent.sh > SHA256SUMS
  fi
)
echo
echo "artifacts in $OUT"
ls -1 "$OUT"
