#!/usr/bin/env bash
# Deploy the Clanker Guard dashboard to docker4.
#
#   ./scripts/deploy-docker4.sh --version 0.1.7 \
#       --release-base https://github.com/derekzacharias/clanker-guard-agent/releases/download/v0.1.7
#
# Builds a static server binary plus the production UI, ships them to the host,
# rebuilds the image there, restarts the container and verifies the result before
# reporting success. Any failure leaves the previous image tagged (see ROLLBACK).
#
# Options:
#   --version V            version reported by /api/health (default: current git describe-ish)
#   --host H               target host (default: docker4.test.intra)
#   --nvd-api-key KEY      NVD API key passed to the container (raises the sync rate limit)
#   --release-base URL     agent installer base URL advertised in the dashboard. When omitted,
#                          the value the running container already uses is reused; if there is
#                          none, the deploy refuses instead of silently hiding the install
#                          commands (the dashboard shows them only when a base is configured)
#   --no-release-base      deploy without an agent release base on purpose
#   --trusted-proxies LIST proxy IPs/CIDRs whose X-Forwarded-For is trusted
#   --public-url URL       also verify through the public TLS endpoint (e.g. https://clanker.example.com)
#   --listen ADDR          container listen address (default: 0.0.0.0:8787)
#   --port P               published host port (default: 8787)
#   --skip-tests           deploy without running the Go test suite first
#   --commit "message"     also commit the working tree (refuses on a dirty test run)
#   --push                 push the commit to origin (requires --commit)
#   --dry-run              print what would happen, change nothing
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="docker4.test.intra"
VERSION=""
RELEASE_BASE="${CLANKER_GUARD_RELEASE_BASE:-}"
ALLOW_NO_RELEASE_BASE=0
TRUSTED_PROXIES="${CLANKER_GUARD_TRUSTED_PROXIES:-}"
PUBLIC_URL="${CLANKER_GUARD_PUBLIC_URL:-}"
NVD_API_KEY="${CLANKER_GUARD_NVD_API_KEY:-}"
LISTEN="0.0.0.0:8787"
PORT="8787"
RUN_TESTS=1
COMMIT_MSG=""
PUSH=0
DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?}"; shift 2 ;;
    --host) HOST="${2:?}"; shift 2 ;;
    --release-base) RELEASE_BASE="${2:?}"; shift 2 ;;
    --no-release-base) ALLOW_NO_RELEASE_BASE=1; shift ;;
    --nvd-api-key) NVD_API_KEY="${2:?}"; shift 2 ;;
    --trusted-proxies) TRUSTED_PROXIES="${2:?}"; shift 2 ;;
    --public-url) PUBLIC_URL="${2:?}"; shift 2 ;;
    --listen) LISTEN="${2:?}"; shift 2 ;;
    --port) PORT="${2:?}"; shift 2 ;;
    --skip-tests) RUN_TESTS=0; shift ;;
    --commit) COMMIT_MSG="${2:?}"; shift 2 ;;
    --push) PUSH=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,/^set -/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; exit 3 ;;
  esac
done

if [ -z "$VERSION" ]; then
  VERSION="$(git -C "$ROOT" describe --tags --always 2>/dev/null | sed 's/^v//' || echo dev)"
fi
STAGE="$(mktemp -d)"
CONTAINER="clanker-guard"
IMAGE="clanker-guard:${VERSION}"
DATA_DIR="/home/dzacharias/clanker-guard/data"
CONFIG_DIR="/home/dzacharias/clanker-guard/config"
REMOTE_DIR="/home/dzacharias/clanker-guard/image"

log() { printf '\n==> %s\n' "$*"; }
run() {
  if [ "$DRY_RUN" = "1" ]; then echo "    [dry-run] $*"; else eval "$@"; fi
}

cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

if [ "$PUSH" = "1" ] && [ -z "$COMMIT_MSG" ]; then
  echo "error: --push needs --commit \"message\" (deploy and record must travel together)" >&2
  exit 3
fi

# A deploy without a release base does not fail: the container starts happily and the dashboard
# simply stops showing the Linux/macOS/Windows install commands, because the server reports "no
# artifacts published". Nothing points at the cause. So remember what the running container uses
# and refuse to drop it, unless the operator says --no-release-base explicitly.
RELEASE_BASE_SOURCE="--release-base"
if [ -n "$RELEASE_BASE" ] && [ "$ALLOW_NO_RELEASE_BASE" = "1" ]; then
  echo "error: --release-base and --no-release-base contradict each other" >&2
  exit 3
fi
if [ -z "$RELEASE_BASE" ]; then
  RELEASE_BASE_SOURCE="CLANKER_GUARD_RELEASE_BASE"
fi
# --no-release-base means "none on purpose": do not resurrect the running container's value.
if [ -z "$RELEASE_BASE" ] && [ "$ALLOW_NO_RELEASE_BASE" != "1" ]; then
  RELEASE_BASE="$(ssh -o BatchMode=yes "$HOST" \
    "docker inspect $CONTAINER --format '{{range .Config.Env}}{{println .}}{{end}}'" 2>/dev/null \
    | sed -n 's/^CLANKER_GUARD_RELEASE_BASE=//p' | head -n 1 || true)"
  if [ -n "$RELEASE_BASE" ]; then
    RELEASE_BASE_SOURCE="remembered from $CONTAINER on $HOST"
  fi
fi
if [ -z "$RELEASE_BASE" ] && [ "$ALLOW_NO_RELEASE_BASE" != "1" ]; then
  cat >&2 <<'EOF'
error: no agent release base, and deploying without one hides the agent install commands.
  Pass --release-base https://github.com/<owner>/<repo>/releases/download/v<version>
  (or set CLANKER_GUARD_RELEASE_BASE). Use --no-release-base only when this dashboard should
  intentionally advertise no published agent artifacts.
EOF
  exit 3
fi

log "target: $HOST · image $IMAGE · listen $LISTEN · published port $PORT"
if [ -n "$RELEASE_BASE" ]; then
  echo "    release base: $RELEASE_BASE ($RELEASE_BASE_SOURCE)"
else
  echo "    release base: none (--no-release-base: the install commands will be hidden)"
fi
if [ -n "$(git -C "$ROOT" status --porcelain)" ]; then
  echo "    note: working tree has uncommitted changes; they will be deployed as-is"
fi

log "build UI"
run "cd '$ROOT/web' && npm run build >/dev/null"

log "build static server binary (CGO_ENABLED=0)"
run "cd '$ROOT' && CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -X github.com/bgdnvk/clanker/cmd.Version=$VERSION' -o '$STAGE/clanker' ."

log "run test suite"
if [ "$RUN_TESTS" = "1" ]; then
  run "cd '$ROOT' && go test ./internal/vuln/... ./cmd/... >/dev/null"
  run "cd '$ROOT' && go vet ./internal/vuln/... ./cmd/... >/dev/null"
else
  echo "    skipped (--skip-tests)"
fi

log "assemble image context"
run "cp -r '$ROOT/web/dist' '$STAGE/web'"
run "cp /etc/ssl/certs/ca-certificates.crt '$STAGE/ca-certificates.crt'"
cat > "$STAGE/Dockerfile" <<'DOCKERFILE'
# Static Go server + built UI on an empty base: no shell, no package manager.
FROM scratch
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY clanker /usr/local/bin/clanker
COPY web /web
VOLUME ["/data", "/config"]
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/clanker", "vuln", "serve"]
DOCKERFILE

log "ship to $HOST"
run "ssh -o BatchMode=yes '$HOST' 'mkdir -p $REMOTE_DIR'"
run "scp -q '$STAGE/clanker' '$STAGE/Dockerfile' '$STAGE/ca-certificates.crt' '$HOST:$REMOTE_DIR/'"
run "ssh -o BatchMode=yes '$HOST' 'rm -rf $REMOTE_DIR/web && mkdir -p $REMOTE_DIR/web'"
run "scp -qr '$STAGE/web/.' '$HOST:$REMOTE_DIR/web/'"

log "build image and restart container on $HOST"
RUN_ARGS="-d --name $CONTAINER --restart unless-stopped --user 1000:1000 -p $PORT:8787 -v $DATA_DIR:/data -v $CONFIG_DIR:/config"
[ -n "$RELEASE_BASE" ] && RUN_ARGS="$RUN_ARGS -e CLANKER_GUARD_RELEASE_BASE=$RELEASE_BASE"
[ -n "$TRUSTED_PROXIES" ] && RUN_ARGS="$RUN_ARGS -e CLANKER_GUARD_TRUSTED_PROXIES=$TRUSTED_PROXIES"
[ -n "$NVD_API_KEY" ] && RUN_ARGS="$RUN_ARGS -e CLANKER_GUARD_NVD_API_KEY=$NVD_API_KEY"
# The container has no writable home; feature state (AI settings, automation, audit) lives beside
# the auth and integration files on the mounted config volume, so it survives a restart.
RUN_ARGS="$RUN_ARGS -e CLANKER_GUARD_CONFIG_DIR=/config -e HOME=/tmp"
run "ssh -o BatchMode=yes '$HOST' 'cd $REMOTE_DIR && docker build --no-cache -q -t $IMAGE . >/dev/null'"
run "ssh -o BatchMode=yes '$HOST' 'docker rm -f $CONTAINER >/dev/null 2>&1 || true'"
# The GitLab integration file lives beside the password file: it holds an access token,
# so it must sit on the mounted config volume with 0600 permissions, not in the container's
# ephemeral home (which would silently drop the token on every restart).
run "ssh -o BatchMode=yes '$HOST' 'docker run $RUN_ARGS $IMAGE --listen $LISTEN --web-dir /web --cache /data/intel.db --auth-file /config/auth.json --gitlab-config /config/gitlab.json'"

log "verify"
if [ "$DRY_RUN" = "1" ]; then
  echo "    [dry-run] would poll /api/health for version $VERSION"
else
  ok=0
  for _ in $(seq 1 20); do
    sleep 1
    health="$(ssh -o BatchMode=yes "$HOST" "curl -sS -m 5 http://127.0.0.1:$PORT/api/health" 2>/dev/null || true)"
    if printf '%s' "$health" | grep -q "\"version\":\"$VERSION\""; then
      echo "    health: $health"
      ok=1
      break
    fi
  done
  if [ "$ok" != "1" ]; then
    echo "    FAILED: /api/health did not report version $VERSION" >&2
    ssh -o BatchMode=yes "$HOST" "docker logs --tail 30 $CONTAINER" >&2 || true
    echo "    ROLLBACK: ssh $HOST 'docker rm -f $CONTAINER && docker run ... <previous image>'" >&2
    exit 4
  fi
  login_code="$(ssh -o BatchMode=yes "$HOST" "curl -sS -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:$PORT/login" || true)"
  [ "$login_code" = "200" ] || { echo "    FAILED: /login returned $login_code" >&2; exit 4; }
  echo "    login: 200"
  unauth="$(ssh -o BatchMode=yes "$HOST" "curl -sS -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:$PORT/api/agents" || true)"
  [ "$unauth" = "401" ] || { echo "    FAILED: /api/agents must be 401 without a session (got $unauth)" >&2; exit 4; }
  echo "    auth:  401 without a session (as expected)"
  # The install commands are hidden by the server, not by the UI, so 'it deployed fine' is not
  # evidence they survived. Read the setting back from the container that is now running.
  if [ -n "$RELEASE_BASE" ]; then
    seen="$(ssh -o BatchMode=yes "$HOST" \
      "docker inspect $CONTAINER --format '{{range .Config.Env}}{{println .}}{{end}}'" 2>/dev/null \
      | sed -n 's/^CLANKER_GUARD_RELEASE_BASE=//p' | head -n 1 || true)"
    if [ "$seen" != "$RELEASE_BASE" ]; then
      echo "    FAILED: the running container's release base is '$seen', wanted '$RELEASE_BASE'" >&2
      echo "    the agent install commands would be hidden; fix RUN_ARGS and redeploy" >&2
      exit 4
    fi
    echo "    release base: verified on the container"
  fi
  # Public path, when a name is given: catches proxy/TLS regressions too.
  if [ -n "${PUBLIC_URL:-}" ]; then
    pub="$(curl -sS -m 8 -o /dev/null -w '%{http_code}' "${PUBLIC_URL%/}/api/health" || true)"
    [ "$pub" = "200" ] || { echo "    FAILED: $PUBLIC_URL/api/health returned $pub" >&2; exit 4; }
    echo "    public: $PUBLIC_URL/api/health 200"
  fi
fi

if [ -n "$COMMIT_MSG" ]; then
  log "commit and push"
  run "cd '$ROOT' && git add -A && git commit -q -m \"$COMMIT_MSG\""
  if [ "$PUSH" = "1" ]; then
    run "cd '$ROOT' && git push origin \"\$(git rev-parse --abbrev-ref HEAD)\""
  else
    echo "    committed; not pushed (--push to publish)"
  fi
else
  echo
  echo "Deployed $IMAGE. Record the change:"
  echo "  git add -A && git commit -m \"...\" && git push origin \$(git rev-parse --abbrev-ref HEAD)"
fi
