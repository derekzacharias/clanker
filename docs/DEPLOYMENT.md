# Deployment

Clanker Guard runs as a container on **docker4** (`192.168.20.6`), published on
port **8787**. Public access terminates TLS at **Nginx Proxy Manager** and forwards
to that port. Everything below is the supported path; there is no manual image
building step.

```
browser ──https──► Nginx Proxy Manager ──http──► docker4:8787 (container clanker-guard)
agent   ──https────────────────────────────────► same endpoint, /api/agents/*
```

## The loop

Every change follows the same four steps — deploy and record travel together:

```bash
# 1. change + test
cd ~/clanker-guard
go test ./internal/vuln/... ./cmd/... 
cd web && npm run build && cd ..

# 2. deploy to docker4 (builds static binary + UI, ships, restarts, verifies)
./scripts/deploy-docker4.sh --version 0.1.8 \
    --release-base https://github.com/derekzacharias/clanker-guard-agent/releases/download/v0.1.7

# 3. verify from the inside and the outside
curl -sS http://127.0.0.1:8787/api/health
curl -sS https://<public-host>/api/health

# 4. record it
git add -A && git commit -m "..." && git push origin feature/vuln-subsystem
```

`scripts/deploy-docker4.sh` runs the test suite, builds `CGO_ENABLED=0`, ships
`clanker` + `web/dist` + a CA bundle, rebuilds the image with `--no-cache`,
restarts the container, then **fails the deploy** unless `/api/health` reports the
version you asked for, `/login` is 200 and `/api/agents` is 401. It can also do
steps 2–4 in one go:

```bash
./scripts/deploy-docker4.sh --version 0.1.8 --commit "fix: ..." --push
```

## What the container is

| | |
|---|---|
| Image | `clanker-guard:<version>`, `FROM scratch` (static Go binary + built UI + CA bundle) |
| Container | `clanker-guard`, `--restart unless-stopped`, runs as uid 1000, **not root** |
| Volumes | `~/clanker-guard/data` → `/data` (SQLite: history + fleet), `~/clanker-guard/config` → `/config` (dashboard password) |
| Banner | The container is only the origin: TLS, HSTS and redirects belong to the proxy |
| Docs on host | `~/clanker-guard/README.md` |

## Behind the TLS proxy

The dashboard is internet-facing, so three things matter:

1. **Trust the proxy for client addresses.** Otherwise every request arrives from
   the proxy's address, so the login rate limit becomes one shared bucket — ten
   wrong passwords from anyone would lock you out too. Find the proxy's address:

   ```bash
   ssh docker4.test.intra "docker logs --since 10m clanker-guard | grep 'unauthenticated api request' | tail -1"
   ```

   then redeploy once with it:

   ```bash
   ./scripts/deploy-docker4.sh --version <v> --trusted-proxies 192.168.20.<proxy-ip>
   ```

   Only the configured addresses' `X-Forwarded-For` is believed (walked right to
   left, so a client cannot forge its way past the limiter). Until it is set, the
   peer address is used and nothing is spoofable — just coarse.

2. **Cookies.** The session cookie is marked `Secure` automatically when the
   request arrives with `X-Forwarded-Proto: https` (NPM sends it). If you ever see
   a cookie without `Secure` in DevTools, the proxy is not forwarding that header.

3. **Proxy settings that must stay on:** *Force SSL*, *HTTP/2* (optional), *Block
   common exploits*, and **no caching for `/api/*`** (a cached 401 or stale JSON
   will confuse both the UI and agents). Websockets are not used.

## Agents over HTTPS

With TLS at the edge there is no reason to run agents over plain HTTP, and the
`--allow-insecure-http` escape hatch should not be used for this deployment:

```bash
clanker-guard-agent enroll --server https://<public-host> \
  --enroll-token <token minted in Settings → Agents>     # single use, 24h TTL
clanker-guard-agent service restart
clanker-guard-agent doctor
```

Tokens are single use; mint one per endpoint.

## Upgrade, rollback, backup

```bash
# upgrade: run the loop above with a new --version

# rollback: the previous image is still tagged locally
ssh docker4.test.intra 'docker images clanker-guard'
ssh docker4.test.intra 'docker rm -f clanker-guard && docker run -d --name clanker-guard \
  --restart unless-stopped --user 1000:1000 -p 8787:8787 \
  -v /home/dzacharias/clanker-guard/data:/data \
  -v /home/dzacharias/clanker-guard/config:/config \
  clanker-guard:<previous-version> --listen 0.0.0.0:8787 --web-dir /web \
  --cache /data/intel.db --auth-file /config/auth.json'

# backup: two files
sudo systemctl stop docker || true          # or: docker stop clanker-guard
cp ~/clanker-guard/data/intel.db{,.$(date +%F)}
cp ~/clanker-guard/config/auth.json{,.$(date +%F)}
docker start clanker-guard
```

## Troubleshooting

| Symptom | Check |
|---|---|
| Blank page in the browser, health 200 | DevTools → Network: is the JS bundle 200? Was the request redirected to https? Is a proxy/VPN intercepting the name? |
| 502 from the proxy | `ssh docker4.test.intra 'docker ps --filter name=clanker-guard'` and `docker logs --tail 30 clanker-guard` |
| Login works, then every action 401 | cookie not being sent: proxy must forward `X-Forwarded-Proto` and not strip `Set-Cookie` |
| Agent reports "cannot reach" | `clanker-guard-agent doctor`; check the public URL resolves and TLS is valid from that endpoint |
| Rate-limited while nobody is attacking | `--trusted-proxies` is not set, so all clients share the proxy's address |
