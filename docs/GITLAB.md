# GitLab ticketing

Clanker Guard can open a GitLab issue from a finding, store the link, and show the issue's
state in the finding panel. GitLab remains the tracker; Clanker Guard remains the evidence.

The integration is **off by default**. Nothing is sent anywhere until it is enabled and
given a server, an access token and a destination project.

---

## 1. What it does, and what it deliberately does not

| Does | Does not |
|---|---|
| Creates one issue per finding per project (`POST /api/v4/projects/:id/issues`) | Create issues automatically by severity |
| Records issue IID, URL, state, assignee, who created it and when | Treat a closed issue as a fixed vulnerability |
| Shows the issue in the finding panel with a link and **Refresh status** | Sync state in the background or receive webhooks |
| Recovers from a timed-out creation by searching for the finding marker first | Run on the GitLab side (no CI config, no bot account required) |
| Refuses plain HTTP to anything that is not a private address | Store the token anywhere the API can return it |

Status values are only what GitLab reports: **opened** or **closed** (plus whatever labels
the project uses). No third state is invented, because no third state exists.

A closed ticket is **not** evidence of remediation. A finding is resolved only when a later
assessment stops reporting it (`POST /api/remediation/{id}/verify`).

---

## 2. Configuring it

### Through the UI

**Settings → Integrations → GitLab**

| Field | Notes |
|---|---|
| Enable GitLab ticketing | Off until switched on |
| GitLab server URL | `https://gitlab.example.com`, or `http://host:port` for an internal instance with the plain-HTTP switch on |
| Access token | Needs `api` scope and at least **Reporter** on a private project. Write-only: stored on the server, never returned |
| Allow plain HTTP for an internal instance | Refused unless the host resolves to a private address |
| Default project | **Load** lists projects the token can see; the chosen one is the default destination |
| Default labels | Comma separated; `security`, the effective severity, `cisa-kev` and `fix-available` are added automatically |
| Default assignee | Optional GitLab username, resolved to an id at creation time |

**Test connection** checks reachability, authentication, project visibility, whether issues
are enabled, and whether the token's role looks sufficient. It **does not create an issue**,
so a green result means "the connection is ready", not "a ticket was created".

### Through the environment

Environment variables override the stored file, which lets a container be configured
without writing a token to disk:

```env
GITLAB_ENABLED=true
GITLAB_URL=http://gitlab.test.intra:8929
GITLAB_API_URL=http://gitlab.test.intra:8929/api/v4   # accepted as an alternative
GITLAB_TOKEN=glpat-…
GITLAB_PROJECT_ID=42
GITLAB_TIMEOUT_SECONDS=15
GITLAB_ALLOW_INSECURE_HTTP=true                        # internal instance only
```

Server flags:

```bash
clanker vuln serve --gitlab-config /config/gitlab.json
# or: CLANKER_GUARD_GITLAB_FILE=/config/gitlab.json
```

The default is `~/.config/clanker-guard/gitlab.json`, a `0600` file written atomically. In
the container deployment it is mounted at `/config/gitlab.json` so it survives restarts.

**Run the server as the file's owner.** The file is rewritten whenever settings change or a
connection test runs, and a file created by a different user (for example a one-off `docker
run` without `--user 1000:1000`) leaves the service unable to read it. The API says so
explicitly and prints the `chown`/`chmod` that fixes it.

---

## 3. Creating a ticket

1. Open a finding (**Vulnerabilities → row**).
2. **Create GitLab Ticket** (only shown when the integration is ready).
3. Review the preview: title, project, optional assignee, labels, and the full markdown body.
4. **Create Ticket**. The panel then shows the issue number, state, link and **Refresh status**.

The preview is rendered by the server (`POST /api/integrations/gitlab/preview`), so what the
operator edits is exactly what would be sent, and the text is not assembled twice.

### What goes into the issue

CVE and aliases, reported and effective severity (with the reason for any escalation), CVSS
and vector, EPSS, KEV, priority, SLA due date, hostname, OS, affected package and installed
version, the scanner's explanation, structured detection evidence, remediation guidance
with its provenance, verification steps, references (including NVD and the KEV catalog), and
the Clanker Guard finding id.

Two rules shape the remediation section:

* **Advisory text stays attributed.** Text quoted from a distribution or vendor advisory is
  labelled as such and still says "confirm it applies to this host".
* **No invented commands.** When no fixed version is published, the issue says so and tells
  the owner to check the advisory for a fix, mitigation or workaround instead of assuming a
  package upgrade resolves it.

Not included: inventory details unrelated to the finding, environment variables, credentials,
or anything from the agent's local files.

---

## 4. Duplicate prevention

Three mechanisms, in order:

1. **A unique row per (finding, project)** in `gitlab_tickets`. A second request finds it and
   returns the existing ticket with `reused: true`; GitLab is never asked again.
2. **A per-finding lock in the server process**, so two simultaneous requests do not both
   decide to create. (A multi-replica deployment would need a shared lock; this one runs as a
   single container.)
3. **A marker in the description**, `<!-- clanker-guard:finding:<key> -->`. If a creation
   attempt ended ambiguously (timeout, dropped connection, 5xx), the row stays pending and the
   next attempt **searches GitLab for the marker** and adopts the issue that already exists
   instead of opening a second one.

A definitive rejection (401/403/404/422) releases the reservation, so a corrected retry is
allowed and does not leave a phantom ticket behind.

---

## 5. Security properties

| Concern | Behaviour |
|---|---|
| Token storage | `0600` file written atomically, or environment; never in the settings table that `/api/settings` serves |
| Token exposure | Sent only as a `PRIVATE-TOKEN` header to the configured origin; never in a URL, never in a response, never logged |
| SSRF | Destination validated: http/https only, no embedded credentials, no query/fragment, link-local and cloud-metadata addresses refused |
| Plain HTTP | Refused unless explicitly allowed **and** every resolved address is private; an unresolvable host over HTTP is refused |
| Redirects | Followed only within the same origin; a redirect elsewhere is dropped rather than carrying the token with it |
| Timeouts | 15 s default, 1–60 s configurable, enforced per request |
| Authorization | Every endpoint sits behind the existing dashboard auth (session cookie or `X-Guard-Token`), with the CSRF origin check on cookie mutations; ticket rows record which credential created them |
| Audit | Configuration changes and ticket creation/refresh are logged with project, issue IID, asset and actor — never the token |

There is no role system in Clanker Guard today: authorization is "a signed-in dashboard
operator". Enabling the integration, saving a token and creating tickets all require one. If
roles are added later, the gate belongs in `middleware`/`routes` next to the existing auth
check, not inside this integration.

---

## 6. API

```
GET    /api/integrations/gitlab                       configuration (token reported as token_set)
PUT    /api/integrations/gitlab                       update; blank token keeps the stored one
POST   /api/integrations/gitlab/test                   connection checks (creates nothing)
GET    /api/integrations/gitlab/projects?search=       projects the token can see
GET    /api/integrations/gitlab/users?search=          assignable accounts
POST   /api/integrations/gitlab/preview                render the issue body for a finding
POST   /api/integrations/gitlab/tickets                create (or reuse) the issue
GET    /api/integrations/gitlab/tickets?finding_key=   tracked tickets
POST   /api/integrations/gitlab/tickets/{id}/refresh   read the issue state from GitLab
```

The finding detail (`GET /api/vulnerabilities/{id}`) includes `gitlab_tickets`, so the panel
shows an existing issue without a second request.

Storage: one additive table, created on startup if absent.

```sql
CREATE TABLE gitlab_tickets (
  id, finding_key, asset, vulnerability_id, project_id, project_path,
  issue_iid, issue_url, title, labels, state, assignee, created_by,
  created_at, last_synced_at, note
);
CREATE UNIQUE INDEX idx_gitlab_tickets_unique ON gitlab_tickets(finding_key, project_id);
```

---

## 7. Testing

`internal/vuln/ticketing` holds the client, the renderer and the store; its tests run against
an in-process fake GitLab (`fake_test.go`), so they need no network:

```bash
go test ./internal/vuln/ticketing/ ./internal/vuln/api/
```

Covered: URL validation (SSRF, metadata, credentials in URL, plain-HTTP rules), token header
placement, 401/403/404/timeout classification, redirect refusal, the connection test creating
nothing, description content and provenance, issue creation, duplicate prevention under
concurrent submission, timeout-then-recover, rejection releasing the reservation, refresh,
and the API's authorization and redaction behaviour. The UI path is covered by
`web/src/test/gitlab.test.tsx` (preview → create → link, existing ticket, refusal, unconfigured
state, settings save without re-sending the token).

Live checks against the internal test instance are recorded in the integration report; the
GitLab version there is CE 19.5.5, which supports every endpoint used here.

---

## 8. Known limits

* No automated creation by severity, no grouping of several findings into one issue, no
  scheduled sync, no webhooks — these are explicit follow-ups, not hidden behaviour.
* Labels are sent as names. GitLab creates missing labels as project labels for a user with
  permission; otherwise it rejects the request with a readable error.
* `assignee_ids` is the field used (still accepted by GitLab, though the API docs mark it
  deprecated in favour of `assignee_id` for a single assignee). Only accounts visible to the
  token can be assigned.
* One issue per (finding, project). If a ticket is closed as "won't fix" and the finding
  reappears, the existing issue is reused rather than reopened automatically — the operator
  decides, because reopening is a judgement call about the finding, not about the ticketing.
