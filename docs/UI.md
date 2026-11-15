# Clanker Guard web interface

The UI is a React + TypeScript application served by `clanker vuln serve` from
the same binary that produces the assessments. It reads a small JSON API over
the local store; **the Go backend remains authoritative** for applicability,
confidence and risk — the frontend never re-derives them.

```bash
# terminal 1 — API + built UI
cd ~/clanker-guard
./bin/clanker vuln serve --listen 127.0.0.1:8787 --web-dir web/dist

# terminal 2 — UI development with hot reload (proxies /api to :8787)
cd web && npm run dev
```

Build once before serving:

```bash
cd web && npm ci && npm run build   # -> web/dist
```

---

## 1. Stack

| Concern | Choice | Why |
|---|---|---|
| Framework | React 18 + TypeScript (strict) | team familiarity, typed API contract |
| Build | Vite 6 | fast builds, no bundler config sprawl |
| Styling | Tailwind CSS 4 (CSS-first `@theme`) | tokens live in one file, no config drift |
| Primitives | Radix UI (Dialog, Tabs, Switch, Tooltip) | accessible behaviour we should not re-implement |
| Icons | lucide-react | consistent, tree-shaken |
| Routing | tiny history-API router (`src/lib/router.tsx`) | no nested routing to justify a dependency |
| Data | `useAsync` hook + typed `fetch` client | pages own their data; no global store to desync |
| Tests | Vitest + Testing Library (jsdom) | same runner as the build toolchain |

Bundle: **376 kB JS (116 kB gzip)**, **32 kB CSS (6.7 kB gzip)**. No chart
library: the severity distribution is a labelled CSS bar, which is smaller and
screen-reader friendly.

```
web/
  src/
    lib/         api.ts (typed client), useApi.ts, format.ts, theme.ts, router.tsx, cn.ts
    components/
      ui/        Button, Card, Badge, Field, Dialog/Drawer, Table, Feedback, Toast, Tooltip, Switch
      AppShell   sidebar + topbar + search + theme toggle + Ask Guard
      badges     SeverityBadge, ApplicabilityBadge, KevBadge, ConfidenceBadge, FixBadge
      StatCard, SeverityBar, PageHeader
    pages/       Overview, Assets, AssetDetail, Vulnerabilities, VulnerabilityDetail,
                 Scans, NewScan, Reports, ReportView, Settings
    test/        setup + fixtures + workflow tests
```

---

## 2. Design system

Semantic tokens only; components never hard-code colours. Light is the default,
dark is a class on `<html>`, choice persists in `localStorage`.

| Token group | Examples | Notes |
|---|---|---|
| Surfaces | `--bg`, `--surface`, `--surface-2`, `--surface-3` | neutral, low-contrast borders |
| Text | `--fg`, `--fg-muted`, `--fg-subtle` | all pairs checked for AA contrast |
| Interaction | `--accent` (blue), `--accent-soft` | one primary action per screen |
| Severity | `--critical`, `--high`, `--medium`, `--low`, `--unknown` (+ `-soft` variants) | always paired with a label and icon |
| Shape | `--radius` (0.65rem), `--shadow-card`, `--shadow-pop` | consistent radii, shadows only for hierarchy |
| Type | Inter/system sans; monospace for CVE, versions, paths, commands | tabular numerals for counts and scores |

**Severity is never colour-only.** `SeverityBadge` renders icon + word +
colour; the distribution bar carries a text legend; tables have a Severity
column with words.

---

## 3. Screens and the question each answers

| Screen | Question it answers | Notes |
|---|---|---|
| **Overview** | What needs attention right now? | 4 metric cards, severity distribution, priority findings, coverage, activity, feed freshness, limitations. Empty state is a first-run call to action — no fabricated numbers. |
| **Assets** | Which endpoints are assessed and how bad is each? | filter by OS / finding / scan age; stale badge; links to detail |
| **Asset detail** | What is on this host and what applies to it? | findings, packages (progressively disclosed), coverage, skipped checks, scan history |
| **Vulnerabilities** | What should I fix, and how sure are we? | filters (severity, applicability, KEV, fix availability, asset, text), sort by remediation priority; evidence panel with confidence, reasons to raise/lower, references |
| **New scan** | How do I run an assessment? | three steps and four types: **Local System**, Network (scope + authorisation), Software/Container, and **Endpoint Scan** (dispatches to an enrolled agent at once when it is online; a request for an unreachable endpoint stays queued and is shown as such) |
| **Scans** | What ran, what is running, what failed? | live stage + percent from the server, cancel, report links, history |
| **Reports** | What did the assessment conclude? | stored reports, JSON/Markdown/SARIF/HTML export, evidence preserved; **software inventory** export (CSV asset list + CycloneDX SBOM) per host, and one environment-wide CSV across every assessed host |
| **Remediation** | Who owes what, and by when? | work items derived from findings: team, owner, state, SLA due date, overdue flag; filter by team/state/overdue; **My work** scopes the queue to the signed-in operator and each row can be claimed; automated execution is reported as unavailable rather than offered |
| **Ownership** | Who is responsible for each machine? | inventory of assets with their work counts, recorded team/engineer, exposure; single-row edit and multi-select bulk assignment; assets routed by the category mapping but with no record say so explicitly ("work maps to X") because routing is not accountability |
| **Settings** | Policy, intelligence, agents, access | tabs; feed freshness + update; agent install commands only when artifacts are published |
| **Sign in** (`/login`) | Who are you, and how do I stay signed in? | username + password form when a dashboard password exists; falls back to the token form on token-only servers; states the session length; one error line, no user/password distinction |

**Ask Guard** is a supporting side panel, not the primary workflow. It is
deterministic: answers come from the stored report via `scan.Ask`, citations
name the findings used, and the panel states that no model was consulted.

---

## 4. Backend contract

`internal/vuln/api` exposes:

```
GET    /api/meta                     capabilities + release state (honest, not aspirational)
GET    /api/overview                 metrics, severity, priority, coverage, activity, feeds
GET    /api/assets                   asset rows
GET    /api/assets/{host}            asset detail (packages, findings, coverage, history)
GET    /api/vulnerabilities          filter/sort/paginate over findings
GET    /api/vulnerabilities/{id}     full finding: evidence, confidence, risk factors, references
GET    /api/scans                    jobs + stored runs
POST   /api/scans                    start local scan (network/SBOM → 422 with reason)
GET    /api/scans/{id}               job progress + report when complete
POST   /api/scans/{id}/cancel        cancel a running job
GET    /api/reports                  stored assessments
GET    /api/reports/{id}             raw report JSON
GET    /api/reports/{id}/export      json | markdown | sarif | html download
GET    /api/feeds                    feed freshness + cache counts
POST   /api/feeds/update             refresh KEV + EPSS as a job
GET    /api/agents                   local agent, endpoints, install commands/build steps
GET    /api/ownership                asset inventory: record + work counts + routed teams
GET    /api/ownership/{host} · PUT   one asset's ownership
POST   /api/ownership/bulk           assign many assets to one team in a single request
GET    /api/remediation              work items (team, state, owner, overdue filters)
GET    /api/remediation/summary      counts + automation status (disabled, with reason)
GET    /api/remediation/{id} · PATCH one item: team, engineer, workflow state
POST   /api/remediation/{id}/verify  record a verification scan (the only path to resolved)
GET    /api/settings  · PUT          policy, offline default, release base
POST   /api/ask                      deterministic answer + citations + grounding
```

Design rules enforced by the API (and its tests):

* capabilities that are not implemented report `false`, and the UI disables them
  with an explanatory banner instead of a fake success;
* install commands are only rendered when a release base URL is configured; the
  UI otherwise shows the real build/publish steps;
* findings are addressed by a stable id derived from host + package + version +
  CVE, so links survive re-scans;
* findings are evidence and never change; ownership, deadline and workflow live
  on the work item derived from them, so the finding flyout shows "owner and
  deadline" from `/api/vulnerabilities/{id}` → `remediation_item` rather than
  re-deriving routing in the browser;
* routing never guesses: an asset with no ownership record and a finding whose
  ecosystem cannot be classified goes to triage, and only `POST
  /api/remediation/{id}/verify` can set `resolved`;
* scan progress percentages come from server stages, not a timer;
* the server refuses to bind a non-loopback address without a credential (a
  password set with `clanker vuln auth set-password`, or `CLANKER_GUARD_TOKEN`),
  and the UI sends the token as `X-Guard-Token`;
* copy controls must work on the deployment people actually run — plain HTTP on
  a LAN address is not a secure context, so `navigator.clipboard` is undefined
  there. `lib/clipboard.ts` falls back to `execCommand`, and if that is blocked
  too it selects the text and says so, instead of failing silently;
* a password deployment signs in on `/login` and keeps an HttpOnly,
  `SameSite=Strict` session cookie; the shell probes `/api/auth/session` before
  painting data, so an unauthenticated visitor is redirected instead of seeing a
  screen of 401s, and a cookie-authenticated mutation without `Origin` /
  `Sec-Fetch-Site` is refused (CSRF);

---

## 5. States the UI must get right

| State | Behaviour |
|---|---|
| First run, no data | “Run your first scan”, explicitly no metrics |
| Loading | skeletons/spinners with `role="status"`; no layout jump |
| Empty result | “No findings in the assessed scope”, plus the reminder that this is not proof of security |
| Uncertain finding | applicability badge + banner; “needs investigation” is never counted as actionable |
| Stale intelligence | top-of-page warning with the last sync per source |
| Failed scan | what failed, what completed, and a retry action |
| API unreachable | recoverable error with retry; the message names `clanker vuln serve` |
| Session expired | redirect to `/login?next=<page>`; no token dialog, no partial screen |
| Wrong password | one generic line (never "no such user"), password field cleared, username kept |
| Rate limited | explains the wait instead of pretending the password was wrong |
| Incomplete assessment | scan errors surfaced on the asset and report pages |

---

## 6. Accessibility (WCAG 2.2 AA practices)

* Skip link to `#main`; one `<h1>` per screen; landmark `nav`, `main`, `header`.
* Every control has a programmatic label: visible `<label>`, `aria-label`, or
  `aria-labelledby` (search, filters, theme toggle, dialog close).
* Focus is always visible (`:focus-visible` ring on the accent colour);
  `prefers-reduced-motion` disables transitions.
* Dialogs/drawers use Radix: focus trap, `Escape`, restored focus, `role="dialog"`
  with an accessible title.
* Tables use `<caption class="sr-only">` and `<th scope="col">`; long tables
  scroll horizontally rather than squeezing columns.
* Status is conveyed with text as well as colour (severity, freshness, scan
  state); `aria-pressed` marks filter chips; `aria-current="page"` marks the nav.
* Toasts announce through `aria-live="polite"`; scan progress is a real
  `role="progressbar"` with `aria-valuenow`.

---

## 7. Tests

```bash
cd web && npm test          # 43 tests, jsdom
npm run build               # tsc --noEmit + vite build
```

Covered workflows:

* **Sign in** — password form posts JSON with `credentials: same-origin`, continues
  to `?next=` (same-origin only, `//host` rejected), clears the legacy token;
  401 keeps the page and shows one generic line; 429 explains the wait; the token
  form appears when no password is configured; an open loopback server renders
  "No sign-in required"; the shell redirects to `/login` instead of painting data
  and a mid-session 401 lands on `/login` rather than the token dialog.
* **Overview** — renders real metrics/priority/coverage; stale-feed warning;
  first-run empty state shows no metrics; API failure surfaces a retry;
  unresolved findings are explained as not actionable.
* **Vulnerabilities** — table content (severity, applicability, KEV, fix);
  severity chip updates the request and `aria-pressed`; evidence drawer states
  that a version match is *not* validated and links authoritative references;
  empty result wording avoids claiming security.
* **New scan** — three-step flow; network/SBOM marked unavailable with reasons;
  configure → review → start posts the right body; server-reported progress;
  cancel calls the cancel endpoint.
* **Theme** — light default, toggle applies `.dark` and persists, stored
  preference wins.
* **Accessibility** — skip link, labelled navigation/search, active-item state,
  Ask Guard dialog labelling.

Not covered (tracked, not implied): real-browser end-to-end (Playwright),
visual regression, i18n/locale formatting, and screen-reader spot checks on
hardware.

---

## 7a. Browser-level verification

The interface is tested in Chromium, Firefox and WebKit with Playwright, against
an isolated snapshot of the scanner database: routes, workflows, authenticated
downloads, axe accessibility checks, keyboard flows and five viewport sizes.
Harness details and the defects that pass found: [TESTING.md](TESTING.md).

## 7b. Continuous improvement screens

Finding details include an analyst review panel (five actions, structured
false-positive reasons, verification result, history). Settings gains one
secondary page, **Continuous improvement**, showing quality metrics with sample
caveats, proposal cards with test results and approve/reject/deploy/rollback
actions, the full fixture comparison, and the audit trail. The Overview shows a
single line when proposals are waiting. Details: [IMPROVEMENT.md](IMPROVEMENT.md).

## 8. Deliberate gaps

1. **No fake data in the app.** There is no seeded demo mode; screenshots and
   demos require a real scan.
2. **No chat-first UI.** Ask Guard is a panel and is explicitly labelled
   deterministic.
3. **No virtualization.** Tables cap at 100–300 rows per view with filters and a
   “showing X of Y” notice; large fleets need pagination UI next.
4. **No server-initiated commands.** Agents enroll, check in and upload reports;
   the server still cannot ask an endpoint to *do* anything. There is no rescan
   scheduling or offline report queue yet, so an endpoint that is down simply
   shows as offline.
5. **Single operator account.** One password (or token); no roles, no SSO, no
   per-user audit trail beyond the login log.
