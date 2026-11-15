# Backlog

Tracked work that is **not implemented**, in priority order. Each item states what
exists today, what is missing, and how we will know it is done. Nothing here is a
commitment to a date.

Sections: [1. Remediation orchestration](#1-enterprise-remediation-orchestration-new)
· [2. Existing known gaps](#2-existing-known-gaps) · [3. Non-negotiable gates](#3-non-negotiable-gates)

---

## 1. Enterprise remediation orchestration (new)

**Status: not started.** Source: architecture brief, recorded 2026‑11‑15.
**Supersedes** the assumption in earlier roadmaps that security engineers patch
every host themselves. Ownership of *governance, prioritisation and verification*
stays with security engineering; ownership of *execution* moves to the team that
operates the system.

### What exists today (reuse, do not rebuild)

| Building block | Where | Reusable for |
|---|---|---|
| Persistent findings + run history + deltas | `internal/vuln/{scan,report,intel}`, `runs` table | finding identity, "new/persistent/resolved" |
| Finding lifecycle (verdicts, reason codes, history) | `internal/vuln/{improve,api}` (`finding_feedback`, `finding_state`) | false-positive / risk-accepted states |
| Asset inventory derived from reports | `runs`, `api/dataset.go` | ownership attaches here |
| Fleet: agents, per-agent credentials, tasks, leases | `internal/vuln/{fleet,api}` (`agents`, `agent_tasks`) | remediation execution channel |
| Agent service lifecycle + `doctor` | `cmd/clanker-guard-agent`, `internal/vuln/service` | post-remediation health checks |
| Software inventory export (CSV/CycloneDX) | `api/handlers.go` | "remediation applied" evidence |
| Risk model (CVSS/EPSS/KEV/confidence) | `internal/vuln/assess` | SLA inputs already present |
| Audit-style event log per agent | `agent_events` | execution audit trail |
| Signed releases + TLS-only agent transport | `scripts/`, `internal/vuln/agent` | secure execution preconditions |

**Not present at all:** ownership model, ticketing adapters, remediation groups,
workflow state machine, approval policy, automated execution, verification jobs,
remediation dashboard. There is **no** external integration layer and **no**
`/integrations` API (the Settings tab is labelled as a placeholder today).

### Decided constraints (apply to every item below)

- A **closed ticket is never evidence that a vulnerability is fixed**; only an
  independent scan/verification can close a remediation item.
- A **ticket status change never authorises privileged execution** on an endpoint.
  Execution requires an approval policy satisfied inside Clanker Guard.
- Ticket bodies, comments, webhook payloads and any external text are **untrusted
  input**: never interpolated into a command, never executed.
- No secrets, credentials or raw scanner dumps leave the product in a ticket.
- Every change here is additive and backwards compatible: existing findings, runs
  and fleet APIs keep working.

### Milestone 1 — Ownership and manual remediation

**B1.1 Asset ownership model** — *new table `asset_owners`, additive API*
- Fields per asset: owner, responsible team, business service/application,
  environment, criticality, internet exposure, support/escalation contact,
  permitted execution mechanism, maintenance window.
- Discovery sources, each pluggable and dry-runnable: manual assignment, CMDB
  import (CSV first), cloud tags, repository metadata (`owner:` in the report
  metadata / repo file).
- Deterministic precedence and a recorded conflict policy; **ambiguous or absent
  ownership goes to a triage queue, never to an arbitrary default team**.
- *Done when:* ownership can be set manually and by import, every asset resolves to
  exactly one of {owned, triage}, and re-running discovery is idempotent.

**B1.2 Default responsibility mapping** — *configuration, not code*
- Ships the brief's defaults (OS packages → IT/Infra/DevOps; source → Development;
  dependencies → Development/DevOps; base images → Platform; config → DevOps;
  cloud config → Cloud/Platform; exceptions → Security/Risk) as **editable
  mappings**, resolved from package/source type + asset type.
- *Done when:* an org can change the mapping without a rebuild and a finding's
  routing is explainable in the UI ("routed to X because …").

**B1.3 Remediation intelligence (no execution)**
- Per finding: minimum supported fix (vendor patched version, backport, mitigation),
  copyable commands, authoritative references, expected service impact, whether
  automated execution is supported at all.
- Must distinguish "vendor-confirmed fixed version" from "newer than vulnerable
  range" — the second is a guess and is labelled as such.
- *Done when:* every actionable finding shows a fix or an explicit
  "no supported fix known", and nothing is invented.

**B1.4 CVE flyout: Overview | Evidence | Remediation | Activity**
- Remediation tab: ownership, due date, recommended fix, actions
  (Create ticket / View ticket / Assign owner / Remediate / Verify fix) with the
  primary action driven by state **and** the caller's authorisation.
- *Done when:* an operator can see who owns a finding, what to run and when it is
  due, without leaving the page.

**B1.5 Internal remediation tracking**
- Work item records separate from findings, with the brief's state machine
  (`Detected → … → Resolved | Failed | Risk accepted | False positive`), including
  `Awaiting Ownership` and `Pending Verification`.
- *Done when:* state transitions are auditable and a finding can be resolved only
  by verification, never by manual "done".

### Milestone 2 — Ticketing

**B2.1 Vendor-neutral adapter layer**
- Provider interface (create/update/comment/transition/link), one implementation
  per provider. Order: ServiceNow, Jira, Azure DevOps, GitHub Issues.
- Compile-time-only dependencies (`net/http`), no SDK added without justification.
- Credentials: encrypted at rest, least-privilege scopes, never logged, never in
  ticket bodies. OAuth where the provider supports it.
- *Done when:* a second provider can be added without touching the remediation
  engine, and a credential leak test (log/breadcrumb scan) passes.

**B2.2 Ticket content + creation policy**
- Policy decides *when* a ticket is created (severity, KEV, exposure, owner known,
  existing ticket, accepted risk).
- Body per the brief: CVE, severity/priority, assets + environments, installed and
  fixed versions, instructions, copyable commands, references, business service,
  impact, owner, due date, deep link back, verification requirements.
- *Done when:* a ticket can be rendered from a finding deterministically (golden
  file test) and contains no secrets or scanner raw output.

**B2.3 Grouping and deduplication**
- Group key derived from responsible team + remediation procedure + OS/environment
  + maintenance window + patch dependency. Never group when fix, authority or
  window differ.
- Stable group id → idempotent create/update; a rescan updates, never duplicates.
- Reappearance after closure opens a **new linked** item, not a silent reopen.
- *Done when:* 50 hosts needing one OpenSSL update produce one ticket listing 50
  assets, and a second scan with no change produces zero new tickets.

**B2.4 Bidirectional synchronisation**
- Outbound: discovered/validated, created/updated, priority change, new assets,
  verified, reopened. Inbound: assignment, acknowledgement, window, approval,
  completion claim, comment.
- Explicit field/status map; conflict resolution documented; authenticated webhooks
  with polling fallback; retries with backoff; rate limiting; dead-letter +
  reconciliation; idempotent event keys.
- *Done when:* replaying the same webhook twice changes nothing, an out-of-order
  event cannot regress state, and every inbound event is audited.

### Milestone 3 — Secure automation (infrastructure path only)

**B3.1 Approved remediation playbooks**
- Declarative, versioned, reviewable: package + target version + preflight +
  health checks + rollback. Nothing free-form, no arbitrary commands.
- *Done when:* a playbook is data (not code), has an owner and a test on a fixture,
  and an unlisted playbook cannot be executed.

**B3.2 Execution framework on the agent task channel**
- Reuses `agent_tasks` (leases, attempts, expiry) and adds: action allowlist
  (`scan`, `remediate.package-update`), per-action approval requirement, execution
  window, dry-run, audit record with digests.
- The agent executes only allow-listed actions with a signed parameter set; the
  server independently authorises every request (never the ticket).
- *Done when:* a task for an unlisted action is refused at both ends, and a
  forged/replayed completion is rejected.

**B3.3 Approval policy + privilege boundaries**
- Approvals recorded inside Clanker Guard (who, when, what, expiry); optional
  dual-control. A ticket field can *request* an approval, never grant one.
- *Done when:* no path exists from an external system to execution without a
  policy-satisfying approval record.

**B3.4 First platform: Linux package update**
- Preflight: package present, target version available, disk space, no held
  packages, maintenance window, not mid-scan.
- Apply → health checks → rescan → verification evidence. Failure at any step stops
  and records partial outcome (patched but unhealthy must be visible).
- *Done when:* a real CVE on a test VM is patched, verified by rescan, and the
  ticket is updated with evidence — and a deliberately broken health check aborts
  the "success" outcome.

### Milestone 4 — Validation, SLAs and the remediation workspace

**B4.1 Verification and regression gate**
- Order: job completed → package state → service health → regression suite →
  targeted rescan → evidence stored → ticket updated.
- Success requires the security verification *and* the health checks; either
  failing marks the item failed with both outcomes recorded.
- *Done when:* "patched but broken" produces a failed remediation plus recovery
  guidance, never a closed ticket.

**B4.2 SLAs and escalation**
- Configurable per severity × criticality × exposure (brief's illustrative
  defaults: 7/30/60/90 days — examples, not mandates). Overdue tracking, escalation
  path, and **no escalation for risk-accepted findings**.
- *Done when:* a finding's due date is explainable ("critical, internet-facing → 7
  days") and an accepted risk does not generate reminders.

**B4.3 Remediation workspace (UI)**
- Open work, unassigned, overdue, awaiting approval, automation-eligible, running,
  failed attempts, verification failures, success rate, exposure trend; filters by
  owner/team/asset/severity/environment/state. Same design system, no new visual
  language.
- *Done when:* an operator can answer "what is overdue, who owns it, and what is
  blocked on me" on one screen.

**B4.4 Application (code) remediation — design only**
- Repository identification, fixed dependency version, generated work item, optional
  proposed change/PR, CI verification, existing review + deployment approvals.
- **Explicitly out of scope for endpoint execution:** never edit application source
  or production dependencies around the app's own deployment path.
- *Done when:* the design exists and is reviewed; implementation is a separate
  milestone.

### Open decisions (needed before Milestone 2)

1. Which provider first (brief lists ServiceNow first; Jira is likely faster to
   prove the adapter design).
2. Where credentials live (reuse `~/.config/clanker-guard` 0600 files vs an OS
   keyring) and who can rotate them.
3. Whether ownership lives only in Clanker Guard or syncs back to the CMDB.
4. Approval model: single approver or dual control for production assets.
5. Ticket closure policy: automatic after verification, or owner confirmation.

### Testing requirements (gate for every item above)

Unit + integration + Playwright, with **no real tickets in production systems**:

- ownership assignment, ambiguity → triage, routing per team
- grouping/dedup: one ticket for N hosts, no duplicate on rescan, reopen linkage
- bidirectional sync: replay, out-of-order, conflict, rate limit, retry, reconciliation
- credential handling: never logged, never in ticket body, least privilege
- authorisation: ticket comment cannot trigger execution; unauthorised user cannot
  approve or execute
- execution: allowlist enforcement, dry-run, lease expiry, forged completion
- verification: regression failure ≠ resolved; both outcomes recorded
- closure/reopen correctness driven by scans, not by ticket state

---

## 2. Existing known gaps

Kept from the earlier roadmaps; still true as of `0.2.1`.

1. **mTLS for agents** — bearer tokens are the identity today; per-agent
   certificates are designed but not issued.
2. **OS keychain storage** — agent credential is a 0600 file; DPAPI/Keychain not used.
3. **Self-update** (`agent update`) — deliberately absent until a user-pinned
   signing key ships end to end (signed manifests exist now, so this is unblocked).
4. **Network assessment**: no UDP, no asset persistence across scans beyond reports.
5. **Integrations API** — the Settings tab is a labelled placeholder; there is no
   `/integrations` endpoint. This backlog section replaces it with a real design.
6. **Portfolio-scale storage** — SQLite suits a single dashboard; 10k+ endpoints
   needs PostgreSQL + a durable queue (measure first: `scripts/` has no load test).
7. **Coverage gaps in detection** — OSV-driven today; distribution OVAL/vendor
   advisory feeds are not ingested.

## 3. Non-negotiable gates

Applies to everything in this file:

- Server-side authorisation on every action; the UI is not the enforcement point.
- Secrets never in logs, tickets, or error messages; redaction tested.
- Fail closed: an unknown action, an unparsable approval, an unreachable provider
  or a failed verification blocks, it does not proceed.
- Audit records are append-only and tamper-evident; every privileged action names
  the actor and the evidence.
- Every feature ships with tests that fail before the change and pass after it.
