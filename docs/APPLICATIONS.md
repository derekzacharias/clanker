# Application vulnerability detection (NVD / CPE correlation)

Clanker Guard now answers "which installed *applications* are vulnerable" with
the same evidence discipline as the OS and package engines. A fully patched
Windows host can still run a vulnerable browser, Office build, runtime or
third-party tool; this engine detects exactly that.

Everything below is implemented, tested and shipped in this repository. Where a
capability is intentionally bounded (e.g. the size of the NVD dataset on the
endpoint), the bound is stated and visible in every report.

---

## 0. Architecture and data flow

The capability extends the existing Clanker Guard pipeline rather than
replacing it. Data flows one way:

```text
                        agent (endpoint)                 server / CLI
   registry · MSI · Click-to-Run · AppX · winget ──► inventory (internal/vuln/inventory)
                                                              │
   NVD API ───────────────────────────────────────────► intel store (nvd package)
   (sync: dictionary + CVEs + match index)                    │ SQLite
                                                              ▼
   normalize (norm/rules.json) ──► dictionary lookup ──► candidate CVEs ──►
   cpe configuration-tree evaluation ──► vendor-advisory cross-check ──►
   findings ──► engine.Finalize (KEV/EPSS/risk/IDs) ──► report ──►
   API (/api/overview, /api/vulnerabilities?category=) ──► dashboard ──►
   remediation groups (one upgrade = one ticket) ──► lifecycle (reopen on reappearance)
```

New components (all additive; no existing package was repurposed):

* `internal/vuln/cpe` — CPE 2.3 parsing/matching, version ranges, NVD
  configuration trees;
* `internal/vuln/norm` — data-driven normalization (`norm/rules.json`);
* `internal/vuln/nvd` — NVD client (rate limits, retries, pagination), SQLite
  store, sync orchestrator with history;
* `internal/vuln/apps` — the correlation assessor plus vendor advisories
  (`vendor_advisories.json`);
* extensions in `model` (application inventory + coverage fields),
  `inventory` (Windows collectors + dedupe), `scan` (pipeline stage), `api`
  (endpoints/facets), `remediate` (desktop-application grouping) and `web`
  (dashboard).

Existing engines are untouched: OSV/distribution correlation still owns OS
packages, the MSRC engine still owns Windows servicing, and network
assessment still owns fingerprinted services. The application engine only
takes what those engines cannot reach, so no redundant database or pipeline
was created — the NVD dataset is the single store all consumers share.

---

## 1. What it does

Pipeline per scan:

```text
installed applications  ──►  normalization (vendor/product/version)  ──►
CPE dictionary lookup (exact identifiers)  ──►  candidate CVEs from the local
NVD store  ──►  configuration-tree evaluation (AND/OR, negate, version
ranges)  ──►  vendor-advisory cross-check  ──►  evidence-backed findings
```

The engine runs entirely against the **local** NVD dataset synchronised into
the intelligence cache. NVD is never queried per application during a scan.

## 2. Inventory: what gets collected on Windows

The agent's Windows inventory collector (`internal/vuln/inventory`, the
`windows_registry` collector) reads, strictly read-only:

* the classic Uninstall hives — machine 64-bit, machine 32-bit
  (`WOW6432Node`), and per-user (`HKCU`), with name, version, publisher,
  install date, install location, scope, architecture, and the registry
  product identifier;
* Windows Installer metadata (`HKLM\SOFTWARE\Classes\Installer\Products`) for
  MSI products, keyed by product code;
* Office Click-to-Run configuration (`VersionToReport`, product release),
  because Click-to-Run products do not publish useful Uninstall versions;
* MSIX / Store packages (`Get-AppxPackage`), with family name as origin;
* installed .NET shared frameworks (from the servicing state collector);
* `winget` export, where the Windows Package Manager is present — bounded by a
  hard timeout, best-effort, and only after source-agreement acceptance;
* file-version metadata for a fixed list of well-known applications (Chrome,
  Firefox, Edge, VLC, Notepad++, 7-Zip, PuTTY, WinSCP) **only** as a fallback
  when the registry carries no usable version — the probe list is a constant,
  no scanned data is ever interpolated into a command.

`Win32_Product` is deliberately never used: enumerating it triggers Windows
Installer consistency checks and can repair or reconfigure installed products.

Deduplication merges the same application observed through several sources
(registry + MSI + winget + file version) into one record whose
`evidence_sources` keeps every origin. Two different versions of the same
application are two records, never merged.

## 3. Intelligence sources

| Source | Purpose |
|---|---|
| NVD CVE API 2.0 | CVE records: descriptions, CVSS, configurations, references, rejected status |
| NVD CPE dictionary | standardized vendor/product/version identities, deprecations |
| NVD CPE match data | affected/fixed version ranges, AND/OR applicability trees (inside CVE records) |
| CISA KEV / FIRST EPSS | exploitation status and probability (existing pipeline) |
| Vendor advisories | authoritative fixed versions, override NVD on conflict (see §5) |

All sources are synchronised centrally into SQLite and correlated locally.

### Synchronisation

```bash
clanker-guard-agent feeds update --with-nvd [--nvd-since YYYY-MM-DD]
                                    [--nvd-api-key KEY] [--nvd-full] [--nvd-max-pages N]
clanker-guard-agent feeds status
```

* initial population is paginated over the whole CVE history (use
  `--nvd-since` to bound the first sync); incremental updates re-fetch the
  window since the last successful sync minus a two-day overlap;
* the client honours NVD's rate limits (5 requests/30 s anonymous, 50 with an
  API key), spaces requests evenly, retries 429/5xx with exponential backoff,
  and honours `Retry-After`;
* the API key is read from `CLANKER_GUARD_NVD_API_KEY`, `NVD_API_KEY`, or the
  `--nvd-api-key` flag. It is never logged, never echoed, and never embedded
  in error text;
* every page is stored in one transaction; a failed sync aborts and **keeps
  the last known valid dataset** — the failure is recorded in
  `nvd_sync_history` and shown by `feeds status`;
* rejected CVEs are stored and marked; correlation excludes them and counts
  them as exclusions;
* administrative visibility (sync history rows): last success, mode
  (full/incremental), totals, imported, updated, failed, duration window, and
  per-run detail — surfaced through `feeds status` and the dashboard's
  intelligence display.

The dataset is bounded by design: the full NVD history is roughly 300 000 CVE
records. With an API key the initial sync takes tens of minutes; without one
it takes hours, which is why `--nvd-since` exists.

## 4. Normalization

Display names never equal NVD names, so `internal/vuln/norm` maps raw
inventory to canonical vendor/product/version/edition/channel/architecture
using a **data file** (`norm/rules.json`): publisher aliases, deterministic
product patterns, version cleaners, architecture and channel hints. Adding or
correcting a mapping is a data edit — no engine code changes, no rebuild
logic touched. The rules file is validated at load; a broken file fails
startup rather than misbehaving mid-scan.

Confidence is tracked per mapping (`pattern` / `dictionary` / `fuzzy` /
`unmapped`), and the original inventory string is always preserved.

**Fuzzy matching is a candidate generator only.** A similarity match
(`bigram` + token scoring) can surface a likely product, but any finding
derived from a fuzzy mapping is classified `potential` with low confidence —
it can never by itself establish that an application is vulnerable.

## 5. CPE matching and applicability

`internal/vuln/cpe` implements CPE 2.3 parsing and matching:

* wildcards (`*`, `?`) and escaped characters per NIST IR 7695;
* case-insensitive component matching;
* exact version equality and the four NVD range bounds
  (`versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`,
  `versionEndExcluding`), evaluated with ecosystem-aware comparators —
  numeric tokens compare numerically, so 120.0.10 > 120.0.9;
* configuration trees: AND/OR nodes, negated nodes, `vulnerable=false` fixed
  entries, and environment prerequisites split by CPE part — an application
  target, OS identities (specific first, generic fallback), and hardware;
* a criteria never matches a target of the wrong part, so "vulnerable on
  Windows" never fires on Linux, and an unknown environment prerequisite
  fails closed;
* CPE deprecation is resolved through `deprecatedBy` chains.

Evaluation outcomes map to the existing finding states:

| Evidence | State |
|---|---|
| deterministic mapping + satisfied vulnerable configuration | `confirmed_applicability` (version correlation) |
| fuzzy mapping + satisfied configuration | `potential` (low confidence) |
| matched only via `vulnerable=false` (fixed version) entries | `not_affected` |
| rejected CVE, no matching configuration | excluded (counted, not reported) |
| no mapping possible | unrecognized — visible coverage gap, never "secure" |

An authoritative vendor advisory (`apps/vendor_advisories.json`, data not
code) overrides NVD when they conflict, and supplies the advisory URL and
fixed version for remediation. If no fixed version exists anywhere, the
remediation says so instead of inventing one.

## 6. Coverage is never silent

Every report carries `metadata.coverage.apps`: discovered / normalized /
mapped / evaluated / skipped / unrecognized applications, candidate CVEs,
confirmed and potential matches, excluded CVEs, errors, NVD dataset freshness
and assessment duration. Rules:

* zero detected vulnerabilities is never reported as "zero evaluated" — the
  coverage block and dashboard say exactly what was assessed;
* applications without NVD intelligence ("never synchronized") produce no
  findings **and** an explicit "inventoried but NOT evaluated" limitation;
* a stale NVD dataset (over 30 days) is flagged on every affected finding
  set;
* unrecognized software is listed by name in the limitations.

## 7. Findings, remediation and lifecycle

Application findings carry the full evidence chain: inventory record with
source and publisher, the normalization decision and method, every matched
CPE criteria, the evaluated version range, the NVD advisory URL, and the
vendor advisory where one exists. They flow through the same enrichment
(KEV/EPSS/CVSS), risk scoring, deduplication and stable identity as every
other finding.

Remediation groups desktop-application findings per **(asset, product)** —
one software upgrade is one remediation unit and one ticket, regardless of
how many CVEs it closes. The group shows the CVE count, the highest severity,
the KEV count and the highest fixed version; expanding it lists every CVE.
Individual CVE records are preserved for reporting and audits.

Lifecycle is the existing remediation state machine: detected → assigned →
fixed → rescan → pending verification → verified resolved. A reappearing
vulnerability reopens the item and records the history; an endpoint that goes
silent, a failed inventory, or unavailable intelligence never resolves
anything — only a verifying rescan does.

## 8. API and dashboard

* `/api/overview` — separate application vs OS finding counts, aggregated
  application coverage, and an explicit "applications not assessed" signal
  when NVD intelligence is missing;
* `/api/vulnerabilities?category=os|application|service` — category filter
  plus category facets;
* `/api/assets/{host}` — application coverage block and per-package
  publisher/scope/product-id/evidence fields;
* `/api/feeds` — NVD CVE and dictionary freshness alongside KEV/EPSS;
* the dashboard shows an application-assessment card on the overview, a
  category filter on the findings list, an application coverage panel on the
  asset page, and a findings-per-package column in the software inventory
  that jumps straight to that application's vulnerabilities.

## 9. Performance

Measured on the CI-equivalent baseline (3 runs, `-benchtime 3x`):

| Scenario | Time | Allocations |
|---|---|---|
| 10 applications × 100 candidate CVEs (all matching) | ~700 ms | ~285 MB |
| 50 applications × 200 candidate CVEs (all matching) | ~4.6 s | ~3 GB |

These are adversarial cases where *every* candidate CVE matches; real scans
match a handful of CVEs per application. The dominating cost is evidence
construction and the evaluation-cache write per (product, version, CVE).
Reusable correlation results are memoised in memory per scan and persisted in
`nvd_eval_cache`, so identical (product, version) pairs are evaluated once
and rescans reuse verdicts; the cache is invalidated per-CVE when the dataset
updates. Candidate CVEs are found through the indexed `nvd_cpe_matches`
(vendor, product) columns, so correlation never scans the CVE table.

## 10. Limits (stated, not hidden)

* NVD only describes upstream versions. For applications this is correct
  (the vendor's own build); distribution packages continue to be assessed
  exclusively by the distribution engine, and Windows OS updates by the MSRC
  engine.
* Application findings are version-correlation evidence. They do not prove a
  vulnerable code path is reachable — KEV/EPSS describe exploitation, and
  `ask` explains the difference.
* The endpoint-side NVD dataset is bounded by disk: a server deployment
  should host the full dataset; endpoints can bound the initial sync window.
* RPM-based container images and CycloneDX XML are still gaps (unchanged).
* CPE `update`/`edition` ordering semantics inside version ranges are not
  applied beyond exact component matching — ranges constrain the `version`
  attribute, as NVD publishes them.

## 11. Windows 11 validation procedure (reproducible)

The automated suite replays a real Windows 11 inventory fixture end to end
(`internal/vuln/scan/apps_e2e_test.go`). To validate on a real Windows 11 VM:

1. snapshot the VM; note the Windows build (fully patched is fine — the OS is
   not the target);
2. install a known-vulnerable application build from a trusted source, e.g.
   Google Chrome 120.0.6099.109 (check
   https://chromereleases.googleblog.com/ for the advisory);
3. run `clanker-guard-agent scan --local`; confirm CVE-2024-0519 (and the
   other CVEs fixed by 120.0.6099.224) appear as `confirmed_applicability`
   with matched CPE evidence, and that the report shows 1 evaluated
   application;
4. upgrade Chrome to a build ≥ 120.0.6099.224 and rescan: the findings must
   disappear from the new report, the delta must list them as resolved, and
   unrelated findings must be unchanged;
5. restore the snapshot and repeat to demonstrate reproducibility.

Do not exploit the vulnerabilities; keep the intentionally vulnerable VM
isolated from production networks and untrusted content.

To validate **OS** patch detection separately, use a Windows 11 VM at an
earlier security patch level and run the same lifecycle with a Windows
security update: before → missing-update findings (MSRC), after → clean with
the "no missing security updates" note.

## 12. Operational notes

* `feeds update` treats each source independently: a KEV/EPSS failure does
  not block MSRC or NVD, and an NVD failure leaves the last known dataset in
  place (recorded as failed in the sync history).
* The dashboard intelligence view shows NVD freshness and staleness; a scan
  with a stale dataset flags it in the report.
* Everything above is covered by unit, integration and negative tests
  (`go test ./internal/vuln/...`); the suite makes no network calls.

---

## 13. Intelligence synchronization monitoring (API contract)

The dashboard's Intelligence tab shows the real state of every intelligence
source, live. This is the contract behind it.

### Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /api/intel/sync` | Unified per-source status, counts and assessment readiness (read-only users allowed) |
| `GET /api/intel/sync/history?source=&outcome=&limit=` | Consolidated synchronization history |
| `POST /api/intel/sync/{source}` | Start one source (kev, epss, nvd, msrc); 202 accepted, 409 if already running (admin) |
| `POST /api/intel/sync/{source}/cancel` | Cancel a running synchronization (admin) |
| `POST /api/feeds/update` | "Update intelligence" — runs kev, epss, nvd and msrc sequentially through the same registry |

### Status contract

Each source reports: source id, name, plain-English description, which
assessment types depend on it, state, stage, progress percent (-1 = unknown),
bytes downloaded / expected (0 = unknown), records processed / expected,
job id, trigger (manual | scheduled) and actor, start/update/last-attempt/
last-success timestamps (UTC), sanitized last error, freshness
(current | approaching | stale | never | n_a), dataset record count and
availability, and the next scheduled check.

### States

`not_initialized, queued, connecting, downloading, validating, processing,
importing, indexing, finalizing, up_to_date, stale, failed, cancelled`.
A source can be downloading while its existing dataset stays valid — activity
and freshness are reported separately, and a failed sync never hides the last
known dataset (it stays available, marked with its actual age).

### Freshness policies

KEV: current < 5 days, approaching < 7, stale ≥ 7. EPSS: current < 2 days,
approaching < 3, stale ≥ 3. NVD: current < 14 days, approaching < 30, stale ≥
30. MSRC: current < 12 h, approaching < 24 h, stale ≥ 24 h (scans re-import
MSRC on demand at the same threshold). OSV: fetched per assessment; the
server reports what is cached and never claims to mirror the dataset.

### Progress

All progress values come from the transfers themselves: bytes are counted
while response bodies are read, records while pages are parsed, and
percentages only when an expected total is known. Unknown totals render as
indeterminate. Stalled jobs (a running history row older than 12 h) are
reaped as failed, so a killed worker never leaves a source stuck on
"running" — and duplicate starts are refused while a job is active.
