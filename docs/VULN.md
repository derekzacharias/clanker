# Clanker Guard — vulnerability assessment subsystem

`clanker vuln` is a separate subsystem inside the Clanker CLI. It is **not**
`clanker scan` (cost analysis) and **not** `clanker security` (HTTP/API posture
review). Those commands are untouched.

Clanker Guard answers one question with evidence: *which installed software has
a vulnerability that actually applies to this exact build?*

```bash
clanker vuln scan --local                       # assess this endpoint
clanker vuln feeds update --with-osv            # cache KEV + EPSS + OSV advisories
clanker vuln report --format markdown           # re-render the last assessment
clanker vuln ask "what should I patch first?"   # grounded, deterministic answers
```

Standalone agent (no cloud, no privileges; enrolling it installs a background service):

```bash
clanker-guard-agent scan --local --format json --output findings.json
```

---

## 1. Why this exists (and what it refuses to do)

Most open-source scanners stop at "a CVE mentions this package name". That
produces two failure modes that Clanker Guard is built to avoid:

| Failure mode | What Clanker Guard does instead |
|---|---|
| Upstream version range applied to a distribution build that has the fix backported → false positive | Resolves applicability from the **distribution's own** affected-version data; downgrades to `probable` and explains the backport caveat when only upstream data exists |
| Third-party build (NodeSource/PPA/COPR) resolved by distribution enumeration → false negative | Detects foreign build markers and returns `needs_investigation` with the reason |
| "No findings" presented as "secure" | Reports coverage, skipped checks, feed freshness and limitations on every run |
| A CVE implies exploitability | Exploitability is tracked separately (KEV, EPSS) and never inferred from CVSS |

Non-goals are explicit: no exploitation, no credential attacks, no privilege
escalation, no evasion, no lateral movement, no denial-of-service testing.

---

## 2. Pipeline

```text
AUTHORIZED ASSET SCOPE  ──► (network mode: gated, see §9)
        │
        ▼
ASSET DISCOVERY          internal/vuln/inventory  (os-release, dpkg/rpm/apk)
        │
        ▼
SOFTWARE INVENTORY       internal/vuln/inventory  (pip/npm/gem/brew/registry)
        │
        ▼
PURL / SPECIES IDENTITY  internal/vuln/pkgurl     (purl, CPE, name normalisation)
        │
        ▼
PUBLIC INTELLIGENCE      internal/vuln/intel      (OSV, CISA KEV, FIRST EPSS, NVD)
        │
        ▼
APPLICABILITY            internal/vuln/assess     (ranges, enumerations, backports)
        │
        ▼
CONFIDENCE + EVIDENCE    internal/vuln/assess     (state machine, reasons to change)
        │
        ▼
RISK PRIORITISATION      internal/vuln/assess     (KEV/EPSS/severity/exposure)
        │
        ▼
REPORT                   internal/vuln/report     (JSON, Markdown, SARIF, HTML)
        │
        ▼
HISTORY / DELTA          internal/vuln/intel      (SQLite runs, new vs resolved)
```

Each stage has its own package, structured input/output, and tests. A stage that
cannot run records a skipped check rather than silently contributing nothing.

### Directory layout

```text
internal/vuln/
  model/       shared types: packages, findings, applicability, coverage, scope
  version/     Debian, RPM, PEP 440, semver and Maven comparators (+ tests)
  pkgurl/      package URL + CPE parsing, ecosystem mapping, name normalisation
  inventory/   collectors: os-release, dpkg status, rpm, apk, pip metadata,
               npm, gem, brew, Windows registry (+ fixture tests)
  intel/       OSV client, KEV/EPSS fetchers, SQLite cache, CVSS scoring
  assess/      applicability engine, confidence rules, risk model
  report/      JSON / Markdown / SARIF / HTML renderers, summary, exit codes
  scope/       authorisation file parsing and the network-scan gate
  scan/        orchestration shared by the CLI and the agent
cmd/vuln.go                  `clanker vuln ...`
cmd/clanker-guard-agent/     standalone agent binary
scripts/install-agent.sh     verified installer (Linux/macOS)
scripts/install-agent.ps1    verified installer (Windows)
scripts/uninstall-agent.sh   removal
scripts/build-agent-release.sh  cross-platform artifacts + SHA-256 manifests
```

---

## 3. Accuracy rules (the part that matters)

### 3.1 Version semantics are ecosystem-specific

`internal/vuln/version` implements the real algorithms:

| Ecosystem | Algorithm | Example |
|---|---|---|
| Debian / Ubuntu | `dpkg` version comparison (`[epoch:]upstream[-revision]`, `~` ordering) | `3.0.13-0ubuntu3.5` > `3.0.13-0ubuntu3.4` |
| RHEL / Rocky / Alma / Fedora / SUSE | `rpmvercmp` with epoch split before release | `1:2.34-100.el9` > `2.34-99.el9` |
| PyPI | PEP 440 (epoch, release, pre, post, dev ordering) | `1.0rc1 < 1.0 < 1.0.post1` |
| npm / Go / crates.io | semver 2.0 with prerelease precedence | `1.0.0-beta.2 < 1.0.0-beta.11` |
| Maven | ComparableVersion qualifier ordering | `1.0-rc1 < 1.0` |
| anything else | numeric/alpha token comparison | reported as lower confidence |

String comparison is never used as a fallback for a version decision: if a
comparator cannot parse the values, the finding becomes `needs_investigation`
with the parse error attached.

### 3.2 Distribution data is authoritative, upstream data is a hint

Distribution advisories (Ubuntu/Debian/Alpine/Red Hat/Rocky/Alma/Fedora) speak
the installed build's version scheme and are matched first:

* **binary view** — Ubuntu records enumerate affected binary versions
  (`libssl3t64 3.0.13-0ubuntu3.6`); the installed dpkg version is compared with
  those.
* **source view** — when the installed package name equals the advisory's source
  package, the affected *source* version enumeration is used.
* **bounded ranges** — `introduced` + `fixed` / `last_affected` are applied with
  the ecosystem comparator.
* **open-ended ranges** — Ubuntu OSV records publish `{introduced: "0"}` with no
  fixed version. Treating that as "everything is affected" is the single biggest
  source of Linux false positives, so Clanker Guard ignores the unbounded range
  and decides from the vendor enumeration instead (`upstream_matching_over_inclusive`
  evidence is recorded when OSV's own matcher disagreed).

If an advisory only provides upstream ranges and the installed package carries a
distribution revision, the finding is downgraded to **probable** with
`vendor_backport_caveat` evidence explaining that the distribution may have
backported the fix.

### 3.3 Third-party builds are not resolved by vendor enumeration

A NodeSource/PPA/COPR package (or a snap transition stub) is not built by the
distribution, so "newer than the last enumerated affected build" proves nothing.
These become `needs_investigation` with a `foreign_build` evidence entry. This
rule was added after it produced a real false negative on a live host
(`nodejs 22.23.5-1nodesource1`).

### 3.4 Finding states

| State | Meaning |
|---|---|
| `confirmed_applicability` | Authoritative version/package evidence shows the advisory applies |
| `validated_behavior` | A safe behaviour-specific check observed the condition (Phase 3+) |
| `probable` | Strong evidence, at least one prerequisite unverified (e.g. backport) |
| `potential` | Only a version/fingerprint match, with unresolved uncertainty |
| `not_affected` | Authoritative evidence shows the condition does not apply |
| `needs_investigation` | Missing, incomplete or conflicting evidence |

Every finding carries `explanation`, `evidence[]`, `confidence_increase_evidence`
and `confidence_reduction_evidence`, so a reviewer can see exactly what to check
to move it.

### 3.5 Risk model

A transparent additive score, capped at 100, with every contribution recorded in
`risk_factors`:

| Factor | Default weight |
|---|---|
| CISA KEV membership | 30 |
| EPSS probability | 20 × EPSS |
| Severity critical / high / medium / low / unknown | 20 / 15 / 8 / 3 / 2 |
| Internet exposure | 10 |
| Asset criticality (0..1) | 10 × criticality |
| Confidence high / medium | 10 / 5 |
| Patch available | 5 |

Weights live in `assess.RiskWeights`; the report states each factor so a reader
can recompute the number. EPSS is never treated as proof of exploitation, and
CVSS is never treated as a probability.

---

## 4. Intelligence sources and their limits

| Source | Used for | Notes / limits |
|---|---|---|
| OSV (`api.osv.dev`) | distro + ecosystem advisories, affected versions | distributions publish different data shapes (see §3.2); coverage varies per ecosystem |
| OSV record detail | aliases, CVSS vectors, references | fetched per advisory, cached in SQLite |
| CISA KEV | known-exploited flag, date added, ransomware use | catalog is small; absence is not evidence of safety |
| FIRST EPSS | exploitation probability + percentile | model version and score date are stored with each score |
| NVD API 2.0 | CVE metadata and CVSS | client exists; used only for enrichment, never as the sole applicability source |
| GitHub advisories | package advisories, aliases, patched versions | delivered through OSV/GHSA records |

Rules enforced in code:

* A failed API call is an **error**, never "no vulnerabilities". `intel` returns
  errors, `scan` records them in `metadata.errors` and marks the run incomplete
  (exit code 4).
* Offline mode uses only cached advisories; an empty cache with `--offline`
  produces an explicit warning and an incomplete assessment, not a clean result.
* Feeds are cached incrementally (per-package advisory lookups plus KEV/EPSS
  snapshots), never as a full NVD download per scan.

---

## 5. What the agent collects (and what it never touches)

Collected, unprivileged, read-only:

* `/etc/os-release`, kernel release, architecture, hostname, container marker.
* `dpkg` status database / `rpm -qa` / `apk` installed database.
* Python distribution metadata (`*.dist-info/METADATA`, `*.egg-info/PKG-INFO`).
* npm global packages (`npm ls -g --json`), Ruby gems (`gem list --local`).
* Homebrew formulae (macOS) and installed-application registry keys (Windows).
* Package provenance needed for backport reasoning (source package, arch,
  revision, vendor).

Never collected: file contents outside package metadata, credentials, tokens,
browser data, documents, environment variables, process arguments, network
traffic.

Network destinations contacted: `api.osv.dev` (scan, unless `--offline`),
`www.cisa.gov` and `epss.cyentia.com` (`feeds update`), and — only when the agent
was enrolled with `enroll --server` — the Clanker Guard server you named, which
receives the finished report and the agent's status. There is no third-party
telemetry, no remote command channel and no auto-update: the server can accept a
report, it cannot ask the endpoint to do anything.

### Agent transport, identity and recovery

- **Transport**: HTTPS is required for enrollment, check-in and report upload.
  Plain HTTP is refused unless the host is loopback or the operator passes
  `--allow-insecure-http` (recorded in the config, re-checked on every run).
- **Identity**: enrollment binds an agent to a hostname *and* a credential. A
  hostname that is already enrolled can only be re-attached by presenting that
  credential (`409 identity_conflict` otherwise), so a reinstall cannot seize an
  existing identity. Credentials are stored as SHA-256 hashes; the plaintext is
  never retrievable.
- **Reinstall**: the CLI presents the credential from the agent config
  automatically, so a normal reinstall keeps its identity, findings history and
  task queue.
- **Recovery**: if the credential is lost, revoke the agent in the dashboard
  (`POST /api/agents/{id}/revoke`); revocation takes effect on the next request
  and re-enrollment then creates a new agent id.
- **Enrollment tokens**: minted on demand in Settings → Agents, single use, expire
  after 24 h (configurable up to 30 days), stored only as SHA-256. A used or
  expired token is refused with a specific reason.
- **Replay protection**: each report carries `X-Guard-Submission-Id`,
  `X-Guard-Sequence` (monotonic per agent, persisted) and
  `X-Guard-Payload-SHA256`. A lower sequence is refused as a replay, a digest
  mismatch is refused before parsing, and retries of the newest submission stay
  idempotent by report id.
- **Task leases**: a claimed scan must report back within 30 minutes; otherwise it
  is requeued (up to 3 attempts) and then failed with a reason, so a killed agent
  cannot wedge the queue.
- **Offline queue**: a report that cannot be delivered is spooled to
  `<config dir>/queue` (0600, 25 reports / 64 MB, newest kept), retried in order on
  the next run, and deleted only after the server acknowledges it.
- **Lifecycle**: `service install|uninstall|start|stop|restart|status` and `doctor`
  (binary, enrollment, transport, server, credential, service, cache, queue).
- **Signed releases**: `SHA256SUMS.sig` (Ed25519) is verified by the installer
  against a pinned public key; a tampered artifact or manifest is refused.
- **Still not implemented**: mTLS with per-agent certificates, OS keychain
  credential storage (DPAPI/Keychain), centralised intelligence snapshots per
  assessment, and self-update (`update`).

### Software asset exports

A findings report answers "what can hurt me". The inventory exports answer "what
is installed", which is where an asset register, CMDB import or licence review
starts:

```bash
# one host, from a stored report
clanker vuln serve ...   # then: GET /api/reports/<id>/export?format=csv
                         #       GET /api/reports/<id>/export?format=cyclonedx

# the whole environment (newest report per host), no auth bypass needed
GET /api/software/export?format=csv
GET /api/software/export?format=cyclonedx&host=<host>
```

CSV columns: `host, os, os_version, kernel, arch, ecosystem, manager, package,
version, release, vendor, origin, purl, source, privileges_required,
known_findings, max_severity, report_id, scanned_at`. `known_findings` and
`max_severity` are derived from the same report by matching
package+version+ecosystem — they show exposure, they are not an applicability
verdict. CycloneDX is 1.5, one component per package, serial number derived from
the content so repeated exports diff cleanly.

Installation: enrolling installs a background service (systemd user unit /
LaunchAgent / logon task) so the endpoint stays reachable; `--no-service` opts out
and nothing is installed beyond the binary. There is no auto-update. Artifacts are
installed only after SHA-256 verification. Published builds live at
`github.com/derekzacharias/clanker-guard-agent/releases`; the dashboard shows the
matching commands when `CLANKER_GUARD_RELEASE_BASE` points at a release
directory. Removal:

```bash
clanker-guard-agent uninstall --yes     # removes binary + cache
./scripts/uninstall-agent.sh --yes      # or from a checkout
```

---

## 6. Command reference

```bash
# endpoint assessment
clanker vuln scan --local [--offline] [--format json|markdown|sarif|html]
                        [--output FILE|-] [--fail-on critical|high|medium|low]
                        [--fail-on-kev] [--include-not-affected]
                        [--asset-criticality 0..1] [--no-python] [--no-npm] [--no-ruby]
                        [--cache FILE] [--quiet]

# intelligence
clanker vuln feeds update [--with-osv]
clanker vuln feeds status

# review
clanker vuln inventory [--format json|markdown]
clanker vuln report [--format ...] [--host HOST] [--output FILE|-]
clanker vuln ask "which findings are in CISA KEV?"
clanker vuln ask "explain CVE-2023-48795"

# authorisation (network mode)
clanker vuln scope validate scope.yaml
clanker vuln scan --scope scope.yaml --target 192.168.20.10 --i-authorize  # refused until Phase 3

# agent
clanker-guard-agent scan --local --format json --output findings.json
clanker-guard-agent feeds update --with-osv
clanker-guard-agent ask "what should I patch first?"
clanker-guard-agent uninstall --yes
```

**Exit codes:** `0` completed with nothing above policy · `2` findings above the
policy threshold · `3` configuration error · `4` incomplete assessment.

---

## 7. Report contract

`schema_version: "1.0"` — see `internal/vuln/report/report_test.go` for the
enforced field list. Each finding carries:

```json
{
  "finding_id": "FINDING-0001",
  "asset": "host",
  "product": "openssl",
  "installed_version": "3.0.11-0ubuntu3.1",
  "ecosystem": "Ubuntu:24.04:LTS",
  "vulnerability_id": "CVE-2026-0001",
  "aliases": ["CVE-2026-0001", "UBUNTU-CVE-2026-0001"],
  "source": "Ubuntu",
  "affected": "confirmed_applicability",
  "validation_status": "version_correlation",
  "confidence": "high",
  "severity": "high",
  "cvss": {"score": 7.5, "vector": "CVSS:3.1/...", "source": "Ubuntu"},
  "epss": {"score": 0.7, "percentile": 0.99},
  "cisa_kev": true,
  "kev": {"cve_id": "CVE-2026-0001", "date_added": "2026-11-01"},
  "evidence": [{"kind": "installed_version", "detail": "...", "url": "..."}],
  "vendor_advisory": {"vendor": "Ubuntu", "id": "UBUNTU-CVE-2026-0001", "url": "..."},
  "fixed_version": "3.0.13-0ubuntu3.9",
  "remediation": "Upgrade openssl to ...",
  "last_checked": "2026-11-13T12:00:00Z",
  "explanation": "why this state was chosen",
  "confidence_increase_evidence": ["..."],
  "confidence_reduction_evidence": ["..."],
  "risk_score": 41.7,
  "risk_factors": [{"name": "cisa_kev", "weight": 30, "detail": "..."}]
}
```

`metadata.coverage` records packages inspected/matched, advisories checked,
sources used, ecosystems that could not be covered, and limitations.
`metadata.feed_freshness` records KEV/EPSS sync times and staleness.
`delta` compares against the previous run for the same host.

---

## 8. Testing

```bash
go test ./internal/vuln/...        # unit + fixture + end-to-end orchestration
go vet ./internal/vuln/...
```

Coverage by area:

* version comparators — ordering tables for every ecosystem, epochs, tildes,
  prereleases, zero padding, invalid input;
* purl/CPE — round-trip and escaping, including npm scopes and CPE-escaped colons;
* inventory — dpkg/rpm/apk/pip/npm/gem/brew/registry parsing from fixtures;
  deinstalled packages excluded, epochs preserved, noisy npm output tolerated;
* intel — OSV batch/detail parsing from a real advisory fixture, CVE extraction
  from distro IDs, CVSS 3.1 base scores against known vectors, KEV/EPSS parsing,
  SQLite cache round-trip, HTTP failures surfacing as errors;
* assess — Debian ranges, Ubuntu binary views, enumeration gaps, cross-ecosystem
  rejection, backport downgrade, foreign builds, CVE dedupe, KEV/EPSS enrichment,
  risk ordering;
* report — schema fields, Markdown/SARIF/HTML rendering, exit-code policy, delta;
* scope — authorisation requirements, public-address refusal, expansion bounds;
* scan — offline end-to-end run against a fixture root with a seeded cache,
  including delta and "empty inventory is an error".

The suite makes no network calls and scans no remote systems.

---

## 9. Network assessment (implemented)

```bash
clanker vuln scan --scope scope.yaml --i-authorize
```

Safety model, enforced in code:

* `scope.yaml` requires `name`, `authorized_by`, `authorized_at`, `targets`, and
  may set `expires_at` (an expired scope is refused);
* public addresses require `allow_public_addresses: true`, expansion beyond
  `max_hosts` (default 256) is refused, and `--target` can only narrow the scope;
* a hostname is resolved exactly once and every resolved address is checked: if
  the scope lists addresses, a name must resolve inside them; a name-only scope
  authorises that name;
* discovery is ordinary `TCP connect` — no raw sockets, no privileges, no
  evasion, bounded ports/concurrency/timeouts;
* fingerprinting sends at most one benign request per service (HTTP GET with an
  honest User-Agent, TLS handshake, SSH banner read, a `PING` to Redis);
* nothing is exploited, brute-forced or fuzzed.

What it produces:

* **services** — host, port, banner, HTTP/TLS observations, product/version when
  observable, distribution-build markers;
* **configuration findings** — deprecated TLS, self-signed/expired certificates,
  unauthenticated Redis, management/data ports reachable from the assessed
  network, plaintext HTTP where HTTPS exists, version disclosure;
* **CVE findings** — NVD CPE lookup for fingerprinted products with a version.

Accuracy rule for network findings (learned the hard way, see B-015 below):

| Fingerprint | Reported as |
|---|---|
| distro build (`OpenSSH_9.6p1 Ubuntu-3ubuntu13.20`) | `needs_investigation` — distributions backport fixes; NVD only knows upstream versions |
| upstream build, version matched by CPE | `probable` — version-level evidence, not proof of reachability |
| configuration observation | `validated_behavior` — the observation is the evidence |

Offline mode makes no outbound calls: NVD is not queried and cached matches are
reused (findings are rebuilt from the cache, never silently dropped).

## 9b. Software / container assessment (implemented)

```bash
clanker vuln scan --sbom ./sbom.json          # CycloneDX, SPDX, Syft
clanker vuln scan --sbom ./package-lock.json  # npm; also requirements.txt,
                                              # go.sum, Cargo.lock,
                                              # composer.lock, Gemfile.lock
clanker vuln scan --image acme/api:1.4.0      # container image
clanker vuln sbom export --output sbom.json   # CycloneDX 1.5 export
```

* documents are parsed as data, never executed; unsupported documents are
  rejected with a clear message (at submit time in the API, not after a job);
* purls drive the ecosystem (`pkg:pypi/...`, `pkg:deb/ubuntu/...?distro=...`), so
  distribution advisories are used where they apply;
* container images are read with `docker save` (never run); both legacy and OCI
  archives are handled, including gzipped layer blobs, and dpkg/apk databases are
  parsed from the layers; RPM-based images are reported as a gap;
* components without a version are listed as gaps instead of being guessed;
* ecosystem identifiers are validated against OSV's naming before any query —
  OSV answers HTTP 200 `{}` for an unknown ecosystem, which would otherwise look
  like "no vulnerabilities" (see B-016).

---

## 10. Repository integration

* `clanker vuln` is registered in `cmd/root.go` as a separate command tree.
* `clanker scan` (cost) and `clanker security` (posture) are untouched.
* No existing package was modified except `cmd/root.go` (one `AddCommand`) and
  `main.go` (honour the documented exit codes).
* Dependencies added: none. SQLite uses `modernc.org/sqlite`, already present in
  `go.mod`; YAML uses the existing `gopkg.in/yaml.v3`.

---

## 11. Release process for the agent

```bash
./scripts/build-agent-release.sh 0.1.0        # linux/darwin/windows × amd64/arm64
# -> dist/v0.1.0/clanker-guard-agent_<os>_<arch>[.exe] + .sha256 + SHA256SUMS
```

Publish the directory as a release (tag `v0.1.0`) under
`https://github.com/bgdnvk/clanker/releases/download/v0.1.0`. The installers
default to that base URL and verify the published checksum before installing:

```bash
curl -fsSL https://github.com/bgdnvk/clanker/releases/download/v0.1.0/install-agent.sh | bash -s -- --version 0.1.0
```

Verified locally in this build: install from a release base directory, version
injection, scan execution, and refusal to install a tampered artifact
(SHA-256 mismatch → exit 3, nothing written).

---

## 11b. Continuous improvement

Analyst reviews, evidence-based verification, detection-policy proposals,
fixture evaluation, approval/rollback and quality metrics live in
`internal/vuln/improve` and are documented in [IMPROVEMENT.md](IMPROVEMENT.md).
Deployed rules are consumed by this scanner through `improve.ActivePolicy`, and
reports record the non-default decisions in `metadata.detection_policy`.

## 11b. Defects found while implementing these modes

* **B-015** — the first live network scan reported 28 *confirmed* CVEs for a
  patched Ubuntu OpenSSH build, because NVD matched the upstream version. Fixed
  by detecting distribution packaging in the fingerprint and reporting those as
  `needs_investigation` with `distro_build` evidence; upstream builds stay
  `probable`.
* **B-016** — Alpine's ecosystem was emitted as `Alpine:3.21.3`; OSV's format is
  `Alpine:v3.21` and it returns HTTP 200 `{}` for unknown ecosystems, so a
  malformed identifier silently produced "no vulnerabilities". Fixed the format
  and added local ecosystem validation: unknown identifiers are reported as
  coverage gaps and never queried.
* **B-017** — the container scanner only read the outer `docker save` archive, so
  every real image reported zero components (layers are nested gzipped blobs).
  Fixed with nested-layer traversal, including `/usr/lib/os-release`.

## 12. Roadmap and known gaps

Work that is planned but not implemented — including remediation ownership,
ticketing and the automation design — is tracked in
[docs/BACKLOG.md](BACKLOG.md).

Implemented (Phase 1 + much of Phase 2):

* endpoint inventory (Linux dpkg/rpm/apk, Python, npm, Ruby, macOS brew, Windows
  registry) with explicit skipped checks;
* OSV correlation with ecosystem-aware version semantics;
* vendor-aware applicability: binary/view enumerations, bounded ranges,
  backport caveats, foreign-build handling;
* CISA KEV + EPSS enrichment, CVSS 3.1 base scoring, transparent risk model;
* confidence/evidence model with reasons to raise or lower each finding;
* JSON/Markdown/SARIF/HTML reports, exit codes, run history and deltas;
* deterministic `ask` grounded in stored findings (works with no LLM);
* verified installers, uninstall, offline mode;
* tests for every stage plus an offline end-to-end test.

Not implemented yet — reported explicitly rather than approximated:

1. **Network assessment** — shipped for TCP discovery, fingerprinting, TLS/SSH
   analysis and NVD correlation. Still missing: UDP, asset persistence across
   scopes, and vetted Nuclei-style signature templates for behaviour-specific
   validation.
2. **Vendor advisory depth (Phase 2 remainder)** — Debian Security Tracker /
   Ubuntu CVE tracker / Red Hat OVAL parsing for explicit patch status instead of
   inference from enumerations; unattended-upgrade state; Windows Update and
   macOS system-patch inventory.
3. **Authenticated endpoint checks (Method C)** — local package release
   verification beyond metadata (e.g. `rpm -V`/`dpkg --verify` baselines).
4. **LLM-assisted investigation (Phase 4)** — `ask` is deterministic today; the
   Clanker agent workers (discovery/inventory/CVE/validation/risk/remediation/
   reporting) are not wired into `internal/agent`.
5. **Managed endpoint communications (Phase 5)** — shipped in the minimal form:
   per-agent enrollment, status check-ins, report upload and **on-demand scans**
   (`New scan → Endpoint Scan`). `clanker-guard-agent watch` holds a claim request
   open, so an available endpoint starts immediately and its presence doubles as
   the reachability signal the dashboard shows; a request for an unreachable
   endpoint is queued, can be withdrawn, and runs when it returns. Not yet: mutual
   TLS, arbitrary server-initiated commands, rescan scheduling, offline report
   buffering, and a timeout that reclaims a task left `running` by a killed agent.
   `install-agent.sh --watch` enrolls and keeps the endpoint available in one step.
6. **SBOM ingestion** — shipped (CycloneDX/SPDX/Syft + five manifest formats);
   CycloneDX 1.5 export shipped. Not yet: CycloneDX XML/protobuf, SPDX export.
7. **Container image inventory** — shipped via `docker save` for dpkg/apk images;
   not yet: RPM-based images, containerd/remote registries, layer caching.
8. **Scheduled rescans and upstream feed diffing** — history/delta exist; no cron.
