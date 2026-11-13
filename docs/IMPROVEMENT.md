# Clanker Adaptive Intelligence Engine (CAIE)

`clanker vuln` learns from analyst reviews under human control. This document
describes what the loop actually does, what it refuses to do, and how to verify
that a change is real.

```text
scan → findings + evidence → analyst review → evidence-based verification
     → recurring-pattern analysis → candidate rule + fixtures
     → sandboxed evaluation against the shipped baseline
     → human approval → versioned deployment → monitoring → rollback
```

Two properties matter more than the feature list:

1. **Feedback is not proof.** An analyst's verdict is recorded, then checked
   against advisory data. Only evidence-backed reviews change a classification.
2. **Only rules change, never code.** A proposal is a versioned detection
   policy evaluated by the same matcher production uses. No agent writes source
   code, opens a pull request, or deploys anything by itself.

---

## 1. Where the seams are

| Concern | Package | Notes |
|---|---|---|
| Detection decisions the loop may tune | `internal/vuln/assess` (`Policy`) | shipped defaults; validated on load |
| Shared decision path | `assess.Classify` | matching + backport policy; used by scans *and* tests |
| Feedback, verification, proposals, rules | `internal/vuln/improve` | own tables in the scanner's SQLite file |
| HTTP surface | `internal/vuln/api` | feedback, improvements, quality, ask |
| CLI | `cmd/vuln.go` | `vuln feedback`, `vuln improve …`, `vuln quality` |
| UI | `web/src/pages/Improvement.tsx`, `FeedbackPanel.tsx` | one secondary page under Settings |

`assess.Policy` currently exposes five decisions, each tied to a real failure
mode observed on a live host:

| Field | Default | What it controls |
|---|---|---|
| `backport_downgrade` | `true` | upstream advisory matched against a distro build is downgraded |
| `backport_outcome` | `probable` | `needs_investigation` makes backport cases review-first |
| `unlisted_build_outcome` | `not_affected` | build newer than the vendor enumeration |
| `foreign_build_outcome` | `needs_investigation` | NodeSource/PPA/COPR rebuilds |
| `snap_stub_unresolved` | `false` | snap transition wrappers carry no application code |

`assess.ParsePolicy` starts from the defaults and overlays a stored payload, so a
partial rule can never silently disable backport awareness. Invalid values are
rejected at parse time.

---

## 2. Reviewing a finding

Actions on every finding (API `POST /api/vulnerabilities/{id}/feedback`, CLI
`clanker vuln feedback <id>`):

`confirmed` · `false_positive` · `needs_investigation` · `remediated` ·
`request_verification`

A false positive requires a structured reason:

| Reason | Automated verification |
|---|---|
| `vendor_patch_installed` | **Yes** — looks for a distribution advisory for the same CVE and re-runs the matcher |
| `incorrect_identification` | **Yes** — snap transition marker or third-party build marker |
| `feature_not_enabled` | No — configuration is not collected; recorded as a gap |
| `advisory_not_applicable` | No — recorded as a gap |
| `other` | No — recorded without a check |

Verification outcomes:

* **supported** — evidence confirms the claim; the finding gets an
  analyst-verified state and the classification changes;
* **contradicted** — evidence says the opposite (e.g. the vendor advisory lists
  the installed build as affected); nothing changes and the reason is recorded;
* **inconclusive** — nothing cached can decide it; nothing changes, and the gap
  becomes an improvement candidate (for example "fetch the vendor advisory").

The scanner verdict is never overwritten. Findings expose both
`affected` (scanner) and `analyst` + `effective_affected` (correction), so a
reader can always see what changed and why.

---

## 3. From reviews to proposals

`Analyze` groups verified reviews by signature and produces one proposal per
signature. It is deterministic and idempotent: re-running without new feedback
updates the same proposal instead of creating duplicates. New feedback against an
already-deployed signature creates a **follow-up** proposal, because a rule that
still misses cases is new evidence.

| Signature | Category | Proposal | Deployable |
|---|---|---|---|
| `fp:snap_stub` | detection accuracy | `snap_stub_unresolved = true` | yes |
| `fp:vendor_backport` | detection accuracy | `backport_outcome = needs_investigation` | yes |
| `fp:foreign_build` | coverage | record package provenance and match packager advisories | no — research |
| `fp:missing_vendor_data` | intelligence | fetch the vendor advisory during verification | no — research |
| `fp:configuration_evidence` | coverage | add configuration collectors | no — research |

Only proposals with a policy change can be tested and deployed. Research-only
items stay in `discovered` and are shown as such; the UI does not offer an
approval button for them.

---

## 4. Evaluation (the part that must not lie)

`improve.Evaluate(policy, fixtures)` runs the candidate policy and the shipped
policy over the labelled corpus and compares them. It is pure: no database, no
network, no filesystem.

Fixture labels are ground truth, not "what the code does":

| Label | Rule the candidate must satisfy |
|---|---|
| `affected` | a vulnerable build must not be dismissed (`not_affected`) |
| `not_affected` | a patched build must not be reported as affected |
| `unresolved` | the verdict must not be `confirmed` (data cannot resolve the build) |
| `corrected` | must equal the analyst-verified outcome exactly |

A candidate **passes** when it improves at least one case and regresses none,
relative to the shipped policy. Requiring one change to fix every known gap would
reject all incremental improvements; allowing a regression would let a rule
silently reduce detection. Metrics (precision/recall/accuracy) are reported only
for the labelled subset and always alongside the baseline.

Fixtures come from two places:

* **curated baseline** (`improve.BaselineFixtures`, 8 cases): Debian ranges,
  Ubuntu binary enumeration, unlisted builds, upstream-on-distro backports,
  third-party rebuilds, snap stub vs. a real build of the same product;
* **feedback-derived**: the reviewed finding replayed with the advisory the scan
  used, expecting the policy's target outcome.

---

## 5. Lifecycle and deployment

```text
discovered → researching → proposed → testing → awaiting_approval
                                                        │
                                          approved ─────┤
                                              │         └→ rejected
                                          deployed
                                              │
                                    monitoring → rolled_back
```

Transitions are validated against a static table (`improve.CanTransition`); every
move is written to `improvement_events` with actor and note. Guards:

* **approve** requires a passing evaluation;
* **deploy** requires `approved`, requires the policy to still pass a *fresh*
  evaluation, and writes a numbered rule row;
* **reject** requires a reason;
* **roll back** deactivates the active rule and re-activates the previous version
  (defaults if none), so behaviour returns to the last known-good state;
* every transition requires an actor.

Deployment writes `improvement_rules` (kind, version, payload, improvement id,
active flag). `scan.Run` loads the active rule through
`improve.ActivePolicy`, so the scan itself cannot diverge from what the UI
approved. Reports record the non-default decisions and the rule id in
`metadata.detection_policy`.

---

## 6. Quality metrics

`GET /api/quality` (and `clanker vuln quality`) reports:

* reviews by verdict, verification outcomes (supported / contradicted /
  inconclusive);
* **documented false-positive rate over reviewed findings** — never presented as
  population precision, and `null` until at least one review exists;
* reviewed-vs-considered ratio;
* open / deployed / rejected proposals;
* explicit caveats (fewer than five reviews is anecdotal).

There is no ground truth for unreviewed findings, so the system does not invent
one.

---

## 7. Safety properties (enforced in code)

* feedback text is stored as data and length/control-character bounded; it is
  never interpreted as instructions;
* advisory content is parsed into typed structures; no `eval`, no template
  execution, no shell interpolation of scanned values;
* a rule can only change the five documented detection knobs, validated at parse
  and deploy time;
* deployment is an explicit human action with an actor recorded; there is no
  "auto-apply" mode;
* evaluation runs in-process against fixed fixtures — no network, no customer
  data, no filesystem writes;
* rollback is one command and restores the previous rule version;
* feedback can be exported and deleted per finding (`/api/feedback/export`,
  `DELETE /api/vulnerabilities/{id}/feedback`);
* nothing leaves the host: no telemetry, no external model calls.

Autonomy is capped by construction: the system can **observe**, **recommend** and
**test**. It cannot approve or deploy itself.

---

## 8. CLI

```bash
# record a review (verified against cached advisories)
clanker vuln feedback c135f6cc9d4b8f3d --verdict false_positive \
  --reason incorrect_identification --analyst derek --note "snap stub"

# proposals
clanker vuln improve list
clanker vuln improve show IMP-71f8163c9985
clanker vuln improve analyze
clanker vuln improve evaluate IMP-71f8163c9985

# controlled release
clanker vuln improve approve IMP-71f8163c9985 --actor derek --note "9 fixtures reviewed"
clanker vuln improve deploy  IMP-71f8163c9985 --actor derek
clanker vuln improve rollback IMP-71f8163c9985 --actor derek

# quality
clanker vuln quality
```

## 9. HTTP API

```
POST   /api/vulnerabilities/{id}/feedback      recorded + verified review
GET    /api/vulnerabilities/{id}/history        review history and state
DELETE /api/vulnerabilities/{id}/feedback       delete reviews + verified state
GET    /api/improvements[?status=]              proposals with counts
GET    /api/improvements/{id}                   proposal + events + active rule
POST   /api/improvements/{id}/evaluate          re-run the fixture suite
POST   /api/improvements/{id}/transition        {to, actor, note}
GET    /api/quality                             detection-quality metrics
GET    /api/feedback/export                     portable review history
POST   /api/ask                                 also answers improvement questions
```

Ask Guard answers these deterministically from stored evidence:

* "What did you learn from my false-positive reviews?"
* "Which scanning capabilities are missing?"
* "Show me the tests supporting this proposed detection update."
* "What improvements would most reduce false positives?"

---

## 10. UI

One secondary page under **Settings → Continuous improvement**:

* quality cards with the reviewed sample size and explicit caveats;
* proposal cards: status, category, risk, affected findings, test outcome, with
  **View changes / Approve / Reject** (and Deploy / Roll back when applicable);
* a drawer with problem, proposed change, policy diff, evidence, the full fixture
  table (baseline vs candidate per case), regressions and the audit trail;
* recent reviews with whether evidence supported them;
* the Overview shows one compact line: "N detection improvement(s) available for
  review".

Finding detail gains a review panel: five actions, a reason list for false
positives, a note field, the analyst name (recorded as the actor), the
verification result, and the review history.

---

## 11. Demonstration (reproducible)

```bash
# 1. scan
clanker vuln scan --local --output before.json
#    one finding: thunderbird 2:1snap1-0ubuntu3 → confirmed (a snap stub, 41 CVEs)

# 2. review it as a false positive with a structured reason
clanker vuln feedback <stable-id> --verdict false_positive \
  --reason incorrect_identification --analyst derek
#    verification: supported — the version is a snap transition marker
#    classification: confirmed_applicability → needs_investigation
#    improvement IMP-… [awaiting_approval]

# 3. inspect the tests
clanker vuln improve show IMP-…
#    passed (9 fixtures, 2 corrected, 0 regressions)
#    snap-transition-stub: confirmed → needs_investigation
#    snap-real-build:       confirmed → confirmed   (detection preserved)

# 4. approve + deploy
clanker vuln improve approve IMP-… --actor derek
clanker vuln improve deploy  IMP-… --actor derek

# 5. rescan: the rule is in force
clanker vuln scan --local --output after.json
#    metadata.detection_policy: ["snap stub unresolved true", "deployed detection rule RULE-…"]
#    all 41 thunderbird findings are now needs_investigation, none dismissed

# 6. roll back and rescan to see the baseline return
clanker vuln improve rollback IMP-… --actor derek
```

---

## 12. Limitations and roadmap

Implemented: feedback with verification, review history, pattern analysis,
policy-based proposals, fixture evaluation, lifecycle with guards and audit trail,
versioned rule deployment, rollback, quality metrics, CLI, API, UI, tests.

Not implemented (deliberately, and reported as such):

* **automatic source-code changes or pull requests** — proposals are policy
  data, not code; there is no self-modifying mode;
* **self-service rule authoring** — a new knob requires a code change plus
  fixtures, reviewed by a human;
* **LLM-assisted research** — all analysis is deterministic; no organizational
  data is sent anywhere;
* **configuration evidence collectors** (`feature_not_enabled` claims remain
  unverifiable);
* **cross-asset deduplication of reviews** — a verified correction applies to one
  finding; it never suppresses the same CVE elsewhere;
* **learned prioritisation** — risk remains the transparent additive model; a
  learned model would need a baseline comparison before it could ship;
* **network assessment** — still Phase 3; the authorisation gate is enforced.
