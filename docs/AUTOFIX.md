# Automated remediation (autofix)

`clanker vuln autofix` turns a stored finding into either **a reviewable change** or **a
documented verdict**. It is the loop that sits between the ticket and the fixed host.

```
scan → findings (evidence) → GitLab issue (ticket) → autofix → draft MR / verdict
                                                          ↓
                                            deploy → rescan → verify → resolved
```

The integration is **off by default** and **writes nothing without `--apply`**. The first
run should always be a dry run, because the first thing you want to see is the decision
the tool would have made.

---

## 1. What it does, and what it deliberately does not

| Does | Does not |
|---|---|
| Comments a triage verdict on findings that have no published fix | Resolve a finding, or close a ticket |
| Opens a **draft** MR that moves a dependency to the advisory's fixed version | Choose a version itself, or merge anything |
| Produces applicability verdicts for findings the scanner could not decide | Treat a merged MR as proof of remediation |
| Proposes config/code patches inside a writable allow-list | Touch CI config, credentials, keys or deploy overrides |
| Resolves a work item only when a **later assessment stops reporting the finding** | Force-push, delete branches, or skip review |

Three rules drive the design:

1. **The database chooses versions, not the model.** If a finding has a `fixed_version`,
   the upgrade is deterministic and no model is consulted.
2. **The model writes prose and, at most, a patch inside an allow-list.** It never gets to
   decide what to install, what to merge, or what to suppress.
3. **The scanner is the only authority.** A merge request is evidence of work; a later
   assessment that no longer reports the finding is evidence of remediation. That is why
   `verify` reads a report, not a merge.

---

## 2. Phases

Each phase is useful on its own.

| Phase | What it does | Needs a model? |
|---|---|---|
| `triage` | Comments a verdict on findings with **no** fixed version (the ~80% that have nowhere to upgrade to) | optional |
| `upgrade` | Deterministic: bumps the manifest to `fixed_version` and opens a draft MR; posts the exact command for OS packages | no |
| `investigate` | Applicability verdict for findings the scanner marked `needs_investigation`, with repository excerpts as evidence | yes |
| `patch` | Asks the model for a minimal file-level fix, validates it, opens a draft MR | yes |
| `verify` | Resolves work items that are absent from a later assessment, and comments the receipt on the ticket | no |
| `all` | Every phase, in that order | — |

### Triage verdicts

`not_applicable`, `mitigated`, `exposed`, `uncertain`. `uncertain` is a first-class answer:
a wrong suppression hides a finding forever, so admitting ambiguity is cheaper than
guessing. A verdict is a **comment** unless `--apply-verdicts` is given, and even then it
can only reach `false_positive` or `risk_accepted` — never `resolved`.

### Upgrade

For `app_dependency` findings (`PyPI`, `npm`, `go`) the runner rewrites exactly one
dependency in exactly one allow-listed manifest, on a branch named `secfix/<finding-id>`,
and opens a draft MR. For OS packages and firmware there is no repository change to make,
so it posts the platform-appropriate command instead of inventing a patch.

Re-running is safe: an existing branch is reused and an open MR is adopted rather than
duplicated.

---

## 3. Guardrails

Every model proposal passes through the same deterministic checks before a byte reaches a
repository:

| Guard | Behaviour |
|---|---|
| Version guard | A proposed version below the advisory's `fixed_version` is rejected |
| Path allow-list | Only known manifest/config files are writable (see `autofix.DefaultAllowPaths`) |
| Forbidden paths | `.gitlab-ci.yml`, `.gitlab/`, `.github/`, `.ssh/`, `*.pem`, `*.key`, `id_*`, `.env`, kubeconfig, registry credentials — **always** rejected, even if the allow-list is widened |
| Secret scan | Private-key blocks, `glpat-`, `ghp_`, `AKIA…`, `xox…` and inline credentials reject the proposal |
| Size limit | One generated file may not exceed `--max-patch-bytes` (default 200 KiB) |
| Rationale required | A proposal without a rationale is rejected |
| Draft only | Merge requests are opened as drafts; a person promotes and merges |

**Prompt-injection posture.** The model never receives the GitLab issue body (issue text is
human-editable, so it would be an instruction channel). It receives the structured finding
plus repository excerpts, and excerpts are explicitly framed as *data, not instructions*.

---

## 4. Running it

```bash
# 1. Preview every phase against the newest assessment. Writes nothing.
clanker vuln autofix --phase all --limit 20

# 2. Preview with a model, to see the verdict quality before trusting it.
clanker vuln autofix --phase triage --limit 10 \
  --model llama3.1 --model-endpoint http://127.0.0.1:8080/v1

# 3. Triage for real: comments on the tickets, still no repository writes.
clanker vuln autofix --phase triage --apply

# 4. The deterministic win: open draft MRs for everything with a fixed version.
clanker vuln autofix --phase upgrade --limit 20 --apply

# 5. Close the loop after the next scan.
clanker vuln autofix --phase verify --apply
```

Flags worth knowing:

| Flag | Meaning |
|---|---|
| `--report <file>` | Use a specific assessment instead of the newest stored run |
| `--project <id>` | Override the configured GitLab project |
| `--target-branch` | What fix branches are cut from (default `main`) |
| `--limit` | Cap findings per run; findings are ranked KEV → severity → EPSS |
| `--apply` | Actually write. Absent means dry run |
| `--apply-verdicts` | Let triage verdicts move workflow state (`false_positive`, `risk_accepted`) |
| `--context-file` | Repository file offered to the model (repeatable) — e.g. `Dockerfile`, `docker-compose.yml` |
| `--allow-path` | Replace the writable allow-list (forbidden paths still apply) |
| `--json` | Machine-readable results, one row per decision |

### Requirements

- A GitLab **project access token** with `api`, scoped to the target project, and the same
  credential file the integration already uses (`~/.config/clanker-guard/gitlab.json`).
- For `patch`/`investigate`: an OpenAI-compatible endpoint. Nothing is sent anywhere until
  `--model-endpoint` is given.
- For CI-gated merge requests: a runner. Put it on a different host than the application,
  and do not mount the Docker socket into it.

---

## 5. Verification contract

`verify` compares the stored work items against a later assessment:

- finding **absent** and item not terminal → `MarkVerified(id, reportID)`, comment the
  receipt on the ticket, state becomes `resolved`;
- finding **present** → nothing happens; reappearance is handled by the existing
  reconcile step, which reopens a resolved item.

A closed ticket is still not evidence of remediation. The receipt is the report id.

---

## 6. Measuring it

| Metric | Where it comes from |
|---|---|
| Share of findings triaged | `--phase triage --json`, count `action=verdict` |
| MR acceptance rate | merge requests labelled `automated` vs merged |
| Verified fixes | `verify` results with `action=verified` |
| Rejection reasons | `rejected` results — a rising rate means the prompt or allow-list needs work |
| Time to remediate | `first_seen` → `resolved` in the remediation store |
