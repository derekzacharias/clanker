# AI providers and issue automation

Two settings sections, one server-side hub:

- **Settings → AI & Models** — choose a provider, store its key, pick a model from the
  provider's live catalog.
- **Settings → Issue automation** — decide whether findings become GitLab issues, by hand,
  with approval, or automatically.

Nothing here is on by default. Automation starts in `manual`, which does nothing.

---

## 1. Where the pieces live

| Layer | Package | Responsibility |
|---|---|---|
| Provider catalog, credentials, discovery, inference | `internal/aihub` | The only code that knows a provider exists |
| Issue drafting and validation | `internal/vuln/issuegen` | Turns a finding into a checked issue draft |
| Mode, policy, budget, audit | `internal/vuln/automation` | Decides whether a draft becomes an issue |
| HTTP | `internal/vuln/api/ai.go` | Settings, credentials, models, preview, run, audit |
| UI | `web/src/components/AISettings.tsx`, `IssueAutomation.tsx` | Two settings panes |

Features never call a provider directly: they ask `aihub.Inference`, which takes a
`Settings` value. Adding a provider is a row in `provider.go`, not a new branch in a
feature.

## 2. Credentials

- Stored in `<config>/clanker-guard/ai/credentials.json`, **AES-256-GCM**, mode `0600`.
- The key is `master.key` (32 random bytes, mode `0600`) or `CLANKER_AI_MASTER_KEY`
  (base64, 32 bytes) so a container can avoid key material on disk.
- The API **never** returns a key. `GET /api/settings/ai` returns
  `{"configured": true, "mask": "••••1234", "source": "file"}`.
- Rotating a key is `PUT` again; deleting is `DELETE /api/settings/ai/credential?provider=…`.
- An environment credential (`CLANKER_AI_KEY_<PROVIDER>`) is reported with
  `source: "environment"` so nobody is surprised when deleting the file entry does not
  remove it.

Authentication is placed per provider (`Authorization: Bearer`, `x-api-key`, `?key=`,
Azure `api-key` + `api-version`), because assuming every provider uses a bearer token is
how integrations break.

## 3. Model discovery

`GET /api/settings/ai/models?provider=openai&refresh=1`

- Calls the provider's own listing API where one exists.
- Normalizes `data` / `models` / `value` envelopes onto one `Model` shape.
- Drops models that cannot do text work (embeddings, images, audio, moderation, rerank).
- Hides `retired` identifiers; `preview` models require the advanced toggle.
- Caches per provider for **24 h**; a list younger than that is served without a call.
- A failed refresh **keeps the last good list** and returns `stale: true` with the reason.
  An empty dropdown is worse than a labelled stale one.
- Azure has no model list: the deployment name is the model. Bedrock is listed but
  disabled — it needs SigV4 signing this build does not implement, and pretending
  otherwise would produce a confusing failure at request time.

`GET /api/settings/ai/test` runs a real one-token completion, not just a list call: a key
can list models and still be denied inference by quota, region or deployment.

## 4. Issue automation

| Mode | Behaviour |
|---|---|
| `manual` | Nothing. The engine returns no results. |
| `assisted` | Drafts are generated and returned for review. No GitLab write. |
| `auto` | Qualifying drafts become issues. Requires `{"confirm": true}` on every run. |

Policy: minimum severity, max per run (bounded at 200), extra labels, assignee, reopen
behaviour, and whether the AI writes the draft at all (`use_ai`). With `use_ai` off the
issue is built from the scan record — same facts, no prose — so a model outage cannot
stop a team from filing work.

**What is always held back**, in every mode including `auto`:

- a draft whose CVE, asset or severity disagrees with the finding;
- a draft with no remediation steps;
- a recommended command that looks destructive (`rm -rf`, `mkfs`, `dd`, `shutdown`,
  firewall disable, `chmod 777`, …) or has no validation step;
- a remediation step naming a version that is not the advisory's fixed version;
- finding text that looks like an instruction (`ignore previous instructions`, …).

Those return `action: "needs_review"` with the reasons, and never reach GitLab.

## 5. Duplicate prevention

Issues are filed through the **existing** `ticketing.Creator`, so the marker search,
recovery-after-timeout and unique index all apply. The rendered body ends with
`<!-- clanker-guard:finding:<key> -->`; a second run finds the first issue and reports
`duplicate` instead of opening another.

## 6. Audit trail

`<config>/clanker-guard/automation/audit.jsonl`, append-only, mode `0600`, one JSON object
per decision: timestamp, action, mode, finding key, CVE, asset, severity, generator,
provider, model, issue IID and URL, reason.

`GET /api/settings/automation/audit?limit=100` reads it. A corrupt line is skipped rather
than hiding the rest of the trail.

## 7. Prompt-injection posture

- The model receives **only** the projection of the finding (asset, product, version,
  advisory, severity, CVSS, KEV, fixed version, scanner explanation, evidence) and it is
  told the text is untrusted data.
- The model output is JSON-only and is validated field by field against the finding.
- The model cannot change thresholds, destinations, labels or permissions: those are read
  from `config.json` by the engine, never from a completion.
- Generated commands are text on a ticket. Nothing in this feature executes them.

## 8. Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/settings/ai` | Providers, settings, masked credential, cached catalog |
| PUT | `/api/settings/ai` | Provider / model / endpoint / api-version / preview toggle |
| PUT | `/api/settings/ai/credential` | Store (or rotate) a key |
| DELETE | `/api/settings/ai/credential?provider=…` | Remove a key |
| POST | `/api/settings/ai/test` | One-token completion against the saved configuration |
| GET | `/api/settings/ai/models?provider=…&refresh=1` | Live or cached model catalog |
| GET/PUT | `/api/settings/automation` | Policy |
| POST | `/api/settings/automation/preview` | Render the issue for one finding id |
| POST | `/api/settings/automation/run` | Execute (`confirm` required for `auto`) |
| GET | `/api/settings/automation/audit` | Audit trail |

## 9. Configuration and verification

1. Settings → AI & Models → pick a provider → paste the key → **Save**.
2. **Refresh models** → pick one → **Save settings**.
3. **Test connection** should report *Connected*.
4. Settings → Issue automation → choose `assisted` → **Preview** a finding id.
5. Read the preview: facts, commands, warnings. If it looks right, switch to `auto` and
   **Run now** — it will ask for confirmation.

Files created on first use:

```
~/.config/clanker-guard/ai/master.key         0600
~/.config/clanker-guard/ai/credentials.json   0600  (ciphertext only)
~/.config/clanker-guard/ai/settings.json      0600  (no secrets)
~/.config/clanker-guard/ai/models-<provider>.json   catalog cache
~/.config/clanker-guard/automation/config.json      policy
~/.config/clanker-guard/automation/audit.jsonl      append-only trail
```

## 10. Known limitations

- **AWS Bedrock** is listed but disabled (needs SigV4).
- **Azure** model discovery returns the configured deployment; listing deployments needs
  a management-plane token with different permissions than an inference key.
- Settings endpoints are open to any authenticated API user: the application has one
  permission model (authenticated or not), and inventing a second one here would be a
  half-measure. Put the server behind an authenticated reverse proxy until per-role
  authorisation exists.
- Pricing is reported as a coarse bucket (`free`/`low`/`medium`/`high`) plus published
  metadata where the provider offers it; exact per-token prices change too fast to embed.
- Token usage is recorded per completion but not yet aggregated into a cost report.
