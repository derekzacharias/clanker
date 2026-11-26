# UX clarity audit

What follows was found by reading the interface strings and walking the screens in a browser against
a copy of the production database, not by scanning for words. Each entry names the file, the problem,
and what changed. Items marked **open** were not changed in this pass and say why.

## Method

- Reviewed every page the shell routes to: Overview, Assets, Asset detail, Scans, New scan, Findings,
  Finding drawer, Remediation (Queue / By upgrade / Ownership), Report view, Administration
  (General, Intelligence, Endpoint agents, Integrations, Continuous improvement, Access, Audit log),
  and the sign-in screen.
- Checked the same screens in light and dark mode, at 1440 px and 390 px.
- Verified each explanation against the code that produces the number or the action, because the most
  damaging copy is a sentence that is fluent and wrong.

## Findings

| # | Screen | Problem | Why it confuses | Change | Priority |
|---|---|---|---|---|---|
| 1 | Assets (`web/src/pages/Assets.tsx:127`) | Row read `agent 0.1.11` while the endpoint ran 0.2.0 | It showed the build behind the last *report*, labelled as the agent. After an upgrade it reads as "the upgrade failed" | Row now shows the enrolled agent's version and a `rescan needed` flag with both builds in the tooltip | P0 (done) |
| 2 | Every page header | Titles carried a sentence of description at most; no explanation of what the page is for or what the numbers mean | A first-time user cannot tell a finding from a task, or a scan from a report | Reusable `InfoTooltip` behind a ⓘ on every page header, explaining purpose, data source and limits | P0 (done) |
| 3 | Overview (`src/pages/Overview.tsx`) | "Current posture" and "Is it getting better?" sat unlabelled; findings and actions were easy to confuse | 1,352 findings vs 283 upgrades is not obvious without knowing one upgrade closes many findings | Both cards now carry contextual help saying exactly that | P0 (done) |
| 4 | New scan (`src/pages/NewScan.tsx:769`) | Progress said "Enriching with KEV / EPSS and scoring risk" | Internal pipeline vocabulary; "enrichment" means nothing to the person watching a scan | Now: "Checking which vulnerabilities are known to be exploited, and scoring risk" | P1 (done) |
| 5 | Info icons | Nothing existed; explanations were either absent or in page prose | Help was not reachable in context, and not reachable at all by keyboard or touch | `InfoTooltip` is hover + focus + click/tap, Escape closes; verified in a browser | P0 (done) |
| 6 | Scan progress stages | Stage names come from the scanner (`discovery`, `assessment`, `feeds`) | A stage called "feeds" does not say it is refreshing vulnerability data | **open** — needs a mapping table stage→sentence; low risk, do next | P2 |
| 7 | Findings drawer | Evidence, references and risk factors were expanded | The decision (owner, fix, verification) was below technical detail | Already restructured in the earlier redesign: verdict → meaning → owner → fix → evidence | P1 (done earlier) |
| 8 | Settings → Integrations | "token_set", "allow_insecure_http" leak into hints | Field names as documentation | **open** — labels are plain, but a couple of hints still quote config keys | P2 |
| 9 | Remediation → Queue | "awaiting owner", "pending verification" are precise but unexplained inside the table | Round-tripping to another page to learn what a state means | **open** — the state list belongs in the table's help; planned with the next queue change | P2 |
| 10 | Error states | Server errors surface as `409 invalid_transition: cannot move from X to Y` | Correct, but phrased for a developer | **open** — the API already sends actionable text for most cases; the remaining raw ones are conflict messages | P2 |
| 11 | Empty states | "No findings in the assessed scope" is careful, but sits next to "0" with no context on an unassessed host | Zero findings and "not assessed" look identical at a glance | Asset page now lists coverage gaps; Overview says "not proof the environment is secure" | P1 (done) |
| 12 | Dark mode | Tooltip colours were untested | Unreadable help is worse than none | Verified: text `rgb(232,237,245)` on `rgb(17,23,34)` | P0 (done) |

## What was deliberately not changed

- **Severity, confidence and applicability vocabulary.** These words are precise and a security
  engineer needs them. They are explained on first use in the finding drawer instead of being
  replaced with friendlier words that would lose the distinction.
- **API field names, database columns and enumeration values.** The interface can be clearer without
  breaking the contract the agent, CLI and integrations already speak.
- **No global find-and-replace.** Every reworded string was checked against the code path that
  produces it; a fluent sentence that misdescribes the behaviour is worse than jargon.

## Verification

`/tmp/ux-help.sh` (kept out of the repo; equivalent steps in the PR notes) starts the server against a
copy of production data and drives it with Playwright: for each of the six pages it asserts one help
control exists with the accessible name `About <Page>`, that it opens on hover, and that it opens
from the keyboard (`Enter`), plus dark-mode contrast and that no page throws. Result: **22/22**.
