# UI writing standards

Rules for every string a user can read: page titles, descriptions, help, labels, buttons, empty
states, errors and toasts.

## Voice

- Plain, professional, and specific. Short sentences. Active voice.
- Write for someone who runs systems but is not a security specialist. Explain a security term the
  first time it appears in a workflow, not in a glossary nobody opens.
- Eighth-grade reading level for instructions where it does not cost precision.
- Never write a sentence that is fluent and wrong. If the code does something conditional, say so.

## The six questions

Every page and every major section answers, in this order:

1. What does this do?
2. Why does it matter?
3. When would I use it?
4. What do I need to provide?
5. What happens after I act?
6. What should I do next?

## Terms

| Avoid | Use | Why |
|---|---|---|
| enrichment / enrich | look up vulnerability details | describes the outcome, not the pipeline |
| lifecycle snapshot | current scan progress | "lifecycle" belongs to the database |
| captured issues | findings detected | "captured" implies the tool took them |
| buckets | groups | plain |
| stub rule | suggested detection rule | a stub sounds unfinished, and it is a suggestion |
| raw entries | detailed observations | "raw" tells the user nothing |
| rollups | summary reports | the word is internal |
| v-conf | version detection confidence | never abbreviate a confidence |
| profile (scan) | scan type | the code and the API say profile; the UI says type |
| toggle role | change user role | name the change, not the control |
| since / until (ISO) | start date and time / end date and time | nobody reads ISO timestamps |

Keep these distinctions; do not let them collapse into "risk":

- **Severity** — what the advisory says about the vulnerability.
- **Priority** — when this organisation should act (severity plus KEV, exposure, asset criticality).
- **Confidence** — how sure the match is.
- **Applicability** — confirmed / probable / needs investigation / not affected.
- **Finding** — evidence. **Remediation item** — work. **Ticket** — the change request.

A finding resolved by verification is not the same as a ticket closed by a person; say which one happened.

## Contextual help (the ⓘ)

Use `InfoTooltip` (`web/src/components/ui/InfoTooltip.tsx`) for every page header and for metrics whose
meaning is not obvious.

- The tooltip must **add** information. Never restate the heading.
- Say what is counted, over which population, from which scan, and how to read it.
- Keep prerequisites, warnings and required instructions **visible on the page**; a tooltip is
  supplementary, never the only place a safety-critical sentence lives.
- One control per heading, positioned immediately after it, labelled `About <heading>`.
- Works with mouse, keyboard and touch; Escape closes it. Verified by Playwright for every page.

## Buttons and destructive actions

- Label the outcome, not the mechanism: "Add system", "Run scheduled scan now", "Save scan schedule".
- A destructive confirmation names what is removed **and** what is kept.
- A disabled control says why it is disabled and what would enable it.
- Icon-only controls carry an accessible name; essential instructions never live only in a hover.

## States

These are five different things and must read differently:

| State | Wording pattern |
|---|---|
| Never scanned | "No scan has run for this system yet." + next action |
| Nothing found | "The last scan found nothing to fix." + coverage caveat |
| Scan failed | "The scan stopped: <reason>." + retry path |
| Completed with gaps | "Completed, but these checks could not run: …" |
| Filtered to nothing | "No results match these filters." + clear action |

And separately: "not assessed" never renders as a number. If a value is unknown, say unknown.

## Errors

Every error answers: what happened, why (if known), what to do, whether retrying helps. No stack
traces, no status codes alone, no database vocabulary. Never print a token, key or credential, even
in a diagnostic disclosure.
