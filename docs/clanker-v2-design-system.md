# Clanker V2 design system

How the interface is built, so the next screen looks like it belongs. Everything here is enforced by
tokens in `web/src/styles.css`; components must not hardcode colours.

## Reference and what was taken from it

Reviewed `katalyst.5studios.net` (a commercial admin template) in a browser: light airy canvas,
white cards at an 18 px radius with a hairline border and almost no shadow, metric tiles with a thin
coloured rule on top, a tinted icon square, a large number and a sparkline, a donut with the total in
the centre and a legend beside it, soft gradient area fills, muted gridlines, and a grouped sidebar
with an uppercase micro-label per group.

Adapted to Clanker, not copied: the only charting dependencies are our own SVG components, the
palette is ours, and the brand gradient appears on the sign-in panel rather than behind data. No
reference assets, fonts or source are used.

## Colour

Semantic tokens only. Light is the default; `.dark` overrides the same names, so a component never
branches on theme.

| Purpose | Token | Light | Dark |
|---|---|---|---|
| App background | `--bg` | `#f7f8fa` | `#0b0f16` |
| Card surface | `--surface` | `#ffffff` | `#111722` |
| Nested surface | `--surface-2` | `#f2f4f7` | `#161d29` |
| Border | `--border-c` | `#e3e8ee` | `#232c3b` |
| Primary text | `--fg` | `#0f1729` | `#e8edf5` |
| Secondary text | `--fg-muted` | `#5b6675` | `#9aa6b8` |
| Accent | `--accent` | `#2563eb` | `#3b82f6` |
| Secondary accent | `--accent-2` | `#8b5cf6` | `#a78bfa` |
| Highlight accent | `--accent-3` | `#22d3ee` | `#67e8f9` |
| Critical / High / Low | `--critical` `--high` `--low` | `#c81e1e` `#b45309` `#157347` | `#f87171` `#fb923c` `#4ade80` |

Rules:

- **Colour means something.** Red is danger or failure, amber is "needs attention", green is verified
  good. Never use red for emphasis or a neutral count.
- Every text/background pair in use meets WCAG AA for its size; `--fg-subtle` was chosen by measuring,
  not by eye.
- Charts use `--chart-*` and `--chart-grid`, so they follow the theme without per-chart work.
- Gradients (`--gradient-brand`, `--gradient-accent`) are for the sign-in panel and selected summary
  surfaces only. Operational panels stay neutral.

## Surfaces and elevation

Four levels, in order: app background → card (`--surface`) → nested panel (`--surface-2`) → control
(`--surface-3`). Separation comes from the border and one step of surface contrast, not from shadows.
`--shadow-card` is for cards that sit above other cards (dialogs use `--shadow-pop`).

Radius: cards `--radius-card` (18 px), controls `--radius-control` (10 px). Buttons stay at their
existing radius; do not mix.

## Typography

System sans (`--font-sans`), monospace for identifiers, versions, paths and commands (`--font-mono`).
Sizes: page title `text-xl` 600; section label `text-xs` uppercase 600 with wide tracking; body
`text-sm`; metadata `text-xs`. Numbers use `tabular-nums` through the `.num` class so columns align.

## Motion

Tokens: `--dur-hover` 120 ms, `--dur-pop` 180 ms, `--dur-page` 220 ms, `--dur-chart` 520 ms, easing
`--ease-out`.

- Entrance only: one fade-and-rise on page mount (`.animate-fade-up`, `.stagger` for short sequences),
  chart draw, and colour transitions on hover. **Nothing loops** except the two blurred orbs on the
  sign-in panel; a security dashboard that moves while you read it is a dashboard you stop trusting.
- Never animate something that delays a click, and never re-animate a chart on data refresh.
- Everything is disabled under `prefers-reduced-motion: reduce`, and the interface stays fully usable:
  verified in a browser with that preference set.

## Components (reuse, do not re-implement)

| Component | Use for |
|---|---|
| `PageHeader` | every page: title, one-line description, `help` behind the ⓘ, actions |
| `InfoTooltip` | all contextual help; hover + focus + click, Escape closes |
| `MetricCard` | one headline number with meaning, accent rule and optional link |
| `SeverityDonut` | severity distribution with a labelled legend (clickable when it navigates) |
| `AgingBars` | age of open work, oldest bucket highlighted |
| `Card`, `CardHeader`, `CardBody` | panels and section titles |
| `Table`, `TableWrap` | data tables; the wrapper handles horizontal scroll |
| `Badge`, severity badges | status and severity, never colour alone |
| `Collapsible` | technical detail (evidence, raw data, references) |
| `EmptyState`, `LoadingBlock`, `ErrorState` | the four different states that are not "zero" |
| `Button` (primary/secondary/ghost/danger) | every action |

## Charts

- Only when the data exists. A trend needs history; the process metrics show a dash until something is
  verified. Do not synthesise series from a snapshot.
- Always pair a chart with its numbers: the donut has a legend with counts and percentages, the ageing
  bars print each value. Meaning must not depend on colour or on judging a length.
- Accessible: `role="img"` with an `aria-label` that states the total, plus the same numbers as text.
- No 3D, no invented baselines, no gradients that hide the shape of the data.

## Contextual help

Every page header and every non-obvious metric carries an ⓘ. The text adds information the heading
does not: what is counted, over which population, from which scan, and how to read it. It never repeats
the label, and a warning or prerequisite is never hidden only in a tooltip.

## Tables

Header row in `text-xs` uppercase muted, sticky inside the scroll container, row hover `--surface-2`,
numbers right-aligned with tabular figures, identifiers monospace. Filters live in a toolbar above the
table; the count of active filters is always visible. Bulk actions appear only with a selection.

## Accessibility checklist for new UI

- Every control reachable and operable by keyboard; focus ring visible (`:focus-visible` uses `--focus`).
- Icon-only controls have an accessible name.
- State is never communicated by colour alone.
- Both themes checked, and reduced motion.
- Long text wraps; nothing relies on hover for essential instructions.
