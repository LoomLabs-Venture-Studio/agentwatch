---
name: AgentWatch
description: A calm, local fitness tracker and security guard for AI coding agents.
colors:
  bg: "#ffffff"
  bg-alt: "#f8fafc"
  field: "#f1f5f9"
  ink: "#0f172a"
  ink-muted: "#475569"
  rule: "#e2e8f0"
  rule-strong: "#cbd5e1"
  petrol: "#0e5f76"
  petrol-strong: "#0a4759"
  petrol-soft: "#e3f0f4"
  on-petrol: "#ffffff"
  ok: "#15803d"
  degraded: "#b45309"
  warn: "#c2410c"
  bad: "#b91c1c"
  dark-bg: "#0f172a"
  dark-bg-alt: "#131d33"
  dark-field: "#1e293b"
  dark-ink: "#e2e8f0"
  dark-ink-muted: "#a3b1c6"
  dark-rule: "#1e293b"
  dark-rule-strong: "#334155"
  dark-petrol: "#67c3d9"
  dark-petrol-strong: "#9ad8e7"
  dark-on-petrol: "#0f172a"
  dark-ok: "#4ade80"
  dark-degraded: "#fbbf24"
  dark-warn: "#fb923c"
  dark-bad: "#f87171"
typography:
  body:
    fontFamily: "Atkinson Hyperlegible Next, Atkinson Hyperlegible, system-ui, sans-serif"
    fontSize: "1rem"
    lineHeight: 1.55
  headline:
    fontFamily: "Atkinson Hyperlegible Next, Atkinson Hyperlegible, system-ui, sans-serif"
    fontSize: "1.6rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  title:
    fontFamily: "Atkinson Hyperlegible Next, Atkinson Hyperlegible, system-ui, sans-serif"
    fontSize: "1.15rem"
    fontWeight: 700
    lineHeight: 1.3
  label:
    fontFamily: "Atkinson Hyperlegible Next, Atkinson Hyperlegible, system-ui, sans-serif"
    fontSize: "0.875rem"
  code:
    fontFamily: "Atkinson Hyperlegible Mono, ui-monospace, Menlo, Consolas, monospace"
    fontSize: "0.875rem"
rounded:
  sm: "4px"
  md: "8px"
  lg: "12px"
spacing:
  gutter: "16px"
  group: "16px"
  section: "32px"
components:
  button-primary:
    backgroundColor: "{colors.petrol}"
    textColor: "{colors.on-petrol}"
    rounded: "{rounded.md}"
    height: "44px"
  button-primary-hover:
    backgroundColor: "{colors.petrol-strong}"
  button-quiet:
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    height: "44px"
---

# Design System: AgentWatch

The source of truth is the agentwatch.info stylesheet,
`docs/assets/stylesheets/extra.css` (#189). The `agentwatch visual` page
(`src/agentwatch/visual.py`) copies the same tokens. Change one, change the
other.

## Overview

**Creative North Star: "The calm instrument"**

AgentWatch is the thing you glance at between other work. Most of the time it
should say "fine" quietly. When something is wrong it should say what and
what to do, in plain words, without alarm. Surfaces are neutral slate. One
petrol accent marks what you can act on. Colour is spent only on state.

**Key characteristics:**

- Light by default. Dark follows the system and has a toggle.
- Slate neutrals and one accent. No gradients, glows or decoration.
- The answer first (a score and its word, the findings), raw data behind a
  disclosure.
- Plain language labels, not field names.

## Colors

- **Petrol** (`#0e5f76`, dark `#67c3d9`): links, the selected tab, primary
  buttons, focus rings. Never used for status.
- **Slate neutrals**: background, text, rules. Muted text is `#475569` /
  `#a3b1c6`, AA on every background.
- **Status** (`ok`, `degraded`, `warn`, `bad`): only for a state, and always
  next to its word ("productive", "high"). Never colour alone.

Score bands, shared by the site and the page: 80-100 ok, 60-79 degraded,
40-59 warn, 0-39 bad. Severity: critical = bad, high = warn,
medium = degraded, low = muted.

## Typography

Atkinson Hyperlegible Next for text, Atkinson Hyperlegible Mono for code,
paths and ids. The site serves the fonts itself (MkDocs privacy plugin). The
local `visual` page fetches nothing, so it names Atkinson first and falls
back to the system UI font when it isn't installed. Embedding a subset of the font in
the page as a data URI is an open board decision.

Numbers use tabular figures. Headings are balanced; paragraphs use
`text-wrap: pretty`.

## Layout

- One column, max 72rem, 16px gutters.
- A report is a section: a 2px ink rule on top, title, actions on the right,
  an "Updated" time, then the body.
- Below 44em, multi-column tables become one labelled list per row, and the
  tabs move to their own row under the brand.

## Elevation & Depth

Flat. Rules and tonal backgrounds, no shadows on the page. (The site uses one
soft shadow on the hero screenshot only.)

## Shapes

Radius 4px for focus rings and code, 8px for buttons and notes, 12px for
large framed panels. Status dots are circles.

## Components

- **Tabs**: text with a 3px petrol underline when selected. `role=tab`,
  arrow keys, Home/End, and the URL hash (`#security`) keeps the tab on
  reload.
- **Buttons**: 44px tall. Primary is filled petrol (one per section, for the
  slow action like "Run audit"). Quiet is outlined slate ("Refresh").
- **Status chip**: a dot plus the word, both in the status colour.
- **Verdict**: a large score, "/ 100 health", then the chip.
- **Facts**: a grid of label over value, each with a rule underneath.
- **Problem note**: a bordered box, bold title in `bad`, then what to do.

## Do's and Don'ts

- Do say what to do next in findings and errors.
- Do keep status colour next to its word.
- Do render anything from a log with `textContent`.
- Don't use cards as the default container, or nest them.
- Don't use emoji or Unicode glyphs as icons. Draw them in SVG.
- Don't load anything from another origin on the local page.
