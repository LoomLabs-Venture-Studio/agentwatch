# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Developers who run AI coding agents (Claude Code, Cursor, Codex, Copilot,
Aider and others) on their own machine, often several at once, often
semi-unattended. They glance at agentwatch between other work to answer three
questions: is my agent healthy, is it doing anything risky, and what has it
cost. A second audience is team leads reading a weekly report or CI output.
*(inferred: the team-lead audience comes from `report` and `check`'s CI exit
code, not from user research.)*

## Product Purpose

A local "fitness tracker + security guard" for AI coding agents. It reads the
agents' own session logs as they stream and flags loops, thrashing, error
spirals, context rot, wasted spend, credential leaks, prompt injection and
data exfiltration. Success: the user notices a stuck or risky session within
minutes instead of after the bill or the leak.

## Positioning

It runs entirely on the user's computer, reads logs the agents already write,
needs no account, proxy or cloud service, and covers many agents with one
vocabulary of health and security findings.

## Operating Context

- Surfaces: the CLI (`check`, `security-scan`, `audit`, `stats`, `report`,
  `history`), live terminal dashboards (`watch`, `watch-all`), a Claude Code
  hook and status line, desktop/webhook alerts, and `agentwatch visual`, a
  local browser page over the same JSON as each command's `--json`.
- `agentwatch visual` is served by a stdlib server on 127.0.0.1 with a
  per-run token. Read only; expensive scans (audit, history sync) run only
  when asked.
- The docs site is agentwatch.info (MkDocs Material, `docs/`).

## Capabilities and Constraints

- Python >= 3.11, stdlib-first; no new dependencies without a documented
  reason.
- The browser page makes same-origin requests only: no CDN, external fonts,
  analytics or images from elsewhere. A strict Content-Security-Policy is
  sent with every response.
- Everything from a log is untrusted: it is redacted server-side and rendered
  with `textContent` only.
- Scores are 0 to 100 with four named ranges; status words come from the
  theme vocabulary (`themes.py`).

## Brand Commitments

- Name: AgentWatch in prose, `agentwatch` as the command.
- Voice: plain language a non-expert can follow, calm, factual, no hype, no
  alarmism; say what happened and what to do next.
- Look: the agentwatch.info redesign (#189) is the reference: calm slate
  neutrals, one petrol accent, status colours only for status and always next
  to their word, Atkinson Hyperlegible, light by default with a dark option.

## Evidence on Hand

- Screenshot: `docs/assets/images/dashboard.svg` (made-up sessions,
  labelled as such).
- No testimonials, customer logos, usage numbers or benchmarks exist. Do not
  invent them.

## Product Principles

1. Local and private by default: nothing leaves the machine unless the user
   wires it (webhook, SIEM).
2. Say it plainly: a finding names the problem, the evidence and the next
   step.
3. Calm until it matters: neutral surfaces, colour reserved for state.
4. Never make things worse: read only, fail open, redact before display.

## Accessibility & Inclusion

WCAG 2.2 AA: text contrast, visible keyboard focus, 44px touch targets on
phones, colour never the only signal, reduced motion respected. The site
chose Atkinson Hyperlegible for legibility. *(inferred: AA as the target
comes from the #189 site work, not a written policy.)*
