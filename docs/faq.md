---
title: FAQ
description: Privacy, cost, AI use, speed, stopping an assistant, supported systems, scores, and reporting problems.
hide:
  - navigation
---

# Questions and answers

## Does it send my data anywhere?

No. AgentWatch runs on your computer and reads the log files your assistant
already writes there. There is no AgentWatch server and no account. Your code
and conversations are never uploaded. If you set up an alert webhook, each alert
sends a short warning message (which can name a file or command) to the address
you chose.

It uses the network in only these ways:

- **Name lookups.** To tell you which server a program is talking to, it looks
  up server names, like any program that opens a web address. `agentwatch net`
  and the dashboard also look up the names of the addresses your programs
  connect to (reverse lookups). Your internet provider or DNS service sees those
  lookups.
- **Alerts you set up.** If you give it a webhook address (for example a Slack
  channel), it posts each alert there: the assistant, the project, the problem,
  its estimated cost and the warning message, with any secrets in it hidden.
- **Optional AI second opinion.** With `--llm`, it talks to Ollama (a free app
  that runs AI models on your own computer), never to an outside AI service.

Its history for the weekly report is a file on your computer too. It keeps
short summaries (times, tokens, cost, scores) and warning messages, cut to 120
characters with paths shortened to the file name and secrets hidden. It never
keeps your prompts or the assistant's replies.

## Does it cost anything?

No. AgentWatch is free and open source under the MIT license. The checks don't
use AI, so running them doesn't add to your AI bill.

The costs it shows are estimates of what your assistant is spending, worked out
from the token counts in its log and the AI provider's published prices.

## Does it use AI?

Not for its checks. Each one is a plain rule, so the same session always gets
the same result, and you can see why a warning appeared.

There is one optional extra: with `--llm`, a local AI model (through Ollama,
on your own computer) adds a second opinion on the warnings. It never changes a
score.

## Will it slow my assistant down?

No. AgentWatch doesn't sit between your assistant and its AI service, and
doesn't change how the assistant works. It reads the log files the assistant
writes anyway.

The exception is the optional Claude Code plugin. It runs AgentWatch's checks
inside Claude Code after each step the assistant takes, which adds a little time
to each step.

## Can it stop my assistant?

Not on its own. AgentWatch watches and warns; it doesn't stop, pause or change
your assistant.

One exception, for Claude Code only: the optional plugin's **loop breaker**.
When the same step has run 6 or more times in the last 10, it blocks the next
identical step once and tells Claude why, so that Claude changes approach.
Commands that are meant to repeat, like running tests, are never blocked. To
turn it off, set the environment variable `AGENTWATCH_LOOP_BREAKER` to `off`.

To install the plugin, type these two commands in Claude Code (AgentWatch 0.2.0
or newer must be installed first):

```text
/plugin marketplace add LoomLabs-Venture-Studio/agentwatch
/plugin install agentwatch@agentwatch
```

[Get started](get-started.md#optional-a-coach-inside-claude-code) says more
about what the plugin does.

## Which systems does it run on?

macOS, Windows and Linux, with Python 3.11 or newer. Windows is supported
directly, without WSL.

Some assistants were only tested on one system; [Supported agents](supported-agents.md)
says which. `agentwatch detect` was tested live on Windows; on macOS and Linux
it has only been checked against sample data, and without administrator rights
it can't see other users' programs (it says the scan is partial).

If symbols show up as boxes or question marks in the old Windows console, use
Windows Terminal or the terminal in VS Code, or run AgentWatch with
`--theme ascii`.

## What do the scores mean?

The health score runs from 0 to 100: 80 and up is productive, 60 to 79
struggling, 40 to 59 spinning, and below 40 stuck. For security,
`agentwatch security-scan` gives a verdict: secure (100), at risk (50 to 99) or
compromised (below 50).
[What it checks](what-it-checks.md) explains each warning and how the scores are
worked out.

## How do I report a problem?

Open an issue on
[GitHub](https://github.com/LoomLabs-Venture-Studio/agentwatch/issues). Say which
assistant and which system you use, and what you expected to see.

If you want to attach a session log, clean it first. This writes a copy with
secrets and personal information hidden:

```bash
agentwatch scrub <log file>
```
