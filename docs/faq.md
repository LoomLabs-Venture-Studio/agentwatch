---
title: FAQ
description: Privacy, cost, AI use, speed, stopping an assistant, supported systems, scores, and reporting problems.
hide:
  - navigation
---

# Questions and answers

## Does it send my data anywhere?

No. AgentWatch runs on your computer and reads the log files your assistant
already writes there. There is no AgentWatch server and no account, and nothing
from your code or your conversations is sent anywhere.

It uses the network in only these ways:

- **Name lookups.** To tell you which server a program is talking to, it looks
  up server names, like any program that opens a web address. Your internet
  provider or DNS service sees those lookups.
- **Alerts you set up.** If you give it a webhook address (for example a Slack
  channel), it posts each alert there: the assistant, the project, the problem
  and its estimated cost, with any secrets hidden.
- **Optional AI second opinion.** With `--llm`, it talks to Ollama on your own
  computer, never to an outside AI service.

Its history for the weekly report is a file on your computer too. It holds
summaries (times, tokens, cost, scores), never your prompts, the assistant's
replies or its commands.

## Does it cost anything?

No. AgentWatch is free and open source under the MIT license. The checks don't
use AI, so running them doesn't add to your AI bill.

The costs it shows are estimates of what your assistant is spending, worked out
from the token counts in its log and the AI provider's published prices.

## Does it use AI?

Not for its checks. Each one is a plain rule, so the same session always gets
the same result, and you can see why a warning appeared.

There is one optional extra: with `--llm`, a local AI model (Ollama, running on
your computer) adds a second opinion on the warnings. It never changes a score.

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
Commands that are meant to repeat, like running tests, are never blocked. You can
turn it off by setting `AGENTWATCH_LOOP_BREAKER=off`. The
[README](https://github.com/LoomLabs-Venture-Studio/agentwatch#claude-code-plugin-coach)
explains how to install the plugin.

## Which systems does it run on?

macOS, Windows and Linux, with Python 3.11 or newer. Windows is supported
directly, without WSL.

Some assistants were only tested on one system; [Supported agents](supported-agents.md)
says which. A few features have limits outside Windows: on macOS and Linux,
`agentwatch detect` can't see other users' programs unless you run it as an
administrator.

If symbols show up as boxes or question marks in the old Windows console, use
Windows Terminal or the terminal in VS Code, or run AgentWatch with
`--theme ascii`.

## What do the scores mean?

The health score runs from 0 to 100: 80 and up is productive, 60 to 79
struggling, 40 to 59 spinning, and below 40 stuck. The security verdict is
secure (100), at risk (50 to 99) or compromised (below 50).
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
