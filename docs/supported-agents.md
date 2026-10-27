---
title: Supported agents
description: Which AI coding assistants AgentWatch works with, and how well each one has been tested.
hide:
  - navigation
---

# Supported agents

AgentWatch reads the log files each assistant writes on your computer. Every
assistant stores its logs differently, so each one is supported separately. The
status below says honestly how far each has been tested in AgentWatch 0.2.1.

Unless a note says otherwise, `agentwatch watch-all` finds the assistant by
itself while it runs, and `agentwatch check --log <file>` can check one of its
log files.

## Tested live

These were checked against the real, running app.

Claude Code
:   Fully supported. Cost estimates included.

Aider
:   Fully supported, including live updates as the chat grows. Aider's chat log
    has no token counts. For cost estimates, turn on Aider's optional analytics
    log and pass it to a check: `agentwatch check --log <chat log>
    --analytics-log <analytics log>`.

Cursor
:   Fully supported for agent-mode chats, which Cursor keeps in a database rather
    than in separate files. AgentWatch reads them while Cursor is open.

GitHub Copilot CLI
:   Tested live with version 1.0.90. Copilot only logs token totals for a whole
    session, so AgentWatch shows no token counts or cost.

GitHub Copilot in VS Code
:   Agent-mode chats. Tested live on Windows with VS Code 1.140:
    `agentwatch ps`, `agentwatch check`, and the dashboard's engine run with
    `--headless`. Token counts,
    but no cost, because Copilot is billed in credits rather than dollars.
    VS Code can hold back saving a chat from a window in the background, so the
    dashboard may lag until you bring that window up.

Antigravity CLI (agy)
:   Tested live with version 1.2.14. Its log has no token counts.

ChatGPT desktop app, Codex view
:   Tested live on Windows with one real coding thread: `agentwatch ps`,
    `agentwatch check`, and the dashboard's engine run with `--headless`. It
    writes the same logs as Codex CLI. No cost estimates. Only the Codex view is covered; the
    Chat and Work views run on OpenAI's servers and leave nothing to read.

## Tested with sample logs only

These work with sample logs built from the assistant's published source code or
recorded sessions, but haven't yet been checked against a running copy. Please
[report anything odd](faq.md#how-do-i-report-a-problem).

Codex CLI
:   Built and tested against OpenAI's published Codex source. No cost estimates.
    The macOS setup was checked against the source code only.

Gemini CLI
:   Built against the Gemini CLI 0.62 and 0.63 source. Token counts, but no cost
    estimates.

OpenCode
:   Built from real recorded OpenCode 1.18 sessions. Not yet tested against a
    running OpenCode.

Kilo Code 7.x
:   The command-line tool and the VS Code extension. Kilo Code 7 is built on
    OpenCode, and AgentWatch reads it the same way. In the VS Code extension,
    only sessions in the window's first folder are found.

Cline
:   The VS Code extension and the Cline command line, with Cline's own cost
    figures. The extension is also found in VS Code Insiders, VSCodium and
    Cursor. Some older Cline tasks show token counts only.

## Limited

Claude Desktop (Cowork)
:   Only Cowork sessions that run directly on your computer show up. Newer
    sessions run inside the app's own virtual machine, where AgentWatch can't
    read them. Checked against the Windows Store version of the app.

Moltbot
:   An AI agent, also called Clawdbot, that can install add-ons called skills. Not
    found automatically and no live view. Check its log files directly:
    `agentwatch check --log <file>`.

## Not supported yet

Windsurf, Roo Code and Kilo Code 5.x aren't supported.

To see every program on your computer that is using AI right now, including ones
AgentWatch can't monitor, run `agentwatch detect`.

## Which systems

AgentWatch runs on macOS, Windows and Linux with Python 3.11 or newer. Some
assistants above were only tested on one system; their notes say which.
