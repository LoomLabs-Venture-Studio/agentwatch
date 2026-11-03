# AgentWatch

Know when your AI coding assistant needs you.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

AgentWatch watches Claude Code, Cursor, Codex and other AI coding assistants
while they work. It tells you when one is going in circles, keeps failing, is
burning through money, or is doing something risky with your passwords, keys
or data. It reads the logs your assistant already writes, on your own computer.

Full guide: [agentwatch.info](https://agentwatch.info).

## Install

You need Python 3.11 or newer, on macOS, Windows or Linux.

```bash
pipx install agentwatch-monitor
```

`pip install agentwatch-monitor` works too, ideally in a virtual environment.
If pip stops with an "externally managed environment" error, use pipx.
Check it worked with `agentwatch --version`.
[Get started](https://agentwatch.info/get-started/) has the steps per system.

## Quick start

```bash
agentwatch check              # check your latest session once
agentwatch watch-all          # live dashboard of every running assistant
agentwatch security-scan      # security verdict: secure, at risk or compromised
```

`check` reads your most recent Claude Code session for the current folder, or
the most recent one anywhere. For another assistant's log, add `--log <file>`.
`watch-all` finds the supported assistants running on your computer by itself.

![The AgentWatch dashboard with four sessions: checkout-api stuck in a loop re-running a failing command, newsletter flagged for credential access and upload, and two sessions working normally.](https://raw.githubusercontent.com/LoomLabs-Venture-Studio/agentwatch/main/docs/assets/images/dashboard.svg)

The live dashboard (`agentwatch watch-all --security`) with four made-up
sessions.

Every session gets a health score from 0 to 100:

| Score | Word | What it means |
| --- | --- | --- |
| 80-100 | productive | Working normally. |
| 60-79 | struggling | Something is slowing it down. |
| 40-59 | spinning | It's wasting effort. Time to step in. |
| 0-39 | stuck | It isn't getting anywhere. |

`--theme classic` uses healthy, degraded, warning and critical instead.
`--theme ascii` uses plain text, for old Windows consoles that show boxes
instead of symbols.

## Supported agents

AgentWatch reads each assistant's own log files, so each one is supported
separately. "Live-verified" means checked against the real, running app.
"Fixture-verified" means tested with sample logs built from the assistant's
source code or recorded sessions, not yet against a running copy.

| Agent | Status | Notes |
| --- | --- | --- |
| Claude Code | Live-verified | Full support, with cost estimates. |
| Aider | Live-verified | Live tailing of the chat history. Token counts and cost need `--analytics-log`. |
| Cursor | Live-verified | Agent-mode chats, read while Cursor is open. |
| GitHub Copilot CLI | Live-verified (1.0.90) | No token counts (Copilot logs session totals only). |
| GitHub Copilot in VS Code | Live-verified on Windows (VS Code 1.140) | Agent-mode chats. Tokens, no cost. |
| Antigravity CLI (`agy`) | Live-verified (1.2.14) | No token counts in its log. |
| ChatGPT desktop app, Codex view | Live-verified on Windows | Same logs as Codex CLI. Chat and Work views run on OpenAI's servers and are not covered. |
| Codex CLI | Fixture-verified | Built against OpenAI's published Codex source. |
| Gemini CLI | Fixture-verified | Built against the gemini-cli 0.62/0.63 source. |
| OpenCode | Fixture-verified | Parser built from real OpenCode 1.18 sessions; live `ps`/`watch-all` not verified. |
| Kilo Code 7.x | Fixture-verified | CLI and VS Code extension; read like OpenCode. |
| Cline | Fixture-verified | VS Code extension and Cline CLI. |
| Claude Desktop (Cowork) | Fixture-verified, limited | Only sessions that run on the host show up; newer sessions run inside the app's VM. |
| Moltbot | Log files only | Not found automatically, no live view. Use `agentwatch check --log <file>`. |

Windsurf, Roo Code and Kilo Code 5.x are not supported. Details and known
limits per agent: [Supported agents](https://agentwatch.info/supported-agents/).

## What it checks

Health (15 checks):

- **Going in circles.** The same command, the same error, again.
- **Failing over and over.** Step after step fails.
- **Stuck, no progress.** Lots of reading and searching, no changes.
- **Forgetting earlier work.** The context window fills up and it re-reads
  files it already saw.
- **Burning money.** Estimated cost per session, and how much went on steps
  that led nowhere.

Security (21 more checks, with `--security`):

- **Leaked passwords and keys** in commands or output.
- **Prompt injection.** Hidden instructions in a file or web page.
- **Data sent somewhere unexpected.** For example, reading `.env` and then
  uploading.
- **Dangerous commands.** Bulk deletes, `sudo`.
- **Unknown add-ons.** New skills being installed or going online.

The checks are plain rules, not AI. They cost nothing to run and give the same
answer every time. `agentwatch list-detectors --security` lists them all.
[What it checks](https://agentwatch.info/what-it-checks/) explains each one.

## Commands

Add `--help` to any command for all options. Full reference with examples:
[docs/commands.md](docs/commands.md), also at
[agentwatch.info/commands](https://agentwatch.info/commands/).

| Command | What it does |
| --- | --- |
| `watch-all` | Live dashboard of every running assistant. `--headless` prints new warnings instead. |
| `watch` | The same dashboard for one session (`--log FILE`). |
| `check` | Check one session once and print a health report. `--security`, `--json`. |
| `security-scan` | Security checks only, with a verdict. `--json`, `--audit-log FILE`. |
| `ps` | List the assistants running now. |
| `report` | What your assistants cost over the last 7 days, and the trend. |
| `stats` | Claude Code token use by tool. `--burn` shows tokens spent on trivial commands. |
| `history sync\|prune\|path` | The local session history behind `report`. |
| `audit` | Search past Claude Code logs for leaked secrets. `--pii`, `--redact`. |
| `scrub FILE` | Write a copy of a file with secrets and personal info hidden. |
| `detect` | List every program on this computer using AI right now. |
| `net` | Show which servers local AI runtimes (Ollama, LM Studio, ...) talk to. |
| `statusline` | A short warning in Claude Code's status line (see below). |
| `list-detectors` | List the checks. |
| `themes` | List the word sets for the score ranges. |

`agentguard` is the same tool with security on by default: `agentguard scan`,
`check`, `watch`, `watch-all` and `audit`.

### Alerts

`watch` and `watch-all` can tell you instead of you watching:

```bash
agentwatch watch-all --headless --notify --budget 5
```

`--notify` shows a desktop notification on a critical session or finding
(`--notify-min high` for high ones too). `--webhook URL` (or
`AGENTWATCH_WEBHOOK`) posts alerts to a Slack-style webhook. `--budget USD`
alerts once per session when its estimated cost reaches that amount.

### Use in CI

`check`, `security-scan` and `audit` end with an exit code a pipeline can act
on: 0 is fine, 1 is a warning, 2 is serious. For `check`, 0 means health 60 or
more, 1 means 40 to 59, 2 means below 40. `--security` also counts the security
verdict. The full table is in
[docs/commands.md](docs/commands.md#use-in-ci).

```yaml
- name: Check the agent's session
  run: agentwatch check --security --log agent-session.jsonl
```

### SIEM integration (optional)

`--siem-log FILE` on `check`, `security-scan`, `watch` and `watch-all` appends
each finding as one line of JSON, for any log forwarder (Splunk, Filebeat,
Datadog Agent) to pick up. It needs an extra:

```bash
pipx install "agentwatch-monitor[siem]"
```

`--llm` (extra `[llm]`) asks a local Ollama model for a second opinion on each
warning and on whether the session still matches the task. It never changes a
score and only talks to Ollama on your own computer.

## Claude Code plugin

The `agentwatch` plugin coaches Claude Code while it works:

- **Coaching.** After each step it checks the session. When a serious loop,
  error spiral or stuck pattern shows up, it adds a short note for Claude:
  what is wrong and what to try instead. Each problem is noted once.
- **Loop breaker.** When the same step has run 6 or more times in the last 10,
  it blocks the next identical step once and tells Claude why. Commands meant
  to repeat, such as running tests, are never blocked. Set
  `AGENTWATCH_LOOP_BREAKER=off` to turn it off.
- **Scrub skill.** Ask Claude to scrub or redact a file before sharing it, and
  it runs `agentwatch scrub` for you (dry run first).

It needs AgentWatch 0.2.0 or newer installed as above. Then, in Claude Code:

```text
/plugin marketplace add LoomLabs-Venture-Studio/agentwatch
/plugin install agentwatch@agentwatch
```

On Claude Code 2.1.275 or newer, one command does both:
`/plugin install agentwatch --marketplace LoomLabs-Venture-Studio/agentwatch`.
If `agentwatch` is not on your PATH, the plugin does nothing.

### Status line

`agentwatch statusline` shows a short warning such as `⚠ loop ~$1.40` in
Claude Code's status line when the session is in trouble, and nothing when it
is fine. It needs the plugin. Plugins cannot set the status line, so add this
to `~/.claude/settings.json`:

```json
{
  "statusLine": {
    "type": "command",
    "command": "agentwatch statusline"
  }
}
```

Use `agentwatch statusline --ok` to also see a check mark when all is well. If
you already have a status line script, pipe the same input to
`agentwatch statusline` and append what it prints.

## Privacy

AgentWatch runs on your computer and reads logs that are already there.

- No server, no account, no telemetry.
- Your code and conversations are never uploaded. If you set up a webhook,
  each alert sends a short warning message (which can name a file or command)
  to the address you chose.
- `report` and the dashboard keep a small local history of session summaries
  (times, tokens, cost, score, short warning messages), never your prompts or
  the assistant's replies. `agentwatch history path` shows where it is.

More in the [FAQ](https://agentwatch.info/faq/).

## Contributing

Issues and pull requests are welcome at
[github.com/LoomLabs-Venture-Studio/agentwatch](https://github.com/LoomLabs-Venture-Studio/agentwatch/issues).
Most useful: new checks for failure patterns you have seen, and real logs from
assistants that are only fixture-verified (Codex CLI, Gemini CLI, OpenCode,
Kilo Code, Cline). Scrub them first with `agentwatch scrub`.

```bash
pip install -e ".[dev,siem,llm]"
python -m pytest tests/
ruff check .
```

Pull requests target the `develop` branch. Checks live in
`src/agentwatch/detectors/`.

## License

MIT. Built by [LoomLabs](https://loomlabs.io).
