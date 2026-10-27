---
title: Commands
description: Every AgentWatch command, its most useful options, examples, and the exit codes for use in CI.
hide:
  - navigation
---

# Commands

Every command starts with `agentwatch`. Add `--help` to any of them for the full
list of options, for example `agentwatch check --help`.

| To... | Run |
| --- | --- |
| watch every running assistant live | [`watch-all`](#watch-all) |
| watch one session live | [`watch`](#watch) |
| check a session once | [`check`](#check) |
| check a session for security problems only | [`security-scan`](#security-scan) |
| list the assistants running now | [`ps`](#ps) |
| see what your assistants cost | [`report`](#report), [`stats`](#stats), [`history`](#history) |
| find secrets in old session logs | [`audit`](#audit) |
| clean a file before sharing it | [`scrub`](#scrub) |
| see every program using AI on this computer | [`detect`](#detect) |
| see who local AI programs talk to | [`net`](#net) |
| show a warning in Claude Code's status line | [`statusline`](#statusline) |
| list the checks or the word sets | [`list-detectors`](#list-detectors), [`themes`](#themes) |

Two options go before the command name: `agentwatch --version` prints the
version, and `agentwatch --theme <name> <command>` changes the words used for
each score range (see [`themes`](#themes)).

## Watch live

### watch-all

The live dashboard: every assistant running on your computer, one row per
session, with its health, cost, memory use and top problem.

| Option | What it does |
| --- | --- |
| `-s`, `--security` | Also run the security checks |
| `--headless` | No dashboard: print one line per new warning, for running in the background |
| `--notify` | Desktop notification when a session turns critical or a critical problem appears |
| `--notify-min high` | Also notify on high-severity problems (the default is `critical`) |
| `--webhook URL` | Post alerts to a Slack-style webhook (or set `AGENTWATCH_WEBHOOK`) |
| `--budget USD` | Alert once per session when its estimated cost reaches this amount |
| `--all-logs` | Read every log in the known log folders instead of finding running assistants |
| `--since 6h` | With `--all-logs`, only logs changed in this window (default `24h`, or `all`) |

```bash
agentwatch watch-all --security
agentwatch watch-all --headless --notify --budget 5
```

In the dashboard, press <kbd>?</kbd> for every key.

### watch

The same dashboard, opened on one session. Without `--log` it picks your most
recent Claude Code session.

| Option | What it does |
| --- | --- |
| `-l`, `--log FILE` | The session's log file |
| `-s`, `--security` | Also run the security checks |
| `--notify`, `--webhook URL`, `--budget USD` | Alerts, as for `watch-all` |

```bash
agentwatch watch --security
```

## Check once

### check

Checks one session and prints a health report. Without `--log` it picks your
most recent Claude Code session for the current folder, or the most recent one
anywhere.

| Option | What it does |
| --- | --- |
| `-l`, `--log FILE` | The log file to check (any supported assistant's) |
| `-s`, `--security` | Also run the security checks |
| `--json` | Output as JSON, for scripts |
| `--analytics-log FILE` | Aider only: the analytics log, for token counts and cost |

```bash
agentwatch check
agentwatch check --security --log session.jsonl
```

### security-scan

Runs only the security checks on one session and prints a verdict: secure, at
risk or compromised.

| Option | What it does |
| --- | --- |
| `-l`, `--log FILE` | The log file to check |
| `--json` | Output as JSON |
| `--audit-log FILE` | Add one line per check to this file, whether it found something or not, as a record that the checks ran |

```bash
agentwatch security-scan --log session.jsonl
```

`check` and `security-scan` also accept `--siem-log FILE`, which appends each
finding as a line of JSON for security tools, and `--llm`, which asks a local
Ollama model for a second opinion without changing any score. Both need
optional extras; see the
[README](https://github.com/LoomLabs-Venture-Studio/agentwatch#siem-integration-optional).
`watch` and `watch-all` accept them too.

### ps

Lists the assistants AgentWatch can see running right now, with their process
IDs and sessions. `--json` for scripts.

```bash
agentwatch ps
```

## Cost

### report

What your assistants cost over the last 7 days: spend, how much went on steps
behind a health warning, the costliest problems, a breakdown by assistant and
project, and the change from the week before.

| Option | What it does |
| --- | --- |
| `--days N` | A different period |
| `--agent NAME` | Only one assistant, for example `claude-code` |
| `--project NAME` | Only one project folder |
| `--json` | Output as JSON |

```bash
agentwatch report
agentwatch report --days 30
```

### stats

Claude Code token use, broken down by tool and by kind of command.

| Option | What it does |
| --- | --- |
| `--all` | All projects, not only the current folder's |
| `--session ID` | One session |
| `--burn` | How many tokens went on simple commands you could have run yourself |
| `--json` | Output as JSON |

```bash
agentwatch stats --burn
```

### history

The local history behind `report`, kept in one file on your computer. It stores
a summary of each session (times, tokens, cost, score and findings), never your
prompts, the assistant's replies or the commands it ran.

| Command | What it does |
| --- | --- |
| `history sync` | Record new or changed sessions (`report` does this for you) |
| `history prune --older-than 90d` | Delete sessions older than 90 days |
| `history path` | Print where the history file is |

## Secrets and privacy

### audit

Searches your past Claude Code session logs for leaked passwords, keys and
tokens.

| Option | What it does |
| --- | --- |
| `--all` | All projects, not only the current folder's |
| `--session ID` | One session |
| `--pii` | Also look for personal information: emails, phone numbers, US Social Security numbers and card numbers |
| `--redact` | Replace what it finds with `[REDACTED]` in the log files |
| `--dry-run` | Report only; change nothing |
| `--json` | Output as JSON |

```bash
agentwatch audit --all --pii
```

### scrub

Hides secrets and personal information in one file before you share it. It
writes a cleaned copy next to the original (`notes.txt` becomes
`notes.scrubbed.txt`).

| Option | What it does |
| --- | --- |
| `--dry-run` | List what would be hidden; write nothing |
| `--in-place` | Overwrite the file, keeping the original as `<file>.bak` |
| `--secrets-only` | Hide secrets only, not personal information |
| `--json` | Output as JSON |

```bash
agentwatch scrub notes.txt --dry-run
agentwatch scrub notes.txt
```

A scrubbed key is hidden, not safe: if a key leaked, replace it.

## Your computer

### detect

Lists the programs on this computer that are using AI right now, including ones
AgentWatch can't monitor. It reads process names and network connections, and
leaves web browsers out. `--json` for scripts.

```bash
agentwatch detect
```

### net

Shows which outside servers local AI programs (Ollama, LM Studio, llama.cpp and
others) connect to, and which of their ports other computers can reach.

| Option | What it does |
| --- | --- |
| `--once` | Take one sample, print a summary and stop |
| `--local` | Also watch running coding assistants |
| `--pid N` | Also watch this process and the processes it started |
| `--duration SECONDS` | Stop after this long and print the summary |
| `--json` | Output as JSON |

```bash
agentwatch net --once
```

## Setup and reference

### statusline

Shows a short warning, such as `loop ~$1.40`, in Claude Code's status line when
the session is in trouble, and nothing when it's fine. It needs AgentWatch's
Claude Code plugin; the
[README](https://github.com/LoomLabs-Venture-Studio/agentwatch#status-line)
shows the one-time setup. `--ok` shows a small check mark when all is well.

### list-detectors

Lists the checks, grouped by category. Add `-s` (`--security`) to include the
security checks.

```bash
agentwatch list-detectors --security
```

### themes

Lists the sets of words AgentWatch can use for each score range. The default is
`agent` (productive, struggling, spinning, stuck); `classic` uses healthy,
degraded, warning and critical; `ascii` uses plain text, for terminals that
can't show symbols.

```bash
agentwatch themes
agentwatch --theme classic check
```

### agentguard

AgentWatch also installs a second command, `agentguard`, with security turned on
by default: `agentguard scan`, `agentguard check`, `agentguard watch`,
`agentguard watch-all` and `agentguard audit`.

## Use in CI

In automated pipelines, such as a GitHub Actions job that runs an assistant,
AgentWatch can fail the job when a session went wrong. Each command ends with an
exit code: 0 lets the job continue, anything else fails it.

| Command | 0 | 1 | 2 |
| --- | --- | --- | --- |
| `check` | Health 60 or more | Health 40 to 59 | Health below 40 |
| `check --security` | Health 60+ and secure | Health 40 to 59, or at risk | Health below 40, or compromised |
| `security-scan` | Secure (100) | At risk (50 to 99) | Compromised (below 50) |
| `audit` | No high or critical finding | A high finding | A critical finding |
| `scrub --dry-run` | Nothing found | Something found | Error |
| `scrub` | Done | | Error |

`check --security` takes the worse of its health result and its security
result, so one critical security finding exits 2 even when the health score is
high. `check`, `security-scan` and `audit` also exit 1 when something goes
wrong, for example when there's no log to read.

```yaml
- name: Check the agent's session
  run: agentwatch check --security --log agent-session.jsonl
```

Add `--json` to get a machine-readable report alongside the exit code.
