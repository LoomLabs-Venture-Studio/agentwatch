# AgentWatch

Real-time health and security monitoring for AI coding agents.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What is AgentWatch?

AgentWatch monitors AI agents (full support for Claude Code and Moltbot; Aider and Cursor are wired end-to-end and live-tested against real installs; Codex CLI support is fixture-verified only, while Codex in the ChatGPT desktop app, which writes the same rollouts, is live-verified on Windows; GitHub Copilot in VS Code (agent-mode chats) is live-verified on Windows against VS Code 1.140 (2026-10-09); Cline (VS Code extension and CLI) is fixture-verified only, live testing not approved; Kilo Code 7.x (CLI and VS Code extension) is fixture-verified only — see [Supported Agents](#supported-agents)) for:

- **Health Issues**: Loops, thrashing, context rot, error spirals
- **Security Threats**: Credential theft, prompt injection, data exfiltration
- **Operational Efficiency**: Token burn rate, context pressure, cache utilization

Think of it as a fitness tracker for your AI agent, plus a security guard.

### Installation

**As a CLI tool (Recommended):**

```bash
pipx install agentwatch-monitor
```

**As a library:**

```bash
pip install agentwatch-monitor
```

> [!TIP]
> Use `pipx` for CLI tools to avoid "externally managed environment" errors and keep your system Python clean.

Optional extras (`pip install "agentwatch-monitor[llm]"` / `[siem]`) add
[Tier-2 LLM analysis](#tier-2-llm-analysis-optional) and
[SIEM export](#siem-integration-optional) — everything else works with the
base install.

## Quick Start

```bash
# Health check
agentwatch check

# Security scan
agentwatch security-scan

# Real-time monitoring TUI
agentwatch watch --security

# Monitor all running agents
agentwatch watch-all

# No dashboard: log new warnings, desktop-notify on critical ones
agentwatch watch-all --headless --notify

# List running agent processes
agentwatch ps

# List every program using AI right now (any app or CLI)
agentwatch detect

# Who do local AI runtimes (Ollama, LM Studio, ...) talk to, and who can reach them?
agentwatch net

# Token usage stats
agentwatch stats
agentwatch stats --burn

# What your agents cost you this week (spend, waste, trend)
agentwatch report
```

## Scoring System

AgentWatch produces three independent scores that blend into one overall health score.

### Overall Health Score

The overall score is a weighted blend of three components:

| Component          | Weight | What it measures                                   |
| ------------------ | ------ | -------------------------------------------------- |
| **Detectors**      | 40%    | Behavioral warnings from pattern detectors         |
| **Efficiency**     | 30%    | Operational resource usage (tokens, cache, pacing) |
| **Context Health** | 30%    | Session rot (repetition, thrashing, stalling)      |

Weights are configurable via `HealthWeights(detectors=0.4, efficiency=0.3, rot=0.3)`.

### Status States

All three scoring systems share a unified 4-state status:

| Status       | Score Range | Meaning                                |
| ------------ | ----------- | -------------------------------------- |
| **Healthy**  | 80 - 100    | Everything is operating normally       |
| **Degraded** | 60 - 79     | Performance declining, monitor closely |
| **Warning**  | 40 - 59     | Significant issues, consider acting    |
| **Critical** | 0 - 39      | Immediate action needed                |

### Detector Categories

Detectors produce warnings with severity levels that deduct from a per-category score (starting at 100):

| Severity | Score Impact |
| -------- | ------------ |
| LOW      | -5           |
| MEDIUM   | -15          |
| HIGH     | -30          |
| CRITICAL | -50          |

Health detector categories and their weights in the detector score:

| Category     | Weight | What it covers                     |
| ------------ | ------ | ---------------------------------- |
| **Progress** | 35%    | Loops, stalls, thrashing           |
| **Errors**   | 30%    | Error spirals, repeated failures   |
| **Context**  | 20%    | Context rot, rediscovery, pressure |
| **Goal**     | 15%    | Currently unused (see note below)  |

> [!NOTE]
> No detector currently sets `category=Category.GOAL` (verified against
> `detectors/base.py`'s `Category` enum and every `detectors/health/*.py`
> file), so this category always has zero warnings and its per-category
> score is permanently locked at 100 — a fixed, inert +15% of the detector
> score rather than an active check. This is **not** the same thing as the
> [Goal-Alignment Advisory](#goal-alignment-advisory-also-under---llm)
> (Tier-2, opt-in via `--llm`): that's a real, working feature, but it's
> purely advisory and never feeds this row or any other score.

### Efficiency Score

Pure operational resource metrics, independent of behavioral signals. Sub-metrics grouped into three penalty categories:

| Category     | Sub-metrics                                              | What it tracks                                              |
| ------------ | -------------------------------------------------------- | ----------------------------------------------------------- |
| **Pressure** | Context pressure (30%), burn rate (20%), I/O ratio (10%) | How full the context window is and how fast tokens are spent |
| **Cache**    | Cache hit rate (15%)                                     | How effectively the session reuses cached context           |
| **Pacing**   | Duration (15%), actions per turn (10%)                   | How long the session has been running and tool call density |

Context pressure is the latest call's context (input + cache creation + cache read) as a share of the context window: 200K, or 1M once any call exceeds 200K. It drops after auto-compaction. Burn rate and I/O ratio count fresh tokens only (cache reads excluded).

Cost (estimated from token counts) is displayed as informational only and does not affect the score.

### Context Health (Rot Detection)

Deterministic rot detection tracks five metric families:

| Metric          | What it detects                                                |
| --------------- | -------------------------------------------------------------- |
| **Behavioral**  | Output length inflation, hedge word density                    |
| **Repetition**  | Repeated sentences, self-repeating n-grams                     |
| **Tool Thrash** | Repeated commands, error loops, stalls                         |
| **Progress**    | Edit deficit, file churn                                       |
| **Constraints** | Violated project constraints (forbidden paths, required files) |

The rot score uses EMA smoothing and a state machine that requires sustained degradation before escalating status.

#### Session Maturity Scaling

Progress-based metrics (edit deficit, stall detection) use **session maturity scaling** to avoid penalizing early conversation. This prevents casual greetings or questions from immediately tanking the health score.

Maturity reaches 1.0 (full penalties) when:

- Any file edit occurs (coding has started), OR
- 3+ turns of code exploration (Read/Search) without edits (agent should be coding by now)

Otherwise, penalties ramp gradually from 0.0 to 1.0 over the first 10 turns.

| Session Pattern                 | Maturity | Effect                         |
| ------------------------------- | -------- | ------------------------------ |
| Greeting + quick question       | 0.2      | Progress penalties reduced 80% |
| 3+ turns reading code, no edits | 1.0      | Full penalties (stalling)      |
| First edit on turn 1            | 1.0      | Full penalties (coding mode)   |
| 10+ turns of pure chat          | 1.0      | Full penalties (ramped up)     |

This scaling only affects progress/stall metrics. Behavioral signals (repetition, error loops, thrashing) always apply at full strength since they indicate real context degradation regardless of session phase.

## Health Detectors (15)

| Detector                  | What It Catches                                       |
| ------------------------- | ----------------------------------------------------- |
| `loop`                    | Agent repeating the same action                       |
| `reread`                  | Re-reading same file multiple times                   |
| `thrash`                  | Repeated edit -> test -> fail cycle                   |
| `stall`                   | No meaningful progress detected                       |
| `same_outcome`            | Different fixes producing the same error              |
| `file_churn`              | File edited repeatedly without a successful test      |
| `exploration_stall`       | No new files explored despite continued activity      |
| `error_class_persistence` | Same type of error persisting despite different fixes |
| `error_spiral`            | Multiple consecutive failures                         |
| `error_blindness`         | Same error repeated without fix                       |
| `syntax_loop`             | Repeated syntax/import errors                         |
| `high_error_rate`         | Unusually high failure rate                           |
| `context_rot`             | Important early files no longer being referenced      |
| `context_pressure`        | Context window filling up                             |
| `rediscovery`             | Agent re-discovering previously learned information   |

## Security Detectors (21)

| Detector               | What It Catches                                           |
| ---------------------- | --------------------------------------------------------- |
| `credential_access`    | Agent accessing credential or secret files                |
| `secret_in_output`     | Potential secret/credential in agent output               |
| `credential_exfil`     | Credential access followed by network activity            |
| `secret_leak_scanner`  | Real-time scanning for secrets leaked through any channel |
| `prompt_injection`     | "Ignore previous instructions" attacks                    |
| `hidden_instruction`   | Zero-width chars, encoded commands                        |
| `indirect_injection`   | Potential injection from external content                 |
| `network_anomaly`      | Unusual network activity                                  |
| `data_exfiltration`    | File reads followed by network activity                   |
| `c2_communication`     | Potential C2 communication pattern                        |
| `dns_exfiltration`     | Potential DNS exfiltration/tunneling                      |
| `undeclared_egress`    | Live: agent connected somewhere no action declared        |
| `privilege_escalation` | sudo, chmod +s, etc.                                      |
| `dangerous_command`    | rm -rf /, fork bombs                                      |
| `mass_file_operation`  | Mass file operation detected                              |
| `sensitive_directory`  | Access to sensitive system directory                      |
| `malicious_skill`      | Skill exhibiting suspicious behavior                      |
| `skill_network`        | Skill making network requests                             |
| `new_skill`            | New skill started executing                               |
| `skill_chain`          | Suspicious skill chaining                                 |
| `skill_install`        | New skill being installed                                 |

AgentWatch registers **36 detectors total** (15 health + 21 security), enumerated at runtime via `agentwatch.detectors.registry.get_all_health_detectors()` / `get_all_security_detectors()` — this is the source of truth if the numbers above ever drift.

Security categories and weights:

| Category     | Weight |
| ------------ | ------ |
| Injection    | 25%    |
| Credential   | 20%    |
| Exfiltration | 20%    |
| Privilege    | 15%    |
| Network      | 10%    |
| Supply Chain | 10%    |

A single CRITICAL severity security warning immediately sets the security score to 0.

## Supported Agents

| Agent                  | Process Discovery                                                | Log Parsing (health/security analysis) | Live Tailing (`watch`/`watch-all`)          | Status                                                          |
| ---------------------- | ------------------------------------------------------------------ | --------------------------------------- | -------------------------------------------- | ---------------------------------------------------------------- |
| **Claude Code**        | Yes (`~/.claude/projects/*/` logs)                                | Yes                                      | Yes                                          | Fully supported                                                 |
| **Moltbot / Clawdbot** | No (not auto-discovered by `agentwatch ps`)                       | Yes (`~/.moltbot/agents/*/sessions/` logs) | No                                          | Partial — point AgentWatch at the log file directly              |
| **Aider**              | Yes (process + `.aider.chat.history.md` located)                  | Yes (Markdown chat history; optional `--analytics-log` JSONL sidecar backfills tokens/cost) | Yes (live-tested against a real appended file) | Fully supported                                                 |
| **Cursor**             | Yes, process-gated (`Cursor.exe`/`Cursor` running -> `state.vscdb`) | Yes (SQLite composer store)             | Yes (poll-based, live-tested), including single-agent `watch --log <state.vscdb>` | Fully supported — `--all-logs` directory-scan mode doesn't apply (Cursor has no fixed directory of per-session files to glob; not a TODO) |
| **GitHub Copilot in VS Code** | Yes, process-gated (`Code.exe`/`code` running -> `workspaceStorage/*/chatSessions/*.jsonl` written in the last 30 min), one row per chat | Yes (VS Code's chat-session mutation log, replayed) | Yes (whole-file replay on change; a finished turn's actions settle 1 s before they are emitted) | Live-verified against VS Code 1.140 (2026-10-09): `ps`, the `watch-all` engine (headless), `check`; `ps` and `check` re-verified on 1.141 (2026-10-10). Token counts per turn, no cost (Copilot credits are not dollars). VS Code itself can hold a background window's session writes: one chat finished at 12:27 reached disk only at 12:42, when the window was brought up, so live views lag until then |
| **Claude Desktop (Cowork sessions)** | Yes, app-gated (Claude Desktop app exe running -> non-archived sessions active in the last 30 min under `local-agent-mode-sessions/`) | Yes (Claude Code JSONL transcript; `check --log <transcript>`) | Yes (append-only JSONL) | Fixture-verified; Windows MSIX path verified against the real file layout; app gate live-verified against 2.31226; current VM-mode Cowork sessions not visible on the host (transcript inside `sessiondata.vhdx`), only host-loop sessions surface; live `ps`/`watch-all` of a session not achieved; non-Store Windows and macOS paths unverified; MCP logs not parsed (redacted by the app) |
| **Codex CLI**          | Yes (process pattern only)                                        | Yes (rollout JSONL, fixture-verified)   | Untested                                     | Fixture-verified only — no live install exists to confirm against. macOS: source-reviewed, not live (#108) |
| **ChatGPT desktop app (Codex view)** | Yes (its bundled `codex.exe app-server` matches the Codex pattern; project taken from the rollout's `session_meta.cwd`) | Yes (same `~/.codex/sessions/` rollout JSONL as Codex CLI, including code mode's `custom_tool_call` items) | Yes (`watch-all` engine, verified headless) | Live-verified on Windows 2026-10-09 (OpenAI.Codex 26.1007.2314.0, bundled codex-cli 0.162.0-alpha) for `ps`, the `watch-all` engine and `check`, against one real code-mode thread with 2 `exec` calls. Since #105, one entry per open thread, each with a stable synthetic pid, fixture-verified only. Known gaps: `item_completed`/`CommandExecution` exit codes not correlated; the code-mode `exec` tool is classified UNKNOWN (it runs a JavaScript program that calls other tools); macOS source-reviewed, not live (#108); WSL mode and `.jsonl.zst` cold rollouts out of scope; a `CODEX_HOME` set in AgentWatch's environment but not the app's points discovery at the wrong home. Chat/Work views are server-side and not monitored |
| **GitHub Copilot CLI** | Yes (native `copilot` binary; session found via `$COPILOT_HOME/session-state/*/inuse.<pid>.lock`) | Yes (`events.jsonl`) | Yes (live-tested)                            | Live-verified against Copilot CLI 1.0.90 (2026-10-01); no token counts (Copilot only logs session totals) |
| **Antigravity CLI (`agy`)** | Yes (`agy` process; conversation found via the `presence/<id>.lock` it holds open) | Yes (`~/.gemini/antigravity-cli/brain/<id>/.system_generated/logs/transcript.jsonl`) | Yes (append-only transcript) | Live-verified against agy 1.2.14 (2026-10-01); no token counts in the transcript |
| **OpenCode**           | Yes (`opencode` binary; newest top-level session whose `directory` is the process cwd) | Yes (read-only SQLite `~/.local/share/opencode/opencode.db`, or `$XDG_DATA_HOME/opencode/`; `check --log <opencode.db>`) | Yes (poll-based) | Parser built from real opencode 1.18.34 sessions (scrubbed fixture), matches the 2026-10-05 live research; `ps`/`watch-all` against a running opencode not yet live-verified |
| **Kilo Code 7.x** (CLI `kilo`, and the VS Code extension `kilocode.kilo-code`, which runs a bundled `kilo serve`) | Yes (native `kilo`/`kilo.exe` binary, npm's node wrapper not counted; newest top-level session whose `directory` is the process cwd, as OpenCode) | Yes (OpenCode's parser on read-only SQLite `~/.local/share/kilo/kilo.db`, or `$XDG_DATA_HOME/kilo/`, or `KILO_DB`; `check --log <kilo.db>`) | Yes (poll-based, OpenCode's watcher) | Fixture-verified only against the Kilo-Org/kilocode source (@ ff20ca7); no live install. Known limits: in the VS Code extension only sessions in the window's first workspace folder are found (Agent Manager worktree sessions and other multi-root folders are not); dev-channel `kilo-<channel>.db` not looked for; a `KILO_DB` not named `kilo*.db` is labelled OpenCode; Kilo 5.x (Roo-style `globalStorage` tasks) out of scope |
| **Gemini CLI**         | Yes (`node .../@google/gemini-cli/bundle/gemini.js`; project found via `~/.gemini/projects.json`, newest session in its `chats/`) | Yes (`~/.gemini/tmp/<project>/chats/session-*.jsonl`, incl. per-turn tokens) | Yes (append-only JSONL) | Fixture-verified against the gemini-cli 0.62.0 source; not yet live-verified |
| **Cline** (VS Code extension `saoudrizwan.claude-dev`, and the Cline CLI) | Yes, from two stores. Legacy extension: process-gated per editor (VS Code `Code.exe`/`code`, VS Code Insiders `Code - Insiders.exe`/`code-insiders`, VSCodium `VSCodium.exe`/`codium`, Cursor `Cursor.exe`/`cursor` running -> that editor's `User/globalStorage/saoudrizwan.claude-dev/tasks/*/api_conversation_history.json` written in the last 30 min; the command column names the editor, e.g. `vscode-insiders (cline)`). SDK store (new extension and Cline CLI): `~/.cline/data/sessions/<id>/` (or `CLINE_SESSION_DATA_DIR`/`CLINE_DATA_DIR`/`CLINE_DIR`), a session whose manifest status is not finished and whose pid is alive; `source` (`vscode`, `cli`, ...) shown in the command column | Yes (Anthropic-style messages; per-request tokens and Cline's own cost; `check --log <file>`) | Yes (whole-file reparse on change; a tool call is emitted once its result exists; a torn read of the SDK file is skipped) | Fixture-verified only against the cline/cline source (`main` @ a484089, `legacy-extension` @ 7761370); live testing not approved. Known limits: legacy tasks on models without native tool calling (tool calls as XML in text) show token counts only; legacy failures are detected from Cline's English result strings; Insiders/VSCodium/Cursor stores are source-verified, not live; Windsurf not supported (no public source for its User folder, #116); non-default VS Code profiles, remote/WSL, subagent transcripts out of scope; Roo Code (#117) and Kilo Code 5.x (#118, out of scope) not supported (`check --log` routes an `api_conversation_history.json` by its `globalStorage/<extension id>/` parent, so theirs are not parsed as Cline; outside `globalStorage` (a copy, or a fork's `customStoragePath` store) a task with a sibling `history_item.json` (Roo Code 3.49.0+) is not read as Cline, but Kilo Code 5.x and older Roo tasks still are); legacy `prompt` tokens depend on the provider (cache excluded for Anthropic) |

Verified against `src/agentwatch/discovery.py` (`AGENT_PATTERNS`, log-file resolution, `psutil`-based on all platforms including Windows) and `src/agentwatch/parser/logs.py` (`detect_log_format`, `parse_claude_code_entry`, `parse_moltbot_entry`). Aider Markdown log parsing lives in `src/agentwatch/parser/aider.py` (`parse_aider_log`, `AiderLogWatcher`); Cursor's read/poll layer lives in `src/agentwatch/parser/cursor_source.py` and `src/agentwatch/cursor_discovery.py`; GitHub Copilot in VS Code's are `src/agentwatch/agents/copilot_vscode.py` and `src/agentwatch/parser/copilot_vscode.py` (`CopilotVscodeWatcher` in `parser/watcher.py`); Copilot CLI's adapter is `src/agentwatch/agents/copilot.py` and its `events.jsonl` parser `src/agentwatch/parser/copilot.py`; agy's are `src/agentwatch/agents/agy.py` and `src/agentwatch/parser/agy.py`; OpenCode's are `src/agentwatch/agents/opencode.py` and `src/agentwatch/parser/opencode.py` (`OpencodeWatcher` in `parser/watcher.py`); Kilo Code's adapter is `src/agentwatch/agents/kilo.py`, a subclass of OpenCode's that reuses its parser and watcher; Gemini CLI's are `src/agentwatch/agents/gemini.py` and `src/agentwatch/parser/gemini.py`; Cline's are `src/agentwatch/agents/cline.py` and `src/agentwatch/parser/cline.py` (`ClineWatcher` in `parser/watcher.py`); Codex's rollout JSONL parsing lives in `src/agentwatch/parser/codex.py` and has been hardened against the real `openai/codex` source but still has no live install to verify against.

## Usage

### One-Time Health Check

```bash
# Auto-detect latest session
agentwatch check

# Specific log file
agentwatch check --log ~/.claude/projects/myapp/session.jsonl

# Aider Markdown chat history (auto-detected by .md extension)
agentwatch check --log ./.aider.chat.history.md

# ...with an optional --analytics-log sidecar to backfill tokens/cost
agentwatch check --log ./.aider.chat.history.md --analytics-log ./analytics.jsonl

# Include security checks
agentwatch check --security

# JSON output (for CI/CD)
agentwatch check --json
```

`check` also reports session efficiency (the same numbers as the TUI's
efficiency bar). With `--json` it is an `efficiency` object: `score`,
`status`, `context_usage_pct`, `token_burn_rate`, `io_ratio`, `cost_total`,
`cost_velocity`, `cache_hit_rate`, `actions_per_turn`, `duration_minutes`
and the `penalty_*` rollups. Efficiency is informational: it does not
change the exit code.

### Security Scan

```bash
# Security-only scan
agentwatch security-scan

# JSON output
agentwatch security-scan --json
```

### Real-Time Monitoring

```bash
# Single agent TUI
agentwatch watch

# With security monitoring
agentwatch watch --security

# All running agents
agentwatch watch-all
```

`watch-all` shows one row per session: status (`●` active, `○` idle 5+
minutes; stopped rows are grey), agent, project, health (`▲`/`▼` while it is
5+ points off its value a minute ago), estimated cost (`n/a` when the model has no known
price), context window fill, time since the last action, and the top
warning (`ok` when none). With `--budget`, the cost column is `COST / BUDGET`:
`$4.12 / $5.00 ▮▮▮▯` (a 4-cell bar; amber from 80%, red once hit; `n/a` with
no known price; under 100 columns `$4.12 ▮▮▮▯`). When the Claude Code
plugin's loop breaker has blocked a call in a session, its top warning reads
`⛔ loop blocked: Bash (7x) $1.40` (the command itself is never shown).
Rows sort by attention: Critical and loop-blocked sessions first, then HIGH
warnings, other warnings, active sessions by recency, idle and stopped last.
Subagents are listed under their parent (`└ sub`), and a team's sessions
under its `TEAM` row (the team sorts by its most urgent member). Sessions with
no action for 15+ minutes, and stopped ones, fold into one `○ … N idle (a to
show)` row at the bottom (a parent stays shown while one of its subagents is);
`a` shows them, `a` again folds them. `/` opens a filter line at the bottom:
rows whose project, agent or top warning contain the text (any case) are
shown as you type (a matching subagent with its parent); Enter keeps the filter (`filter: xyz` next to the sort),
Esc clears it. Below the table, the
selected session's health, efficiency, context, cost per minute, security
findings, network endpoints and top 3 warnings.

`watch-all --all-logs` reads every log under the known log directories
instead of discovering running processes. By default only logs modified in
the last 24 hours are loaded (older ones are not read at all, and one shows up
once it is written to again); `--since 6h`, `--since 2d` or `--since all`
changes that. The Events panel says how many were loaded
(`23 sessions loaded (last 24h of 118 logs)`). Each session is shown by its
project name: for Claude Code the last part of the working directory its
transcript records (a `.claude/worktrees/...` worktree counts as its project,
the home directory is `~`), else its `~/.claude/projects` folder; other agents
as `agentwatch history` names them. Claude Code subagent logs sit under their
session. The log file is on the detail view's Process tab.

The header line counts sessions, active ones and those that need you (Critical,
or a HIGH or worse warning), the estimated cost of the sessions on screen
(not your history: `agentwatch report` has that), alerts this run (sent to
`--notify`/`--webhook`; without those, new HIGH or worse findings), loop
breaker blocks this run (`blocks N`, including sessions already blocked at
startup), the per-session `--budget` limit when set (`budget $5.00/session`),
and the time. When the line does not fit, the clock goes first (and the cost
reads `spent $X`), then the `agentwatch` title, then `N active`.

The layout follows the terminal size (recomputed only on a resize). Under 100
columns the AGENT and CTX columns and the Selected strip are hidden (Enter
shows them; the filter still matches the agent), PROJECT is shorter and TOP
SIGNAL takes the rest of the width. Under 30 rows the Events panel shows 3
lines; under 20 rows it is hidden and `e` shows it in place of the table (`e`
or Esc goes back). An 80x24 terminal shows 13 session rows.

The Events panel at the bottom lists, newest first: sessions started
and stopped, each new warning (one line per finding) and when it clears,
alerts sent, a loop breaker block (`⛔ proj loop breaker blocked a repeated
call (~$1.40)`), `s` (`security on: N findings` / `security off`, one line,
not one per finding), and with `--budget` a session reaching 80% and 100% of it.
Warnings and blocks a session already has when it is first seen are not
listed (one "N sessions loaded; M loop blocks so far" line at startup
instead). Loop breaker state is the coach's per-session state file, read
only: its modification time is checked every 2 seconds and the file is read
only when it changed. watch-all finds that file through the plugin's data dir
(`~/.claude/plugins/data/agentwatch-*/coach`) or the pointer the hook leaves
in the per-user cache (`$XDG_CACHE_HOME/agentwatch/coach`); if the hook and
watch-all run with different `XDG_CACHE_HOME` values and the plugin data is
outside `~/.claude/plugins/data`, it can't.

Enter opens the selected session full screen, in four tabs: Health (overall
health and its status, efficiency, context health, actions/errors/duration
and every warning with its suggestion and cost; plus a `Loop breaker:` line:
`armed (Nx)`, `blocked once`, `not armed`, or
`off in this shell (AGENTWATCH_LOOP_BREAKER=off)`: the variable is read
from watch-all's environment, not the hook's), Security (findings, or how
to turn security mode on, plus raw counts of credential file accesses,
privilege commands, network actions and injection-like messages), Network
(the remote endpoints seen during its actions) and Process (pid, type,
uptime, working directory, CPU, memory, team, session id; `n/a` with
`--all-logs`). It updates every second. A session is rescored only when it
has new actions (or after `s`), the same for every session.

Keys: arrows select a session, Enter opens it, `o` cycles the sort
(attention, cost, recent), `a` shows/folds idle sessions, `/` filters,
`e` focuses the Events panel to scroll it (`e` or
Esc goes back), `s` toggles security detectors, `?` shows a help screen (the
keys, what the columns and icons mean, and the main flags; Esc, `?` or `q`
closes it), `q` quits. The footer lists the most used keys first. In the detail
view: Tab/Shift+Tab or `1`-`4` switch tabs, arrows and PgUp/PgDn scroll, Esc,
Backspace or `q` go back to the table.

While `watch` / `watch-all` run, AgentWatch polls each agent process's
sockets (and its child processes') about once a second, unprivileged, and
records which remote endpoints (IP, port) were open during each action. The
stats line (in `watch-all`, the selected session's strip) shows `Net: N endpoints`. With `--security`, the
`undeclared_egress` detector warns when the agent connects to an address
that no action declared (a WebFetch host) and that is not a known LLM
provider (the `detect` list) or agent vendor host (Claude Code telemetry
and updates). Typical hit: a Bash `npm install` or a script phoning home.
Loopback and link-local addresses are ignored; private (LAN) addresses are
flagged. Its only network traffic is DNS lookups of those hosts.

Limits: connections that open and close within one poll (about 1 s) are
missed; there are no byte counts; matching is by IP, so a CDN address shared
with an allowed host hides an undeclared one, and behind a proxy or VPN
every connection goes to the proxy. Editor-hosted sessions (Cursor, Copilot
in VS Code, Cline, Claude Desktop, ChatGPT-app Codex threads, `kilo serve`)
share one process with other sessions, so they are not sampled
(`Net: n/a (not attributable)`), nor are `opencode serve`, Aider (its log
has no real per-action times) or `watch-all --all-logs`. Single `watch` of
an OpenCode/Kilo database finds no process (`Net: no live process`); use
`watch-all`. One-shot `check` / `security-scan` never sample. Claude Code,
Codex and Gemini log a tool call when it starts, so a Bash command's
connection may be reported on the next action.

### Alerts

Agents run unattended, so AgentWatch can tell you when a session goes bad
without a dashboard on screen.

```bash
# No dashboard: one line per new warning on stdout; Ctrl+C to stop
agentwatch watch-all --headless

# Desktop notification on a Critical session or a new CRITICAL finding
agentwatch watch-all --notify
agentwatch watch --notify --security

# Also alert on HIGH findings
agentwatch watch-all --headless --notify --notify-min high

# Post alerts to a Slack (or Discord/Teams-style) incoming webhook
agentwatch watch-all --headless --webhook https://hooks.slack.com/services/...
export AGENTWATCH_WEBHOOK=https://hooks.slack.com/services/...   # same, from the environment (--webhook wins if both are set)
```

Headless output looks like:

```
14:02:11 HIGH     Claude Code · myproj [loop] Repeated action: Bash (8x)  ~$1.40 · 210k tok
```

An alert reads `agentwatch: Claude Code · myproj — loop ~$1.40`, followed
by the warning's own message with secrets redacted; no other transcript
content is sent. You get one alert per finding per session (it alerts again
if the finding clears and comes back) and at most one "critical" alert per
session every 10 minutes. `--notify-min` (`critical` by default, or `high`)
applies to `--notify` and `--webhook`; the headless log shows every new
warning.

Findings a session already has when AgentWatch first sees it (its log's
history, at startup or when a session is discovered later) are a silent
baseline, so opening `watch-all` over old sessions does not fire a burst of
alerts; only findings that appear afterwards, and a session turning
Critical afterwards, alert. Add `--notify-existing` to alert on those too.
The headless log still prints them.

- **Windows:** a toast from Windows PowerShell (`powershell -NoProfile`,
  shown under "Windows PowerShell" in the notification center). If the toast
  fails, AgentWatch beeps and warns once.
- **macOS:** `osascript` (`display notification`). Allow notifications for
  Script Editor / your terminal in System Settings if nothing appears.
- **Linux:** `notify-send`, if it is on `PATH` (package `libnotify-bin` or
  `libnotify`).
- No notifier: one warning on stderr, then monitoring continues.

The webhook gets `POST` JSON `{"text": "..."}` (5 s timeout, sent in the
background). The URL is a secret: AgentWatch never prints it (errors show
`https://hooks.slack.com/***`), and a failing webhook is reported once and
never stops monitoring. `AGENTWATCH_WEBHOOK` is only read, never written; if both it and
`--webhook` are set, the flag wins.
Redirects are not followed (a 3xx counts as a failure), `& < >` are escaped
so a path or repo name cannot ping `<!channel>` or post a disguised link, and
a plain `http://` URL gets a startup warning (alert text would travel
unencrypted).

Alert text is one line per field: control characters (terminal escapes,
bells, newlines) become spaces and long names are cut, so a crafted project
name cannot clear your terminal, write your clipboard or fake a log line.
Alerts are delivered one at a time; if more than three pile up, they arrive
as one summary (`agentwatch: 12 new alerts`).

Run headless in the background:

```bash
# macOS / Linux
nohup agentwatch watch-all --headless --notify > ~/agentwatch-alerts.log 2>&1 &
```

```powershell
# Windows (PowerShell)
Start-Process agentwatch -ArgumentList "watch-all","--headless","--notify" `
  -WindowStyle Hidden -RedirectStandardOutput "$env:USERPROFILE\agentwatch-alerts.log"
```

A hidden window has no Ctrl+C; stop it with `Stop-Process -Name agentwatch`.

`--headless` runs the same engine as the `watch-all` dashboard (process
discovery every 5 s, per-agent scoring); it only skips drawing it.

#### Budget alert

```bash
# One alert per session when its estimated cost reaches $5
agentwatch watch-all --budget 5
agentwatch watch-all --headless --budget 5 --webhook https://hooks.slack.com/services/...
```

The alert reads `agentwatch: Claude Code · myproj — budget $5.00 hit` with
`session cost $5.12` as its body (headless also prints one `BUDGET` line).
Each session alerts once, the first time its cost reaches or passes the
limit; it does not repeat as the cost keeps rising. A session already over
budget when AgentWatch first sees it alerts at startup (the budget alert is
not part of the silent baseline). `--budget` alone turns on `--notify`, so
the regular Critical/finding desktop alerts are on too; add `--webhook`
instead to get only the webhook (add `--notify` for both). The amount must
be a positive number of USD.

Agents whose cost AgentWatch cannot price (Codex, Gemini, Copilot VS Code)
can never trigger it, and `agentwatch statusline` does not show the budget.

### Process Discovery

```bash
# List running agent processes with PIDs and session IDs
agentwatch ps

# JSON output for scripting
agentwatch ps --json
```

### AI-Use Detection

```bash
# Programs on this machine using AI right now, supported or not
agentwatch detect

# JSON output for scripting
agentwatch detect --json
```

`agentwatch detect` lists programs that are talking to an AI provider
(Anthropic, OpenAI, Copilot, Cursor, Mistral, xAI, DeepSeek, OpenRouter,
Groq) or serving a local LLM (Ollama, LM Studio, llama.cpp, Jan, GPT4All,
Msty) right now,
including ones agentwatch can't monitor yet. Browsers are excluded. It is
local and read-only: it reads process names, executable paths and socket
tables, and its only network traffic is DNS lookups of those providers'
domains (your DNS resolver will see them). Live-verified on Windows
(unelevated). On macOS/Linux, other users' processes need root and the scan
is reported as partial; this path is fixture-verified only. Attribution is
by provider IP, so a provider whose API shares IPs with its other services
can't be told apart; Google (Gemini) is left out for that reason.
The SUPPORTED column (`adapter` in `--json`, a string) names the agentwatch
adapter for each program. One editor process can host its own adapter and
Cline, so it is labelled with every one of them that has a live session in
that editor (e.g. `copilot-vscode, cline` for `Code.exe`/`code`,
`cursor, cline` for `Cursor.exe`/`cursor`), or its own adapter if neither
does. VS Code Insiders and VSCodium processes are labelled `cline`, the only
adapter that monitors them. A Cline task counts only for the editor whose
store it is in; a Cline SDK-store session with source `vscode` doesn't name
the fork, so it counts for stable VS Code only. Connections are not split
between adapters.

### Local AI Network Activity

```bash
# Live: one line per new outgoing endpoint, listener or client; Ctrl+C prints a summary
agentwatch net

# One sample, summary table
agentwatch net --once

# NDJSON events (stream) or one JSON document (--once)
agentwatch net --json
agentwatch net --once --json

# Also watch any other process tree; poll every 2 s
agentwatch net --pid 1234 --pid 5678 --interval 2

# Headless: run 10 minutes, then print the summary (or the JSON summary event)
agentwatch net --json --duration 600

# Also watch running agents (Claude Code, Aider, opencode, ...) with their own process
agentwatch net --local
agentwatch net --local --once --json
```

Ctrl+C, SIGTERM and (Windows) Ctrl+Break or closing the console all print
the summary, the only place with a final last-seen time. A headless
background run on Windows can't be stopped gracefully (`taskkill` without
`/F` refuses), so use `--duration` there.

`agentwatch net` answers "does a local AI talk to external servers, and if
so, to whom?". It finds local LLM runtimes by exact process name: Ollama
(`ollama`, `ollama app`), llama.cpp (`llama-server`), llama-cpp-python
(`python*` running `llama_cpp.server`), LM Studio (`LM Studio`, `llmster`,
`lms`), Jan (`Jan-Desktop`, `jan`, `jan-llama-worker`), GPT4All (`gpt4all`,
or `chat` from a `gpt4all` install), and Msty (`msty`, `Msty Studio`,
`msty-local`, `MstySidecar*`). `--pid N` adds any other process (a pid with
no process is reported: `pid N not found` on stderr, `missing_pids` in JSON;
`--pid 0` is refused). Each
target's whole process tree is sampled every `--interval` seconds (default
1). Nothing is allow-listed, not even the AI-provider and agent-vendor
hosts that `detect` and `undeclared_egress` accept: every remote endpoint
that isn't loopback, link-local or multicast is reported with the owning
process, first/last seen, tcp/udp, and a name. Names are tried in order:
1. the Windows DNS client cache (`dns-cache`);
2. `known`: a guess. The IP matches a forward lookup of a known host: the AI
   providers, agent vendor hosts (Datadog intake, `downloads.claude.ai`) and
   each runtime's by-design hosts (e.g. `registry.ollama.ai`,
   `huggingface.co`, `lmstudio.ai`). The lookups are refreshed every 5 min. A
   CDN IP shared by several known hosts lists all of them (`a|b`);
3. reverse DNS (`rdns`);
4. the bare IP (`ip`).
Private (LAN) addresses are kept and tagged `LAN` (`"lan": true`). If no
runtime is running it says so and, in stream mode, waits for one to start.
Unprivileged and read-only; its only network traffic is DNS lookups: the
known hosts, and reverse lookups of the IPs it finds.

Incoming: every TCP listener in a runtime's tree is listed. One bound to all
interfaces (`0.0.0.0` / `::`) or to any non-loopback address is flagged
`EXPOSED` (`"exposed": true`, `scope` `all interfaces` or `lan`), because
other machines can reach it (an exposed Ollama API is a known risk). A
loopback-only listener is listed as `loopback` and not flagged. Clients
connected to a listener are listed too. A local client is shown by process
name and pid (`curl.exe(4321) [local]`), found in the system socket table.
A remote client is named like an outgoing endpoint and tagged `lan` or
`public`. A client inside the runtime's own tree is internal and not listed
(e.g. `ollama serve` talking to its `llama-server` child). One in another
tree, such as the `ollama run` CLI, is listed. A local client counts once per
process, however many ports it reconnects on. The summary adds LISTENERS and
CLIENTS tables (`listeners` / `clients` in JSON) and ends with
`N listener(s) reachable from other machines` when any was exposed.

AI providers: an outgoing endpoint, of any target, whose IP belongs to an AI
provider domain (the `detect` list: `api.anthropic.com`, `api.openai.com`,
...; matched by the known-host lookups or the DNS-cache name) is flagged
`AI-PROVIDER <name>` (`"ai_provider": "anthropic"`, else `null`). The summary
adds `N connection(s) to cloud AI providers (from ...)`. Flagged is not
hidden: every endpoint is still reported, and agent vendor hosts (Datadog
intake, `downloads.claude.ai`) are reported and named but not flagged.

`--local` adds running agents that `agentwatch ps` finds, as targets
`agent:<type>` (e.g. `agent:aider`, `agent:claude-code`), for agents on
local models (Aider or opencode pointed at Ollama, ...). Their cloud
AI-provider traffic is flagged, not allowed. An agent counts only if its
pid is its own process (the process's command line, read in memory and
never stored, matches that agent). Agents are re-discovered in the
background every 5 s; `--once` waits for one discovery. A runtime started
from an agent (Ollama launched in a Claude Code shell) stays its own target
(`ollama`), and so does an agent started by a runtime: each target's walk
skips the other targets' subtrees, so nothing is counted twice. Only a
runtime inside another runtime (`ollama serve`'s `llama-server`) is covered
by its parent. An agent's connection to a watched runtime (Aider -> Ollama
on `127.0.0.1:11434`), or one from a tool the agent started, shows as a
local client of that runtime, by process name. Editor-hosted agents
(Cursor, Copilot in VS Code, Cline, Claude Desktop/Cowork), Codex app-server
threads, and agents whose command line can't be read have no verifiable
process of their own, so they aren't watched. They are counted once:
`N agent(s) without a verifiable own process not watched (...; use --pid
<pid>)`, `unwatched_agents` in JSON.

Known limits:
- No ICMP (needs admin); unconnected UDP isn't seen either.
- Connections opened and closed within one poll interval are missed.
- DoH, a VPN or a proxy hides hostnames: you see the proxy or resolver IP,
  and the DNS client cache may be empty (the name falls back to rdns or IP).
- Agents hosted in an editor (Cursor, Copilot, Cline, Claude Desktop) attribute
  to the editor process: `--local` skips them, so watch the editor with
  `--pid <editor pid>` (its own traffic is mixed in).
- `--local` can't verify an agent whose command line it may not read (another
  user's or an elevated process); it is counted as not watched.
- An agent target covers its whole process tree, so traffic of the tools it
  runs (git, npm, curl, an MCP server) shows as `agent:<type>`.
- Agent discovery runs in the background (it takes seconds), so a newly
  started agent appears a few seconds late and its first connections can
  be missed.
- WebView2/Chromium endpoints (an app's embedded browser) often stay a bare
  IP: Chromium resolves DNS itself, so the Windows DNS client cache has no
  entry for them.
- LM Studio's `lms` starts the app detached, so the app is matched by its own
  name, not through `lms`'s process tree.
- Ollama CLI calls (`ollama run`, `ollama list`, ...) are their own short-lived
  `ollama.exe` processes, so each shows up as a target with a STARTED/STOPPED
  pair; their traffic goes to the local server on loopback and isn't listed.
- Reverse lookups run concurrently, at most ~2 s per poll. A slower one shows
  the bare IP at first, and the summary picks up the name once it arrives.
- Reverse DNS often names the cloud host, not the service: e.g. `ollama.com`
  shows as `15.133.36.34.bc.googleusercontent.com [rdns]` when no known-host
  lookup matches.
- A runtime's embedded browser shows up under that runtime with its own
  process name (e.g. the Ollama app's `msedgewebview2.exe` UI, talking to
  Microsoft hosts).
- Short client requests (`ollama list`, a one-shot `curl`) are usually over
  within one poll and missed, like short outgoing connections.
- A client on this machine that connects through one of its LAN IPs is still
  found in the system socket table and shown as local. Without access to that
  table (macOS without root) each process is read instead, so other users'
  client processes can be missed: a loopback one still shows as `[local]`
  without a name, and a LAN-IP one shows as a `lan` client.

### Token Usage Stats

```bash
# Stats for current project
agentwatch stats

# Stats across all projects
agentwatch stats --all

# Analyze a specific session
agentwatch stats --session <SESSION_ID>

# Efficiency analysis — see how many tokens went to trivial
# commands (git, ls, npm run dev) vs substantive AI work
agentwatch stats --burn

# JSON output
agentwatch stats --json
```

### Weekly Report

What your agents cost you, across every agent and project, from a local
history of your sessions.

```bash
# Last 7 days: spend, waste, costliest findings, per agent/project, trend
agentwatch report

# Other period, one agent or project, JSON
agentwatch report --days 30
agentwatch report --agent claude-code --project web
agentwatch report --json

# The history behind it
agentwatch history sync              # only new or changed logs are read
agentwatch history sync --days 14    # only logs written in the last 14 days
agentwatch history prune --older-than 90d
agentwatch history path
```

```
agentwatch report: last 7 days (2026-10-11 to 2026-10-18)

  Sessions 83   Spend ~$222.11   Tokens 380.4M
  Waste: ~$10.72 (5%) on stalls, loops, rereads and repeated errors
  vs previous 7 days: spend +$103.57, waste +$10.52  (43 sessions, ~$118.54)
  Note: 1 session without a price (no token data or an unlisted model): n/a, left out of spend and %.

  Costliest findings
    exploration_stall      web                        ~$3.87  2026-10-18
    ...
```

- `report` syncs first (this period and the one before; `--no-sync` skips
  it). A session counts in the period of its last action. Logs written in
  the last 60 s are still being written and wait for the next sync
  (`history sync --include-active` takes them).
- Spend is each API call once, priced like `check`. Waste is `check`'s waste
  figure (the calls behind health findings, a call shared by two findings
  once) summed over sessions. A session with no token data or an unlisted
  model is n/a: counted, but left out of spend and the waste %, never
  guessed.
- Security counts findings, not secrets: leak findings (credential
  category; one secret can raise more than one, e.g. `secret_leak` and
  `secret_in_command`), egress (network, exfiltration), injection and other
  (privilege, supply chain). Dates are UTC.
- Sources: Claude Code (subagent transcripts too), Codex, Copilot CLI,
  Gemini CLI, Antigravity, Copilot in VS Code and Cline, one session per log
  file. Not yet: Cursor, OpenCode and Kilo (one database holds every session)
  and Aider (no fixed log location).

**What is stored.** One SQLite file, `history path` (`%LOCALAPPDATA%\agentwatch\history.db`
on Windows, `$XDG_DATA_HOME/agentwatch/history.db` or
`~/.local/share/agentwatch/history.db` elsewhere; the folder is 0700 on
POSIX). Per session: agent, session id, project folder name (the last part of
the path only, `~` for the home folder), a hash of the log path, first/last action time, action count,
tokens, USD (empty when unknown), the waste figure, health score and status,
the log's size and mtime. Per finding: a hash of its identity, signal,
severity, category, tokens, USD, first seen, and for health findings a short
message (one line, at most 120 chars, secrets redacted, paths cut to the file
name). No transcript text, prompts, commands, tool output or full paths.
With the Microsoft Store Python the file is redirected like the coach state
(see the Claude Code plugin section): `history path` prints the path
agentwatch uses, the bytes live under `...\Packages\PythonSoftwareFoundation.Python.3.X_<id>\LocalCache\Local\agentwatch`.
Nothing leaves the machine. Kept until `history prune` (no limit by default);
a sync without `--days` re-reads pruned sessions whose logs are still on disk.

`report --json` (schema 1, fields only added, never renamed):

| Key | Content |
|-----|---------|
| `schema` | `1` |
| `period` | `days`, `start`, `end` (ISO 8601 UTC) |
| `filters` | `agent`, `project` (null when not given) |
| `totals` | `sessions`, `unpriced_sessions`, `cost_usd`, `tokens`, `waste_usd`, `waste_pct`, `waste_findings` |
| `previous` | the same as `totals`, for the period before |
| `trend` | `cost_usd`, `waste_usd`: this period minus the previous one |
| `top_findings` | up to 3: `signal`, `severity`, `agent`, `project`, `cost_usd`, `tokens`, `date` (UTC), `message` |
| `by_agent`, `by_project` | `totals` fields plus `agent` / `project`, costliest first |
| `security` | finding counts: `total`, `leaks`, `egress`, `injection`, `other` |

USD values are null when unknown (no priced session, or no previous period).

### Scrub Secrets and Personal Info

```bash
# Hide secrets and personal info in one file; writes notes.scrubbed.txt
agentwatch scrub notes.txt

# See what would be hidden (masked), write nothing
agentwatch scrub notes.txt --dry-run --json

# Overwrite the file, keeping the original as notes.txt.bak
agentwatch scrub notes.txt --in-place

# Secrets only, leave emails/phones/etc. alone
agentwatch scrub notes.txt --secrets-only

# One Claude Code session log: writes <log>.scrubbed.jsonl, the copy to share
agentwatch scrub <log>.jsonl --dry-run --json
agentwatch scrub <log>.jsonl

# Many Claude Code session logs, in place
# (skips the log of a session that is still running)
agentwatch audit --all --pii
agentwatch audit --all --redact --pii
```

`audit` does not look at user prompts or tool results, so personal info
typed into a prompt stays in the log after `audit`. To share a session log,
use the `scrub` copy, which covers every line.

Personal info is emails, phone numbers, SSNs, card numbers and US street
addresses. A `.bak` still holds the original values; delete it once you have
checked the result. Rotate any leaked key: hiding it does not make it safe.

### AgentGuard (Security-Focused CLI)

```bash
# Same tool, security-first defaults
agentguard scan
agentguard watch
```

## Exit Codes

| Code | Meaning             |
| ---- | ------------------- |
| 0    | Healthy or Degraded |
| 1    | Warning             |
| 2    | Critical            |

Use in CI/CD:

```bash
agentwatch check --json || echo "Agent health issues detected"
agentwatch security-scan || echo "Security issues detected"
```

`scrub` uses its own codes (2 is an error here, not a critical finding):

| Run     | 0             | 1               | 2     |
| ------- | ------------- | --------------- | ----- |
| real    | done          | -               | error |
| dry run | nothing found | found something | error |

## Scrub Skill (Claude Code)

A Claude Code skill that runs `scrub`/`audit --pii` for you when you ask to
scrub, sanitize or redact a file, or are about to share a log. It always
dry-runs first and never prints the raw values. For one session log it uses
`scrub` (a clean copy that also covers prompts and tool results); for
in-place redaction across many logs it uses `audit --redact --pii`, which
skips prompts and tool results. It moves a scrubbed session log out of
`~/.claude/projects/` so it is not counted as another session. It ships in the
[Claude Code plugin](#claude-code-plugin-coach), or install it alone by copying the
folder:

```bash
cp -r plugin/skills/agentwatch-scrub ~/.claude/skills/agentwatch-scrub
```

Claude Code only.

## Claude Code plugin (coach)

The `agentwatch` plugin coaches Claude Code while it works. After every tool
call a hook runs agentwatch's health detectors on the live session. When a
new HIGH or CRITICAL loop, thrash, error spiral or stuck pattern shows up, it
adds a short note to Claude's context (what is wrong, the evidence, what to
try). It reports each problem once per session, again only if it clears
and comes back. Context-size estimates are not coached. The plugin also
includes the scrub skill.

**Loop breaker.** When the same action has run 6 or more times in the last
10 tool calls (a HIGH loop), the plugin's PreToolUse hook blocks the next
identical call once and tells Claude why: "agentwatch blocked this call: the
same action ran 6 times in the last 10 calls (~$0.42 so far). Change
approach: read the last error and fix its cause, or ask the user." A retry
right after the block is allowed (one block per loop); once the loop is no
longer HIGH it is forgotten, so a new loop blocks again. Bash commands that
repeat on purpose are never blocked (the warning still fires): `sleep`,
`gh run watch`, `gh pr checks`, `git status`, `git log`, `git diff`,
`pytest`, `python -m pytest`, `python3 -m pytest`, `uv run pytest`,
`npm test`, `npm run test`, `pnpm test`, `pnpm run test`, `yarn test`,
`yarn run test`, `bun test`, `npx jest`, `npx vitest`, `cargo test`,
`go test`, `make test`, `./gradlew test`, `mvn test`. They match as whole
words, after any leading `cd <path> &&` and `VAR=value` prefixes (so
`cd app && pytest` is allowed, `sleepy` is not). It reads only the coach's
state file (no transcript parsing); the armed loop entry holds only a hash of
the action, its count and cost, never the command or path. Any error lets the
call through. Set
`AGENTWATCH_LOOP_BREAKER=off` (board approved; default on) to turn it off.
Claude Code only: other agents have no PreToolUse hook and keep getting
warnings in `watch`/`watch-all` and alerts.

The plugin needs agentwatch **0.2.0 or later** on your PATH (`agentwatch hook`
is not in 0.1.x, the current PyPI release). Until 0.2.0 is on PyPI, install
from git:

```bash
pipx install git+https://github.com/LoomLabs-Venture-Studio/agentwatch@develop-overdrive
```

Then add the plugin. `/plugin marketplace add owner/repo` reads the default
branch, which has no `plugin/` yet, so pin the branch with `#ref` for now:

```
/plugin marketplace add LoomLabs-Venture-Studio/agentwatch#develop-overdrive
/plugin install agentwatch@agentwatch
```

Once `plugin/` is on the default branch, drop the `#develop-overdrive`. On
Claude Code 2.1.275+ one step also works:
`/plugin install agentwatch --marketplace LoomLabs-Venture-Studio/agentwatch#develop-overdrive`.
To try it from a checkout without installing: `claude --plugin-dir ./plugin`.

If `agentwatch` is not on PATH the hook does nothing. Any error, bad input or
missing transcript also exits 0 silently. Subagents are coached from their
own transcript. The note quotes tool output as evidence (with `<`/`>`
removed); its advice line is fixed text. Dedup state is a small JSON file per
session in the plugin's data dir (`$CLAUDE_PLUGIN_DATA/coach`), or else
`%LOCALAPPDATA%\agentwatch\coach` on Windows and `~/.cache/agentwatch/coach`
elsewhere (`0700`, never the shared temp dir). If the plugin's data dir
cannot be written, the per-user dir is used instead. It also holds that
session's latest health warnings; files older than 7 days are deleted.

With the Microsoft Store Python on Windows, writes to `%LOCALAPPDATA%` are
redirected into the app's private folder, so the state is really under
`%LOCALAPPDATA%\Packages\PythonSoftwareFoundation.Python.3.X_<id>\LocalCache\Local\agentwatch\coach`.
agentwatch itself sees the same redirect, so this only matters when you look
for the files by hand. This also applies to a pipx/venv install built on the
Store Python; a python.org Python has no redirect.

### Status line

`agentwatch statusline` puts one short word in Claude Code's status line when
the session is unhealthy, and prints nothing when it is healthy:

```
⚠ loop ~$1.40
```

The word is the most severe current HIGH/CRITICAL coach finding: `loop`,
`thrash`, `errors` or `stuck` (yellow for HIGH, red for CRITICAL), plus the
cost of the API calls behind it when that is known. It reads only the
coach's state file for the session, never the transcript, so it needs the
plugin's hook (above) and runs in about 150 ms on Windows, most of it Python
startup. It prints nothing when there is no state for the session yet (no
tool call so far, or no coach), when the state is older than 10 minutes, or
on any error, and always exits 0. `--ok` prints a dim `✓ agentwatch` when
the coach's last check was healthy. `NO_COLOR` turns colors off.

Plugins cannot set the main status line (a plugin's settings only apply
`agent` and `subagentStatusLine`), so this is a one-line manual setup in
`~/.claude/settings.json`:

```json
{
  "statusLine": {
    "type": "command",
    "command": "agentwatch statusline"
  }
}
```

Use `"agentwatch statusline --ok"` to see the check mark when all is well.
On Windows, Claude Code runs the command through Git Bash (or PowerShell
without Git Bash); if you give a full path to `agentwatch`, write it with
forward slashes.

**Already have a status line script?** Call `agentwatch statusline` from
inside it with the same stdin and append what it prints:

```bash
#!/usr/bin/env bash
input=$(cat)
model=$(printf '%s' "$input" | jq -r '.model.display_name')
aw=$(printf '%s' "$input" | agentwatch statusline)
echo "[$model] ${aw}"
```

In a PowerShell script use `$aw = $json | agentwatch statusline`. If the `⚠`
comes out garbled, the console code page is not UTF-8: set
`[Console]::OutputEncoding = [Text.Encoding]::UTF8` first. (A BOM that
PowerShell adds to piped stdin is ignored.)

**[ccstatusline](https://github.com/sirmalloc/ccstatusline):** its Custom
Command widget passes the same Claude Code JSON on stdin (plus
`terminal_width`). Add a Custom Command widget with the command
`agentwatch statusline` and turn on "preserve colors" (otherwise
ccstatusline strips the colors and applies its own). In
`~/.config/ccstatusline/settings.json` the widget is:

```json
{ "id": "agentwatch", "type": "custom-command", "commandPath": "agentwatch statusline", "preserveColors": true }
```

The widget's default timeout (1000 ms) is plenty.

## Configuration

```python
from agentwatch import create_registry, ActionBuffer, parse_file
from agentwatch.health import HealthWeights, calculate_health, calculate_efficiency

# Create custom registry
registry = create_registry(mode="all")  # "health", "security", or "all"

# Parse logs
buffer = ActionBuffer()
for action in parse_file(Path("session.jsonl")):
    buffer.add(action)

# Run checks
warnings = registry.check_all(buffer)

# Calculate scores with custom weights
eff = calculate_efficiency(warnings, buffer)
report = calculate_health(
    warnings,
    efficiency_score=eff.score,
    rot_score=0.2,
    weights=HealthWeights(detectors=0.5, efficiency=0.25, rot=0.25),
)

print(f"Overall: {report.overall_score}% ({report.status})")
```

### Custom Detectors

```python
from agentwatch import Detector, Category, Severity, Warning, ActionBuffer

class MyDetector(Detector):
    category = Category.PROGRESS
    name = "my_detector"
    description = "Detects my custom pattern"

    def check(self, buffer: ActionBuffer) -> Warning | None:
        if some_condition:
            return Warning(
                category=self.category,
                severity=Severity.HIGH,
                signal="my_signal",
                message="Something bad detected",
            )
        return None

registry.add_detector(MyDetector())
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  TIER 1: Deterministic Detectors (always on)            │
│  - Pattern matching, regex, thresholds                  │
│  - Zero cost, zero latency, auditable                   │
└─────────────────────────────────────────────────────────┘
                          │
                          v (optional, --llm flag)
┌─────────────────────────────────────────────────────────┐
│  TIER 2: LLM Analysis (opt-in, --llm)                    │
│  - Semantic triage of Tier-1 warnings                   │
│  - Session-level goal-alignment advisory                │
│  - Local Ollama only -- no external API, ever            │
└─────────────────────────────────────────────────────────┘
```

All built-in detectors are deterministic (Tier 1) for:

- **Auditability**: Can explain exactly why alerts fired
- **Speed**: Real-time detection
- **Cost**: No API calls
- **No meta-injection**: Can't fool a regex

Tier 1 is the sole driver of every health/security score -- Tier 2 never
changes a score or severity. It either attaches an advisory opinion to a
warning Tier 1 already found, or (for goal-alignment) prints its own
session-level advisory block (see [Tier-2 LLM Analysis](#tier-2-llm-analysis-optional)
below).

## Tier-2 LLM Analysis (optional)

```bash
pip install "agentwatch-monitor[llm]"
ollama pull llama3.2   # or any other locally-pulled chat model
ollama serve

agentwatch security-scan --log ~/.claude/projects/myapp/session.jsonl --llm
agentwatch check --security --llm --llm-model llama3.2
agentwatch watch --security --llm            # live TUI, throttled to a 30s cadence
agentwatch watch-all --llm                   # same, per agent
```

Local-only, by explicit design, not an oversight: this project's own
security detectors exist partly to catch credential leaks and secrets *in
agent logs*, so Tier 2 only ever talks to a local Ollama daemon -- nothing
here makes a network call to any external host, and there's no API-key env
var to configure. If Ollama isn't running or the requested model isn't
pulled, `--llm` degrades to a printed warning and Tier-1-only results
rather than failing the scan (in the live TUI, a one-time notification
instead).

Each assessed warning gets a `likely_true_positive`/`confidence`/
`rationale` opinion attached under `details.llm_assessment` in JSON output
(and consequently in `--siem-log` export too), plus a dedicated "TIER-2 LLM
ASSESSMENT" section in plain-text output (a `[Tier-2] ...` line inline in
the live TUI's warnings list). Capped at the first 10 warnings per run to
keep `--llm` runs bounded against a slow local model; in `watch`/
`watch-all`, assessment is additionally throttled to a 30-second cadence
(instead of the 1s health-refresh tick) and runs in a background worker so
a slow local model can never stall the dashboard.

### Goal-Alignment Advisory (also under `--llm`)

The same `--llm` flag also runs a second, independent Tier-2 capability:
a session-level judgment of whether the agent's recent actions still look
aligned with what the user actually asked for. It compares the stated task
(the first action in the log carrying a non-empty `incoming_message`) — plus
any later user follow-ups/redirects — against a synopsis of the most recent
actions, via the same local Ollama model. No separate flag is needed; it
runs automatically alongside per-warning triage whenever `--llm` is passed:

```bash
agentwatch check --llm
agentwatch security-scan --llm
agentwatch watch --llm        # live TUI, same 30s throttle cadence
agentwatch watch-all --llm    # same, per agent
```

Purely advisory, like per-warning triage above: it never produces a
`Warning` and never affects any score (including the currently-inert
`Category.GOAL` row — see [Detector Categories](#detector-categories)).
Printed as its own "TIER-2 GOAL ALIGNMENT (advisory, not scored)" block with
an `[ALIGNED]` / `[POSSIBLE DRIFT]` / `[UNCLEAR]` label and a one/two
sentence summary (a top-level `goal_alignment` key in JSON output).

Stays silent — no block, no output — when the log carries no stated task at
all (no action has a non-empty `incoming_message`). This is the documented,
expected outcome for any current Codex CLI session: `parser/codex.py`
doesn't capture `incoming_message`, so there's nothing to judge alignment
against.

## SIEM Integration (optional)

```bash
pip install "agentwatch-monitor[siem]"

agentwatch security-scan --log ~/.claude/projects/myapp/session.jsonl --siem-log /var/log/agentwatch/findings.jsonl
agentwatch watch --security --siem-log /var/log/agentwatch/findings.jsonl   # live TUI
agentwatch watch-all --siem-log /var/log/agentwatch/findings.jsonl          # per agent
```

Appends one JSON object per finding (plus a run summary line for the
one-shot `check`/`security-scan` commands) to the given path, using
`python-json-logger`. This deliberately doesn't target or know about any
specific SIEM product -- a JSON-lines file is the standard hand-off point
any log-forwarding agent (Splunk Universal Forwarder, Filebeat, Datadog
Agent, ...) already knows how to tail and parse. Opens in append mode, so
it's safe to point every run at the same path.

In the live `watch`/`watch-all` TUIs, export is streaming rather than a
one-shot dump: each still-open warning is appended exactly once (keyed by
detector signal + stable identifying details, not by its often-changing
message text), matching how a real event stream behaves rather than
re-emitting the same open finding every second. `watch-all` exports each
tracked agent independently under its own identity. A broken path (or a
missing `siem`/`llm` extra) surfaces as a single dashboard notification
instead of crashing the session.

## Multi-Agent Monitoring

`agentwatch watch-all` auto-discovers running agents via process scanning and monitors them on a unified dashboard. Each agent gets its own isolated scoring pipeline. Agent identification uses `psutil` (cross-platform, including native Windows support) to resolve the exact log file each process has open, preventing cross-contamination when multiple agents work on the same project.

## Contributing

Contributions welcome! Especially:

- New detectors for failure patterns you've observed
- Codex CLI: a real captured rollout log to verify the fixture-based parser against (see [Supported Agents](#supported-agents))
- Better heuristics for existing detectors

## License

MIT

---

Built for developers who give AI agents real power and want to keep that power in check.

Built by [LoomLabs](https://loomlabs.io).
