# Changelog

Notable changes to AgentWatch (`agentwatch-monitor`). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Issue and PR
numbers refer to the GitHub repository.

## [Unreleased]

### Added

- `watch-all --all-logs` loads only logs modified in the last 24 hours by
  default (older logs are not read; one appears once it is written to
  again). `--since Nh|Nd|all` changes the window. Sessions show their project
  name (from the cwd a Claude Code transcript records, worktrees as their
  project, `~` for home) instead of the log file name; Claude Code subagent
  logs sit under their session.
- `watch-all`: sessions with no action for 15+ minutes, and stopped ones,
  fold into one `… N idle` row (`a` shows them). `/` filters rows by
  project, agent or top warning as you type (Enter keeps, Esc clears).
- `watch-all` shows the Claude Code loop breaker: a blocked session's top
  warning is `⛔ loop blocked: <tool> (Nx) $X` and it sorts with Critical
  sessions; one Events line per block; `blocks N` in the header; a
  `Loop breaker:` line on the detail view's Health tab. The coach's state
  file is read only, and only when its modification time changes.
- `watch-all --budget`: the cost column becomes `COST / BUDGET` with a
  4-cell bar (amber from 80%, red once hit) and the header shows the budget.
- `watch-all`: `s` adds one Events line (`security on: N findings` /
  `security off`) instead of one line per finding the rescoring adds or clears.

- Loop circuit breaker in the Claude Code plugin: a PreToolUse hook denies,
  once, the next call that repeats a HIGH loop (6+ identical actions in the
  last 10 calls), with a fixed reason shown to Claude. Retries are allowed,
  common polling/test commands are never blocked, and any error lets the call
  through. `AGENTWATCH_LOOP_BREAKER=off` turns it off. Claude Code only.
- `--budget USD` on `watch` and `watch-all`: one alert per session when its
  estimated cost first reaches the limit, through the same desktop/webhook/
  headless sinks. A session already over budget when first seen alerts at
  startup; `--budget` alone turns on `--notify` (so the regular Critical/
  finding desktop alerts are on too; add `--webhook` instead to get only the
  webhook). Sessions with an unknown cost (Codex, Gemini, Copilot VS Code) never alert.
- Alerts for unattended sessions. `watch-all --headless` runs the watch-all
  engine without the dashboard and prints one line per new warning (and
  waits for agents if none are running yet). `--notify` on `watch` and
  `watch-all` shows a desktop notification (Windows toast, macOS
  `osascript`, Linux `notify-send`; no new dependencies) when a session turns
  Critical or a new finding at `--notify-min` (`critical` by default, or
  `high`) appears. `--webhook URL` (or `AGENTWATCH_WEBHOOK`) posts the same
  alerts as Slack-compatible JSON `{"text": ...}`. One alert per finding per
  session, a Critical session at most once per 10 minutes; text is the
  agent, project, label, cost and the redacted warning message only.
  Findings a session already has when first seen are a silent baseline
  (`--notify-existing` alerts on them too).

- `agentwatch report`: what your agents cost you over the last 7 days (or
  `--days N`), across agents and projects: sessions, spend, tokens, waste
  (`check`'s waste figure summed over sessions, with its % of spend), the 3
  costliest findings, a per-agent and per-project breakdown, security
  finding counts and the change against the previous period. Sessions with
  no price show as n/a and are left out of spend and %. `--agent`,
  `--project`, `--json` (schema 1, documented in the README), `--no-sync`.
- `agentwatch history sync|prune|path`: a local SQLite history of sessions
  and findings behind the report (`%LOCALAPPDATA%\agentwatch\history.db`, or
  `~/.local/share/agentwatch/`). Only new or changed logs are read; logs
  still being written wait unless `--include-active`. No transcript text,
  prompts, commands or full paths are stored. Kept until `history prune
  --older-than 90d`.
- Claude Code plugin (`plugin/`) with a health coach: a PostToolUse hook runs
  `agentwatch hook`, which checks the live session with the health detectors
  and adds a short note (problem, evidence, what to try) to Claude's context
  for each new HIGH/CRITICAL loop, thrash, error spiral or stuck pattern,
  once per session. It never blocks a tool call (PR #139).
- Dollar cost per health finding: each health warning carries the tokens
  and USD of the API calls behind the actions it covers (`~$1.40 · 210k tok`)
  in `check` text and `--json`, the `watch`/`watch-all` TUIs and the SIEM
  export (`tokens`, `cost_usd`). `check` adds a `Waste: ~$X on N findings
  (Y% of session cost)` line and a `waste` JSON object. Fields are absent,
  never 0 or estimated, when the agent logs no tokens or the model has no
  listed price.

### Fixed

- `watch-all --budget`: the cost column switches between its wide and
  narrow form when the terminal is resized across 100 columns; the narrow
  header says `spent $X` and the limit reads `budget $X/session`.
- `watch-all` team rows: teams that form after startup get their header,
  members sit under it in tree order, and the header goes when the team's
  sessions are gone.
- `stats` now counts subagent transcripts (`<session>/subagents/*.jsonl`),
  also under `--session <id>`; usage was about 2.5x too low. A message id
  seen in both files counts once.
- `--log`, `--analytics-log`, `--siem-log` and `--audit-log` given a
  directory (`check`, `security-scan`, `watch`, `watch-all`, `agentguard`) is
  a one-line usage error instead of an `IsADirectoryError` traceback.
- `watch-all`: after `s`, every session is rescored on the next tick (idle
  sessions kept their old report). The selected session is no longer
  rescored every second without new actions, which moved its context health
  and state on its own; every session is now rescored only on new actions.

### Security

- Coach notes, alerts and headless lines replace control characters
  (terminal escapes, BEL, newlines, bidi overrides) with spaces through one
  shared helper (`secret_scanner.one_line`); the coach note previously kept
  ESC sequences.

### Changed

- `watch-all` shows a sessions table instead of the agent sidebar: one row
  per session with status dot, agent, project, health (with ▲/▼ after a move
  of 5 points or more), cost, context %, time since the last action and the
  top warning. Rows sort by attention (Critical, then HIGH, then other
  warnings, then active by recency, idle or stopped last); `o` switches to
  cost or recent order and the cursor stays on its session. Subagents sit
  under their parent. A strip under the table shows the selected session's
  numbers and top 3 warnings; the full panels return in a detail view. Each
  tick updates only the cells that changed. The `c` (clear Python cache) key
  is gone. HEALTH's ▲/▼ compares with the score a minute ago; AGENT shows
  display names (Claude Code, OpenCode, Kilo Code; alert text too); stopped
  sessions are grey.
- `watch-all`'s title bar is a one-line header: sessions, active, need you
  (Critical or a HIGH+ warning), on-screen cost, alerts this run and the
  time. An Events panel lists sessions started/stopped, new and cleared
  warnings, alerts sent and `--budget` 80%/100% crossings, newest first;
  `e` focuses it to scroll, Esc returns to the table. Stopped sessions are
  not counted as needing you. Sessions already over `--budget` when loaded
  give one "N sessions over budget; N alerts sent" line instead of two lines
  each (the alerts themselves are still sent).
- `watch-all`: Enter opens a session full screen with Health, Security,
  Network and Process tabs (Tab/Shift+Tab or 1-4; Esc, Backspace or `q`
  back to the same row). The health panels are shorter in `watch` too: one
  status word (on the overall health bar), no raw 0.00-1.00 numbers next to
  bars, context modules at 0 left out, durations in hours and minutes, all
  warnings and full suggestions in the detail view. The security panel reads
  "Security: clean" or "N findings" instead of reusing health words.
- `stats` and `audit` name a Claude Code project after the `cwd` its
  transcripts record, so `agentwatch-main` is no longer shown as `main`
  (the old name decoded the project dir, which can't tell `-` from `/`).
  A session run in the home folder is named `~`, not the user name.
- Pricing: one table in `cc_stats.PRICING` (Anthropic's price page,
  2026-10-17) keyed by model id. `stats` priced every "opus" at $15/$75,
  overstating current Opus (Opus 5.5 is $4/$20, Opus 4.5-5 $5/$25). `stats`
  and the session cost now price each API call by its own model, with 1h
  cache writes at the 1h rate, through the same `usage_cost_usd()`; `stats`
  used the report's dominant model and the 5m rate for every call. Session
  cost counts each Claude Code call once (every content-block line repeats
  its usage). An unlisted model makes the cost "n/a" instead of a Sonnet-rate
  guess.

## [0.2.0] - Unreleased

Everything on `develop` since `v0.1.6` (2026-03-10).

### Added

- `agentwatch net`: shows which external servers local AI runtimes (Ollama,
  LM Studio, llama.cpp, ...) talk to, named from the DNS cache, known hosts or
  reverse DNS. Nothing is allow-listed. Supports `--once`, `--json`,
  `--pid`, `--interval` and `--duration` (PR #134).
- `agentwatch net` lists runtime listeners and flags the ones other machines
  can reach (bound to all interfaces or a LAN address), plus the clients
  connected to them (PR #135).
- `agentwatch net --local` also watches running agents (Aider, opencode, ...)
  and flags connections to cloud AI providers (PR #136).
- Per-action network tracking in `watch` / `watch-all`: each agent's live
  endpoints are sampled (unprivileged, about once a second) and the stats line
  shows `Net:`. New `undeclared_egress` security detector (medium) flags
  endpoints not explained by a declared host, a known AI provider or a known
  agent vendor host (#130, PR #130).
- `agentwatch scrub <file>`: hides secrets and personal info (email, phone,
  US SSN, card numbers, US street address) in a `.scrubbed` copy, or
  `--in-place` with a `.bak`. Also `--dry-run`, `--json`, `--secrets-only`
  (PR #133).
- `agentwatch audit --pii` reports personal info as low-severity findings
  that never change the exit code (PR #133).
- Claude Code skill `skills/agentwatch-scrub` for scrubbing a file or session
  log by asking Claude Code (PR #133).
- Per-agent adapter registry. Discovery, `parse_file`, `watch-all` and the
  TUI dispatch through it, and a failing adapter is skipped. Adds the GitHub
  Copilot CLI and Antigravity CLI (`agy`) adapters (PR #29).
- OpenCode adapter: reads the SQLite `opencode.db` store read-only (#67, PR #69).
- Gemini CLI adapter: parses `chats/session-*.jsonl` (#65, PR #68).
- GitHub Copilot in VS Code adapter: parses the `chatSessions/*.jsonl` mutation
  logs. Includes the design spec (#87, PRs #88, #89).
- Claude Desktop Cowork adapter (#73, PR #102).
- Cline adapter: covers the legacy globalStorage store, the SDK store
  (`~/.cline/data/sessions/`) and the Cline CLI (#104, PR #112).
- Cline: legacy store discovery for VS Code forks (#116, PR #124).
- Kilo Code 7.x adapter: reuses the OpenCode parser on `kilo.db`
  (#118, PR #123).
- `agentwatch detect`: machine-wide detection of AI use. It attributes
  connections to AI providers and local model ports to processes
  (#79, PR #80).
- `agentwatch detect` names version-named binaries by their adapter, so
  Claude Code shows as `claude-code` instead of `2.1.310`. Without an
  adapter it uses the nearest meaningful parent folder. `detect --json` has
  a new `display_name` field, and `name` is unchanged (PR #172).
- `agentwatch check` reports session efficiency in text and JSON output
  (#40, PR #51).
- Cursor support: `check`, `security-scan` and `watch-all` read Cursor
  agent-mode sessions from `state.vscdb` (PR #2), and `watch --log
  state.vscdb` works in the single-agent TUI (PR #13).
- Aider support: parses `.aider.chat.history.md` in every edit format,
  including resumed sessions, with an optional `--analytics-log` sidecar for
  tokens and cost. Live tailing in `watch` / `watch-all` (PR #2).
- Codex CLI support: session discovery and rollout log parsing (PR #2).
  Rollouts are resolved from the process's open files when a pid is known,
  and more Codex tool names are classified (PR #14).
- Native Windows support: psutil process discovery, Windows path encoding
  and a UTF-8 console (PR #2).
- `ascii` theme for consoles without Unicode (PR #2).
- `--siem-log PATH` writes findings as JSON lines for SIEM ingestion
  (`siem` extra) on `check` and `security-scan` (PR #2), and on `watch` /
  `watch-all`, exporting each warning once (PR #15).
- `--llm` adds an optional local-Ollama second opinion on warnings (`llm`
  extra) (PR #2), plus a goal-alignment advisory that is never scored
  (PRs #9, #15).
- `security-scan --audit-log PATH` writes a JSON-lines record of every
  security detector run (PR #8).
- `security-scan` shows raw security-signal counts (`security_stats` in
  `--json`), and `check` and the TUI show peak context tokens (PR #8).

### Changed

- Behaviour change: `agentwatch ps --json` is always a flat list of agent
  objects. It used to switch to a team-shaped list when sub-agents existed.
  Each object now has `parent_agent_pid`, `team_id`, `team_name` and `depth`,
  so the tree can be rebuilt. The per-team `member_count`,
  `subagent_count` and `max_depth` fields are gone (PR #172).
- Behaviour change: `security-scan` and the TUI security panel now say SECURE /
  AT RISK / COMPROMISED instead of health labels such as STUCK. A score of
  exactly 50 is now AT RISK with JSON `status: at_risk` (it was COMPROMISED /
  `compromised`). The exit code is unchanged (1 at 50). Scores below 50 stay
  COMPROMISED with exit 2 (PR #172).
- Claude Code and Gemini actions take their network host from a tool's
  `url`, so URL fetches reach the network detectors (#130, PR #130).
- Status messages such as "Using log ..." go to stderr, so `--json` stdout
  stays clean (PR #20).
- Secrets in findings are masked: values of 20+ characters show only the last
  4, shorter ones show `[hidden, N chars]`, and commands in warning details
  are masked too. Affects `matched_prefix`, SIEM, `audit --json` and the TUI
  (PR #23).
- Synthetic PIDs are a crc32 of the session id, so they stay stable across
  runs (#90, PR #92).
- Copilot in VS Code: finished requests settle for 1 s before they are
  emitted (#91, PR #93).
- Codex: the ChatGPT desktop app's app-server gets one `ps` entry per open
  thread (#105, PR #111).
- `check` prefers the current directory's session when `--log` is omitted
  (#47, PR #52).
- One-shot scans run the security detectors over the whole session
  (#35, PR #56).
- Rates show "--" until a session has 2 active minutes (#45, PR #50).
- Security: redaction of truncated windows is memoized (#25, PR #57).
- Faster scans and TUI refreshes on long sessions (PR #2).
- `Action.user_id`, which was never set, is removed from the model (PR #8).

### Fixed

- Parser: a non-text `host` in a tool's input no longer hides the URL host,
  so network detectors still fire (PR #138).
- Security: PEM private-key bodies are redacted, not just the header line
  (PR #133).
- PII: a card number followed by a CVV or expiry is now hidden, and phone
  numbers with an invalid NANP area code or exchange (`100-200-3000`) are no
  longer flagged (PR #140).
- Claude Code 2.1.300+: the `api-request`, `api-request-shape` and
  `api-request-blob` lines logged on every model turn are no longer parsed
  as actions, which raised false `api-request` loops and diluted real ones
  (PR #144).
- Loop detector: Claude Code's failed `tool_result` records are no longer a
  loop key or a window slot, so repeated failing calls are reported on the
  call itself, with its error. Tools with no file path or command (MCP
  tools, WebSearch, ...) are keyed on a hash of their input, so distinct
  calls are not a loop (PR #144).
- Context pressure: `context_pressure`/`context_critical` measure the latest
  call's context against the model's window instead of summing tokens over
  the session against a fixed 180K (reported "231% full" on a 1M-window
  session at 26%). Claude Code transcripts report the window from the model
  id; with no known window or no reported usage, no percentage is claimed
  (PR #144).
- Breaking: `ContextPressureDetector` no longer takes a `model` argument;
  the window comes from the log (PR #144).
- Warning dedup keys stay stable when a failure's error text changes run to
  run (durations, pids, temp paths, timestamps): a loop is keyed on its
  call, and other error text is normalized first. The coach, SIEM export
  and the TUI no longer treat each repeat as a new warning (PR #148).
- Security: `scrub` no longer leaks quoted secrets in `.json` files (Cline
  `api_conversation_history.json`, copied logs) or corrupts them: JSON input
  is redacted on decoded string values and is never written back invalid. A
  shell-escaped quote inside a quoted value (`"S3cret\"Pw"`) no longer ends
  the match, and a quoted `Bearer "..."` token is masked. JSON text inside
  a transcript string (a tool_result of `cat x.json`) is redacted too
  (PR #143).
- Security: bare `key=value` / `key: value` secrets (`password=Hunter2!`,
  `client_secret=...`, `AUTH_TOKEN=...`, `api_key: ...`) are masked
  everywhere, with no revealed tail. Values under 8 chars, without a digit
  and a letter or a symbol, short lowercase words (`gpt4all`), code
  expressions and placeholders (`***`, `gho_****`, `<...>`, `${VAR}`,
  `changeme`) are left alone (PR #143).
- `detect`: `Code.exe` and `Cursor.exe` map to their editor adapters
  (#100, PR #101).
- `detect`: editor processes are credited to every candidate editor adapter
  that has live sessions (#119, PR #120).
- `detect`: Cline is credited to VS Code forks and to Cursor processes
  (#127, PR #128).
- Cline: `api_conversation_history.json` is routed by extension id
  (#117, PR #121).
- Cline: outside globalStorage, Roo Code 3.49.0+ tasks (marked by
  `history_item.json`) are no longer claimed as Cline. Kilo Code 5.x and
  Roo Code below 3.49 still fall back to Cline (#117, PR #125).
- Codex: ChatGPT desktop Codex sessions show the rollout's project instead
  of the app-server's cwd, and use the most recently modified open rollout
  (#74, PR #77).
- Codex: the ChatGPT app's bin dir is never reported as the project
  (#94, PR #95).
- Codex: action count, cache hit rate, context % and cost are corrected
  (#82, PR #83).
- Codex: `item_completed` exit codes and patch status are correlated by call
  id (#106, PR #113).
- Codex: tool calls made inside code-mode `exec` scripts are surfaced
  (#107, PR #114).
- Codex: unrenamed `codex-<arch>-<triple>` release binaries are matched on
  every OS. The macOS side is source-reviewed, not run on a Mac
  (#108, PR #122).
- Discovery: `claude-code` false positives are dropped from `ps`
  (#84, PR #85).
- Discovery: Claude Code's full project-dir encoding is matched
  (#75, PR #86).
- Discovery: the non-Store Claude Desktop is no longer matched as
  `claude-code` (#109, PR #110).
- OpenCode: malformed rows are skipped, and a locked DB is reported as
  unreadable (#70, PR #72).
- Fixes from the Sprint 26 follow-ups (#62, #63, #64, PR #66).
- Parser: unrecognised and binary logs are rejected instead of being parsed
  as Claude Code (#39, PR #48).
- `watch`: the single-agent TUI showed no live data for any agent because the
  first action was dropped (PR #12).
- `stats` no longer crashes on non-UTF-8 bytes in a Claude Code log (PR #17).
- `--version` reports the installed package version (PR #19).
- `audit --redact` replaces only secret values, keeps JSON lines valid,
  preserves non-UTF-8 bytes, writes atomically and keeps a one-time `.bak`
  (PR #22). Its redaction count no longer includes false positives (PR #3).
- Watcher: Claude metadata-only sessions are emitted the same way as in
  `parse_file` (#39, PR #61).
- Parser: Claude Code bookkeeping entries are skipped, and the loop key is
  fixed (#46, PR #54).
- Parser: unparseable timestamps stay untimed and never fall back to
  `datetime.now()` (#44, PR #53).
- Parser: session duration comes from real timestamps, with idle gaps capped
  (#38, PR #43).
- Health: burn rate and io ratio exclude cache reads (#36, PR #37).
- Health: context pressure measures how full the window is, not the
  cumulative budget (#36, PR #42).
- Security: the remaining secret leak sinks are closed. Network hosts keep
  only the hostname, so query-string tokens are dropped. Error text and LLM
  prompts are masked, and more secret forms are detected
  (`PGPASSWORD=`, `mysql -p`, `--password=`, `curl -u`, URL credentials,
  `Authorization: Bearer`) (#24, PR #30).
- Security: DB-URL redaction no longer runs past the password, a placeholder
  no longer hides a live URL after it, and masking never reveals password
  characters. Stock-default passwords are no longer reported (#26, PR #34).
- Security: DB URL scanner gaps are fixed, and `check --json` output is
  stable (#33, PR #58).
- Security: follow-ups from the secret scanner QA (#31, PR #59).
- Security: the Discord, JWT and high-entropy patterns run in linear time
  (#32, PR #60).
- Security: `c2_beacon` patterns match whole words only (#41, PR #55).
- Net: `watch-all` re-tracks a session's sockets when a new process takes
  over its log, and `net --once` exits 1 when every `--pid` is missing.
- Watchers: live tailing works on macOS. Appends reported as `added` by
  FSEvents are read, and a 1 s fallback tick catches missed events. A
  truncated log, or one rewritten with different content, is re-read from the
  start; an atomic rewrite with the same content keeps its place. Covers Aider
  and the JSONL watcher behind `watch` (PR #165).
- `watch` / `watch-all` no longer exit when Claude Code logs an `error` that
  is an object, or when log text contains Textual markup such as `[/]`.
  Log text is shown literally (PR #166).
- A log line that fails to parse is skipped and the watch continues. Codex
  tool output that is not a string no longer raises (PR #166).
- Several Claude Code sessions in one project directory are tracked as
  separate agents. Each process is mapped through its own session record,
  the mapping is re-checked on every scan, and watchers are no longer leaked,
  so a log that comes back is not emitted twice (PR #169).
- Behaviour change: Cursor lists only composers active in the last 30 minutes
  as running agents. Older composers in `state.vscdb` are no longer reported
  (PR #167).
- Cursor: reading `state.vscdb` waits at most 1 s for a database lock (PR #167).
- `net`: traffic of a tracked child agent is attributed to the child only, not
  counted again under its tracked parent (PR #167).
- Security: the hidden-instruction HTML comment check runs in linear time.
  Padding no longer hides an instruction, and an unterminated `<!--` no
  longer stalls a scan (PR #167).
- Behaviour change: a non-local `OLLAMA_HOST` disables Tier-2 LLM analysis
  with a one-line reason. Loopback and bind-all addresses are accepted, and an
  explicit `host=` still works (PR #167).
- Behaviour change: `audit --redact` refuses a log that was written in the
  last 5 s, unless `--force` is given (which prints a warning). Appends made
  while a log is being redacted are no longer lost (PR #168).
- Behaviour change: each `audit --redact` run writes its own
  `<log>.bak.<UTC timestamp>` backup and lists the exact paths. Earlier `.bak`
  files are left alone (PR #168).
- Behaviour change: `scrub --in-place` and `audit --redact` refuse symlinks
  instead of replacing them, which left the target's secrets in place (PR #168).
- Behaviour change: `audit` scans user prompts and tool results. The scrub
  skill documentation says so (PR #168).
- Security: real secrets that contain a placeholder word (for example
  `sk_live_TODO...`) are redacted. Password previews no longer show the last
  4 characters (PR #168).

### Documentation

- README: goal alignment, the GOAL category and Cursor's scope are described
  accurately (PR #16).
- README: GitHub Copilot in VS Code (#87, PR #96).
- CLAUDE.md: crc32 synthetic pids, the Copilot-in-VS-Code settle, Kilo Code,
  Cline forks, the Roo marker and macOS Codex (PRs #97, #126).
- Copilot in VS Code re-verified on VS Code 1.141, with a note on the write
  delay (#87, PR #98).
- PLAYBOOK Sprints 28 to 32 (PRs #71, #81, #99, #115).
- Research: live agent testing and adapter candidates (#39, PR #49). Also the
  agent landscape, adapter roadmap and AI-use detection (PR #78).
- ADR proposing a TLS-intercepting proxy for network visibility (PR #103,
  rebuilt from PR #21).

## [0.1.6] and earlier

Released history is in the PyPI releases up to `v0.1.6`.
