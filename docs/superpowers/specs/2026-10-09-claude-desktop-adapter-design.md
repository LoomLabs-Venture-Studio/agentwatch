# Claude Desktop adapter (Cowork sessions + MCP logs) — design

**Date:** 2026-10-09
**Branch:** `feature/claude-desktop-adapter` (from `develop`, PR targets `develop`)
**Status:** approved in brainstorming, awaiting spec review

## Goal

Make agentwatch monitor the agent work done inside the Claude Desktop app:

1. **Cowork (local agent mode) sessions** — surfaced by `ps` / `watch-all`,
   checkable with `check` / `security-scan`, run through every existing
   health and security detector.
2. **MCP server traffic** — tool calls Claude Desktop makes to user-configured
   MCP servers (including from plain chats), parsed from its MCP logs.

Plain chat conversations are out of scope: they are stored server-side and
nothing on disk is reliably parseable.

ChatGPT Desktop is **not** part of this work. It is a separate read-only
research spike once it is installed on the dev machine (it is not installed
now, and its agent mode runs in OpenAI's cloud; Codex runs that write
`~/.codex` are already covered by the `codex` adapter).

## Findings this design rests on (verified 2026-10-09, this machine)

- Claude Desktop is installed as an MSIX package: `Claude 2.31226.0.0`,
  executable `C:\Program Files\WindowsApps\Claude_2.31226.0.0_x64__pzs8sxrjxfjjc\app\Claude.exe`.
- Its data root is
  `%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\`
  (MSIX virtualises `%APPDATA%\Claude`; the real `%APPDATA%\Claude` holds
  only `claude_desktop_config.json`).
- Cowork sessions live at
  `local-agent-mode-sessions/<a>/<b>/local_<id>.json` (metadata) with a
  sibling directory `local_<id>/`. Metadata keys used here: `cliSessionId`,
  `cwd`, `lastActivityAt` (epoch **milliseconds**, int), `isArchived`,
  `model`, `title`.
- The transcript is
  `local_<id>/.claude/projects/<encoded>/<cliSessionId>.jsonl` — Claude Code
  JSONL. 32/32 sessions on this machine map this way. The existing
  `_parse_jsonl` parses them unchanged (`adapter_for` → `claude-code`).
  Subagent transcripts sit under `<cliSessionId>/subagents/agent-*.jsonl`.
- Cowork's agent runs inside a VM (`claude-code-vm/`, `cowork_vm_node.log`,
  `vmProcessName` in metadata). There is no per-session host process, so
  discovery must be app-gated like Cursor's, not PID-based.
- MCP logs: `logs/mcp-server-<name>.log` (plus an aggregate `logs/mcp.log`).
  Line format:
  `<ISO-8601 ts> [<server>] [<level>] Message from client|server: <JSON-RPC>`.
  This machine's logs contain only `initialize` / `tools/list`, no
  `tools/call`, so call/result parsing is fixture-verified until a live
  sample is captured.
- `Claude.exe` does **not** match the `claude-code` process pattern
  (`(^|[/\\])claude(\.exe)?$`, case-sensitive) — confirmed with
  `match_process_adapter`. No collision to fix.

## Components

### `src/agentwatch/claude_desktop_discovery.py` (new)

Mirrors `cursor_discovery.py`.

- `claude_desktop_roots() -> list[Path]` — existing roots, in order:
  1. `%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude` (Windows
     MSIX; **verified**)
  2. `%APPDATA%\Claude` (Windows non-Store install; **unverified**)
  3. `~/Library/Application Support/Claude` (macOS; **unverified**)
  Only roots that contain `local-agent-mode-sessions/` or `logs/` are
  returned. Docstring marks verification status per root.
- `is_claude_desktop_running() -> bool` — any process whose name is exactly
  `Claude.exe` (Windows) or `Claude` (macOS), case-sensitive, via
  `psutil.process_iter(attrs=["name"])`, swallowing per-process psutil
  errors (same shape as `is_cursor_running`).
- `find_claude_desktop_agents(now: float | None = None) -> list[AgentProcess]`
  — returns `[]` unless running; otherwise:
  - one entry per Cowork session where `isArchived` is falsy, the transcript
    exists, and `lastActivityAt` is within `ACTIVITY_WINDOW_SECONDS`;
  - one entry per `logs/mcp-server-*.log` whose mtime is within the window.
- `ACTIVITY_WINDOW_SECONDS = 1800` with a
  `# ponytail: fixed 30 min window, make it a CLI option if users need it`
  comment.

`AgentProcess` fields for a Cowork session: `agent_type="claude-desktop"`,
`log_file=<transcript>`, `working_directory=Path(cwd)`,
`session_id=cliSessionId`, `command="Claude Desktop (Cowork)"`, synthetic
`pid` (same scheme as Cursor's synthetic entries, so it never collides with
real PIDs). For an MCP log: `log_file=<mcp log>`,
`working_directory=<root>`, `session_id=None`,
`command="Claude Desktop MCP: <server>"`, synthetic `pid`.

### `src/agentwatch/agents/claude_desktop.py` (new)

`ClaudeDesktopAdapter(BaseAdapter)`: `name="claude-desktop"`,
`kind="editor"`. Registered in `agents/__init__.py` after `GeminiAdapter`.

- `discover()` → `claude_desktop_discovery.find_claude_desktop_agents()`
  (call-time module lookup so tests can monkeypatch).
- `claims(path)` → `True` only for a `.log` file whose first non-empty
  lines (bounded, e.g. 20) include one matching the MCP line regex. Cowork
  `.jsonl` transcripts are deliberately left to `claude-code`'s catch-all
  (identical format).
- `make_watcher(source, session_id)` → `.jsonl`: `LogWatcher`; `.log`:
  `McpLogWatcher`.
- `parse_file(path, session_id)` → `.jsonl`: `_parse_jsonl`; `.log`:
  `parse_mcp_log`.
- `is_live` — `BaseAdapter` default (`log_file` exists) is correct: these
  are real files, unlike Cursor's synthetic keys.

### `src/agentwatch/parser/mcp_log.py` (new)

- `MCP_LINE_RE` — `^(\S+) \[([^\]]+)\] \[(\w+)\] Message from (client|server): (\{.*\})$`.
- `McpLogParser` — stateful, fed one line at a time:
  - client `{"method":"tools/call","id":X,"params":{"name":N,"arguments":A}}`
    → buffered under `(server, X)`;
  - server `{"id":X,"result":{...}}` or `{"id":X,"error":{...}}` → pops the
    pending call and emits one `Action`;
  - everything else (other methods, notifications, non-matching lines,
    invalid JSON, non-dict JSON) → ignored;
  - a response with no pending request → dropped;
  - `flush()` → emits still-pending calls with unknown outcome (used by
    one-shot `parse_file` at EOF only, never by the watcher — same rule as
    `CodexParser`).
- Action mapping: `tool_name=f"mcp__{server}__{tool}"` (same naming Claude
  Code transcripts already use for MCP tools); tool input = `arguments`;
  success = no `error` and `result.isError` is not true; error text from
  `error.message` or the result's text content; `timestamp` = request line's
  timestamp; result text truncated the same way other parsers do. Map to the
  existing `ToolType` via the same classification other parsers use (no new
  enum values).
- `parse_mcp_log(path) -> Iterator[Action]` — reads with
  `encoding="utf-8", errors="ignore"`, feeds every line, flushes at EOF.

### `McpLogWatcher` in `src/agentwatch/parser/watcher.py`

Same contract as `LogWatcher` (byte-offset tail, `watchfiles.awatch`,
`on_action` callbacks, handles truncation/rotation the same way), but feeds
raw text lines to an `McpLogParser` instead of `json.loads`. Reuse
`LogWatcher`'s tailing code rather than copying it if it can be shared with
a small hook; otherwise a minimal subclass.

## Data flow

- `ps` / `watch-all`: `discovery` merges `editor_adapters()` results →
  `ClaudeDesktopAdapter.discover()` → `MultiLogWatcher` →
  `adapter.make_watcher()` → actions → existing detectors and scoring.
- `check` / `security-scan --log <file>`: `adapter_for(path)` → `.jsonl` →
  `claude-code`; MCP `.log` → `claude-desktop` → `parse_mcp_log`.
- `watch --log <mcp .log>`: `ui/app.py` dispatches by suffix today; add a
  `.log` branch only if the adapter path does not already cover it (check
  during planning).

## Error handling

- Discovery never raises: unreadable/invalid metadata JSON, missing
  `cliSessionId`, missing transcript, missing `cwd`, unreadable log mtime —
  each skips that one item.
- Parser never raises on bad input: invalid lines are skipped (same policy
  as the #70 OpenCode fix).
- `claims()` returns `False` on any read error.
- Not running → `discover()` returns `[]`, even if session files exist (same
  board rule as Cursor: no stale "agents" after the app closes).

## Testing (TDD — each test written to fail first)

Fixtures (scrubbed, synthetic — no real user content copied):

- `tests/fixtures/claude_desktop/` tree mirroring the real layout: two
  sessions (one active, one archived), one stale session, metadata JSON with
  only the keys used, a short Claude Code transcript each, a `subagents/`
  file that must be ignored, and `logs/mcp-server-demo.log`.
- MCP log fixture lines: `initialize`, `tools/list`, a `tools/call` with a
  successful result, one with `result.isError: true`, one with a JSON-RPC
  `error`, one pending (no response), an orphan response, a garbage line,
  and an invalid-JSON line.

Tests:

- root resolution order and existence filtering (env monkeypatched);
- running gate: not running → `[]` even with fixtures present;
- activity window (inject `now`), archived skip, `cliSessionId` →
  transcript mapping, subagents ignored, broken metadata skipped;
- `claims` / `adapter_for` routing: MCP `.log` → `claude-desktop`; Cowork
  `.jsonl` → `claude-code`; other `.log` (e.g. `main.log`-style) → not
  claimed; generic SQLite rejection test from #48 unchanged;
- `McpLogParser` outcomes for every fixture line above, plus `flush()`;
- `McpLogWatcher` tails appended lines and emits once per call;
- registry order test updated for the new adapter.

Gate: full suite + `ruff check .` green.

## Verification plan

- Fixture-verified: everything above.
- Live (on this machine, before marking the PR ready):
  1. Open Claude Desktop, run a short Cowork task → `agentwatch ps` lists it
     as `claude-desktop`; `watch-all` shows live actions; `check --log
     <transcript>` scores it.
  2. Trigger one MCP tool call from a chat → capture the real `tools/call`
     line shape, confirm `McpLogParser` handles it, and replace any fixture
     assumption it contradicts.
- Record the outcome in CLAUDE.md and the README agent list as
  "Claude Desktop (Cowork + MCP logs)", with Windows MSIX live-verified and
  non-Store Windows / macOS paths marked unverified.

## Out of scope (possible follow-ups)

- Subagent transcripts as child agents in the team tree.
- `audit.jsonl` (HMAC-signed audit trail).
- Using `egressAllowedDomains` / `enabledMcpTools` metadata as security
  detector inputs.
- The aggregate `logs/mcp.log` (per-server logs carry the same traffic).
- The pre-existing `claude.exe --chrome-native-host` false positive in `ps`
  (separate bug, separate issue).
- ChatGPT Desktop (separate spike).
