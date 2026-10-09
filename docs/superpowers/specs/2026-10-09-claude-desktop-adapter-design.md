# Claude Desktop adapter (Cowork sessions) — design

**Date:** 2026-10-09
**Branch:** `feature/claude-desktop-adapter` (from `develop`, PR targets `develop`)
**Issue:** #73
**Status:** revised after research (see Revision note below)

## Revision 2026-10-09 (post-research)

- **MCP-log component dropped** (no `parser/mcp_log.py`, no `McpLogWatcher`,
  no `.log` claims). Since ~2026-06-27 Claude Desktop redacts its MCP logs to
  `Message from client: method="tools/call" id=6` /
  `Message from server: id=6 result(1 blocks)` — no tool name, arguments or
  result, so nothing useful becomes an `Action`. Confirmed on this machine's
  logs. Sources: https://github.com/anthropics/claude-code/issues/66726,
  https://modelcontextprotocol.io/docs/tools/debugging. Cowork transcripts
  already record their own `mcp__*` tool calls. Moved to Out of scope.
- **Transcript lookup by glob, not by encoded cwd.** `encode_path_for_claude`
  matched 0/32 real sessions (the real dir name is
  `re.sub(r'[^A-Za-z0-9]', '-', cwd)`). Lookup is
  `local_<id>/.claude/projects/*/<cliSessionId>.jsonl`; 5/32 real sessions
  have extra `*.jsonl` files in `projects/*`, so selection is by
  `cliSessionId`, never by mtime. `<cliSessionId>/subagents/` is ignored.
- `local-agent-mode-sessions/` also holds a `skills-plugin/` dir; the
  `<a>/<b>/local_*.json` scan must tolerate unrelated dirs/files.
- Roots are returned only if they contain `local-agent-mode-sessions/`.
- Running gate is exactly `Claude.exe` (Windows) / `Claude` (macOS,
  unverified), case-sensitive — not `cowork-svc.exe` (a Windows service that
  runs with the app closed), not lowercase `claude.exe` (Claude Code).
- Removed the claim that the agent "runs inside a VM" (metadata has
  `hostLoopMode=true`). App-gating stays because there is no per-session
  host process to map.
- `watch --log` needs no change: `ui/app.py` dispatches via `adapter_for`,
  and Cowork `.jsonl` is claimed by `claude-code` (identical format).

## Goal

Make agentwatch monitor Cowork (local agent mode) sessions in the Claude
Desktop app: surfaced by `ps` / `watch-all`, checkable with `check` /
`security-scan`, run through every existing health and security detector.

Plain chat conversations are out of scope: they are stored server-side and
nothing on disk is reliably parseable. ChatGPT Desktop is a separate spike.

## Findings (verified 2026-10-09, this machine)

- Claude Desktop is installed as an MSIX package (`Claude.exe` under
  `C:\Program Files\WindowsApps\Claude_<ver>_x64__pzs8sxrjxfjjc\app\`).
- Data root: `%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude\`
  (MSIX virtualises `%APPDATA%\Claude`).
- Cowork sessions: `local-agent-mode-sessions/<a>/<b>/local_<id>.json`
  (metadata) plus a sibling directory `local_<id>/`. Keys used (types
  checked on all 32 sessions): `cliSessionId` str, `cwd` str,
  `lastActivityAt` int epoch ms, `isArchived` bool; `sessionId` equals the
  `local_<id>` stem.
- Transcript: `local_<id>/.claude/projects/<dir>/<cliSessionId>.jsonl` —
  Claude Code JSONL, parsed unchanged by `_parse_jsonl`
  (`adapter_for` -> `claude-code`).
- `Claude.exe` does not match the `claude-code` process pattern
  (case-sensitive) — no collision.

## Components

### `src/agentwatch/claude_desktop_discovery.py` (new)

- `claude_desktop_roots() -> list[Path]` — candidate roots, in order, kept
  only if they contain `local-agent-mode-sessions/`:
  1. `%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude` (Windows
     MSIX; **verified**)
  2. `%APPDATA%\Claude` (Windows non-Store; **unverified**)
  3. `~/Library/Application Support/Claude` (macOS; **unverified**)
- `is_claude_desktop_running() -> bool` — any process named exactly
  `Claude.exe` / `Claude`, same shape as `is_cursor_running`.
- `find_claude_desktop_agents(now=None) -> list[AgentProcess]` — `[]` unless
  running; otherwise one entry per session that is not archived, has
  `lastActivityAt` within `ACTIVITY_WINDOW_SECONDS` (1800, with a
  `# ponytail:` comment), and whose transcript exists.

`AgentProcess`: `agent_type="claude-desktop"`, `log_file=<transcript>`,
`working_directory=Path(cwd)`, `session_id=cliSessionId`,
`command="Claude Desktop (Cowork)"`, `pid=cursor_discovery._synthetic_pid`
keyed on the session id, `uptime=""`.

### `src/agentwatch/agents/claude_desktop.py` (new)

`ClaudeDesktopAdapter(BaseAdapter)`: `name="claude-desktop"`,
`kind="editor"`, registered after `GeminiAdapter`. `discover()` calls
`find_claude_desktop_agents()` (call-time module lookup). `claims()` keeps
the `BaseAdapter` default (`False`). `make_watcher` / `parse_file` delegate
to `ClaudeCodeAdapter` (same JSONL). `is_live` is the default.

## Data flow

- `ps` / `watch-all`: `discovery` merges `editor_adapters()` ->
  `ClaudeDesktopAdapter.discover()` -> `MultiLogWatcher` (adapter looked up
  by `agent_type`) -> `LogWatcher` -> detectors and scoring.
- `check` / `security-scan` / `watch --log <transcript>`: `adapter_for` ->
  `claude-code`.

## Error handling

Discovery never raises: unreadable/invalid metadata JSON, missing
`cliSessionId`, missing `cwd`, missing transcript each skip that session.
Not running -> `[]`, even if session files exist (same rule as Cursor).

## Testing (TDD)

Synthetic fixture trees built in `tmp_path` (no real content). Tests: root
order + existence filter; not running -> `[]`; activity window with injected
`now`; archived and stale skipped; `cliSessionId` -> transcript with a decoy
`.jsonl` present; subagents ignored; broken/invalid metadata, missing
`cliSessionId`, missing `cwd`, missing transcript skipped; `skills-plugin/`
tolerated; registry order; adapter yields a working `LogWatcher`;
`parse_file` of a Cowork transcript. Gate: full suite + `ruff check .`.

## Verification plan

- Fixture-verified: everything above. Windows MSIX path verified against
  the real file layout.
- Live (before marking the PR ready): open Claude Desktop, run a short
  Cowork task -> `agentwatch ps` lists it as `claude-desktop`; `watch-all`
  shows live actions; `check --log <transcript>` scores it.

## Out of scope (possible follow-ups)

- MCP logs (`logs/mcp*.log`): redacted by the app since ~2026-06-27 (see
  Revision note), no tool name/args/result to parse.
- Subagent transcripts as child agents in the team tree.
- `audit.jsonl` (HMAC-signed audit trail).
- Using `egressAllowedDomains` / `enabledMcpTools` metadata as security
  detector inputs.
- The pre-existing `claude.exe --chrome-native-host` false positive in `ps`.
- ChatGPT Desktop (separate spike).
