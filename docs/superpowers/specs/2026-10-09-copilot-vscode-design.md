# GitHub Copilot in VS Code — Design

**Date:** 2026-10-09
**Branch:** `docs/copilot-vscode-spec` (from `develop` @ `114c425`)
**Issue:** none yet

## Goal

Make `agentwatch ps` / `watch-all` / `check` / `security-scan` see GitHub
Copilot agent-mode chats running inside VS Code. First half of the VS Code
track; Cline gets its own spec later.

## Findings (real session, VS Code 1.140)

A real agent session was created with `code chat -m agent` in a scratch
folder. VS Code wrote it to
`%APPDATA%/Code/User/workspaceStorage/<workspace-hash>/chatSessions/<session-id>.jsonl`;
`workspaceStorage/<workspace-hash>/workspace.json` holds the folder URI.

The file is a **mutation log**, not an event log:

- Line 0: `{"kind":0,"v":{...}}` — full snapshot (`sessionId`, `requests`,
  `responderUsername`, `creationDate`, ...).
- `{"kind":1,"k":[path...],"v":...}` — set the value at key path `k`.
- `{"kind":2,"k":[path...],"v":[...],"i":n}` — extend the array at `k` with
  `v`; when `i` is present, truncate the array to `i` first.

Replaying lines 0..N in order gives the session state. Confirmed: all 5 tool
calls of the real session rebuild correctly.

State shape used here:

- `requests[]`: `timestamp` (epoch ms), `modelId` (e.g. `copilot/auto`),
  `promptTokens`, `completionTokens`, `copilotCredits`, `response[]`.
- Tool parts in `response[]`: `kind: "toolInvocationSerialized"`,
  `toolCallId`, `toolId`, `isComplete`, `invocationMessage`, and optionally
  `resultError`, `resultDetails`, `toolSpecificData`.
- `resultError` is `false` on success, not absent. "Key present" is not an
  error signal; only a truthy value is.
- Terminal calls: `toolSpecificData.kind == "terminal"`,
  `.commandLine.original`, `.cwd.fsPath`, `.terminalCommandState.exitCode`.
- File tools: `invocationMessage.uris` is a dict keyed by `file://` URI.
- Tool parts carry no timestamp of their own.

`toolId`s seen: `copilot_readFile`, `copilot_applyPatch`, `copilot_memory`,
`run_in_terminal`.

## Approach

Replay the whole file on each change; emit each tool call once, by
`toolCallId`, when `isComplete`. Same shape as `AiderLogWatcher` (whole-file
reparse on a watchfiles trigger, emitted-id cursor). Session files are small;
incremental mutation application is not worth the code.

## Components

1. **Adapter** `copilot-vscode` in `agents/copilot_vscode.py`. Editor kind,
   placed right after `cursor` in `ADAPTERS` (`agents/__init__.py`).
2. **Parser** `parser/copilot_vscode.py`:
   - `replay(path) -> dict` applies the mutation log. A malformed or partial
     line (file mid-write) is skipped, never raised.
   - `actions(state) -> list[Action]` maps state to actions (rules below).
3. **`vscode_paths.py`** (new, shared): `default_user_dir(app)`, extracted
   from `cursor_discovery.default_cursor_user_dir()`. Cursor calls it with
   `"Cursor"`, Copilot with `"Code"`. No other refactor.
4. **Reuse** `cursor_discovery.build_workspace_map()` for workspace hash ->
   project folder.
5. **`CopilotVscodeWatcher`** in `parser/watcher.py`: watchfiles trigger ->
   full replay -> emit actions not yet emitted (set of emitted keys).
6. **`sniff_jsonl_format()`** (`agents/base.py`) returns `copilot-vscode`
   when line 0 is `{"kind":0,"v":{...}}` and `v` has `sessionId` and
   `requests`, so the Claude Code adapter's `claims()` rejects the file.

## Parsing and tool mapping

| `toolId` | `ToolType` | fields |
|---|---|---|
| `run_in_terminal` | `BASH` | `command` = `toolSpecificData.commandLine.original` |
| `copilot_readFile` | `READ` | `file_path` = first key of `invocationMessage.uris`, as a filesystem path |
| `copilot_applyPatch` | `EDIT` | `file_path` as above |
| anything else (e.g. `copilot_memory`) | `UNKNOWN` | `tool_name` = `toolId` |

Only `toolId`s seen in a real session are mapped. New ones are added when a
real session shows them.

**Success:**

- If `toolSpecificData.terminalCommandState.exitCode` exists: success iff
  `exitCode == 0`; otherwise `error_message = "exit code N"`.
- Else failure iff `resultError` is truthy or `resultDetails.isError` is
  `true`; `error_message = resultError` when it is a string.

**Emit rules:**

- A tool call is emitted once (key `toolCallId`), only when `isComplete`.
  Tool actions stream live while the turn runs.
- Each request emits one `assistant_message` action (key `requestId`) once
  `completionTokens` is present: `tokens_in = promptTokens`, `tokens_out = completionTokens`.
  `assistant_message` is in `NON_TOOL_ROLE_LABELS`, so `LoopDetector`
  ignores it (Cursor precedent). This keeps tokens off already-emitted tool
  actions.
- `timestamp` = the owning request's `timestamp`.
- `unpriced = True`, `cost_usd = 0`: `copilotCredits` are not dollars, and
  `modelId` may be `copilot/auto`.

## Discovery

`find_copilot_vscode_agents()`, merged into `find_running_agents()` like
`find_cursor_agents()`:

1. **Process gate:** any process named `Code.exe` (Windows) or `code`
   (Linux), name-only `psutil` loop like `is_cursor_running()`. The macOS
   process name is unverified. No clash with Cursor (`Cursor.exe`).
2. **Scan** `default_user_dir("Code")/workspaceStorage/*/chatSessions/*.jsonl`.
3. **Recency:** keep files modified within
   `COPILOT_VSCODE_ACTIVE_WINDOW_S = 1800` seconds. VS Code keeps every old
   chat; without this, `ps` lists all of them.
4. **Project:** workspace hash -> folder via `build_workspace_map()`.
   Unresolved -> skip (Cursor rule). Empty-window chats are skipped.
5. Sessions with zero `requests` are skipped (opened but unused chat).
6. Entry: `log_file` = the real `.jsonl` path (one file per session, so no
   synthetic log key); `pid` = `_synthetic_pid(session_id)`;
   `session_id` = file stem; `command` = `"vscode (copilot)"`.
7. Never raises; any failure -> empty list.

`check --log <file>` needs no special case: `adapter_for()` + the sniff
route it.

## Testing

- **Fixture** `tests/fixtures/copilot_vscode/session.jsonl`: scrubbed copy
  of the real session. User path replaced (`C:\Users\<user>` ->
  `C:\Users\dev`), large `result.metadata.renderedUserMessage` text trimmed,
  mutation structure unchanged so it still replays.
- **Unit tests** in `tests/test_copilot_vscode.py`:
  - replay: `kind:1`, `kind:2` with and without `i`;
  - mapping table;
  - `resultError: false` -> success; `exitCode: 1` -> failure,
    `"exit code 1"`;
  - emit-once: append lines, replay again, no duplicates;
  - partial last line skipped;
  - `assistant_message` withheld until `completionTokens` exists;
  - Claude Code adapter does not claim the file;
  - discovery against a temp user dir (`require_running=False`): recency
    cutoff, unresolved workspace, empty session.
- **Live:** new agent chat via
  `%LOCALAPPDATA%\Programs\Microsoft VS Code\bin\code.cmd chat -m agent`
  (on this machine `code` on PATH is Cursor), then `agentwatch ps`,
  `watch-all` (headless), `check`.

## Out of scope

VS Code Insiders / VSCodium user dirs (`default_user_dir(app)` makes them a
one-line addition), archived chats, remote/WSL windows, edit tools not yet
seen live (`replaceString`, `createFile`, ...), Copilot credit reporting,
Cline (own spec).
