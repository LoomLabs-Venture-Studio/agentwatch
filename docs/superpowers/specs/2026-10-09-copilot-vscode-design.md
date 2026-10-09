# GitHub Copilot in VS Code — Design

**Date:** 2026-10-09
**Branch:** `docs/copilot-vscode-spec` (from `develop` @ `114c425`)
**Issue:** #87

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
  `v` (`v` may be absent); when `i` is present, truncate the array to `i`
  first.
- `{"kind":3,"k":[path...]}` — delete the key at `k`.
- A `kind:0` line resets the state. VS Code also rewrites the whole file
  (its "replace" op), so the file can shrink.

Source: `src/vs/workbench/contrib/chat/common/model/objectMutationLog.ts`
(`EntryKind` Initial=0, Set=1, Push=2, Delete=3) and `chatSessionStore.ts`
(append vs replace writes), microsoft/vscode @ main, checked 2026-10-09.

Replaying lines 0..N in order gives the session state. Confirmed: all 5 tool
calls of the real session rebuild correctly.

State shape used here:

- `requests[]`: `timestamp` (epoch ms), `modelId` (e.g. `copilot/auto`),
  `promptTokens`, `completionTokens`, `copilotCredits`, `response[]`.
- `requests[].modelState`: `{"value": n}`, with `completedAt` once the turn
  ends. `ResponseModelState` (`chatService.ts`): 0 Pending, 1 Complete,
  2 Cancelled, 3 Failed, 4 NeedsInput (e.g. waiting for terminal
  confirmation).
- `completionTokens` / `promptTokens` are written **mid-turn and
  overwritten later**: the real session set them to 431/20275 while
  `modelState` was 4, then 588/20603 after it reached 1.
- Tool parts in `response[]`: `kind: "toolInvocationSerialized"`,
  `toolCallId`, `toolId`, `isComplete`, `isConfirmed`, `invocationMessage`,
  and optionally `resultError`, `resultDetails`, `toolSpecificData`.
- **`isComplete` is always `true` in the file.** `ChatToolInvocation.toJSON()`
  hard-codes it, in-flight calls included. The real session shows it: the
  first `run_in_terminal` was written with `isComplete: true`, no
  `isConfirmed` and no `terminalCommandState` while it waited for the user,
  then rewritten (`kind:2` with `i`) with `isConfirmed: {"type": 4}` and
  `exitCode: 0`.
- `isConfirmed`: `{"type": n}` with `ToolConfirmKind` 0 Denied,
  1 ConfirmationNotNeeded, 2 Setting, 3 LmServicePerTool, 4 UserAction,
  5 Skipped; a bare boolean before VS Code 1.104; absent while the call
  waits for confirmation.
- `invocationMessage` is either a markdown object (with `uris`) or a plain
  string (`copilot_memory`).
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
`toolCallId`, when it is final (rule below). Same shape as `AiderLogWatcher` (whole-file
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
5. **`CopilotVscodeWatcher`** in `parser/watcher.py`: watchfiles trigger
   (`added` or `modified` on the file, since VS Code may rewrite it) ->
   full replay -> emit actions not yet emitted (set of emitted keys).
6. **`detect_log_format()`** (`parser/logs.py`, used by
   `sniff_jsonl_format()`) returns `copilot_vscode` for an entry
   `{"kind":0,"v":{...}}` whose `v` has `sessionId` and `requests`. The
   Claude Code adapter's `claims()` excludes `copilot_vscode`; the new
   adapter claims `.jsonl` files that sniff as `copilot_vscode`.

## Parsing and tool mapping

| `toolId` | `ToolType` | fields |
|---|---|---|
| `run_in_terminal` | `BASH` | `command` = `toolSpecificData.commandLine.original` |
| `copilot_readFile` | `READ` | `file_path` = first key of `invocationMessage.uris`, as a filesystem path (none when `invocationMessage` is a string) |
| `copilot_applyPatch` | `EDIT` | `file_path` as above |
| anything else (e.g. `copilot_memory`) | `UNKNOWN` | `tool_name` = `toolId` |

Only `toolId`s seen in a real session are mapped. New ones are added when a
real session shows them.

**Success:**

- `isConfirmed` type 0 (Denied) or `false`: failure, `error_message =
  "denied"`. Type 5 (Skipped): failure, `"skipped"`.
- Else if `toolSpecificData.terminalCommandState.exitCode` exists: success iff
  `exitCode == 0`; otherwise `error_message = "exit code N"`.
- Else failure iff `resultError` is truthy or `resultDetails.isError` is
  `true`; `error_message = resultError` when it is a string.

**Emit rules:**

- A tool call is emitted once (key `toolCallId`), only when final:
  `isConfirmed` is present, and one of
  - it was denied or skipped (type 0 or 5, or `false`);
  - a result is recorded: `terminalCommandState.exitCode`, a truthy
    `resultError`, or `resultDetails`;
  - a later `thinking` or markdown part (no `kind`, or `markdownContent`)
    follows it in the same response: the model only writes again after the
    round's tool results are back;
  - its request is finished (`modelState.value` in 1, 2, 3).

  `isComplete` is not used (always `true`). Most tool actions still stream
  while the turn runs; a call followed only by more tool calls waits for
  the next model output or the turn end.
- Each request emits one `assistant_message` action (key `requestId`) once
  the request is finished (`modelState.value` in 1, 2, 3), not when
  `completionTokens` first appears (it is overwritten mid-turn):
  `tokens_in = promptTokens`, `tokens_out = completionTokens`.
  `assistant_message` is in `NON_TOOL_ROLE_LABELS`, so `LoopDetector`
  ignores it (Cursor precedent). This keeps tokens off already-emitted tool
  actions.
- `timestamp` = the owning request's `timestamp`. Terminal calls:
  `duration_ms = terminalCommandState.duration` when present.
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
  of the real session. User name and GitHub login replaced with `dev`
  everywhere (paths, URIs), large `result.metadata.renderedUserMessage` text trimmed,
  mutation structure unchanged so it still replays.
- **Unit tests** in `tests/test_copilot_vscode.py`:
  - replay: `kind:1`, `kind:2` with and without `i`, `kind:3`, a later
    `kind:0` resetting state;
  - mapping table;
  - `resultError: false` -> success; `exitCode: 1` -> failure,
    `"exit code 1"`; denied -> failure;
  - a terminal call without `isConfirmed` (waiting for the user) is not
    emitted; once rewritten with `exitCode` it is emitted once, with the
    real result (the real session's lines 9 and 12);
  - fixture has no `Zaid` / `zaid-akroush` left;
  - emit-once: append lines, replay again, no duplicates;
  - partial last line skipped;
  - `assistant_message` withheld until the request is finished, then
    carries the final tokens (588/20603 in the fixture, not 431/20275);
  - Claude Code adapter does not claim the file;
  - discovery against a temp user dir (`require_running=False`): recency
    cutoff, unresolved workspace, empty session.
- **Live:** new agent chat via
  `%LOCALAPPDATA%\Programs\Microsoft VS Code\bin\code.cmd chat -m agent`
  (on this machine `code` on PATH is Cursor), then `agentwatch ps`,
  `watch-all` (headless), `check`.

## Out of scope

Flat `.json` session files (VS Code before 1.109, or
`chat.useLogSessionStorage: false`), VS Code Insiders / VSCodium user dirs (`default_user_dir(app)` makes them a
one-line addition), archived chats, remote/WSL windows, edit tools not yet
seen live (`replaceString`, `createFile`, ...), Copilot credit reporting,
Cline (own spec).
