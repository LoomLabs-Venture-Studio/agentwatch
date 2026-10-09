# GitHub Copilot in VS Code — Implementation Plan

**Issue:** #87
**Spec:** `docs/superpowers/specs/2026-10-09-copilot-vscode-design.md`
(branch `docs/copilot-vscode-spec`, PR #88). The spec is the source of truth;
this plan only orders the work.
**Branch:** `feature/copilot-vscode-adapter` (from `develop` @ `114c425`)

TDD throughout: write the failing test, see it fail, implement, see it pass.
One commit per task, format `type(scope): description [#87]`.

## Task 1: fixture

- `tests/fixtures/copilot_vscode/session.jsonl`: copy of the real session
  `%APPDATA%/Code/User/workspaceStorage/2a87d79baf715713d5dc1aab5d2c3647/chatSessions/b4d87730-a8da-47a4-8a80-c39642ea196f.jsonl`.
- Scrub: `zaid-akroush` -> `dev`, `Zaid` -> `dev` (paths and URIs). Trim
  `result.metadata.renderedUserMessage` text (line 13) to a short stub.
  Mutation structure unchanged: 23 lines, same kinds/keys/`i`.
- Commit: `test(copilot-vscode): add scrubbed real session fixture [#87]`.

## Task 2: parser `parser/copilot_vscode.py`

- `replay(path) -> dict | None`: kinds 0 (reset), 1 (set), 2 (push, optional
  `v`, optional `i` truncate), 3 (delete). Malformed/partial lines and
  mutations whose path does not resolve are skipped, never raised. No
  `kind:0` -> `None`.
- `actions(state, session_id=None) -> list[tuple[str, Action]]` (key, action):
  keys are `toolCallId` / `requestId`. Tool mapping, success, emit rules and
  `assistant_message` exactly as the spec's "Parsing and tool mapping".
  Timestamps: request `timestamp` ms -> naive UTC (opencode precedent).
  `unpriced=True`. File URIs -> paths via `cursor_discovery._file_uri_to_path`.
- `parse_copilot_vscode(path, session_id=None) -> Iterator[Action]` for the
  one-shot path.
- Tests (`tests/test_copilot_vscode.py`): replay kinds; mapping table;
  `resultError: false` success; exit code 1 failure `"exit code 1"`; denied;
  terminal call without `isConfirmed` not emitted, then emitted once with
  `exitCode` (replay fixture prefix lines 0..9 vs 0..12); assistant_message
  withheld until `modelState` 1/2/3 and carries 588/20603; partial last line;
  fixture has no `Zaid`/`zaid-akroush`. Full fixture -> 5 tool actions
  (`copilot_readFile` READ, `copilot_memory` UNKNOWN, `copilot_applyPatch`
  EDIT, `run_in_terminal` x2 BASH: `python hello.py` ok, `nonexistent-cmd`
  failed) + 1 assistant_message.

## Task 3: format sniff + adapter + registry

- `detect_log_format()`: `copilot_vscode` for `{"kind":0,"v":{sessionId, requests, ...}}`.
- `ClaudeCodeAdapter.claims()` excludes `copilot_vscode`.
- `agents/copilot_vscode.py`: `CopilotVscodeAdapter` (`name="copilot-vscode"`,
  `kind="editor"`), `claims` = `.jsonl` sniffed `copilot_vscode`,
  `parse_file`, `make_watcher`, `discover` (Task 5). Registered right after
  `cursor`. Update the registry-order tests and the module docstring.
- Tests: `adapter_for(fixture)` is copilot-vscode; claude-code does not claim it;
  `parse_file(fixture)` yields the Task 2 actions.

## Task 4: `vscode_paths.py` + watcher

- `vscode_paths.default_user_dir(app)`: body of
  `cursor_discovery.default_cursor_user_dir()` parameterised by app folder
  name; `default_cursor_user_dir()` becomes `return default_user_dir("Cursor")`.
- `CopilotVscodeWatcher(path, session_id=None)` in `parser/watcher.py`:
  initial replay, then `awatch(path.parent)`, react to `added`/`modified` of
  `path`, emit keys not yet emitted. Same `on_action`/`watch_with_callbacks`
  surface as `AiderLogWatcher`.
- Tests: append lines to a temp copy, `_read_new_actions()` twice, no
  duplicates; the pending terminal call appears only after its rewrite.

## Task 5: discovery

- `find_copilot_vscode_agents(*, user_dir=None, require_running=True,
  now=None)` in `agents/copilot_vscode.py` (or a small module next to it),
  per spec "Discovery": name gate `Code.exe`/`code`, scan
  `workspaceStorage/*/chatSessions/*.jsonl`, 1800 s mtime window,
  `build_workspace_map`, skip unresolved and zero-request sessions,
  `_synthetic_pid(session_id)`, `command="vscode (copilot)"`. Never raises.
- Tests with a temp user dir and `require_running=False`: recency cutoff,
  unresolved workspace, empty session, happy path fields.

## Task 6: verification

- `python -m pytest tests/ -q`, `ruff check .`.
- Live: `code.cmd chat -m agent` in `~/Desktop/aw-vscode-test`, then
  `agentwatch ps`, `watch-all` engine headless, `agentwatch check --log <session>`.
- CLAUDE.md: add the adapter to "What This Is" / Architecture.
