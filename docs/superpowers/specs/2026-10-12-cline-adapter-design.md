# Cline Adapter — Design

**Date:** 2026-10-12
**Branch:** `feature/cline-adapter` (from `develop` @ `d3b70d5`)
**Issue:** #104
**Status:** Approved by the board, 2026-10-13 (see "Board decisions").
Fixture-verified only. Live testing was not approved, so nothing here has
been checked against a real Cline install.

## Goal

Make `agentwatch ps` / `watch-all` / `check` / `security-scan` see Cline
tasks. Cline is the VS Code extension `saoudrizwan.claude-dev`
(github.com/cline/cline). This is the second half of the VS Code track
(Copilot in VS Code was the first, #87).

## Sources

Everything below was read from source (read-only clones; no Cline code was
run). There is no Cline install on the dev machine, so **no claim here has
been checked against a live session yet.**

- **N** = `cline/cline` `main` @ `a48408909bf9b2ff7f620d420be8547fb509e8ed`
  (2026-10-12). Marketplace extension 4.1.23 (`apps/vscode/package.json:5`),
  CLI `@cline/cli` 3.0.70 (`apps/cli/package.json:2-4`).
- **L** = `cline/cline` `legacy-extension` @
  `7761370240ffce9e3890cb56f6c51655f3f5b0a7` (2026-08-18). Extension
  4.0.12 (`apps/vscode/package.json:5`).
- **V** = `microsoft/vscode` `main` @
  `72b3e1558739d58ace9bcb200578d4508c7c00d5`.

## Findings

### 1. Two storage formats ship at the same time

Since 4.1.0 the published VSIX is an A/B package. It contains a **legacy**
bundle (the `legacy-extension` branch) and a **next** bundle (the new
SDK-based extension, `main`). A loader picks one per window. The choice
comes from a PostHog percentage flag (`ext-sdk-bundle-rollout`), "starting
at 1%" (N `CHANGELOG.md:422`; N `apps/vscode-rollout/README.md`, "How it
works" and "Cohort rules").

The two bundles store tasks in different places and in different formats:

| | Legacy bundle (L) | Next / SDK bundle (N) |
|---|---|---|
| Root | VS Code `globalStorage/saoudrizwan.claude-dev/` | `~/.cline/data/` |
| Per task | `tasks/<taskId>/api_conversation_history.json`, `ui_messages.json`, `task_metadata.json`, `context_history.json`, `settings.json` | `sessions/<id>/<id>.messages.json`, `sessions/<id>/<id>.json` (manifest) |
| Index | `state/taskHistory.json` | `db/sessions.db` (SQLite) plus the per-session manifest |
| Also written by | — | Cline CLI, JetBrains, Cline desktop |

The rollout README says outright that tasks made on the SDK bundle are
"stored as SDK sessions the legacy bundle doesn't list". The SDK bundle
does read the legacy store, read-only, for history: `legacyExtensionStorageDir`
is set to `globalStorageUri.fsPath` (N
`apps/vscode/src/sdk/SdkController.ts:507`;
`apps/vscode/src/sdk/sdk-task-history.ts:215-222`).

### 2. Legacy bundle (L)

**Location.** The extension passes `context.globalStorageUri.fsPath` to
`HostProvider` (L `apps/vscode/src/extension.ts:635-646`). Task dirs are
`<globalStorageFsPath>/tasks/<taskId>` (L `core/storage/disk.ts:129-133`,
`444-448`). VS Code builds `globalStorageUri` as
`<profile>/globalStorage/<extension id, lowercased>` (V
`src/vs/workbench/api/common/extHostStoragePaths.ts:89-91`), where
`globalStorageHome = joinPath(location, 'globalStorage')` (V
`src/vs/platform/userDataProfile/common/userDataProfile.ts:196`). For the
default profile that gives
`default_user_dir("Code")/globalStorage/saoudrizwan.claude-dev/`. Cline's
own comment confirms that task data stays on this path and is not moved to
`~/.cline/data` (L `apps/vscode/src/hosts/vscode/vscode-to-file-migration.ts:25-32`).

**File names** (L `core/storage/disk.ts:48-71`): `api_conversation_history.json`,
`ui_messages.json`, `context_history.json`, `task_metadata.json`. Very old
tasks may still have `claude_messages.json`, which the reader migrates on
open (L `disk.ts:305-325`).

**Writes.** `api_conversation_history.json`, `ui_messages.json` and
`state/taskHistory.json` are **rewritten whole** through `atomicWriteFile`
(write `<file>.tmp.<ts>.<rand>.json`, then `rename`) (L `disk.ts:34-46`,
`282-300`, `328-337`, `500-505`). A reader never sees a torn file, but the
file is replaced, not appended to. `task_metadata.json` is a plain
`fs.writeFile` and can be read torn (L `disk.ts:389-394`).

**`api_conversation_history.json`** is a JSON array of `ClineStorageMessage`
(L `shared/messages/content.ts:99-123`): an Anthropic `MessageParam`
(`role`, `content` as a string or a block list) plus `id`, `modelInfo
{modelId, providerId, mode}`, `metrics {tokens {prompt, completion,
cached}, cost}` and `ts` (epoch ms) (L `shared/messages/metrics.ts:3-18`).

- Assistant messages are appended once per API request, after the stream
  ends: `[redacted thinking..., thinking?, text?, tool_use...]`, with that
  request's `metrics` (L `core/task/index.ts:3204-3215`, `3842-3884`).
- `tool_use` blocks: `{type, id, name, input, call_id?}`. Tool names are
  `ClineDefaultTool` (L `shared/tools.ts:8-36`).
- Results come back in the next user message. With a real tool id they are
  `{type: "tool_result", tool_use_id, call_id, content}`, where `content`
  is `"<description> Result:\n<text>"` and **`is_error` is never set** (L
  `core/task/tools/utils/ToolResultUtils.ts:36-49`, `66-84`).
- **XML mode.** Native tool calling is used only when `nativeToolCallEnabled`
  is on (the default, L `shared/storage/state-keys.ts:89`) **and** the
  provider/model is "next-gen" (Claude 4+, GPT-5, Gemini 2.5/3, ...; L
  `utils/model-utils.ts:246-255`). Otherwise the tool call is XML inside the
  assistant `text` block, and the result is a plain `text` block
  `"[tool for 'x'] Result:..."` with tool id `"cline"` (L
  `ToolResultUtils.ts:36`, `66-73`; `core/task/index.ts:3375`, `3555-3556`).
- Errors are signalled only through the result text:
  `"The user denied this operation."` and `"The tool execution failed with
  the following error:\n<error>..."` (L `core/prompts/responses.ts:23-25`).
  `execute_command` results begin with `"Command executed successfully
  (exit code 0)."` or `"Command failed with exit code N."` (L
  `integrations/terminal/CommandOrchestrator.ts:634-646`), behind the
  description `[execute_command for '<cmd>']` (L
  `ExecuteCommandToolHandler.ts:63-65`).

**`ui_messages.json`** is a JSON array of `ClineMessage` `{ts, type:
"ask"|"say", ask?, say?, text?, partial?, ...}` (L
`shared/ExtensionMessage.ts:123-140`). `say: "api_req_started"` carries a
JSON `text` of `ClineApiReqInfo {tokensIn, tokensOut, cacheWrites,
cacheReads, cost, cancelReason, streamingFailedMessage}` (L `:350-365`).
`say/ask: "tool"` carries `ClineSayTool {tool: "readFile"|"editedExistingFile"|...,
path, diff, ...}` (L `:202-227`). It is a UI log: richer for display, but
harder to pair calls with results. The API history already has the ids,
inputs, results and per-request tokens, so this design does not parse
`ui_messages.json`.

**`state/taskHistory.json`** is a JSON array of `HistoryItem {id, ts, task,
tokensIn, tokensOut, cacheWrites?, cacheReads?, totalCost,
cwdOnTaskInitialization?, modelId?, ...}` (L `shared/HistoryItem.ts:1-20`;
path at L `disk.ts:453-455`). Nothing in it marks a task as active.

### 3. SDK bundle and Cline CLI (N)

**Location.** Data dir = `CLINE_DATA_DIR`, else `CLINE_DIR/data`, else
`~/.cline/data` (N `sdk/packages/shared/src/storage/paths.ts:158-167`,
`186-192`; the extension resolves the same way in
`apps/vscode/src/shared/storage/storage-context.ts:93-100`). The sessions
dir is `CLINE_SESSION_DATA_DIR`, else `<data>/sessions` (`paths.ts:194-200`).
Cline's docs list the same layout (N `docs/getting-started/config.mdx:14-34`).

**Per-session files** (N `sdk/packages/core/src/services/session-artifacts.ts:63-94`):
`sessions/<id>/<id>.messages.json`, `<id>.json` (manifest), and
`<id>.compaction.json`. Subagent and teammate transcripts sit in the root
session's dir as `<agentId>.messages.json` or
`<agentId>__<teamTaskId>.messages.json` (`:132-144`).

**Manifest** `<id>.json` (N `core/src/session/models/session-manifest.ts:6-30`):
`version: 1`, `session_id`, `source`, `pid`, `started_at`, `ended_at?`,
`exit_code?`, `status`, `interactive`, `provider`, `model`, `cwd`,
`workspace_root`, `prompt?`, `metadata?` (has `title`), `messages_path?`.

- `status` is one of `idle`, `running`, `pending`, `completed`, `failed`,
  `cancelled`. The first three are non-terminal (N
  `sdk/packages/shared/src/session/records.ts:1-16`;
  `core/src/types/common.ts:7-11`).
- `pid` is `process.pid` of the host that runs the session (N
  `core/src/runtime/host/local-runtime-host.ts:478-485`). The VS Code
  extension runs the SDK in-process (`backendMode: "local"`), with `source
  "vscode"` (N `apps/vscode/src/sdk/vscode-session-host.ts:168`, `185`), so
  `pid` is the VS Code extension host. The CLI uses `source "cli"` (N
  `apps/cli/src/runtime/run-agent.ts:284`) and `backendMode: "auto"` (N
  `apps/cli/src/runtime/interactive/session-runtime.ts:157`). Whether
  `auto` puts the CLI's `pid` on a shared hub daemon has not been checked.
- Status changes rewrite the manifest (N `local-runtime-host.ts:2488-2510`).
  Cline itself treats a non-terminal session whose `pid` is dead as failed
  (`persistence-service.ts:430-445` and `reconcileDeadRunningSession`).

**Messages** `<id>.messages.json` (N `core/src/services/session-data.ts:334-380`):
`{version: 1, updated_at, agent: "lead"|"subagent"|"teammate", sessionId,
taskType?, origin {source, mode, sessionId, ...}, messages: [...],
system_prompt?}`.

- The file is **rewritten whole with a plain `writeFileSync`, not
  atomically**, so a torn read is possible (N
  `core/src/session/stores/session-manifest-store.ts:220-238`). It is
  persisted at each primary-agent `iteration_end` (N
  `core/src/services/agent-events.ts:312-318`) and when a run ends.
- `messages[]` is `MessageWithMetadata` (N
  `sdk/packages/shared/src/llms/messages.ts:130-165`): `role`, `content`
  (a string or blocks), `id?`, `modelInfo {id, provider}`, `metrics
  {inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens, cost}`,
  `ts?`.
- Blocks (`messages.ts:57-125`): `tool_use {id, call_id?, name, input}`;
  `tool_result {tool_use_id, name, content, is_error?}`, where `is_error`
  **is** written (N `core/src/runtime/config/agent-message-codec.ts:296-303`);
  also `text`, `thinking`, `redacted_thinking`, `image`, `file`, `media`.
- Per-turn `metrics` are stamped on assistant messages. When a run has no
  per-turn metrics, only its last assistant message gets run totals (N
  `session-data.ts:122-200`).
- Built-in tool names (N `core/src/extensions/tools/constants.ts:12-22`):
  `read_files`, `search_codebase`, `run_commands`, `fetch_web_content`,
  `apply_patch`, `editor`, `skills`, `ask_question`, `submit_and_exit`.
  Input schemas: N `core/src/extensions/tools/schemas.ts:57`
  (`read_files.files[].path`), `111` (`search_codebase.queries`), `149-171`
  (`run_commands.commands[]`, plus loose forms), `185`
  (`fetch_web_content.requests[].url`), `194` (`editor.path`), `234`
  (`apply_patch.input`). The VS Code host adds its own tools
  (`apps/vscode/src/sdk/vscode-run-commands-tool.ts`,
  `vscode-file-read-executor.ts`). Their names have not been checked.

### 4. The Cline CLI

There is a standalone CLI: `@cline/cli`, binary `cline` (N
`apps/cli/package.json:2-4`, `38-39`). It writes to the same
`~/.cline/data/sessions` store as the SDK bundle. One SDK-format reader
therefore covers the CLI, the SDK VS Code bundle, JetBrains and Cline
desktop, all told apart by `source`.

## Approach

One `cline` adapter with two small source readers. Both formats use the
same Anthropic-style blocks (`tool_use.id` ↔ `tool_result.tool_use_id`),
so one block-to-`Action` mapper serves both. Each source has its own
tool-name table and error rule. Files are rewritten whole and are small, so
the watcher re-parses the whole file on each change and emits by key
(`CopilotVscodeWatcher` / `AiderLogWatcher` shape). No incremental parsing.

## Components

1. **Adapter** `cline` in `agents/cline.py`. Editor kind, appended to the
   end of `ADAPTERS`.
   - `discover()` = `find_cline_agents()` (below).
   - `claims(path)`: `path.name == "api_conversation_history.json"`, or
     `path.name.endswith(".messages.json")` whose top level has
     `version == 1`, a `messages` list and `sessionId`. No existing adapter
     claims `.json`.
   - `make_watcher` → `ClineWatcher`; `parse_file` → `parse_cline`.
2. **Parser** `parser/cline.py`:
   - `load(path) -> list[dict] | None`: `json.load`. Legacy files are
     top-level arrays; SDK files use `["messages"]`. A torn or partial file
     returns `None`. It never raises.
   - `actions(messages, flavor, session_id) -> list[(key, Action)]`, using
     the rules below.
3. **`ClineWatcher`** in `parser/watcher.py`: on a watchfiles `added` or
   `modified` event for the file (the legacy `rename` shows up as either),
   reload. On `None` keep the last state. Emit actions whose key is new.
4. **Reuse:** `vscode_paths.default_user_dir`,
   `copilot_vscode._vscode_running` (moved to a shared spot only if a
   second caller needs it; importing it is fine),
   `cursor_discovery._synthetic_pid`, `discovery._format_etime`.

## Parsing and tool mapping

**Pairing.** Walk the messages in order. Each assistant `tool_use` is held
until a `tool_result` with the same id appears in a later user message,
then emitted once (key = tool id). A `tool_use` with no result yet is not
emitted. This is the same "emit when final" rule as Copilot.

**Legacy tool names** (L `shared/tools.ts:8-36`):

| tool | `ToolType` | fields |
|---|---|---|
| `execute_command` | `BASH` | `command` = `input.command` |
| `read_file` | `READ` | `file_path` = `input.path` or `input.absolutePath` |
| `write_to_file` | `WRITE` | `file_path` = `input.path` |
| `replace_in_file`, `apply_patch` | `EDIT` | `file_path` = `input.path` (none for `apply_patch`) |
| `search_files` | `SEARCH` | `file_path` = `input.path` |
| `list_files`, `list_code_definition_names` | `LIST` | `file_path` = `input.path` |
| `browser_action` | `BROWSER` | — |
| `use_mcp_tool`, `access_mcp_resource`, `load_mcp_documentation` | `MCP` | — |
| `web_fetch` | `UNKNOWN` | `network_host` from `input.url` if present |
| anything else | `UNKNOWN` | `tool_name` = name |

**SDK tool names** (N `constants.ts:12-22`):

| tool | `ToolType` | fields |
|---|---|---|
| `run_commands` | `BASH` | `command` = the commands joined with `"\n"`; for a structured entry, `command` plus `args`. The loose forms in `schemas.ts:162-171` are accepted |
| `read_files` | `READ` | `file_path` = the first `files[].path` (or the bare string form) |
| `editor` | `EDIT` | `file_path` = `input.path` |
| `apply_patch` | `EDIT` | — |
| `search_codebase` | `SEARCH` | — |
| `fetch_web_content` | `UNKNOWN` | `network_host` from the first `requests[].url` |
| anything else | `UNKNOWN` | `tool_name` = name |

Legacy input names come from what the handlers read: `block.params.path ||
block.params.absolutePath` (L
`core/task/tools/handlers/WriteToFileToolHandler.ts:32-36`), `command`,
`regex`, `url`. Native `input` values are copied into `params` (L
`core/task/StreamResponseHandler.ts:208`). `path` is relative to the
workspace and is reported as written (not resolved against the cwd). These
names have not been seen in a real history yet. If one is wrong,
`file_path` is just empty; nothing breaks.

**Success:**

- SDK: failure iff `is_error is True`.
- Legacy: there is no `is_error`, so failure iff the result text, after
  the `"<description> Result:\n"` prefix, starts with `"The user denied
  this operation."`, `"The tool execution failed with the following
  error:"`, or `"Command failed with exit code "`. `error_message` = that
  line.

**Tokens.** Each assistant message that has `metrics` emits one
`assistant_message` action (key = message index plus `id`), with
`tokens_in`/`tokens_out` and `cost_usd`.

- Legacy: `prompt`, `completion`, `cost`.
- SDK: `inputTokens` + `cacheReadTokens` + `cacheWriteTokens` for input,
  `outputTokens`, `cost`.

`assistant_message` is in `NON_TOOL_ROLE_LABELS`, so `LoopDetector` ignores
it (Cursor/Copilot precedent). `cost_usd` uses Cline's own reported cost.
When it is absent, set `unpriced = True`.

**Timestamps.** The owning assistant message's `ts` when present, else the
file mtime.

## Discovery

`find_cline_agents()`, merged in like `find_copilot_vscode_agents()`. It
never raises; any failure gives an empty list.

**Legacy source:**

1. Gate: `_vscode_running()` (`Code.exe` / `code`).
2. Scan
   `default_user_dir("Code")/globalStorage/saoudrizwan.claude-dev/tasks/*/api_conversation_history.json`.
3. Keep files modified within the 1800 s window Copilot uses
   (`COPILOT_VSCODE_ACTIVE_WINDOW_S`, reused). Nothing on
   disk marks a task as active, so recency is the only signal (same
   reasoning as Copilot).
4. Project = `cwdOnTaskInitialization` of the matching `HistoryItem` in
   `state/taskHistory.json`. If it cannot be resolved, use
   `working_directory=None` (#94 allows that) rather than skipping. A task
   is per-folder by construction, but the field is optional.
5. Entry: `log_file` = the real file; `pid = _synthetic_pid(taskId)`;
   `session_id` = taskId; `command = "vscode (cline)"`.

**SDK source** (no editor gate, because the CLI has no editor):

1. Sessions dir from agentwatch's own environment, resolved the way Cline
   resolves it: `CLINE_SESSION_DATA_DIR`, else `CLINE_DATA_DIR/sessions`,
   else `CLINE_DIR/data/sessions`, else `~/.cline/data/sessions` (N
   `sdk/packages/shared/src/storage/paths.ts:158-167`, `186-200`). Each
   value is trimmed and ignored when empty, as Cline does. This is the same
   approach opencode takes with `OPENCODE_DB`.
2. Read each `sessions/*/<id>.json` manifest. Keep it if `status` is
   non-terminal **and** `psutil.pid_exists(pid)`, which is Cline's own
   liveness rule. Also apply the 1800 s mtime window on `messages.json`,
   because a long-idle interactive session in a still-open VS Code stays
   `idle` forever.
3. Root sessions only (the `<id>.messages.json` named after the dir).
   Subagent/teammate files are skipped in v1.
4. Entry: `log_file` = `<dir>/<id>.messages.json`. The manifest's
   absolute `messages_path` is not followed, so a manifest cannot point
   agentwatch outside the sessions dir. `pid =
   _synthetic_pid(session_id)`. Several sessions share one extension-host
   pid, and `AgentProcess.pid` must be unique, so the real `pid` is used
   only for the liveness check. `working_directory = cwd`; `command =
   f"cline ({source})"`; uptime from `started_at`.

`check --log <file>` works through `claims()`.

## Testing

- **Fixtures, synthetic only** (no Cline install, no real user data), built
  from the source shapes above:
  - `tests/fixtures/cline/legacy/tasks/<id>/api_conversation_history.json`:
    native-mode `execute_command` (exit 0 and exit 1), `read_file`,
    `replace_in_file`, one denied call, and a trailing `tool_use` with no
    result.
  - `tests/fixtures/cline/legacy/state/taskHistory.json`.
  - `tests/fixtures/cline/sdk/sessions/<id>/<id>.json` and
    `<id>.messages.json`: `run_commands` (string and structured forms),
    `read_files`, `editor`, one `is_error: true`, per-turn metrics, and a
    subagent file in the same dir.
- **Unit tests** in `tests/test_cline.py`:
  - both mapping tables;
  - the success rules (legacy text prefixes, SDK `is_error`);
  - an unpaired `tool_use` is held, then emitted once when the result
    arrives (rewrite the file, reload, check there are no duplicates);
  - a torn file (truncated JSON) gives `None` and the watcher keeps its
    state;
  - token actions per assistant message (both metric shapes);
  - `claims()` accepts both file kinds and rejects an unrelated `.json`;
    the Claude Code adapter does not claim them;
  - discovery against temp dirs (`require_running=False`): recency
    cutoff, terminal status skipped, dead pid skipped, subagent file
    skipped, unresolved legacy cwd gives `None`.
- **Live:** none is possible on this machine yet (no Cline install, no
  credentials). Ship as **fixture-verified** in CLAUDE.md/README, the same
  honesty rule as Codex.

## Known limitations

- XML-mode legacy tasks (models that are not "next-gen", or native tool
  calling turned off) show no tool actions in v1, only per-request token
  actions.
- Legacy "active" is a recency guess. A task finished less than 30 minutes
  ago is listed.
- The legacy error rule depends on Cline's English result strings.

## Out of scope

- Legacy tasks in editors other than VS Code stable: Insiders, VSCodium,
  Cursor, Windsurf (#116).
- Roo Code (#117) and Kilo Code (#118).
- Non-default VS Code profiles (`<User>/profiles/<id>/globalStorage`, V
  `userDataProfile.ts:196`).
- Remote / WSL extension hosts.
- Parsing XML-in-text tool calls in legacy tasks. Those tasks show token
  actions only.
- Live verification: installing Cline or getting credentials was not
  approved.
- `ui_messages.json`, subagent/teammate transcripts, JetBrains-specific
  paths, `sessions.db`.

## Board decisions (2026-10-13)

1. Support both formats: the legacy `globalStorage` task store and the SDK
   `~/.cline/data/sessions` store, with the env overrides resolved as in
   Cline's source.
2. The Cline CLI is in scope. It shares the SDK store, and the manifest's
   `source` tells it apart.
3. Legacy editors: VS Code stable only. Other editors are tracked in #116.
4. Roo Code (#117) and Kilo Code (#118) are not part of #104.
5. Legacy XML-in-text tool calls get token counts only, with no XML
   parsing. The code marks this with a `ponytail:` comment.
6. Live testing is not approved. Ship as fixture-verified only.
7. Non-default VS Code profiles and remote/WSL windows are out of scope.
