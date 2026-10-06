# agentwatch adapter candidates: research probe (2026-10-05)

Nothing was installed and nothing was run. Every claim cites a URL. "Confirmed" means read in official source code, official docs, or the official npm registry record. "Unverified" means no official source was found. Source code was read from each project's default branch (`main`, or `dev` for OpenCode) as of today, so line contents can drift.

How agentwatch adapters work (from `src/agentwatch/agents/{base,copilot,agy}.py`): an adapter supplies `process_pattern` (a regex over argv[0], or over the script that follows node/python), `resolve_log(cwd, pid)`, `claims(path)`, `make_watcher`, and `parse_file`. The cheapest target is an append-only JSONL file that `LogWatcher` can tail. A SQLite store needs a polling watcher like `CursorWatcher`. A whole-file JSON rewrite needs a reparse plus a cursor, like `AiderLogWatcher`.

## Summary table

| Agent | Official package / install | Publisher verified | Process in ps | Local store (Linux) | Format | Append-only? | Call ids |
|---|---|---|---|---|---|---|---|
| Gemini CLI | `npm i -g @google/gemini-cli` | yes (Google) | `node …/bin/gemini` | `~/.gemini/tmp/<slug>/chats/session-*.jsonl` | JSONL | yes (records re-appended; last one per `id` wins) | yes (`toolCalls[].id`) |
| Qwen Code | `npm i -g @qwen-code/qwen-code` | yes (QwenLM, OIDC) | `node …/bin/qwen` | `~/.qwen/projects/<sanitized-cwd>/chats/<sessionId>.jsonl` | JSONL | yes | yes (`callId`) |
| OpenCode | `npm i -g opencode-ai` / `brew install anomalyco/tap/opencode` | yes (anomalyco, OIDC) | native `opencode` | `~/.local/share/opencode/opencode.db` | SQLite (WAL) | rows | yes (`callID`) |
| Kilo CLI | `npm i -g @kilocode/cli` | yes (Kilo-Org, OIDC) | native `kilo` | `~/.local/share/kilo/kilo.db` | SQLite (WAL, OpenCode fork) | rows | yes (inherited) |
| Crush | `brew install charmbracelet/tap/crush` / `npm i -g @charmland/crush` | yes (Charm, OIDC) | native `crush` | `<project>/.crush/crush.db` | SQLite (WAL) | rows, updated in place | yes (`tool_call_id`) |
| Goose | `curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh \| bash` | yes (aaif-goose, formerly block) | native `goose` | `~/.local/share/goose/sessions/sessions.db` | SQLite (WAL) | inserts, some delete+reinsert | yes (tool request `id`) |
| Cline CLI | `npm i -g cline` | yes (Cline Bot Inc, OIDC) | `node …/bin/cline` (unverified) | `~/.cline/data/sessions/<id>/<id>.messages.json` | whole JSON | **rewritten** | unverified field names |
| Continue `cn` | `npm i -g @continuedev/cli` | yes (continuedev, OIDC) | `node …/dist/cn.js` | `~/.continue/sessions/<id>.json` | whole JSON | **rewritten** | yes (`toolCallId`) |
| Cursor CLI | `curl https://cursor.com/install -fsS \| bash` | yes (cursor.com) | `agent` (unverified in ps) | `~/.cursor/chats/<ws-hash>/<uuid>/` (Cursor staff, forum) | unverified | unverified | stream-json only |
| Amp | `curl -fsSL https://ampcode.com/install.sh \| bash` (npm `@ampcode/cli`) | yes (Sourcegraph/Amp, OIDC) | native `amp` | **server-side threads** | n/a | n/a | stream-json only |
| Kiro CLI (ex-Amazon Q) | `curl -fsSL https://cli.kiro.dev/install \| bash` | yes (kiro.dev / AWS) | `kiro-cli` | unofficial reports only: SQLite and/or `~/.kiro/sessions/cli/*.jsonl` | unverified | unverified | unverified |
| Roo Code | none, **shut down 2026-05-15** | n/a | n/a | n/a | n/a | n/a | n/a |

## Look-alike and publisher warnings

- **`qwen-code` (unscoped npm)** is NOT official. It is v0.0.5, published by an individual account (`liangshuai`), has an HTML-junk description, and pulls an unusual dependency, `gensign-node`. Its `repository` field points at QwenLM, but anyone can set that field. The real package is `@qwen-code/qwen-code`, published via GitHub OIDC. Confirmed: https://registry.npmjs.org/qwen-code/latest and https://registry.npmjs.org/@qwen-code/qwen-code/latest
- **`crush` (unscoped npm)** is an unrelated "Simple MediaCrush command-line executable" by KenanY. The real package is `@charmland/crush`. Confirmed: https://registry.npmjs.org/crush/latest
- **`amp` (unscoped npm)** is TJ Holowaychuk's "Abstract messaging protocol" and is unrelated. `@sourcegraph/amp` is now a stub ("Renamed to @ampcode/cli"). The real package is `@ampcode/cli`. Confirmed: https://registry.npmjs.org/amp/latest, https://registry.npmjs.org/@sourcegraph/amp/latest, https://registry.npmjs.org/@ampcode/cli/latest
- **`opencode-ai`** has no `repository` field in its npm record. It is still legitimate: it was published via a GitHub OIDC trusted publisher, its maintainer is `thdxr`, and the official README names this exact package. Unscoped `opencode` does not exist on npm (404). The repo now lives at `anomalyco/opencode`. Confirmed: https://registry.npmjs.org/opencode-ai/latest and https://github.com/anomalyco/opencode
- **`gemini-cli` (unscoped npm)** returns 404. The real package is `@google/gemini-cli`. Confirmed: https://registry.npmjs.org/gemini-cli/latest
- **Goose moved orgs.** `github.com/block/goose` now redirects to `github.com/aaif-goose/goose`, and the official installer pulls from `aaif-goose/goose`. Confirmed: HTTP `Location` header from https://github.com/block/goose, plus https://raw.githubusercontent.com/aaif-goose/goose/main/download_cli.sh (`REPO="aaif-goose/goose"`)
- **Amazon Q Developer CLI is now the closed-source Kiro CLI.** Homebrew renamed the `amazon-q` cask to `kiro-cli`. Confirmed: https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/upgrade-to-kiro.html and https://github.com/orgs/Homebrew/discussions/6555
- **Kilo CLI is a fork of OpenCode.** The README says so: https://raw.githubusercontent.com/Kilo-Org/kilocode/main/README.md

---

## Per-agent sections

### 1. Gemini CLI (Google)
- **Install / package:** `npm install -g @google/gemini-cli` or `brew install gemini-cli`. Confirmed (https://raw.githubusercontent.com/google-gemini/gemini-cli/main/README.md). The npm record shows repo `google-gemini/gemini-cli`, publisher `google-wombot` (node-team-npm+wombot@google.com), and bin `gemini -> bundle/gemini.js`. Confirmed (https://registry.npmjs.org/@google/gemini-cli/latest)
- **Process:** an npm-installed bin is a node script, so ps shows `node /…/bin/gemini`. The bin entry is confirmed (npm record above). The exact argv shape is unverified; it is inferred from the npm bin shim.
- **Location:** `~/.gemini/tmp/<project-slug>/chats/session-<YYYY-MM-DDTHH-MM>-<first8 of sessionId>.jsonl`. Subagent files go in `chats/<parentId>/<sessionId>.jsonl`. Confirmed:
  - `chats` directory, filename, and subagent nesting: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/services/chatRecordingService.ts
  - `SESSION_FILE_PREFIX='session-'`: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/services/chatRecordingTypes.ts
  - `GEMINI_DIR='.gemini'` and `GEMINI_CLI_HOME` overriding the home dir: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/utils/paths.ts
  - The project directory is a **slug from basename(project root)**, de-duplicated with `-N`. The slug is recorded in `~/.gemini/projects.json`, and a `.project_root` marker sits in each slug dir. The old SHA-256 hash dirs are migrated. https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/config/storage.ts and https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/config/projectRegistry.ts
  - The official docs still say `<project_hash>`, which is stale relative to the code: https://geminicli.com/docs/cli/session-management/
  - On macOS seatbelt (`SANDBOX=sandbox-exec`) the root moves to `~/.cache/.gemini`. Confirmed (storage.ts).
- **Format:** JSONL written with `appendFileSync`. Confirmed (chatRecordingService.ts).
  - The first line is metadata: `sessionId`, `projectHash`, `startTime`, `lastUpdated`, `kind`, `directories`.
  - When a message is updated (tool results or tokens added), the **whole message record is re-appended**. The reader keeps the last record per `id`.
  - Control lines are `{"$set":…}`, `{"$patch":…}`, and `{"$rewindTo":id}`.
  - A full rewrite happens only in an unreadable-file recovery path.
  - Legacy `.json` files are migrated to `.jsonl`. Confirmed (same file).
- **Fields:** confirmed (chatRecordingTypes.ts).
  - Message: `id`, `timestamp`, `type` (`user|gemini|info|error|warning`), `content`.
  - Gemini messages also carry `toolCalls[]`, `thoughts`, `tokens`, and `model`.
  - `ToolCallRecord`: `id`, `name`, `args`, `result`, `status`, `timestamp`, `agentId?`, `resultDisplay?`.
  - `tokens`: `input`, `output`, `cached`, `thoughts?`, `tool?`, `total`.
  - Errors appear as `type:"error"` messages and as tool `status`.
  - The exact `Status` enum values are unverified (the type is imported, not shown).
- **Storage:** local only. Confirmed (the docs page above describes per-project local history).
- **Adapter notes:** `LogWatcher` works, but the parser must de-duplicate by message `id` (emit when `status` becomes terminal) and skip `$`-prefixed control lines. `resolve_log` reads `projects.json` to map cwd to slug, then takes the newest `session-*.jsonl`. This is very close to Copilot's shape.

### 2. Qwen Code (Alibaba / QwenLM, a Gemini CLI fork)
- **Install / package:** `npm install -g @qwen-code/qwen-code@latest`, `brew install qwen-code`, or a standalone script hosted on `qwen-code-assets.oss-cn-hangzhou.aliyuncs.com`. Confirmed (https://raw.githubusercontent.com/QwenLM/qwen-code/main/README.md). The npm record shows repo `QwenLM/qwen-code`, OIDC publish, and bin `qwen -> cli-entry.js`. Confirmed (https://registry.npmjs.org/@qwen-code/qwen-code/latest). See the look-alike warning above.
- **Process:** `node …/bin/qwen`. The bin is confirmed; the argv shape is unverified.
- **Location:** `<runtimeBaseDir>/projects/<sanitizeCwd(projectRoot)>/chats/<sessionId>.jsonl`.
  - `runtimeBaseDir` is resolved in this order: pinned context, then `QWEN_RUNTIME_DIR`, then settings, then `QWEN_HOME`, then `~/.qwen`.
  - `sanitizeCwd` replaces every non-alphanumeric character with `-`, the same scheme as Claude Code's `~/.claude/projects` encoding.
  - Confirmed: https://raw.githubusercontent.com/QwenLM/qwen-code/main/packages/core/src/config/storage.ts, https://raw.githubusercontent.com/QwenLM/qwen-code/main/packages/core/src/utils/paths.ts (`QWEN_DIR='.qwen'`, `sanitizeCwd`), and https://raw.githubusercontent.com/QwenLM/qwen-code/main/packages/core/src/services/chatRecordingService.ts
  - The doc comment in that file says `~/.qwen/tmp/<project_id>/chats/`, which conflicts with the `getProjectDir()` code (`projects/`). Trust the code; verify on a live install.
- **Format:** append-only JSONL. The class doc says "never rewrite the file". Confirmed (chatRecordingService.ts).
- **Fields:** confirmed (same file). The shape is strikingly similar to Claude Code.
  - Identity and context: `uuid`, `parentUuid`, `sessionId`, `timestamp`, `cwd`, `version`, `gitBranch`.
  - `type`: `user|assistant|tool_result|system`, plus a `subtype`.
  - `message` holds Gemini `Content` (parts with `functionCall` and `functionResponse`).
  - `toolCallResult` (with `callId` and `status`).
  - Tokens and model: `usageMetadata`, `model`, `contextWindowSize`.
  - `turn_result` records carry `state: completed|cancelled|error` plus an `error {message, code}`.
  - Subagent fields: `agentId` and `isSidechain`.
- **Storage:** local only. Confirmed (file paths above).
- **Adapter notes:** cheapest of all, because it is native append-only JSONL with call ids and cwd-encoded directories, so `resolve_log` can mirror Claude Code's. `LogWatcher` works with no changes.

### 3. OpenCode (anomalyco, formerly sst)
- **Install:** confirmed (https://github.com/anomalyco/opencode README).
  - `curl -fsSL https://opencode.ai/install | bash`
  - `npm i -g opencode-ai@latest`
  - `brew install anomalyco/tap/opencode` (recommended)
  - `brew install opencode` (core formula, updated less often)
  - The npm record has 12 platform optionalDependencies (`opencode-linux-x64`, …), a postinstall step, and OIDC publish. Confirmed (https://registry.npmjs.org/opencode-ai/latest)
- **Process:** a native binary named `opencode` (the npm bin points at `bin/opencode.exe`, which postinstall swaps in). Confirmed (npm record). The ps name `opencode` is unverified but likely.
- **Location:** `$XDG_DATA_HOME/opencode/opencode.db`, so `~/.local/share/opencode/opencode.db` by default.
  - Channel builds (anything other than latest, beta, or prod) use `opencode-<channel>.db`.
  - Overrides: `OPENCODE_DB` (absolute path or a name under the data dir) and `OPENCODE_DISABLE_CHANNEL_DB`.
  - Confirmed: https://raw.githubusercontent.com/anomalyco/opencode/dev/packages/core/src/database/database.ts and https://raw.githubusercontent.com/anomalyco/opencode/dev/packages/core/src/global.ts (`xdgData`)
  - The legacy per-message JSON files under `storage/` are no longer written. Confirmed via an official-repo issue: https://github.com/anomalyco/opencode/issues/13654
- **Format:** SQLite with `journal_mode = WAL`. Confirmed (database.ts).
  - Tables: `session` (has `directory`, `parent_id`, and `tokens_input/output/reasoning/cache_read/cache_write`), `message` (`data` JSON), `part` (`data` JSON), `todo`, `session_message` (`seq`, `type`, `data`), and others.
  - Confirmed: https://raw.githubusercontent.com/anomalyco/opencode/dev/packages/core/src/session/sql.ts
  - Tool parts are `part.type === "tool"`, with `callID` and `state.status` of `completed` or `error`. Confirmed: https://raw.githubusercontent.com/anomalyco/opencode/dev/packages/opencode/src/session/message-v2.ts
  - The full `state` field set (`input`/`output`/`error`) is unverified beyond `status`.
- **Storage:** local. Shares are opt-in (`share_url` column). Confirmed (sql.ts).
- **Adapter notes:** needs a polling SQLite watcher. This is the CursorWatcher pattern: read-only, `?mode=ro` (or `immutable=1`), and a watermark on `part` time or rowid filtered by `session.directory == cwd`. There are many hosts on the same DB, but the schema is open and versioned.

### 4. Kilo CLI (Kilo-Org, an OpenCode fork)
- **Install:** confirmed (https://raw.githubusercontent.com/Kilo-Org/kilocode/main/README.md).
  - `npm install -g @kilocode/cli`
  - `curl -fsSL https://kilo.ai/cli/install | bash`
  - `brew install Kilo-Org/tap/kilo`
  - The npm record has bins `kilo` and `kilocode`, OIDC publish, and 12 platform optional deps. Confirmed (https://registry.npmjs.org/@kilocode/cli/latest)
- **Process:** native `kilo`. Bin names are confirmed; the ps form is unverified.
- **Location / format:** `$XDG_DATA_HOME/kilo/kilo.db` (or `kilo-<channel>.db`), SQLite WAL, with overrides `KILO_DB` and `KILO_DISABLE_CHANNEL_DB`. Confirmed: https://raw.githubusercontent.com/Kilo-Org/kilocode/main/packages/core/src/database/database.ts and https://raw.githubusercontent.com/Kilo-Org/kilocode/main/packages/core/src/global.ts (`app = "kilo"`)
- **Schema:** it has the same `packages/core/src/session/sql.ts` file as OpenCode. Field-level parity is unverified.
- **Notes:** an OpenCode adapter likely covers Kilo with a different path and binary name. The Kilo VS Code extension (the original Roo/Cline-style one) is a separate product, and its storage is unverified.

### 5. Crush (Charm)
- **Install:** confirmed (https://raw.githubusercontent.com/charmbracelet/crush/main/README.md).
  - `brew install charmbracelet/tap/crush`
  - `npm install -g @charmland/crush`
  - `go install github.com/charmbracelet/crush@latest`
  - `winget install charmbracelet.crush`
  - AUR `crush-bin`
  - The npm record shows repo `charmbracelet/crush`, OIDC + SLSA provenance, and bin `crush -> run-crush.js`, whose postinstall downloads the Go binary. Confirmed (https://registry.npmjs.org/@charmland/crush/latest)
- **Process:** a native Go binary, `crush`. Via npm, `node run-crush.js` may also appear as a parent; whether it execs or spawns is unverified.
- **Location:** **per-project** `<nearest .crush dir up to the project boundary, else cwd>/.crush/crush.db`. It can be overridden by the `data_directory` config option. Confirmed: https://raw.githubusercontent.com/charmbracelet/crush/main/internal/config/load.go (`defaultDataDirectory = ".crush"`, `LookupClosestBounded`) and https://raw.githubusercontent.com/charmbracelet/crush/main/internal/db/connect.go (`crush.db`, `journal_mode: WAL`)
- **Schema:** confirmed.
  - `sessions`: `id`, `parent_session_id`, `prompt_tokens`, `completion_tokens`, `cost`, …
  - `messages`: `id`, `session_id`, `role`, `parts` JSON, `model`, `created_at`, `updated_at`, `finished_at`.
  - Source: https://raw.githubusercontent.com/charmbracelet/crush/main/internal/db/migrations/20250424200609_initial.sql
  - `parts` entries: `ToolCall{id, name, input}` and `ToolResult{tool_call_id, name, content, is_error}`. Source: https://raw.githubusercontent.com/charmbracelet/crush/main/internal/message/content.go
- **Write style:** messages are updated in place (`updated_at`, streaming), so a watcher must poll on `updated_at`/`finished_at`, not on rowid. The update style is inferred from the schema; the exact UPDATE cadence is unverified.
- **Storage:** local. `resolve_log` is trivial: `cwd/.crush/crush.db`.

### 6. Goose (aaif-goose, formerly block/goose)
- **Install:** `curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | bash`, which installs to `GOOSE_BIN_DIR` (default `~/.local/bin`). Confirmed (https://raw.githubusercontent.com/aaif-goose/goose/main/README.md and https://raw.githubusercontent.com/aaif-goose/goose/main/download_cli.sh). There is also a desktop app.
- **Process:** native Rust binary `goose`. The installer is confirmed; the ps name is unverified but likely.
- **Location:** `Paths::data_dir()/sessions/sessions.db`. On Linux the `etcetera` app strategy gives `~/.local/share/goose/sessions/sessions.db`. `GOOSE_PATH_ROOT` overrides the root.
  - Confirmed: https://raw.githubusercontent.com/aaif-goose/goose/main/crates/goose/src/session/session_manager.rs (`DB_NAME="sessions.db"`, `SESSIONS_FOLDER="sessions"`, WAL) and https://raw.githubusercontent.com/aaif-goose/goose/main/crates/goose/src/config/paths.rs (`GOOSE_PATH_ROOT`, `data_dir`)
  - The exact expanded Linux path is unverified from code. It is consistent with third-party reports.
- **Schema:** confirmed (session_manager.rs, schema v16).
  - `messages(id AUTOINCREMENT, message_id, session_id, role, content_json, created_timestamp, tokens, metadata_json)`.
  - Session rows carry `working_dir` plus input/output/cache token columns.
  - Messages are INSERTed, but some paths `DELETE FROM messages WHERE session_id=?` and reinsert (replace or truncate).
- **Content:** a tagged union (`type`, camelCase) with `ToolRequest{id, toolCall}` and `ToolResponse{id, toolResult}`. `ToolResult` is a Result type, so errors are encoded as Err. Confirmed: https://raw.githubusercontent.com/aaif-goose/goose/main/crates/goose-provider-types/src/conversation/message.rs. The exact JSON of the Ok/Err encoding is unverified.
- **Notes:** pre-1.10 releases wrote `.jsonl` per session. This comes from third-party reports only (unverified against official source).

### 7. Cline (VS Code extension + Cline CLI)
- **Install (CLI):** `npm i -g cline`. The npm record shows repo `cline/cline` (`apps/cli`), OIDC + SLSA, maintainers @cline.bot, and bin `cline -> bin/cline`. Confirmed (https://registry.npmjs.org/cline/latest)
- **Process:** `node …/bin/cline` is unverified. The `bin/cline` launcher may be a shell or native shim.
- **CLI storage:** `$CLINE_SESSION_DATA_DIR`, or `$CLINE_DATA_DIR/sessions`, or `$CLINE_DIR/data/sessions`, defaulting to `~/.cline/data/sessions`. Confirmed: https://raw.githubusercontent.com/cline/cline/main/sdk/packages/shared/src/storage/paths.ts
  - Per session: `<id>/<id>.messages.json`, `<id>.json` (manifest), and `<id>.compaction.json`. Confirmed: https://raw.githubusercontent.com/cline/cline/main/sdk/packages/core/src/services/session-artifacts.ts
  - There is also a `sessions.db` SQLite index. Confirmed: https://raw.githubusercontent.com/cline/cline/main/sdk/packages/core/src/services/storage/sqlite-session-store.ts
  - The messages file is **fully rewritten** on every persist (`writeFileSync(path, JSON.stringify(payload))`). Confirmed: https://raw.githubusercontent.com/cline/cline/main/sdk/packages/core/src/session/stores/session-manifest-store.ts
  - Messages are `MessageWithMetadata[]` (provider-neutral). Exact tool and call-id field names are unverified.
- **VS Code extension storage:** `<globalStorage>/tasks/<taskId>/api_conversation_history.json` and `ui_messages.json`, both whole-JSON files. Confirmed: https://raw.githubusercontent.com/cline/cline/main/apps/vscode/src/core/storage/disk.ts
- **Notes:** reparse-on-change is needed (Aider-style watcher with an emitted-count cursor).

### 8. Roo Code
- The repo was archived on 2026-05-15. The README says "The Roo Code Extension was shut down on May 15th." Confirmed (https://github.com/RooCodeInc/Roo-Code). **Skip it.** The successor fork, "ZooCode", is unverified.

### 9. Continue (`cn` CLI)
- **Install:** `npm i -g @continuedev/cli`. The npm record shows repo `continuedev/continue`, OIDC + SLSA, and bin `cn -> dist/cn.js`. Confirmed (https://registry.npmjs.org/@continuedev/cli/latest)
- **Process:** `node …/dist/cn.js` (or `…/bin/cn`). The bin is confirmed; the argv form is unverified.
- **Location:** `$CONTINUE_GLOBAL_DIR/sessions/<sessionId>.json`, default `~/.continue/sessions/`, plus a `sessions.json` index. Confirmed: https://raw.githubusercontent.com/continuedev/continue/main/extensions/cli/src/session.ts and https://raw.githubusercontent.com/continuedev/continue/main/core/util/paths.ts
- **Format:** whole JSON, rewritten with `fs.writeFileSync(JSON.stringify(session))`. Confirmed: https://raw.githubusercontent.com/continuedev/continue/main/core/util/history.ts
- **Fields:** `ChatHistoryItem.toolCallStates[]` with `toolCallId`, `toolCall`, `status`, `parsedArgs`, and `output`. `status` is one of `generating|generated|calling|errored|done|canceled`. Confirmed: https://raw.githubusercontent.com/continuedev/continue/main/core/index.d.ts
- **Storage:** local. Remote Hub sessions were removed. Confirmed (session.ts comment).

### 10. Cursor CLI (`agent`, formerly `cursor-agent`)
- **Install:** `curl https://cursor.com/install -fsS | bash`. The binary is `agent`, in `~/.local/bin`. Confirmed (https://cursor.com/docs/cli/installation). The old name `cursor-agent` appears only in forum posts (unverified as a current alias).
- **Location:** `~/.cursor/chats/<workspace-hash>/<chat-uuid>/`, local only, no cloud sync. IDE chats live elsewhere (`~/.cursor/projects/…`).
  - This was stated by Cursor staff on the official forum, not in the docs: https://forum.cursor.com/t/cursor-cli-past-chats-not-showing-up/152450 and https://forum.cursor.com/t/local-ide-agent-chats-and-the-agent-cli-still-use-separate-session-stores/165486
  - `XDG_CONFIG_HOME` reportedly changes the location (same forum thread).
  - **The file format inside the chat dir is unverified.** The CLI is closed source.
- **Structured stream:** `--output-format stream-json` emits `system/init`, `user`, `assistant`, and `tool_call` (`started`/`completed`, linked by `call_id`), with `result.success`. There are no token fields, and on error the stream may end with only stderr. Confirmed (https://cursor.com/docs/cli/reference/output-format). That only helps for headless runs agentwatch launches itself, not for passive monitoring.

### 11. Amp (Sourcegraph → ampcode.com)
- **Install:** `curl -fsSL https://ampcode.com/install.sh | bash`. Confirmed (https://ampcode.com/docs/cli). The npm package is `@ampcode/cli` (bin `amp`, native per-platform deps, maintainers sqs@sourcegraph.com and ampcode.com accounts). Confirmed (https://registry.npmjs.org/@ampcode/cli/latest)
- **Process:** native `amp`, with a bundled Bun runtime. Confirmed (docs/cli mentions bundled Bun; the npm bin is `bin/amp.exe`).
- **Storage:** threads are **server-side**. Every thread has an `ampcode.com/threads/T-…` URL and opens from any client, and getting a local copy requires `amp threads export`. Confirmed (https://ampcode.com/docs/threads). No local thread path is documented in settings. Confirmed (https://ampcode.com/docs/cli/settings).
- `--execute --stream-json` is "compatible with Claude Code's format as much as possible": `tool_use.id` / `tool_result.tool_use_id` / `is_error`, and `usage`. Confirmed (https://ampcode.com/docs/cli/streaming-json).
- **Verdict:** passive monitoring is infeasible. A wrapper mode that pipes `--stream-json` into the existing Claude Code parser would be nearly free, but it is a different feature.

### 12. Kiro CLI (formerly Amazon Q Developer CLI)
- **Install:** `curl -fsSL https://cli.kiro.dev/install | bash`. The binary is `kiro-cli`. Confirmed (https://kiro.dev/docs/cli/). Also `brew install kiro-cli` (cask renamed from `amazon-q`). Confirmed (https://github.com/orgs/Homebrew/discussions/6555)
- **Closed source.** The `aws/amazon-q-developer-cli` repo now receives critical fixes only. Confirmed (https://github.com/aws/amazon-q-developer-cli)
- **Storage:** the official docs say only that `/chat new` "saves your current session to the database", that conversations are remembered per directory, and that `--resume`, `--resume-id`, and `--resume-picker` exist. Confirmed (https://kiro.dev/docs/cli/chat/). No path or format is documented.
- **Third-party reports (unverified):**
  - `~/.local/share/kiro-cli/data.sqlite3`, table `conversations_v2` (one row per cwd, a whole-conversation JSON blob, which implies in-place rewrite).
  - The newer TUI writes `~/.kiro/sessions/cli/*.jsonl`.
  - The same DB holds bearer tokens in `auth_kv`, which is a reason to open it read-only and never copy it.

---

## Ranking (effort vs value)

Effort scale: **JSONL tail** < **SQLite poll** < **whole-JSON reparse** < **closed or undocumented format** < **server-side**.

| Rank | Agent | Value | Effort | Rationale |
|---|---|---|---|---|
| 1 | **Gemini CLI** | very high (largest free-tier CLI user base, Google) | low | Append-only JSONL with tool ids, status, and tokens. Needs a de-duplicate-by-`id` pass and a `projects.json` slug lookup. Reuses `LogWatcher`. Same `~/.gemini` family as the existing `agy` adapter. |
| 2 | **Qwen Code** | medium-high (large in China; Gemini fork) | lowest | Append-only JSONL with a Claude-Code-like `uuid/parentUuid/type/cwd` shape, cwd-encoded dirs (same encoding as Claude Code), `callId`, `usageMetadata`, and an explicit error state. Could share a Gemini-parts helper with #1. |
| 3 | **OpenCode** (+ **Kilo** nearly free) | very high (~212k GitHub stars per repo page) | medium | SQLite WAL that needs a CursorWatcher-style poller. The schema is open source, with `callID` and per-session token columns and a `session.directory` filter for cwd. A second adapter config covers Kilo (`kilo.db`, `kilo` binary). |
| 4 | **Crush** | medium (Charm community) | medium | SQLite WAL with clean `tool_call_id`/`is_error` and per-project `.crush/crush.db`, so cwd mapping is trivial. Messages update in place, so the poller needs an `updated_at` watermark. |
| 5 | **Goose** | medium (Linux Foundation/AAIF project, desktop + CLI) | medium | SQLite WAL with `working_dir` on the session and tool request/response ids. Delete+reinsert paths complicate the watermark. |
| 6 | Continue `cn` | medium | medium-high | Whole-JSON rewrite, but has rich `toolCallStates` with `errored` status. |
| 7 | Cline CLI | medium-high (extension is huge; CLI is new) | medium-high | Whole-JSON rewrite plus a SQLite index. Tool field names are unverified. |
| 8 | Kiro CLI | medium (AWS users) | high | Closed source, the format is undocumented, and the DB holds auth tokens. |
| 9 | Cursor CLI | high users | high | Closed source; the chat dir format is undocumented. |
| 10 | Amp | medium | infeasible passively | Server-side threads. |
| — | Roo Code | — | — | Shut down. |

### Top 5 with install commands
1. **Gemini CLI:** `npm install -g @google/gemini-cli` (or `brew install gemini-cli`)
2. **Qwen Code:** `npm install -g @qwen-code/qwen-code@latest` (NOT unscoped `qwen-code`)
3. **OpenCode:** `npm i -g opencode-ai@latest` or `brew install anomalyco/tap/opencode` (Kilo: `npm install -g @kilocode/cli`)
4. **Crush:** `brew install charmbracelet/tap/crush` or `npm install -g @charmland/crush` (NOT unscoped `crush`)
5. **Goose:** `curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | bash`

## Open questions (need a live install to settle)
1. Gemini `Status` enum values and whether `toolCalls[].result` carries an error flag (the type is imported and not shown). Also how often a message is re-appended during one tool run, which drives de-duplication cost.
2. Qwen: does the live layout use `~/.qwen/projects/<sanitized>/chats/` (code) or `~/.qwen/tmp/<id>/chats/` (doc comment)? Also, does the "managed transcript" sink write somewhere else?
3. OpenCode/Kilo: the exact `ToolPart.state` fields (`input`, `output`, `error`, `time`), and whether reading a WAL DB with `mode=ro` works without `immutable=1` while the agent is running. CursorWatcher precedent suggests yes, but this is unverified here.
4. Crush: the UPDATE cadence on `messages.parts` during streaming, and whether the npm wrapper process stays alive as the parent of the Go binary (this affects process de-duplication, like Copilot's `process_exclude`).
5. Goose: the JSON encoding of `ToolResult` Err, and the exact Linux path that `etcetera` resolves.
6. The argv shape in `ps` for each node-shim CLI (gemini, qwen, cn, cline), which determines `process_pattern`.
7. Cursor CLI and Kiro CLI on-disk formats are closed. Only a live, logged-in session can settle them, and that is out of scope under the no-login constraint.
