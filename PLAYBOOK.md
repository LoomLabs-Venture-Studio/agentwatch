# agentwatch-main -- Playbook

## Project Standards (Permanent)

### Development Protocol

Before ANY code change:
1. Read the target file(s) completely
2. Understand current behavior
3. Identify all callers/consumers
4. Check docs for context

After EVERY code change:
1. Build -- must pass
2. Tests -- must pass, no regressions
3. Lint -- no new warnings
4. All green -> commit
5. Any red -> fix before continuing

This protocol applies whether using a harness or not.

### Commit Messages
```
type(scope): description [ISSUE-ID]
type: fix | feat | refactor | test | docs | chore
```

### Quality Gates
1. Build passes
2. No test regressions
3. No new lint warnings
4. Scope check: only change what's assigned
5. Security: no secrets, no unauthed endpoints, no user data in logs

### Rollback Protocol
1. `git stash` current changes
2. Verify clean state with build + test
3. Report failure
4. Do NOT retry same approach
5. Propose alternative, wait for approval

---

## Current Sprint (CTO Updates This Section)

### Sprint: Sprint 0 — Repository Bootstrap & Baseline Health
**Type:** chore / bootstrap
**Priority:** Unblocks all future sprints (no committed baseline, no CI gate,
no accurate docs existed before this)
**PRD Status:** not needed (recon-driven; see
`C:\Users\Zaid\.claude\plans\what-do-you-recommend-unified-tulip.md` for the
full plan)
**Harness:** PLAYBOOK standalone (`.loom/config.yml` shows no GSD/Ruflo
signal)

### Acceptance Criteria
- [x] `pip install -e ".[dev]"` succeeds from a clean venv
- [x] `python -m pytest tests/ -v` collects and runs all 7 suites — 244/245
      pass; 1 pre-existing Windows-platform limitation logged as backlog
      (task #7), not a regression
- [x] `ruff check .` wired into CI
- [x] CI (`verify-deploy.yml`, repurposed from a generic Node.js template)
      runs install + ruff + pytest on push/PR to main/master
- [x] `CLAUDE.md` Stack/Architecture/Key Patterns/Known Issues sections
      reflect real project state, no placeholder brackets remain
- [x] README.md and docs/index.md agree on detector counts (35 = 15 health +
      20 security) and supported agents
- [x] Root-level scratch files resolved: `demo_teams.py` moved to
      `scripts/`, `csv_parser.py` and `flatten_test.py` deleted (board
      sign-off obtained before removal)
- [ ] First git commit made (pending — go-ahead requested from board)

### Implementation Plan
1. Investigate + resolve 3 root-level scratch files — done (engineer)
2. Fill `CLAUDE.md` with real project data — done (CTO)
3. Fix local dev env, get tests running — done (engineer); found and fixed a
   real reproducibility bug in `SessionStats.duration_minutes`
   (`src/agentwatch/parser/models.py`) that computed against
   `datetime.now()` instead of the log's own timestamp span
4. Repurpose `.github/workflows/verify-deploy.yml` into a Python CI gate —
   done (devops)
5. Reconcile detector counts / agent-support docs between README.md and
   docs/index.md — done (engineer); README's "17 detectors" was stale, real
   count is 35
6. Update this section + stage the first commit — in progress (CTO); commit
   itself pending explicit board go-ahead per Irreversible Action Checkpoint

### Follow-up backlog (not in this sprint)
- Task #7: native Windows support — scoped, promoted to Sprint 1 below.

---

### Sprint: Sprint 1 — Native Windows Support (Task #7)
**Type:** bugfix / platform support
**Priority:** AgentWatch silently reports zero running agents on Windows
today (POSIX-only `ps`/`lsof` shell-outs + POSIX-only path encoding fail
silently instead of erroring)
**PRD Status:** full implementation plan approved; see
`C:\Users\Zaid\.claude\plans\whats-the-plans-glittery-forest.md`
**Harness:** PLAYBOOK standalone (no GSD/Ruflo signal)

### Acceptance Criteria
- [x] `psutil>=5.9.0` added to core `[project.dependencies]` in `pyproject.toml`
- [x] New `src/agentwatch/path_encoding.py` with `encode_path_for_claude()`
      (unconditional regex-replace of `/`, `\`, `:`, ` ` with `-`),
      unit-tested including the empirically-confirmed case
      (`C:\Users\Zaid\Desktop\claude work\...` ->
      `C--Users-Zaid-Desktop-claude-work-...`)
- [x] `discovery.py::_encode_path_for_claude` removed, replaced by the
      shared function; `cc_stats.py::cwd_to_project_dir` wired to the same
      shared function
- [x] `discovery.py::_get_process_cwd` rewritten on `psutil.Process.cwd()`;
      `AccessDenied`/`NoSuchProcess`/`ZombieProcess` -> skip (return
      `None`), preserving the existing `cwd is None -> continue` contract
      in `find_running_agents`
- [x] `discovery.py::find_running_agents` rewritten on
      `psutil.process_iter()`, dropping the `subprocess.run(["ps", ...])`
      call entirely; `AGENT_PATTERNS` regex matching unchanged; memory/etime
      conversions correct (RSS bytes->MB, `create_time`->etime-format string)
- [x] `_find_open_jsonl` rewritten on `psutil.Process.open_files()` —
      **deviation from plan**: the plan called for leaving this on the mtime
      fallback, but that silently breaks the documented "avoid
      cross-contamination when multiple agents share a project directory"
      guarantee on Windows specifically (`lsof` never worked there in the
      first place). Replacing it removes the platform gap instead of
      papering over it. Added 5 new tests (`TestFindOpenJsonl` in
      `test_discovery.py`) since this function previously had zero coverage.
- [x] `ui/multi_app.py` comment at ~line 538-541 updated to reference psutil
      instead of ps/lsof
- [x] `tests/test_discovery_cache.py`'s tests updated to mock
      `psutil.process_iter` instead of `subprocess.run`
- [x] `tests/test_cc_stats.py::test_cwd_to_project_dir_existing` fixed to be
      platform-agnostic (was the 1 known-failing test on Windows)
- [x] `python -m pytest tests/ -v` fully green — 270/270 (245 baseline +
      25 new: path_encoding, discovery-cache psutil mocks, find_open_jsonl)
- [x] `ruff check` clean on every file this sprint touched (`discovery.py`,
      `cc_stats.py`, `path_encoding.py`, `cli.py`'s new code, and the
      touched test files). **Caveat**: `ruff check .` across the whole repo
      still reports ~635 pre-existing warnings (mostly W293/E501) in files
      this sprint didn't touch — unrelated lint debt, out of scope here.
- [x] Manual smoke test: `agentwatch ps` (run as `python -m agentwatch.cli
      ps`, which the console-script entry points route through) correctly
      listed all 17 real running `claude` processes on this Windows machine
      with resolved working directories and a correct process/team tree.
      **This surfaced a second, separate Windows bug**: the first run
      crashed with `UnicodeEncodeError` because Windows consoles default
      Python's stdout to `cp1252`, which can't encode the box-drawing
      characters (`═╔╗` etc.) `cli.py` uses in report output. Fixed with a
      `_ensure_utf8_stdio()` helper called from both `main()` and
      `security_main()` that reconfigures stdout/stderr to UTF-8 on
      `win32` only (no-op elsewhere). Without this fix, Task #7 would have
      been necessary but not sufficient — psutil discovery would work but
      every plain-CLI command would still crash on Windows.

### Implementation Plan
See full file-by-file plan at
`C:\Users\Zaid\.claude\plans\whats-the-plans-glittery-forest.md`.
Landed as: (1) `pyproject.toml` psutil dep, (2) new `path_encoding.py` +
tests, (3) `cc_stats.py` wired to shared encoder + test fix, (4)
`discovery.py` full psutil rewrite (including `_find_open_jsonl`, a
deviation from the original plan — see acceptance criteria above) +
`test_discovery_cache.py` rewrite + `multi_app.py` comment, (5) `cli.py`
UTF-8 stdio fix found via the manual smoke test. Status: done.

### Follow-up backlog (not in this sprint)
- Aider log parser: process detection + log path resolution already exist
  (`.aider.chat.history.md`), but the format isn't parsed into `Action`
  objects yet. Researched + independently verified 2026-07-10 (Aider isn't
  installed on this machine, so this is web/source research against
  Aider's real GitHub repo and live sample files, not a local capture).
  **PRD written** (2026-07-10):
  `C:\Users\Zaid\.claude\plans\aider-log-parser-prd.md` — full file-by-file
  design (new `parser/aider.py`, ordinal turn-pairing between the Markdown
  and opt-in analytics JSONL, dual diff-marker regex support), 6 open
  questions flagged for live-install confirmation. Ready for sprint
  scoping.

  **`.aider.chat.history.md`** is append-only Markdown, no fixed schema.
  Verified against two real public transcripts
  (`johns10/generaite_todo_app_1/.aider.chat.history.md`,
  `dfeldman/operation-conundrum.github.io/aider-chat-history.md`):
  session boundary `# aider chat started at <timestamp>` (once per
  launch/resume, not per-turn), aider status lines prefixed `> `, user
  prompts as `#### <text>` headings, file edits as a filename line + a
  fenced diff block, auto-commits as `Commit <hash> <message>` lines (the
  closest thing to a per-edit success signal). **Caveat confirmed during
  verification**: the diff-block delimiter isn't stable across versions —
  the johns10 example uses `<<<<<<< SEARCH`/`=======`/`>>>>>>> REPLACE`,
  the dfeldman one uses the older `<<<<<<< ORIGINAL`/`=======`/`>>>>>>>
  UPDATED`. No per-turn timestamps, no explicit success/fail markers, no
  token/cost data anywhere in this file.

  **Better source exists**: an opt-in `--analytics-log <file>.jsonl` flag
  (docs: aider.chat/docs/more/analytics.html, verified real; sample:
  `aider/website/assets/sample-analytics.jsonl` in the aider repo,
  verified real) writes clean JSONL, one object per line:
  `{"event": ..., "properties": {...}, "user_id": "<uuid4>", "time":
  <unix_seconds>}`. Its `message_send` event's `properties` include
  `main_model`, `edit_format`, `prompt_tokens`, `completion_tokens`,
  `total_tokens`, `cost`, `total_cost` — maps almost 1:1 onto `Action`'s
  `tokens_in`/`tokens_out`/`cost_usd`. Other event types
  (`command_add`/`command_edit`/`command_run`/`repo`) exist but carry
  empty `properties: {}` in the verified sample — no file paths or shell
  command text recoverable from them; `exit` only carries a `reason`
  string. **This flag is opt-in, off by default** — can't be assumed
  present the way Claude Code's JSONL always is.

  **Recommended approach**: two-source parser — `--analytics-log` JSONL
  as primary for token/cost when present, falling back to
  heading/regex Markdown scraping (`#### ` for turns, filename + diff-
  marker regex for edits, `Commit ` lines for success) for tool-call/edit
  detail. Never rely on Markdown alone for cost data. Parsing difficulty:
  trivial for analytics JSONL, hard for Markdown scraping (no fixed
  schema, delimiter drift across versions).

- Codex CLI log support (OpenAI's terminal coding agent,
  github.com/openai/codex): researched + independently verified
  2026-07-10 (not installed on this machine — web/source research
  against the real GitHub repo, issues, and docs). **PRD written**
  (2026-07-10): `C:\Users\Zaid\.claude\plans\codex-cli-support-prd.md` —
  new `_resolve_codex_log()` + dedicated `parser/codex.py` with
  `call_id`-based buffering and explicit era-detection, 7-item
  live-install-gated open-questions list, acceptance criteria that block
  merge on real-install re-validation. Ready for sprint scoping.

  Session logs are real and exist at
  `~/.codex/sessions/YYYY/MM/DD/rollout-<TIMESTAMP>-<UUID>.jsonl` — one
  file per session, date-bucketed. Root is `~/.codex/` on macOS/Linux,
  `%USERPROFILE%\.codex\` on native Windows, overridable via `CODEX_HOME`
  (confirmed at developers.openai.com/codex/environment-variables; the
  "can be a comma-separated list" detail from the first research pass
  was **not** independently confirmed — treat as unverified). Separate,
  distinct files exist alongside it: `~/.codex/history.jsonl` (command
  history, unbounded-growth tracked in real issue #4963) and
  `~/.codex/log/codex-tui.log` (app debug log, singular `log/` dir per
  issue #13463, not `logs/`).

  Format: newline-delimited JSON, each line a `RolloutLine` wrapping
  `timestamp`/`type`/`payload`. Confirmed directly against
  `codex-rs/protocol/src/protocol.rs` in the real source: `call_id`
  fields genuinely exist and correlate tool calls to their outputs (e.g.
  `McpToolCallBeginEvent`/`EndEvent`) — no parent/child event link, must
  match by `call_id`. Event types `session_meta`, `response_item`,
  `event_msg`, `turn_context` corroborated by two independent
  primary-adjacent sources; the exact nested type-string format (e.g.
  whether it's literally `"response_item/function_call"` vs. a
  `type="response_item"` with an inner `payload.type`) wasn't
  verbatim-located in the 6,201-line source file within the research
  window — treat exact type-string formatting as needing direct
  confirmation before writing a parser. **No `cost_usd`-equivalent
  field** — confirmed via direct source search, zero matches.

  **Version stability is a real, confirmed risk**: a community viewer
  tool (github.com/PixelPaw-Labs/codex-trace, verified real) explicitly
  special-cases three metadata schema eras in its README verbatim:
  "new (>=0.44), mid, and oldest (2025/08)". Also confirmed real:
  openai/codex issue #21660 (open, filed **2026-05-08** — a first-pass
  research error claimed "Aug-2026-era," corrected here) — rollout files
  are created world-readable (`0o666 & ~umask` instead of `0o600`) on
  Unix, a security-relevant detail for `agentwatch`'s own file-permission
  assumptions if this is ever implemented, separate from the parsing
  question.

  **Bottom line**: unlike Aider, Codex CLI's log is JSONL (matches
  AgentWatch's existing parser model much more naturally), but the schema
  has already changed multiple times across versions with no apparent
  stability guarantee — recommend confirming exact field names against a
  live install before committing to a parser implementation, and building
  in version-era detection from day one given the confirmed precedent.

- Cursor support: currently zero support (no process pattern, no log
  resolution). Researched 2026-07-10 against this machine's real Cursor
  install — findings below correct and supersede the earlier note (which
  pointed at the wrong file). **Architecture review written** (2026-07-10):
  `C:\Users\Zaid\.claude\plans\cursor-sqlite-architecture-review.md` —
  weighs polling-strategy and watcher-abstraction alternatives (recommends
  a two-tier `composerHeaders`-then-`composerData` poll and a new
  `CursorWatcher` class rather than generalizing `LogWatcher`), recommends
  Cursor needs its own discovery mechanism (not `AGENT_PATTERNS`, since
  it's a GUI IDE not a spawned CLI process), and proposes a read-only
  Phase 0 research spike before implementation given how much of the
  bubble-level content schema remains genuinely unverified. Ready for
  sprint scoping (starting with the Phase 0 spike, per its own
  recommendation).

  **Wrong file previously flagged**: `~/.cursor/ai-tracking/
  ai-code-tracking.db` exists but every table is empty except one metadata
  row. It's a commit-level AI-vs-human line-attribution DB (the "% AI
  written" stat), not a session/conversation log — not useful for
  real-time monitoring even when populated.

  **The real conversation store**: `~/AppData/Roaming/Cursor/User/
  globalStorage/state.vscdb` (SQLite, not JSONL — confirms the
  architecture concern, just at the right location this time).
  - `cursorDiskKV` table, `composerData:<uuid>` keys hold JSON blobs with
    a `conversationMap` of message "bubbles," tool-call state, model
    config, todos — the Cursor analog of Claude Code's JSONL actions.
  - `composerHeaders` table is a cheap index: composerId -> workspaceId +
    timestamps + `unifiedMode` (`"chat"` vs `"agent"` — agent mode is the
    one worth watching).
  - `workspaceStorage/<hash>/workspace.json`'s `folder` field cleanly
    resolves workspaceId -> real project path (URL-encoded `file://`
    URI) — maps to cwd about as easily as Claude Code's own path
    encoding does. Architecturally this part is fine.
  - No `-wal`/`-shm` sidecar file present when Cursor isn't running ->
    confirms this needs a polling/re-query ingestion path, not
    `LogWatcher`'s append-only byte-offset tailing.

  **Encryption blocker — resolved (2026-07-10), independently
  verified**: every `composerData` blob on this machine — even empty
  ones — carries a `blobEncryptionKey` field, which looked concerning at
  first (could have meant conversation content is encrypted at rest; this
  Cursor install has ~zero real chat history so it couldn't be checked
  directly). Follow-up research + a separate verification pass against
  primary sources concluded **conversation content is plaintext JSON by
  default, not ciphertext**:
  - Cursor's own privacy page (cursor.com/data-use, fetched directly)
    only documents "client-generated keys" for *transient server-side
    caching* ("only exist on our servers for the duration of a
    request") — not local disk storage. `blobEncryptionKey` most likely
    belongs to that, not local encryption.
  - Two independent, real open-source extraction tools —
    `somogyijanos/cursor-chat-export` and `saharmor/cursor-view` — were
    fetched directly and confirmed to read `composerData` blobs via
    plain `json.loads()` with **no crypto imports anywhere** in either
    codebase.
  - A security researcher's direct-inspection claim ("no encryption, no
    OS keychain protection") was corroborated (found via cache; X blocks
    unauthenticated direct fetch, so not independently re-verified
    firsthand).
  - Cursor's forum thread on Privacy Mode (forum.cursor.com, fetched
    directly) confirmed Privacy Mode governs server-side retention/
    training use only, never local disk format.
  - **Genuine remaining gap**: no source found tested a conversation
    created *while Privacy Mode was actively on* — all evidence covers
    the default/common case. Low risk, but not airtight for every
    configuration.

  Net effect: the encryption risk that was the #1 blocker to scoping
  this is now downgraded from "possible showstopper" to "confirmed
  non-issue for the default case." Cursor support is now blocked only on
  writing a PRD + architecture review for the SQLite polling ingestion
  path (see above) — no more open technical unknowns of this size.

---

### Sprint: Detector Performance Pass — reconciled retroactively (2026-07-10)
**Type:** performance / refactor
**Status:** Found already implemented and passing in the working tree while
preparing the first real commit against `origin/main`; never previously
recorded in this file. Documented now so the history is honest, not because
it's new work being scoped.

**What it does:** `turns_from_buffer(buffer)` was being recomputed
independently by ~6 detectors (`behavioral`, `constraints`, `progress`,
`repetition`, `tool_thrash`, and the caller of `_turns_since_progress`)
every single scan pass. Each `compute_*` function in
`src/agentwatch/detectors/health/{behavioral,constraints,progress,
repetition,tool_thrash}.py` now accepts an optional keyword-only `turns:
list[Turn] | None = None` and only calls `turns_from_buffer` itself if the
caller didn't already supply it — backward compatible, no behavior change
for existing callers.

Two more changes bundled with it:
- `ActionBuffer.last(n)` (`parser/models.py`) replaced
  `list(self.actions)[-n:]` (materializes the whole deque every call) with
  an `itertools.islice`-based tail read. ~30 of the 35 registered detectors
  depend on this method's ordering, so `tests/test_action_buffer.py` was
  added specifically to pin ordering/boundary behavior (empty buffer, `n=0`,
  `n` > buffer size) before/after the change.
- `MultiAgentWatchApp` (`ui/multi_app.py`) added action-count-based change
  detection so an idle agent's buffer isn't fully re-scanned by every
  detector on each 1s refresh tick, and replaced an O(T*N) team-aggregation
  linear scan with a precomputed pid -> team_id map.
  `tests/test_multi_app_refresh.py` added, driving the real app via
  Textual's headless pilot (`App.run_test()`) rather than mocking the
  refresh path away.
- `detectors/health/context.py`'s `important_forgotten` filter changed
  from an O(forgotten * early_actions) nested loop to a single set
  comprehension.

### Acceptance Criteria
- [x] All `compute_*` detector entry points accept optional `turns` without
      changing default behavior when omitted
- [x] `tests/test_action_buffer.py` (new) covers empty buffer, `n<=0`,
      `n` > size, and ordering
- [x] `tests/test_multi_app_refresh.py` (new) exercises the real
      `refresh_ui()` path via headless Textual pilot, not mocks
- [x] `python -m pytest tests/ -v` — 270/270 pass with this work included
- [x] `ruff check .` — no new warnings versus the pre-existing ~635-warning
      baseline (confirmed by direct count during commit prep)

---

## Task #7: Native Windows Support

**Status:** Implemented (2026-07-10). Full native support via `psutil`,
as scoped below.

**Result:** `psutil>=5.9.0` added as a core dependency. `discovery.py`'s
`find_running_agents()`, `_get_process_cwd()`, and `_find_open_jsonl()`
now use `psutil.process_iter()` / `psutil.Process.cwd()` /
`psutil.Process.open_files()` instead of shelling out to `ps`/`lsof`. Path
encoding moved to a shared `path_encoding.py::encode_path_for_claude()`
used by both `discovery.py` and `cc_stats.py`, implementing the
empirically-verified Windows rule (`\`, `:`, ` ` -> `-` alongside the
existing `/` -> `-`). 270/270 tests pass (5 new tests added for
`_find_open_jsonl`), `ruff check` clean on all touched files.

The manual smoke test (real `agentwatch ps` run against this machine's 17
live `claude` processes) also surfaced a second, unrelated Windows bug:
`cli.py`'s box-drawing report output crashed with `UnicodeEncodeError` on
Windows' default `cp1252` console encoding. Fixed alongside this sprint
via `_ensure_utf8_stdio()` in `cli.py` — see Sprint 1 acceptance criteria
above for the full detail on both this and the `_find_open_jsonl` scope
deviation.

### Problem
All POSIX-only code is confined to two files: `discovery.py` and
`cc_stats.py`. `parser/watcher.py` and the UI layer are already
platform-clean (pure `Path` / `watchfiles`).

1. **Process discovery shells out to POSIX-only tools** (`discovery.py`):
   - `find_running_agents()` runs `ps -eo pid,ppid,%cpu,rss,etime,args`
   - `_get_process_cwd()` / `_find_open_jsonl()` run `lsof`
   - Neither exists on native Windows. Failures are caught
     (`FileNotFoundError` -> return `[]`/`None`), so today this doesn't
     crash — it silently reports zero agents running with no error,
     which is a worse UX than a hard failure.
   - No `psutil` (or other cross-platform process) dependency exists yet.

2. **Path encoding assumes `/`-only separators**
   (`discovery.py::_encode_path_for_claude`,
   `cc_stats.py::cwd_to_project_dir`): both do
   `str(path).replace("/", "-")`, a no-op on Windows paths, producing the
   wrong Claude Code project-dir name and failing to locate the log file.
   - Verified against this machine's real `~/.claude/projects/`: Claude
     Code's actual Windows encoding replaces `\`, `:`, **and spaces**
     with `-`, e.g.
     `C:\Users\Zaid\Desktop\claude work\agentwatch\agentwatch-main` ->
     `C--Users-Zaid-Desktop-claude-work-agentwatch-agentwatch-main`.
   - This is the root cause of the known-failing test
     `test_cc_stats.py::TestCwdMapping::test_cwd_to_project_dir_existing`.

### Chosen approach
Add `psutil` as a core dependency (`pyproject.toml`); replace the
`ps`/`lsof` subprocess calls in `discovery.py` with
`psutil.process_iter()` (single call surfaces pid/ppid/cwd/cmdline/rss/cpu
directly — no second `lsof` shell-out needed for cwd resolution). Make
path encoding platform-aware using the confirmed Windows rule
(`\`, `:`, ` ` -> `-`) alongside the existing POSIX rule (`/` -> `-`).

### Estimated surface
- `pyproject.toml`: add `psutil` dependency
- `discovery.py`: rewrite `find_running_agents()`,
  `_get_process_cwd()`, `_find_open_jsonl()`, `_encode_path_for_claude()`
  (~100 lines)
- `cc_stats.py`: fix `cwd_to_project_dir()` encoding (~10 lines)
- `tests/test_discovery.py`, `tests/test_cc_stats.py`: update/add
  platform-aware cases, including a real fix for the currently-skipped
  Windows failure
- No changes expected in `parser/watcher.py` or `ui/` — already
  platform-clean

### Open question for implementation sprint
`psutil.Process.cwd()` can raise `AccessDenied` on Windows for processes
not owned by the current user (UAC/permissions) — need to decide
graceful-degradation behavior (skip vs. partial result) before writing
the replacement for `_get_process_cwd()`.

### Harness Integration
If harness active: feed this Current Sprint section as the spec.
If no harness: follow Development Protocol above directly.
