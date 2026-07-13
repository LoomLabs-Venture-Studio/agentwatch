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
- [x] Commits made and pushed — see below (superseded the original
      "first git commit" framing once it turned out `origin/main` already
      had 30 commits of real history; see `CLAUDE.md` Known Issues)
- [x] Draft PR opened for board review: PR #2,
      `chore/ci-docs-perf-windows-support` -> `main`
      (https://github.com/LoomLabs-Venture-Studio/agentwatch/pull/2)

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
6. Update this section + stage the first commit — done (CTO). Discovered
   mid-commit-prep that `origin/main` was never actually empty (30 real
   commits, PyPI releases through v0.1.6) — the local `.git` was just a
   disconnected fresh `git init`. Corrected course: branched off
   `origin/main` instead of committing an orphan baseline, split the real
   working-tree delta into 3 commits (bootstrap+bugfix, a previously-
   undocumented detector performance pass reconciled into PLAYBOOK here,
   and Sprint 1's Windows support), pushed, opened draft PR #2. Board
   review is next, not a merge decision by CTO.

**Status: Sprint 0 + Sprint 1 both done, submitted as PR #2, awaiting
board review.** See Task #7 section below for Sprint 1 detail and the new
"Detector Performance Pass" entry above Task #7 for the reconciled
undocumented work.

**Known non-blocking issue surfaced during push:** the local Loom-generated
`.git/hooks/pre-push` runs `scripts/verify-deploy.mjs`, which crashes with
`Cannot find package 'yaml'` (no `package.json`/`node_modules` in this repo
to supply it). The hook's exit-code contract treated the crash the same as
its own "WARN, push anyway" path, so the push wasn't blocked — but the
check never actually ran. Flagged in the PR description; needs a devops
follow-up (not yet assigned).

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
  bubble-level content schema remains genuinely unverified.
  **Promoted to Sprint 2 below (2026-07-11)** — board picked this over
  Aider/Codex CLI as the next sprint, scoped to the Phase 0 spike only.

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

### Sprint: Sprint 2 — Cursor Support, Phase 0 Research Spike
**Type:** research / spike (explicitly not implementation)
**Priority:** Unblocks Cursor `CursorWatcher` implementation (Phase 1),
which cannot be scoped or assigned until this phase's findings are
reviewed — per the architecture review's own Delegation section, this is
a harder gate than the usual "board approval to merge": it's board
approval to even start writing Phase 1.
**PRD Status:** architecture review exists (not a PRD) at
`C:\Users\Zaid\.claude\plans\cursor-sqlite-architecture-review.md`; this
sprint's own scoping plan is at
`C:\Users\Zaid\.claude\plans\whats-next-serialized-elephant.md`
**Harness:** PLAYBOOK standalone (no GSD/Ruflo signal)

**Why Cursor over Aider/Codex CLI:** board reviewed a comparison of all
three researched-but-unscoped backlog items (2026-07-11). Aider is more
tractable/lower-risk and Codex CLI has real value but an unverified core
schema guess — both remain in the Sprint 1 follow-up backlog above,
unscoped, for a future sprint. Board chose to prioritize Cursor's Phase 0
spike now that a populated Cursor install (real agent-mode chat history)
is available to inspect, which was the blocking dependency called out in
the architecture review.

### Acceptance Criteria
- [ ] A real populated `conversationMap` directly inspected (not
      inferred); every item in the architecture review's Open Questions
      section answered concretely or explicitly flagged "still open,
      tracked as follow-up" — no silent gaps. Covers: bubble schema
      (dict-by-id vs. list; role field names/values; tool-call bubble
      structure), whether per-turn cost/token data exists locally at all,
      how to detect "agent finished/errored" vs. "still working," whether
      a workspace can have multiple concurrent composers, whether Privacy
      Mode changes/removes local persistence, and the open product
      question of whether discovery should gate on "Cursor.exe running"
      (flagged for board decision, not resolved unilaterally by the
      engineer)
- [ ] Read-while-Cursor-has-file-open behavior (`mode=ro` SQLite URI)
      empirically confirmed on Windows, not just assumed from SQLite's
      general concurrent-reader guarantee
- [ ] No write ever executes against `state.vscdb` during the spike
- [ ] Zero changes under `src/agentwatch/` — this phase produces a
      findings document, not merged application code
- [ ] Findings written up as an appendix/sibling to
      `cursor-sqlite-architecture-review.md`, with sanitized (structure-
      only, no real prompts/code) example JSON

### Implementation Plan
1. Engineer runs the spike against a populated Cursor install: read-only
   connect to `state.vscdb`, query `composerHeaders` +
   `cursorDiskKV` (`composerData:<uuid>`), inspect real `conversationMap`
   content for one agent-mode and one chat-mode composer, confirm
   read-while-open on Windows, toggle Privacy Mode and re-check. Writes
   findings doc. **No `src/agentwatch/` changes.**
2. CTO reviews findings against the 5 acceptance criteria above.
3. QA independently re-runs 2-3 of the engineer's queries against a
   populated install as a spot-check (no test suite applicable here).
4. CTO reports findings to the board; Phase 1 (`CursorWatcher` real
   implementation) stays unscoped until the board explicitly signs off.

**Status: blocked (2026-07-11).** Engineer ran the spike against this
machine's real `state.vscdb` (14 `composerHeaders` rows, 10 real
`composerData` blobs — not the zero-conversation install the original
architecture review was written against). Confirmed empirically: read-
while-open on Windows works (20 rapid read-only queries against a live,
actively-writing `Cursor.exe`, 0 errors), the `mode=ro` connection
actively rejects writes (`sqlite3.OperationalError` on an explicit test
`INSERT`, not just "we chose not to write"), a workspace can have
multiple concurrent composers (`agent` + `chat` at once, confirmed
directly), and `conversationMap` is a JSON object rather than a list
(partial — key format still unknown). **Blocked on the core goal**: every
one of the 10 real `composerData` blobs has an **empty**
`conversationMap`, so bubble schema / role fields / tool-call structure /
turn-boundary detection remain unanswered. Live suspect: `privacyMode:
true` (`PRIVACY_MODE_NO_TRAINING`) is already enabled on this account —
plausible cause, not proven, and it contradicts the architecture review's
earlier claim (based on Cursor's own docs/forum) that Privacy Mode only
affects server-side retention, not local disk persistence. That claim may
need revisiting once this is resolved. Findings appended to
`cursor-sqlite-architecture-review.md` under "Phase 0 Findings
(2026-07-11)". `src/agentwatch/` confirmed untouched.

**Retest after Privacy Mode disabled (2026-07-11, same day):** user
turned Privacy Mode off (confirmed persisted to disk: `privacyMode`
`"true"` -> `"false"`, `newPrivacyMode2` `PRIVACY_MODE_NO_TRAINING` ->
`PRIVACY_MODE_USAGE_DATA_TRAINING_ALLOWED`) and ran a real agent-mode
conversation. **`conversationMap` is still empty on every composer,
byte-for-byte identical to before the toggle** — Privacy Mode is now
ruled out as the cause (consistent with, not contradicting, the original
review's forum research that it's server-side-only). New lead: 50s of
read-only polling while Cursor stayed open showed **zero further writes**
to `state.vscdb` after startup — points to a flush-on-close/tab-switch
timing gap, i.e. `composerData` may only get persisted when a composer
tab/window is closed, not live or on a short autosave timer. Findings in
`cursor-sqlite-architecture-review.md`, new subsection "Phase 0 Findings,
retest after Privacy Mode disabled". `src/agentwatch/` reconfirmed
untouched.

**Next step (board decision pending): close the composer tab or fully
quit Cursor immediately after sending a message, then re-check** — not
done automatically since force-closing the user's live session isn't a
call an agent should make unilaterally.

**Flush-timing retest completed (2026-07-12).** User sent a real message
and fully quit Cursor. Baseline + after-close read-only snapshots taken and
diffed (see `cursor-sqlite-architecture-review.md`, "Baseline snapshot
before flush-timing retest" and "After-close snapshot, flush-timing
retest" sections). **Literal theory refuted**: `conversationMap` is still
empty (`{}`) on every composer, including the newly-created one — closing/
quitting does not populate that field. **But a real write did land, in a
different place than expected**: `fullConversationHeadersOnly` went from
empty to a populated per-bubble index (`bubbleId`, numeric `type` enum,
`createdAt`, grouping flags — no message content), and `conversationState`
grew from a 1-character placeholder (`"~"`) to a 19,329-character
non-JSON, fully-printable string (`"~Ci..."..."W0="`) — very likely
protobuf or another binary/structured encoding rather than plain JSON.
New token/context-usage fields also appeared (`contextTokensUsed`,
`contextTokenLimit`, `promptTokenBreakdown`, etc.), correcting an earlier
guess about where usage data lives. **Caveat**: the test composer was
`chat` mode, not `agent` mode — confirms the flush mechanism generally,
not yet confirmed specifically for agent-mode composers.

**Net effect**: this changes Phase 1's actual target. The plan can no
longer assume "parse JSON out of `conversationMap`" — real content lives
in `conversationState`, which needs a decode step the original
architecture review never anticipated. **Board decision (2026-07-12):
invest in decoding `conversationState`'s encoding** rather than building
`CursorWatcher` on metadata-only fields or parking Cursor. Scoped as a
sub-investigation below.

### Sub-investigation: decode `conversationState` encoding
**Type:** research / spike
**Goal:** determine `conversationState`'s encoding scheme (leading
candidates: protobuf, base64/custom-framed, or a proprietary format) and
produce a working prototype decoder, so a future Phase 1 can actually
extract bubble/message content instead of only the empty-`conversationMap`
metadata layer.
**Constraints (same as prior Cursor recon passes)**: read-only against
`state.vscdb`, zero writes, zero changes under `src/agentwatch/` (this is
still investigation, not implementation — decoder prototypes belong in a
scratch script, not shipped code, until the encoding is actually
confirmed). **New constraint specific to this task**: decoding will likely
surface real conversation content for the first time in this
investigation — that's expected and fine since this is the user's own
local data and they explicitly directed this work, but findings written to
`cursor-sqlite-architecture-review.md` must still describe *structure*
(field names, types, nesting) rather than reproduce real prompt/message
text verbatim, consistent with every prior sanitized-findings entry in
that doc.

### Acceptance Criteria
- [x] `conversationState`'s encoding scheme identified with direct
      evidence (not guessed) — e.g. successfully decoded via a specific
      library/method, or a documented reason why a specific guess was
      ruled out
- [x] If decodable: a working prototype decode function (scratch script,
      not `src/agentwatch/`) that turns the raw string into structured
      data for at least one real captured `conversationState` value
- [x] Decoded structure's shape documented (sanitized) in
      `cursor-sqlite-architecture-review.md`: bubble/message boundaries,
      role field name(s) and values, tool-call representation if present
- [ ] If NOT decodable within reasonable effort: findings document why
      (e.g. proprietary/unknown framing, no matching known format found),
      explicit recommendation on whether further effort is worth it
      — N/A, it was decodable (see below)
- [x] Zero changes under `src/agentwatch/`; zero writes to `state.vscdb`

### Implementation Plan
1. Engineer takes the real `conversationState` value already captured in
   the after-close snapshot (or re-queries fresh if needed, read-only) and
   attempts decoding: check for base64/base64url framing (the trailing
   `=` is suggestive), check for protobuf magic-byte patterns, try common
   compression (gzip/zlib) after any base64 strip, per the `"~"` prefix
   possibly being a placeholder/sentinel character rather than payload.
2. If a working decode path is found, document structure + write a
   prototype in a scratch location.
3. CTO reviews findings against acceptance criteria.
4. Report to board: is Phase 1 (`CursorWatcher`) now unblocked, or does
   this need more investigation / external reference (e.g. checking if
   `somogyijanos/cursor-chat-export` or `saharmor/cursor-view` have
   already solved this — both were cited in the earlier encryption
   research as real, fetched-and-verified tools).

**Status: complete (2026-07-12), reported 2026-07-13.** Encoding
identified with direct evidence: `~` sentinel + base64 + a valid,
byte-complete protobuf message, hand-decoded via a dependency-free
scratch parser (never committed, per constraints). Result **refutes the
hypothesis that motivated it**: the decoded payload is ~97%
context-window token-accounting/telemetry (per-category token budgets for
rules/skills/MCP/subagents), not conversation content — no `role` field,
no message text, no tool-call data anywhere in it. This is the third
field-level hypothesis in this investigation (`conversationMap`, the
flush-on-close theory, now `conversationState`) to come up empty.

The engineer then ran an unscoped but flagged follow-on ("Investigation
round 4" in `cursor-sqlite-architecture-review.md`) and found what this
sub-investigation was actually trying to unblock: **three independent,
corroborating sources of real bubble content** — `cursorDiskKV
bubbleId:<composerId>:<bubbleId>` rows (the real per-bubble store, `type`
1/2 = user/assistant), `agentKv:blob:*` cache rows, and a newly-discovered
`conversation-search.db` FTS5 index. Round 4's recommendation: route back
to the board to authorize Phase 1 (`CursorWatcher`) against `bubbleId:*`
as primary source — the blocking gap is closed. Alternative next steps it
also flagged: one more full-file byte-diff pass (the method that has
reliably surfaced every real signal in this investigation so far), or
park Cursor support as not currently tractable. **Board decision needed**
on which of these three to take before Phase 1 work is scoped/assigned.

---

### Sprint: Sprint 3 — Aider Log Parser
**Type:** feature
**Priority:** AgentWatch already detects running `aider` processes and
resolves their log path (`discovery.py::_resolve_aider_log`), but
`agentwatch check --log <aider log>` silently reports "No actions found"
today — `parse_file()` is JSONL-only and every Markdown line fails
`json.loads()`.
**PRD Status:** full implementation plan approved, includes ready-to-use
code:  `C:\Users\Zaid\.claude\plans\aider-log-parser-prd.md`
**Harness:** PLAYBOOK standalone (no GSD/Ruflo signal)
**Board decision (2026-07-11):** started in parallel with the blocked
Cursor Phase 0 spike (Sprint 2) and the devops pre-push hook fix below —
none of the three touch overlapping files.

### Acceptance Criteria (from the PRD's own Verification section)
- [x] New `src/agentwatch/parser/aider.py`: `parse_aider_markdown`,
      `parse_aider_analytics`, `parse_aider_log`, matching both
      SEARCH/REPLACE and legacy ORIGINAL/UPDATED diff-marker styles
- [x] `parser/logs.py::parse_file()` extension-based dispatch: `.md` ->
      aider parser, existing JSONL loop unchanged for everything else
- [x] `parser/__init__.py` exports the three new entry points
- [x] `cli.py`: new `--analytics-log` option on `check`/`security-scan`,
      updated `--log` help text on both
- [x] New `tests/test_aider_parser.py` covering: session-start parsing +
      mtime fallback, turn-splitting incl. zero-turn edge case, both
      diff-marker styles, commit-line success/failure inference,
      Markdown-only "degraded but useful" zero-cost case, analytics merge
      by ordinal incl. mismatched-count fallback, `parse_file()` dispatch
      regression test
- [x] `python -m pytest tests/ -v` fully green, `ruff check .` no new
      warnings
- [x] Manual smoke test: hand-written `.aider.chat.history.md` fixture ->
      `agentwatch check --log <fixture>` reports a non-zero action count
      (no real Aider install required for this)
- [x] PR description explicitly notes which Open Questions from the PRD
      (ordinal message_send-to-turn pairing, analytics file lifecycle,
      edit-format coverage beyond SEARCH/REPLACE, `.aider/logs/*.log`
      fallback format, resumed-session handling) are deferred rather than
      resolved — per the PRD, these don't block this PR but must not be
      silently dropped

### Implementation Plan
Suggested commit sequence per the PRD: (1) Markdown-only parser + tests,
(2) analytics JSONL parsing + ordinal merge + merge tests, (3)
`parse_file()` dispatch + exports + dispatch regression test, (4) `cli.py`
`--analytics-log` option + help text, (5) README/docs/index.md mention of
Aider Markdown support. Live `agentwatch watch` tailing is explicitly out
of scope for this sprint (see PRD Open Questions) — one-shot `check`/
`security-scan` support only.

**Status: complete (implemented 2026-07-11, verified 2026-07-13).** Code-level
work was fully done and committed (`c3129cd`) well before this status line was
ever updated. CTO re-verification (not just trusting the original engineer
report): `parser/aider.py`/`__init__.py`/`logs.py`/`cli.py` all match the PRD
exactly; `test_aider_parser.py` covers every listed case including 3
in-code-documented QA regression fixes (empty-block diff matching,
backtick-wrapped filenames, turn-headers-inside-fences); `pytest` 443/443
green; `aider.py` + its test file individually 100% ruff-clean; repo-wide
ruff warning count actually *decreased* (635 -> 590) comparing pre-Sprint-3
to current HEAD, confirming no new warnings anywhere, not just in touched
files. Manual smoke test re-run directly against a hand-written fixture:
`agentwatch check --log <fixture>` produced a real health report, not "No
actions found." **Gap found and now fixed**: the PR description originally
covered Codex's 7 open questions but not Aider's 5 — corrected in the same
pass that closed this status update (PR #2 body edited to add the missing
paragraph and refresh a stale Cursor reference).

---

### Devops: fix broken local pre-push hook
**Type:** chore / infra
**Priority:** low (non-blocking today, but the check silently never runs)
**Problem:** `.git/hooks/pre-push` (Loom-generated) runs `node
scripts/verify-deploy.mjs`, which crashes with `Cannot find package
'yaml'` — no `package.json`/`node_modules` exist in this repo to supply
the `yaml` import the script needs. The crash's exit code happens to
match the hook's own "WARN, push anyway" contract, so pushes were never
actually blocked, but the deploy-graph integrity checks (env polarity,
config consistency, out-of-band DDL) never ran either. Confirmed real
`.loom/stack.yml` + `.loom/environments.yml` manifests are present, so
this isn't a no-op-by-design case — the checks are meant to run.
Flagged since Sprint 0, unassigned until now.
**Board decision (2026-07-11):** assigned to devops in parallel with
Sprint 2/3 — touches only `package.json`/`node_modules`/`.gitignore`, no
overlap with either.

### Acceptance Criteria
- [x] `package.json` added with `yaml` as a dependency
- [x] `node_modules/` added to `.gitignore` (not currently present)
- [x] `node scripts/verify-deploy.mjs` runs to completion without
      crashing (PASS/WARN/FAIL per its own documented exit codes, not an
      import error)
- [x] A real git push (or `git push --dry-run` / manual hook invocation)
      shows the hook actually executing the checks, not silently
      no-op-ing via the old crash-shaped WARN path
- [x] No changes to the GitHub Actions Python CI gate
      (`.github/workflows/verify-deploy.yml`, already repurposed in
      Sprint 0) — this is a separate, local-only hook

**Status: complete (implemented 2026-07-11, verified 2026-07-13).**
CTO re-verification: `package.json` present with `yaml ^2.6.1`;
`.gitignore` has `node_modules/`; ran `node scripts/verify-deploy.mjs`
directly — clean exit 0, real skip semantics (`0 pass, 0 warn, 0 fail, 3
skip`), no crash/import error; a real push already exercised this hook
end-to-end during the prior session (first real proof-of-life, replacing
the old `yaml`-import crash); confirmed `.github/workflows/verify-deploy.yml`
untouched since before this branch (`git diff 430bad6..HEAD --stat` empty
for that path). All 5 acceptance criteria met.

---

### Sprint: Sprint 4 — Codex CLI Support, Phase 1 (fixture-based implementation)
**Type:** feature
**Priority:** `discovery.py::AGENT_PATTERNS` already detects running `codex`
processes, but `find_running_agents()`'s log-resolution dispatch only
branches on `"claude-code"`/`"aider"` — Codex processes always get
`log_file=None`, so `agentwatch check`/`watch` can never parse a Codex
session even though the process is visible in `agentwatch ps`.
**PRD Status:** full implementation plan exists:
`C:\Users\Zaid\.claude\plans\codex-cli-support-prd.md` — written entirely
from source/issue-tracker research (real `openai/codex` repo,
`codex-rs/protocol/src/protocol.rs`, issues #4963/#13463/#21660,
`PixelPaw-Labs/codex-trace`), **no live Codex CLI install was available to
verify against** (confirmed again 2026-07-12: no `~/.codex`, no `codex` on
PATH on this machine either). Confidence is high on file locations and the
outer JSONL envelope; explicitly not high on exact inner field names — see
PRD's "Open Questions / Requires Live Install to Confirm" (7 items, most
importantly #1: the literal `type` string nesting on `response_item`
lines).
**Harness:** PLAYBOOK standalone (no GSD/Ruflo signal)
**Board decision (2026-07-12):** given no live install exists on this or
any available machine right now, board chose to proceed with implementation
now (fixture-based, version-era-guarded) rather than block on a research-only
spike or wait indefinitely for a live install — matching the PRD's own
recommended delegation split, not a deviation from it.

### Scope for this sprint
PRD's Suggested Commit Sequence, **steps 1-4 only**:
1. `discovery.py`: new `_resolve_codex_log()` + `_read_codex_session_meta()`
   helper, wired into `find_running_agents()`'s dispatch; honors
   `CODEX_HOME` (single-root only — comma-separated multi-root support is
   unconfirmed, PRD Open Question #2)
2. New `src/agentwatch/parser/codex.py`: `CodexParser` (stateful,
   `call_id`-based function-call/output correlation, `flush()` for
   end-of-stream), `_detect_codex_era()` (version/shape-sniffing across the
   3 confirmed schema eras), `classify_codex_tool()` — all built and unit
   tested against a **hand-authored fixture file**, not real captured
   output
3. `logs.py`: `detect_log_format()` Codex branch + `parse_file()` wiring;
   `parser/__init__.py` exports (`CodexParser`, `classify_codex_tool`)
4. `watcher.py`: `LogWatcher` stateful-parser wiring — lazy `CodexParser`
   construction, **no `flush()` call on the tail path** (a live tail keeps
   pending calls buffered indefinitely; only `parse_file()`'s one-shot
   batch read flushes at EOF) — this asymmetry must be code-commented, not
   just implied

**Explicitly out of scope / hard-gated, not this sprint:** PRD commit 5 (the
"confirm against a real install" gate) — requires installing Codex CLI,
capturing a real `rollout-*.jsonl`, and patching whatever the research got
wrong (expected: era-detection field name, `type` string nesting, real tool
names for `classify_codex_tool`). Do not mark this sprint's output
production-verified; it is fixture-verified only, with a known-unconfirmed
core assumption (PRD Open Question #1) baked into both the parser and its
own test fixtures.

### Acceptance Criteria
- [x] `discovery.py::_resolve_codex_log()` implemented, wired into
      `find_running_agents()`'s dispatch, unit-tested against hand-authored
      fixture `session_meta` lines (both cwd-match and mtime-fallback paths)
- [x] `parser/codex.py` (`CodexParser`, `classify_codex_tool`,
      `_detect_codex_era`, extraction helpers) implemented and unit-tested
      against a hand-authored fixture `rollout-*.jsonl` built from the
      confirmed `protocol.rs` envelope shape
- [x] `logs.py::detect_log_format` correctly identifies the fixture file as
      `"codex"`, no cross-contamination with existing Claude Code/Moltbot/
      Aider detection (regression check on existing fixtures)
- [x] `parse_file()` and `LogWatcher` both produce a correct `Action` stream
      from the fixture, including: a `function_call`/`function_call_output`
      pair separated by narration (non-adjacent lines), and a call whose
      output never arrives before end-of-stream (validates `flush()` on
      `parse_file`, validates no premature/no flush on `LogWatcher`)
- [x] `python -m pytest tests/ -v` fully green, no regressions — **345/345
      pass**
- [x] `ruff check .` clean on all new/touched files — confirmed zero
      warnings on the 7 files this sprint touched; repo's ~598 pre-existing
      warnings are all in unrelated files, out of scope
- [x] PR description explicitly flags: (a) this is fixture-verified only,
      no live Codex install exists to confirm against; (b) all 7 PRD Open
      Questions carried forward, unresolved, into a follow-up gate — not
      silently dropped; (c) `classify_codex_tool` is expected to
      misclassify most/all real Codex actions as `UNKNOWN` until real tool
      names are confirmed (PRD Open Question #3)
- [ ] **Not in this sprint's acceptance criteria, tracked separately as a
      follow-up gate**: live-install re-validation (PRD's own commit-5 gate)
      before this is called production-ready

### Implementation Plan
Per the PRD's own Delegation section: engineer implements steps 1-4 against
the hand-authored fixtures, fully test-covered, ruff-clean. CTO reviews.
QA does a fixture-based verification pass (no live-install spot-check
possible this sprint). Live-install re-validation stays an explicit unscoped
follow-up, blocking a separate future "production-ready" sign-off, not this
sprint's merge.

**Status: implementation complete, CTO-reviewed (2026-07-13), committed to
`chore/ci-docs-perf-windows-support` — not merged, not pushed.** CTO review
(read-only pass against the diff + a real `pytest`/`ruff` run) confirmed all
6 code-level acceptance criteria above are met with no rework needed:
`_resolve_codex_log()` covers both cwd-match and mtime-fallback with
`CODEX_HOME` override support; `CodexParser`/`classify_codex_tool`/
`_detect_codex_era` are implemented and fixture-tested;
`detect_log_format` identifies Codex fixtures with zero cross-contamination
on existing Claude Code/Moltbot/Aider detection (regression-tested); the
`flush()`-on-`parse_file()`-but-never-on-`LogWatcher` asymmetry is
explicitly code-commented in both `logs.py` and `watcher.py`, not just
implied; `pytest tests/ -v` is 345/345 green; `ruff check` is clean on all
7 new/touched files.

**PR-description caveats (carried into the PR body verbatim, not just this
file):**
1. **Fixture-verified only.** No live Codex CLI install exists on this or
   any available machine (confirmed 2026-07-10 and again 2026-07-12) — every
   test in `test_codex_discovery.py` / `test_codex_parser.py` runs against
   hand-authored fixtures built from source-code research
   (`codex-rs/protocol/src/protocol.rs`), not a captured real session.
2. **All 7 PRD Open Questions remain unresolved**, carried forward as an
   explicit follow-up gate, not silently dropped — most importantly Open
   Question #1 (whether `response_item` lines nest `type` literally as
   `"response_item/function_call"` vs. `type="response_item"` +
   `payload.type`), which the parser's core dispatch logic depends on.
3. **`classify_codex_tool` is expected to misclassify most/all real Codex
   actions as `UNKNOWN`** until real tool names are confirmed against a live
   install (PRD Open Question #3) — this is a known, accepted limitation of
   this sprint's scope, not a bug.

Live-install re-validation (PRD's own commit-5 gate) stays an explicit,
separately-tracked follow-up before this is called production-ready — it is
not part of this sprint's completion and does not block this commit.

**Next:** hand off to QA for a fixture-based verification pass (no
live-install spot-check possible this sprint). No push to the remote branch
yet — local commits only, pending review.

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

---

## Task #8: Pure-ASCII theme for legacy Windows console compatibility

**Type:** feature (small) / bugfix-adjacent
**Priority:** low-medium — cosmetic, has a workaround, but affects default
out-of-the-box experience for anyone on plain `cmd.exe`/`powershell.exe`
**PRD Status:** not needed (small, recon-driven; findings below are from a
live manual test on the user's own Windows machine, not fixture/guesswork)
**Harness:** PLAYBOOK standalone (no GSD/Ruflo signal)

### Problem, confirmed empirically (2026-07-13)
User ran `agentwatch watch` on plain PowerShell: emoji glyphs (`🚀😓🔄🧱`
etc., the default `agent` theme) rendered as `?`. Diagnosed live, in this
order, each step actually tested rather than assumed:
1. **Not a re-run of the Task #7 crash bug.** `_ensure_utf8_stdio()`
   (`cli.py`) already reconfigures Python's own stdout/stderr to UTF-8 —
   confirmed no crash, just wrong rendering.
2. **Not a console code-page problem either**, though it looked like one at
   first. User's console reported `chcp` -> code page 437 (a real, live
   data point, not assumed) matching the "?" symptom. But switching to
   `chcp 65001` and re-running **did not fix it** — ruled out.
3. **Root cause: legacy `conhost.exe` (behind plain `cmd.exe`/
   `powershell.exe`) has no font-fallback.** After `chcp 65001`, the
   failure mode changed from a plain `?` to a "tofu" box-with-`?` — the
   standard Unicode missing-glyph fallback, which only appears when the
   *encoding* is already correct but the *font* has no glyph for that
   codepoint. Confirmed even simple 1-codepoint symbols (`✓`/`✗` from the
   `technical` theme) fail the same way, not just full-color emoji.
   VS Code's integrated terminal renders the exact same output correctly
   because its renderer (like Windows Terminal's) does font-fallback;
   legacy `conhost.exe` does not. This is a Windows-console-host capability
   gap, not something `_ensure_utf8_stdio()` or any stdout-encoding fix can
   solve — confirmed before any code was written, not discovered by
   shipping a broken fix.

### Chosen approach
Board decision (2026-07-13): don't chase an unfixable terminal-host
limitation. Instead, add a genuinely pure-ASCII theme (no `✓`/`✗` dingbats
either, since those already proved to tofu the same way) using bracketed
text labels (e.g. `[OK]` / `[WARN]` / `[ALERT]` / `[FAIL]`) as the
`emoji_0`..`emoji_3` values, so legacy-console users have a real escape
hatch instead of just being told to switch terminals. Document the
underlying conhost font-fallback limitation (README/CLAUDE.md Known
Issues) alongside it, recommending Windows Terminal for anyone who wants
the existing emoji themes to render correctly.

### Acceptance Criteria
- [ ] New `StatusTheme` registered in `THEMES` (`themes.py`), e.g. name
      `"ascii"`, using only 7-bit ASCII in every `emoji_*` field —
      bracketed text labels per the user's request (`[OK]`/`[WARN]`/
      `[ALERT]`/`[FAIL]` or equivalent), not just swapping dingbats for
      other dingbats
- [ ] `StatusTheme.emoji_for()`'s unknown-status fallback (`"❓"`,
      `themes.py` line ~77) is itself non-ASCII — confirm whether this path
      is reachable in practice (it shouldn't be, since `status_from_score`
      always returns one of the 4 registered labels) and either leave a
      code comment explaining why it's safe, or fix it to a
      theme-appropriate ASCII fallback if it *is* reachable
- [ ] Verify rendering/alignment: existing emoji values are short
      (1-2 display columns); bracketed text labels like `[ALERT]` are
      longer. Check `ui/app.py`, `ui/rot_widget.py`, `health/score.py`,
      and `cli.py`'s report formatting (the files that consume
      `get_status_emoji`/`emoji_for`) for any fixed-width padding/alignment
      assumptions that would misalign with a longer label, and fix or
      confirm harmless
- [ ] `agentwatch themes` output includes the new theme in its listing
- [ ] `--theme ascii` works end-to-end on `check`, `watch`, and
      `security-scan` (spot check at minimum `check`, since `watch`/TUI
      can't be verified headlessly the same way)
- [ ] New/updated tests in whichever `tests/test_themes*.py` (or nearest
      equivalent) covers theme registration/lookup — add the new theme to
      existing parametrized cases rather than hand-rolling a parallel test
      file, if such a pattern already exists
- [ ] `python -m pytest tests/ -v` fully green, `ruff check` clean on
      touched files
- [ ] **Documentation** (the other half of this task): README.md and/or
      `CLAUDE.md` Known Issues gets a short, honest write-up of the
      conhost font-fallback limitation — legacy `cmd.exe`/`powershell.exe`
      can't render the emoji themes (not an AgentWatch bug, no code fix
      possible), recommends either `--theme ascii` or switching to Windows
      Terminal (`wt.exe`) / VS Code's integrated terminal, both of which
      render the existing themes correctly

### Implementation Plan
1. Engineer adds the `ascii` theme to `themes.py`, checks/fixes any
   fixed-width rendering assumptions in the consuming files listed above,
   adds test coverage, confirms `pytest`/`ruff` clean.
2. Engineer (or CTO, whichever is more natural given this is partly a docs
   task) writes the README/CLAUDE.md Known Issues entry documenting the
   conhost limitation and the two workarounds.
3. CTO reviews.
4. Manual smoke test on the user's real Windows machine (the same one that
   found this bug) confirms `--theme ascii` actually renders cleanly where
   the emoji themes tofu'd.

**Status: implemented, CTO-reviewed, committed to
`chore/ci-docs-perf-windows-support` (2026-07-13)** — not merged, not
pushed. Engineer added `THEME_ASCII` (`[OK]`/`[WARN]`/`[ALERT]`/`[FAIL]`)
to `themes.py`, registered in `THEMES`; added a code comment documenting
why `emoji_for()`'s non-ASCII `"❓"` fallback is unreachable in current call
paths rather than leaving it unexplained; traced every consumer of
`emoji_for`/`get_status_emoji` (`cli.py`, `ui/app.py`, `ui/rot_widget.py`,
`health/score.py`) and confirmed none apply fixed-width formatting to the
emoji field, so the longer ASCII labels don't misalign anything; new
`tests/test_themes.py` covers registration, ASCII-only output on all 4
levels, and a bonus sanity check across every registered theme; `CLAUDE.md`
Known Issues documents the conhost font-fallback root cause and both
workarounds (`--theme ascii`, or Windows Terminal/VS Code's terminal).
CTO independently re-ran `pytest`/`ruff` rather than trusting the
engineer's report — 366/366 tests pass, `ruff check` clean on both touched
files. Manual smoke test (`--theme ascii check`/`security-scan` against a
real fixture) confirmed clean ASCII-only output.

**Known gap surfaced by user re-testing on their real machine (2026-07-13,
same day): `--theme ascii` does not fully eliminate emoji in `watch`'s
Security panel.** User ran `agentwatch --theme ascii watch` and still saw
a tofu'd `🛡️` in the security status line. Root cause traced: Task #8 was
correctly scoped to "theme-driven `emoji_*` glyphs," but several places in
the codebase hardcode emoji **independent of the theme system entirely** —
these were never in scope for Task #8 and are a pre-existing gap, not a
regression:
- `ui/app.py::SecurityStatus.render()` — hardcodes `"🛡️  SECURE"` /
  `"⚠️  AT RISK"` / `"🚨 COMPROMISED"` directly, never calls `get_theme()`
  (unlike `HealthBar`/`EfficiencyBar` in the same file, which do it right)
- `cli.py`'s `security-scan` command (~line 500-506) — a separate,
  duplicated copy of the same SECURE/AT RISK/COMPROMISED logic, also
  hardcoded
- `cli.py` — further hardcoded emoji in report headers: `"✅ No issues
  detected"`, `"🚨 CRITICAL SECURITY ALERTS 🚨"`, `"⚠️  HIGH SEVERITY
  WARNINGS"`
- `detectors/base.py::Severity.emoji` — a hardcoded per-severity
  (LOW/MEDIUM/HIGH/CRITICAL) emoji mapping, architecturally independent of
  `StatusTheme` (severity is categorical, not score-derived), feeds into
  `Warning.emoji` used across detector output
- `ui/multi_app.py` — not yet fully audited, flagged for the same check

**Board decision (2026-07-13): full audit, not a spot patch.** Wire all of
the above to the theme system so `--theme ascii` is actually ASCII-clean
everywhere, not just in the two widgets that happened to already call
`get_theme()`.

### Acceptance Criteria (Task #9 — the follow-up)
- [ ] `ui/app.py::SecurityStatus.render()` calls `get_theme()` /
      `emoji_for()` instead of hardcoding emoji, following the same
      pattern already used correctly by `HealthBar` in the same file
- [ ] `cli.py`'s `security-scan` SECURE/AT RISK/COMPROMISED block
      shares logic with (or is replaced by calling into) the same
      theme-driven mapping as the TUI widget, rather than staying a
      second hand-copied hardcoded block — the duplication is exactly
      why this bug was easy to introduce and miss in one place but not
      the other
- [ ] `cli.py`'s other hardcoded report-header emoji (`"✅ No issues
      detected"`, `"🚨 CRITICAL SECURITY ALERTS 🚨"`, `"⚠️  HIGH SEVERITY
      WARNINGS"`) audited and made theme-aware where it makes sense
- [ ] `detectors/base.py::Severity.emoji` — this one needs actual design
      judgment, not just a mechanical swap: `Severity` is a 4-level
      categorical enum (LOW/MEDIUM/HIGH/CRITICAL) independent of
      `StatusTheme`'s score-derived 4 levels, and there's no clean 1:1
      mapping (nothing in `Severity` corresponds to `level_0`/"all
      good"). Engineer should propose a specific mapping (e.g. onto
      `emoji_1`/`emoji_2`/`emoji_3` with LOW and MEDIUM possibly sharing
      a level, or another approach) and flag the tradeoff explicitly for
      CTO review rather than picking silently
- [ ] `ui/multi_app.py` audited for the same hardcoded-emoji pattern,
      fixed if found
- [ ] Regression safety: existing (non-ascii) themes' visible output is
      unchanged after this refactor — add/extend tests asserting e.g.
      `Warning.emoji`/`SecurityStatus` output for the default `agent`
      theme matches pre-refactor values, not just that the `ascii` theme
      is now clean
- [ ] New test(s) proving zero non-ASCII characters appear anywhere in
      `watch --security` / `security-scan` / `check --security` output
      when `--theme ascii` is active — this is the actual regression
      test for what the user just found, not just unit-level emoji
      checks
- [ ] `python -m pytest tests/ -v` fully green, `ruff check` clean on all
      touched files

### Implementation Plan
Engineer audits and fixes each hardcoded-emoji site above, proposes the
`Severity.emoji` mapping explicitly rather than deciding silently, adds
the end-to-end zero-non-ASCII regression test. CTO reviews (including the
`Severity` mapping tradeoff specifically). Manual smoke test on the user's
real Windows machine again before considering this closed — that's the
only environment that's actually caught real bugs here so far, twice.

**Status: implemented, CTO-reviewed, committed to
`chore/ci-docs-perf-windows-support` (2026-07-13)** — not merged, not
pushed. Engineer added `security_status_from_score()` and `ascii_safe()`
shared helpers (`themes.py`); redesigned `Severity.emoji`
(`detectors/base.py`) to stay unchanged for all 11 non-ascii themes and
only swap to `[LOW]`/`[MED]`/`[HIGH]`/`[CRIT]` under `ascii` (design
tradeoff documented in-code, reviewed); wired `SecurityStatus`
(`ui/app.py`) and `security-scan` (`cli.py`) to the shared helper instead
of two hand-copied hardcoded blocks; found and fixed one more hardcoded
glyph in `ui/multi_app.py` not in the original audit list. New
`tests/test_theme_emoji_wiring.py` (77 tests) covers widget/CLI/TUI-pilot
level output plus per-theme regression (all 11 non-ascii themes visually
unchanged). CTO independently re-verified: 443/443 tests pass; ruff
before/after diffed per touched file against the pre-edit baseline (zero
new warnings, several files' counts actually decreased); live smoke test
against a real session log (`--theme ascii check --security`) confirmed
clean output (`[OK]`, `[WARN]`, `[ALERT]`, `[MED]`, `[TIP]`, no tofu).

**QA correction (2026-07-13):** independent QA verification (byte-level
scan of real command output, not just the unit-test suite) found that
`check`/`security-scan` output under `--theme ascii` still contains
`═`/`╔╗╚╝` box-drawing characters (U+2550 etc.) in `cli.py`'s report
headers — literally non-ASCII, which contradicts this section's original
"fully ASCII-clean" / "zero non-ASCII characters" wording above. **This is
a documentation-precision correction, not a functional bug**: box-drawing
characters are part of CP437 (the exact legacy code page confirmed active
on the user's real machine during the Task #8 investigation), which was
built for DOS-era box-drawing UI and renders them natively — unlike emoji/
dingbats, which are the actual, and only, root cause of the conhost
font-fallback problem this task exists to fix. `test_theme_emoji_wiring.py`
already scoped box-drawing out for this exact reason (see its module
docstring's "SCOPE NOTE"), but that scoping was never reflected back into
this section's completion language, which is the gap QA correctly caught.
**Re-verified live** (2026-07-13, same day): user ran
`agentwatch --theme ascii check --security` in their real PowerShell
(the same environment that found the original Task #8 bug) and confirmed
the `═` divider lines render as actual horizontal double-lines, not tofu/
`?`. Task #9's actual, correctly-scoped claim is: **zero emoji/dingbat
characters** render under `--theme ascii` — not "zero non-ASCII
characters" — and that narrower claim holds, live-verified.
