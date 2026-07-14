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

### Sprint: Sprint 5 — Cursor Support, Phase 1 (`CursorWatcher`)
**Type:** feature
**Priority:** unblocks Cursor support entirely — every prior investigation
round (1-3) was blocked on "no populated conversation exists to inspect";
round 4 (2026-07-12) closed that gap with real, three-way-corroborated
content.
**PRD Status:** architecture review + 4 rounds of investigation exist at
`C:\Users\Zaid\.claude\plans\cursor-sqlite-architecture-review.md`. No
separate PRD document — this section's acceptance criteria serve that role,
derived directly from round 4's confirmed findings.
**Harness:** PLAYBOOK standalone (no GSD/Ruflo signal)
**Board decision (2026-07-14):** authorize `CursorWatcher` build against
`bubbleId:*` as primary source, per round 4's recommendation #1. Scoped to
architecture review's **Phase 1 only** (steps 1-3: `cursor_source.py`,
`CursorWatcher`, bubble-to-`Action` mapping) — Phase 2 (`cursor_discovery.py`
+ UI/CLI wiring) stays out of scope, both because the review phases it
separately and because it carries its own unresolved product question
("does Cursor.exe running need to gate discovery") that the board hasn't
ruled on.

### Critical correction this sprint must build against
The architecture review's original Approach step 3 sketch (`_diff_bubbles`
reading `composerData.conversationMap`) is **confirmed wrong** —
`conversationMap` is empty/vestigial on every composer observed across all
4 investigation rounds. Round 4 found the real per-bubble content store:
`cursorDiskKV` rows keyed `bubbleId:<composerId>:<bubbleId>`. Do not
implement against the original sketch; implement against the corrected
schema below.

### Acceptance Criteria
- [x] New `src/agentwatch/parser/cursor_source.py`: `open_readonly()`
      (`mode=ro` URI, per the architecture review's snippet — unchanged),
      `fetch_composer_headers()` using the **real, corrected**
      `composerHeaders` schema (`composerId`, `workspaceId`, `createdAt`,
      `lastUpdatedAt` int column — not JSON-only, `isArchived`,
      `isSubagent`, `recency`, `checkpointAt`, `value` JSON), `fetch_bubbles
      (conn, composer_id)` querying `cursorDiskKV WHERE key LIKE
      'bubbleId:' || ? || ':%'`, `fetch_checkpoint(conn, composer_id,
      checkpoint_id)` querying `checkpointId:<composerId>:<checkpointId>`
      for file/diff cross-reference
- [x] Bubble-to-`Action` mapping uses the round-4-confirmed real fields,
      not the original guess: `type` (int: `1`=user, `2`=assistant) ->
      role, `text` -> content (not `conversationMap`, not `richText`),
      `thinking`/`thinkingDurationMs`/`thinkingStyle` -> optional
      reasoning metadata, `tokenCount.inputTokens`/`outputTokens` ->
      `tokens_in`/`tokens_out` (real field, but document in-code that it
      was observed as always `{0,0}` for the `composer-2.5` model in every
      sample seen — do not treat a zero reading as a parsing bug),
      `modelInfo.modelName` -> model identity when present (first bubble
      of a turn only, per round 4), `checkpointId` -> cross-referenced
      `checkpointId:*` row's `files`/`nonExistentFiles` for `file_path`.
      **Note**: `Action` has no dedicated model-identity field, so
      `modelInfo` (like `thinking`/`thinkingDurationMs`/`thinkingStyle`) is
      surfaced via `raw` rather than promoted to a top-level attribute —
      the same "stuff the source object into `raw` for detector access to
      un-promoted fields" pattern every other parser in this package
      already uses, not a gap.
- [x] `toolResults` (list) exists structurally but its **populated shape
      was never observed in any of the 4 investigation rounds** — no tool
      call happened in the one real exchange available. Tool-call
      classification must default conservatively (analogous to Codex's
      `classify_codex_tool` UNKNOWN-until-confirmed precedent) rather than
      guess a shape. Document this as a known limitation in the module
      docstring, not hidden.
- [x] Do **not** fall back to `SessionStats.estimated_cost`'s blended-rate
      heuristic for Cursor sources when `tokenCount` reads zero — leave
      `tokens_in`/`tokens_out`/`cost_usd` at `0`/`0.0`, per the original
      architecture review's explicit instruction not to duplicate that
      fallback
- [x] New `CursorWatcher` class in `parser/watcher.py`: two-tier poll
      (`composerHeaders.lastUpdatedAt` cheap check first, selective
      `bubbleId:*` refetch only for composers whose watermark advanced),
      matching the architecture review's recommendation (a) gated by (c).
      `header_poll_interval`/`min_blob_poll_interval` as constructor args,
      not hardcoded, mirroring `MultiLogWatcher.poll_interval`
- [x] `mode=ro` enforced on every connection; a test asserts an explicit
      `INSERT` attempt raises `sqlite3.OperationalError`, not just that the
      code never calls `INSERT`/`UPDATE` (matches how round 1 empirically
      verified this, not just assumed it)
- [x] New tests (`test_cursor_source.py`, `test_cursor_watcher.py`) against
      a hand-built fixture SQLite DB matching the **real, round-4-confirmed
      schema** (`composerHeaders` real columns, `bubbleId:*` real JSON
      shape incl. `type`/`text`/`tokenCount`/`checkpointId`,
      `checkpointId:*` real shape) — not the original review's guessed
      `conversationMap`-based sketch, which is now known-wrong. Cover: a
      user+assistant bubble pair -> 2 correctly-typed `Action`s, a
      `lastUpdatedAt` change across two poll ticks triggering exactly one
      `bubbleId:*` refetch (assert on query/mock call count, not just
      output), an empty/vestigial `conversationMap` composer producing no
      spurious actions
- [x] Zero changes to `detectors/health/*.py` or `detectors/security/*.py`
      — the `Action` abstraction should mean detectors need no changes;
      existing detector test suite passes unmodified as a regression check
- [x] Explicitly out of scope, not attempted this sprint: `cursor_discovery.
      py` (Phase 2), any `ui/multi_app.py`/`cli.py` wiring, `agentKv:blob:*`
      or `conversation-search.db` as alternate/cross-check sources (round 4
      flagged both as options for whoever scopes Phase 1 in more detail —
      deferred, not silently dropped)
- [ ] PR description explicitly states: fixture-verified only against a
      schema derived from one real (but tool-call-free) exchange; tool-call
      bubble shape and whether `tokenCount` is ever populated for paid
      model tiers remain open, tracked as follow-up gates before
      production-ready, same honesty standard as the Codex CLI sprint —
      **not attempted this sprint**: no PR was opened (explicit instruction
      this sprint was local-commit-only, mirroring how Sprint 4 also ended
      at "committed, not pushed, not PR'd"). The substance of this caveat
      is documented instead in `cursor_source.py`'s module docstring and in
      the status writeup below, ready to carry into the PR body verbatim
      whenever a PR for this branch is opened.
- [x] `python -m pytest tests/ -v` fully green, `ruff check .` clean on all
      new/touched files

### Implementation Plan
Engineer implements `cursor_source.py` + `CursorWatcher` against the
corrected `bubbleId:*`-based schema above, fixture-tested. CTO reviews
against acceptance criteria (including verifying the fixture schema
actually matches round 4's documented field names/types, not a
re-guessed shape). QA does a fixture-based verification pass. Phase 2
(`cursor_discovery.py` + UI/CLI wiring) stays unscoped pending a separate
board decision on the "does Cursor.exe running gate discovery" product
question.

**Status: implementation complete, CTO-reviewed (2026-07-14), committed to
`chore/ci-docs-perf-windows-support` as `9b6a4a9`** — not pushed. CTO
independently re-ran `pytest`/`ruff` rather than trusting the engineer's
report: 468/468 tests pass; `ruff check` clean on all 5 new/touched files;
repo-wide `ruff check .` unchanged at 590 errors (zero new warnings);
`git diff --stat` confirmed zero changes under `detectors/`, `ui/`,
`cli.py`, and no `cursor_discovery.py` created. Spot-read `cursor_source.py`
and `CursorWatcher` directly — schema matches round 4's confirmed findings,
tool classification defaults conservatively per the Codex precedent, and
the min-blob-poll throttle correctly leaves the watermark un-advanced
rather than dropping a delta. Handed to QA next.

Built `src/agentwatch/parser/cursor_source.py` (`open_readonly`,
`fetch_composer_headers`, `fetch_bubbles`, `fetch_checkpoint`,
`bubble_to_action`, `classify_cursor_tool`) against the round-4-confirmed
`bubbleId:<composerId>:<bubbleId>` schema, not the original review's wrong
`conversationMap` guess. Added `CursorWatcher` to `parser/watcher.py`,
structurally parallel to `LogWatcher` (`watch() -> AsyncIterator[Action]`,
`on_action`, `watch_with_callbacks`), internally a synchronous `_poll_once()`
two-tier poll (cheap `lastUpdatedAt` watermark check, then a
`min_blob_poll_interval`-throttled selective `fetch_bubbles` refetch that
deliberately leaves the watermark un-advanced when throttled so a delta is
delayed, never dropped) driven by a plain `asyncio.sleep(header_poll_interval)`
timer loop — no `watchfiles.awatch` early-wake optimization was added, per
the sprint's own "acceptable as baseline, don't over-engineer" guidance.
Both intervals are constructor args (`header_poll_interval=5.0`,
`min_blob_poll_interval=1.0`), not hardcoded. `parser/__init__.py` updated to
export `CursorWatcher` and the `cursor_source` entry points, mirroring how
Sprint 4 wired `CodexParser`/`classify_codex_tool` — not explicitly required
by this sprint's acceptance criteria, but consistent with existing project
pattern and not itself UI/CLI wiring (no `ui/`, `cli.py`, or
`cursor_discovery.py` touched — confirmed via `git diff --stat` showing only
`parser/__init__.py`, `parser/watcher.py` modified and `parser/cursor_source.py`
new).

New `tests/test_cursor_source.py` (19 tests) and `tests/test_cursor_watcher.py`
(6 tests) build a hand-crafted fixture SQLite DB against the real schema
(`composerHeaders` real columns, `cursorDiskKV` `bubbleId:*`/`checkpointId:*`
real key shapes) — every specifically-required case is covered: a
user+assistant bubble pair producing 2 correctly-typed `Action`s, a
`lastUpdatedAt` change across two/three poll ticks asserted via
`unittest.mock.patch(..., wraps=...)` call-count on `fetch_bubbles` (not just
output), an empty/vestigial composer (header exists, zero `bubbleId:*` rows)
producing zero spurious actions, a composer with `lastUpdatedAt IS NULL`
(never messaged) skipped without crashing, `open_readonly()` + an explicit
`INSERT` raising `sqlite3.OperationalError` (replicating round 1's empirical
proof, not a mocked assertion), and a deterministic (fake-clock, no real
`sleep`) throttle-then-recovery test for `min_blob_poll_interval`. `python -m
pytest tests/ -v` — **468/468 pass**, zero regressions (up from Sprint 4's
345; the delta includes this sprint's 25 new tests plus other work already
on this branch). `ruff check` on the 5 new/touched files (`cursor_source.py`,
`watcher.py`, `parser/__init__.py`, both new test files) is clean; repo-wide
`ruff check .` is **590 errors — unchanged from the documented pre-existing
baseline**, confirming zero new warnings introduced anywhere. `git diff
--stat -- src/agentwatch/detectors/` and `-- src/agentwatch/ui/
src/agentwatch/cli.py` are both empty, confirming the scope boundary
(detectors untouched, no UI/CLI wiring, no `cursor_discovery.py`) held.

**Flagged, not resolved unilaterally**: the acceptance criteria's "PR
description" bullet is left unchecked above — this sprint's instructions
were explicitly local-commit-only (no push, no PR), so there is no PR body
to put the fixture-verified-only caveat in yet. That caveat text lives in
`cursor_source.py`'s module docstring instead, ready to carry forward
verbatim into a PR body whenever this branch is actually opened for review.

---

### Sprint: Sprint 6 — Aider Log Parser, Phase 2 (deferred open questions)
**Type:** feature / hardening
**Priority:** closes gaps explicitly deferred (not resolved) when Sprint 3
shipped — several materially affect correctness for real aider sessions
(resumed sessions, long-lived analytics files) even though none blocked
the original PR
**PRD Status:** original PRD (`C:\Users\Zaid\.claude\plans\
aider-log-parser-prd.md`) Open Questions section is the source for this
sprint's scope
**Harness:** PLAYBOOK standalone (no GSD/Ruflo signal)
**Board decision (2026-07-14):** scope and delegate now. Split the 5
deferred open questions by whether they're resolvable without a live
aider install (research- or design-only) vs. genuinely live-install-gated,
same honesty standard already applied to Codex CLI — don't guess silently
on the gated ones.

### Scope for this sprint
**Resolvable now (implement):**
1. **Resumed-session handling.** `.aider.chat.history.md` can contain
   multiple `# aider chat started at` headers if the user resumes aider
   against the same project. Currently the whole file is treated as one
   session. Split on each header into a separate synthetic `session_id`/
   `Action` stream per resume — this is fully determined by the documented
   format, no live install needed to implement or test.
2. **Analytics file lifecycle / session-boundary detection.** Harden
   `parse_aider_log()`'s ordinal `message_send`-to-turn pairing for the
   case where `--analytics-log` points at a long-lived file reused across
   many sessions: detect session boundaries within the analytics JSONL via
   `exit` events or large time gaps between consecutive `message_send`
   entries, and only pair events falling within the current Markdown
   session's time window (bounded below by `_parse_session_start()`'s
   timestamp) rather than blind whole-file ordinal pairing.
3. **`.aider/logs/*.log` fallback format.** Research aider's current real
   source (github.com/Aider-AI/aider) to confirm whether this
   `discovery.py::_resolve_aider_log()` fallback path is still a live
   convention and, if so, what format it's actually in. If confidently
   derivable from source without a live install (same evidentiary bar the
   original PRD held itself to for the Markdown format), add a parser
   branch; if the convention is confirmed dead, remove the dead fallback
   path rather than leaving it silently producing zero actions forever.
4. **Edit-format coverage (`whole`/`udiff`).** Research aider's real edit-
   format coder implementations (`aider/coders/*.py` in the real repo) to
   determine actual transcript rendering for the `whole` and `udiff` edit
   formats, the same way the original SEARCH/REPLACE regex was derived
   from real captured transcripts, not guessed. Extend `DIFF_BLOCK_RE` or
   add format-specific matchers only if source-derived with real
   confidence; otherwise leave explicitly flagged as still open rather
   than shipping a guessed regex.

**Explicitly still live-install-gated, not attempted this sprint:**
5. **Ordinal `message_send`-to-turn pairing under two-model edit formats
   (architect+editor) or retry-on-malformed-edit.** Cannot be confirmed
   without a real multi-turn session using a two-model format. Instead of
   leaving this silently fragile, make the mismatched-count case degrade
   *visibly*: emit a code comment and a debug-level log/warning when the
   analytics event count and turn count disagree, rather than pairing
   silently with reduced confidence and no signal to the caller.
6. **Live `agentwatch watch`/TUI tailing for Aider.** Confirmed real,
   separate feature work (block-aware incremental parser in `LogWatcher`,
   relaxing `MultiLogWatcher`'s hardcoded `.jsonl`-only filters) — stays
   out of scope, flagged as its own future sprint, not silently dropped.

### Acceptance Criteria
- [x] `.aider.chat.history.md` files with 2+ `# aider chat started at`
      headers produce 2+ distinct `session_id` values / `Action` streams,
      each internally ordinal-consistent; single-header files unaffected
      (regression test against Sprint 3's existing fixtures)
- [x] Analytics merge only pairs `message_send` events falling within the
      current session's time window when the analytics file contains
      events from multiple sessions (new fixture: one analytics JSONL
      spanning 2 synthetic sessions' worth of events, verify correct
      partitioning)
- [x] `.aider/logs/*.log` fallback: either a working parser branch backed
      by source-derived evidence, or the dead-code path removed with a
      code comment explaining why (research citation required either way,
      matching this project's existing verification standard — no
      unverified guesses)
- [x] `whole`/`udiff` edit-format coverage: either extended matcher(s)
      backed by source-derived evidence, or explicitly documented as still
      open in the PR description with the specific source files checked
      and why confidence wasn't reached
- [x] Mismatched analytics-event-count-vs-turn-count case now emits a
      visible signal (log line or equivalent), not just silent best-effort
      pairing — regression test asserts the signal fires
- [x] New/extended tests in `tests/test_aider_parser.py` covering all of
      the above; `python -m pytest tests/ -v` fully green, no regressions
      on existing Sprint 3 test cases
- [x] `ruff check .` clean on touched files
- [ ] PR description explicitly lists which of the original 5 open
      questions were resolved this sprint vs. which remain deferred (item
      5's live-install gate, item 6's live-tailing scope) — same
      no-silent-drop standard as every prior sprint on this branch. **Not
      yet applicable**: this sprint's instructions were explicitly
      local-commit-only (no push, no PR), same as Sprint 5 — there is no
      PR body to put this in yet. The caveat text lives in
      `parser/aider.py`'s module docstring and this section's status
      writeup below instead, ready to carry forward verbatim whenever this
      branch is actually opened for review.

### Implementation Plan
Engineer works items 1-4 (resolvable now) plus the visible-degradation
fix for item 5, in roughly that order per the PRD's existing "each
independently green" commit-sequence convention. Item 6 stays explicitly
unscoped. CTO reviews, including spot-checking the source citations for
items 3-4 against the real aider repo rather than trusting the research
claim at face value. QA verification pass follows.

**Status: implementation complete (2026-07-14), committed to
`chore/ci-docs-perf-windows-support` — not pushed, no PR opened, per this
sprint's explicit local-commit-only instructions.**

All 4 "resolvable now" items plus item 5's visible-degradation fix were
implemented and tested; item 6 stayed explicitly out of scope (not touched
— `parser/watcher.py`/`MultiLogWatcher` untouched by this sprint's diff).

- **Item 1 (resumed sessions):** `parser/aider.py` gained `_split_sessions()`
  (splits raw transcript text on every `# aider chat started at` header
  into per-resume segments) and `_Session`/`_parse_aider_sessions()` (each
  segment gets its own `session_id` and its own turn ordinals restarting at
  0). `parse_aider_markdown()` now flattens across sessions; a single-header
  or headerless file still produces exactly one segment, so Sprint 3's
  existing fixtures/tests pass byte-identically unchanged (verified: all
  pre-existing `TestParseSessionStart`/`TestSplitTurns`/`TestDiffBlockStyles`/
  etc. tests still pass with zero modification to their assertions).
- **Item 2 (analytics session-boundary detection):** new
  `_session_time_windows()` computes a (lower, upper) epoch-seconds window
  per session — lower-bounded by that session's own `session_start` (with a
  24h grace period on the *first* session only, to absorb the fact that a
  Markdown header's timestamp is a naive local wall-clock string while
  analytics `time` values are absolute Unix epoch seconds — this grace
  window was not just theoretical: it's what surfaced during testing that
  one of Sprint 3's own existing analytics-merge fixtures had event
  timestamps ~9 days away from its session header with no realistic
  relationship to it, which needed correcting to a temporally-sane value
  relative to that header, computed the same way the implementation does
  it, rather than an arbitrary hardcoded epoch literal), upper-bounded by
  the next session's start or a 24h fallback window for the last/only
  session. An `exit` event inside a session's window caps its upper bound
  early, per the PRD's schema notes. `parse_aider_log()` now partitions
  `message_send` events into the correct session's window before doing
  ordinal pairing within that session only — critical once item 1 makes
  turn ordinals restart per session (two sessions can both have a turn
  ordinal 0; blind whole-file ordinal pairing would incorrectly backfill
  both sessions' turn-0 actions from the same single event). New
  `TestAnalyticsSessionBoundaries` test class proves this with a
  2-session fixture where naive global ordinal pairing would produce wrong
  results but session-aware pairing produces correct, distinct per-session
  token/cost values, plus a dedicated exit-event-boundary test.
- **Item 3 (`.aider/logs/*.log` fallback) — resolved as "confirmed dead,
  removed":** researched against Aider's real current source
  (github.com/Aider-AI/aider @ main, fetched 2026-07-14). Found zero
  evidence this is a real convention: a GitHub code search across the repo
  for `.aider/logs`/`aider/logs` returns nothing; `aider/args.py`'s full CLI
  flag surface only defines `--chat-history-file` (default
  `.aider.chat.history.md`), `--llm-history-file`, `--input-history-file`,
  and `--analytics-log` — all either arbitrary user-supplied paths or the
  one confirmed Markdown default, none defaulting into a `.aider/logs/`
  directory; the docs (`options.md`, `sample.aider.conf.yml`) agree. The
  closest real reference is GitHub issue Aider-AI/aider#3574 ("Feature
  Suggestion: Better organized aider logs") — still **open and
  unimplemented**, and it proposes a *different* directory name
  (`.ai-chats/`) as a third-party wrapper, not anything Aider itself
  writes. Given this — not just "unconfirmed" but actively contradicted by
  the full flag surface, docs, and an open feature request for something
  similar under a different name — the dead `.aider/logs/` fallback branch
  in `discovery.py::_resolve_aider_log()` was removed rather than left
  producing zero actions forever, with a code comment citing exactly what
  was checked and a note on how to re-add it if a real convention like
  this is ever confirmed later.
- **Item 4 (`whole`/`udiff` edit formats) — resolved, both implemented:**
  researched directly against `aider/coders/wholefile_coder.py` +
  `wholefile_prompts.py` and `aider/coders/udiff_coder.py` +
  `udiff_prompts.py` in the real repo. Both formats' transcript shapes were
  confirmed with high confidence — doubly verified against both the
  coder's own round-trip parsing logic (which has to parse this shape back
  out of real LLM output) and the prompt's literal `example_messages` text,
  which agree. New `UDIFF_BLOCK_RE` (reserved ` ```diff ` fence + `---`/
  `+++` header pair + `@@ ... @@` hunks) and `WHOLE_FILE_BLOCK_RE` (filename
  line + fence + full raw file content, no internal marker) added, plus
  `_extract_edit_blocks()` to dispatch across all three formats
  (`diff`/`udiff`/`whole`) per turn without double-counting a block that
  matches more than one matcher's shape. **Known, documented limitation**:
  `whole` format has no internal marker distinguishing a real edit block
  from an ordinary illustrative code sample the assistant might show for
  an unrelated reason — this is a real, source-confirmed structural fact
  about the format (Aider's own coder has the identical ambiguity re-parsing
  its own model's output), not a gap in this regex, and is documented as
  such directly in `WHOLE_FILE_BLOCK_RE`'s docstring rather than hidden.
  New `TestWholeFileEditFormat`/`TestUdiffEditFormat` test classes, kept
  clearly separate from the SEARCH/REPLACE/ORIGINAL-UPDATED cases, cover
  both formats plus non-double-classification in both directions (a
  diff-marker block isn't also picked up as `whole`; a udiff block isn't
  swallowed by the generic `whole` matcher).
- **Item 5 (visible degradation) — resolved:** `parse_aider_log()` now logs
  a `WARNING`-level line via a module-level `logging.getLogger(__name__)`
  (no pre-existing logging convention was found elsewhere in the codebase
  to match — `grep`'d for `logging.getLogger`/`import logging` across
  `src/agentwatch`, zero hits — so this establishes one, following the
  standard-library idiom) whenever a session's turn count and
  in-window `message_send` event count disagree, stating both counts and
  the session_id. The actual pairing behavior is unchanged (still `zip()`'s
  shortest-wins) — this is visibility only, not a fix, per the item's
  explicit scope. `TestMismatchLogging` asserts both that the warning fires
  on mismatch (via `caplog`) and that it does *not* fire when counts match.
- **Item 6 (live tailing):** confirmed untouched — `git diff --stat --
  src/agentwatch/parser/watcher.py` is empty for this sprint's diff.

**Verification:** `python -m pytest tests/ -v` — **483/483 pass**, zero
regressions (41/41 in `test_aider_parser.py` specifically, up from 26
before this sprint). `ruff check` clean on all 3 touched files
(`parser/aider.py`, `discovery.py`, `tests/test_aider_parser.py`);
repo-wide `ruff check .` is **590 errors — unchanged from the documented
pre-existing baseline**, confirming zero new warnings anywhere.

**One real bug found and fixed during testing, not just research-time
uncertainty**: `UDIFF_BLOCK_RE`'s first draft used `\S.*` (unbounded,
under `re.DOTALL`) for the `a_path`/`b_path` capture groups, which
greedily swallowed the entire hunk body (including newlines) into the
path capture before backtracking — caught by
`TestUdiffEditFormat::test_udiff_block_matches` actually asserting the
real filename value rather than just "a match happened," and fixed by
switching to `\S[^\n]*` (matching the same style already used for
`DIFF_BLOCK_RE`'s `filename` group), which cannot cross a newline
regardless of the `DOTALL` flag.

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

---

### Sprint: Sprint 7 — Cursor Support, Phase 2 (discovery + CLI/TUI wiring)
**Type:** feature
**Priority:** unblocks Cursor end-to-end — Phase 1 (`CursorWatcher` +
`cursor_source.py`, Sprint 5) built the read/poll layer but nothing ever
called it: no discovery mechanism existed, so `agentwatch ps`/`watch-all`/
`check` never surfaced a Cursor conversation even on a machine with a real,
active one.
**PRD Status:** no separate PRD; scoped directly from Sprint 5's own
explicit "out of scope, Phase 2" callout and this section's acceptance
criteria.
**Board decision (2026-07-14):** user authorized implementing all
remaining roadmap items (Cursor Phase 2, Aider live-tailing, Codex
hardening) in one continuous pass, testing each live as it lands. Two
product decisions Sprint 5 had explicitly deferred were resolved directly
with the user rather than picked unilaterally: (1) gate Cursor discovery on
`Cursor.exe` actually running (matches every other agent type, rather than
surfacing stale composer data from a closed IDE); (2) for Codex/Aider items
explicitly gated on a live install that still doesn't exist, do best-effort
work against real primary sources and flag clearly rather than skip
entirely.

### Acceptance Criteria
- [x] New `src/agentwatch/cursor_discovery.py`: `is_cursor_running()`
      (psutil name match, mirrors every other agent's process-gate
      philosophy), `default_cursor_user_dir()` (Windows path verified
      against this machine's real install; macOS/Linux follow the standard
      VS Code fork convention but are unverified), `build_workspace_map()`
      (decodes `workspaceStorage/<id>/workspace.json`'s `folder` file URI —
      verified against this machine's 2 real populated workspace entries),
      `find_cursor_agents()` returning synthetic `AgentProcess` entries for
      qualifying composers
- [x] `AgentProcess` gains a `cursor_db_path` field; `log_file` becomes a
      synthetic, never-created-on-disk per-composer identity key for Cursor
      entries (`cursor_discovery.py::_cursor_synthetic_log_key`) since
      `MultiLogWatcher` keys its tracking dicts by `log_file` and every
      composer in one install shares one real `state.vscdb`
- [x] `CursorWatcher` gains `composer_id_filter` so multiple independent
      watcher instances (one per composer, sharing one DB) don't duplicate
      each other's actions
- [x] `discovery.py::find_running_agents()` merges in
      `cursor_discovery.find_cursor_agents()` after the real-process scan
      (lazy import, mirrors the `logs.py`↔`codex.py` circular-import
      pattern), wrapped so a Cursor-specific failure never breaks discovery
      of real Claude Code/Aider/Codex processes
- [x] `MultiLogWatcher` (`_find_all_logs`/`from_processes`/
      `refresh_processes`/`watch()`) recognizes cursor entries by
      `agent_type` (not suffix) and constructs a real `CursorWatcher`
      against `cursor_db_path`, filtered to that entry's composer —
      exercised by both `agentwatch ps` and `agentwatch watch-all`
- [x] `parser/logs.py::parse_file()` dispatches `.vscdb` paths to a new
      `cursor_source.parse_cursor_session()` (auto-picks the most-recently-
      active agent-mode composer when no `session_id` filter is given,
      mirroring `find_latest_session()`'s auto-detect semantics) — wires
      `agentwatch check`/`security-scan --log <state.vscdb>` end to end
- [x] New tests: `test_cursor_discovery.py`, extended
      `test_cursor_source.py`/`test_cursor_watcher.py`, new
      `test_multi_log_watcher_cursor.py`, new `TestFindRunningAgentsCursorMerge`
      in `test_discovery.py`, new `.vscdb` cases in
      `test_aider_parser.py::TestParseFileDispatch`
- [x] `python -m pytest tests/ -v` fully green, `ruff check` clean on all
      new/touched files
- [x] **Live smoke test against this machine's real Cursor install** (not
      just fixtures) — see Status below

### Implementation Plan
Engineer builds `cursor_discovery.py` against the real
`workspaceStorage`/`composerHeaders` schema (already confirmed in Sprint
5's investigation rounds), wires it into `find_running_agents()`,
`MultiLogWatcher`, and `parse_file()`, adds fixture-based tests, then runs
the actual CLI against this machine's real, populated Cursor install
(the same one every prior Cursor investigation round used) for a genuine
end-to-end check, not just unit tests.

**Status: complete, live-tested (2026-07-14).**

**Real bug found and fixed via live testing, not just research**: Cursor
creates a placeholder composer (literal id `"empty-state-draft"`,
`isDraft: true`) with a real `lastUpdatedAt` newer than an actual
conversation but zero bubbles. Without filtering it out, both
`find_cursor_agents()` and `cursor_source.select_latest_agent_composer()`
would surface/auto-pick this phantom empty "agent" ahead of the real one —
caught because `agentwatch check --log <real state.vscdb>` returned 0
actions on the first live run, not because it was anticipated. Fixed by
excluding `isDraft` composers in both places, covered by new regression
tests in each.

**Full live verification, both with Cursor closed and running**:
- `check`/`security-scan --log <real state.vscdb>` (Cursor closed, no
  process gate needed for the one-shot path): correctly parsed a real
  58-bubble agentwatch-main conversation, produced a real health report
  (89% PRODUCTIVE) and a real security scan (100%, 0 issues)
- `agentwatch ps` with Cursor closed: 0 cursor entries (gate correctly
  excludes it), no crash
- With Cursor opened live on this machine: `is_cursor_running()` correctly
  flips to `True`; `find_cursor_agents()` and `agentwatch ps --json` both
  correctly surface the one real agent-mode composer with correct
  workspace/session/uptime; a direct drive of
  `MultiLogWatcher.from_processes(find_running_agents())` (the same
  machinery `watch-all` uses) confirmed a real `CursorWatcher` instance
  gets constructed for it alongside the real Claude Code session watcher

**Known limitation found live, fixed in a follow-up session (2026-07-14,
same day)**: `detectors/health/loops.py::LoopDetector` keys repetition on
`f"{tool_name}:{file_path}"`. Every Cursor turn's `tool_name` is the
literal constant `"user_message"`/`"assistant_message"` (unlike Claude
Code/Aider/Codex, where it reflects the actual tool invoked) — so any
Cursor conversation with >=4 turns in the detector's 10-action window
tripped a "loop" false positive purely from the constant role label. Real
example seen live in the 89% report above. Fixed via a detector-side
carve-out (the option identified but not yet chosen at the time this note
was originally written): a new shared `NON_TOOL_ROLE_LABELS` sentinel set
in `parser/models.py` (`{"user_message", "assistant_message",
"unknown_bubble"}`), excluded from `LoopDetector`'s repetition tally.
`RereadDetector`/`ThrashDetector` key on `file_path` directly, not
`tool_name`, so they were never affected and needed no change. Richer
per-turn `tool_name` from `toolResults` remains unconfirmed/unpursued —
the carve-out doesn't depend on it. Covered by `tests/test_loops.py`
(536/536 tests passing repo-wide after this fix, up from 532).

**Explicitly out of scope, not attempted**: single-agent `agentwatch watch
--log <state.vscdb>` (live TUI) — Cursor's poll-based, composer-picking
data model doesn't fit `AgentWatchApp`'s current single-`LogWatcher`
assumption the way it fits `MultiLogWatcher`'s per-agent-process model;
`--all-logs` directory-scan mode (Cursor has no fixed discoverable
directory of per-session files to glob).

`python -m pytest tests/ -v` — **530/530 pass** after this sprint's Cursor
work (up from 483 baseline); `ruff check` clean on all new/touched files;
repo-wide `ruff check .` **589 errors, down from 590** — zero new
warnings, one pre-existing one incidentally fixed.

---

### Sprint: Sprint 7 (cont'd) — Aider Phase 3 (live watch/TUI tailing)
**Type:** feature
**Priority:** closes PLAYBOOK Sprint 6 item 6, the one item explicitly
deferred as "confirmed real, separate feature work" rather than resolved —
`agentwatch watch`/`watch-all` silently produced zero actions for a live
Aider session because `LogWatcher`'s byte-offset JSONL tailing can't parse
Markdown, and `MultiLogWatcher._find_all_logs()` hardcoded a `.jsonl`-only
filter that excluded `.aider.chat.history.md` from process-mode discovery
entirely.
**PRD Status:** no separate PRD; scope is exactly Sprint 6 item 6's own
description (`C:\Users\Zaid\.claude\plans\aider-log-parser-prd.md`'s
lineage).
**Board decision:** same continuous-pass authorization as Sprint 7's Cursor
half above.

### Acceptance Criteria
- [x] New `AiderLogWatcher` (`parser/watcher.py`): reparses the whole file
      via `aider.py`'s existing `parse_aider_sessions()` (renamed from
      `_parse_aider_sessions` — the same code already used by
      `parse_aider_markdown()`/`parse_aider_log()`, not new parsing logic)
      on every `watchfiles.awatch` file-change trigger (same signal
      `LogWatcher` uses — Aider's Markdown file is a real append-only file,
      unlike Cursor's rewritten-in-place SQLite DB), emitting only each
      session's new action-count tail — the same "count, not content-diff"
      cursor idiom `CursorWatcher._bubble_cursor` already established
- [x] `MultiLogWatcher._find_all_logs()` recognizes `.md` alongside
      `.jsonl` in process mode; `watch()` constructs an `AiderLogWatcher`
      (not a `LogWatcher`, which would silently produce zero actions) for
      `.md` entries
- [x] Single-agent `ui/app.py::AgentWatchApp` also dispatches `.md` to
      `AiderLogWatcher` — Sprint 6 item 6's own wording named both
      `agentwatch watch` and `watch-all`/TUI, not just the multi-agent path
- [x] `cli.py`'s `watch` command `--log` help text updated to mention Aider
      Markdown (matches `check`/`security-scan`'s existing wording)
- [x] New tests: `test_aider_watcher.py` (incremental-cursor behavior
      driven directly, plus one real async test growing a real file on
      disk), `test_multi_log_watcher_aider.py` (dispatch wiring)
- [x] `python -m pytest tests/ -v` fully green, `ruff check` clean on all
      new/touched files
- [x] **Live smoke test against a real growing file** — see Status below

### Implementation Plan
Engineer renames `aider.py`'s private `_parse_aider_sessions`/`_Session` to
public `parse_aider_sessions`/`AiderSession` (needed for cross-module reuse
from `watcher.py`, zero behavior change), builds `AiderLogWatcher` against
it, wires `MultiLogWatcher` and `AgentWatchApp`, adds tests, then drives a
real file being appended to on disk while a live watcher is running against
it.

**Status: complete, live-tested (2026-07-14).**

Live smoke test: wrote a real `.aider.chat.history.md` fixture to disk,
started `AiderLogWatcher.watch()` against it, confirmed the 2 existing
actions (prompt + edit) were emitted immediately, then appended a brand
new `#### ` turn to the file mid-run and confirmed the watcher picked it up
via the real `watchfiles.awatch` file-change signal and emitted exactly the
one new action — no duplicates, no missed content. Separately confirmed
(via a headless Textual pilot run of the real `AgentWatchApp`) that a
`.md` log path correctly constructs an `AiderLogWatcher` (not a
`LogWatcher`) and the app renders without crashing.

**Known limitation, documented not fixed (matches the same bar as Sprint 6
item 5's `zip()`-shortest-wins caveat)**: an `aider_prompt` action is
emitted as soon as its `#### ` header line appears, using whatever body
content has been written so far — a poll mid-write could see an
incomplete snapshot that is never re-emitted once counted. Edit-block
actions are unaffected (their regexes require a closing marker, so an
in-progress block simply doesn't match yet and appears complete once it
does). Analytics-log (`--analytics-log`) backfill is deliberately not
wired into live tailing — it's a whole-file/whole-session operation with
no obvious incremental equivalent; live-tailed actions keep
`tokens_in`/`tokens_out`/`cost_usd` at their Markdown-only 0/0/0.0
defaults.

**Known pre-existing harness quirk, not a regression**: a headless Textual
`run_test()` pilot's background `run_worker()` task doesn't populate
`app._buffer` within the test even after several seconds of `pilot.pause()`
+ `asyncio.sleep()` — confirmed this is identical for the pre-existing
JSONL/`LogWatcher` path too (not something this sprint introduced), so the
live-tailing correctness claim above rests on the direct
`AiderLogWatcher.watch()` drive, not the pilot-buffer assertion.

`python -m pytest tests/ -v` — **530/530 pass**; `ruff check` clean on all
new/touched files (`ui/app.py`'s pre-existing 37-error baseline actually
*decreased* to 36, one incidental whitespace fix); repo-wide unchanged.

---

### Sprint 8 — Codex CLI: primary-source hardening (no live install)
**Type:** hardening / research
**Priority:** Codex CLI support (Sprint 4) has been fixture-verified-only
since it shipped, with 7 open questions explicitly gated on a live install
that still doesn't exist on this or any available machine. Rather than
leave it untouched again, this sprint tried a different evidentiary path:
the real `openai/codex` source is a public GitHub repo and can be read
directly, even without installing/running the CLI itself.
**PRD Status:** no new PRD; scoped directly against
`codex-cli-support-prd.md`'s existing "Open Questions / Requires Live
Install to Confirm" list.
**Board decision:** user explicitly authorized "best-effort fixture work,
clearly flagged" for exactly this kind of live-install-gated item, same
continuous-pass authorization as the rest of this batch.

### What this sprint actually did
Fetched `codex-rs/protocol/src/protocol.rs` and `models.rs` directly from
`github.com/openai/codex` @ `main` (public repo, no auth, no install
needed) and read the real struct/enum definitions rather than relying on
secondary sources (issue trackers, community viewer tools) the way the
original Sprint 4 research had to. This is still **not** a live-captured
real rollout file — it's the current source, which the project's own prior
research already flagged as having changed shape multiple times across
versions — but it's a direct, primary-source upgrade over guessing for
several specific open questions.

**Open Question #1 (payload nesting) — RESOLVED, high confidence.**
`RolloutLine { timestamp, ordinal, #[serde(flatten)] item: RolloutItem }`,
`RolloutItem` is `#[serde(tag = "type", content = "payload")]`. Confirms
the two-level `{"type": ..., "payload": {...}}` nesting this parser always
assumed, read directly from the struct definition, not inferred. Bonus
finding: every rollout line also carries a real `ordinal: Option<u64>`
field, not previously documented anywhere in this project's research
(not extracted — low priority, timestamps already order actions).

**`_CODEX_EVENT_TYPES` (`logs.py`) — extended with real evidence.** The
real `RolloutItem` enum has 8 variants, not the originally-researched 4:
added `compacted`, `world_state`, `inter_agent_communication`,
`inter_agent_communication_metadata` (the latter two: a multi-agent
feature not previously known about at all).

**`_extract_function_call_output` (`codex.py`) — corrected, real bug
fixed.** `FunctionCallOutputPayload`'s actual `Deserialize` impl hardcodes
`success: None` and its wire shape is only ever a plain string or a
content-item array — never an object with `success`/`error` keys. The
previous `isinstance(output, dict)` check was checking a shape that cannot
occur on the wire — **confirmed dead code, not just unconfirmed** — meaning
every real Codex tool call was being classified as successful regardless
of actual outcome. Now honestly returns `is_error=False` (there is nothing
on this event to detect failure from) rather than a guessed heuristic.

**`_extract_token_count` (`codex.py`) — corrected, real bug fixed, Open
Question #6 resolved.** Real shape is `{"type": "token_count", "info":
{"total_token_usage": {...}, "last_token_usage": {...},
"model_context_window": ...}}` — token fields are nested two levels
deeper than the old flat `payload.get("input_tokens")` guess (which always
fell through to 0), and real field names are `input_tokens`/
`cached_input_tokens`/`output_tokens`/`reasoning_output_tokens`/
`total_tokens`, not `prompt_tokens`/`completion_tokens`. Open Question #6
("delta vs. cumulative?") turned out not to be ambiguous at all — both
exist as separate fields (`last_token_usage` = delta, `total_token_usage`
= cumulative). Now reads `last_token_usage` into `Action.tokens_in`/
`tokens_out`, matching every other parser's per-action-delta semantics.

**Major new finding, NOT implemented (documented, not silently
dropped)**: the real success/failure signal for exec-type tool calls is a
separate `event_msg` event, `ExecCommandEnd` — correlatable by the same
`call_id` as the `FunctionCall`, carrying real `exit_code: i32` and
`status: Completed | Failed | Declined`, plus real `stdout`/`stderr`/
`formatted_output`. Wiring this in means correlating a SECOND independent
event family into `CodexParser`'s existing single-pending-dict model — a
real architectural change, and genuine open questions remain even with
source access (does `exec_command_end` always co-occur with
`function_call_output` for the same call; what carries success for
`apply_patch`/MCP tool calls). Recommended as a well-scoped next sprint.

**Still genuinely unconfirmed, unchanged from Sprint 4**: Open Question #2
(`CODEX_HOME` comma-separated multi-root), #3 (real tool names beyond
`apply_patch` for `classify_codex_tool`), #5 (no PID-based log resolution
equivalent to `lsof`).

### Acceptance Criteria
- [x] Every corrected assumption cites the specific source file/struct
      read, not a re-guess — see docstrings in `codex.py`/`logs.py`
- [x] Existing fixture-based tests updated to the corrected real shapes
      (not just made to pass) — `test_codex_parser.py`'s
      `function_call_output`/`token_count` fixture lines rebuilt to match
      the real wire shape; the test that asserted the old (now-confirmed-
      impossible) `{"success": false}` shape was replaced with one
      asserting the corrected, honest behavior
- [x] New regression tests for the `_CODEX_EVENT_TYPES` extension and
      `_extract_token_count`'s defensive handling of a missing `info` key
- [x] `python -m pytest tests/ -v` fully green, `ruff check` clean on all
      touched files
- [x] Still explicitly NOT claimed production-ready: module docstring
      updated to state plainly that this remains fixture-based, and that 3
      of the original 7 open questions plus 1 new one (ExecCommandEnd
      correlation) remain open

### Implementation Plan
Fetch real source directly (`curl` against `raw.githubusercontent.com`,
public repo, no auth), grep for the relevant struct/enum definitions,
cross-check every extraction function in `codex.py` against what was
actually found, fix what's confirmed wrong, document what's confirmed
right, and clearly scope what's newly discovered but not yet implemented.

**Status: complete (2026-07-14).** `python -m pytest tests/ -v` —
**532/532 pass**; `ruff check` clean on `codex.py`/`logs.py`/
`test_codex_parser.py`; repo-wide `ruff check .` **589 errors — unchanged**
from the post-Sprint-7 baseline, zero new warnings anywhere.

---

### Sprint 9 — Task #9 follow-up: non-emoji punctuation missed by the
ascii-theme audit
**Type:** bugfix
**Priority:** small, self-contained correctness gap in an already-shipped
fix (Task #9), found while resuming this branch — a stray uncommitted edit
in `cli.py` (extracting `_print_burn_report`'s `×` literal to a local
variable, no behavior change yet) turned out to be a real, unfinished bug
fix rather than a discardable scratch edit.
**PRD Status:** not needed — same bug class and same fix mechanism
(`themes.ascii_safe()`) as Task #9, scoped directly against what that
task's own test file (`test_theme_emoji_wiring.py`) documented as
deliberately out of scope.

### What this sprint found
Task #9's `test_theme_emoji_wiring.py` module docstring claimed the
`→`-style arrows used throughout `cli.py` "render fine via the legacy
CP437 codepage even where emoji doesn't," lumping them in with the
box-drawing characters (`═`/`╔`/`╗`/`╚`/`╝`) that genuinely are CP437-safe
and so were correctly left alone. That claim was never actually verified
and is wrong: `"→".encode("cp437")` raises `UnicodeEncodeError`, and so do
`•` (bullet) and `…` (ellipsis) — none of the three have CP437 coverage,
unlike box-drawing, which was purpose-built for DOS-era UI. These three
were hardcoded (not `ascii_safe()`-wired) at several call sites the
original emoji-range grep never would have caught, since none of them are
in the emoji Unicode blocks: `cli.py`'s per-warning detail arrow (used by
both `check` and `security-scan`), `list-detectors`' bullet, `themes`'
legend separator, `stats --burn`'s "×N" trivial-command counts
(`_print_burn_report`), and three TUI widgets' "waiting for data…" /
"loading…" placeholders and detail arrows (`ui/app.py`'s `EfficiencyBar`
and `WarningsList`, `ui/rot_widget.py`'s `ContextHealthWidget`).

**Deliberately left alone, same reasoning as `--help` text and box-drawing
before it**: em-dashes (`—`) embedded in prose — `--help` option
descriptions, `stats --burn`'s verdict sentences, and detector-supplied
`description`/`message` strings (e.g. `loops.py`'s "Repeated
edit→test→fail cycle", which also contains an arrow). These are content
strings, not one-off UI decoration, so they don't fit `ascii_safe()`'s
"generic glyph with no natural theme home" model — fixing them would mean
rewriting prose across every detector and every `--help` string, a much
larger and separate concern, consistent with how Task #9 itself scoped
out box-drawing rather than silently pulling it in.

### Acceptance Criteria
- [x] All 8 identified call sites wired through `themes.ascii_safe()`,
      matching the existing `💡`/`📄` pattern exactly
- [x] `test_theme_emoji_wiring.py` module docstring corrected (the
      "arrows render fine via CP437" claim was false — see above) and a
      new `TestNonEmojiPunctuationAsciiSafe` class added (9 new tests:
      CLI-runner-level for `list-detectors`/`themes`/`stats --burn`,
      widget-level for the three TUI placeholders), each with a paired
      default-theme test proving nothing was silently ASCII-ified
- [x] `list-detectors`' test scoped to just the bullet, not a blanket
      "no arrows anywhere" — some detectors' own description text uses
      `→` as prose punctuation, which is registry content, not decoration,
      and correctly out of scope (documented in the test itself)
- [x] `python -m pytest tests/ -v` fully green — **544/544 pass** (536
      baseline + 8 new; one of the 9 new tests reuses an existing
      CliRunner invocation)
- [x] `ruff check` clean on all 4 touched files; repo-wide `ruff check .`
      **585 errors — down from 589**, zero new warnings
- [x] Live-verified: `python -m agentwatch.cli --theme ascii list-detectors`
      and `--theme ascii themes` both confirmed to render `*`/`->` in
      place of `•`/`→` in real command output, not just under test

### Implementation Plan
Finish the stray uncommitted edit (the `×` extraction was correct
groundwork, just not wired to `ascii_safe()` yet), then grep the whole
`src/agentwatch` tree for any character that survives a `str.encode(
"cp437")` check outside comments/docstrings to find the rest of this bug
class, triage each hit into "decorative glyph → fix" vs. "prose content →
leave, document why," and extend the existing Task #9 test file rather
than starting a new one.

**Status: complete (2026-07-14).**
