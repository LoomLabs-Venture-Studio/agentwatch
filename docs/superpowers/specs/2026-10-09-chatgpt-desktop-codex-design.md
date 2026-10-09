# ChatGPT Desktop (Codex view) Discovery — Design

**Date:** 2026-10-09
**Branch:** `feature/chatgpt-desktop-adapter` (from `develop` @ `6525672`)
**Issue:** #74

## Goal

Make `agentwatch ps` / `watch-all` / `check` show Codex sessions run from the
unified ChatGPT desktop app correctly, with the smallest change to the
existing Codex path. No new adapter, no new module.

## Findings

- The ChatGPT desktop app (Store package `OpenAI.Codex`, main exe
  `ChatGPT.exe`) runs Codex through a bundled
  `%LOCALAPPDATA%\OpenAI\Codex\bin\<hash>\codex.exe`, launched by
  `ChatGPT.exe` with `app-server` args. It is the same binary family as the
  Codex CLI (`codex-cli 0.162.0-alpha`).
- It writes the same rollouts as the CLI:
  `$CODEX_HOME` (or `~/.codex`) `/sessions/YYYY/MM/DD/rollout-<ts>-<id>.jsonl`
  (openai/codex `codex-rs/rollout/src/recorder.rs:1739-1761`,
  `codex-rs/rollout/src/lib.rs:86-87`; the app's `app.asar` resolves
  `CODEX_HOME ?? ~/.codex`).
- One app-server process serves every thread; each thread has its own cwd.
  Its `session_meta` has `originator: "Codex Desktop"`.
- The existing Codex process pattern (`agents/codex.py`) already matches that
  `codex.exe`, so `agentwatch ps` lists it as `codex`. Log resolution already
  works (cwd match fails, then falls back to the newest rollout in the
  today/yesterday buckets).

Two real bugs:

1. The process cwd is the `bin\<hash>` directory, so `ps` shows
   `PROJECT=<hash>` and `working_directory` is wrong.
2. `_find_open_codex_rollout` returns the *first* open rollout; an
   app-server can have several open at once.

## Change (`discovery.py` only)

1. `_find_open_codex_rollout`: among the matching open rollouts, return the
   most recently modified one (a stat error skips that file).
2. In `find_running_agents`, after a Codex log is resolved, use its
   `session_meta.cwd` (via `_read_codex_session_meta`) as
   `working_directory`. Applied to every Codex process, CLI included: for
   the CLI the meta cwd equals the process cwd, so one rule is simpler than
   detecting the desktop app. Missing/invalid meta keeps the process cwd;
   nothing raises. The corrected cwd is written back into
   `DiscoveryCache.cwd_by_pid` so cached scans report the same value.

## Tests (synthetic fixtures in `tmp_path` only)

- Newest of several open rollouts is chosen.
- Meta cwd overrides process cwd in `find_running_agents`, and stays
  corrected on a cached second scan.
- Missing meta cwd keeps the process cwd.
- Existing Codex discovery tests still pass.

## Verification plan

- Full pytest suite + `ruff check .` green.
- Read-only live sanity: `agentwatch ps` with a ChatGPT app-server running
  and no rollout yet must list it without crashing.
- Board live check (not possible here, needs a signed-in app): run one Codex
  task in the ChatGPT desktop app, then `agentwatch ps` should show the
  task's project (not the hash dir) and a `rollout-*.jsonl` log;
  `agentwatch check --log <that rollout>` should parse it.

## Out of scope

- Chat/Work views: server-side, nothing parseable locally.
- One entry per thread for concurrent threads (the app-server is one PID;
  we show its most recently active rollout).
- WSL mode (rollouts live inside the distro).
- `.jsonl.zst` compressed cold rollouts.
- `claude-cowork-transcript-imports/`.
- The desktop diagnostic logs / `logs_2.sqlite`.
