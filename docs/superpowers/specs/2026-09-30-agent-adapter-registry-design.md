# Agent Adapter Registry — Design (Sub-project 0 of `feature/cli-agents`)

**Date:** 2026-09-30
**Branch:** `feature/cli-agents` (from `develop` @ `45e19ce`)
**Status:** Approved design, pending spec review

## Context

`feature/cli-agents` will add support for four more coding agents: Gemini CLI,
GitHub Copilot CLI, opencode, and Cline/Roo/Kilo (VS Code extensions). Today
agentwatch supports Claude Code, Codex, Aider and Cursor, but agent-specific
behaviour is spread across five dispatch sites as hardcoded tables and
`if agent_type == ...` / file-suffix branches:

1. `discovery.py` — `AGENT_PATTERNS` dict + `if/elif` log-resolver chain in
   `find_running_agents`.
2. `cursor_discovery.py` — separate discovery path for the editor-based agent.
3. `parser/watcher.py` — `_has_live_log` (cursor special case),
   `MultiLogWatcher._find_all_logs` (`.jsonl`/`.md`/cursor filter),
   and watcher construction in `MultiLogWatcher.watch`.
4. `ui/app.py` — single-agent TUI picks `LogWatcher` / `AiderLogWatcher` /
   `CursorWatcher` by path.
5. `parser/logs.py` — `detect_log_format` + `parse_file` for one-shot
   commands (`check`, `security-scan`).

Adding each new agent under this structure means edits to all five sites.
Sub-project 0 replaces that with a registry of per-agent adapters so every
later agent is one module + fixtures + one registry line.

Sub-projects 1–4 (Gemini, Copilot, opencode, Cline/Roo/Kilo) each get their
own spec/plan/PR, built from real captured session logs.

## Goals

- One place per agent that owns: process detection, log location, parsing,
  watcher construction, liveness.
- Core modules (discovery, watchers, TUI, one-shot parse) dispatch through the
  registry instead of naming agents.
- **Zero behaviour change** for the four existing agents.

## Non-goals

- No new agents in this sub-project.
- No changes to parsers' parsing logic, detectors, or scoring.
- No external/entry-point plugin system.
- No CLI, TUI or JSON output changes.

## Design

### 1. Adapter interface — `src/agentwatch/agents/base.py`

```python
class Watcher(Protocol):
    def watch(self) -> AsyncIterator[Action]: ...

class AgentAdapter(Protocol):
    name: str                          # "claude-code", "codex", "aider", "cursor"
    kind: Literal["process", "editor"]

    # kind == "process": identify the OS process and its log
    process_pattern: str | None        # regex against process name/cmdline
    process_exclude: str | None
    def resolve_log(self, cwd: Path, pid: int | None) -> tuple[Path | None, str | None]: ...

    # kind == "editor": adapter performs its own discovery
    def discover(self) -> list[AgentProcess]: ...

    def claims(self, path: Path) -> bool: ...
    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher: ...
    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]: ...   # opts: e.g. analytics_log for Aider
    def is_live(self, proc: AgentProcess) -> bool: ...
```

A small `BaseAdapter` class supplies defaults: `discover()` returns `[]`,
`is_live()` returns `proc.log_file is not None and proc.log_file.exists()`,
`resolve_log()` returns `(None, None)`.

Existing `LogWatcher`, `AiderLogWatcher`, `CursorWatcher` already satisfy
`Watcher`; they are not modified.

### 2. Registry — `src/agentwatch/agents/__init__.py`

- `ADAPTERS: list[AgentAdapter]` — ordered: claude-code, aider, codex, cursor (preserves historical `AGENT_PATTERNS` first-match-wins process-matching order; see "Ordering is load-bearing" below for how the same order affects `claims()`).
- `get(name: str) -> AgentAdapter | None`.
- `adapter_for(path: Path) -> AgentAdapter | None` — first adapter whose
  `claims(path)` is true.
- `process_adapters()` / `editor_adapters()` — filtered views.

**Ordering is load-bearing.** Registry order drives two things: process matching
(first match wins per PID) and `adapter_for` (first adapter whose `claims()` is
true). Claude Code's `claims()` is the JSONL catch-all: it claims any `.jsonl`
that is not sniffed as Codex (including `unknown` and Moltbot sniffs), matching
today's `detect_log_format` fallback. Moltbot remains a format handled inside the
Claude Code/JSONL path (it is not a discoverable agent). Consequently an adapter
for a new JSONL-logging agent appended after claude-code is never reached via
`adapter_for`. It must either be inserted BEFORE claude-code (safe only if its
process pattern does not overlap claude-code/aider/codex, since process matching
is first-match-wins in the same order), or claude-code's `claims()` must be
narrowed. Which to do is decided in that sub-project against real captured logs.

`claims()` for JSONL agents reuses `detect_log_format` on the first non-skip
entry; Aider claims `.md` transcripts; Cursor claims `state.vscdb` / its
synthetic key.

### 3. Adapters — `src/agentwatch/agents/{claude_code,codex,aider,cursor}.py`

Thin wrappers that call existing functions; no parsing logic moves or
changes:

| Adapter | resolve_log / discover | make_watcher | parse_file |
|---|---|---|---|
| claude-code | `discovery._resolve_claude_code_log` | `LogWatcher` | existing JSONL branch of `logs.parse_file` |
| codex | `discovery._resolve_codex_log` | `LogWatcher` | existing JSONL branch of `logs.parse_file` |
| aider | `discovery._resolve_aider_log` | `AiderLogWatcher` | `aider.parse_aider_log(path, analytics_path=opts["analytics_log"])` + session filter |
| cursor | `cursor_discovery.find_cursor_agents` | `CursorWatcher` | `cursor_source.parse_cursor_session(path, composer_id=session_id)` |

`logs.parse_file(path, session_id, analytics_log)` keeps its exact signature
and generator semantics; internally the `.md` / `.vscdb` suffix branches are
replaced by `adapter_for(path).parse_file(...)`, with the JSONL branch
remaining the body that the claude-code/codex adapters call.

Process patterns and excludes are copied verbatim from `AGENT_PATTERNS`.

### 4. Dispatch-site rewiring

- `discovery.find_running_agents`: iterate `process_adapters()`; replace the
  `if/elif` resolver chain with `adapter.resolve_log(cwd, pid)`.
  `AGENT_PATTERNS` stays as a derived, read-only mapping built from the
  registry (back-compat for any importer).
- `watcher._has_live_log`: `get(proc.agent_type).is_live(proc)`.
- `MultiLogWatcher._find_all_logs` (process mode): include an entry when its
  agent's adapter exists and the process isn't stopped — no suffix checks.
- `MultiLogWatcher.watch`: `adapter.make_watcher(proc or path, sid)`;
  path-mode (no proc) falls back to `adapter_for(path)`, then `LogWatcher`.
- `ui/app.py`: resolve adapter via `adapter_for(log_path)` (or explicit agent
  type when known) and call `make_watcher`.
- `logs.parse_file`: see table note above; unclaimed paths fall through to
  the JSONL branch exactly as today.

All existing public import paths (`agentwatch.parser.*`,
`agentwatch.discovery.*`) keep working.

### 5. Error handling

Behaviour matches today:
- Unknown `agent_type` / no claiming adapter → fall back to current default
  (`LogWatcher` for JSONL paths; entry skipped in process mode). Never raise.
- Adapter `resolve_log` / `discover` exceptions are caught per-adapter and
  logged at debug level so one broken agent can't take down discovery for
  the others (discovery today already swallows per-process errors).

## Testing & Acceptance Criteria

1. Full suite passes on Windows: **794 passed, 1 skipped**, with **no edits to
   any existing test file**.
2. New `tests/test_agent_registry.py` covers:
   - all four adapters registered, in the documented order;
   - process patterns/excludes identical to the old `AGENT_PATTERNS`;
   - `adapter_for` precedence (Claude Code JSONL vs Codex JSONL vs Aider `.md`
     vs Cursor) using existing fixtures;
   - `is_live` for a process agent and for Cursor;
   - **extensibility:** a fake adapter registered only in the test is
     discovered (monkeypatched process list), watched via `MultiLogWatcher`,
     and parsed via one-shot `parse_file` — without editing any core module.
3. `ruff check .` clean.
4. No diff in CLI/TUI/`--json` output for the four existing agents.
5. One logical commit per step; draft PR into `develop`.

## Risks

- **Hidden dispatch sites** not in the five listed above. Mitigation: engineer
  greps for `agent_type`, `.suffix`, `"cursor"`, `"codex"`, `"aider"`,
  `"claude-code"`, `log_format` before and after; any remaining site is either
  migrated or documented as intentional (e.g. display labels in `cli.py`,
  SIEM `agent_type` field).
- **Circular imports** (`agents` ↔ `discovery` ↔ `parser`). Mitigation:
  adapters import parser/discovery functions lazily inside methods where
  needed.
