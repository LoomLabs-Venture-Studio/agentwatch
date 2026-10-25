# Agent Adapter Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace agentwatch's hardcoded per-agent dispatch (5 sites) with a registry of per-agent adapters, with zero behaviour change for Claude Code, Codex, Aider and Cursor.

**Architecture:** New package `src/agentwatch/agents/` holds an `AgentAdapter` protocol + `BaseAdapter` defaults, four thin adapters that wrap existing functions, and a module-level ordered `ADAPTERS` list with lookup helpers. Discovery, `MultiLogWatcher`, the single-agent TUI, and one-shot `parse_file` then dispatch through the registry instead of naming agents or checking file suffixes.

**Tech Stack:** Python 3.11+ (dev box: 3.13 on Windows), pytest, ruff, psutil, textual.

**Spec:** `docs/superpowers/specs/2026-09-30-agent-adapter-registry-design.md`

## Global Constraints

- Branch: `feature/cli-agents` (from `develop`). Never touch `main`. Do not push; the CTO handles push/PR.
- **No edits to any existing file under `tests/`.** Only new test files may be added.
- Full suite baseline (Windows): `794 passed, 1 skipped`. Final state must be baseline + new tests, 0 failures.
- `ruff check .` must be clean (line-length 100, rules E/F/I/N/W).
- Use `python -m pytest` and `python -m pip` (bare `pip` targets a different interpreter on this machine).
- No parsing-logic changes in `parser/logs.py`, `parser/codex.py`, `parser/aider.py`, `parser/cursor_source.py`, or the watcher classes' internals.
- No CLI/TUI/`--json` output changes.
- **Monkeypatch compatibility (load-bearing):** existing tests monkeypatch `agentwatch.discovery._resolve_claude_code_log`, `agentwatch.discovery._get_process_cwd`, `agentwatch.discovery.psutil.process_iter`, and `agentwatch.cursor_discovery.find_cursor_agents`. Adapters MUST look these up via the module attribute **at call time** (`from agentwatch import discovery` inside the method, then `discovery._resolve_claude_code_log(...)`), never bind them with `from ... import name` at module load.
- **Import-cycle rule:** `agentwatch.agents` must not import `agentwatch.discovery`, `agentwatch.cursor_discovery`, or `agentwatch.parser` at module level (only inside methods, or under `TYPE_CHECKING`). `discovery.py` imports `agentwatch.agents` at module level.
- **Registry order:** `claude-code`, `aider`, `codex`, `cursor` — this preserves today's `AGENT_PATTERNS` process-match order (first match wins per PID). The spec's order line says claude-code, codex, aider, cursor; Task 6 corrects the spec to match.
- Commit message format: `type(scope): description`, each ending with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01B5y5tyTmAQWYq87m2fanWh
  ```

---

## File Structure

| File | Responsibility |
|---|---|
| Create `src/agentwatch/agents/__init__.py` | `ADAPTERS` list, `get`, `adapter_for`, `process_adapters`, `editor_adapters`, `register` (test helper) |
| Create `src/agentwatch/agents/base.py` | `Watcher` + `AgentAdapter` protocols, `BaseAdapter` defaults, `sniff_jsonl_format` helper |
| Create `src/agentwatch/agents/claude_code.py` | Claude Code (+ Moltbot JSONL) adapter |
| Create `src/agentwatch/agents/codex.py` | Codex adapter |
| Create `src/agentwatch/agents/aider.py` | Aider adapter |
| Create `src/agentwatch/agents/cursor.py` | Cursor (editor-kind) adapter |
| Modify `src/agentwatch/discovery.py` | Derive `AGENT_PATTERNS`; loop over adapters in `find_running_agents` |
| Modify `src/agentwatch/parser/logs.py` | Extract `_parse_jsonl`; `parse_file` dispatches via registry |
| Modify `src/agentwatch/parser/watcher.py` | `_has_live_log`, `_find_all_logs`, watcher construction via registry |
| Modify `src/agentwatch/ui/app.py` | Single-agent watcher selection via registry (Cursor composer toast stays) |
| Create `tests/test_agent_registry.py` | Registry, adapters, claims, liveness |
| Create `tests/test_agent_registry_dispatch.py` | Discovery/watcher/parse_file via registry + fake-adapter extensibility |

---

### Task 1: `agents` package — protocols, adapters, registry (no dispatch changes yet)

**Files:**
- Create: `src/agentwatch/agents/base.py`, `__init__.py`, `claude_code.py`, `codex.py`, `aider.py`, `cursor.py`
- Test: `tests/test_agent_registry.py`

**Interfaces:**
- Produces:
  - `agentwatch.agents.ADAPTERS: list[AgentAdapter]`
  - `get(name: str) -> AgentAdapter | None`
  - `adapter_for(path: Path) -> AgentAdapter | None`
  - `process_adapters() -> list[AgentAdapter]`, `editor_adapters() -> list[AgentAdapter]`
  - `register(adapter: AgentAdapter) -> None` (appends; tests use `monkeypatch.setattr(agents, "ADAPTERS", [...])` to isolate)
  - `agentwatch.agents.base.BaseAdapter` with attrs `name`, `kind`, `process_pattern`, `process_exclude` and methods `resolve_log(cwd, pid)`, `discover()`, `claims(path)`, `make_watcher(source, session_id)`, `parse_file(path, session_id=None, **opts)`, `is_live(proc)`
  - `agentwatch.agents.base.sniff_jsonl_format(path: Path, max_lines: int = 50) -> str | None`

- [ ] **Step 1: Write the failing tests** — `tests/test_agent_registry.py`

```python
"""Tests for the agent adapter registry (cli-agents sub-project 0)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentwatch import agents
from agentwatch.agents.base import BaseAdapter, sniff_jsonl_format
from agentwatch.discovery import AgentProcess

# Snapshot of discovery.AGENT_PATTERNS as of develop@45e19ce. Adapters must
# reproduce these verbatim.
_LEGACY_PATTERNS = {
    "claude-code": {
        "pattern": r"\bclaude\b",
        "exclude": r"Claude\.app|Claude Helper|claude-code-guide|shell-snapshots",
    },
    "aider": {"pattern": r"\baider\b", "exclude": None},
    "codex": {"pattern": r"\bcodex\b", "exclude": None},
}


def _write_jsonl(path: Path, entries: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")
    return path


class TestRegistryShape:
    def test_order(self):
        assert [a.name for a in agents.ADAPTERS] == ["claude-code", "aider", "codex", "cursor"]

    def test_get(self):
        assert agents.get("codex").name == "codex"
        assert agents.get("nope") is None

    def test_kinds(self):
        assert [a.name for a in agents.process_adapters()] == ["claude-code", "aider", "codex"]
        assert [a.name for a in agents.editor_adapters()] == ["cursor"]

    def test_process_patterns_match_legacy(self):
        got = {
            a.name: {"pattern": a.process_pattern, "exclude": a.process_exclude}
            for a in agents.process_adapters()
        }
        assert got == _LEGACY_PATTERNS

    def test_all_adapters_subclass_base(self):
        assert all(isinstance(a, BaseAdapter) for a in agents.ADAPTERS)


class TestClaims:
    def test_claude_code_jsonl(self, tmp_path):
        p = _write_jsonl(
            tmp_path / "s.jsonl",
            [{"type": "user", "sessionId": "abc", "message": {"role": "user", "content": "hi"}}],
        )
        assert agents.adapter_for(p).name == "claude-code"

    def test_moltbot_jsonl_goes_to_claude_code(self, tmp_path):
        p = _write_jsonl(tmp_path / "m.jsonl", [{"skill": "x", "role": "assistant"}])
        assert agents.adapter_for(p).name == "claude-code"

    def test_codex_jsonl(self, tmp_path):
        p = _write_jsonl(
            tmp_path / "rollout.jsonl", [{"type": "session_meta", "payload": {"id": "1"}}]
        )
        assert sniff_jsonl_format(p) == "codex"
        assert agents.adapter_for(p).name == "codex"

    def test_skip_entries_do_not_lock_format(self, tmp_path):
        p = _write_jsonl(
            tmp_path / "s.jsonl",
            [{"type": "file-history-snapshot"}, {"type": "session_meta", "payload": {}}],
        )
        assert agents.adapter_for(p).name == "codex"

    def test_missing_jsonl_falls_to_claude_code(self, tmp_path):
        assert agents.adapter_for(tmp_path / "missing.jsonl").name == "claude-code"

    def test_aider_md(self, tmp_path):
        p = tmp_path / ".aider.chat.history.md"
        p.write_text("# aider chat started at 2026-01-01 00:00:00\n", encoding="utf-8")
        assert agents.adapter_for(p).name == "aider"

    def test_cursor_vscdb(self, tmp_path):
        assert agents.adapter_for(tmp_path / "state.vscdb").name == "cursor"

    def test_unclaimed(self, tmp_path):
        assert agents.adapter_for(tmp_path / "notes.txt") is None


class TestIsLive:
    def test_process_agent_uses_log_file(self, tmp_path):
        log = tmp_path / "a.jsonl"
        proc = AgentProcess(pid=1, agent_type="claude-code", working_directory=tmp_path,
                            log_file=log)
        assert agents.get("claude-code").is_live(proc) is False
        log.write_text("", encoding="utf-8")
        assert agents.get("claude-code").is_live(proc) is True

    def test_cursor_uses_db_path_not_synthetic_log(self, tmp_path):
        db = tmp_path / "state.vscdb"
        proc = AgentProcess(pid=1, agent_type="cursor", working_directory=tmp_path,
                            log_file=tmp_path / "never-created", cursor_db_path=db)
        assert agents.get("cursor").is_live(proc) is False
        db.write_bytes(b"")
        assert agents.get("cursor").is_live(proc) is True


class TestMakeWatcher:
    def test_types(self, tmp_path):
        from agentwatch.parser.watcher import AiderLogWatcher, CursorWatcher, LogWatcher

        assert isinstance(agents.get("claude-code").make_watcher(tmp_path / "a.jsonl", "s"),
                          LogWatcher)
        assert isinstance(agents.get("codex").make_watcher(tmp_path / "a.jsonl", None),
                          LogWatcher)
        assert isinstance(agents.get("aider").make_watcher(tmp_path / "a.md", "s"),
                          AiderLogWatcher)
        proc = AgentProcess(pid=1, agent_type="cursor", working_directory=tmp_path,
                            log_file=tmp_path / "k", cursor_db_path=tmp_path / "state.vscdb")
        w = agents.get("cursor").make_watcher(proc, "composer-1")
        assert isinstance(w, CursorWatcher)
        assert w.db_path == tmp_path / "state.vscdb"
        assert w.composer_id_filter == "composer-1"

    def test_session_id_passed_through(self, tmp_path):
        w = agents.get("claude-code").make_watcher(tmp_path / "a.jsonl", "sess-9")
        assert w.session_id == "sess-9"


class TestResolveLogDelegatesAtCallTime:
    """Adapters must look up discovery._resolve_* at call time so existing
    tests' monkeypatches keep working."""

    def test_claude_code(self, tmp_path, monkeypatch):
        import agentwatch.discovery as discovery

        monkeypatch.setattr(discovery, "_resolve_claude_code_log",
                            lambda cwd, pid=None: (tmp_path / "x.jsonl", "sid"))
        assert agents.get("claude-code").resolve_log(tmp_path, 5) == (tmp_path / "x.jsonl", "sid")

    def test_cursor_discover(self, monkeypatch):
        sentinel = [object()]
        monkeypatch.setattr("agentwatch.cursor_discovery.find_cursor_agents", lambda: sentinel)
        assert agents.get("cursor").discover() is sentinel


def test_register_appends(monkeypatch):
    monkeypatch.setattr(agents, "ADAPTERS", list(agents.ADAPTERS))

    class Fake(BaseAdapter):
        name = "fake"
        kind = "process"
        process_pattern = r"\bfakeagent\b"

    agents.register(Fake())
    assert agents.get("fake") is not None
    with pytest.raises(ValueError):
        agents.register(Fake())
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_agent_registry.py -q`
Expected: collection ERROR `ModuleNotFoundError: No module named 'agentwatch.agents'`.

- [ ] **Step 3: Implement `src/agentwatch/agents/base.py`**

```python
"""Agent adapter protocol and defaults.

Each supported coding agent is described by one adapter. Core modules
(discovery, watchers, TUI, one-shot parse) dispatch through
``agentwatch.agents`` instead of naming agents.

Import rule: nothing from agentwatch.discovery / cursor_discovery / parser at
module level -- those import this package, so imports happen inside methods.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action


@runtime_checkable
class Watcher(Protocol):
    def watch(self) -> AsyncIterator[Action]: ...


class AgentAdapter(Protocol):
    name: str
    kind: Literal["process", "editor"]
    process_pattern: str | None
    process_exclude: str | None

    def resolve_log(self, cwd: Path, pid: int | None) -> tuple[Path | None, str | None]: ...
    def discover(self) -> list[AgentProcess]: ...
    def claims(self, path: Path) -> bool: ...
    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher: ...
    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]: ...
    def is_live(self, proc: AgentProcess) -> bool: ...


class BaseAdapter:
    """Defaults shared by all adapters. Subclasses override what they need."""

    name: str = ""
    kind: Literal["process", "editor"] = "process"
    process_pattern: str | None = None
    process_exclude: str | None = None

    def resolve_log(self, cwd: Path, pid: int | None) -> tuple[Path | None, str | None]:
        return None, None

    def discover(self) -> list[AgentProcess]:
        return []

    def claims(self, path: Path) -> bool:
        return False

    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher:
        raise NotImplementedError(f"{self.name} adapter has no watcher")

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        raise NotImplementedError(f"{self.name} adapter has no one-shot parser")

    def is_live(self, proc: AgentProcess) -> bool:
        return proc.log_file is not None and proc.log_file.exists()

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.name!r}>"


def source_path(source: AgentProcess | Path) -> Path:
    """The log path of a watcher source (a Path, or an AgentProcess's log_file)."""
    if isinstance(source, Path):
        return source
    assert source.log_file is not None
    return source.log_file


def sniff_jsonl_format(path: Path, max_lines: int = 50) -> str | None:
    """Return detect_log_format() of the first non-"skip" JSONL entry.

    None when the file is missing/unreadable or has no decisive entry within
    *max_lines*. Mirrors parse_file()'s own detection (same function, same
    "skip" semantics) so claims() never disagrees with the parser.
    """
    from agentwatch.parser.logs import detect_log_format

    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    return None
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(entry, dict):
                    continue
                fmt = detect_log_format(entry)
                if fmt != "skip":
                    return fmt
    except OSError:
        return None
    return None
```

- [ ] **Step 4: Implement the four adapters**

`src/agentwatch/agents/claude_code.py`:

```python
"""Claude Code adapter (also owns Moltbot-format JSONL, which is a log
format, not a discoverable agent)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import BaseAdapter, Watcher, sniff_jsonl_format, source_path

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action


class ClaudeCodeAdapter(BaseAdapter):
    name = "claude-code"
    kind = "process"
    process_pattern = r"\bclaude\b"
    process_exclude = r"Claude\.app|Claude Helper|claude-code-guide|shell-snapshots"

    def resolve_log(self, cwd: Path, pid: int | None) -> tuple[Path | None, str | None]:
        from agentwatch import discovery  # call-time lookup: tests monkeypatch this

        return discovery._resolve_claude_code_log(cwd, pid=pid)

    def claims(self, path: Path) -> bool:
        # Every JSONL that isn't Codex -- including missing/undecidable files,
        # which parse_file() has always treated as Claude Code/Moltbot.
        return path.suffix == ".jsonl" and sniff_jsonl_format(path) != "codex"

    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher:
        from agentwatch.parser.watcher import LogWatcher

        return LogWatcher(source_path(source), session_id=session_id)

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        from agentwatch.parser.logs import _parse_jsonl

        return _parse_jsonl(path, session_id)
```

`src/agentwatch/agents/codex.py`:

```python
"""Codex (OpenAI) adapter."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import BaseAdapter, Watcher, sniff_jsonl_format, source_path

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action


class CodexAdapter(BaseAdapter):
    name = "codex"
    kind = "process"
    process_pattern = r"\bcodex\b"
    process_exclude = None

    def resolve_log(self, cwd: Path, pid: int | None) -> tuple[Path | None, str | None]:
        from agentwatch import discovery

        return discovery._resolve_codex_log(cwd, pid=pid)

    def claims(self, path: Path) -> bool:
        return path.suffix == ".jsonl" and sniff_jsonl_format(path) == "codex"

    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher:
        # LogWatcher auto-detects Codex and owns the no-flush-on-poll rule.
        from agentwatch.parser.watcher import LogWatcher

        return LogWatcher(source_path(source), session_id=session_id)

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        from agentwatch.parser.logs import _parse_jsonl

        return _parse_jsonl(path, session_id)
```

`src/agentwatch/agents/aider.py`:

```python
"""Aider adapter (Markdown chat-history transcripts)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import BaseAdapter, Watcher, source_path

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action


class AiderAdapter(BaseAdapter):
    name = "aider"
    kind = "process"
    process_pattern = r"\baider\b"
    process_exclude = None

    def resolve_log(self, cwd: Path, pid: int | None) -> tuple[Path | None, str | None]:
        from agentwatch import discovery

        return discovery._resolve_aider_log(cwd)

    def claims(self, path: Path) -> bool:
        return path.suffix == ".md"

    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher:
        from agentwatch.parser.watcher import AiderLogWatcher

        return AiderLogWatcher(source_path(source), session_id=session_id)

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        from agentwatch.parser.aider import parse_aider_log

        for action in parse_aider_log(path, analytics_path=opts.get("analytics_log")):
            if session_id is None or action.session_id == session_id:
                yield action
```

`src/agentwatch/agents/cursor.py`:

```python
"""Cursor adapter (editor-kind: one shared state.vscdb, no per-session process)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import BaseAdapter, Watcher

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action


class CursorAdapter(BaseAdapter):
    name = "cursor"
    kind = "editor"

    def discover(self) -> list[AgentProcess]:
        import agentwatch.cursor_discovery as cursor_discovery  # call-time lookup

        return cursor_discovery.find_cursor_agents()

    def claims(self, path: Path) -> bool:
        return path.suffix == ".vscdb"

    def is_live(self, proc: AgentProcess) -> bool:
        # log_file is a synthetic never-created identity key for Cursor
        # (see cursor_discovery._cursor_synthetic_log_key); real I/O is the db.
        return proc.cursor_db_path is not None and proc.cursor_db_path.exists()

    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher:
        from agentwatch.parser.watcher import CursorWatcher

        db_path = source if isinstance(source, Path) else source.cursor_db_path
        return CursorWatcher(db_path, composer_id_filter=session_id)

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        from agentwatch.parser.cursor_source import parse_cursor_session

        yield from parse_cursor_session(path, composer_id=session_id)
```

- [ ] **Step 5: Implement `src/agentwatch/agents/__init__.py`**

```python
"""Registry of supported coding-agent adapters.

Order matters: process matching is first-match-wins per PID, in this order
(preserves the historical AGENT_PATTERNS order). To add an agent: create
agents/<name>.py with a BaseAdapter subclass and append it here.
"""

from __future__ import annotations

from pathlib import Path

from .aider import AiderAdapter
from .base import AgentAdapter, BaseAdapter, Watcher
from .claude_code import ClaudeCodeAdapter
from .codex import CodexAdapter
from .cursor import CursorAdapter

ADAPTERS: list[AgentAdapter] = [
    ClaudeCodeAdapter(),
    AiderAdapter(),
    CodexAdapter(),
    CursorAdapter(),
]


def get(name: str | None) -> AgentAdapter | None:
    for adapter in ADAPTERS:
        if adapter.name == name:
            return adapter
    return None


def adapter_for(path: Path) -> AgentAdapter | None:
    """First adapter (in registry order) that claims *path*."""
    for adapter in ADAPTERS:
        if adapter.claims(path):
            return adapter
    return None


def process_adapters() -> list[AgentAdapter]:
    return [a for a in ADAPTERS if a.kind == "process"]


def editor_adapters() -> list[AgentAdapter]:
    return [a for a in ADAPTERS if a.kind == "editor"]


def register(adapter: AgentAdapter) -> None:
    if get(adapter.name) is not None:
        raise ValueError(f"adapter {adapter.name!r} already registered")
    ADAPTERS.append(adapter)


__all__ = [
    "ADAPTERS",
    "AgentAdapter",
    "BaseAdapter",
    "Watcher",
    "adapter_for",
    "editor_adapters",
    "get",
    "process_adapters",
    "register",
]
```

Note: `get`, `adapter_for`, etc. read the module global `ADAPTERS` at call time, so `monkeypatch.setattr(agents, "ADAPTERS", [...])` isolates tests.

Note: `claude_code`/`codex` `parse_file` import `agentwatch.parser.logs._parse_jsonl`, which Task 3 creates. The import is inside the method and Task 1's tests don't call it, so Task 1 passes on its own.

- [ ] **Step 6: Run tests**

Run: `python -m pytest tests/test_agent_registry.py -q`
Expected: all PASS.
Run: `python -m pytest -q`
Expected: `794 passed, 1 skipped` + the new tests, 0 failed.
Run: `ruff check .` → clean.

- [ ] **Step 7: Commit**

```bash
git add src/agentwatch/agents tests/test_agent_registry.py
git commit -m "feat(agents): add agent adapter registry for claude-code, aider, codex, cursor" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01B5y5tyTmAQWYq87m2fanWh"
```

---

### Task 2: Discovery dispatches through the registry

**Files:**
- Modify: `src/agentwatch/discovery.py` (lines ~17-31 `AGENT_PATTERNS`; ~176-222 inside `find_running_agents`; ~249-258 Cursor append)
- Test: `tests/test_agent_registry_dispatch.py` (new)

**Interfaces:**
- Consumes: `agents.process_adapters()`, `agents.editor_adapters()`, `adapter.resolve_log(cwd, pid)`, `adapter.discover()`
- Produces: `discovery.AGENT_PATTERNS` remains a `dict[str, dict]` with identical content (derived).

- [ ] **Step 1: Write the failing test** — create `tests/test_agent_registry_dispatch.py`

```python
"""Core dispatch sites route through agentwatch.agents (cli-agents sub-project 0)."""

from __future__ import annotations

import types
from pathlib import Path

import agentwatch.discovery as discovery
from agentwatch import agents
from agentwatch.agents.base import BaseAdapter
from agentwatch.discovery import AgentProcess


class _FakeProcess:
    def __init__(self, pid: int, cmdline: list[str]):
        self.info = {
            "pid": pid,
            "ppid": 1,
            "cmdline": cmdline,
            "name": cmdline[0],
            "memory_info": types.SimpleNamespace(rss=1024 * 1024),
            "cpu_percent": 0.0,
            "create_time": 1_700_000_000.0,
        }


def _iter(*procs):
    return lambda attrs=None: iter(list(procs))


class FakeAgentAdapter(BaseAdapter):
    """An agent that exists only in this test file."""

    name = "fakeagent"
    kind = "process"
    process_pattern = r"\bfakeagent\b"

    def __init__(self, log: Path):
        self._log = log

    def resolve_log(self, cwd, pid):
        return self._log, "fake-session"

    def claims(self, path):
        return path.suffix == ".fake"

    def make_watcher(self, source, session_id):
        from agentwatch.parser.watcher import LogWatcher

        path = source if isinstance(source, Path) else source.log_file
        return LogWatcher(path, session_id=session_id)

    def parse_file(self, path, session_id=None, **opts):
        from datetime import datetime

        from agentwatch.parser.models import Action, ToolType

        yield Action(timestamp=datetime(2026, 1, 1), tool_name="Read",
                     tool_type=ToolType.READ, success=True, session_id="fake-session")


def _isolate(monkeypatch, *extra):
    monkeypatch.setattr(agents, "ADAPTERS", [*agents.ADAPTERS, *extra])
    monkeypatch.setattr("agentwatch.cursor_discovery.find_cursor_agents", lambda: [])


class TestDiscoveryViaRegistry:
    def test_agent_patterns_still_exported(self):
        assert set(discovery.AGENT_PATTERNS) == {"claude-code", "aider", "codex"}
        assert discovery.AGENT_PATTERNS["codex"] == {"pattern": r"\bcodex\b", "exclude": None}

    def test_fake_adapter_discovered_without_core_edits(self, tmp_path, monkeypatch):
        log = tmp_path / "s.fake"
        log.write_text("", encoding="utf-8")
        _isolate(monkeypatch, FakeAgentAdapter(log))
        monkeypatch.setattr(discovery.psutil, "process_iter",
                            _iter(_FakeProcess(777, ["fakeagent", "--go"])))
        monkeypatch.setattr(discovery, "_get_process_cwd", lambda pid: tmp_path)

        found = discovery.find_running_agents()

        assert [(a.pid, a.agent_type, a.log_file, a.session_id) for a in found] == [
            (777, "fakeagent", log, "fake-session")
        ]

    def test_first_match_wins_in_registry_order(self, tmp_path, monkeypatch):
        _isolate(monkeypatch)
        monkeypatch.setattr(discovery.psutil, "process_iter",
                            _iter(_FakeProcess(5, ["aider", "--model", "codex"])))
        monkeypatch.setattr(discovery, "_get_process_cwd", lambda pid: tmp_path)
        monkeypatch.setattr(discovery, "_resolve_aider_log", lambda cwd: (None, None))

        found = discovery.find_running_agents()

        assert [a.agent_type for a in found] == ["aider"]

    def test_broken_adapter_does_not_break_others(self, tmp_path, monkeypatch):
        class Boom(BaseAdapter):
            name = "boom"
            kind = "editor"

            def discover(self):
                raise RuntimeError("boom")

        _isolate(monkeypatch, Boom())
        monkeypatch.setattr(discovery.psutil, "process_iter",
                            _iter(_FakeProcess(9, ["claude"])))
        monkeypatch.setattr(discovery, "_get_process_cwd", lambda pid: tmp_path)
        monkeypatch.setattr(discovery, "_resolve_claude_code_log",
                            lambda cwd, pid=None: (None, None))

        assert [a.agent_type for a in discovery.find_running_agents()] == ["claude-code"]
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_agent_registry_dispatch.py -q`
Expected: `test_fake_adapter_discovered_without_core_edits` and `test_broken_adapter_does_not_break_others` FAIL (discovery ignores registry).

- [ ] **Step 3: Implement in `discovery.py`**

Replace the `AGENT_PATTERNS` literal (lines ~17-31) with:

```python
from agentwatch import agents as _agents

# Back-compat: read-only view derived from the adapter registry. New agents
# are added in agentwatch/agents/, not here.
AGENT_PATTERNS: dict[str, dict] = {
    a.name: {"pattern": a.process_pattern, "exclude": a.process_exclude}
    for a in _agents.process_adapters()
}
```

(Place the import with the other imports at the top, after `from agentwatch.path_encoding import ...`; ruff's isort rule will flag order otherwise.)

In `find_running_agents`, replace the loop header

```python
        for agent_type, config in AGENT_PATTERNS.items():
            pattern = config["pattern"]
            exclude = config["exclude"]
```

with

```python
        for adapter in _agents.process_adapters():
            agent_type = adapter.name
            pattern = adapter.process_pattern
            exclude = adapter.process_exclude
            if not pattern:
                continue
```

and replace the resolver chain

```python
                if agent_type == "claude-code":
                    log_file, session_id = _resolve_claude_code_log(cwd, pid=pid)
                elif agent_type == "aider":
                    log_file, session_id = _resolve_aider_log(cwd)
                elif agent_type == "codex":
                    log_file, session_id = _resolve_codex_log(cwd, pid=pid)
```

with

```python
                try:
                    log_file, session_id = adapter.resolve_log(cwd, pid)
                except Exception:
                    log_file, session_id = None, None
```

Replace the Cursor block

```python
    try:
        from agentwatch.cursor_discovery import find_cursor_agents

        agents.extend(find_cursor_agents())
    except Exception:
        pass
```

with (keep the explanatory comment above it, reworded to "editor-kind adapters (Cursor, ...)"):

```python
    for editor in _agents.editor_adapters():
        try:
            agents.extend(editor.discover())
        except Exception:
            # One broken editor integration must not hide the others.
            continue
```

Note the local variable in `find_running_agents` is named `agents` — that's why the module is imported as `_agents`.

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_agent_registry_dispatch.py tests/test_discovery.py tests/test_discovery_cache.py tests/test_codex_discovery.py tests/test_cursor_discovery.py -q` → all PASS.
Run: `python -m pytest -q` → 0 failed. `ruff check .` → clean.
If an import cycle appears (`ImportError: cannot import name ... partially initialized module`), a module under `agents/` is importing discovery/parser at module level — move it inside the method.

- [ ] **Step 5: Commit**

```bash
git add src/agentwatch/discovery.py tests/test_agent_registry_dispatch.py
git commit -m "refactor(discovery): resolve agents and logs via adapter registry" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01B5y5tyTmAQWYq87m2fanWh"
```

---

### Task 3: One-shot `parse_file` dispatches through the registry

**Files:**
- Modify: `src/agentwatch/parser/logs.py` (`parse_file`, ~lines 462-555)
- Test: append a class to `tests/test_agent_registry_dispatch.py`

**Interfaces:**
- Produces: `agentwatch.parser.logs._parse_jsonl(path: Path, session_id: str | None) -> Iterator[Action]` — the existing JSONL body, unchanged.
- `parse_file(path, session_id=None, analytics_log=None)` keeps its exact signature and generator behaviour.

- [ ] **Step 1: Write the failing test** (append to `tests/test_agent_registry_dispatch.py`)

```python
class TestParseFileViaRegistry:
    def test_fake_adapter_parse_file(self, tmp_path, monkeypatch):
        from agentwatch.parser.logs import parse_file

        p = tmp_path / "x.fake"
        p.write_text("anything", encoding="utf-8")
        _isolate(monkeypatch, FakeAgentAdapter(p))

        actions = list(parse_file(p))

        assert [a.session_id for a in actions] == ["fake-session"]

    def test_unclaimed_path_falls_back_to_jsonl(self, tmp_path):
        import json

        from agentwatch.parser.logs import parse_file

        p = tmp_path / "log.txt"  # no adapter claims .txt
        p.write_text(json.dumps({"type": "user", "sessionId": "s",
                                 "message": {"role": "user", "content": "hi"}}) + "\n",
                     encoding="utf-8")
        # Same result as before the refactor: parsed as Claude Code JSONL.
        assert isinstance(list(parse_file(p)), list)
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_agent_registry_dispatch.py::TestParseFileViaRegistry -q`
Expected: `test_fake_adapter_parse_file` FAIL (parse_file treats `.fake` as JSONL → no actions).

- [ ] **Step 3: Implement in `parser/logs.py`**

1. Rename the JSONL portion of `parse_file` (from the `from .codex import CodexParser` lazy import through the final Codex flush loop) into a new private generator directly above `parse_file`:

```python
def _parse_jsonl(path: Path, session_id: str | None = None) -> Iterator[Action]:
    """JSONL body of parse_file (Claude Code / Moltbot / Codex, auto-detected)."""
    # Imported lazily (not at module level) to avoid a logs.py <-> codex.py
    # circular import — codex.py imports classify_tool from this module at
    # its own module level.
    from .codex import CodexParser

    ...  # the existing loop and Codex flush, moved verbatim
```

2. Replace the body of `parse_file` (keep its docstring) with:

```python
    from agentwatch.agents import adapter_for

    adapter = adapter_for(path)
    if adapter is None:
        yield from _parse_jsonl(path, session_id)
        return
    yield from adapter.parse_file(path, session_id, analytics_log=analytics_log)
```

This deletes the `.md` and `.vscdb` suffix branches (now in the aider/cursor adapters). Claude Code/Codex JSONL route to `_parse_jsonl` via their adapters, so their behaviour is byte-identical.

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_agent_registry_dispatch.py tests/test_agent_registry.py tests/test_aider_parser.py tests/test_codex_parser.py tests/test_cursor_source.py -q` → PASS.
Run: `python -m pytest -q` → 0 failed. `ruff check .` → clean.

- [ ] **Step 5: Commit**

```bash
git add src/agentwatch/parser/logs.py tests/test_agent_registry_dispatch.py
git commit -m "refactor(parser): dispatch one-shot parse_file via adapter registry" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01B5y5tyTmAQWYq87m2fanWh"
```

---

### Task 4: `MultiLogWatcher` dispatches through the registry

**Files:**
- Modify: `src/agentwatch/parser/watcher.py` — `_has_live_log` (~365-376), `MultiLogWatcher._find_all_logs` (~486-507), watcher construction in `MultiLogWatcher.watch` (~528-538)
- Test: append a class to `tests/test_agent_registry_dispatch.py`

**Interfaces:**
- Consumes: `agents.get(name)`, `agents.adapter_for(path)`, `adapter.is_live(proc)`, `adapter.make_watcher(source, session_id)`

- [ ] **Step 1: Write the failing test** (append)

```python
class TestMultiLogWatcherViaRegistry:
    def test_fake_agent_is_live_listed_and_watched(self, tmp_path, monkeypatch):
        from agentwatch.parser.watcher import LogWatcher, MultiLogWatcher, _has_live_log

        log = tmp_path / "s.fake"
        log.write_text("", encoding="utf-8")
        _isolate(monkeypatch, FakeAgentAdapter(log))
        proc = AgentProcess(pid=777, agent_type="fakeagent", working_directory=tmp_path,
                            log_file=log, session_id="fake-session", command="fakeagent")

        assert _has_live_log(proc)
        mlw = MultiLogWatcher.from_processes([proc])
        assert mlw._find_all_logs() == [log]
        w = mlw._make_watcher(log)
        assert isinstance(w, LogWatcher) and w.session_id == "fake-session"
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_agent_registry_dispatch.py::TestMultiLogWatcherViaRegistry -q`
Expected: FAIL (`.fake` suffix filtered out by `_find_all_logs`; `_make_watcher` doesn't exist).

- [ ] **Step 3: Implement in `parser/watcher.py`**

`_has_live_log` body (keep docstring, update it to say "delegates to the agent's adapter"):

```python
    from agentwatch.agents import get

    adapter = get(proc.agent_type)
    if adapter is not None:
        return adapter.is_live(proc)
    return proc.log_file is not None and proc.log_file.exists()
```

`_find_all_logs` process-mode branch:

```python
        if self._process_mode:
            from agentwatch.agents import adapter_for, get

            return [
                p for p, proc in self._process_meta.items()
                if (get(proc.agent_type) is not None or adapter_for(p) is not None)
                and proc.command != "(stopped)"
            ]
```

(Update the docstring: "entries whose agent has a registered adapter (or whose path an adapter claims)".) Path-mode branch unchanged.

Add a method on `MultiLogWatcher` and use it in `watch()`:

```python
    def _make_watcher(self, log_meta: Path) -> Watcher:
        """Build the watcher for one tracked entry via its agent's adapter.

        Falls back to adapter_for(path), then plain LogWatcher -- the
        historical default for any JSONL path.
        """
        from agentwatch.agents import adapter_for, get

        proc = self._process_meta.get(log_meta)
        sid = proc.session_id if proc else None
        adapter = (get(proc.agent_type) if proc else None) or adapter_for(log_meta)
        if adapter is None:
            return LogWatcher(log_meta, session_id=sid)
        return adapter.make_watcher(proc if proc is not None else log_meta, sid)
```

In `watch()`, replace

```python
                        proc = self._process_meta.get(log_meta)
                        sid = proc.session_id if proc else None
                        watcher: LogWatcher | AiderLogWatcher | CursorWatcher
                        if proc is not None and proc.agent_type == "cursor":
                            ...
                        else:
                            watcher = LogWatcher(log_meta, session_id=sid)
```

with

```python
                        watcher = self._make_watcher(log_meta)
```

Change the type hints `LogWatcher | AiderLogWatcher | CursorWatcher` on `self.watchers` and `fill_queue` to `Watcher`, with `from agentwatch.agents.base import Watcher` at the top of `watcher.py` (safe: `agents.base` imports nothing from parser at module level).

**Behaviour check:** for Cursor, the old code passed `db_path=proc.cursor_db_path, composer_id_filter=sid`; `CursorAdapter.make_watcher(proc, sid)` does the same. For Aider (`.md`), old code used `AiderLogWatcher(log_meta, session_id=sid)`; same via adapter. Path mode (no proc): `.jsonl` → claude-code/codex adapter → `LogWatcher` (same as before).

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_agent_registry_dispatch.py tests/test_multi_log_watcher_aider.py tests/test_multi_log_watcher_cursor.py tests/test_multi_app_refresh.py tests/test_multi_app_live_wiring.py -q` → PASS.
Run: `python -m pytest -q` → 0 failed. `ruff check .` → clean.

- [ ] **Step 5: Commit**

```bash
git add src/agentwatch/parser/watcher.py tests/test_agent_registry_dispatch.py
git commit -m "refactor(watcher): build per-agent watchers via adapter registry" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01B5y5tyTmAQWYq87m2fanWh"
```

---

### Task 5: Single-agent TUI (`ui/app.py`) dispatches through the registry

**Files:**
- Modify: `src/agentwatch/ui/app.py` — watcher selection in `on_mount` (~lines 466-499)
- Test: append a class to `tests/test_agent_registry_dispatch.py`

**Interfaces:**
- Consumes: `agents.adapter_for(path)`, `adapter.make_watcher(path, session_id)`. Keeps `self._resolve_cursor_composer_id()` and its toast.

- [ ] **Step 1: Write the failing test** (append)

```python
class TestSingleAgentAppViaRegistry:
    def test_select_watcher_uses_adapter(self, tmp_path, monkeypatch):
        from agentwatch.parser.watcher import LogWatcher
        from agentwatch.ui.app import select_single_agent_watcher

        log = tmp_path / "s.fake"
        log.write_text("", encoding="utf-8")
        _isolate(monkeypatch, FakeAgentAdapter(log))

        w = select_single_agent_watcher(log, cursor_composer_id=None)

        assert isinstance(w, LogWatcher) and w.path == log

    def test_select_watcher_defaults(self, tmp_path):
        from agentwatch.parser.watcher import AiderLogWatcher, CursorWatcher, LogWatcher
        from agentwatch.ui.app import select_single_agent_watcher

        assert isinstance(select_single_agent_watcher(tmp_path / "a.jsonl", None), LogWatcher)
        assert isinstance(select_single_agent_watcher(tmp_path / "a.md", None), AiderLogWatcher)
        assert isinstance(select_single_agent_watcher(tmp_path / "x.log", None), LogWatcher)
        cw = select_single_agent_watcher(tmp_path / "state.vscdb", "comp-1")
        assert isinstance(cw, CursorWatcher) and cw.composer_id_filter == "comp-1"
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_agent_registry_dispatch.py::TestSingleAgentAppViaRegistry -q`
Expected: FAIL `ImportError: cannot import name 'select_single_agent_watcher'`.

- [ ] **Step 3: Implement in `ui/app.py`**

Add a module-level function (above the App class):

```python
def select_single_agent_watcher(log_path: Path, cursor_composer_id: str | None):
    """Pick the live watcher for ``agentwatch watch --log <path>``.

    Delegates to the adapter that claims *log_path*; unclaimed paths get a
    plain LogWatcher (historical default: JSONL with format auto-detection).
    For Cursor, *cursor_composer_id* is the composer to follow.
    """
    from agentwatch.agents import adapter_for
    from agentwatch.parser import LogWatcher

    adapter = adapter_for(log_path)
    if adapter is None:
        return LogWatcher(log_path)
    session = cursor_composer_id if adapter.name == "cursor" else None
    return adapter.make_watcher(log_path, session)
```

Replace the `on_mount` block from `self.watcher = None` through the final `else: self.watcher = LogWatcher(self.log_path)` with:

```python
        self.watcher = None
        composer_id = None
        if self.log_path.suffix == ".vscdb":
            composer_id = self._resolve_cursor_composer_id()
            if composer_id is None:
                # (keep the existing explanatory comment and self.notify(...) call verbatim)
                ...
        if self.log_path.suffix != ".vscdb" or composer_id is not None:
            self.watcher = select_single_agent_watcher(self.log_path, composer_id)
```

Keep the `self.notify(...)` call text exactly as it is today. Remove `AiderLogWatcher, CursorWatcher, LogWatcher` from the `on_mount` import line if now unused (ruff F401 will tell you). Update the explanatory comment above the block to say selection is delegated to the adapter registry.

Note: `.vscdb` is still named here because the composer-resolution toast is UI behaviour specific to the single-agent Cursor case; that's an intentional, documented exception (record it in Task 6's audit).

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_agent_registry_dispatch.py tests/test_cursor_single_agent_tui.py tests/test_app_live_wiring.py tests/test_app_on_action_regression.py -q` → PASS.
Run: `python -m pytest -q` → 0 failed. `ruff check .` → clean.

- [ ] **Step 5: Commit**

```bash
git add src/agentwatch/ui/app.py tests/test_agent_registry_dispatch.py
git commit -m "refactor(ui): select single-agent watcher via adapter registry" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01B5y5tyTmAQWYq87m2fanWh"
```

---

### Task 6: Dispatch-site audit, spec correction, final verification

**Files:**
- Modify: `docs/superpowers/specs/2026-09-30-agent-adapter-registry-design.md` (registry order line)
- Modify (if audit finds anything): the offending module

- [ ] **Step 1: Audit for remaining hardcoded dispatch**

Run:
```bash
git grep -nE 'agent_type ?==|\.suffix ?(==|in)|"(claude-code|codex|aider|cursor)"|log_format ?==' -- src/agentwatch
```

Classify every hit:
- **OK (not dispatch):** inside `src/agentwatch/agents/`; `detect_log_format` / `LogWatcher._parse_entry` / `_parse_jsonl` internal format handling (claude_code vs moltbot vs codex inside one JSONL stream — a parser concern); `cursor_discovery.py` setting `agent_type="cursor"`; `cli.py` display columns; SIEM/live_integrations passing `agent_type` through as data; `ui/app.py` `.vscdb` composer-toast (Task 5 note); path-mode `.jsonl` scanning in `_find_all_logs` / `find_log_files` (directory scan, not agent dispatch).
- **Must fix:** any remaining branch that picks a parser/watcher/resolver/liveness rule by agent name or suffix. Route it through `agentwatch.agents` using the same pattern as Tasks 2-5, with a test in `tests/test_agent_registry_dispatch.py`.

Paste the grep output and your classification into the task report.

- [ ] **Step 2: Correct the spec's registry order**

In the spec, section "2. Registry", change
`` - `ADAPTERS: list[AgentAdapter]` — ordered: claude-code, codex, aider, cursor. ``
to
`` - `ADAPTERS: list[AgentAdapter]` — ordered: claude-code, aider, codex, cursor (preserves historical `AGENT_PATTERNS` first-match-wins order; claude-code vs codex JSONL claims are mutually exclusive by content, so claim order doesn't depend on it). ``

- [ ] **Step 3: Full verification**

Run: `python -m pytest -q` → expect `N passed, 1 skipped` with N = 794 + new tests, 0 failed.
Run: `ruff check .` → `All checks passed!`
Run: `git diff develop --stat -- tests/` → only `tests/test_agent_registry.py` and `tests/test_agent_registry_dispatch.py` appear (no existing test file modified).
Run smoke checks (no crash, same output shape as on develop):
```bash
agentwatch --version
agentwatch ps --json
agentwatch list-detectors
```
(`ps --json` exercises `find_running_agents` end to end; compare its keys against the same command run on `develop`.)

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/specs/2026-09-30-agent-adapter-registry-design.md
git commit -m "docs(spec): correct adapter registry order to match process-match precedence" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01B5y5tyTmAQWYq87m2fanWh"
```

(Plus a separate `refactor(...)` commit per module if the audit required fixes.)

- [ ] **Step 5: Report**

Report: commit list (`git log --oneline develop..HEAD`), final pytest summary line, ruff result, `git diff develop --stat`, the audit grep output + classification. Do not push.
