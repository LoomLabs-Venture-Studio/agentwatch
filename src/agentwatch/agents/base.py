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
    *max_lines*; "unknown" for binary files. Mirrors parse_file()'s own
    detection (same function, same "skip" semantics) so claims() never
    disagrees with the parser.
    """
    from agentwatch.parser.logs import detect_log_format, is_binary_file

    if is_binary_file(path):
        return "unknown"

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
