"""Antigravity CLI (``agy``) adapter."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import psutil

from .base import BaseAdapter, Watcher, sniff_jsonl_format, source_path

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action

# No documented override for this location (unlike CODEX_HOME/COPILOT_HOME).
AGY_HOME = Path.home() / ".gemini" / "antigravity-cli"


def resolve_agy_log(cwd: Path, pid: int | None = None) -> tuple[Path | None, str | None]:
    """Resolve a running agy process's transcript.

    A live agy holds ``presence/<conversation-id>.lock`` open (seen live,
    1.2.14); the transcript is
    ``brain/<conversation-id>/.system_generated/logs/transcript.jsonl``. The
    presence files stay behind after exit and the transcript records no cwd,
    so without a PID match there is no reliable fallback.
    """
    # ponytail: PID-only; add a cwd/mtime fallback if open_files() is denied in practice.
    if pid is None:
        return None, None
    try:
        open_files = psutil.Process(pid).open_files()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None, None
    for f in open_files:
        path = Path(f.path)
        if path.parent.name == "presence" and path.suffix == ".lock":
            cid = path.stem
            log = AGY_HOME / "brain" / cid / ".system_generated" / "logs" / "transcript.jsonl"
            return (log if log.exists() else None), cid
    return None, None


class AgyAdapter(BaseAdapter):
    name = "agy"
    kind = "process"
    process_pattern = r"(^|[/\\])agy(\.exe)?(\s|$)"
    process_exclude = None

    def resolve_log(self, cwd: Path, pid: int | None) -> tuple[Path | None, str | None]:
        return resolve_agy_log(cwd, pid=pid)

    def claims(self, path: Path) -> bool:
        return path.suffix == ".jsonl" and sniff_jsonl_format(path) == "agy"

    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher:
        from agentwatch.parser.watcher import LogWatcher

        return LogWatcher(source_path(source), session_id=session_id)

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        from agentwatch.parser.logs import _parse_jsonl

        return _parse_jsonl(path, session_id)
