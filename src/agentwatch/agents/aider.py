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
