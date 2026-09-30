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
