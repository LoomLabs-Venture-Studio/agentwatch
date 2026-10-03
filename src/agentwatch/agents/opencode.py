"""opencode adapter (process-kind, but every session lives in one SQLite file)."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import psutil

from .base import BaseAdapter, Watcher

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action


_COLUMNS = {
    "session": {"id", "directory", "parent_id", "time_updated"},
    "message": {"id", "session_id", "time_created", "data"},
    "part": {"id", "message_id", "time_created", "data"},
}


def opencode_db() -> Path:
    """opencode's database path (see ``parser/opencode.py`` for the source).

    ``OPENCODE_DB`` is read from agentwatch's own environment, not the
    opencode process's.
    """
    data = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "opencode"
    override = os.environ.get("OPENCODE_DB")
    # ponytail: non-release channels' opencode-<channel>.db is not looked for.
    return data / override if override else data / "opencode.db"


def session_key(db: Path, session_id: str) -> Path:
    """``<db>#<session>``: MultiLogWatcher keys agents by log_file, and every
    opencode session shares one db (Cursor's synthetic-key precedent). Never
    opened; ``db_of()`` recovers the real file."""
    return db.with_name(f"{db.name}#{session_id}")


def db_of(path: Path) -> Path:
    return path.with_name(path.name.partition("#")[0])


class OpencodeAdapter(BaseAdapter):
    name = "opencode"
    kind = "process"
    # The npm package's bin is the native binary itself (bin/opencode.exe on
    # every platform, seen live 1.18.34).
    process_pattern = r"(^|[/\\])opencode(\.exe)?$"
    process_exclude = None

    def resolve_log(self, cwd: Path, pid: int | None) -> tuple[Path | None, str | None]:
        """Newest top-level session whose directory is the process cwd and
        that was updated since the process started.

        The start-time bound stops a new process from showing the previous
        run's session before its own exists (seen live). Re-resolved every
        discovery scan (the key never exists on disk), so a new session in the
        same TUI is picked up. opencode keeps no per-session lock or file, so
        two opencode processes in one directory both resolve to its newest
        session.
        """
        from agentwatch.parser.opencode import latest_session, open_readonly

        db = opencode_db()
        if not db.exists():
            return None, None
        since_ms = 0
        if pid is not None:
            try:
                since_ms = int(psutil.Process(pid).create_time() * 1000)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        conn = open_readonly(db)
        try:
            sid = latest_session(conn, cwd, since_ms)
        finally:
            conn.close()
        return (session_key(db, sid), sid) if sid else (None, None)

    def claims(self, path: Path) -> bool:
        if path.suffix != ".db" or not path.is_file():
            return False
        from agentwatch.parser.opencode import open_readonly

        try:
            conn = open_readonly(path)
            try:
                # Columns parser/opencode.py queries, not just table names: a
                # look-alike db must not reach the parser and crash `check`.
                return all(
                    need <= {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
                    for table, need in _COLUMNS.items()
                )
            finally:
                conn.close()
        except sqlite3.Error:
            return False

    def is_live(self, proc: AgentProcess) -> bool:
        return proc.log_file is not None and db_of(proc.log_file).exists()

    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher:
        from agentwatch.parser.watcher import OpencodeWatcher

        path = source if isinstance(source, Path) else source.log_file
        return OpencodeWatcher(db_of(path), session_id=session_id)

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        from agentwatch.parser.opencode import parse_opencode_session

        yield from parse_opencode_session(path, session_id)
