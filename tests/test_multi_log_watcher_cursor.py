"""Tests for `MultiLogWatcher`'s Cursor wiring (PLAYBOOK Sprint 7).

Cursor composers share one real `state.vscdb` per install, but
`MultiLogWatcher` keys its internal tracking dicts (`_process_meta`/
`_active_files`/`watchers`) by `AgentProcess.log_file` -- a real path for
every other agent type. Cursor entries instead carry a synthetic,
never-created `log_file` (see `cursor_discovery.py::_cursor_synthetic_log_key`)
and the real DB path in `cursor_db_path`. These tests exercise that wiring
end to end: `_has_live_log()`'s cursor-aware liveness check, `_find_all_logs()`
including cursor entries despite their non-`.jsonl` synthetic suffix, and
`watch()` actually constructing a `CursorWatcher` (not a `LogWatcher`) and
filtering it to the right composer.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3

from agentwatch.discovery import AgentProcess
from agentwatch.parser.watcher import CursorWatcher, LogWatcher, MultiLogWatcher

SCHEMA_SQL = """
CREATE TABLE composerHeaders (
    composerId TEXT PRIMARY KEY,
    workspaceId TEXT,
    createdAt INTEGER,
    lastUpdatedAt INTEGER,
    isArchived INTEGER,
    isSubagent INTEGER,
    recency INTEGER,
    checkpointAt INTEGER,
    value TEXT
);
CREATE TABLE cursorDiskKV (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def _build_db(path, composer_id: str, text: str) -> None:
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(SCHEMA_SQL)
        conn.execute(
            "INSERT INTO composerHeaders "
            "(composerId, workspaceId, createdAt, lastUpdatedAt, isArchived, "
            "isSubagent, recency, checkpointAt, value) "
            "VALUES (?, 'ws-1', 0, 1000, 0, 0, 0, NULL, ?)",
            (composer_id, json.dumps({"unifiedMode": "agent"})),
        )
        conn.execute(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            (
                f"bubbleId:{composer_id}:b1",
                json.dumps(
                    {
                        "type": 1,
                        "text": text,
                        "tokenCount": {"inputTokens": 0, "outputTokens": 0},
                        "toolResults": [],
                        "createdAt": "2026-07-14T00:00:00.000Z",
                    }
                ),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _cursor_proc(db_path, composer_id: str, pid: int) -> AgentProcess:
    return AgentProcess(
        pid=pid,
        agent_type="cursor",
        working_directory=db_path.parent,
        log_file=db_path.with_name(f"state__cursor__{composer_id}.vscdb"),
        session_id=composer_id,
        command="cursor (agent)",
        cursor_db_path=db_path,
    )


class TestFindAllLogsIncludesCursor:
    def test_cursor_entry_surfaces_despite_non_jsonl_suffix(self, tmp_path):
        db_path = tmp_path / "state.vscdb"
        _build_db(db_path, "c1", "hi")
        proc = _cursor_proc(db_path, "c1", pid=111)

        watcher = MultiLogWatcher.from_processes([proc])
        logs = watcher._find_all_logs()

        assert proc.log_file in logs

    def test_stopped_cursor_entry_excluded(self, tmp_path):
        db_path = tmp_path / "state.vscdb"
        _build_db(db_path, "c1", "hi")
        proc = _cursor_proc(db_path, "c1", pid=111)
        proc.command = "(stopped)"

        watcher = MultiLogWatcher(paths=[])
        watcher._process_mode = True
        watcher._process_meta[proc.log_file] = proc

        assert proc.log_file not in watcher._find_all_logs()


class TestFromProcessesLiveness:
    def test_cursor_entry_added_when_real_db_exists(self, tmp_path):
        db_path = tmp_path / "state.vscdb"
        _build_db(db_path, "c1", "hi")
        proc = _cursor_proc(db_path, "c1", pid=111)

        watcher = MultiLogWatcher.from_processes([proc])
        assert proc.log_file in watcher._process_meta

    def test_cursor_entry_skipped_when_real_db_missing(self, tmp_path):
        missing_db = tmp_path / "does-not-exist.vscdb"
        proc = _cursor_proc(missing_db, "c1", pid=111)

        watcher = MultiLogWatcher.from_processes([proc])
        assert proc.log_file not in watcher._process_meta

    def test_refresh_processes_marks_cursor_entry_stopped(self, tmp_path):
        db_path = tmp_path / "state.vscdb"
        _build_db(db_path, "c1", "hi")
        proc = _cursor_proc(db_path, "c1", pid=111)

        watcher = MultiLogWatcher.from_processes([proc])
        watcher.refresh_processes([])  # process no longer present

        assert watcher._process_meta[proc.log_file].command == "(stopped)"
        assert watcher._process_meta[proc.log_file].cursor_db_path == db_path


class TestWatchConstructsCursorWatcher:
    async def test_cursor_process_gets_a_cursor_watcher_not_a_log_watcher(self, tmp_path):
        db_path = tmp_path / "state.vscdb"
        _build_db(db_path, "c1", "hello from cursor")
        proc = _cursor_proc(db_path, "c1", pid=111)

        watcher = MultiLogWatcher.from_processes([proc], poll_interval=0.01)
        gen = watcher.watch()
        try:
            event_type, log_path = await asyncio.wait_for(gen.__anext__(), timeout=2)
            assert event_type == "agent_added"
            assert log_path == proc.log_file
            assert isinstance(watcher.watchers[proc.log_file], CursorWatcher)
            assert not isinstance(watcher.watchers[proc.log_file], LogWatcher)

            event_type, (action, path) = await asyncio.wait_for(gen.__anext__(), timeout=2)
            assert event_type == "action"
            assert path == proc.log_file
            assert action.session_id == "c1"
            assert action.incoming_message == "hello from cursor"
        finally:
            await gen.aclose()

    async def test_cursor_watcher_is_filtered_to_its_own_composer(self, tmp_path):
        """Two AgentProcess entries share one db_path (two composers in the
        same Cursor install) -- each must only ever see its own composer's
        actions, never the other's."""
        db_path = tmp_path / "state.vscdb"
        conn = sqlite3.connect(str(db_path))
        try:
            conn.executescript(SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()
        _append_composer(db_path, "c1", "from c1")
        _append_composer(db_path, "c2", "from c2")

        proc1 = _cursor_proc(db_path, "c1", pid=111)
        proc2 = _cursor_proc(db_path, "c2", pid=222)

        watcher = MultiLogWatcher.from_processes([proc1, proc2], poll_interval=0.01)
        gen = watcher.watch()
        seen_messages: dict[str, str] = {}
        try:
            deadline = asyncio.get_event_loop().time() + 3
            while len(seen_messages) < 2 and asyncio.get_event_loop().time() < deadline:
                event_type, data = await asyncio.wait_for(gen.__anext__(), timeout=2)
                if event_type == "action":
                    action, _path = data
                    seen_messages[action.session_id] = action.incoming_message
        finally:
            await gen.aclose()

        assert seen_messages == {"c1": "from c1", "c2": "from c2"}


def _append_composer(db_path, composer_id: str, text: str) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "INSERT INTO composerHeaders "
            "(composerId, workspaceId, createdAt, lastUpdatedAt, isArchived, "
            "isSubagent, recency, checkpointAt, value) "
            "VALUES (?, 'ws-1', 0, 1000, 0, 0, 0, NULL, ?)",
            (composer_id, json.dumps({"unifiedMode": "agent"})),
        )
        conn.execute(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            (
                f"bubbleId:{composer_id}:b1",
                json.dumps(
                    {
                        "type": 1,
                        "text": text,
                        "tokenCount": {"inputTokens": 0, "outputTokens": 0},
                        "toolResults": [],
                        "createdAt": "2026-07-14T00:00:00.000Z",
                    }
                ),
            ),
        )
        conn.commit()
    finally:
        conn.close()
