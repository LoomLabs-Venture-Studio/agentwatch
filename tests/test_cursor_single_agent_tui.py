"""Tests for single-agent ``agentwatch watch --log <state.vscdb>`` (live TUI).

PLAYBOOK Sprint 7 explicitly left this out of scope: "Cursor's poll-based,
composer-picking data model doesn't fit ``AgentWatchApp``'s current
single-``LogWatcher`` assumption." This closes that gap by teaching
``AgentWatchApp.on_mount`` a ``.vscdb`` branch, following the same shape as
the existing ``.md`` -> ``AiderLogWatcher`` dispatch from Sprint 7's Aider
Phase 3.

Fixture DBs use the same real, round-4-confirmed ``composerHeaders`` /
``cursorDiskKV`` schema ``test_cursor_watcher.py`` / ``test_cursor_source.py``
/ ``test_multi_log_watcher_cursor.py`` already build against -- not guessed.
"""

from __future__ import annotations

import json
import sqlite3

from agentwatch.parser.watcher import AiderLogWatcher, CursorWatcher, LogWatcher
from agentwatch.ui.app import AgentWatchApp

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


def _bubble(bubble_type: int, text: str, created_at: str) -> dict:
    return {
        "type": bubble_type,
        "text": text,
        "tokenCount": {"inputTokens": 0, "outputTokens": 0},
        "toolResults": [],
        "createdAt": created_at,
    }


def _build_db(path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    return conn


def _add_composer(
    conn: sqlite3.Connection,
    composer_id: str,
    last_updated_at,
    *,
    unified_mode: str = "agent",
    is_archived: bool = False,
    is_draft: bool = False,
) -> None:
    value = json.dumps({"unifiedMode": unified_mode, "isDraft": is_draft})
    conn.execute(
        "INSERT INTO composerHeaders "
        "(composerId, workspaceId, createdAt, lastUpdatedAt, isArchived, "
        "isSubagent, recency, checkpointAt, value) "
        "VALUES (?, 'ws-1', 0, ?, ?, 0, 0, NULL, ?)",
        (composer_id, last_updated_at, int(is_archived), value),
    )
    conn.commit()


def _add_bubble(conn: sqlite3.Connection, composer_id: str, bubble_id: str, bubble: dict) -> None:
    conn.execute(
        "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
        (f"bubbleId:{composer_id}:{bubble_id}", json.dumps(bubble)),
    )
    conn.commit()


class TestVscdbDispatchConstructsCursorWatcher:
    """A ``.vscdb`` --log path must build a real ``CursorWatcher``, not fall
    through to a plain ``LogWatcher`` (which can't parse SQLite) or an
    ``AiderLogWatcher`` (which is for Markdown)."""

    async def test_vscdb_path_builds_cursor_watcher(self, tmp_path):
        db_path = tmp_path / "state.vscdb"
        conn = _build_db(db_path)
        _add_composer(conn, "c1", last_updated_at=1000)
        _add_bubble(conn, "c1", "b1", _bubble(1, "hello", "2026-07-12T03:10:08.000Z"))
        conn.close()

        app = AgentWatchApp(log_path=db_path, security_mode=False)
        async with app.run_test():
            assert isinstance(app.watcher, CursorWatcher)
            assert not isinstance(app.watcher, LogWatcher)
            assert not isinstance(app.watcher, AiderLogWatcher)

    async def test_md_path_still_builds_aider_watcher(self, tmp_path):
        """Regression guard: adding the .vscdb branch must not disturb the
        existing .md -> AiderLogWatcher dispatch it was modeled on."""
        md_path = tmp_path / ".aider.chat.history.md"
        md_path.write_text("# aider chat started at 2026-07-14 10:00:00\n")

        app = AgentWatchApp(log_path=md_path, security_mode=False)
        async with app.run_test():
            assert isinstance(app.watcher, AiderLogWatcher)

    async def test_jsonl_path_still_builds_plain_log_watcher(self, tmp_path):
        """Regression guard: non-.md/.vscdb paths keep using LogWatcher."""
        log_path = tmp_path / "session.jsonl"
        log_path.write_text("")

        app = AgentWatchApp(log_path=log_path, security_mode=False)
        async with app.run_test():
            assert isinstance(app.watcher, LogWatcher)


class TestAutoComposerSelection:
    """No explicit composer/session is passed for single-agent watch -- the
    most-recently-active agent-mode composer must be auto-picked, mirroring
    ``cursor_source.select_latest_agent_composer`` / ``parse_file()``'s
    ``.vscdb`` dispatch for the one-shot check/security-scan path."""

    async def test_picks_the_most_recently_updated_agent_mode_composer(self, tmp_path):
        db_path = tmp_path / "state.vscdb"
        conn = _build_db(db_path)
        _add_composer(conn, "older", last_updated_at=1000)
        _add_bubble(conn, "older", "b1", _bubble(1, "old convo", "2026-07-12T03:10:08.000Z"))
        _add_composer(conn, "newer", last_updated_at=2000)
        _add_bubble(conn, "newer", "b1", _bubble(1, "new convo", "2026-07-12T04:10:08.000Z"))
        conn.close()

        app = AgentWatchApp(log_path=db_path, security_mode=False)
        async with app.run_test():
            assert isinstance(app.watcher, CursorWatcher)
            assert app.watcher.composer_id_filter == "newer"

    async def test_excludes_non_agent_mode_composer(self, tmp_path):
        db_path = tmp_path / "state.vscdb"
        conn = _build_db(db_path)
        _add_composer(conn, "ask-mode", last_updated_at=5000, unified_mode="ask")
        _add_bubble(
            conn, "ask-mode", "b1", _bubble(1, "not agent mode", "2026-07-12T03:10:08.000Z")
        )
        _add_composer(conn, "agent-mode", last_updated_at=1000, unified_mode="agent")
        _add_bubble(conn, "agent-mode", "b1", _bubble(1, "agent mode", "2026-07-12T03:10:08.000Z"))
        conn.close()

        app = AgentWatchApp(log_path=db_path, security_mode=False)
        async with app.run_test():
            assert app.watcher.composer_id_filter == "agent-mode"

    async def test_excludes_empty_state_draft_composer(self, tmp_path):
        """Regression guard for the real Sprint 7 phantom-composer bug:
        Cursor's placeholder 'empty-state-draft' composer carries a real,
        newer lastUpdatedAt but zero bubbles and isDraft=True -- it must
        never be auto-picked ahead of a real conversation."""
        db_path = tmp_path / "state.vscdb"
        conn = _build_db(db_path)
        _add_composer(conn, "real", last_updated_at=1000)
        _add_bubble(conn, "real", "b1", _bubble(1, "real convo", "2026-07-12T03:10:08.000Z"))
        _add_composer(conn, "empty-state-draft", last_updated_at=9999, is_draft=True)
        conn.close()

        app = AgentWatchApp(log_path=db_path, security_mode=False)
        async with app.run_test():
            assert app.watcher.composer_id_filter == "real"


class TestNoMatchingComposerIsGraceful:
    """Missing DB / no qualifying composer must produce an idle dashboard,
    not a crash -- same bar as every other agent-type error path."""

    async def test_no_agent_mode_composer_does_not_crash(self, tmp_path):
        db_path = tmp_path / "state.vscdb"
        conn = _build_db(db_path)
        _add_composer(conn, "only-ask", last_updated_at=1000, unified_mode="ask")
        conn.close()

        app = AgentWatchApp(log_path=db_path, security_mode=False)
        async with app.run_test():
            assert app.watcher is None
            # Refresh loop must still run cleanly against an empty buffer.
            app.refresh_display()

    async def test_only_draft_composer_does_not_crash(self, tmp_path):
        db_path = tmp_path / "state.vscdb"
        conn = _build_db(db_path)
        _add_composer(conn, "empty-state-draft", last_updated_at=1000, is_draft=True)
        conn.close()

        app = AgentWatchApp(log_path=db_path, security_mode=False)
        async with app.run_test():
            assert app.watcher is None

    async def test_missing_db_file_does_not_crash(self, tmp_path):
        """The DB doesn't exist on disk at all (e.g. a stale --log path) --
        open_readonly() will raise; this must be caught, not propagated."""
        missing_path = tmp_path / "does-not-exist.vscdb"

        app = AgentWatchApp(log_path=missing_path, security_mode=False)
        async with app.run_test():
            assert app.watcher is None
            app.refresh_display()

    async def test_empty_db_no_composers_at_all_does_not_crash(self, tmp_path):
        db_path = tmp_path / "state.vscdb"
        conn = _build_db(db_path)
        conn.close()

        app = AgentWatchApp(log_path=db_path, security_mode=False)
        async with app.run_test():
            assert app.watcher is None


class TestHeadlessPilotStartsCleanly:
    """Full headless Textual pilot run against a real fixture DB -- the
    same bar test_multi_app_refresh.py already established for TUI-level
    coverage in this codebase."""

    async def test_app_mounts_and_renders_with_real_composer(self, tmp_path):
        db_path = tmp_path / "state.vscdb"
        conn = _build_db(db_path)
        _add_composer(conn, "c1", last_updated_at=1000)
        _add_bubble(conn, "c1", "b1", _bubble(1, "hello", "2026-07-12T03:10:08.000Z"))
        _add_bubble(conn, "c1", "b2", _bubble(2, "hi there", "2026-07-12T03:10:09.000Z"))
        conn.close()

        app = AgentWatchApp(log_path=db_path, security_mode=True)
        async with app.run_test() as pilot:
            await pilot.pause()
            # The initial poll (CursorWatcher.watch()'s synchronous first
            # tick) runs inside the background worker -- give it a beat to
            # land, then force a refresh and confirm no exception surfaced.
            await pilot.pause()
            app.refresh_display()
            assert app._buffer is not None
