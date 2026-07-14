"""Tests for `agentwatch.parser.watcher.CursorWatcher`.

Drives the two-tier poll (`_poll_once`) directly rather than the async
`watch()` loop, since the interesting behavior -- selective `fetch_bubbles`
refetch keyed off `composerHeaders.lastUpdatedAt` watermark deltas -- is
synchronous and side-effect-only-via-instance-state. This mirrors how
`CodexParser` is tested by calling `parse_line`/`flush` directly rather than
driving `LogWatcher.watch()` end-to-end for every case.

Fixture DB is built against the real round-4-confirmed schema (see
`test_cursor_source.py` / `cursor_source.py`'s module docstring), not the
original architecture review's wrong `conversationMap`-based guess.
"""

from __future__ import annotations

import json
import sqlite3
from unittest.mock import patch

import pytest

from agentwatch.parser import cursor_source
from agentwatch.parser.watcher import CursorWatcher

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


class _FixtureDb:
    """Thin wrapper around a real sqlite3 file connection (writable) used
    to set up / mutate the fixture DB that CursorWatcher will separately
    read via `open_readonly()`."""

    def __init__(self, path):
        self.path = path
        self.conn = sqlite3.connect(str(path))
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()

    def upsert_header(self, composer_id: str, last_updated_at: int | None) -> None:
        self.conn.execute(
            "INSERT INTO composerHeaders "
            "(composerId, workspaceId, createdAt, lastUpdatedAt, isArchived, "
            "isSubagent, recency, checkpointAt, value) "
            "VALUES (?, 'workspace-1', 0, ?, 0, 0, 0, NULL, '{}') "
            "ON CONFLICT(composerId) DO UPDATE SET lastUpdatedAt = excluded.lastUpdatedAt",
            (composer_id, last_updated_at),
        )
        self.conn.commit()

    def add_bubble(self, composer_id: str, bubble_id: str, bubble: dict) -> None:
        self.conn.execute(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            (f"bubbleId:{composer_id}:{bubble_id}", json.dumps(bubble)),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


@pytest.fixture
def db(tmp_path):
    fixture = _FixtureDb(tmp_path / "state.vscdb")
    yield fixture
    fixture.close()


class TestCursorWatcherPolling:
    def test_first_tick_emits_actions_for_populated_composer(self, db):
        db.upsert_header("c1", last_updated_at=1000)
        db.add_bubble("c1", "b1", _bubble(1, "hello", "2026-07-12T03:10:08.000Z"))
        db.add_bubble("c1", "b2", _bubble(2, "hi there", "2026-07-12T03:10:09.000Z"))

        watcher = CursorWatcher(db.path, min_blob_poll_interval=0.0)
        actions = watcher._poll_once()

        assert len(actions) == 2
        assert actions[0].incoming_message == "hello"
        assert actions[1].outgoing_data == "hi there"

    def test_empty_composer_produces_zero_spurious_actions(self, db):
        """A composer header exists (real `lastUpdatedAt`) but has no
        `bubbleId:*` rows at all -- the vestigial/empty-`conversationMap`
        real-world case. Must not raise and must not fabricate actions."""
        db.upsert_header("c-empty", last_updated_at=1000)

        watcher = CursorWatcher(db.path, min_blob_poll_interval=0.0)
        actions = watcher._poll_once()

        assert actions == []

    def test_composer_never_messaged_is_skipped(self, db):
        """`lastUpdatedAt` NULL (composer created, never sent a message) --
        must not crash on a None watermark comparison and must not poll
        bubbles for it."""
        db.upsert_header("c-draft", last_updated_at=None)

        watcher = CursorWatcher(db.path, min_blob_poll_interval=0.0)
        with patch.object(
            cursor_source, "fetch_bubbles", wraps=cursor_source.fetch_bubbles
        ) as spy:
            actions = watcher._poll_once()

        assert actions == []
        spy.assert_not_called()

    def test_second_tick_only_refetches_advanced_composer(self, db):
        """Two composers exist. Only one's `lastUpdatedAt` advances between
        tick 1 and tick 2 -- `fetch_bubbles` must only be called again for
        that one composer, asserted via call count, not just output."""
        db.upsert_header("c1", last_updated_at=1000)
        db.add_bubble("c1", "b1", _bubble(1, "hello", "2026-07-12T03:10:08.000Z"))

        db.upsert_header("c2", last_updated_at=1000)
        db.add_bubble("c2", "b1", _bubble(1, "unrelated", "2026-07-12T03:10:08.000Z"))

        watcher = CursorWatcher(db.path, min_blob_poll_interval=0.0)

        real_fetch_bubbles = cursor_source.fetch_bubbles
        with patch(
            "agentwatch.parser.watcher.fetch_bubbles", wraps=real_fetch_bubbles
        ) as spy:
            first_actions = watcher._poll_once()
            assert len(first_actions) == 2  # one bubble from each composer
            assert spy.call_count == 2  # c1 and c2 both fetched on first tick

            # No DB change: second tick should skip both (watermark unchanged).
            second_actions = watcher._poll_once()
            assert second_actions == []
            assert spy.call_count == 2

            # Only c1's watermark advances; c2 is untouched.
            db.upsert_header("c1", last_updated_at=2000)
            db.add_bubble("c1", "b2", _bubble(2, "world", "2026-07-12T03:10:12.000Z"))

            third_actions = watcher._poll_once()
            assert len(third_actions) == 1
            assert third_actions[0].outgoing_data == "world"
            # Exactly one additional fetch_bubbles call (for c1 only).
            assert spy.call_count == 3

    def test_min_blob_poll_interval_throttles_then_recovers(self, db, monkeypatch):
        """A rapid re-poll within `min_blob_poll_interval` of the last
        blob fetch is throttled (no `fetch_bubbles` call, watermark left
        un-advanced), but the delta is not lost -- once enough time has
        passed, a later tick picks it up. Uses a fake `time.monotonic()`
        clock so this is deterministic, not a real sleep."""
        db.upsert_header("c1", last_updated_at=1000)
        db.add_bubble("c1", "b1", _bubble(1, "hello", "2026-07-12T03:10:08.000Z"))

        watcher = CursorWatcher(db.path, min_blob_poll_interval=5.0)

        fake_now = {"t": 0.0}
        monkeypatch.setattr(
            "agentwatch.parser.watcher.time.monotonic", lambda: fake_now["t"]
        )

        real_fetch_bubbles = cursor_source.fetch_bubbles
        with patch(
            "agentwatch.parser.watcher.fetch_bubbles", wraps=real_fetch_bubbles
        ) as spy:
            first_actions = watcher._poll_once()
            assert len(first_actions) == 1
            assert spy.call_count == 1

            # Bump the watermark immediately -- well within the throttle
            # window, so this tick must not call fetch_bubbles again.
            db.upsert_header("c1", last_updated_at=2000)
            db.add_bubble("c1", "b2", _bubble(2, "world", "2026-07-12T03:10:12.000Z"))

            fake_now["t"] = 1.0  # 1s later, still inside the 5s throttle
            throttled_actions = watcher._poll_once()
            assert throttled_actions == []
            assert spy.call_count == 1

            fake_now["t"] = 10.0  # past the throttle window
            recovered_actions = watcher._poll_once()
            assert len(recovered_actions) == 1
            assert recovered_actions[0].outgoing_data == "world"
            assert spy.call_count == 2


class TestCursorWatcherComposerFilter:
    """`composer_id_filter` restricts polling to one composer -- needed when
    MultiLogWatcher spins up one CursorWatcher per composer (via
    cursor_discovery.py) against a state.vscdb shared by many composers, so
    independent watcher instances don't duplicate each other's actions."""

    def test_filter_only_emits_actions_for_the_named_composer(self, db):
        db.upsert_header("c1", last_updated_at=1000)
        db.add_bubble("c1", "b1", _bubble(1, "hello", "2026-07-12T03:10:08.000Z"))
        db.upsert_header("c2", last_updated_at=1000)
        db.add_bubble("c2", "b1", _bubble(1, "unrelated", "2026-07-12T03:10:08.000Z"))

        watcher = CursorWatcher(db.path, min_blob_poll_interval=0.0, composer_id_filter="c1")
        actions = watcher._poll_once()

        assert len(actions) == 1
        assert actions[0].session_id == "c1"

    def test_filter_ignores_other_composers_updating_later(self, db):
        db.upsert_header("c1", last_updated_at=1000)
        db.add_bubble("c1", "b1", _bubble(1, "hello", "2026-07-12T03:10:08.000Z"))
        db.upsert_header("c2", last_updated_at=1000)
        db.add_bubble("c2", "b1", _bubble(1, "unrelated", "2026-07-12T03:10:08.000Z"))

        watcher = CursorWatcher(db.path, min_blob_poll_interval=0.0, composer_id_filter="c1")
        first = watcher._poll_once()
        assert len(first) == 1

        # c2 advances -- filtered watcher must not pick it up.
        db.upsert_header("c2", last_updated_at=2000)
        db.add_bubble("c2", "b2", _bubble(2, "still unrelated", "2026-07-12T03:10:12.000Z"))
        second = watcher._poll_once()
        assert second == []

    def test_no_filter_preserves_original_whole_db_behavior(self, db):
        db.upsert_header("c1", last_updated_at=1000)
        db.add_bubble("c1", "b1", _bubble(1, "hello", "2026-07-12T03:10:08.000Z"))
        db.upsert_header("c2", last_updated_at=1000)
        db.add_bubble("c2", "b1", _bubble(1, "also here", "2026-07-12T03:10:08.000Z"))

        watcher = CursorWatcher(db.path, min_blob_poll_interval=0.0)
        actions = watcher._poll_once()

        assert len(actions) == 2


class TestCursorWatcherReadOnly:
    def test_poll_never_writes_to_the_db(self, db):
        """`_poll_once()` must only ever open the DB via `open_readonly()`
        -- assert this by opening a second, independent read-only
        connection afterward and confirming the row count/content is
        unchanged (no write side effects leaked through)."""
        db.upsert_header("c1", last_updated_at=1000)
        db.add_bubble("c1", "b1", _bubble(1, "hello", "2026-07-12T03:10:08.000Z"))

        watcher = CursorWatcher(db.path, min_blob_poll_interval=0.0)
        watcher._poll_once()

        conn = sqlite3.connect(str(db.path))
        try:
            row_count = conn.execute("SELECT COUNT(*) FROM cursorDiskKV").fetchone()[0]
        finally:
            conn.close()
        assert row_count == 1  # only the one bubble this test inserted
