"""Tests for `agentwatch.parser.cursor_source`.

Covers the read-only Cursor `state.vscdb` access layer: `open_readonly`,
`fetch_composer_headers`, `fetch_bubbles`, `fetch_checkpoint`, and the
bubble-to-`Action` mapping (`bubble_to_action`, `classify_cursor_tool`).

The fixture DB below is hand-built against the REAL schema confirmed by
investigation round 4 (`bubbleId:<composerId>:<bubbleId>` rows in
`cursorDiskKV`, real `composerHeaders` columns) -- not the original
architecture review's wrong `conversationMap`-based guess. See
`cursor_source.py`'s module docstring for the schema-correction history.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from agentwatch.parser.cursor_source import (
    bubble_to_action,
    classify_cursor_tool,
    fetch_bubbles,
    fetch_checkpoint,
    fetch_composer_headers,
    open_readonly,
    parse_cursor_session,
    select_latest_agent_composer,
)
from agentwatch.parser.models import ToolType

# ---------------------------------------------------------------------------
# Fixture DB builder
# ---------------------------------------------------------------------------

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


def build_fixture_db(path) -> None:
    """Build a hand-crafted fixture DB matching the real round-4 schema.

    Composers:
    - ``composer-populated``: has a user bubble + an assistant bubble, a
      checkpoint with a populated ``files`` list, real ``lastUpdatedAt``.
    - ``composer-empty``: a header row exists but no ``bubbleId:*`` rows at
      all -- the "vestigial `conversationMap`" real-world case (round 4:
      composers exist with real timestamps but zero bubble content).
    """
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(SCHEMA_SQL)

        conn.execute(
            "INSERT INTO composerHeaders "
            "(composerId, workspaceId, createdAt, lastUpdatedAt, isArchived, "
            "isSubagent, recency, checkpointAt, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "composer-populated",
                "workspace-1",
                1000,
                2000,
                0,
                0,
                1,
                None,
                json.dumps({"unifiedMode": "agent", "forceMode": "edit"}),
            ),
        )
        conn.execute(
            "INSERT INTO composerHeaders "
            "(composerId, workspaceId, createdAt, lastUpdatedAt, isArchived, "
            "isSubagent, recency, checkpointAt, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "composer-empty",
                "workspace-1",
                500,
                None,
                0,
                0,
                2,
                None,
                json.dumps({"unifiedMode": "chat", "forceMode": "edit"}),
            ),
        )

        user_bubble = {
            "type": 1,
            "text": "fix it",
            "richText": "<p>fix it</p>",
            "tokenCount": {"inputTokens": 0, "outputTokens": 0},
            "modelInfo": {"modelName": "composer-2.5"},
            "checkpointId": "cp-1",
            "toolResults": [],
            "createdAt": "2026-07-12T03:10:08.877Z",
        }
        assistant_bubble = {
            "type": 2,
            "text": "Fixed the bug in foo.py.",
            "turnDurationMs": 1331,
            "tokenCount": {"inputTokens": 0, "outputTokens": 0},
            "modelInfo": None,
            "toolResults": [],
            "createdAt": "2026-07-12T03:10:11.131Z",
        }
        conn.execute(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            ("bubbleId:composer-populated:bubble-a", json.dumps(user_bubble)),
        )
        conn.execute(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            ("bubbleId:composer-populated:bubble-b", json.dumps(assistant_bubble)),
        )

        checkpoint = {
            "files": [{"path": "foo.py"}],
            "nonExistentFiles": [],
            "newlyCreatedFolders": [],
            "activeInlineDiffs": [],
        }
        conn.execute(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            ("checkpointId:composer-populated:cp-1", json.dumps(checkpoint)),
        )

        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def fixture_db(tmp_path):
    db_path = tmp_path / "state.vscdb"
    build_fixture_db(db_path)
    return db_path


# ---------------------------------------------------------------------------
# open_readonly
# ---------------------------------------------------------------------------


class TestOpenReadonly:
    def test_read_only_connection_can_query(self, fixture_db):
        conn = open_readonly(fixture_db)
        try:
            rows = conn.execute("SELECT composerId FROM composerHeaders").fetchall()
            assert len(rows) == 2
        finally:
            conn.close()

    def test_read_only_connection_rejects_insert(self, fixture_db):
        """Replicates round 1's empirical proof that `mode=ro` really is
        enforced (not just assumed): an explicit write raises
        `sqlite3.OperationalError`, not a silent no-op."""
        conn = open_readonly(fixture_db)
        try:
            with pytest.raises(sqlite3.OperationalError):
                conn.execute(
                    "INSERT INTO composerHeaders (composerId) VALUES ('should-fail')"
                )
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# fetch_composer_headers
# ---------------------------------------------------------------------------


class TestFetchComposerHeaders:
    def test_returns_all_composers_keyed_by_id(self, fixture_db):
        conn = open_readonly(fixture_db)
        try:
            headers = fetch_composer_headers(conn)
        finally:
            conn.close()

        assert set(headers.keys()) == {"composer-populated", "composer-empty"}
        assert headers["composer-populated"]["lastUpdatedAt"] == 2000
        assert headers["composer-populated"]["workspaceId"] == "workspace-1"
        assert headers["composer-populated"]["unifiedMode"] == "agent"

    def test_null_last_updated_at_preserved(self, fixture_db):
        """A composer that was created but never had a message sent has a
        real, nullable `lastUpdatedAt` -- must not be coerced to 0."""
        conn = open_readonly(fixture_db)
        try:
            headers = fetch_composer_headers(conn)
        finally:
            conn.close()

        assert headers["composer-empty"]["lastUpdatedAt"] is None


# ---------------------------------------------------------------------------
# fetch_bubbles
# ---------------------------------------------------------------------------


class TestFetchBubbles:
    def test_returns_bubbles_ordered_by_created_at(self, fixture_db):
        conn = open_readonly(fixture_db)
        try:
            bubbles = fetch_bubbles(conn, "composer-populated")
        finally:
            conn.close()

        assert len(bubbles) == 2
        assert bubbles[0]["type"] == 1
        assert bubbles[0]["text"] == "fix it"
        assert bubbles[1]["type"] == 2
        assert bubbles[1]["text"] == "Fixed the bug in foo.py."

    def test_empty_composer_produces_no_bubbles(self, fixture_db):
        """The vestigial/empty `conversationMap` real-world case: a
        composer header exists, but zero `bubbleId:*` rows for it."""
        conn = open_readonly(fixture_db)
        try:
            bubbles = fetch_bubbles(conn, "composer-empty")
        finally:
            conn.close()

        assert bubbles == []

    def test_unknown_composer_produces_no_bubbles(self, fixture_db):
        conn = open_readonly(fixture_db)
        try:
            bubbles = fetch_bubbles(conn, "does-not-exist")
        finally:
            conn.close()

        assert bubbles == []


# ---------------------------------------------------------------------------
# fetch_checkpoint
# ---------------------------------------------------------------------------


class TestFetchCheckpoint:
    def test_fetches_populated_checkpoint(self, fixture_db):
        conn = open_readonly(fixture_db)
        try:
            checkpoint = fetch_checkpoint(conn, "composer-populated", "cp-1")
        finally:
            conn.close()

        assert checkpoint is not None
        assert checkpoint["files"] == [{"path": "foo.py"}]

    def test_missing_checkpoint_returns_none(self, fixture_db):
        conn = open_readonly(fixture_db)
        try:
            checkpoint = fetch_checkpoint(conn, "composer-populated", "does-not-exist")
        finally:
            conn.close()

        assert checkpoint is None


# ---------------------------------------------------------------------------
# classify_cursor_tool
# ---------------------------------------------------------------------------


class TestClassifyCursorTool:
    def test_empty_tool_results_is_unknown(self):
        assert classify_cursor_tool({"toolResults": []}) == ToolType.UNKNOWN

    def test_missing_tool_results_is_unknown(self):
        assert classify_cursor_tool({}) == ToolType.UNKNOWN

    def test_non_list_tool_results_is_unknown(self):
        assert classify_cursor_tool({"toolResults": "not-a-list"}) == ToolType.UNKNOWN

    def test_recognizable_name_field_delegates_to_classify_tool(self):
        # Speculative shape -- toolResults' populated form was never
        # observed in any investigation round, but if a `name` field shows
        # up, it should be classified via the shared substring rules.
        bubble = {"toolResults": [{"name": "read_file"}]}
        assert classify_cursor_tool(bubble) == ToolType.READ

    def test_unrecognizable_entry_shape_is_unknown(self):
        bubble = {"toolResults": [{"somethingElse": 1}]}
        assert classify_cursor_tool(bubble) == ToolType.UNKNOWN


# ---------------------------------------------------------------------------
# bubble_to_action
# ---------------------------------------------------------------------------


class TestBubbleToAction:
    def test_user_bubble_maps_to_incoming_message(self, fixture_db):
        conn = open_readonly(fixture_db)
        try:
            bubbles = fetch_bubbles(conn, "composer-populated")
            checkpoint = fetch_checkpoint(conn, "composer-populated", "cp-1")
        finally:
            conn.close()

        user_bubble = bubbles[0]
        action = bubble_to_action(user_bubble, "composer-populated", checkpoint)

        assert action.incoming_message == "fix it"
        assert action.outgoing_data is None
        assert action.session_id == "composer-populated"
        assert action.file_path == "foo.py"
        assert action.raw is user_bubble

    def test_assistant_bubble_maps_to_outgoing_data(self, fixture_db):
        conn = open_readonly(fixture_db)
        try:
            bubbles = fetch_bubbles(conn, "composer-populated")
        finally:
            conn.close()

        assistant_bubble = bubbles[1]
        action = bubble_to_action(assistant_bubble, "composer-populated")

        assert action.outgoing_data == "Fixed the bug in foo.py."
        assert action.incoming_message is None
        assert action.duration_ms == 1331

    def test_token_count_zero_is_not_estimated(self, fixture_db):
        """`tokenCount` reads {0, 0} for the composer-2.5 model in every
        real sample observed -- this must NOT be filled in with any
        estimated-cost fallback. Leave tokens_in/tokens_out/cost_usd at
        0/0/0.0 exactly."""
        conn = open_readonly(fixture_db)
        try:
            bubbles = fetch_bubbles(conn, "composer-populated")
        finally:
            conn.close()

        action = bubble_to_action(bubbles[1], "composer-populated")
        assert action.tokens_in == 0
        assert action.tokens_out == 0
        assert action.cost_usd == 0.0

    def test_no_checkpoint_leaves_file_path_none(self, fixture_db):
        conn = open_readonly(fixture_db)
        try:
            bubbles = fetch_bubbles(conn, "composer-populated")
        finally:
            conn.close()

        action = bubble_to_action(bubbles[0], "composer-populated", checkpoint=None)
        assert action.file_path is None

    def test_unknown_type_still_produces_an_action(self):
        bubble = {"type": 99, "text": "", "createdAt": "2026-07-12T03:10:08.877Z"}
        action = bubble_to_action(bubble, "composer-x")
        assert action.tool_name == "unknown_bubble"
        assert action.incoming_message is None
        assert action.outgoing_data is None


# ---------------------------------------------------------------------------
# select_latest_agent_composer / parse_cursor_session
#
# Separate fixture DB (not `fixture_db` above) with multiple composers of
# varying mode/archived/draft/timestamp status, matching the real shape
# confirmed via a live smoke test against this machine's Cursor install
# (PLAYBOOK Sprint 7, 2026-07-14) that found the real `empty-state-draft`
# case.
# ---------------------------------------------------------------------------


def build_multi_composer_db(path) -> None:
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(SCHEMA_SQL)

        def insert_header(composer_id, last_updated_at, value_extra, archived=0):
            value = {"unifiedMode": "agent", "forceMode": "edit", **value_extra}
            conn.execute(
                "INSERT INTO composerHeaders "
                "(composerId, workspaceId, createdAt, lastUpdatedAt, isArchived, "
                "isSubagent, recency, checkpointAt, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    composer_id, "workspace-1", 1000, last_updated_at,
                    archived, 0, 1, None, json.dumps(value),
                ),
            )

        # The real conversation -- oldest lastUpdatedAt of the qualifying set.
        insert_header("c-real", 1000, {})
        conn.execute(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            (
                "bubbleId:c-real:b1",
                json.dumps(
                    {
                        "type": 1,
                        "text": "hello",
                        "tokenCount": {"inputTokens": 0, "outputTokens": 0},
                        "toolResults": [],
                        "createdAt": "2026-07-12T03:10:08.000Z",
                    }
                ),
            ),
        )

        # Newer chat-mode composer -- must never be auto-picked.
        insert_header("c-chat", 2000, {"unifiedMode": "chat"})

        # Newer archived agent composer -- must never be auto-picked.
        insert_header("c-archived", 3000, {}, archived=1)

        # Newest of all, but a draft with zero bubbles -- the real bug found
        # live: without isDraft filtering this wins the "most recent" pick
        # and produces zero actions.
        insert_header("empty-state-draft", 9999, {"isDraft": True})

        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def multi_composer_db(tmp_path):
    db_path = tmp_path / "state.vscdb"
    build_multi_composer_db(db_path)
    return db_path


class TestSelectLatestAgentComposer:
    def test_picks_real_composer_over_newer_draft(self, multi_composer_db):
        conn = open_readonly(multi_composer_db)
        try:
            headers = fetch_composer_headers(conn)
        finally:
            conn.close()

        assert select_latest_agent_composer(headers) == "c-real"

    def test_no_qualifying_composer_returns_none(self):
        headers = {
            "c1": {"unifiedMode": "chat", "isArchived": False, "lastUpdatedAt": 100},
            "c2": {"unifiedMode": "agent", "isArchived": True, "lastUpdatedAt": 200},
            "c3": {"unifiedMode": "agent", "isArchived": False, "lastUpdatedAt": None},
            "c4": {
                "unifiedMode": "agent", "isArchived": False,
                "isDraft": True, "lastUpdatedAt": 300,
            },
        }
        assert select_latest_agent_composer(headers) is None


class TestParseCursorSession:
    def test_auto_pick_returns_real_composer_actions(self, multi_composer_db):
        actions = parse_cursor_session(multi_composer_db)
        assert len(actions) == 1
        assert actions[0].session_id == "c-real"
        assert actions[0].incoming_message == "hello"

    def test_explicit_composer_id_bypasses_auto_pick(self, multi_composer_db):
        actions = parse_cursor_session(multi_composer_db, composer_id="c-chat")
        assert actions == []  # c-chat has a header but zero bubbles

    def test_unknown_composer_id_returns_empty(self, multi_composer_db):
        assert parse_cursor_session(multi_composer_db, composer_id="does-not-exist") == []

    def test_no_qualifying_composer_returns_empty(self, tmp_path):
        db_path = tmp_path / "empty.vscdb"
        conn = sqlite3.connect(str(db_path))
        try:
            conn.executescript(SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()

        assert parse_cursor_session(db_path) == []
