"""opencode SQLite parsing, watching and discovery.

tests/fixtures/opencode_session.db holds two real opencode 1.18.34 sessions
(scrubbed: home and scratch paths -> /home/user/...):

- BOARD: the board's 2026-10-01 capture -- read, write, bash, failed read.
- EDIT: Sprint 26's live run -- read, edit, bash, failed read.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from agentwatch import agents
from agentwatch.agents.opencode import OpencodeAdapter, db_of, session_key
from agentwatch.detectors.security.secret_scanner import (
    SecretLeakScanner,
    extract_scannable_content,
)
from agentwatch.discovery import AgentProcess, match_process_adapter
from agentwatch.parser.logs import (
    LogUnreadableError,
    UnsupportedLogFormatError,
    ensure_supported_log,
    parse_file,
)
from agentwatch.parser.models import ActionBuffer, ToolType
from agentwatch.parser.opencode import latest_session, message_actions, open_readonly
from agentwatch.parser.watcher import MultiLogWatcher, OpencodeWatcher

FIXTURE = Path(__file__).parent / "fixtures" / "opencode_session.db"
BOARD = "ses_f08d09377ffeC40l8L5VMp2PzY"
EDIT = "ses_efd367219ffeGpoiA57zp53xr5"


def _tools(actions):
    return [a for a in actions if a.tool_name not in ("user_message", "text_output")]


@pytest.fixture
def db(tmp_path):
    """A writable copy, so tests can append rows; the fixture stays untouched."""
    path = tmp_path / "opencode.db"
    shutil.copy(FIXTURE, path)
    return path


class TestParse:
    def test_board_session_actions(self):
        actions = list(parse_file(FIXTURE, session_id=BOARD))
        assert [a.tool_name for a in actions] == [
            "user_message", "read", "write", "bash", "read", "text_output",
        ]
        assert all(a.session_id == BOARD for a in actions)

    def test_user_prompt_is_incoming_message(self):
        user = list(parse_file(FIXTURE, session_id=BOARD))[0]
        assert "run python3 --version" in user.incoming_message
        assert user.tool_type == ToolType.UNKNOWN

    def test_read(self):
        read = _tools(parse_file(FIXTURE, session_id=BOARD))[0]
        assert read.tool_type == ToolType.READ
        assert read.success
        assert read.file_path == "/home/user/aw-test/notes.txt"
        assert "1: hello" in read.raw["content"]
        assert read.duration_ms == 20

    def test_write_is_secret_scanned(self):
        write = _tools(parse_file(FIXTURE, session_id=BOARD))[1]
        assert write.tool_type == ToolType.WRITE
        assert write.file_path == "/home/user/aw-test/notes.txt"
        assert ("hello world", "file_write", write.file_path) in extract_scannable_content(write)

    def test_edit_is_secret_scanned(self):
        edit = _tools(parse_file(FIXTURE, session_id=EDIT))[1]
        assert edit.tool_name == "edit"
        assert edit.tool_type == ToolType.EDIT
        assert edit.file_path == "/home/user/aw-test2/notes.txt"
        assert edit.raw["input"] == {"content": "hello world"}
        assert edit.raw["content"] == "Edit applied successfully."

    def test_bash(self):
        bash = _tools(parse_file(FIXTURE, session_id=BOARD))[2]
        assert bash.tool_type == ToolType.BASH
        assert bash.command == "python3 --version"
        assert bash.success
        assert bash.raw["content"] == "Python 3.14.6\n"

    def test_failed_read(self):
        for sid, home in ((BOARD, "aw-test"), (EDIT, "aw-test2")):
            failed = _tools(parse_file(FIXTURE, session_id=sid))[3]
            assert failed.tool_type == ToolType.READ
            assert failed.success is False
            assert failed.error_message == f"File not found: /home/user/{home}/missing.txt"

    def test_bash_nonzero_exit_fails(self):
        conn = open_readonly(FIXTURE)
        (data,) = conn.execute(
            "SELECT data FROM part WHERE session_id = ? AND data LIKE '%\"tool\":\"bash\"%'",
            (BOARD,),
        ).fetchone()
        conn.close()
        part = json.loads(data)
        part["state"]["metadata"]["exit"] = 2
        [action] = message_actions({"role": "assistant"}, [part], BOARD)
        assert action.success is False
        assert action.error_message == "exit code 2"

    def test_missing_timestamps_are_none(self):
        # Never stamped with datetime.now() (#44).
        part = {"type": "tool", "tool": "read", "state": {"status": "completed", "input": {}}}
        [tool] = message_actions({"role": "assistant"}, [part], BOARD)
        text = {"type": "text", "text": "hi"}
        [prompt] = message_actions({"role": "user", "time": {}}, [text], BOARD)
        assert tool.timestamp is None and prompt.timestamp is None

    def test_step_tokens_on_first_action(self):
        actions = list(parse_file(FIXTURE, session_id=BOARD))
        read = actions[1]
        assert (read.tokens_in, read.tokens_out, read.cache_read_tokens) == (8174, 38, 1942)
        final = actions[-1]
        assert final.outgoing_data.startswith('notes.txt now says "hello world"')
        assert (final.tokens_in, final.tokens_out) == (68, 33)
        assert sum(a.tokens_in for a in actions) == 8456  # session.tokens_input

    def test_default_is_latest_session(self):
        assert {a.session_id for a in parse_file(FIXTURE)} == {EDIT}


class TestSessionSelection:
    def test_by_directory(self):
        conn = open_readonly(FIXTURE)
        assert latest_session(conn, Path("/home/user/aw-test")) == BOARD
        assert latest_session(conn, Path("/home/user/aw-test2")) == EDIT
        assert latest_session(conn, Path("/nowhere")) is None
        # A session not updated since the process started is not its session.
        assert latest_session(conn, Path("/home/user/aw-test"), since_ms=1790853488061) is None
        conn.close()


class TestAdapter:
    def test_claims(self, tmp_path):
        assert agents.adapter_for(FIXTURE).name == "opencode"
        other = tmp_path / "other.db"
        sqlite3.connect(other).execute("CREATE TABLE t (x)").connection.close()
        assert agents.adapter_for(other) is None
        assert agents.adapter_for(tmp_path / "x.vscdb").name == "cursor"

    def test_lookalike_db_not_claimed(self, tmp_path):
        # Same table names, other columns: used to crash check --log with
        # "no such column: directory".
        other = tmp_path / "app.db"
        conn = sqlite3.connect(other)
        for table in ("session", "message", "part"):
            conn.execute(f"CREATE TABLE {table} (id TEXT, value TEXT)")
        conn.execute("INSERT INTO session VALUES ('s1', 'x')")
        conn.commit()
        conn.close()
        assert agents.adapter_for(other) is None
        with pytest.raises(UnsupportedLogFormatError):  # #48
            list(parse_file(other))

    @pytest.mark.parametrize("cmdline", [
        ["opencode", "run", "use claude to fix codex"],
        ["/x/lib/node_modules/opencode-ai/bin/opencode.exe"],
        ["C:\\npm\\node_modules\\opencode-ai\\bin\\opencode.exe", "-c"],
    ])
    def test_process_match(self, cmdline):
        assert match_process_adapter(cmdline).name == "opencode"

    @pytest.mark.parametrize("cmdline", [
        ["claude", "--model", "opencode"],
        ["bash", "-c", "opencode run hi"],
        ["opencode-helper"],
    ])
    def test_process_no_match(self, cmdline):
        adapter = match_process_adapter(cmdline)
        assert adapter is None or adapter.name != "opencode"

    def test_resolve_log(self, tmp_path, monkeypatch):
        (tmp_path / "opencode").mkdir()
        shutil.copy(FIXTURE, tmp_path / "opencode" / "opencode.db")
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        monkeypatch.delenv("OPENCODE_DB", raising=False)
        log, sid = OpencodeAdapter().resolve_log(Path("/home/user/aw-test"), None)
        assert sid == BOARD
        assert log == tmp_path / "opencode" / f"opencode.db#{BOARD}"
        assert db_of(log) == tmp_path / "opencode" / "opencode.db"
        proc = AgentProcess(pid=1, agent_type="opencode", working_directory=Path("/"),
                            log_file=log, session_id=sid)
        assert OpencodeAdapter().is_live(proc)

    def test_multilogwatcher_builds_session_watcher(self, db):
        key = session_key(db, BOARD)
        proc = AgentProcess(pid=1, agent_type="opencode", working_directory=Path("/"),
                            log_file=key, session_id=BOARD)
        mlw = MultiLogWatcher.from_processes([proc])
        assert mlw._find_all_logs() == [key]
        watcher = mlw._make_watcher(key)
        assert isinstance(watcher, OpencodeWatcher)
        assert (watcher.db_path, watcher.session_id) == (db, BOARD)


class TestWatcher:
    def test_emits_each_message_once(self, db):
        watcher = OpencodeWatcher(db, session_id=BOARD)
        assert len(watcher._poll_once()) == 6
        assert watcher._poll_once() == []

    def test_follows_latest_session(self, db):
        watcher = OpencodeWatcher(db)
        assert {a.session_id for a in watcher._poll_once()} == {EDIT}

    def test_waits_for_message_to_finish(self, db):
        conn = sqlite3.connect(db)
        mid, created, data = conn.execute(
            "SELECT id, time_created, data FROM message WHERE session_id = ? "
            "ORDER BY time_created DESC LIMIT 1", (BOARD,),
        ).fetchone()
        watcher = OpencodeWatcher(db, session_id=BOARD)
        watcher._poll_once()

        # A new step in progress: its finished tool part waits for the step.
        step = json.loads(data)
        del step["time"]["completed"]
        (tool,) = conn.execute(
            "SELECT data FROM part WHERE session_id = ? AND data LIKE '%\"tool\":\"bash\"%'",
            (BOARD,),
        ).fetchone()
        conn.execute("INSERT INTO message VALUES ('msg_new', ?, ?, ?, ?)",
                     (BOARD, created + 10, created + 10, json.dumps(step)))
        conn.execute("INSERT INTO part VALUES ('prt_new', 'msg_new', ?, ?, ?, ?)",
                     (BOARD, created + 11, created + 11, tool))
        conn.commit()
        assert watcher._poll_once() == []

        step["time"]["completed"] = created + 20
        conn.execute("UPDATE message SET data = ? WHERE id = 'msg_new'", (json.dumps(step),))
        conn.commit()
        conn.close()
        assert [a.tool_name for a in watcher._poll_once()] == ["bash"]

    def test_running_tool_holds_message_despite_later_prompt(self, db):
        # A prompt queued while a tool runs (prompt.ts writes the user row
        # before the busy loop ends) must not close the running step early.
        conn = sqlite3.connect(db)
        mid, created, data = conn.execute(
            "SELECT id, time_created, data FROM message WHERE session_id = ? "
            "ORDER BY time_created DESC LIMIT 1", (BOARD,),
        ).fetchone()
        (bash_data,) = conn.execute(
            "SELECT data FROM part WHERE session_id = ? AND data LIKE '%\"tool\":\"bash\"%'",
            (BOARD,),
        ).fetchone()
        (user_data,) = conn.execute(
            "SELECT data FROM message WHERE session_id = ? AND data LIKE '%\"role\":\"user\"%'",
            (BOARD,),
        ).fetchone()
        watcher = OpencodeWatcher(db, session_id=BOARD)
        watcher._poll_once()

        step = json.loads(data)
        del step["time"]["completed"]
        bash = json.loads(bash_data)
        done_state = dict(bash["state"])
        bash["state"] = {"status": "running", "input": done_state["input"],
                         "time": {"start": done_state["time"]["start"]}}
        conn.execute("INSERT INTO message VALUES ('msg_run', ?, ?, ?, ?)",
                     (BOARD, created + 10, created + 10, json.dumps(step)))
        conn.execute("INSERT INTO part VALUES ('prt_run', 'msg_run', ?, ?, ?, ?)",
                     (BOARD, created + 11, created + 11, json.dumps(bash)))
        conn.execute("INSERT INTO message VALUES ('msg_queued', ?, ?, ?, ?)",
                     (BOARD, created + 12, created + 12, user_data))
        conn.commit()
        assert [a.tool_name for a in watcher._poll_once()] == []

        bash["state"] = done_state
        step["time"]["completed"] = created + 20
        conn.execute("UPDATE part SET data = ? WHERE id = 'prt_run'", (json.dumps(bash),))
        conn.execute("UPDATE message SET data = ? WHERE id = 'msg_run'", (json.dumps(step),))
        conn.commit()
        conn.close()
        [action] = [a for a in watcher._poll_once() if a.tool_name == "bash"]
        assert action.command == "python3 --version"
        assert action.tokens_in == step["tokens"]["input"] > 0

    def test_orphaned_running_tool_released_by_later_assistant(self, db):
        # opencode SIGKILLed mid-tool leaves the part "running" forever; a resumed
        # run (`opencode run -s`) appends new steps after it. Those must not be
        # held back, and the orphan surfaces as a failed "interrupted" call.
        conn = sqlite3.connect(db)
        created, data = conn.execute(
            "SELECT time_created, data FROM message WHERE session_id = ? "
            "ORDER BY time_created DESC LIMIT 1", (BOARD,),
        ).fetchone()
        (bash_data,) = conn.execute(
            "SELECT data FROM part WHERE session_id = ? AND data LIKE '%\"tool\":\"bash\"%'",
            (BOARD,),
        ).fetchone()
        (write_data,) = conn.execute(
            "SELECT data FROM part WHERE session_id = ? AND data LIKE '%\"tool\":\"write\"%'",
            (BOARD,),
        ).fetchone()
        (user_data,) = conn.execute(
            "SELECT data FROM message WHERE session_id = ? AND data LIKE '%\"role\":\"user\"%'",
            (BOARD,),
        ).fetchone()
        watcher = OpencodeWatcher(db, session_id=BOARD)
        watcher._poll_once()

        killed = json.loads(data)
        del killed["time"]["completed"]
        bash = json.loads(bash_data)
        bash["state"] = {"status": "running", "input": bash["state"]["input"],
                         "time": {"start": bash["state"]["time"]["start"]}}
        write = json.loads(write_data)
        write["state"]["input"]["content"] = "GITHUB_TOKEN=ghp_uA1D9rvmF8n2aw14M4xy9CPf2PA2dpbhA04M"
        resumed = json.loads(data)
        rows = [
            ("msg_killed", killed, [("prt_orphan", bash)]),
            ("msg_resume", json.loads(user_data), []),
            ("msg_after", resumed, [("prt_secret", write)]),
        ]
        for n, (mid, msg, parts) in enumerate(rows, start=1):
            t = created + 10 * n
            conn.execute("INSERT INTO message VALUES (?, ?, ?, ?, ?)",
                         (mid, BOARD, t, t, json.dumps(msg)))
            for pid, part in parts:
                conn.execute("INSERT INTO part VALUES (?, ?, ?, ?, ?, ?)",
                             (pid, mid, BOARD, t + 1, t + 1, json.dumps(part)))
        conn.commit()
        conn.close()

        actions = watcher._poll_once()
        # (the resume prompt row has no text part here, so no user_message)
        assert [a.tool_name for a in actions] == ["bash", "write"]
        orphan, secret_write = actions
        assert orphan.success is False
        assert orphan.error_message == "interrupted"
        assert orphan.command == "python3 --version"
        buffer = ActionBuffer()
        for a in actions:
            buffer.add(a)
        warning = SecretLeakScanner().check(buffer)
        assert warning is not None
        assert warning.signal == "secret_leak"
        assert "github" in warning.message.lower()
        assert secret_write.file_path == "/home/user/aw-test/notes.txt"


def _bash_step(conn):
    """(time_created, message data, bash part data) of BOARD's last step."""
    created, data = conn.execute(
        "SELECT time_created, data FROM message WHERE session_id = ? "
        "ORDER BY time_created DESC LIMIT 1", (BOARD,),
    ).fetchone()
    (bash,) = conn.execute(
        "SELECT data FROM part WHERE session_id = ? AND data LIKE '%\"tool\":\"bash\"%'",
        (BOARD,),
    ).fetchone()
    return created, json.loads(data), json.loads(bash)


def _bad_part(msg, part):
    return msg, '["x"]'


def _bad_metadata(msg, part):
    part["state"]["metadata"] = "z"
    return msg, json.dumps(part)


def _bad_time(msg, part):
    msg["time"] = 123
    return msg, json.dumps(part)


def _bad_tokens(msg, part):
    msg["tokens"]["input"] = "abc"
    return msg, json.dumps(part)


def _bad_cost(msg, part):
    msg["cost"] = "free"
    return msg, json.dumps(part)


class TestMalformedRows:
    """#70: schema-valid rows with malformed JSON are skipped, never fatal."""

    @pytest.fixture(params=[_bad_part, _bad_metadata, _bad_time, _bad_tokens, _bad_cost])
    def bad_db(self, request, db):
        conn = sqlite3.connect(db)
        created, msg, part = _bash_step(conn)
        msg, part_data = request.param(msg, part)
        conn.execute("INSERT INTO message VALUES ('msg_bad', ?, ?, ?, ?)",
                     (BOARD, created + 10, created + 10, json.dumps(msg)))
        conn.execute("INSERT INTO part VALUES ('prt_bad', 'msg_bad', ?, ?, ?, ?)",
                     (BOARD, created + 11, created + 11, part_data))
        conn.commit()
        conn.close()
        return db

    def test_check_skips_bad_row(self, bad_db):
        actions = list(parse_file(bad_db, session_id=BOARD))
        assert [a.tool_name for a in actions][:6] == [
            "user_message", "read", "write", "bash", "read", "text_output",
        ]

    def test_watch_skips_bad_row(self, bad_db):
        watcher = OpencodeWatcher(bad_db, session_id=BOARD)
        assert len(watcher._poll_once()) >= 6
        assert watcher._poll_once() == []


class TestLockedDb:
    """#70: a locked db is reported as locked, not as an unsupported format."""

    @pytest.fixture
    def locked(self, db):
        conn = sqlite3.connect(db, isolation_level=None)  # fixture is rollback-journal
        conn.execute("BEGIN EXCLUSIVE")
        yield db
        conn.execute("ROLLBACK")
        conn.close()

    def test_check_says_locked(self, locked):
        with pytest.raises(LogUnreadableError, match="locked"):
            ensure_supported_log(locked)
            list(parse_file(locked, session_id=BOARD))

    def test_watch_waits_out_lock(self, locked):
        # Not rejected as unsupported: watch starts, and OpencodeWatcher's
        # poll retries (sqlite3.Error) until the lock is released.
        ensure_supported_log(locked)
