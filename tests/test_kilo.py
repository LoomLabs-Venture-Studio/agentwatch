"""Kilo Code 7.x: opencode's store and parser under Kilo's path, env var and
process names. Fixture-verified only: the db is built here from Kilo's
``packages/core/src/session/sql.ts`` (Kilo-Org/kilocode @ ff20ca7)."""

from __future__ import annotations

import json
import sqlite3
import time
import types
from pathlib import Path

import pytest

import agentwatch.discovery as discovery
from agentwatch import agents
from agentwatch.agents.kilo import KiloAdapter
from agentwatch.agents.opencode import db_of, session_key
from agentwatch.discovery import match_process_adapter
from agentwatch.parser.logs import parse_file
from agentwatch.parser.models import ToolType
from agentwatch.parser.watcher import MultiLogWatcher, OpencodeWatcher

OPENCODE_FIXTURE = Path(__file__).parent / "fixtures" / "opencode_session.db"
PROJECT = "/home/user/kilo-proj"
SID = "ses_kilo1"
NOW = int(time.time() * 1000)  # after any real pid's start time, for resolve_log


def _build(path: Path) -> Path:
    """Kilo's session/message/part tables (sql.ts:24-102, the columns that
    matter plus a few NOT NULL extras) with one session: a prompt, then a
    step with a read and a bash that exits 1."""
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE session (id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
            parent_id TEXT, slug TEXT NOT NULL, directory TEXT NOT NULL,
            title TEXT NOT NULL, version TEXT NOT NULL,
            time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL);
        CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL,
            time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL);
        CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL,
            session_id TEXT NOT NULL, time_created INTEGER NOT NULL,
            time_updated INTEGER NOT NULL, data TEXT NOT NULL);
    """)
    t = NOW - 10_000
    conn.execute("INSERT INTO session VALUES (?, 'prj', NULL, 's', ?, 't', '7.8.9', ?, ?)",
                 (SID, PROJECT, t, NOW))
    user = {"role": "user", "time": {"created": t}}
    step = {"role": "assistant", "time": {"created": t + 10, "completed": t + 900},
            "cost": 0.01,
            "tokens": {"input": 120, "output": 30, "reasoning": 5,
                       "cache": {"read": 40, "write": 0}}}
    read = {"type": "tool", "callID": "c1", "tool": "read", "state": {
        "status": "completed", "input": {"filePath": f"{PROJECT}/a.py"}, "output": "x = 1",
        "title": "a.py", "metadata": {}, "time": {"start": t + 20, "end": t + 50}}}
    bash = {"type": "tool", "callID": "c2", "tool": "bash", "state": {
        "status": "completed", "input": {"command": "pytest"}, "output": "1 failed",
        "title": "run tests", "metadata": {"exit": 1}, "time": {"start": t + 60, "end": t + 800}}}
    conn.execute("INSERT INTO message VALUES ('msg_1', ?, ?, ?, ?)",
                 (SID, t, t, json.dumps(user)))
    conn.execute("INSERT INTO part VALUES ('prt_1', 'msg_1', ?, ?, ?, ?)",
                 (SID, t, t, json.dumps({"type": "text", "text": "run the tests"})))
    conn.execute("INSERT INTO message VALUES ('msg_2', ?, ?, ?, ?)",
                 (SID, t + 10, t + 10, json.dumps(step)))
    for n, part in enumerate((read, bash), start=2):
        conn.execute("INSERT INTO part VALUES (?, 'msg_2', ?, ?, ?, ?)",
                     (f"prt_{n}", SID, t + 10 * n, t + 10 * n, json.dumps(part)))
    conn.commit()
    conn.close()
    return path


@pytest.fixture
def kilo_db(tmp_path):
    (tmp_path / "kilo").mkdir()
    return _build(tmp_path / "kilo" / "kilo.db")


class TestDbPath:
    # xdg-basedir 5.1.0 (global.ts:3) has no per-OS branch: XDG_DATA_HOME, else
    # <home>/.local/share on Linux, macOS and Windows alike.
    def test_default_is_home_local_share(self, tmp_path, monkeypatch):
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        monkeypatch.delenv("KILO_DB", raising=False)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert KiloAdapter().db_path() == tmp_path / ".local" / "share" / "kilo" / "kilo.db"

    def test_xdg_data_home(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        monkeypatch.delenv("KILO_DB", raising=False)
        assert KiloAdapter().db_path() == tmp_path / "kilo" / "kilo.db"

    def test_kilo_db_override(self, tmp_path, monkeypatch):
        # database.ts:51-53: absolute as is, relative to the data dir.
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        monkeypatch.setenv("KILO_DB", "other.db")
        assert KiloAdapter().db_path() == tmp_path / "kilo" / "other.db"
        monkeypatch.setenv("KILO_DB", str(tmp_path / "abs.db"))
        assert KiloAdapter().db_path() == tmp_path / "abs.db"

    def test_opencode_env_does_not_leak(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        monkeypatch.delenv("KILO_DB", raising=False)
        monkeypatch.setenv("OPENCODE_DB", "x.db")
        assert KiloAdapter().db_path() == tmp_path / "kilo" / "kilo.db"
        assert agents.get("opencode").db_path() == tmp_path / "opencode" / "x.db"


class TestProcess:
    @pytest.mark.parametrize("cmdline", [
        ["kilo"],  # curl/brew native install
        ["/usr/lib/node_modules/@kilocode/cli/bin/.kilo", "run", "hi"],  # postinstall cache
        ["/x/node_modules/@kilocode/cli-linux-x64/bin/kilo"],
        ["C:\\Users\\J D\\AppData\\Roaming\\npm\\node_modules\\@kilocode\\cli-windows-x64"
         "\\bin\\kilo.exe"],
        ["/home/u/.vscode/extensions/kilocode.kilo-code-7.8.9-linux-x64/bin/kilo",
         "serve", "--port", "0"],
        ["C:\\Users\\J D\\.vscode\\extensions\\kilocode.kilo-code-7.8.9\\bin\\kilo.exe",
         "serve", "--port", "0"],
    ])
    def test_native_binary_matches(self, cmdline):
        assert match_process_adapter(cmdline).name == "kilo-code"

    @pytest.mark.parametrize("cmdline", [
        # npm's node wrapper: its native child is the one counted.
        ["node", "/usr/local/bin/kilo", "run", "hi"],
        ["/usr/bin/node", "/usr/local/bin/kilocode"],
        ["C:\\Program Files\\nodejs\\node.exe",
         "C:\\Users\\u\\AppData\\Roaming\\npm\\node_modules\\@kilocode\\cli\\bin\\kilo"],
        ["kilo-helper"],
        ["claude", "--model", "kilo"],
        ["bash", "-c", "kilo run hi"],
    ])
    def test_no_match(self, cmdline):
        adapter = match_process_adapter(cmdline)
        assert adapter is None or adapter.name != "kilo-code"

    def test_opencode_still_opencode(self):
        assert match_process_adapter(["/x/bin/opencode.exe"]).name == "opencode"


class TestRouting:
    def test_kilo_db_to_kilo_code(self, kilo_db):
        assert agents.adapter_for(kilo_db).name == "kilo-code"

    def test_opencode_db_to_opencode(self):
        assert agents.adapter_for(OPENCODE_FIXTURE).name == "opencode"

    def test_lookalike_kilo_db_unclaimed(self, tmp_path):
        other = tmp_path / "kilo.db"
        sqlite3.connect(other).execute("CREATE TABLE session (id TEXT)").connection.close()
        assert agents.adapter_for(other) is None


class TestParse:
    def test_actions(self, kilo_db):
        actions = list(parse_file(kilo_db))
        assert [a.tool_name for a in actions] == ["user_message", "read", "bash"]
        assert actions[0].incoming_message == "run the tests"
        read, bash = actions[1:]
        assert read.tool_type == ToolType.READ and read.success
        assert read.file_path == f"{PROJECT}/a.py"
        assert (read.tokens_in, read.tokens_out, read.cache_read_tokens) == (120, 35, 40)
        assert bash.command == "pytest"
        assert bash.success is False and bash.error_message == "exit code 1"

    def test_watcher(self, kilo_db):
        watcher = OpencodeWatcher(kilo_db)
        assert len(watcher._poll_once()) == 3
        assert watcher._poll_once() == []


class TestDiscovery:
    def test_resolve_log(self, kilo_db, monkeypatch):
        monkeypatch.setenv("XDG_DATA_HOME", str(kilo_db.parent.parent))
        monkeypatch.delenv("KILO_DB", raising=False)
        log, sid = KiloAdapter().resolve_log(Path(PROJECT), None)
        assert (log, sid) == (session_key(kilo_db, SID), SID)
        assert db_of(log) == kilo_db
        assert KiloAdapter().resolve_log(Path("/elsewhere"), None) == (None, None)

    def test_find_running_agents(self, kilo_db, monkeypatch):
        monkeypatch.setenv("XDG_DATA_HOME", str(kilo_db.parent.parent))
        monkeypatch.delenv("KILO_DB", raising=False)
        monkeypatch.setattr("agentwatch.cursor_discovery.find_cursor_agents", lambda: [])
        info = {"pid": 4242, "ppid": 1, "name": "kilo", "cpu_percent": 0.0,
                "memory_info": types.SimpleNamespace(rss=1), "create_time": 1_700_000_000.0,
                "cmdline": ["/ext/kilocode.kilo-code-7.8.9/bin/kilo", "serve", "--port", "0"]}
        monkeypatch.setattr(discovery.psutil, "process_iter",
                            lambda attrs=None: iter([types.SimpleNamespace(info=info)]))
        monkeypatch.setattr(discovery, "_get_process_cwd", lambda pid: Path(PROJECT))

        [found] = discovery.find_running_agents()

        assert (found.agent_type, found.session_id) == ("kilo-code", SID)
        assert found.log_file == session_key(kilo_db, SID)
        watcher = MultiLogWatcher.from_processes([found])._make_watcher(found.log_file)
        assert isinstance(watcher, OpencodeWatcher)
        assert (watcher.db_path, watcher.session_id) == (kilo_db, SID)
