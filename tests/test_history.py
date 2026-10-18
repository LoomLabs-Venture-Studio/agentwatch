"""Session history store and `agentwatch history`."""

import json
import os
import sqlite3
import time
from datetime import datetime, timedelta

import pytest
from click.testing import CliRunner

from agentwatch import history
from agentwatch.agents import ClaudeCodeAdapter
from agentwatch.cli import cli
from agentwatch.detectors import create_registry
from agentwatch.detectors.base import warning_dedup_key
from agentwatch.parser import ActionBuffer, parse_file

SECRET = "ghp_" + "a1B2" * 9
PROMPT = "PLEASE-FIX-THE-LAUNCH-CODES-PROMPT"
PRIVATE_DIR = "C:\\Users\\secretuser\\private"
USAGE = {"input_tokens": 10, "output_tokens": 200, "cache_read_input_tokens": 40_000}
T0 = datetime(2026, 10, 1, 12, 0, 0)


def _line(i, kind, content, msg_id=None):
    entry = {
        "type": kind, "sessionId": "s1",
        "timestamp": (T0 + timedelta(seconds=i)).isoformat() + "Z",
        "message": {"role": kind, "content": content},
    }
    if kind == "assistant":
        entry["message"].update(id=msg_id, model="claude-opus-5-5", usage=USAGE)
    return entry


def write_log(path, attempts=8, start=0):
    """A prompt, then the same failing command (with a secret and a private
    path in it) retried *attempts* times: a loop and an error spiral."""
    cmd = f"{PRIVATE_DIR}\\deploy.sh --token {SECRET}"
    lines = [] if start else [_line(0, "user", PROMPT)]
    for n in range(start, start + attempts):
        lines.append(_line(2 * n + 1, "assistant", [
            {"type": "tool_use", "id": f"tu_{n}", "name": "Bash", "input": {"command": cmd}},
        ], f"msg_{n}"))
        lines.append(_line(2 * n + 2, "user", [{
            "type": "tool_result", "tool_use_id": f"tu_{n}", "is_error": True,
            "content": f"error: {PRIVATE_DIR}\\deploy.sh failed with {SECRET}",
        }]))
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write("".join(json.dumps(e) + "\n" for e in lines))
    old = time.time() - 3600  # not "still being written"
    os.utime(path, (old, old))
    return path


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Claude Code as the only agent, its projects dir and the data dir in tmp."""
    projects = tmp_path / "projects"
    monkeypatch.setattr("agentwatch.cc_stats.CLAUDE_PROJECTS_DIR", projects)
    monkeypatch.setattr("agentwatch.agents.ADAPTERS", [ClaudeCodeAdapter()])
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    return projects / "C--Users-secretuser-private-myproj"


def _rows(conn, sql, *args):
    return conn.execute(sql, args).fetchall()


# --- schema / migration ----------------------------------------------------

def test_new_db_has_current_schema(env):
    conn = history.connect()
    assert history.db_path().parent.name == "agentwatch"
    assert conn.execute("PRAGMA user_version").fetchone()[0] == history.SCHEMA_VERSION
    tables = {r[0] for r in _rows(conn, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"sessions", "findings"} <= tables


def test_migration_hook_runs_only_missing_steps(env, monkeypatch):
    write_log(env / "a.jsonl")
    conn = history.connect()
    history.sync(conn)
    conn.close()
    monkeypatch.setattr(history, "_MIGRATIONS", [*history._MIGRATIONS,
                                                 ["ALTER TABLE sessions ADD COLUMN note TEXT"]])
    monkeypatch.setattr(history, "SCHEMA_VERSION", len(history._MIGRATIONS))
    conn = history.connect()
    assert conn.execute("PRAGMA user_version").fetchone()[0] == history.SCHEMA_VERSION
    assert _rows(conn, "SELECT count(*), max(note) FROM sessions") == [(1, None)]


def test_newer_schema_is_refused(env):
    conn = history.connect()
    conn.execute(f"PRAGMA user_version = {history.SCHEMA_VERSION + 1}")
    conn.close()
    with pytest.raises(RuntimeError, match="newer"):
        history.connect()


@pytest.mark.parametrize("platform, var, expect", [
    ("win32", "LOCALAPPDATA", ("L", "agentwatch")),
    ("linux", "XDG_DATA_HOME", ("X", "agentwatch")),
])
def test_data_dir(monkeypatch, platform, var, expect):
    monkeypatch.setattr("sys.platform", platform)
    monkeypatch.setenv(var, expect[0])
    assert history.data_dir().parts[-2:] == expect


def test_data_dir_default_posix(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    assert history.data_dir() == tmp_path / ".local" / "share" / "agentwatch"


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_data_dir_created_0700(env):
    history.connect()
    assert history.data_dir().stat().st_mode & 0o777 == 0o700


# --- incremental sync --------------------------------------------------------

def test_sync_is_incremental_and_idempotent(env):
    a, b = write_log(env / "a.jsonl"), write_log(env / "b.jsonl")
    conn = history.connect()
    assert history.sync(conn)["new"] == 2
    before = _rows(conn, "SELECT * FROM sessions ORDER BY log_hash")
    counts = history.sync(conn)
    assert (counts["new"], counts["updated"], counts["unchanged"]) == (0, 0, 2)
    assert _rows(conn, "SELECT * FROM sessions ORDER BY log_hash") == before

    write_log(a, attempts=4, start=8)  # grown
    counts = history.sync(conn)
    assert (counts["updated"], counts["unchanged"]) == (1, 1)
    (actions,) = _rows(conn, "SELECT actions FROM sessions WHERE log_hash = ?",
                       history.log_hash(a))[0]
    assert actions == len(list(parse_file(a)))

    b.unlink()  # deleted: kept as history
    history.sync(conn)
    assert _rows(conn, "SELECT count(*) FROM sessions") == [(2,)]


def test_active_and_old_logs(env):
    log = write_log(env / "a.jsonl")
    mtime = log.stat().st_mtime
    conn = history.connect()
    assert history.sync(conn, now=mtime + 10)["active"] == 1
    assert history.sync(conn, days=1, now=mtime + 3 * 86400)["older"] == 1
    assert _rows(conn, "SELECT count(*) FROM sessions") == [(0,)]
    assert history.sync(conn, include_active=True, now=mtime + 10)["new"] == 1


def test_sync_in_worker_processes(env, monkeypatch):
    for name in "ab":
        write_log(env / f"{name}.jsonl")
    monkeypatch.setattr(history, "_POOL_MIN", 2)
    conn = history.connect()
    assert history.sync(conn)["new"] == 2
    assert _rows(conn, "SELECT count(*), sum(waste_findings > 0) FROM sessions") == [(2, 2)]


class _FakePool:
    """map() yields one real result, then raises *error*."""
    shutdowns: list = []

    def __init__(self, error):
        self.error = error

    def map(self, fn, *args):
        yield fn(*(a[0] for a in args))
        raise self.error

    def shutdown(self, **kwargs):
        _FakePool.shutdowns.append(kwargs)


def test_broken_pool_falls_back_to_serial(env, monkeypatch):
    from concurrent.futures.process import BrokenProcessPool

    for name in "abc":
        write_log(env / f"{name}.jsonl")
    monkeypatch.setattr(history, "_POOL_MIN", 2)
    monkeypatch.setattr("concurrent.futures.ProcessPoolExecutor",
                        lambda: _FakePool(BrokenProcessPool("worker died")))
    _FakePool.shutdowns.clear()
    conn = history.connect()
    assert history.sync(conn)["new"] == 3
    assert _rows(conn, "SELECT count(*), sum(waste_findings > 0) FROM sessions") == [(3, 3)]
    assert _FakePool.shutdowns == [{"wait": False, "cancel_futures": True}]


def test_ctrl_c_cancels_queued_logs(env, monkeypatch):
    for name in "ab":
        write_log(env / f"{name}.jsonl")
    monkeypatch.setattr(history, "_POOL_MIN", 2)
    monkeypatch.setattr("concurrent.futures.ProcessPoolExecutor",
                        lambda: _FakePool(KeyboardInterrupt()))
    _FakePool.shutdowns.clear()
    conn = history.connect()
    with pytest.raises(KeyboardInterrupt):
        history.sync(conn)
    assert _FakePool.shutdowns == [{"wait": False, "cancel_futures": True}]
    assert _rows(conn, "SELECT count(*) FROM sessions") == [(1,)]  # the one finished


_CONNECT_AT = """
import sys, time
from pathlib import Path
from agentwatch.history import connect
time.sleep(max(0.0, float(sys.argv[2]) - time.time()))
connect(Path(sys.argv[1])).close()
"""


def test_two_first_runs_at_once(tmp_path):
    import subprocess
    import sys

    for round_ in range(3):
        db = tmp_path / f"r{round_}" / "history.db"
        start = str(time.time() + 1.5)
        procs = [subprocess.Popen([sys.executable, "-c", _CONNECT_AT, str(db), start],
                                  stderr=subprocess.PIPE, text=True) for _ in range(2)]
        for p in procs:
            _, err = p.communicate(timeout=60)
            assert p.returncode == 0, err
        conn = sqlite3.connect(db)
        assert conn.execute("PRAGMA user_version").fetchone() == (history.SCHEMA_VERSION,)
        conn.close()


@pytest.mark.parametrize("cwd", [
    "C:\\work\\agentwatch-main\\.claude\\worktrees\\agent-a0e4f1",
    "/home/u/agentwatch-main/.claude/worktrees/agent-a0e4f1",
    "/home/u/agentwatch-main/.claude/worktrees/agent-a0e4f1/src/pkg",
    "/home/u/agentwatch-main/.claude/worktrees",
])
def test_worktree_cwd_is_its_project(cwd):
    from agentwatch.cc_stats import project_name

    assert project_name(cwd) == "agentwatch-main"


def test_project_names_from_recorded_cwd(env, tmp_path, monkeypatch):
    from pathlib import Path

    from agentwatch.agents.base import folder_name
    from agentwatch.cc_stats import project_dir_to_name
    from agentwatch.path_encoding import encode_path_for_claude

    home = tmp_path / "home" / "Victim Name"
    monkeypatch.setattr(Path, "home", lambda: home)
    projects = env.parent
    in_home = projects / encode_path_for_claude(home)
    dashed = projects / "C--work-agentwatch-main"
    for d, cwd in ((in_home, str(home)), (dashed, "C:\\work\\agentwatch-main")):
        d.mkdir(parents=True)
        (d / "s.jsonl").write_text(json.dumps({"type": "summary", "cwd": cwd}) + "\n",
                                   encoding="utf-8")
        write_log(d / "s.jsonl")
    conn = history.connect()
    history.sync(conn)
    assert sorted(p for (p,) in _rows(conn, "SELECT project FROM sessions")) == [
        "agentwatch-main", "~"]
    assert project_dir_to_name(projects / encode_path_for_claude(home / "x")) == "x"
    empty = projects / encode_path_for_claude(home)
    (empty / "s.jsonl").unlink()  # no transcript to read a cwd from: decoded, still "~"
    assert project_dir_to_name(empty) == "~"
    assert folder_name(str(home)) == "~" and folder_name(str(home / "proj")) == "proj"


def test_unreadable_log_is_remembered_not_counted(env):
    env.mkdir(parents=True)
    bad = env / "bad.jsonl"
    bad.write_bytes(b"\x00\x01 not json")
    old = time.time() - 3600
    os.utime(bad, (old, old))
    conn = history.connect()
    history.sync(conn)
    assert _rows(conn, "SELECT actions FROM sessions") == [(0,)]
    assert history.sync(conn)["unchanged"] == 1


# --- findings: dedup, attribution, privacy -----------------------------------

def test_findings_deduplicated_per_session(env):
    log = write_log(env / "a.jsonl")
    warnings = create_registry("all").scan(parse_file(log), ActionBuffer())
    conn = history.connect()
    history.sync(conn)
    rows = _rows(conn, "SELECT key_hash, first_seen FROM findings")
    assert len(rows) == len({warning_dedup_key(w) for w in warnings}) > 1
    first = dict(rows)

    write_log(log, attempts=4, start=8)
    history.sync(conn)
    again = dict(_rows(conn, "SELECT key_hash, first_seen FROM findings"))
    assert len(again) == len(set(again))
    assert all(again[k] == first[k] for k in again.keys() & first.keys())


def test_waste_matches_check(env):
    log = write_log(env / "a.jsonl")
    out = CliRunner().invoke(cli, ["check", "--log", str(log), "--json"])
    waste = json.loads(out.stdout)["waste"]
    conn = history.connect()
    history.sync(conn)
    (row,) = _rows(conn, "SELECT waste_findings, waste_tokens, waste_usd, tokens, cost_usd, "
                         "health_score, project, agent FROM sessions")
    assert row[:3] == (waste["findings"], waste["tokens"], waste["cost_usd"])
    assert row[3] == waste["session_tokens"]
    assert row[4] == pytest.approx(waste["session_cost_usd"], abs=1e-4)
    assert row[5] == json.loads(out.stdout)["overall_score"]
    assert row[6:] == ("myproj", "claude-code")


def test_db_holds_no_transcript_text_or_paths(env):
    log = write_log(env / "a.jsonl")
    conn = history.connect()
    history.sync(conn)
    messages = [m for (m,) in _rows(conn, "SELECT message FROM findings WHERE category IN "
                                       "('progress', 'errors', 'context', 'goal')")]
    ((leaks, with_message),) = _rows(conn, "SELECT count(*), count(message) FROM findings "
                                           "WHERE category = 'credential'")
    assert leaks and not with_message  # security messages can quote the command
    conn.close()
    data = history.db_path().read_bytes()
    for needle in (SECRET, SECRET[-12:], PROMPT, "secretuser", "deploy.sh --token",
                   str(log), str(env), "C--Users"):
        assert needle.encode() not in data, needle
    assert messages and all(len(m) <= 120 for m in messages)


SPACED = "C:\\Users\\Victim Spacename\\Documents\\plan.txt"


@pytest.mark.parametrize("message, details, expect", [
    (f"Repeated action: Edit on {SPACED} (8x)", {}, "Repeated action: Edit on plan.txt (8x)"),
    ("Re-reading file: /Users/john doe/notes/plan.md (5x)", {},
     "Re-reading file: plan.md (5x)"),
    (f'Edit→test→fail cycle on "{SPACED}" (3x)', {}, "Edit→test→fail cycle on plan.txt (3x)"),
    (f"Re-reading {SPACED} after long gaps (4x)", {}, "Re-reading plan.txt after long gaps (4x)"),
    (f"Edited {SPACED} 5x with no successful test in between", {"file": SPACED},
     "Edited plan.txt 5x with no successful test in between"),
    ("Repeated action: Read on /srv/my files/a b.py (6x)", {"path": "/srv/my files/a b.py"},
     "Repeated action: Read on a b.py (6x)"),
    ("Re-reading file: https://h.example/v1/api?token=abc123def (3x)", {},
     "Re-reading file: api (3x)"),
    ("Fetched https://h.example/v1/api#frag?x=1 and /x/y?k=v ok", {}, "Fetched api and y ok"),
])
def test_safe_message_cuts_paths_with_spaces(message, details, expect):
    assert history.safe_message(message, details) == expect


def test_safe_message_hides_secrets_and_controls():
    out = history.safe_message(f"Error\x1b[31m in {PRIVATE_DIR}\\a.py: {SECRET} " + "x" * 300)
    assert "a.py" in out and "secretuser" not in out
    assert SECRET[-4:] not in out and "\u2026" not in out and "[secret]" in out
    assert "\x1b" not in out and len(out) <= 120


# --- prune / path ------------------------------------------------------------

def test_prune_and_path(env):
    write_log(env / "a.jsonl")
    runner = CliRunner()
    assert runner.invoke(cli, ["history", "sync"]).exit_code == 0
    path = runner.invoke(cli, ["history", "path"]).output.strip()
    assert path == str(history.db_path())
    out = runner.invoke(cli, ["history", "prune", "--older-than", "10d"])
    assert "Removed 1 session" in out.output  # the fixture session ended 2026-10-01
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT count(*) FROM findings").fetchone() == (0,)
    assert runner.invoke(cli, ["history", "prune", "--older-than", "soon"]).exit_code == 2


# --- each adapter's history_logs ---------------------------------------------

def test_adapters_find_their_history(tmp_path, monkeypatch):
    from agentwatch.agents import get

    def put(rel, text="{}\n"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    monkeypatch.setenv("COPILOT_HOME", str(tmp_path / "copilot"))
    monkeypatch.setenv("GEMINI_CLI_HOME", str(tmp_path / "g"))
    monkeypatch.setenv("CLINE_DIR", str(tmp_path / "cline"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "appdata"))
    monkeypatch.setattr("sys.platform", "win32" if os.name == "nt" else "linux")
    monkeypatch.setattr("agentwatch.agents.agy.AGY_HOME", tmp_path / "agy", raising=False)
    cwd = str(tmp_path / "work" / "proj")
    codex = put("codex/sessions/2026/10/01/rollout-x.jsonl", json.dumps(
        {"type": "session_meta", "payload": {"id": "c1", "cwd": cwd}}) + "\n")
    copilot = put("copilot/session-state/cp1/events.jsonl", json.dumps(
        {"type": "session.start", "data": {"context": {"cwd": cwd}}}) + "\n")
    gemini = put("g/.gemini/tmp/abc/chats/session-1.jsonl")
    put("g/.gemini/projects.json", json.dumps({"projects": {cwd: "abc"}}))
    agy = put("agy/brain/cv1/.system_generated/logs/transcript.jsonl")
    vscode = put("appdata/Code/User/workspaceStorage/ws1/chatSessions/chat1.jsonl")
    put("appdata/Code/User/workspaceStorage/ws1/workspace.json",
        json.dumps({"folder": (tmp_path / "work" / "proj").as_uri()}))
    cline = put("cline/data/sessions/k1/k1.messages.json")
    put("cline/data/sessions/k1/k1.json", json.dumps({"cwd": cwd}))
    put("cline/data/sessions/k1/other.messages.json")  # not the root session

    for name, path, meta in [
        ("codex", codex, ("c1", "proj")),
        ("copilot", copilot, ("cp1", "proj")),
        ("gemini", gemini, ("session-1", "proj")),
        ("agy", agy, ("cv1", None)),
        ("copilot-vscode", vscode, ("chat1", "proj")),
        ("cline", cline, ("k1", "proj")),
    ]:
        adapter = get(name)
        assert list(adapter.history_logs()) == [path], name
        assert adapter.history_meta(path) == meta, name
