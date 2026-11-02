"""`agentwatch report` cost by model, cache savings, errors by type and CSV,
on the real path: fixture logs -> `history sync` -> `report` (text, JSON, CSV)."""

import csv
import io
import json
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from agentwatch import history, report
from agentwatch.agents import ClaudeCodeAdapter, get
from agentwatch.cli import cli

SECRET = "ghp_" + "Zx9Q" * 9
NOW = datetime.now(timezone.utc).replace(microsecond=0)
T0 = NOW - timedelta(hours=2)

# claude-opus-5-5: $/M input 4, output 20, 5m write 5, cache read 0.20, 1h write 8
OPUS = {"input_tokens": 1000, "output_tokens": 100, "cache_creation_input_tokens": 2000,
        "cache_read_input_tokens": 10000,
        "cache_creation": {"ephemeral_5m_input_tokens": 1500, "ephemeral_1h_input_tokens": 500}}
OPUS_USD = (1000 * 4 + 100 * 20 + 1500 * 5 + 500 * 8 + 10000 * 0.20) / 1e6  # 0.0195
OPUS_SAVED = 10000 * (4 - 0.20) / 1e6  # 0.038: the reads at the input rate, minus their price

# (tool, input, failed result text, expected kind)
FAILURES = [
    ("Bash", {"command": "rm -rf build"},
     "The user doesn't want to proceed with this tool use. The tool use was rejected.",
     "permission_denied"),
    ("Bash", {"command": "git push"}, "PreToolUse:Bash hook error: [guard]: blocked", "blocked"),
    ("Bash", {"command": "cd app && python -m pytest -q"},
     "Exit code 1\n..F..\n=========== 1 failed, 4 passed in 0.31s ===========", "test_failure"),
    ("Bash", {"command": "make build"}, "Command timed out after 2m 0.0s", "timeout"),
    ("Edit", {"file_path": "/w/a.py"},
     "<tool_use_error>String to replace not found in file.\nString: foo</tool_use_error>",
     "edit_failed"),
    ("Read", {"file_path": "/w/missing.py"}, "File does not exist.", "file_not_found"),
    ("Bash", {"command": "frob"}, "Exit code 127\n/bin/bash: line 1: frob: command not found",
     "command_not_found"),
    ("Bash", {"command": "./run.sh"}, "Exit code 126\n/bin/bash: ./run.sh: Permission denied",
     "permission_denied"),
    ("Bash", {"command": "curl https://example.invalid"},
     "Exit code 6\ncurl: (6) Could not resolve host: example.invalid", "network"),
    ("Bash", {"command": "false"}, f"Exit code 2\ndeploy said {SECRET}", "nonzero_exit"),
    ("mcp__srv__ping", {}, "something odd happened", "other"),
]


def _ts(i):
    return (T0 + timedelta(seconds=i)).isoformat().replace("+00:00", "Z")


def _assistant(i, msg_id, content, model="claude-opus-5-5", usage=None):
    return {"type": "assistant", "sessionId": "s1", "timestamp": _ts(i),
            "message": {"role": "assistant", "id": msg_id, "model": model,
                        "usage": usage or {"input_tokens": 1, "output_tokens": 1},
                        "content": content}}


def _result(i, tu_id, text):
    return {"type": "user", "sessionId": "s1", "timestamp": _ts(i),
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": tu_id, "is_error": True, "content": text},
            ]}}


def _write(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(e) + "\n" for e in lines), encoding="utf-8")
    old = time.time() - 3600  # not "still being written"
    os.utime(path, (old, old))
    return path


def claude_log(path):
    """One priced call with every cache field, then one failure of each kind
    (1 input + 1 output token each: $24e-6)."""
    lines = [{"type": "user", "sessionId": "s1", "timestamp": _ts(0),
              "message": {"role": "user", "content": "go"}},
             _assistant(1, "m_cache", [{"type": "text", "text": "ok"},
                                       {"type": "tool_use", "id": "tu_c", "name": "Bash",
                                        "input": {"command": "ls"}}], usage=OPUS)]
    for n, (tool, inp, text, _) in enumerate(FAILURES):
        lines.append(_assistant(10 + 2 * n, f"m_{n}", [
            {"type": "tool_use", "id": f"tu_{n}", "name": tool, "input": inp}]))
        lines.append(_result(11 + 2 * n, f"tu_{n}", text))
    return _write(path, lines)


def unpriced_log(path):
    return _write(path, [_assistant(1, "m_x", [{"type": "text", "text": "hi"},
                                               {"type": "tool_use", "id": "t", "name": "Read",
                                                "input": {"file_path": "/w/x"}}],
                                    model="claude-unlisted-1",
                                    usage={"input_tokens": 300, "output_tokens": 30})])


def codex_log(path):
    """A failing pytest run, then 1,000 input tokens of which 800 cached."""
    lines = [
        {"timestamp": _ts(0), "type": "session_meta",
         "payload": {"id": "cx1", "cwd": "/home/u/svc", "cli_version": "0.45.2"}},
        {"timestamp": _ts(1), "type": "response_item",
         "payload": {"type": "function_call", "call_id": "c1", "name": "shell",
                     "arguments": json.dumps({"command": ["pytest", "-q"]})}},
        {"timestamp": _ts(2), "type": "event_msg",
         "payload": {"type": "exec_command_end", "call_id": "c1", "exit_code": 1,
                     "stderr": "FAILED tests/test_a.py::test_x - assert 1 == 2\n1 failed"}},
        {"timestamp": _ts(3), "type": "event_msg",
         "payload": {"type": "token_count", "info": {"last_token_usage": {
             "input_tokens": 1000, "cached_input_tokens": 800, "output_tokens": 50}}}},
    ]
    return _write(path, lines)


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Claude Code and Codex logs under tmp; the data dir in tmp too."""
    projects = tmp_path / "projects"
    monkeypatch.setattr("agentwatch.cc_stats.CLAUDE_PROJECTS_DIR", projects)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    monkeypatch.setattr("agentwatch.agents.ADAPTERS", [ClaudeCodeAdapter(), get("codex")])
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    claude_log(projects / "-w-web" / "a.jsonl")
    unpriced_log(projects / "-w-api" / "b.jsonl")
    codex_log(tmp_path / "codex" / "sessions" / "2026" / "11" / "01" / "rollout-cx1.jsonl")
    return tmp_path


def _report(*args):
    out = CliRunner().invoke(cli, ["report", *args])
    assert out.exit_code == 0, out.output
    return out.stdout


@pytest.mark.parametrize("tool, inp, text, kind", FAILURES)
def test_error_kind(tool, inp, text, kind):
    action = SimpleNamespace(error_message=text, incoming_message=text,
                             command=inp.get("command"))
    assert history.error_kind(action) == kind


def test_test_failure_needs_a_test_command_and_a_failure_line():
    a = SimpleNamespace(error_message="Exit code 1\n1 failed", incoming_message=None,
                        command="ruff check . && echo '1 failed'")
    assert history.error_kind(a) == "nonzero_exit"  # not a test runner
    a.command, a.error_message = "pytest -q", "Exit code 4\nERROR: usage"
    assert history.error_kind(a) == "nonzero_exit"  # a test runner, no failed tests


def test_sync_then_report_json(env):
    rep = json.loads(_report("--json"))
    models = {(m["agent"], m["model"]): m for m in rep["models"]}
    opus = models[("claude-code", "claude-opus-5-5")]
    assert opus["calls"] == 1 + len(FAILURES)
    assert opus["cache_read_tokens"] == 10000 and opus["cache_write_1h_tokens"] == 500
    assert opus["cost_usd"] == round(OPUS_USD + len(FAILURES) * 24e-6, 4)
    assert opus["cache_saved_usd"] == round(OPUS_SAVED, 4)
    # 10,000 read of 1,000 + 11 uncached + 2,000 written + 10,000 read
    assert opus["cache_hit_pct"] == round(10000 / 13011 * 100, 1)
    unpriced = models[("claude-code", "claude-unlisted-1")]
    assert (unpriced["tokens"], unpriced["cost_usd"], unpriced["cache_saved_usd"]) == (
        330, None, None)
    codex = models[("codex", None)]  # Codex logs no model id and no price
    assert (codex["input_tokens"], codex["cache_read_tokens"], codex["cost_usd"]) == (
        200, 800, None)
    assert codex["cache_hit_pct"] == 80.0
    assert rep["cache"]["saved_usd"] == round(OPUS_SAVED, 4)  # priced models only
    # The model rows add up to the spend and tokens the totals report.
    assert sum(m["tokens"] for m in rep["models"]) == rep["totals"]["tokens"]
    assert sum(m["cost_usd"] or 0 for m in rep["models"]) == pytest.approx(
        rep["totals"]["cost_usd"], abs=1e-4)

    e = rep["errors"]
    kinds = {k["kind"]: k for k in e["by_kind"]}
    assert kinds["permission_denied"]["count"] == 2
    assert kinds["test_failure"]["count"] == 2  # Claude Code pytest + Codex pytest
    assert kinds["test_failure"]["sessions"] == 2
    assert kinds["test_failure"]["sessions_pct"] == round(2 / 3 * 100, 1)
    assert set(kinds) == set(history.ERROR_KINDS)
    assert all(k["previous"] == 0 and k["delta"] == k["count"] for k in e["by_kind"])
    assert e["failed_calls"] == len(FAILURES) + 1 and e["sessions"] == 2
    assert {t["tool"]: t["count"] for t in e["by_tool"]}["Bash"] == 8


def test_no_error_text_is_stored(env):
    conn = history.connect()
    history.sync(conn)
    rows = conn.execute("SELECT kind, tool, count FROM session_errors").fetchall()
    assert {(k, t) for k, t, _ in rows} >= {("network", "Bash"), ("other", "mcp__srv__ping")}
    assert {k for k, _, _ in rows} <= set(history.ERROR_KINDS)
    dump = "\n".join(sqlite3.connect(history.db_path()).iterdump())
    for text in (SECRET, "frob", "example.invalid", "String to replace", "/w/"):
        assert text not in dump


def test_text_report(env):
    text = _report()
    assert "Cost by model" in text
    assert "claude-opus-5-5" in text and "(not logged)" in text
    assert "Cache saved ~$0.04 against the input rate" in text
    assert "Errors by type: 12 failed calls in 2 sessions (67%)" in text
    assert "test_failure" in text and "by tool: Bash 8" in text


CSV_HEADER = "table,rank,name,metric,value"


def test_csv(env):
    out = _report("--format", "csv")
    assert out.splitlines()[0] == CSV_HEADER == ",".join(report.CSV_HEADER)
    rows = list(csv.DictReader(io.StringIO(out)))
    have = {(r["table"], r["metric"]) for r in rows}
    for pair in [("report", "schema"), ("totals", "cost_usd"), ("previous", "sessions"),
                 ("models", "cost_usd"), ("models", "cache_saved_usd"), ("cache", "hit_pct"),
                 ("cache", "saved_usd"), ("errors", "failed_calls"),
                 ("errors.by_kind", "count"), ("errors.by_kind", "delta"),
                 ("errors.by_tool", "count"), ("by_agent", "cost_usd"),
                 ("security", "total")]:
        assert pair in have, pair
    first = [r for r in rows if r["table"] == "models" and r["rank"] == "1"]
    assert {r["name"] for r in first} == {"claude-opus-5-5"}  # costliest first, named
    unpriced = [r for r in rows if r["name"] == "claude-unlisted-1" and r["metric"] == "cost_usd"]
    assert unpriced[0]["value"] == ""  # null, never 0
    assert "/w/" not in out and SECRET not in out


def test_csv_cells_never_start_a_formula():
    out = io.StringIO()
    report.write_csv({"by_project": [{"project": "=HYPERLINK(1)", "n": -1}]}, out)
    assert out.getvalue().splitlines()[1] == "by_project,1,'=HYPERLINK(1),n,-1"


def test_stats_csv(env):
    out = CliRunner().invoke(cli, ["stats", "--all", "--format", "csv"])
    assert out.exit_code == 0, out.output
    lines = out.stdout.splitlines()
    assert lines[0] == CSV_HEADER
    assert "stats,,,sessions,2" in lines and any(r.startswith("by_tool,,Bash,") for r in lines)


def test_empty_period(env):
    conn = history.connect()
    history.sync(conn)
    rep = report.build(conn, days=7, now=time.time() + 30 * 86400)
    assert rep["models"] == []
    assert rep["cache"]["hit_pct"] is None and rep["cache"]["saved_usd"] is None
    assert rep["errors"]["failed_calls"] == 0 and rep["errors"]["sessions_pct"] is None
    assert rep["errors"]["by_kind"] == [] and rep["errors"]["by_tool"] == []
    assert "No sessions" in "\n".join(report.render(rep))
    out = io.StringIO()
    report.write_csv(rep, out)
    assert out.getvalue().startswith(CSV_HEADER + "\n")


def test_migration_from_schema_1_rescans_old_rows(env):
    """A DB written by the previous release: its rows get the breakdown on the
    next sync, though their logs did not change."""
    log = env / "projects" / "-w-web" / "a.jsonl"
    history.data_dir().mkdir(parents=True)
    old = sqlite3.connect(history.db_path())
    for statement in history._MIGRATIONS[0]:
        old.execute(statement)
    st = log.stat()
    old.execute(
        "INSERT INTO sessions (log_hash, agent, actions, size, mtime_ns, synced, ended)"
        " VALUES (?, 'claude-code', 5, ?, ?, 0, ?)",
        (history.log_hash(log), st.st_size, st.st_mtime_ns, time.time()),
    )
    old.execute("PRAGMA user_version = 1")
    old.commit()
    old.close()

    conn = history.connect()
    assert conn.execute("PRAGMA user_version").fetchone()[0] == history.SCHEMA_VERSION == 2
    assert conn.execute("SELECT size FROM sessions").fetchone()[0] == -1
    counts = history.sync(conn)
    assert counts["updated"] == 1 and counts["unchanged"] == 0
    assert conn.execute(
        "SELECT count(*) FROM session_models WHERE log_hash = ?", (history.log_hash(log),)
    ).fetchone()[0] == 1
    assert history.sync(conn)["unchanged"] == 3  # rescanned once, not every time


def test_rescan_replaces_breakdown_rows(env):
    conn = history.connect()
    history.sync(conn)
    log = env / "projects" / "-w-web" / "a.jsonl"
    with open(log, "a", encoding="utf-8") as f:  # one more failure
        f.write(json.dumps(_assistant(90, "m_more", [
            {"type": "tool_use", "id": "tu_more", "name": "Read", "input": {"file_path": "x"}}],
        )) + "\n" + json.dumps(_result(91, "tu_more", "File does not exist.")) + "\n")
    old = time.time() - 3000
    os.utime(log, (old, old))
    assert history.sync(conn)["updated"] == 1
    assert conn.execute(
        "SELECT count FROM session_errors WHERE kind = 'file_not_found'"
    ).fetchone()[0] == 2
    conn.execute("DELETE FROM sessions")  # prune: the breakdown goes with the session
    assert conn.execute("SELECT count(*) FROM session_errors").fetchone()[0] == 0
