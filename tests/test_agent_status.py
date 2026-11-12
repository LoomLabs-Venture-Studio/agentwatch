"""Per-agent live status (agent_status.py) and its visual endpoint."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agentwatch import agent_status
from agentwatch.discovery import AgentProcess

SECRET = "ghp_" + "Zq8wXv3Lk9Pm2Rt7Yb4Nc6Hd1Fg5Js0Ae8Ui3"  # fake GitHub PAT
LONG = "pytest " + "x" * 300 + " --token " + SECRET


def _call(i, name, inp, ts):
    return {"type": "assistant", "sessionId": "s", "timestamp": ts, "cwd": "/w",
            "message": {"role": "assistant", "id": f"m{i}", "model": "claude-sonnet-4-5",
                        "content": [{"type": "tool_use", "id": f"t{i}", "name": name,
                                     "input": inp}],
                        "usage": {"input_tokens": 100, "output_tokens": 50}}}


def _result(i, error):
    return {"type": "user", "sessionId": "s", "timestamp": "2026-11-01T10:00:01Z",
            "message": {"role": "user", "content": [{
                "type": "tool_result", "tool_use_id": f"t{i}", "is_error": error,
                "content": f"SECRET RESULT {SECRET}"}]}}


@pytest.fixture
def log(tmp_path):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [_call(1, "Edit", {"file_path": "/w/src/visual.py", "old_string": "a",
                               "new_string": "b"}, now),
             _result(1, False),
             _call(2, "Bash", {"command": LONG}, now), _result(2, True)]
    p = tmp_path / "s.jsonl"
    p.write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")
    return p


def _agent(log, pid=1):
    return AgentProcess(pid=pid, agent_type="claude-code", working_directory=Path("/w"),
                        log_file=log, command="claude")


@pytest.fixture(autouse=True)
def _clean_cache():
    agent_status._CACHE.clear()
    yield
    agent_status._CACHE.clear()


def test_builder_output(log):
    row = agent_status.build([_agent(log)])["agents"][0]
    assert row["pid"] == 1 and row["agent_type"] == "claude-code"
    assert row["last_action"]["tool"] == "Bash"
    assert row["last_action"]["target"] == "pytest"
    assert row["last_action"]["ok"] is False
    assert 0 <= row["last_action"]["age_s"] < 60
    assert 0 <= row["health"]["score"] <= 100 and row["health"]["label"]
    assert row["cost_usd"] is None or row["cost_usd"] >= 0
    assert row["active"] is True


def test_file_target_is_base_name(log):
    log.write_text("\n".join(log.read_text().splitlines()[:2]) + "\n", encoding="utf-8")
    row = agent_status.build([_agent(log)])["agents"][0]
    assert row["last_action"]["tool"] == "Edit"
    assert row["last_action"]["target"] == "visual.py"
    assert row["last_action"]["ok"] is True


def test_old_log_is_not_active(log):
    old = time.time() - 600
    os.utime(log, (old, old))
    assert agent_status.build([_agent(log)])["agents"][0]["active"] is False


def test_unchanged_log_is_not_reparsed(log, monkeypatch):
    calls = []
    real = agent_status._score
    monkeypatch.setattr(agent_status, "_score", lambda p: calls.append(p) or real(p))
    agent_status.build([_agent(log)])
    agent_status.build([_agent(log)])
    assert len(calls) == 1
    with log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(_call(3, "Read", {"file_path": "/w/a.py"}, "2026-11-01T10:05:00Z"))
                + "\n")
    row = agent_status.build([_agent(log)])["agents"][0]
    assert len(calls) == 2 and row["last_action"]["tool"] == "Read"


def test_cache_pruned_to_running_agents(log):
    agent_status.build([_agent(log)])
    assert log in agent_status._CACHE
    agent_status.build([])
    assert not agent_status._CACHE


@pytest.mark.parametrize("path", [None, Path("/nonexistent/x.jsonl")])
def test_no_log_gives_null_fields(path):
    row = agent_status.build([_agent(path)])["agents"][0]
    assert row["pid"] == 1
    assert row["last_action"] is None and row["health"] is None
    assert row["cost_usd"] is None and row["active"] is None


def test_unparseable_log_gives_null_fields(tmp_path):
    p = tmp_path / "junk.jsonl"
    p.write_text("not json\n", encoding="utf-8")
    row = agent_status.build([_agent(p)])["agents"][0]
    assert row["last_action"] is None and row["health"] is None


def test_no_args_results_or_secrets_leak(log):
    text = json.dumps(agent_status.build([_agent(log)]))
    assert SECRET not in text and "SECRET RESULT" not in text
    assert "xxxx" not in text and "--token" not in text
    assert "/w/src" not in text  # only the base name


def test_command_env_prefix_skipped():
    assert agent_status._program("FOO=bar BAZ=1 /usr/bin/pytest -x") == "pytest"
    assert agent_status._program("") == ""
    assert agent_status._program("echo 'unterminated") == "echo"
