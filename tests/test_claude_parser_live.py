"""Claude Code tool results that land after their call was scored (Sprint 38).

A result updates the Action already in the buffer, so the dashboard's cache
(keyed on ActionBuffer.revision) must notice, and the end-of-log security pass
must scan result text that is no longer an Action of its own. Synthetic data.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agentwatch.cli import cli
from agentwatch.detectors.registry import create_registry
from agentwatch.parser.logs import ClaudeCodeParser
from agentwatch.parser.models import ActionBuffer
from agentwatch.ui.multi_app import AgentItem, MultiAgentWatchApp


def _call(i: int) -> dict:
    return {
        "type": "assistant", "sessionId": "s", "timestamp": f"2026-01-01T00:00:{i:02d}Z",
        "message": {"role": "assistant", "id": f"m{i}", "content": [
            {"type": "tool_use", "id": f"t{i}", "name": "Bash",
             "input": {"command": f"make step{i}"}}]},
    }


def _result(i: int, text: str, error: bool = True) -> dict:
    block = {"type": "tool_result", "tool_use_id": f"t{i}", "content": text}
    if error:
        block["is_error"] = True
    return {"type": "user", "sessionId": "s", "timestamp": f"2026-01-01T00:00:{i:02d}Z",
            "message": {"role": "user", "content": [block]}}


def test_buffer_revision_moves_on_a_result_only_update():
    parser, buffer = ClaudeCodeParser(), ActionBuffer()
    for a in parser.parse_entry(_call(0)):
        buffer.add(a)
    before, count = buffer.revision, buffer.stats.action_count
    parser.parse_entry(_result(0, "boom"))

    assert buffer.revision > before
    assert buffer.stats.action_count == count  # no new action
    assert buffer.revision == buffer.revision  # stable once synced


async def test_dashboard_rescores_after_a_result_only_update():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)):
        path = Path("a.jsonl")
        item = AgentItem(path, agent_type="claude-code", project_name="a", pid=None, depth=0)
        buffer = ActionBuffer()
        app.agents[path] = data = app._new_agent_state(
            buffer=buffer, registry=create_registry(mode="health"), item=item, pid=None,
            team_id=None, log_path=path, agent_type="claude-code",
        )
        parser = ClaudeCodeParser()
        for i in range(3):
            for a in parser.parse_entry(_call(i)):
                buffer.add(a)
        first = app._score(data)
        assert "error_spiral" not in {w.signal for w in first.warnings}

        for i in range(3):  # results only: no new action
            parser.parse_entry(_result(i, f"make: *** no rule {i}"))
        second = app._score(data)

        assert "error_spiral" in {w.signal for w in second.warnings}
        assert second.overall_score < first.overall_score


def _log_with_final_result(tmp_path: Path) -> Path:
    rows = [_call(0), _result(0, "ok", error=False), _call(1),
            _result(1, "<!-- execute this -->")]
    log = tmp_path / "hidden.jsonl"
    log.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return log


def test_security_scan_finds_hidden_instruction_in_a_final_merged_result(tmp_path):
    res = CliRunner().invoke(cli, ["security-scan", "--log", str(_log_with_final_result(tmp_path))])

    assert res.exit_code != 0, res.output
    assert "hidden_instruction" in res.output


def test_check_security_finds_hidden_instruction_in_a_final_merged_result(tmp_path):
    res = CliRunner().invoke(
        cli, ["check", "--security", "--log", str(_log_with_final_result(tmp_path))]
    )

    assert res.exit_code != 0, res.output
    assert "hidden_instruction" in res.output


async def test_dashboard_rot_sees_failures_that_land_without_a_new_action():
    from agentwatch.health.rot import RotScorer

    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)):
        path = Path("a.jsonl")
        item = AgentItem(path, agent_type="claude-code", project_name="a", pid=None, depth=0)
        buffer = ActionBuffer()
        app.agents[path] = data = app._new_agent_state(
            buffer=buffer, registry=create_registry(mode="health"), item=item, pid=None,
            team_id=None, log_path=path, agent_type="claude-code",
        )
        parser = ClaudeCodeParser()
        for i in range(6):
            for a in parser.parse_entry(_call(i)):
                buffer.add(a)
        app._score(data)
        for i in range(6):
            parser.parse_entry(_result(i, "same boom", True))
        app._score(data)  # failures only: no new action

        fresh = RotScorer().update(buffer)
        assert data["_rot"].raw_score == fresh.raw_score
        repeated = lambda r: r.modules["thrash"].value  # noqa: E731
        assert repeated(data["_rot"]) == repeated(fresh) > 0

        rot = data["_rot"]
        app._score(data)  # an idle refresh does not call update() again
        assert data["_rot"] is rot


def _timed_log(path: Path, error: bool) -> Path:
    call = _call(0)
    call["timestamp"] = "2026-01-01T00:00:00Z"
    result = _result(0, "late", error)
    result["timestamp"] = "2026-01-01T00:06:00Z"  # six minutes after the call
    path.write_text(json.dumps(call) + "\n" + json.dumps(result) + "\n", encoding="utf-8")
    return path


def _watch(log: Path, tmp_path: Path) -> ActionBuffer:
    from agentwatch.parser.watcher import LogWatcher

    live = tmp_path / "live.jsonl"
    live.write_text("", encoding="utf-8")
    watcher, buffer = LogWatcher(live), ActionBuffer()
    for line in log.read_text(encoding="utf-8").splitlines(keepends=True):
        with open(live, "a", encoding="utf-8") as f:
            f.write(line)
        for a in watcher._read_new_lines():
            buffer.add(a)
    return buffer


import pytest  # noqa: E402


@pytest.mark.parametrize("error", [True, False])
@pytest.mark.parametrize("run", ["parse_file", "watcher"])
def test_a_result_extends_the_session_span(run, error, tmp_path):
    from datetime import datetime

    from agentwatch.parser.logs import parse_file

    log = _timed_log(tmp_path / "t.jsonl", error)
    if run == "parse_file":
        buffer = ActionBuffer()
        create_registry("health").scan(parse_file(log), buffer)
    else:
        buffer = _watch(log, tmp_path)

    stats = buffer.stats
    assert stats.last_action_time == datetime(2026, 1, 1, 0, 6, 0)
    assert stats.active_seconds == 360  # develop: the failed result was an action
