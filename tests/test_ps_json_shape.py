"""`ps --json` is always a flat list of agent objects with the same keys.

It used to switch to a team-shaped list when sub-agents existed. Consumers
rebuild the tree from parent_agent_pid / depth / team_id on each object.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agentwatch import cli
from agentwatch.discovery import AgentProcess

EXPECTED_KEYS = {
    "pid", "parent_pid", "parent_agent_pid", "team_id", "team_name", "depth",
    "agent_type", "project", "working_directory", "log_file", "session_id",
    "cpu_percent", "memory_mb", "uptime",
}


def _root() -> AgentProcess:
    return AgentProcess(
        pid=100, agent_type="claude-code", working_directory=Path("/work/app"),
        parent_pid=1, team_id=100, depth=0,
    )


def _sub() -> AgentProcess:
    return AgentProcess(
        pid=101, agent_type="claude-code", working_directory=Path("/work/app"),
        parent_pid=100, parent_agent_pid=100, team_id=100, depth=1,
    )


def _ps_json(monkeypatch, agents) -> object:
    monkeypatch.setattr(cli, "find_running_agents", lambda: agents)
    result = CliRunner().invoke(cli.cli, ["ps", "--json"])
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def test_no_subagents_is_flat_list_with_team_fields(monkeypatch):
    rows = _ps_json(monkeypatch, [_root()])

    assert isinstance(rows, list) and len(rows) == 1
    assert set(rows[0]) == EXPECTED_KEYS
    assert rows[0]["team_id"] == 100 and rows[0]["depth"] == 0
    assert rows[0]["team_name"] == "claude-code:app"


def test_with_subagents_is_still_flat_list_with_same_keys(monkeypatch):
    rows = _ps_json(monkeypatch, [_root(), _sub()])

    assert isinstance(rows, list) and len(rows) == 2
    assert all(set(row) == EXPECTED_KEYS for row in rows)
    root, sub = rows
    assert (root["pid"], root["depth"], root["parent_agent_pid"]) == (100, 0, None)
    assert (sub["pid"], sub["depth"], sub["parent_agent_pid"]) == (101, 1, 100)
    assert root["team_id"] == sub["team_id"] == 100
    assert sub["team_name"] == root["team_name"] == "claude-code:app"


def test_shape_is_identical_with_and_without_subagents(monkeypatch):
    solo = _ps_json(monkeypatch, [_root()])[0]
    team = _ps_json(monkeypatch, [_root(), _sub()])[0]

    assert set(solo) == set(team)
