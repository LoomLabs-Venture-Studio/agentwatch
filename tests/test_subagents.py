"""`agentwatch subagents`: each subagent log of a Claude Code session, scored."""

import json
import os
import shutil
from pathlib import Path

from click.testing import CliRunner

from agentwatch.cli import cli
from agentwatch.subagents import build, session_of

FIX = Path(__file__).parent / "fixtures"


def _session(tmp_path: Path) -> Path:
    session = tmp_path / "abc.jsonl"
    shutil.copy(FIX / "claude_code_2_1_30x.jsonl", session)
    sub = tmp_path / "abc" / "subagents"
    sub.mkdir(parents=True)
    shutil.copy(FIX / "claude_error_spiral.jsonl", sub / "agent-a1.jsonl")
    (sub / "agent-a1.meta.json").write_text(json.dumps(
        {"agentType": "engineer", "description": "Fix\x1b[31m it", "spawnDepth": 2}))
    shutil.copy(FIX / "claude_code_2_1_30x.jsonl", sub / "agent-a2.jsonl")  # no meta
    os.utime(sub / "agent-a2.jsonl", (1, 1))  # old: not active, listed last
    (sub / "agent-a3.meta.json").write_text("{}")  # meta without a log: ignored
    return session


def test_build_scores_each_subagent(tmp_path):
    session = _session(tmp_path)
    assert session_of(session.with_suffix("") / "subagents" / "agent-a1.jsonl") == session
    data = build(session)
    assert (data["total"], data["active"]) == (2, 1)
    eng, other = data["subagents"]
    assert (eng["id"], eng["type"], eng["depth"], eng["active"]) == ("a1", "engineer", 2, True)
    assert "\x1b" not in eng["description"]
    assert eng["actions"] > 0 and eng["health_score"] is not None
    assert (other["type"], other["active"]) == ("subagent", False)
    assert [r["id"] for r in build(session, active_only=True)["subagents"]] == ["a1"]


def test_cli_json_and_text(tmp_path):
    session = _session(tmp_path)
    out = CliRunner().invoke(cli, ["subagents", "--log", str(session), "--json"])
    assert out.exit_code == 0, out.output
    assert json.loads(out.output)["total"] == 2
    out = CliRunner().invoke(cli, ["subagents", "--log", str(session)])
    assert "engineer" in out.output and "1 active, 2 in all" in out.output


def test_no_subagents(tmp_path):
    session = tmp_path / "x.jsonl"
    session.write_text("")
    assert build(session)["subagents"] == []


def test_with_subagents_and_parent(tmp_path):
    from agentwatch.discovery import AgentProcess
    from agentwatch.subagents import parent_log, with_subagents

    session = _session(tmp_path)
    sub = session.with_suffix("") / "subagents"
    (sub / "agent-a1.jsonl").write_text(
        (sub / "agent-a1.jsonl").read_text() + '{"content":[{"type":"tool_use","id":"tu9"}]}\n')
    shutil.copy(FIX / "claude_code_2_1_30x.jsonl", sub / "agent-a4.jsonl")
    (sub / "agent-a4.meta.json").write_text(json.dumps(
        {"agentType": "qa", "spawnDepth": 2, "toolUseId": "tu9"}))
    main = AgentProcess(pid=7, agent_type="claude-code", working_directory=tmp_path,
                        log_file=session, depth=0, team_id=7)
    other = AgentProcess(pid=8, agent_type="aider", working_directory=tmp_path, log_file=None)
    procs = with_subagents([main, other])
    added = {p.log_file.stem: p for p in procs[2:]}
    assert set(added) == {"agent-a1", "agent-a4"}  # a2 is old: not active
    assert (added["agent-a1"].pid, added["agent-a1"].team_id) == (7, 7)
    assert (added["agent-a1"].depth, added["agent-a4"].depth) == (2, 2)  # spawnDepth
    assert parent_log(sub / "agent-a4.jsonl") == sub / "agent-a1.jsonl"
    assert parent_log(sub / "agent-a1.jsonl") == session
