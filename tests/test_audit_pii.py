"""`agentwatch audit --pii` (spec AC9)."""

from __future__ import annotations

import json

from click.testing import CliRunner

from agentwatch.cli import cli

EMAIL = "jane.doe@gmail.com"


def _log(tmp_path, monkeypatch):
    project = tmp_path / "projects" / "-tmp-proj"
    project.mkdir(parents=True)
    log = project / "sess1.jsonl"
    line = {
        "type": "assistant",
        "message": {
            "id": "msg_1",
            "model": "claude-sonnet-4-5-20250929",
            "content": [{
                "type": "tool_use",
                "id": "tool_1",
                "name": "Bash",
                "input": {"command": f"git config user.email {EMAIL}"},
            }],
            "usage": {"input_tokens": 100, "output_tokens": 50},
        },
    }
    log.write_text(json.dumps(line) + "\n")
    monkeypatch.setattr("agentwatch.cc_stats.CLAUDE_PROJECTS_DIR", tmp_path / "projects")
    return log


def test_without_pii_finds_nothing(tmp_path, monkeypatch):
    _log(tmp_path, monkeypatch)
    res = CliRunner().invoke(cli, ["audit", "--all", "--json"])
    assert res.exit_code == 0
    assert json.loads(res.stdout)["total_findings"] == 0


def test_pii_finding_is_low_and_exit_zero(tmp_path, monkeypatch):
    _log(tmp_path, monkeypatch)
    res = CliRunner().invoke(cli, ["audit", "--all", "--pii", "--json"])
    assert res.exit_code == 0
    out = json.loads(res.stdout)
    assert [(f["secret_type"], f["severity"]) for f in out["findings"]] == [("email", "low")]
    assert "Personal info" in out["findings"][0]["remediation"]
    assert EMAIL not in res.stdout


def test_pii_redact_removes_it_and_keeps_bak(tmp_path, monkeypatch):
    log = _log(tmp_path, monkeypatch)
    res = CliRunner().invoke(cli, ["audit", "--all", "--pii", "--redact", "--json"])
    assert res.exit_code == 0
    assert json.loads(res.stdout)["redacted"] == 1
    assert EMAIL not in log.read_text()
    assert EMAIL in log.with_name("sess1.jsonl.bak").read_text()
