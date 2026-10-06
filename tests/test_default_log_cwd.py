"""#47: with no --log, check/security-scan prefer the current directory's session."""

import json
import os

from click.testing import CliRunner

from agentwatch import cc_stats
from agentwatch.cli import cli
from agentwatch.path_encoding import encode_path_for_claude

ENTRY = {
    "type": "assistant", "sessionId": "s1", "timestamp": "2026-01-01T12:00:00Z",
    "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "a.py"}}]},
}


def _session(project_dir, name, mtime):
    project_dir.mkdir(parents=True, exist_ok=True)
    log = project_dir / f"{name}.jsonl"
    log.write_text(json.dumps(ENTRY) + "\n", encoding="utf-8")
    os.utime(log, (mtime, mtime))
    return log


def _setup(tmp_path, monkeypatch, with_cwd_session):
    projects = tmp_path / "projects"
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(cc_stats, "CLAUDE_PROJECTS_DIR", projects)
    monkeypatch.setattr("agentwatch.parser.logs.DEFAULT_SEARCH_PATHS", [projects])
    monkeypatch.chdir(work)
    _session(projects / "other-project", "newest", 2_000_000_000)
    if with_cwd_session:
        _session(projects / encode_path_for_claude(work.resolve()), "mine", 1_000_000_000)


def test_prefers_current_directory_session(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, with_cwd_session=True)
    result = CliRunner().invoke(cli, ["check", "--json"])
    assert "mine.jsonl" in result.stderr
    assert json.loads(result.stdout)["session_fallback"] is None
    assert "Fallback" not in CliRunner().invoke(cli, ["check"]).stdout


def test_fallback_is_named_in_report(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, with_cwd_session=False)
    for cmd in (["check"], ["security-scan"]):
        out = CliRunner().invoke(cli, cmd).stdout
        assert "Fallback:" in out and "other-project" in out, cmd
    for cmd in (["check", "--json"], ["security-scan", "--json"]):
        note = json.loads(CliRunner().invoke(cli, cmd).stdout)["session_fallback"]
        assert "other-project" in note, cmd
