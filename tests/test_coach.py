"""`agentwatch hook`: the Claude Code coach (PostToolUse/PostToolUseFailure hook)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from agentwatch import coach
from agentwatch.cli import cli


def _tool_use(i: int, command: str) -> dict:
    return {
        "type": "assistant",
        "sessionId": "s1",
        "timestamp": f"2026-10-17T10:00:{i:02d}Z",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": f"t{i}", "name": "Bash", "input": {"command": command}},
        ]},
    }


def _result(i: int, error: str | None) -> dict:
    block = {"type": "tool_result", "tool_use_id": f"t{i}", "content": error or "ok"}
    if error:
        block["is_error"] = True
    return {
        "type": "user",
        "sessionId": "s1",
        "timestamp": f"2026-10-17T10:00:{i:02d}Z",
        "message": {"role": "user", "content": [block]},
    }


def _write(path: Path, entries: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")
    return path


def _looping(tmp_path: Path) -> Path:
    """The same failing `pytest` command, 8 times in a row: a HIGH loop."""
    entries = []
    for i in range(8):
        entries += [_tool_use(i, "pytest tests/test_x.py"), _result(i, "AssertionError: boom")]
    return _write(tmp_path / "loop.jsonl", entries)


def _healthy(tmp_path: Path) -> Path:
    entries = []
    for i in range(12):
        entries += [_tool_use(i, f"echo step {i}"), _result(i, None)]
    return _write(tmp_path / "ok.jsonl", entries)


def _payload(transcript: Path, session: str = "sess-1", event: str = "PostToolUse") -> str:
    return json.dumps({
        "session_id": session,
        "transcript_path": str(transcript),
        "cwd": str(transcript.parent),
        "hook_event_name": event,
        "tool_name": "Bash",
        "tool_input": {"command": "pytest"},
        "tool_response": {},
        "tool_use_id": "t7",
    })


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch):
    monkeypatch.setattr(coach, "state_dir", lambda: tmp_path / "state")


def test_fires_on_loop_with_documented_schema(tmp_path):
    out = coach.run(_payload(_looping(tmp_path)))
    data = json.loads(out)
    assert set(data) == {"hookSpecificOutput"}
    spec = data["hookSpecificOutput"]
    assert spec["hookEventName"] == "PostToolUse"
    lines = spec["additionalContext"].splitlines()
    assert 1 <= len(lines) <= 3
    assert lines[0].startswith("agentwatch coach [high]: ")
    assert "repeated" in lines[0].lower()
    assert any("AssertionError" in line for line in lines)


def test_post_tool_use_failure_echoes_event(tmp_path):
    out = coach.run(_payload(_looping(tmp_path), event="PostToolUseFailure"))
    assert json.loads(out)["hookSpecificOutput"]["hookEventName"] == "PostToolUseFailure"


def test_silent_on_healthy_session(tmp_path):
    assert coach.run(_payload(_healthy(tmp_path))) is None


def test_dedup_then_rereport_after_clear(tmp_path):
    loop = _looping(tmp_path)
    assert coach.run(_payload(loop)) is not None
    assert coach.run(_payload(loop)) is None  # same loop: not nagged again
    assert coach.run(_payload(loop, session="other")) is not None  # per session
    assert coach.run(_payload(_healthy(tmp_path))) is None  # loop cleared
    assert coach.run(_payload(loop)) is not None  # recurred: report again


def test_state_records_latest_status(tmp_path):
    coach.run(_payload(_looping(tmp_path)))
    state = json.loads((tmp_path / "state" / "sess-1.json").read_text(encoding="utf-8"))
    assert state["reported"]
    assert any(w["signal"] == "loop" for w in state["warnings"])


@pytest.mark.parametrize("stdin", [
    "", "not json", "[1, 2]", '{"hook_event_name": "PostToolUse"}',
    '{"hook_event_name": "PostToolUse", "session_id": "s", "transcript_path": 5}',
])
def test_fail_open_on_garbage(stdin):
    assert coach.run(stdin) is None


def test_fail_open_on_missing_transcript(tmp_path):
    assert coach.run(_payload(tmp_path / "nope.jsonl")) is None


def test_ignores_other_events(tmp_path):
    assert coach.run(_payload(_looping(tmp_path), event="Stop")) is None


def test_session_id_cannot_escape_state_dir(tmp_path):
    coach.run(_payload(_looping(tmp_path), session="../../evil"))
    assert not (tmp_path / "evil.json").exists()
    assert len(list((tmp_path / "state").iterdir())) == 1


def test_cli_hook_command_prints_json_and_exits_zero(tmp_path):
    result = CliRunner().invoke(cli, ["hook"], input=_payload(_looping(tmp_path)))
    assert result.exit_code == 0
    assert json.loads(result.output)["hookSpecificOutput"]["additionalContext"]


def test_cli_hook_hidden_from_help():
    assert " hook " not in CliRunner().invoke(cli, ["--help"]).output


def test_entry_fast_path_fails_open_in_real_process(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-c", "from agentwatch._entry import main; main()", "hook"],
        input="garbage", capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0
    assert proc.stdout == ""


def test_watchdog_exits_zero_silently_on_timeout():
    # stdin never closes, so the read hangs until the BUDGET_S watchdog fires.
    proc = subprocess.Popen(
        [sys.executable, "-c", "from agentwatch._entry import main; main()", "hook"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        proc.wait(timeout=coach.BUDGET_S + 30)
        assert proc.returncode == 0
        assert proc.stdout.read() == b""
    finally:
        proc.kill()
        proc.stdin.close()

