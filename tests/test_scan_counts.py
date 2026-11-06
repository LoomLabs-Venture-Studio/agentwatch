"""Counts reported by `security-scan` and `error_spiral` are real totals.

`security-scan` reported `len(buffer)` (the ActionBuffer keeps only the
newest 500) as the number of actions analyzed, and `error_spiral` counted
failures only inside its 5-action window, so both capped on long sessions.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from click.testing import CliRunner

from agentwatch import visual
from agentwatch.cli import cli
from agentwatch.detectors.base import warning_dedup_key
from agentwatch.detectors.health.errors import ErrorSpiralDetector
from agentwatch.parser.models import Action, ActionBuffer, ToolType

N_ACTIONS = 650  # more than ActionBuffer's default max_size (500)


def _write_log(path, n: int) -> None:
    base = datetime(2026, 1, 1, 12, 0, 0)
    lines = [
        json.dumps({
            "sessionId": "s1",
            "timestamp": (base + timedelta(seconds=i)).isoformat(),
            "tool": "Bash",
            "command": f"echo {i}",
        })
        for i in range(n)
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_log_is_longer_than_the_buffer():
    assert N_ACTIONS > ActionBuffer().max_size


def test_security_scan_text_reports_every_action(tmp_path):
    log = tmp_path / "session.jsonl"
    _write_log(log, N_ACTIONS)
    result = CliRunner().invoke(cli, ["security-scan", "--log", str(log)])
    assert f"Analyzed {N_ACTIONS} actions" in result.output


def test_security_scan_json_reports_every_action(tmp_path):
    log = tmp_path / "session.jsonl"
    _write_log(log, N_ACTIONS)
    result = CliRunner().invoke(cli, ["security-scan", "--log", str(log), "--json"])
    payload = json.loads(result.output)
    assert payload["action_count"] == N_ACTIONS


def test_visual_security_reports_every_action(tmp_path, monkeypatch):
    log = tmp_path / "session.jsonl"
    _write_log(log, N_ACTIONS)
    monkeypatch.setattr(visual.cli, "_default_log", lambda: (log, None))
    assert visual._security(False)["action_count"] == N_ACTIONS


def _action(i: int, *, success: bool, tokens: int = 0) -> Action:
    return Action(
        timestamp=datetime(2026, 1, 1, 12, 0, 0) + timedelta(seconds=i),
        tool_name="Bash",
        tool_type=ToolType.BASH,
        success=success,
        command=f"make test {i}",
        error_message=None if success else "exit code 1",
        tokens_in=tokens,
        message_id=f"m{i}",
    )


def _buffer(successes: int, failures: int) -> ActionBuffer:
    buffer = ActionBuffer()
    for i in range(successes):
        buffer.add(_action(i, success=True))
    for i in range(successes, successes + failures):
        buffer.add(_action(i, success=False, tokens=10))
    return buffer


def test_error_spiral_reports_the_whole_run():
    warning = ErrorSpiralDetector().check(_buffer(successes=5, failures=30))
    assert warning is not None
    assert warning.details["consecutive_failures"] == 30
    assert "30 consecutive failures" in warning.message
    # Cost covers every failed call in the run, not only the window.
    assert warning.tokens == 30 * 10


def test_error_spiral_run_stops_at_the_last_success():
    buffer = _buffer(successes=0, failures=10)
    buffer.add(_action(100, success=True))
    for i in range(101, 105):
        buffer.add(_action(i, success=False))
    warning = ErrorSpiralDetector().check(buffer)
    assert warning is not None
    assert warning.details["consecutive_failures"] == 4


def test_error_spiral_run_is_bounded_by_the_buffer():
    warning = ErrorSpiralDetector().check(_buffer(successes=0, failures=N_ACTIONS))
    assert warning is not None
    assert warning.details["consecutive_failures"] == ActionBuffer().max_size


def test_error_spiral_still_fires_at_the_threshold_only():
    detector = ErrorSpiralDetector()
    assert detector.check(_buffer(successes=5, failures=2)) is None
    warning = detector.check(_buffer(successes=5, failures=3))
    assert warning is not None
    assert warning.details["consecutive_failures"] == 3


def test_growing_spiral_keeps_one_dedup_key():
    detector = ErrorSpiralDetector()
    keys = {
        warning_dedup_key(detector.check(_buffer(successes=5, failures=n)))
        for n in (3, 7, 8, 30)
    }
    assert len(keys) == 1
