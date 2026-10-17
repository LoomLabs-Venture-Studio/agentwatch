"""warning_dedup_key must survive error text that changes run to run.

Since #144 a loop warning carries the real linked error. pytest durations,
pids, temp paths and timestamps change on every run, so a key built from
that text changed on every call: the coach re-sent the loop note, and SIEM
export / the TUI saw a new warning each time.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from agentwatch.detectors.base import (
    Category,
    Severity,
    Warning,
    normalize_error,
    warning_dedup_key,
)
from agentwatch.detectors.health.loops import LoopDetector
from agentwatch.parser.models import Action, ActionBuffer, ToolType


def _failing_bash(i: int, error: str) -> Action:
    return Action(
        timestamp=datetime(2026, 10, 18, 12, 0) + timedelta(seconds=i),
        tool_name="Bash",
        tool_type=ToolType.BASH,
        success=False,
        command="python -m pytest tests/test_app.py",
        error_message=error,
    )


def _warning(signal: str, **details) -> Warning:
    return Warning(
        category=Category.ERRORS, severity=Severity.HIGH, signal=signal, message="m",
        details=details,
    )


def test_loop_key_is_stable_when_only_the_duration_changes():
    buf, keys = ActionBuffer(), set()
    for i in range(12):
        buf.add(_failing_bash(i, f"FAILED tests/test_app.py::test_x\n1 failed in 0.{53 + i}s"))
        w = LoopDetector().check(buf)
        if w:
            keys.add(warning_dedup_key(w))
    assert len(keys) == 1


def test_loops_on_different_tools_keep_different_keys():
    """With no path or command, the loop is identified by tool + input hash."""
    def loop(tool: str) -> Warning:
        buf = ActionBuffer()
        for i in range(10):
            buf.add(Action(
                timestamp=None, tool_name=tool, tool_type=ToolType.MCP, success=True,
                raw={"input": {"text": "document.title"}},
            ))
        return LoopDetector().check(buf)

    a, b = loop("mcp__chrome__javascript_tool"), loop("mcp__chrome__read_page")
    assert a and b and warning_dedup_key(a) != warning_dedup_key(b)


def test_thrash_and_stuck_keys_ignore_volatile_error_parts():
    runs = [
        "2026-10-18T12:00:01.123Z pid 4242 AssertionError in /tmp/pytest-of-dev/pytest-17/"
        "test_x0/app.py line 12 (0x7f3a9c) 1 failed in 0.53s",
        "2026-10-18T12:04:59.987Z pid 5170 AssertionError in /tmp/pytest-of-dev/pytest-18/"
        "test_x0/app.py line 14 (0x7f3b11) 1 failed in 0.61s",
    ]
    for signal in ("thrash", "same_outcome", "file_churn"):
        a, b = (warning_dedup_key(_warning(signal, file="app.py", last_error=e)) for e in runs)
        assert a == b, signal


def test_windows_temp_paths_and_whitespace_are_normalized():
    a = r"PermissionError: C:\Users\dev\AppData\Local\Temp\tmpab12cd\out.txt  in 1.2 s"
    b = r"PermissionError: C:\Users\dev\AppData\Local\Temp\tmpzz98yx\out.txt in 0.9s"
    assert normalize_error(a) == normalize_error(b)


def test_genuinely_different_errors_keep_different_keys():
    a = "ModuleNotFoundError: No module named 'requests'"
    b = "AssertionError: assert response.status_code == 200"
    assert warning_dedup_key(_warning("error_blindness", error_pattern=a)) != warning_dedup_key(
        _warning("error_blindness", error_pattern=b)
    )
    assert warning_dedup_key(_warning("thrash", file="app.py", last_error=a)) != (
        warning_dedup_key(_warning("thrash", file="app.py", last_error=b))
    )
