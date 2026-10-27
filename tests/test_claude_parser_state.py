"""Claude Code parser state across JSONL lines (Sprint 38 B + D).

B: a tool_result updates the Action of the tool_use it answers instead of
becoming a second Action, so error detectors see failed calls.
D: a message's usage is counted once, however many lines/blocks it spans.
Both run through parse_file() and the live LogWatcher path. Synthetic data only.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentwatch.detectors.health.errors import ErrorBlindnessDetector
from agentwatch.detectors.health.loops import LoopDetector
from agentwatch.detectors.registry import create_registry
from agentwatch.parser.logs import ClaudeCodeParser, parse_file
from agentwatch.parser.models import ActionBuffer
from agentwatch.parser.watcher import LogWatcher

FIXTURES = Path(__file__).parent / "fixtures"


def _via_parse_file(fixture: str) -> tuple[list, ActionBuffer, list]:
    actions = list(parse_file(FIXTURES / fixture))
    buffer = ActionBuffer()
    warnings = create_registry("health").scan(iter(actions), buffer)
    return actions, buffer, warnings


def _via_watcher(fixture: str, tmp_path: Path) -> tuple[list, ActionBuffer, list]:
    """Append the fixture to a temp file one line at a time, polling after each
    line, and feed the buffer as the live consumer does."""
    log = tmp_path / "session.jsonl"
    log.write_text("", encoding="utf-8")
    watcher = LogWatcher(log)
    buffer = ActionBuffer()
    seen = []
    for line in (FIXTURES / fixture).read_text(encoding="utf-8").splitlines(keepends=True):
        with open(log, "a", encoding="utf-8") as f:
            f.write(line)
        for action in watcher._read_new_lines():
            buffer.add(action)
            seen.append(action)
    return seen, buffer, create_registry("health").check_health(buffer)


PATHS = pytest.mark.parametrize("run", ["parse_file", "watcher"])


def _run(run: str, fixture: str, tmp_path: Path):
    if run == "parse_file":
        return _via_parse_file(fixture)
    return _via_watcher(fixture, tmp_path)


@PATHS
def test_failed_calls_are_marked_and_fire_error_detectors(run, tmp_path):
    actions, buffer, warnings = _run(run, "claude_error_spiral.jsonl", tmp_path)

    assert [a.tool_name for a in actions] == ["Bash"] * 10  # no tool_result actions
    assert [a.success for a in actions] == [True] * 4 + [False] * 6
    assert all("No rule to make target" in a.error_message for a in actions[4:])
    signals = {w.signal for w in warnings}
    assert {"error_spiral", "high_error_rate"} <= signals
    assert buffer.stats.error_count == 6
    assert len(buffer.recent_errors(10)) == 6


@PATHS
def test_successful_result_content_is_kept_on_the_call(run, tmp_path):
    actions, _, _ = _run(run, "claude_result_content.jsonl", tmp_path)

    assert len(actions) == 1
    assert actions[0].success is True
    assert actions[0].incoming_message == "README.md\nsetup.py"


def test_result_content_is_redacted():
    parser = ClaudeCodeParser()
    token = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    (call,) = parser.parse_entry({
        "type": "assistant", "sessionId": "s", "timestamp": "2026-01-01T00:00:00Z",
        "message": {"role": "assistant", "id": "m", "content": [
            {"type": "tool_use", "id": "t", "name": "Bash", "input": {"command": "env"}}]},
    })
    parser.parse_entry({
        "type": "user", "sessionId": "s", "timestamp": "2026-01-01T00:00:01Z",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t", "content": f"TOKEN={token}"}]},
    })
    assert token not in call.incoming_message


def test_unmatched_error_result_keeps_its_own_action():
    (action,) = ClaudeCodeParser().parse_entry({
        "type": "user", "sessionId": "s", "timestamp": "2026-01-01T00:00:01Z",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "gone", "is_error": True, "content": "boom"}]},
    })
    assert action.tool_name == "tool_result" and not action.success


def _failing_calls(n: int) -> list:
    """n identical failing Bash calls, call and result on separate lines."""
    parser = ClaudeCodeParser()
    actions = []
    for i in range(n):
        ts = f"2026-01-01T00:00:{i:02d}Z"
        actions += parser.parse_entry({
            "type": "assistant", "sessionId": "s", "timestamp": ts,
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": f"t{i}", "name": "Bash", "input": {"command": "x"}}]},
        })
        parser.parse_entry({
            "type": "user", "sessionId": "s", "timestamp": ts,
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": f"t{i}", "is_error": True,
                 "content": "boom"}]},
        })
    return actions


@pytest.mark.parametrize(
    "detector, window", [(LoopDetector, 10), (ErrorBlindnessDetector, 15)]
)
def test_history_gate_counts_a_merged_failure_twice(detector, window):
    """A failed call was two Actions (call + result) before results were merged,
    so window//2 rounded up failing calls open the gate; one fewer does not."""
    need = (window + 1) // 2
    for n, fires in ((need - 1, False), (need, True)):
        buffer = ActionBuffer()
        for a in _failing_calls(n):
            buffer.add(a)
        assert (detector().check(buffer) is not None) is fires, n


def test_history_gate_unchanged_for_successful_calls():
    buffer = ActionBuffer()
    for a in _failing_calls(9):
        a.success, a.error_message, a.error_merged = True, None, False
        buffer.add(a)
    assert LoopDetector().check(buffer) is None  # 9 < 10 calls
    a = _failing_calls(1)[0]
    a.success, a.error_message, a.error_merged = True, None, False
    buffer.add(a)
    assert LoopDetector().check(buffer) is not None
