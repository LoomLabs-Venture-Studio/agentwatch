"""Tests for `agentwatch.detectors.health.loops`.

Covers `LoopDetector`'s real-repetition detection, and the Cursor
role-label carve-out (`NON_TOOL_ROLE_LABELS`): Cursor's `state.vscdb` bubbles
always carry `tool_name` "user_message"/"assistant_message" (see
`cursor_source.py::bubble_to_action`), which used to make any ordinary
multi-turn Cursor conversation trip a false "loop" warning purely from the
constant role label, not from real repeated tool calls (PLAYBOOK Sprint 7,
2026-07-14 live finding).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from agentwatch.detectors.health.loops import LoopDetector
from agentwatch.parser.models import Action, ActionBuffer, ToolType


def _make_action(
    tool_name: str,
    tool_type: ToolType = ToolType.UNKNOWN,
    file_path: str | None = None,
    offset_seconds: float = 0,
) -> Action:
    return Action(
        timestamp=datetime(2026, 1, 29, 12, 0) + timedelta(seconds=offset_seconds),
        tool_name=tool_name,
        tool_type=tool_type,
        success=True,
        file_path=file_path,
    )


class TestLoopDetector:
    def test_no_fire_under_window(self):
        det = LoopDetector(threshold=4, window=10)
        buf = ActionBuffer()
        for i in range(5):
            buf.add(_make_action("bash", ToolType.BASH))
        assert det.check(buf) is None

    def test_fires_on_real_repeated_tool_calls(self):
        det = LoopDetector(threshold=4, window=10)
        buf = ActionBuffer()
        for i in range(10):
            buf.add(_make_action("bash", ToolType.BASH, file_path="run.sh", offset_seconds=i))
        warning = det.check(buf)
        assert warning is not None
        assert warning.signal == "loop"
        assert "bash" in warning.message

    def test_cursor_role_labels_do_not_trip_false_loop(self):
        """The Sprint 7 live finding: a normal back-and-forth Cursor
        conversation (constant "user_message"/"assistant_message" tool_name,
        no real repeated tool call) must not be flagged as a loop."""
        det = LoopDetector(threshold=4, window=10)
        buf = ActionBuffer()
        for i in range(5):
            buf.add(_make_action("user_message", offset_seconds=i * 2))
            buf.add(_make_action("assistant_message", offset_seconds=i * 2 + 1))
        assert det.check(buf) is None

    def test_real_loop_still_detected_alongside_cursor_role_labels(self):
        """A genuine repeated tool call mixed into a Cursor-style window
        (were `tool_name` ever to carry real per-turn values from
        `toolResults`) must still be caught -- the carve-out only excludes
        the role-label sentinels, not everything else."""
        det = LoopDetector(threshold=4, window=10)
        buf = ActionBuffer()
        buf.add(_make_action("user_message", offset_seconds=0))
        buf.add(_make_action("assistant_message", offset_seconds=1))
        for i in range(4):
            buf.add(
                _make_action(
                    "run_command", ToolType.BASH, file_path="build.sh", offset_seconds=2 + i
                )
            )
        buf.add(_make_action("user_message", offset_seconds=10))
        buf.add(_make_action("assistant_message", offset_seconds=11))
        buf.add(_make_action("user_message", offset_seconds=12))
        buf.add(_make_action("assistant_message", offset_seconds=13))

        warning = det.check(buf)
        assert warning is not None
        assert warning.details["tool"] == "run_command"
        assert warning.details["count"] == 4
