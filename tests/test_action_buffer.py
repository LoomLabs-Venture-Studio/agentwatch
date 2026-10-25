"""Tests for ActionBuffer.last() ordering and edge cases.

Added alongside the fix that replaced ``list(self.actions)[-n:]`` (full
deque materialization on every windowed detector call) with an
itertools.islice-based tail read. Ordering and boundary behavior must be
preserved exactly since ~30 of the 35 registered detectors rely on
chronological ordering from this method.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from agentwatch.parser.models import Action, ActionBuffer, ToolType


def _make_action(i: int) -> Action:
    return Action(
        timestamp=datetime.now() + timedelta(seconds=i),
        tool_name=f"tool_{i}",
        tool_type=ToolType.READ,
        success=True,
    )


def _fill(buffer: ActionBuffer, count: int) -> list[Action]:
    actions = [_make_action(i) for i in range(count)]
    for a in actions:
        buffer.add(a)
    return actions


class TestActionBufferLast:
    def test_empty_buffer(self):
        buffer = ActionBuffer(max_size=100)
        assert buffer.last(5) == []

    def test_n_zero_returns_empty(self):
        buffer = ActionBuffer(max_size=100)
        _fill(buffer, 10)
        assert buffer.last(0) == []

    def test_n_negative_returns_empty(self):
        buffer = ActionBuffer(max_size=100)
        _fill(buffer, 10)
        assert buffer.last(-3) == []

    def test_n_less_than_len_returns_last_n_in_chronological_order(self):
        buffer = ActionBuffer(max_size=100)
        actions = _fill(buffer, 10)
        result = buffer.last(3)
        assert [a.tool_name for a in result] == [a.tool_name for a in actions[-3:]]

    def test_n_equal_to_len_returns_everything_in_order(self):
        buffer = ActionBuffer(max_size=100)
        actions = _fill(buffer, 5)
        result = buffer.last(5)
        assert [a.tool_name for a in result] == [a.tool_name for a in actions]

    def test_n_greater_than_len_returns_everything_in_order(self):
        buffer = ActionBuffer(max_size=100)
        actions = _fill(buffer, 4)
        result = buffer.last(50)
        assert [a.tool_name for a in result] == [a.tool_name for a in actions]

    def test_n_one_returns_most_recent_only(self):
        buffer = ActionBuffer(max_size=100)
        actions = _fill(buffer, 10)
        result = buffer.last(1)
        assert len(result) == 1
        assert result[0].tool_name == actions[-1].tool_name

    def test_respects_deque_eviction_at_max_size(self):
        buffer = ActionBuffer(max_size=5)
        actions = _fill(buffer, 10)  # only last 5 survive in the deque
        result = buffer.last(3)
        assert [a.tool_name for a in result] == [a.tool_name for a in actions[-3:]]
