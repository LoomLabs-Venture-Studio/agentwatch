"""#44: no parser stamps datetime.now() on an action.

A missing or unparseable timestamp leaves the action untimed (None). It is
still counted and scanned, but adds nothing to session duration.
"""

from datetime import datetime, timedelta

import pytest

from agentwatch.parser.codex import CodexParser
from agentwatch.parser.cursor_source import bubble_to_action
from agentwatch.parser.logs import parse_claude_code_entry, parse_moltbot_entry
from agentwatch.parser.models import Action, ActionBuffer, ToolType

BAD = ["not-a-date", 1735732800, None]
T0 = datetime(2026, 1, 1, 12, 0, 0)


def _claude(ts):
    return {
        "type": "assistant", "sessionId": "s1", "timestamp": ts,
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "a.py"}}]},
    }


def _first(result):
    return result[0] if isinstance(result, list) else result


@pytest.mark.parametrize("ts", BAD)
def test_claude_code(ts):
    action = _first(parse_claude_code_entry(_claude(ts)))
    assert action is not None and action.timestamp is None


@pytest.mark.parametrize("ts", BAD)
def test_moltbot(ts):
    entry = {"role": "assistant", "tool_call": {"name": "edit", "input": {}}, "ts": ts}
    action = parse_moltbot_entry(entry)
    assert action is not None and action.timestamp is None


@pytest.mark.parametrize("ts", BAD)
def test_codex(ts):
    entry = {"type": "response_item", "timestamp": ts, "payload": {
        "type": "function_call", "name": "shell", "call_id": "c1",
        "arguments": '{"command": ["ls"]}'}}
    parser = CodexParser()
    actions = parser.parse_line(entry) + parser.flush()
    assert actions and all(a.timestamp is None for a in actions)


@pytest.mark.parametrize("ts", BAD)
def test_cursor(ts):
    action = bubble_to_action({"type": 2, "createdAt": ts, "text": "hi"}, "c1")
    assert action.timestamp is None


@pytest.mark.parametrize("position", [0, -1])
def test_untimed_action_adds_no_duration(position):
    """QA repro: a stray first or last action used to make a 120-minute
    session report 30 or 150 minutes."""
    timed = [Action(timestamp=T0 + timedelta(minutes=m), tool_name="Read",
                    tool_type=ToolType.READ, success=True) for m in range(0, 121, 10)]
    stray = Action(timestamp=None, tool_name="Read", tool_type=ToolType.READ, success=True)
    actions = timed[:]
    actions.insert(len(actions) if position == -1 else 0, stray)
    buffer = ActionBuffer()
    for a in actions:
        buffer.add(a)
    assert len(buffer) == 14
    assert buffer.stats.duration_minutes == 120
