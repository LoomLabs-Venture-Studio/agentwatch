"""Regression tests for #38: session duration on current Claude Code logs."""

import json
from datetime import datetime, timedelta

from agentwatch.health.score import calculate_efficiency
from agentwatch.parser.logs import parse_file
from agentwatch.parser.models import Action, ActionBuffer, ToolType

T0 = datetime(2026, 1, 1, 12, 0, 0)


def _assistant(minute: int) -> dict:
    return {
        "type": "assistant",
        "sessionId": "s1",
        "timestamp": (T0 + timedelta(minutes=minute)).isoformat() + "Z",
        "message": {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": f"t{minute}", "name": "Read",
                         "input": {"file_path": f"f{minute}.py"}}],
            "usage": {"input_tokens": 2000, "output_tokens": 1000},
        },
    }


def _buffer(actions) -> ActionBuffer:
    buffer = ActionBuffer(max_size=1000)
    for action in actions:
        buffer.add(action)
    return buffer


def test_untimed_metadata_lines_do_not_set_duration(tmp_path):
    """Current Claude Code logs interleave metadata lines with no timestamp
    (last-prompt, mode, ai-title, ...). They used to become actions stamped
    datetime.now(), so duration came out ~0 (metadata first) or "now minus
    session start" (metadata last)."""
    meta = [{"type": t, "sessionId": "s1"} for t in ("mode", "last-prompt", "ai-title")]
    lines = meta + [_assistant(m) for m in range(0, 11)] + meta
    log = tmp_path / "s1.jsonl"
    log.write_text("\n".join(json.dumps(e) for e in lines) + "\n", encoding="utf-8")

    buffer = _buffer(parse_file(log))
    assert len(buffer) == 11
    assert buffer.stats.duration_minutes == 10.0
    report = calculate_efficiency([], buffer)
    assert report.token_burn_rate == 3300.0  # 33K fresh tokens / 10 min


def test_idle_gap_of_resumed_session_is_capped():
    """A session resumed a day later must not count the idle day."""
    def act(ts):
        return Action(timestamp=ts, tool_name="Read", tool_type=ToolType.READ, success=True)

    times = [T0 + timedelta(minutes=m) for m in range(0, 11)]
    resumed = T0 + timedelta(days=1)
    times += [resumed + timedelta(minutes=m) for m in range(0, 6)]
    buffer = _buffer(act(t) for t in times)
    # 10 + 5 active minutes, plus the idle gap capped at 30.
    assert buffer.stats.duration_minutes == 45.0


def test_out_of_order_earlier_action_extends_span():
    def act(ts):
        return Action(timestamp=ts, tool_name="Read", tool_type=ToolType.READ, success=True)

    buffer = _buffer(act(T0 + timedelta(minutes=m)) for m in (5, 10, 0))
    assert buffer.stats.duration_minutes == 10.0
    assert buffer.stats.start_time == T0
