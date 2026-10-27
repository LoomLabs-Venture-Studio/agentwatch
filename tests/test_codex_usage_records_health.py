"""Codex `token_count` usage records must not distort the health detectors.

Every Codex turn is followed by a `token_count` event, which the parser keeps
as an Action (tool_name USAGE_RECORD) so tokens still count. Health detectors
that tally, window or streak-count actions must treat them as non-actions.
Synthetic rollouts only.
"""

from __future__ import annotations

import json

from agentwatch.detectors.health.context import ContextRotDetector, RediscoveryDetector
from agentwatch.detectors.health.errors import (
    ErrorBlindnessDetector,
    ErrorSpiralDetector,
    HighErrorRateDetector,
    SyntaxLoopDetector,
)
from agentwatch.detectors.health.loops import LoopDetector, RereadDetector, StallDetector
from agentwatch.detectors.health.stuck import (
    ErrorClassPersistenceDetector,
    ExplorationStallDetector,
    FileChurnDetector,
    SameOutcomeDetector,
)
from agentwatch.detectors.health.tool_thrash import compute_tool_thrash
from agentwatch.detectors.registry import create_registry
from agentwatch.parser.logs import parse_file
from agentwatch.parser.models import (
    USAGE_RECORD,
    Action,
    ActionBuffer,
    ToolType,
    is_tool_call,
)

USAGE = {"input_tokens": 100, "cached_input_tokens": 0, "output_tokens": 10,
         "reasoning_output_tokens": 0, "total_tokens": 110}


def _line(ts, type_, payload):
    return {"timestamp": f"2026-10-09T14:{ts // 60:02d}:{ts % 60:02d}Z",
            "type": type_, "payload": payload}


def _rollout(tmp_path, commands, usage=True):
    entries = [_line(0, "session_meta", {"id": "s1", "cwd": "/x", "cli_version": "0.162.0"})]
    for i, cmd in enumerate(commands):
        t = 10 + i * 4
        entries.append(_line(t, "response_item", {
            "type": "function_call", "call_id": f"c{i}", "name": "shell",
            "arguments": json.dumps({"command": ["bash", "-lc", cmd]})}))
        entries.append(_line(t + 1, "response_item", {
            "type": "function_call_output", "call_id": f"c{i}", "output": "ok"}))
        if usage:
            entries.append(_line(t + 2, "event_msg", {
                "type": "token_count",
                "info": {"last_token_usage": USAGE, "total_token_usage": USAGE,
                         "model_context_window": 258_400}}))
    path = tmp_path / "rollout-2026-10-09T14-00-00-s1.jsonl"
    path.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")
    return path


def _buffer(path):
    buf = ActionBuffer()
    for action in parse_file(path):
        buf.add(action)
    return buf


def _signals(buf):
    registry = create_registry(mode="health")
    return registry.scan(iter(list(buf.actions)), buf)


def test_distinct_calls_with_usage_records_are_not_a_loop(tmp_path):
    buf = _buffer(_rollout(tmp_path, [f"cat f{i}.ts" for i in range(8)]))
    assert any(a.tool_name == USAGE_RECORD for a in buf.actions)
    assert LoopDetector().check(buf) is None
    assert "loop" not in {w.signal for w in _signals(buf)}


def test_real_loop_still_caught_with_usage_records(tmp_path):
    with_usage = LoopDetector().check(_buffer(_rollout(tmp_path, ["cat a.ts"] * 10)))
    bare_dir = tmp_path / "bare"
    bare_dir.mkdir()
    bare = LoopDetector().check(_buffer(_rollout(bare_dir, ["cat a.ts"] * 10, usage=False)))
    assert with_usage is not None and bare is not None
    assert with_usage.severity == bare.severity
    assert with_usage.details["count"] == bare.details["count"] == 10


# --- synthetic buffers: usage records interleaved with agent actions -------------

def _act(i, tool="Bash", ttype=ToolType.BASH, ok=True, path=None, cmd=None, err=None):
    return Action(timestamp=None, tool_name=tool, tool_type=ttype, success=ok,
                  file_path=path, command=cmd, error_message=err)


def _usage():
    return Action(timestamp=None, tool_name=USAGE_RECORD, tool_type=ToolType.UNKNOWN,
                  success=True)


def _interleave(actions, usage=True):
    buf = ActionBuffer()
    for a in actions:
        buf.add(a)
        if usage:
            buf.add(_usage())
    return buf


def test_is_tool_call_predicate():
    assert is_tool_call(_act(0))
    assert not is_tool_call(_usage())
    assert not is_tool_call(_act(0, tool="user_message"))


def test_error_spiral_streak_not_broken_by_usage_records():
    acts = [_act(i, ok=False, err=f"boom {i}", cmd=f"c{i}") for i in range(4)]
    assert ErrorSpiralDetector().check(_interleave(acts, usage=False)) is not None
    assert ErrorSpiralDetector().check(_interleave(acts)) is not None


def test_high_error_rate_not_diluted_by_usage_records():
    acts = [_act(i, ok=False, err=f"boom {i}", cmd=f"c{i}") for i in range(12)]
    assert HighErrorRateDetector().check(_interleave(acts)) is not None


def _neutral(n, start=0):
    """Distinct successful reads: nothing for a detector to key on."""
    return [_act(i, "Read", ToolType.READ, path=f"n{i}.py") for i in range(start, start + n)]


def _fails(n, err):
    return [_act(i, ok=False, err=err, cmd=f"c{i}") for i in range(n)]


# A usage record after every action doubles the raw actions, so a window of N
# raw actions held N/2 real ones. Each test puts the signal in the oldest part
# of an exactly-N-real-action window: seen only when usage records take no slots.

def test_error_blindness_window_not_filled_by_usage_records():
    acts = _fails(3, "same failure") + _neutral(12)
    assert ErrorBlindnessDetector().check(_interleave(acts, usage=False)) is not None
    assert ErrorBlindnessDetector().check(_interleave(acts)) is not None


def test_syntax_loop_window_not_filled_by_usage_records():
    acts = _fails(3, "SyntaxError: bad") + _neutral(12)
    assert SyntaxLoopDetector().check(_interleave(acts, usage=False)) is not None
    assert SyntaxLoopDetector().check(_interleave(acts)) is not None


def test_reread_window_not_halved_by_usage_records():
    acts = [_act(i, "Read", ToolType.READ, path="a.py") for i in range(3)] + _neutral(12)
    assert RereadDetector().check(_interleave(acts, usage=False)) is not None
    assert RereadDetector().check(_interleave(acts)) is not None


def test_stall_window_not_halved_by_usage_records():
    acts = _neutral(15)
    assert StallDetector().check(_interleave(acts, usage=False)) is not None
    assert StallDetector().check(_interleave(acts)) is not None


def _edit_fail_cycles(n):
    out = []
    for i in range(n):
        out.append(_act(i, "Edit", ToolType.EDIT, path="a.py"))
        out.append(_act(i, ok=False, err="AssertionError: nope", cmd="pytest"))
    return out


def test_same_outcome_window_not_halved_by_usage_records():
    acts = _edit_fail_cycles(3) + _neutral(19)
    assert SameOutcomeDetector().check(_interleave(acts, usage=False)) is not None
    assert SameOutcomeDetector().check(_interleave(acts)) is not None


def test_file_churn_window_not_halved_by_usage_records():
    acts = [_act(i, "Edit", ToolType.EDIT, path="a.py") for i in range(4)] + _neutral(26)
    assert FileChurnDetector().check(_interleave(acts, usage=False)) is not None
    assert FileChurnDetector().check(_interleave(acts)) is not None


def test_error_class_persistence_window_not_halved_by_usage_records():
    acts = _edit_fail_cycles(4) + _neutral(12)
    assert ErrorClassPersistenceDetector().check(_interleave(acts, usage=False)) is not None
    assert ErrorClassPersistenceDetector().check(_interleave(acts)) is not None


def test_exploration_stall_split_ignores_usage_records():
    # 20 real actions in the recent window; a new file in its oldest part.
    acts = [_act(i, "Read", ToolType.READ, path=f"f{i % 3}.py") for i in range(10)]
    acts += _neutral(1, 100) + [_act(i, "Read", ToolType.READ, path="f0.py") for i in range(19)]
    bare = ExplorationStallDetector().check(_interleave(acts, usage=False))
    assert bare is None
    assert ExplorationStallDetector().check(_interleave(acts)) is None


def test_context_rot_ignores_usage_records():
    early = [_act(i, "Edit", ToolType.EDIT, path=f"e{i}.py") for i in range(4)]
    acts = early + [_act(i, "Read", ToolType.READ, path=f"r{i % 5}.py") for i in range(80)]
    assert ContextRotDetector().check(_interleave(acts, usage=False)) is not None
    assert ContextRotDetector().check(_interleave(acts)) is not None


def test_rediscovery_window_not_halved_by_usage_records():
    acts = _neutral(200)
    for i in (0, 40, 80):
        acts[i] = _act(i, "Read", ToolType.READ, path="x.py")
    assert RediscoveryDetector().check(_interleave(acts, usage=False)) is not None
    assert RediscoveryDetector().check(_interleave(acts)) is not None


def test_repeated_tool_calls_metric_ignores_usage_records():
    acts = [_act(i, cmd=f"cat f{i}.ts") for i in range(8)]
    result = compute_tool_thrash(_interleave(acts))
    repeated = next(c for c in result.contributors if c.name == "repeated_tool_calls")
    assert repeated.value == 0.0
