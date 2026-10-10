"""Codex dashboard metrics (#82), pinned to a real ChatGPT-desktop rollout.

Numbers come from a real 2-tool-call thread (gpt-6-luna, 2026-10-09):
3 token_count events, 74,042 input tokens of which 58,624 cached, last
call 28,031 input tokens, model_context_window 258,400.
"""

from __future__ import annotations

import json

from agentwatch.health.score import calculate_efficiency
from agentwatch.parser.logs import parse_file
from agentwatch.parser.models import ActionBuffer
from agentwatch.ui.app import EfficiencyBar

WINDOW = 258_400
# (input_tokens, cached_input_tokens, output_tokens) per model call
CALLS = [(18_111, 13_440, 120), (27_900, 17_792, 106), (28_031, 27_392, 34)]


def _token_count(ts, inp, cached, out):
    usage = {"input_tokens": inp, "cached_input_tokens": cached,
             "output_tokens": out, "reasoning_output_tokens": 0,
             "total_tokens": inp + out}
    return {"timestamp": ts, "type": "event_msg", "payload": {
        "type": "token_count",
        "info": {"last_token_usage": usage, "total_token_usage": usage,
                 "model_context_window": WINDOW},
    }}


def _call(ts, call_id):
    return {"timestamp": ts, "type": "response_item", "payload": {
        "type": "custom_tool_call", "call_id": call_id, "name": "exec",
        "input": "echo hi", "status": "completed"}}


def _output(ts, call_id):
    return {"timestamp": ts, "type": "response_item", "payload": {
        "type": "custom_tool_call_output", "call_id": call_id,
        "output": "Script completed\nOutput:\nhi"}}


def _buffer(tmp_path):
    entries = [
        {"timestamp": "2026-10-09T14:25:39Z", "type": "session_meta",
         "payload": {"id": "s1", "cwd": "C:/x", "cli_version": "0.162.0"}},
        _call("2026-10-09T14:25:43Z", "c1"), _output("2026-10-09T14:25:50Z", "c1"),
        _token_count("2026-10-09T14:25:50.4Z", *CALLS[0]),
        _call("2026-10-09T14:25:52Z", "c2"), _output("2026-10-09T14:25:54Z", "c2"),
        _token_count("2026-10-09T14:25:54.4Z", *CALLS[1]),
        _token_count("2026-10-09T14:25:58Z", *CALLS[2]),
    ]
    path = tmp_path / "rollout-2026-10-09T14-25-39-s1.jsonl"
    path.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")
    buf = ActionBuffer()
    for action in parse_file(path):
        buf.add(action)
    return buf


def test_token_count_records_not_counted_as_actions(tmp_path):
    buf = _buffer(tmp_path)
    assert buf.stats.activity_count == 2
    assert buf.stats.action_count == 5  # change-detection counter: every record


def test_actions_per_turn_counts_tool_calls_only(tmp_path):
    report = calculate_efficiency([], _buffer(tmp_path))
    assert report.actions_per_turn == 2.0


def test_cached_input_split_from_fresh_input(tmp_path):
    stats = _buffer(tmp_path).stats
    assert stats.total_cache_read == 58_624
    assert stats.total_input_tokens == 74_042 - 58_624
    assert stats.peak_context_tokens == 28_031  # fresh + cached, unchanged


def test_cache_hit_rate_is_share_of_prompt_served_from_cache(tmp_path):
    report = calculate_efficiency([], _buffer(tmp_path))
    assert report.cache_hit_rate == round(58_624 / 74_042, 3)


def test_context_pct_uses_reported_window(tmp_path):
    report = calculate_efficiency([], _buffer(tmp_path))
    assert report.context_usage_pct == round(28_031 / WINDOW * 100, 1)


def test_cost_unknown_for_unpriced_model(tmp_path):
    report = calculate_efficiency([], _buffer(tmp_path))
    assert report.cost_total is None and report.cost_velocity is None
    bar = EfficiencyBar()
    bar._report = report
    assert "Est. cost: n/a" in bar._build_content()
