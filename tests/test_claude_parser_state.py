"""Claude Code parser state across JSONL lines (Sprint 38 B + D).

B: a tool_result updates the Action of the tool_use it answers instead of
becoming a second Action, so error detectors see failed calls.
D: a message's usage is counted once, however many lines/blocks it spans.
Both run through parse_file() and the live LogWatcher path. Synthetic data only.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentwatch.detectors.health.errors import ErrorBlindnessDetector
from agentwatch.detectors.health.loops import LoopDetector
from agentwatch.detectors.registry import create_registry
from agentwatch.parser.logs import ClaudeCodeParser, parse_file
from agentwatch.parser.models import ActionBuffer
from agentwatch.parser.watcher import LogWatcher

FIXTURES = Path(__file__).parent / "fixtures"


def _via_parse_file(fixture: str | Path) -> tuple[list, ActionBuffer, list]:
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
    for line in Path(FIXTURES / fixture).read_text(encoding="utf-8").splitlines(keepends=True):
        with open(log, "a", encoding="utf-8") as f:
            f.write(line)
        for action in watcher._read_new_lines():
            buffer.add(action)
            seen.append(action)
    return seen, buffer, create_registry("health").check_health(buffer)


PATHS = pytest.mark.parametrize("run", ["parse_file", "watcher"])


def _run(run: str, fixture: str | Path, tmp_path: Path):
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


def test_unmatched_error_result_keeps_its_own_action():
    (action,) = ClaudeCodeParser().parse_entry({
        "type": "user", "sessionId": "s", "timestamp": "2026-01-01T00:00:01Z",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "gone", "is_error": True, "content": "boom"}]},
    })
    assert action.tool_name == "tool_result" and not action.success


@PATHS
@pytest.mark.parametrize(
    "fixture", ["claude_usage_one_line.jsonl", "claude_usage_split_lines.jsonl"]
)
def test_message_usage_counted_once(run, fixture, tmp_path):
    actions, buffer, _ = _run(run, fixture, tmp_path)

    assert len(actions) == 2
    # one line: first Action carries the usage; split: each line repeats it
    expected = [150, 0] if "one_line" in fixture else [150, 150]
    assert [a.tokens_in + a.tokens_out for a in actions] == expected
    stats = buffer.stats
    assert stats.total_tokens == 150
    assert stats.billed_tokens == 150
    assert stats.total_input_tokens == 100 and stats.total_output_tokens == 50
    assert stats.last_context_tokens == 100  # context fill still read
    assert stats.peak_context_tokens == 100
    assert stats.estimated_cost == pytest.approx(
        (100 * 3 + 50 * 15) / 1_000_000  # claude-sonnet-4-5 list rates, once
    )


def test_entry_without_message_id_bills_its_first_action_only():
    (a, b) = ClaudeCodeParser().parse_entry({
        "type": "assistant", "sessionId": "s", "timestamp": "2026-01-01T00:00:00Z",
        "costUSD": 0.5,
        "message": {"role": "assistant", "usage": {"input_tokens": 10, "output_tokens": 5},
                    "content": [
                        {"type": "tool_use", "id": i, "name": "Bash", "input": {"command": c}}
                        for i, c in (("a", "ls"), ("b", "pwd"))
                    ]},
    })
    assert (a.tokens_in, a.tokens_out, a.cost_usd) == (10, 5, 0.5)
    assert (b.tokens_in, b.tokens_out, b.cost_usd) == (0, 0, 0.0)


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


@PATHS
def test_streamed_output_tokens_count_at_their_maximum(run, tmp_path):
    """One message over 3 lines whose output_tokens grow 10, 40, 50: output is
    counted 50 (cc_stats takes the max per message.id), input once."""
    fixture = tmp_path / "streamed.jsonl"
    rows = []
    for i, out in enumerate((10, 40, 50)):
        rows.append({
            "type": "assistant", "sessionId": "s", "timestamp": f"2026-01-01T00:00:0{i}Z",
            "message": {"role": "assistant", "id": "msg_1", "model": "claude-sonnet-4-5",
                        "usage": {"input_tokens": 100, "output_tokens": out},
                        "content": [{"type": "tool_use", "id": f"t{i}", "name": "Bash",
                                     "input": {"command": f"echo {i}"}}]},
        })
    fixture.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    actions, buffer, _ = _run(run, fixture, tmp_path)

    assert [a.tokens_out for a in actions] == [10, 40, 50]  # each line as logged
    assert [a.tokens_in for a in actions] == [100, 100, 100]
    stats = buffer.stats
    assert (stats.total_input_tokens, stats.total_output_tokens) == (100, 50)
    assert stats.total_tokens == 150
    assert stats.billed_tokens == 150  # the max copy, not the first (110)
    assert stats.estimated_cost == pytest.approx((100 * 3 + 50 * 15) / 1_000_000)


def test_buffer_counts_cost_and_cache_once_per_message():
    parser, buffer = ClaudeCodeParser(), ActionBuffer()
    for i in range(2):
        for a in parser.parse_entry({
            "type": "assistant", "sessionId": "s", "timestamp": f"2026-01-01T00:00:0{i}Z",
            "costUSD": 0.25,
            "message": {"role": "assistant", "id": "m", "usage": {
                "input_tokens": 1, "output_tokens": 2,
                "cache_creation_input_tokens": 30, "cache_read_input_tokens": 40},
                "content": [{"type": "tool_use", "id": f"t{i}", "name": "Bash",
                             "input": {"command": "ls"}}]},
        }):
            buffer.add(a)
    stats = buffer.stats
    assert (stats.total_cost, stats.total_cache_creation, stats.total_cache_read) == (0.25, 30, 40)


def _write_failing_log(path: Path, n: int, error=lambda i: f"make: no rule {i}", prefix="") -> None:
    rows = []
    for i in range(n):
        ts = f"2026-01-01T{i // 3600:02d}:{i // 60 % 60:02d}:{i % 60:02d}Z"
        rows.append({
            "type": "assistant", "sessionId": "s", "timestamp": ts,
            "message": {"role": "assistant", "id": f"m{i}", "content": [
                {"type": "tool_use", "id": f"t{i}", "name": "Bash",
                 "input": {"command": f"{prefix}step {i}"}}]},
        })
        rows.append({
            "type": "user", "sessionId": "s", "timestamp": ts,
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": f"t{i}", "is_error": True,
                 "content": error(i)}]},
        })
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def _run_log(run: str, log: Path, tmp_path: Path, mode: str = "health"):
    if run == "parse_file":
        buffer = ActionBuffer()
        warnings = create_registry(mode).scan(parse_file(log), buffer)
        return buffer, warnings
    live = tmp_path / "live.jsonl"
    live.write_text("", encoding="utf-8")
    watcher, buffer = LogWatcher(live), ActionBuffer()
    for line in log.read_text(encoding="utf-8").splitlines(keepends=True):
        with open(live, "a", encoding="utf-8") as f:
            f.write(line)
        for action in watcher._read_new_lines():
            buffer.add(action)
    return buffer, create_registry(mode).check_health(buffer)


@PATHS
def test_error_count_is_exact_past_the_buffer_size(run, tmp_path):
    log = tmp_path / "many.jsonl"
    _write_failing_log(log, 601)
    buffer, _ = _run_log(run, log, tmp_path)

    assert buffer.stats.error_count == 601
    assert len(buffer.recent_errors(1000)) == 601


@PATHS
def test_secret_in_failed_tool_result_is_still_a_leak(run, tmp_path):
    token = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    log = tmp_path / "leak.jsonl"
    _write_failing_log(log, 1, error=lambda i: f"curl failed, TOKEN={token}")
    actions = list(parse_file(log))
    assert token not in actions[0].error_message  # the error text stays masked
    assert token in actions[0].incoming_message  # the scanner needs the raw text

    buffer = ActionBuffer()
    warnings = create_registry("security").scan(iter(actions), buffer)
    assert "secret_leak" in {w.signal for w in warnings}
    assert all(token not in str(w.details) + w.message for w in warnings)


@PATHS
def test_syntax_loop_fires_at_the_same_call_count_as_before(run, tmp_path):
    """8 SyntaxError calls (16 Actions on develop) opened the window-15 gate."""
    log = tmp_path / "syntax.jsonl"
    _write_failing_log(log, 8, error=lambda i: f"SyntaxError: bad {i}")
    _, warnings = _run_log(run, log, tmp_path)

    assert "syntax_loop" in {w.signal for w in warnings}


def test_no_history_gate_counts_raw_actions():
    """Warm-up gates use buffer.history_len (a merged failure is two calls' worth),
    except the two that read only the failures themselves."""
    import re

    root = Path(__file__).parent.parent / "src" / "agentwatch" / "detectors" / "health"
    gates = {
        (p.name, line.strip())
        for p in root.glob("*.py")
        for line in p.read_text(encoding="utf-8").splitlines()
        if re.match(r"\s*if len\(buffer\) <", line)
    }
    assert gates == {
        ("errors.py", "if len(buffer) < self.threshold:"),
        ("errors.py", "if len(buffer) < self.min_actions:"),
    }


def test_peak_usage_map_is_bounded(monkeypatch):
    import agentwatch.parser.models as models

    monkeypatch.setattr(models, "_MAX_PEAK_MESSAGES", 3)
    parser, buffer = ClaudeCodeParser(), ActionBuffer()
    for i in range(10):
        for a in parser.parse_entry({
            "type": "assistant", "sessionId": "s", "timestamp": "2026-01-01T00:00:00Z",
            "message": {"role": "assistant", "id": f"m{i}", "usage": {"input_tokens": 5},
                        "content": [{"type": "tool_use", "id": f"t{i}", "name": "Bash",
                                     "input": {"command": "ls"}}]},
        }):
            buffer.add(a)
    assert len(buffer._peak_usage) == 3
    assert buffer.stats.total_input_tokens == 50


def test_tool_result_text_is_not_the_stated_task():
    from agentwatch.llm import OllamaAnalyzer

    parser, buffer = ClaudeCodeParser(), ActionBuffer()
    for e in (
        {"type": "assistant", "sessionId": "s", "timestamp": "2026-01-01T00:00:00Z",
         "message": {"role": "assistant", "id": "m", "content": [
             {"type": "tool_use", "id": "t", "name": "Bash", "input": {"command": "ls"}}]}},
        {"type": "user", "sessionId": "s", "timestamp": "2026-01-01T00:00:01Z",
         "message": {"role": "user", "content": [
             {"type": "tool_result", "tool_use_id": "t", "content": "README.md"}]}},
    ):
        for a in parser.parse_entry(e):
            buffer.add(a)

    assert buffer.actions[0].incoming_message == "README.md"
    analyzer = OllamaAnalyzer.__new__(OllamaAnalyzer)
    assert analyzer.assess_goal_alignment(buffer) is None
