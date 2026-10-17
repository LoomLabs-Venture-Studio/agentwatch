"""Dollar cost per health finding: pricing table, attribution, display."""

import json
from datetime import datetime, timedelta

import pytest
from click.testing import CliRunner

from agentwatch.cc_stats import PRICING, price_for, usage_cost_usd
from agentwatch.cli import cli
from agentwatch.detectors import create_registry
from agentwatch.detectors.health import LoopDetector
from agentwatch.parser import ActionBuffer, parse_file
from agentwatch.parser.models import Action, ToolType

T0 = datetime(2026, 10, 1, 12, 0, 0)
# One API call's usage in the fixtures, and its Opus 5.5 price:
# 10*$4 + 200*$20 + 1000*$8 (1h write) + 40000*$0.20, per MTok.
USAGE = {
    "input_tokens": 10,
    "output_tokens": 200,
    "cache_creation_input_tokens": 1000,
    "cache_read_input_tokens": 40_000,
    "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 1000},
}
CALL_TOKENS = 41_210
CALL_COST = 0.02004


def _assistant(i, msg_id, block, model):
    return {
        "type": "assistant", "sessionId": "s1",
        "timestamp": (T0 + timedelta(seconds=i)).isoformat() + "Z",
        "message": {"id": msg_id, "role": "assistant", "model": model,
                    "content": [block], "usage": USAGE},
    }


def _error(i, tool_id, text="FAILED test_x.py::test_a - AssertionError"):
    return {
        "type": "user", "sessionId": "s1",
        "timestamp": (T0 + timedelta(seconds=i)).isoformat() + "Z",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": tool_id, "is_error": True, "content": text},
        ]},
    }


def _bash(tool_id, cmd="pytest -x"):
    return {"type": "tool_use", "id": tool_id, "name": "Bash", "input": {"command": cmd}}


def _write(path, lines):
    path.write_text("\n".join(json.dumps(e) for e in lines) + "\n", encoding="utf-8")
    return path


def loop_log(path, model="claude-opus-5-5", attempts=8):
    """The same failing command retried: one API call per attempt."""
    lines = []
    for n in range(attempts):
        lines.append(_assistant(2 * n, f"msg_{n}", _bash(f"tu_{n}"), model))
        lines.append(_error(2 * n + 1, f"tu_{n}"))
    return _write(path, lines)


def spiral_log(path):
    """One call issues three Bash calls in parallel; all three fail. Claude Code
    writes a line per tool_use block, each repeating the call's full usage."""
    text = {"type": "text", "text": "Running checks."}
    lines = [_assistant(0, "msg_ok", text, "claude-opus-5-5")]
    lines += [_assistant(1, "msg_par", _bash(f"tu_{k}", f"make t{k}"), "claude-opus-5-5")
              for k in range(3)]
    lines += [_error(2, f"tu_{k}", f"error {k}") for k in range(3)]
    return _write(path, lines)


def _scan(path):
    buffer = ActionBuffer()
    warnings = create_registry("health").scan(parse_file(path), buffer)
    return {w.signal: w for w in warnings}, buffer


# --- pricing table -----------------------------------------------------------


@pytest.mark.parametrize("model, key", [
    ("claude-opus-5-5", "claude-opus-5-5"),
    ("claude-opus-5", "claude-opus-5"),
    ("claude-sonnet-4-5-20250929", "claude-sonnet-4-5"),
    ("claude-opus-4-20250514", "claude-opus-4"),
    ("us.anthropic.claude-opus-4-1-20250805-v1:0", "claude-opus-4-1"),
    ("claude-3-5-haiku@20241022", "claude-3-5-haiku"),
    ("claude-opus-4-6[1m]", "claude-opus-4-6"),
    ("Claude-Haiku-4-5", "claude-haiku-4-5"),
])
def test_price_lookup_by_model_id_prefix(model, key):
    assert price_for(model) == PRICING[key]


@pytest.mark.parametrize("model", [
    None, "", "<synthetic>", "opus", "gpt-5-codex", "gemini-2.5-pro",
    "claude-opus-4-9", "claude-sonnet-6", "claude-opus-5-5-preview",
])
def test_unknown_model_has_no_price(model):
    assert price_for(model) is None
    assert usage_cost_usd(model, 1000, 1000) is None


def test_current_opus_is_not_priced_at_opus_4_1_rates():
    # QA: the old table billed every "opus" at $15/$75.
    assert price_for("claude-opus-5-5")[:2] == (4.0, 20.0)
    assert price_for("claude-opus-4-6")[:2] == (5.0, 25.0)


def test_cache_writes_split_by_ttl():
    # 1M 5m-writes + 1M 1h-writes on Opus 5.5: $5 + $8.
    assert usage_cost_usd("claude-opus-5-5", 0, 0, 2_000_000, 0, 1_000_000) == pytest.approx(13.0)


def test_haiku_5_5_long_prompt_tier():
    short = usage_cost_usd("claude-haiku-5-5", input_tokens=100_000)
    long = usage_cost_usd("claude-haiku-5-5", input_tokens=100_001)
    assert short == pytest.approx(0.01)
    assert long == pytest.approx(100_001 * 0.50 / 1e6)


# --- attribution ---------------------------------------------------------------


def test_loop_charged_for_its_repeated_calls(tmp_path):
    found, _ = _scan(loop_log(tmp_path / "s1.jsonl"))
    loop = found["loop"]
    calls = loop.details["count"]
    assert calls >= 4
    assert loop.tokens == calls * CALL_TOKENS
    assert loop.cost_usd == pytest.approx(calls * CALL_COST)


def test_error_results_charged_to_the_call_that_issued_them(tmp_path):
    # Claude Code error results carry no usage; each is charged to its tool_use's call.
    found, _ = _scan(loop_log(tmp_path / "s1.jsonl"))
    blind = found["error_blindness"]
    assert blind.tokens == blind.details["count"] * CALL_TOKENS
    assert blind.cost_usd == pytest.approx(blind.details["count"] * CALL_COST)


def test_error_spiral_counts_a_shared_call_once(tmp_path):
    found, buffer = _scan(spiral_log(tmp_path / "s1.jsonl"))
    spiral = found["error_spiral"]
    assert spiral.details["consecutive_failures"] == 3
    assert spiral.tokens == CALL_TOKENS  # three failures, one API call
    assert spiral.cost_usd == pytest.approx(CALL_COST)
    # The session total also counts each call once (2 calls, 4 lines with usage).
    assert buffer.stats.billed_tokens == 2 * CALL_TOKENS
    assert buffer.stats.billed_cost == pytest.approx(2 * CALL_COST)


def test_unknown_model_keeps_tokens_drops_cost(tmp_path):
    found, buffer = _scan(loop_log(tmp_path / "s1.jsonl", model="claude-opus-9"))
    loop = found["loop"]
    assert loop.tokens == loop.details["count"] * CALL_TOKENS
    assert loop.cost_usd is None
    assert "cost_usd" not in loop.to_dict()
    assert loop.cost_label.endswith(" tok") and "$" not in loop.cost_label
    assert buffer.stats.billed_cost is None
    # QA #145: no Sonnet-rate guess for the session either.
    assert buffer.stats.estimated_cost is None


def test_check_json_unknown_model_session_cost_is_null(tmp_path):
    log = loop_log(tmp_path / "s1.jsonl", model="claude-opus-4-9")
    out = json.loads(CliRunner().invoke(cli, ["check", "--log", str(log), "--json"]).stdout)
    assert out["efficiency"]["cost_total"] is None
    assert out["waste"]["session_cost_usd"] is None
    assert out["waste"]["tokens"] is not None


def test_agent_without_token_data_has_no_cost_fields():
    buffer = ActionBuffer()
    for i in range(10):
        buffer.add(Action(timestamp=T0 + timedelta(seconds=i), tool_name="bash",
                          tool_type=ToolType.BASH, success=True, command="ls"))
    w = LoopDetector().check(buffer)
    assert w is not None
    assert (w.tokens, w.cost_usd, w.cost_label) == (None, None, None)
    assert "tokens" not in w.to_dict() and "cost_usd" not in w.to_dict()


def test_unpriced_agent_reports_tokens_only():
    # e.g. Codex: tokens on the action, no price for its model.
    buffer = ActionBuffer()
    for i in range(10):
        buffer.add(Action(timestamp=T0 + timedelta(seconds=i), tool_name="exec_command",
                          tool_type=ToolType.BASH, success=True, command="ls",
                          tokens_in=100, unpriced=True))
    w = LoopDetector().check(buffer)
    assert w.tokens == 100 * w.details["count"]
    assert w.cost_usd is None


def test_agent_reported_cost_is_used_as_is():
    buffer = ActionBuffer()
    for i in range(10):
        buffer.add(Action(timestamp=T0 + timedelta(seconds=i), tool_name="bash",
                          tool_type=ToolType.BASH, success=True, command="ls",
                          tokens_in=100, cost_usd=0.5))
    w = LoopDetector().check(buffer)
    assert w.cost_usd == pytest.approx(0.5 * w.details["count"])


# --- display -------------------------------------------------------------------


def test_check_json_schema(tmp_path):
    log = loop_log(tmp_path / "s1.jsonl")
    out = json.loads(CliRunner().invoke(cli, ["check", "--log", str(log), "--json"]).stdout)
    loop = next(w for w in out["warnings"] if w["signal"] == "loop")
    assert isinstance(loop["tokens"], int) and isinstance(loop["cost_usd"], float)
    waste = out["waste"]
    assert set(waste) == {"findings", "tokens", "cost_usd", "session_tokens", "session_cost_usd"}
    assert waste["session_tokens"] == 8 * CALL_TOKENS
    assert waste["session_cost_usd"] == pytest.approx(8 * CALL_COST, abs=1e-4)  # rounded
    # Findings overlap (loop + error_blindness share calls): each call once.
    assert waste["tokens"] <= waste["session_tokens"]


def test_check_json_omits_cost_without_token_data(tmp_path):
    log = loop_log(tmp_path / "s1.jsonl")
    lines = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()]
    for e in lines:
        e["message"].pop("usage", None)
    _write(log, lines)
    out = json.loads(CliRunner().invoke(cli, ["check", "--log", str(log), "--json"]).stdout)
    assert out["warnings"]
    assert all("tokens" not in w and "cost_usd" not in w for w in out["warnings"])
    assert out["waste"] is None


def test_check_text_shows_cost_and_waste(tmp_path):
    log = loop_log(tmp_path / "s1.jsonl")
    text = CliRunner().invoke(cli, ["check", "--log", str(log)]).output
    loop_line = next(line for line in text.splitlines() if "[loop]" in line)
    assert "~$0.10 · 206k tok" in loop_line  # 5 calls * $0.02004, 5 * 41,210 tokens
    assert "Waste: ~$" in text and "% of session cost)" in text


def test_tui_warning_list_shows_cost(tmp_path):
    from agentwatch.ui.app import WarningsList

    found, _ = _scan(loop_log(tmp_path / "s1.jsonl"))
    widget = WarningsList()
    widget._warnings = [found["loop"]]
    assert "~$0.10 · 206k tok" in widget._build_content()


def test_siem_payload_carries_cost(tmp_path):
    from agentwatch.siem import SiemLogger

    found, _ = _scan(loop_log(tmp_path / "s1.jsonl"))
    path = tmp_path / "siem.jsonl"
    with SiemLogger(path) as siem:
        siem.log_warning(found["loop"])
        siem.log_warning(LoopDetector().check(_tokenless_loop()))
    priced, bare = (json.loads(x) for x in path.read_text(encoding="utf-8").splitlines())
    assert priced["tokens"] == found["loop"].tokens
    assert priced["cost_usd"] == pytest.approx(found["loop"].cost_usd)
    assert "tokens" not in bare and "cost_usd" not in bare


def _tokenless_loop():
    buffer = ActionBuffer()
    for i in range(10):
        buffer.add(Action(timestamp=T0, tool_name="bash", tool_type=ToolType.BASH,
                          success=True, command=f"ls{i % 1}"))
    return buffer


@pytest.mark.parametrize("cost, share", [(0.004, "<1%"), (0.006, "1%"), (0.5, "50%")])
def test_waste_share_under_half_a_percent_reads_below_one(cost, share):
    from agentwatch.cli import _waste_line

    line = _waste_line({"findings": 2, "tokens": 10, "cost_usd": cost,
                        "session_tokens": 100, "session_cost_usd": 1.0})
    assert f"({share} of session cost)" in line
