"""Spend caps: `agentwatch budget` and the coach hook's PreToolUse check."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from agentwatch import budget, coach, statusline
from agentwatch.cli import cli

SID = "sess-1"
SONNET = "claude-sonnet-4-5-20250929"  # $3/M input, $15/M output


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    """Real user_state_dir() and state_dir(), under tmp_path."""
    for var in ("LOCALAPPDATA", "XDG_CACHE_HOME", "HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(tmp_path))
    for var in ("CLAUDE_PLUGIN_DATA", "AGENTWATCH_LOOP_BREAKER", "CLAUDE_CONFIG_DIR"):
        monkeypatch.delenv(var, raising=False)
    assert tmp_path in coach.user_state_dir().parents
    return tmp_path


def _assistant(msg_id: str, usd_in: float = 1.0, model: str = SONNET, tool: int = 0) -> dict:
    """An assistant line whose usage costs usd_in dollars of Sonnet input."""
    return {"type": "assistant", "timestamp": "2026-11-13T10:00:00Z",
            "message": {"id": msg_id, "model": model, "role": "assistant",
                        "content": [{"type": "tool_use", "id": f"t{tool}", "name": "Read",
                                     "input": {"file_path": f"/x{tool}.py"}}],
                        "usage": {"input_tokens": round(usd_in * 1_000_000 / 3),
                                  "output_tokens": 0}}}


def _transcript(path: Path, *entries: dict, append: bool = False) -> Path:
    with open(path, "a" if append else "w", encoding="utf-8") as f:
        f.write("".join(json.dumps(e) + "\n" for e in entries))
    return path


def _post(transcript: Path, tool_use_id: str = "t0", agent_id: str | None = None):
    payload = {"session_id": SID, "transcript_path": str(transcript),
               "hook_event_name": "PostToolUse", "tool_name": "Read",
               "tool_input": {"file_path": "/x.py"}, "tool_use_id": tool_use_id}
    if agent_id:
        payload["agent_id"] = agent_id
    return coach.run(json.dumps(payload))


def _pre(tool_use_id: str = "tnext", command: str = "ls"):
    return coach.run(json.dumps({
        "session_id": SID, "transcript_path": "/none.jsonl", "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": command}, "tool_use_id": tool_use_id}))


def _out(text: str | None) -> dict:
    return {} if text is None else json.loads(text)["hookSpecificOutput"]


def _set(**caps) -> None:
    budget.save_budget(caps)


def _spend(tmp_path: Path, usd: float, n: int = 1) -> Path:
    """A session transcript totalling *usd*, recorded by a PostToolUse pass."""
    entries = [_assistant(f"m{i}", usd / n, tool=i) for i in range(n)]
    path = _transcript(tmp_path / "s.jsonl", *entries)
    _post(path)
    return path


# --- no caps ----------------------------------------------------------------------

def test_no_budget_file_is_a_no_op_and_cheap(tmp_path, monkeypatch):
    monkeypatch.delitem(sys.modules, "agentwatch.budget", raising=False)
    assert not budget.budget_path().exists()
    assert coach._budget({"tool_name": "Bash"}, SID) is None
    assert "agentwatch.budget" not in sys.modules  # never imported
    # PostToolUse records no cost without a budget.
    path = _transcript(tmp_path / "s.jsonl", _assistant("m1", 5.0))
    _post(path)
    state = json.loads(coach.state_path(coach.state_dir(), SID).read_text())
    assert "cost_usd" not in state
    # One failed open per call: generous CPU-time bound for slow CI runners.
    payload = {"tool_name": "Bash"}
    start = time.process_time()
    for _ in range(1000):
        coach._budget(payload, SID)
    assert time.process_time() - start < 1.0  # well under 1 ms per call


def test_parse_settings_ignores_bad_caps():
    assert budget.parse_settings({"session": 0}) is None
    assert budget.parse_settings({"session": -1, "block": "5", "day": True}) is None
    assert budget.parse_settings({"session": float("nan")}) is None
    assert budget.parse_settings({"session": 1e300}) is None
    assert budget.parse_settings([1]) is None
    assert budget.parse_settings({"day": 3, "action": "nope"}) == {"day": 3.0, "action": "ask"}


@pytest.mark.parametrize("junk", ["{not json", "[]", '{"session": "x"}', "[" * 100_000, ""])
def test_corrupt_settings_fail_open(tmp_path, junk):
    _spend(tmp_path, 50.0)  # recorded or not, a corrupt file is no cap
    budget.budget_path().write_text(junk, encoding="utf-8")
    assert _pre() is None
    _post(tmp_path / "s.jsonl")  # PostToolUse still works
    assert budget.load_budget() is None


def test_error_inside_the_check_fails_open(tmp_path, monkeypatch):
    _set(session=1.0)
    _spend(tmp_path, 5.0)

    def boom(*_a, **_k):
        raise RuntimeError("x")
    monkeypatch.setattr(budget, "spends", boom)
    assert _pre() is None


# --- session cap ------------------------------------------------------------------

def test_session_over_cap_asks_with_a_fixed_reason(tmp_path):
    _set(session=5.0)
    _spend(tmp_path, 6.0)
    out = _out(_pre())
    assert out["permissionDecision"] == "ask"
    assert out["permissionDecisionReason"] == (
        "agentwatch: this session has spent about $6.00 (cap $5.00). Continue?")


def test_under_80_percent_says_nothing(tmp_path):
    _set(session=10.0)
    _spend(tmp_path, 7.0)
    assert _pre() is None


def test_deny_mode_blocks_every_call(tmp_path):
    _set(session=5.0, action="deny")
    _spend(tmp_path, 6.0)
    for tool_id in ("a", "b"):
        out = _out(_pre(tool_id))
        assert out["permissionDecision"] == "deny"
        assert "about $6.00 (cap $5.00" in out["permissionDecisionReason"]
        assert "agentwatch budget set" in out["permissionDecisionReason"]


def test_80_percent_advisory_once_per_cap(tmp_path):
    _set(session=10.0)
    _spend(tmp_path, 8.5)
    out = _out(_pre())
    assert "permissionDecision" not in out
    assert out["additionalContext"].startswith(
        "agentwatch budget: this session has spent about $8.50, 85% of the $10.00 session cap")
    assert _pre() is None  # once
    _set(session=9.0)  # a changed cap starts over
    assert "94% of the $9.00" in _out(_pre())["additionalContext"]


def test_approve_then_reask_at_next_25_percent_step(tmp_path):
    _set(session=4.0)
    path = _spend(tmp_path, 4.4)  # 110%
    assert _out(_pre("c1"))["permissionDecision"] == "ask"
    # Claude Code ran the call (the user approved): its PostToolUse acks the ask.
    _post(path, tool_use_id="c1")
    assert _pre("c2") is None
    _transcript(path, _assistant("m9", 0.4, tool=9), append=True)  # 120%: same step
    _post(path, tool_use_id="c2")
    assert _pre("c3") is None
    _transcript(path, _assistant("m10", 0.4, tool=10), append=True)  # 130%: next step
    _post(path, tool_use_id="c3")
    out = _out(_pre("c4"))
    assert out["permissionDecision"] == "ask"
    assert "about $5.20 (cap $4.00)" in out["permissionDecisionReason"]


def test_denied_ask_asks_again(tmp_path):
    _set(session=4.0)
    _spend(tmp_path, 4.4)
    assert _out(_pre("c1"))["permissionDecision"] == "ask"
    # The user said no: no PostToolUse for c1, so the next call asks again.
    assert _out(_pre("c2"))["permissionDecision"] == "ask"


def test_guard_and_breaker_come_first(tmp_path):
    _set(session=1.0)
    _spend(tmp_path, 5.0)
    out = _out(_pre(command="rm -rf ~"))
    assert out["permissionDecision"] == "ask"
    assert "this session has spent" not in out["permissionDecisionReason"]


def test_session_spend_includes_subagents_and_is_incremental(tmp_path):
    _set(session=100.0)
    main = _spend(tmp_path, 2.0)
    sub = main.with_suffix("") / "subagents" / "agent-a1.jsonl"
    sub.parent.mkdir(parents=True)
    _transcript(sub, _assistant("s1", 3.0))
    _post(main, agent_id="a1")
    directory = coach.state_dir()
    assert budget.session_spend(directory, SID) == pytest.approx(5.0)
    # A repeated message id (one line per content block) is counted once.
    _transcript(main, _assistant("m0", 2.0, tool=5), _assistant("m7", 1.0), append=True)
    _post(main)
    state = json.loads(coach.state_path(directory, SID).read_text())
    assert state["cost_usd"] == pytest.approx(3.0)
    assert state["cost_scan"]["offset"] == main.stat().st_size


def test_partial_last_line_waits(tmp_path):
    path = _transcript(tmp_path / "s.jsonl", _assistant("m1", 1.0))
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(_assistant("m2", 1.0))[:40])
    scan = budget.scan_cost(path, None)
    assert scan["usd"] == pytest.approx(1.0, abs=1e-4)
    assert scan["offset"] < path.stat().st_size


def test_unpriced_model_adds_nothing(tmp_path):
    path = _transcript(tmp_path / "s.jsonl", _assistant("m1", 1.0, model="claude-opus-9-9"))
    assert budget.scan_cost(path, None)["usd"] == 0.0


# --- block / day caps from the status line cache ------------------------------------

def _cache(block_cost: float | None = None, day_cost: float | None = None,
           age: float = 0.0) -> None:
    now = time.time()
    cache = statusline.block_cache_path()
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({
        "block": None if block_cost is None else {
            "end": now + 3600, "cost_usd": block_cost, "projected_cost_usd": None},
        "day": {"start": statusline.day_start(now), "cost_usd": day_cost}}))
    os.utime(cache, (now - age, now - age))


def test_block_cap_from_fresh_cache():
    _set(block=20.0)
    _cache(block_cost=25.0)
    out = _out(_pre())
    assert out["permissionDecision"] == "ask"
    assert "5-hour usage block is at about $25.00" in out["permissionDecisionReason"]


def test_stale_or_missing_block_cache_skips_the_check():
    _set(block=20.0, day=20.0)
    assert _pre() is None  # no cache
    _cache(block_cost=25.0, day_cost=25.0, age=budget.CACHE_FRESH_S + 5)
    assert _pre() is None  # stale: never recomputed in the hook


def test_day_cap_and_yesterdays_total_ignored():
    _set(day=10.0, action="deny")
    _cache(day_cost=12.0)
    out = _out(_pre())
    assert out["permissionDecision"] == "deny"
    assert "spend today is about $12.00" in out["permissionDecisionReason"]
    cache = statusline.block_cache_path()
    data = json.loads(cache.read_text())
    data["day"]["start"] -= 86400  # written yesterday
    cache.write_text(json.dumps(data))
    assert _pre() is None


# --- settings file ------------------------------------------------------------------

@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_settings_file_private():
    _set(session=5.0)
    path = budget.budget_path()
    assert path == coach.user_state_dir() / "budget"
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


# --- CLI --------------------------------------------------------------------------

def test_cli_set_status_off():
    runner = CliRunner()
    out = runner.invoke(cli, ["budget"]).output
    assert out.startswith("agentwatch budget: off")
    result = runner.invoke(cli, ["budget", "set", "--session", "5", "--block", "20"])
    assert result.exit_code == 0, result.output
    assert "session $5.00, block $20.00; over a cap: ask" in result.output
    assert "statusline --cost" in result.output
    result = runner.invoke(cli, ["budget", "set", "--block", "0", "--day", "30",
                                 "--action", "deny"])
    assert json.loads(budget.budget_path().read_text()) == {
        "session": 5.0, "day": 30.0, "action": "deny"}
    assert "session $5.00, day $30.00; over a cap: deny" in result.output
    out = runner.invoke(cli, ["budget", "status"]).output
    assert "no spend recorded yet" in out
    assert runner.invoke(cli, ["budget", "off"]).output == "agentwatch budget: off\n"
    assert not budget.budget_path().exists()


def test_cli_rejects_bad_input():
    runner = CliRunner()
    assert runner.invoke(cli, ["budget", "set"]).exit_code == 2
    assert runner.invoke(cli, ["budget", "set", "--session", "-1"]).exit_code == 2
    assert runner.invoke(cli, ["budget", "set", "--session", "nan"]).exit_code == 2
    assert runner.invoke(cli, ["budget", "set", "--session", "0"]).exit_code == 2  # no cap left
    assert not budget.budget_path().exists()


def test_cli_status_shows_session_spend(tmp_path):
    runner = CliRunner()
    runner.invoke(cli, ["budget", "set", "--session", "10"])
    _spend(tmp_path, 4.0)
    out = runner.invoke(cli, ["budget", "status"]).output
    assert "Latest session sess-1 (updated 0m ago): about $4.00 of $10.00" in out


def test_statusline_shows_block_cap(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    _cache(block_cost=4.0)
    _set(block=20.0)
    assert statusline._block_text().startswith("5h $4.00 · cap $20.00 · resets ")


# --- end to end through `agentwatch hook` -------------------------------------------

def _hook(home: Path, payload: dict) -> subprocess.CompletedProcess:
    env = dict(os.environ, HOME=str(home), XDG_CACHE_HOME=str(home), LOCALAPPDATA=str(home))
    env.pop("CLAUDE_PLUGIN_DATA", None)
    return subprocess.run(
        [sys.executable, "-c", "from agentwatch._entry import main; main()", "hook"],
        input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=60)


def test_hook_end_to_end(home, tmp_path):
    _set(session=2.0)
    path = _transcript(tmp_path / "s.jsonl", _assistant("m1", 3.0))
    base = {"session_id": SID, "transcript_path": str(path), "tool_name": "Read",
            "tool_input": {"file_path": "/x.py"}, "tool_use_id": "t0"}
    post = _hook(home, {**base, "hook_event_name": "PostToolUse"})
    assert (post.returncode, post.stdout) == (0, "")
    pre = _hook(home, {**base, "hook_event_name": "PreToolUse", "tool_use_id": "t1"})
    assert pre.returncode == 0
    assert _out(pre.stdout)["permissionDecision"] == "ask"
    assert "about $3.00 (cap $2.00)" in _out(pre.stdout)["permissionDecisionReason"]
    budget.budget_path().write_text("{corrupt", encoding="utf-8")
    pre = _hook(home, {**base, "hook_event_name": "PreToolUse", "tool_use_id": "t2"})
    assert (pre.returncode, pre.stdout) == (0, "")


def test_block_cap_reads_its_own_config_dirs_cache(home, tmp_path, monkeypatch):
    """The hook reads the cache of the CLAUDE_CONFIG_DIR it runs with (#240)."""
    _set(block=20.0)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "orca"))
    _cache(block_cost=25.0)  # orca is over its cap
    monkeypatch.delenv("CLAUDE_CONFIG_DIR")
    _cache(block_cost=5.0)  # ~/.claude is not
    assert _pre() is None
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "orca"))
    assert _out(_pre())["permissionDecision"] == "ask"
    # The same through a real `agentwatch hook` process.
    payload = {"session_id": SID, "transcript_path": "/none.jsonl", "tool_name": "Bash",
               "hook_event_name": "PreToolUse", "tool_input": {"command": "ls"},
               "tool_use_id": "e1"}
    for config, decision in ((str(tmp_path / "orca"), "ask"), ("", None)):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", config)
        proc = _hook(home, payload)
        assert proc.returncode == 0
        assert _out(proc.stdout or None).get("permissionDecision") == decision
