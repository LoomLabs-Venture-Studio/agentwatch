"""Loop circuit breaker: the coach hook's PreToolUse path (Feature 7)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from agentwatch import coach
from agentwatch.detectors.health.loops import LoopDetector
from agentwatch.parser.logs import parse_file
from agentwatch.parser.models import ActionBuffer

CMD = "python -c 'import x'"
FIXTURE = Path(__file__).parent / "fixtures" / "claude_code_2_1_30x.jsonl"


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch):
    monkeypatch.setattr(coach, "state_dir", lambda: tmp_path / "state")
    monkeypatch.setattr(coach, "user_state_dir", lambda: tmp_path / "user-state")
    monkeypatch.delenv("AGENTWATCH_LOOP_BREAKER", raising=False)


def _call(i: int, name: str, tool_input: dict, error: str | None = "boom") -> list[dict]:
    ts = f"2026-10-17T10:{i // 60:02d}:{i % 60:02d}Z"
    use = {"type": "assistant", "timestamp": ts, "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": f"t{i}", "name": name, "input": tool_input}]}}
    block = {"type": "tool_result", "tool_use_id": f"t{i}", "content": error or "ok"}
    if error:
        block["is_error"] = True
    return [use, {"type": "user", "timestamp": ts, "message": {"role": "user", "content": [block]}}]


def _transcript(tmp_path: Path, calls: list[tuple[str, dict]], name: str = "s.jsonl") -> Path:
    entries = [e for i, (n, inp) in enumerate(calls) for e in _call(i, n, inp)]
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")
    return path


def _hook(transcript: Path, event: str, tool_input: dict, tool: str = "Bash",
          agent_id: str | None = None, tool_use_id: str = "tnext") -> str | None:
    payload = {"session_id": "sess-1", "transcript_path": str(transcript),
               "hook_event_name": event, "tool_name": tool, "tool_input": tool_input,
               "tool_use_id": tool_use_id}
    if agent_id:
        payload["agent_id"] = agent_id
    return coach.run(json.dumps(payload))


def _loop(tmp_path: Path, n: int = 6, command: str = CMD) -> Path:
    """n identical failing Bash calls; PostToolUse after the last one arms at n >= 6."""
    t = _transcript(tmp_path, [("Bash", {"command": command})] * n)
    _hook(t, "PostToolUse", {"command": command}, tool_use_id=f"t{n - 1}")
    return t


def _denied(out: str | None) -> bool:
    return out is not None and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_seventh_call_after_high_loop_is_denied_with_documented_json(tmp_path):
    t = _loop(tmp_path)
    data = json.loads(_hook(t, "PreToolUse", {"command": CMD}))
    assert set(data) == {"hookSpecificOutput"}
    spec = data["hookSpecificOutput"]
    assert set(spec) == {"hookEventName", "permissionDecision", "permissionDecisionReason"}
    assert spec["hookEventName"] == "PreToolUse"
    assert spec["permissionDecision"] == "deny"
    reason = spec["permissionDecisionReason"]
    assert reason.startswith("agentwatch blocked this call: the same action ran 6 times")
    assert CMD not in reason and "<" not in reason and ">" not in reason


def test_retry_after_denial_is_allowed_and_stays_blocked_once(tmp_path):
    t = _loop(tmp_path)
    assert _denied(_hook(t, "PreToolUse", {"command": CMD}))
    assert _hook(t, "PreToolUse", {"command": CMD}) is None
    # Next PostToolUse still sees the same HIGH loop: no second block.
    t = _loop(tmp_path, n=8)
    assert _hook(t, "PreToolUse", {"command": CMD}) is None


def test_different_call_is_allowed(tmp_path):
    t = _loop(tmp_path)
    assert _hook(t, "PreToolUse", {"command": "ls"}) is None


def test_medium_loop_does_not_arm(tmp_path):
    t = _loop(tmp_path, n=5)
    assert _hook(t, "PreToolUse", {"command": CMD}) is None


@pytest.mark.parametrize("command", ["sleep 30", "  pytest -x", "gh run watch 1",
                                     "python -m pytest tests", "git status"])
def test_allowlisted_command_is_never_denied(tmp_path, command):
    t = _loop(tmp_path, command=command)
    assert _hook(t, "PreToolUse", {"command": command}) is None


def test_missing_state_allows(tmp_path):
    assert _hook(tmp_path / "none.jsonl", "PreToolUse", {"command": CMD}) is None


@pytest.mark.parametrize("text", ["{not json", "[]", '{"armed": 5}', '{"armed": {}}'])
def test_corrupt_state_allows(tmp_path, text):
    t = _loop(tmp_path)
    (tmp_path / "state" / "sess-1.json").write_text(text, encoding="utf-8")
    assert _hook(t, "PreToolUse", {"command": CMD}) is None


@pytest.mark.parametrize("stdin", ["", "garbage", "{}", '{"hook_event_name": "PreToolUse"}'])
def test_bad_stdin_allows(stdin):
    assert coach.run(stdin) is None


@pytest.mark.parametrize("value", ["off", "OFF", " Off "])
def test_env_off_switch_allows(tmp_path, monkeypatch, value):
    t = _loop(tmp_path)
    monkeypatch.setenv("AGENTWATCH_LOOP_BREAKER", value)
    assert _hook(t, "PreToolUse", {"command": CMD}) is None
    monkeypatch.setenv("AGENTWATCH_LOOP_BREAKER", "on")
    assert _denied(_hook(t, "PreToolUse", {"command": CMD}))


def test_subagent_state_is_separate_from_parent(tmp_path):
    parent = _transcript(tmp_path, [("Bash", {"command": f"echo {i}"}) for i in range(12)])
    sub_dir = parent.with_suffix("") / "subagents"
    sub_dir.mkdir(parents=True)
    _transcript(sub_dir, [("Bash", {"command": CMD})] * 6, name="agent-a1b2.jsonl")
    _hook(parent, "PostToolUse", {"command": "echo 11"}, tool_use_id="t11")
    _hook(parent, "PostToolUse", {"command": CMD}, agent_id="a1b2", tool_use_id="t5")
    assert _hook(parent, "PreToolUse", {"command": CMD}) is None  # parent not armed
    assert _denied(_hook(parent, "PreToolUse", {"command": CMD}, agent_id="a1b2"))


@pytest.mark.parametrize("tool, tool_input", [
    ("Bash", {"command": CMD, "description": "run it"}),
    ("Edit", {"file_path": "/p/a.py", "old_string": "a", "new_string": "b"}),
    ("Write", {"file_path": "/p/a.py", "content": "x"}),
    ("Read", {"file_path": "/p/a.py"}),
    ("mcp__claude-in-chrome__javascript_tool", {"action": "javascript_exec", "tabId": 1,
                                                "text": "document.title"}),
])
def test_pre_tool_use_key_matches_loop_detector(tmp_path, tool, tool_input):
    t = _transcript(tmp_path, [(tool, tool_input)] * 6)
    buffer = ActionBuffer()
    for action in parse_file(t):
        buffer.add(action)
    warning = LoopDetector().check(buffer)
    assert warning.details["loop_id"] == coach.call_loop_id(tool, tool_input)


def test_loop_clearing_rearms(tmp_path):
    t = _loop(tmp_path)
    assert _denied(_hook(t, "PreToolUse", {"command": CMD}))
    calls = [("Bash", {"command": CMD})] * 8
    calls += [("Bash", {"command": f"echo {i}"}) for i in range(10)]
    t = _transcript(tmp_path, calls)
    _hook(t, "PostToolUse", {"command": "echo 9"}, tool_use_id="t17")  # loop gone: entry dropped
    assert "armed" not in json.loads((tmp_path / "state" / "sess-1.json").read_text("utf-8"))
    t = _transcript(tmp_path, calls + [("Bash", {"command": CMD})] * 6)
    _hook(t, "PostToolUse", {"command": CMD}, tool_use_id="t23")
    assert _denied(_hook(t, "PreToolUse", {"command": CMD}))


def test_end_to_end_real_transcript_fixture(tmp_path):
    """Real Claude Code 2.1.30x lines: a failing Bash call cloned 6 times."""
    lines = [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()]
    bash = next(e for e in lines if e["type"] == "assistant"
                and e["message"]["content"][0].get("name") == "Bash")
    failed = next(e for e in lines if e["type"] == "user"
                  and e["message"]["content"][0].get("is_error"))
    out = []
    for i in range(6):
        use, res = copy.deepcopy(bash), copy.deepcopy(failed)
        use["message"]["content"][0]["id"] = f"toolu_{i}"
        res["message"]["content"][0]["tool_use_id"] = f"toolu_{i}"
        out += [use, res]
    t = tmp_path / "real.jsonl"
    t.write_text("\n".join(json.dumps(e) for e in out) + "\n", encoding="utf-8")
    tool_input = bash["message"]["content"][0]["input"]
    payload = {"session_id": "real", "transcript_path": str(t), "tool_name": "Bash",
               "tool_input": tool_input, "tool_use_id": "toolu_5"}
    post = coach.run(json.dumps({**payload, "hook_event_name": "PostToolUseFailure"}))
    assert "agentwatch coach [high]" in post  # the coach note still fires
    pre = coach.run(json.dumps({**payload, "hook_event_name": "PreToolUse",
                                "tool_use_id": "toolu_6"}))
    assert _denied(pre)
    assert "so far)" in pre and "boom" not in pre
