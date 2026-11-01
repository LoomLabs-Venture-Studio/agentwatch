"""Turn-end markers (parser) -> Alerter `--notify-done` (watch/watch-all)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from agentwatch import alerts
from agentwatch.alerts import Alerter
from agentwatch.parser.codex import CodexParser
from agentwatch.parser.copilot import CopilotParser
from agentwatch.parser.copilot_vscode import actions as vscode_actions
from agentwatch.parser.copilot_vscode import replay
from agentwatch.parser.logs import parse_file
from agentwatch.parser.models import ActionBuffer, turn_ended
from agentwatch.parser.opencode import parse_opencode_session
from agentwatch.themes import get_theme

FIXTURES = Path(__file__).parent / "fixtures"


def _codex() -> list[dict]:
    return [
        {"type": "session_meta", "payload": {"id": "s1", "cwd": "/p", "cli_version": "0.162.0"}},
        {"type": "response_item", "payload": {"type": "function_call", "name": "shell",
                                              "arguments": '{"command":["ls"]}', "call_id": "c1"}},
        {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c1",
                                              "output": "ok"}},
        {"type": "event_msg", "payload": {"type": "token_count", "info": None}},
        {"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "done"}},
    ]


def _copilot() -> list[dict]:
    """Event shapes from a live Copilot CLI 1.0.90 session (two model calls)."""
    def ev(t, data):
        return {"type": t, "data": data, "id": t, "parentId": None,
                "timestamp": "2026-10-01T12:21:50.000Z"}
    return [
        ev("session.start", {"sessionId": "s1"}),
        ev("user.message", {"content": "read notes"}),
        ev("assistant.turn_start", {"turnId": "0"}),
        ev("assistant.message", {"toolRequests": [{"toolCallId": "c1", "name": "view"}]}),
        ev("tool.execution_start", {"toolCallId": "c1", "toolName": "view",
                                    "arguments": {"path": "/p/notes"}}),
        ev("tool.execution_complete", {"toolCallId": "c1", "success": True}),
        ev("assistant.turn_end", {"turnId": "0"}),
        ev("assistant.turn_start", {"turnId": "1"}),
        ev("assistant.message", {"toolRequests": [], "phase": "final_answer"}),
        ev("assistant.turn_end", {"turnId": "1"}),
    ]


def _claude(stop_reason: str | None) -> list[dict]:
    return [
        {"type": "assistant", "timestamp": "2026-10-01T12:00:00Z", "message": {
            "id": "m1", "role": "assistant", "stop_reason": "tool_use",
            "content": [{"type": "tool_use", "id": "t1", "name": "Bash",
                         "input": {"command": "ls"}}]}},
        {"type": "user", "timestamp": "2026-10-01T12:00:01Z", "message": {
            "role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1",
                                         "content": "ok"}]}},
        {"type": "assistant", "timestamp": "2026-10-01T12:00:02Z", "message": {
            "id": "m2", "role": "assistant", "stop_reason": stop_reason,
            "content": [{"type": "text", "text": "All done."}]}},
        # Bookkeeping Claude Code writes after the turn: not new activity.
        {"type": "system", "subtype": "turn_duration", "timestamp": "2026-10-01T12:00:03Z",
         "content": "", "durationMs": 3000},
    ]


def _flat(parser, entries):
    return [a for e in entries for a in parser.parse_line(e)]


def _newest_first(actions):
    return reversed(list(actions))


class TestParsers:
    def test_codex_task_complete(self):
        acts = _flat(CodexParser(), _codex())
        assert turn_ended(_newest_first(acts)) is acts[-1]
        assert acts[-1].tool_name == "turn_end"
        # Not agent activity: counts and loop windows are unchanged.
        buf = ActionBuffer()
        for a in acts:
            buf.add(a)
        assert buf.stats.activity_count == 1

    def test_codex_mid_turn_is_not_done(self):
        assert turn_ended(_newest_first(_flat(CodexParser(), _codex()[:-1]))) is None

    def test_copilot_cli_only_the_reply_turn_ends(self):
        acts = _flat(CopilotParser(), _copilot())
        assert [a.tool_name for a in acts if a.turn_end] == ["turn_end"]
        assert turn_ended(_newest_first(acts)) is acts[-1]
        assert turn_ended(_newest_first(_flat(CopilotParser(), _copilot()[:7]))) is None

    def test_claude_code_end_turn(self, tmp_path):
        log = tmp_path / "s.jsonl"
        log.write_text("\n".join(json.dumps(e) for e in _claude("end_turn")) + "\n")
        acts = list(parse_file(log))
        done = turn_ended(_newest_first(acts))
        assert done is not None and done.tool_name == "text_output"
        assert acts[-1].tool_name == "system"  # skipped over

    def test_claude_code_subagent_reply_is_not_done(self, tmp_path):
        entries = [{**e, "isSidechain": True} for e in _claude("end_turn")]
        log = tmp_path / "s.jsonl"
        log.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
        acts = list(parse_file(log))
        assert not any(a.turn_end for a in acts)
        a, sent = _alerter(notify_existing=True)
        a.observe("s", "claude-code", "p", [], SimpleNamespace(status=get_theme().level_0,
                  overall_score=95), actions=len(acts), done=turn_ended(_newest_first(acts)))
        assert sent == []

    def test_claude_code_streaming_or_tool_use_is_not_done(self, tmp_path):
        log = tmp_path / "s.jsonl"
        log.write_text("\n".join(json.dumps(e) for e in _claude(None)) + "\n")
        assert turn_ended(_newest_first(parse_file(log))) is None

    def test_opencode_stop_step(self):
        acts = parse_opencode_session(FIXTURES / "opencode_session.db")
        assert turn_ended(_newest_first(acts)) is acts[-1]

    def test_copilot_vscode_finished_request(self):
        acts = [a for _, a in vscode_actions(replay(FIXTURES / "copilot_vscode" / "session.jsonl"))]
        done = turn_ended(_newest_first(acts))
        assert done is not None and done.tool_name == "assistant_message"

    def test_new_activity_clears(self):
        acts = _flat(CodexParser(), _codex()) + _flat(CodexParser("s1"), _codex()[1:3])
        assert turn_ended(_newest_first(acts)) is None


# --- Alerter ----------------------------------------------------------------


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(alerts, "_monotonic", lambda: now[0])

    class _Inline:
        def __init__(self, target, args=(), daemon=None):
            self._target, self._args = target, args

        def start(self):
            self._target(*self._args)

    monkeypatch.setattr(alerts, "Thread", _Inline)
    return now


def _alerter(**kw):
    sent: list[tuple[str, str]] = []
    a = Alerter(notify=True, notify_done=True, **kw)
    a._desktop = lambda title, body: sent.append((title, body))
    return a, sent


def _pass(a, acts, cost=None, session="s1"):
    report = SimpleNamespace(status=get_theme().level_0, overall_score=95)
    a.observe(session, "codex", "proj", [], report, actions=len(acts), cost=cost,
              done=turn_ended(_newest_first(acts)))


def test_already_done_at_startup_is_baselined_then_next_turn_alerts(clock):
    a, sent = _alerter()
    turn1 = _flat(CodexParser(), _codex())
    _pass(a, turn1)                       # history: finished before we started
    clock[0] += alerts.BASELINE_S + 1
    _pass(a, turn1)
    assert sent == []
    parser = CodexParser("s1")
    turn2 = turn1 + _flat(parser, _codex()[1:3])  # new activity
    _pass(a, turn2)
    assert sent == []
    turn2 += _flat(parser, _codex()[3:])
    _pass(a, turn2, cost=0.4213)
    _pass(a, turn2, cost=0.4213)          # same state: no repeat
    assert sent == [("agentwatch: Codex · proj — finished ~$0.42",
                     "waiting for your next prompt")]


def test_lines_of_one_reply_alert_once(clock):
    from agentwatch.parser.models import Action, ToolType

    a, sent = _alerter(notify_existing=True)
    first, second = (Action(None, "text_output", ToolType.UNKNOWN, True, message_id="m9",
                            turn_end=True) for _ in range(2))
    _pass(a, [first])
    _pass(a, [first, second])
    assert len(sent) == 1


def test_done_off_by_default(clock):
    sent = []
    a = Alerter(notify=True, notify_existing=True)
    a._desktop = lambda *x: sent.append(x)
    _pass(a, _flat(CodexParser(), _codex()))
    assert sent == []


def test_headless_log_line(clock):
    lines = []
    a, sent = _alerter(log=lines.append, notify_existing=True)
    _pass(a, _flat(CopilotParser(), _copilot()))
    assert len(sent) == 1 and "DONE" in lines[0] and "finished" in lines[0]


def test_notify_done_option_builds_alerter(monkeypatch):
    from agentwatch import cli as cli_mod

    a = cli_mod._make_alerter(False, "critical", False, None, notify_done=True)
    assert a.notify and a.notify_done
    seen = {}
    monkeypatch.setattr(cli_mod, "build_agent_tree", lambda _: [])
    monkeypatch.setattr(cli_mod, "find_running_agents", lambda: [])

    class _App:
        def __init__(self, **kw):
            seen.update(kw)

        def run(self, **kw):
            pass

    monkeypatch.setattr("agentwatch.ui.multi_app.MultiAgentWatchApp", _App)
    result = CliRunner().invoke(cli_mod.cli, ["watch-all", "--headless", "--notify-done"])
    assert result.exit_code == 0, result.output
    assert seen["alerter"].notify_done


async def test_headless_engine_done(tmp_path, monkeypatch):
    """watch-all's engine on a Claude Code log: the turn that ended before
    start is baselined; a new turn that ends alerts once."""
    from agentwatch.ui.multi_app import MultiAgentWatchApp

    monkeypatch.setattr(alerts, "BASELINE_S", 1.0)
    log = tmp_path / "s1.jsonl"

    def lines(entries):
        return "".join(json.dumps(e) + "\n" for e in entries)

    log.write_text(lines(_claude("end_turn")), encoding="utf-8")
    sent = []
    alerter = Alerter(notify=True, notify_done=True)
    alerter._desktop = lambda t, b: sent.append(t)
    app = MultiAgentWatchApp(watch_paths=[log], alerter=alerter)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(2.0)  # history loaded, past the baseline
        assert sent == []
        turn2 = _claude("end_turn")
        for i, e in enumerate(turn2):
            e["timestamp"] = f"2026-10-01T12:01:0{i}Z"
        turn2[0]["message"]["content"][0]["id"] = "t2"
        turn2[1]["message"]["content"][0]["tool_use_id"] = "t2"
        turn2[2]["message"]["id"] = "m3"
        with log.open("a", encoding="utf-8") as f:
            f.write(lines(turn2))
        for _ in range(50):
            await pilot.pause(0.1)
            if sent:
                break
        await pilot.pause(0.5)
    assert sent == ["agentwatch: s1.jsonl — finished"]
