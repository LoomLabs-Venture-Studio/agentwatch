"""Gemini CLI adapter + parser (#65).

The fixture is synthetic: record shapes follow gemini-cli v0.62.0's
chatRecordingService.ts / chatRecordingTypes.ts and the live 0.62.0 run in
docs/research/agent-live-test-2026-10-05.md (header line, messages re-appended
by id as they update, ``$set`` patch lines). No real session content.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime

import pytest
from click.testing import CliRunner

from agentwatch import agents
from agentwatch.agents.base import sniff_jsonl_format
from agentwatch.agents.gemini import resolve_gemini_log
from agentwatch.cli import cli
from agentwatch.discovery import match_process_adapter
from agentwatch.parser.logs import detect_log_format, parse_file
from agentwatch.parser.models import ToolType
from agentwatch.parser.watcher import LogWatcher

HEADER = {
    "sessionId": "0f1e2d3c-0000-4000-8000-000000000001",
    "projectHash": "a" * 64,
    "startTime": "2026-10-05T17:10:47.000Z",
    "lastUpdated": "2026-10-05T17:10:47.000Z",
    "kind": "main",
}
USER = {
    "id": "u1", "timestamp": "2026-10-05T17:10:50.000Z", "type": "user",
    "content": [{"text": "create hello.py that prints hello, run it"}],
}


def _fr(call_id, name, **response):
    return [{"functionResponse": {"id": call_id, "name": name, "response": response}}]


SHELL_CALL = {
    "id": "c1", "name": "run_shell_command", "args": {"command": "python hello.py"},
    "status": "executing", "timestamp": "2026-10-05T17:10:52.000Z",
}
TURN1_PENDING = {
    "id": "g1", "timestamp": "2026-10-05T17:10:51.000Z", "type": "gemini", "content": "",
    "model": "gemini-2.5-pro", "toolCalls": [SHELL_CALL],
}
TURN1_DONE = dict(
    TURN1_PENDING,
    toolCalls=[dict(SHELL_CALL, status="success",
                    result=_fr("c1", "run_shell_command", output="Output: hello"))],
    tokens={"input": 1200, "output": 30, "cached": 1000, "thoughts": 20, "tool": 0,
            "total": 1250},
)
TURN2 = {
    "id": "g2", "timestamp": "2026-10-05T17:11:00.000Z", "type": "gemini", "content": "Done.",
    "model": "gemini-2.5-pro",
    "tokens": {"input": 1500, "output": 10, "cached": 0, "total": 1510},
    "toolCalls": [
        {"id": "c2", "name": "write_file", "status": "success",
         "timestamp": "2026-10-05T17:11:01.000Z",
         "args": {"file_path": "/w/hello.py", "content": "print('hello')\n"},
         "result": _fr("c2", "write_file", output="Created /w/hello.py")},
        {"id": "c3", "name": "replace", "status": "error",
         "timestamp": "2026-10-05T17:11:02.000Z",
         "args": {"file_path": "/w/x.py", "old_string": "a", "new_string": "b"},
         "result": _fr("c3", "replace", error="old_string not found")},
        {"id": "c4", "name": "run_shell_command", "status": "success",
         "timestamp": "2026-10-05T17:11:03.000Z", "args": {"command": "false"},
         "result": _fr("c4", "run_shell_command", output="Output: (empty)\nExit Code: 1")},
        {"id": "c5", "name": "read_file", "status": "cancelled",
         "args": {"file_path": "/w/hello.py"}},  # no own timestamp: message's is used
    ],
}
UNTIMED = {
    "id": "g3", "timestamp": "not-a-date", "type": "gemini", "content": "",
    "toolCalls": [{"id": "c6", "name": "list_directory", "status": "awaiting_approval",
                   "args": {"dir_path": "/w"}}],
}
LINES = [
    HEADER, USER, {"$set": {"lastUpdated": "2026-10-05T17:10:50.000Z"}},
    TURN1_PENDING, TURN1_DONE, TURN2,
    {"type": "info", "id": "i1", "timestamp": "2026-10-05T17:11:04.000Z", "content": "note"},
    UNTIMED,
]


def _write(p, entries):
    p.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")
    return p


@pytest.fixture
def log(tmp_path):
    return _write(tmp_path / "session-2026-10-05T17-10-0f1e2d3c.jsonl", LINES)


def _by_id(actions):
    return {a.raw["id"]: a for a in actions}


class TestParse:
    def test_actions(self, log):
        actions = list(parse_file(log))
        names = [a.tool_name for a in actions]
        # Each message/call once, despite g1 being re-appended; c6 never finished
        # so it is flushed at EOF; the info notice is not an action.
        assert names == [
            "user_message", "assistant_message", "run_shell_command",
            "assistant_message", "write_file", "replace", "run_shell_command", "read_file",
            "list_directory",
        ]
        assert {a.session_id for a in actions} == {HEADER["sessionId"]}
        a = _by_id(actions)

        assert a["u1"].incoming_message == "create hello.py that prints hello, run it"
        assert a["u1"].timestamp == datetime(2026, 10, 5, 17, 10, 50)

        assert a["c1"].tool_type == ToolType.BASH and a["c1"].success
        assert a["c1"].command == "python hello.py"
        assert a["c1"].raw["content"] == "Output: hello"
        assert a["c1"].timestamp == datetime(2026, 10, 5, 17, 10, 52)

        assert a["c2"].tool_type == ToolType.WRITE and a["c2"].file_path == "/w/hello.py"
        assert a["c2"].raw["input"] == {"content": "print('hello')\n"}

        assert a["c3"].tool_type == ToolType.EDIT and not a["c3"].success
        assert a["c3"].error_message == "old_string not found"

        assert not a["c4"].success and a["c4"].error_message == "exit code 1"

        assert a["c5"].tool_type == ToolType.READ and not a["c5"].success
        assert a["c5"].timestamp == datetime(2026, 10, 5, 17, 11, 0)

        # Missing/unparseable timestamp: untimed, never "now" (#44).
        assert a["c6"].timestamp is None and a["c6"].file_path == "/w"

    def test_tokens(self, log):
        turns = [a for a in parse_file(log) if a.tool_name == "assistant_message"]
        t1, t2 = turns
        assert (t1.tokens_in, t1.cache_read_tokens, t1.tokens_out) == (200, 1000, 50)
        assert (t2.tokens_in, t2.cache_read_tokens, t2.tokens_out) == (1500, 0, 10)
        assert t2.outgoing_data == "Done."

    def test_checkpoint_set_messages_does_not_duplicate(self, tmp_path):
        p = _write(tmp_path / "s.jsonl",
                   [HEADER, USER, TURN1_DONE, {"$set": {"messages": [USER, TURN1_DONE]}}])
        assert [a.tool_name for a in parse_file(p)] == [
            "user_message", "assistant_message", "run_shell_command",
        ]

    def test_live_tail_emits_call_once_when_final(self, tmp_path):
        p = _write(tmp_path / "s.jsonl", [HEADER, USER, TURN1_PENDING])
        w = LogWatcher(p)
        assert [a.tool_name for a in w._read_new_lines()] == ["user_message"]
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(TURN1_DONE) + "\n" + json.dumps(TURN1_DONE) + "\n")
        got = w._read_new_lines()
        assert [a.tool_name for a in got] == ["assistant_message", "run_shell_command"]
        assert got[1].success


class TestClaims:
    def test_header_detected(self):
        assert detect_log_format(HEADER) == "gemini"

    def test_adapter_for_picks_gemini(self, log):
        assert sniff_jsonl_format(log) == "gemini"
        assert agents.adapter_for(log).name == "gemini"
        assert not agents.get("claude-code").claims(log)

    @pytest.mark.parametrize("entries, owner", [
        ([{"type": "assistant", "sessionId": "s1", "timestamp": "2026-01-01T00:00:00Z",
           "message": {"role": "assistant", "content": [
               {"type": "tool_use", "id": "t1", "name": "Read", "input": {}}]}}], "claude-code"),
        ([{"type": "session.start", "id": "e1", "timestamp": "2026-01-01T00:00:00Z",
           "data": {"sessionId": "s", "context": {"cwd": "/w"}}}], "copilot"),
        ([{"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE",
           "created_at": "2026-01-01T00:00:00Z", "tool_calls": []}], "agy"),
        ([{"timestamp": "2026-01-01T00:00:00Z", "type": "session_meta",
           "payload": {"id": "s"}}], "codex"),
    ])
    def test_other_agents_not_claimed(self, tmp_path, entries, owner):
        p = _write(tmp_path / "other.jsonl", entries)
        assert not agents.get("gemini").claims(p)
        assert agents.adapter_for(p).name == owner


class TestDiscovery:
    @pytest.mark.parametrize("argv, expected", [
        (["node", "/usr/lib/node_modules/@google/gemini-cli/bundle/gemini.js"], "gemini"),
        (["node", "--max-old-space-size=8192",
          r"C:\Users\u\AppData\Roaming\npm\node_modules\@google\gemini-cli\bundle\gemini.js",
          "--yolo"], "gemini"),
        (["gemini", "-p", "hi"], "gemini"),
        (["codex", "--model", "gemini-2.5-pro"], "codex"),  # args never steal a PID
        (["agy"], "agy"),
    ])
    def test_process_matching(self, argv, expected):
        assert match_process_adapter(argv).name == expected

    def test_resolve_log_via_project_registry(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GEMINI_CLI_HOME", str(tmp_path))
        project = tmp_path / "proj"
        project.mkdir()
        gemini = tmp_path / ".gemini"
        chats = gemini / "tmp" / "proj" / "chats"
        chats.mkdir(parents=True)
        key = os.path.abspath(project)
        key = key.lower() if sys.platform == "win32" else key
        (gemini / "projects.json").write_text(json.dumps({"projects": {key: "proj"}}))
        old = _write(chats / "session-2026-10-05T17-00-aaaaaaaa.jsonl", [HEADER])
        new = _write(chats / "session-2026-10-05T18-00-bbbbbbbb.jsonl", [HEADER])
        os.utime(old, (1, 1))
        assert resolve_gemini_log(project) == (new, None)
        assert resolve_gemini_log(tmp_path / "elsewhere") == (None, None)


def test_check_cli(log):
    result = CliRunner().invoke(cli, ["check", "--log", str(log), "--json"])
    assert "unsupported log format" not in result.output, result.output
    assert result.exit_code in (0, 1, 2), result.output
    assert json.loads(result.output)
