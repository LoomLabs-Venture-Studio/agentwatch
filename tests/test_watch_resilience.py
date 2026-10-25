"""A log line must never kill the watch (Sprint 37 F1 follow-up)."""

from __future__ import annotations

import json
import logging

import pytest

from agentwatch.parser.codex import CodexParser
from agentwatch.parser.watcher import LogWatcher

MARKER = "BOOM-MARKER-SECRET"


def _claude_line(uuid: str, text: str) -> dict:
    return {
        "type": "assistant",
        "uuid": uuid,
        "sessionId": "s1",
        "timestamp": "2026-10-24T10:00:00Z",
        "message": {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": uuid, "name": "Bash",
                         "input": {"command": text}}],
        },
    }


def _write(path, entries):
    path.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")


def test_watcher_skips_line_whose_parse_raises(tmp_path, monkeypatch, caplog):
    log = tmp_path / "session.jsonl"
    _write(log, [_claude_line("a", "echo one"), _claude_line("b", MARKER),
                 _claude_line("c", "echo three")])
    watcher = LogWatcher(log)
    real = watcher._parse_entry
    calls = []

    def flaky(entry):
        calls.append(entry)
        if MARKER in json.dumps(entry):
            raise AttributeError("synthetic parse failure")
        return real(entry)

    monkeypatch.setattr(watcher, "_parse_entry", flaky)
    with caplog.at_level(logging.DEBUG, logger="agentwatch.parser.watcher"):
        actions = watcher._read_new_lines()

    assert [a.command for a in actions] == ["echo one", "echo three"]
    assert MARKER not in caplog.text
    assert any("Skipping" in r.message for r in caplog.records)

    # The bad line is behind the position now: a second poll does not re-read it.
    n = len(calls)
    assert watcher._read_new_lines() == []
    assert len(calls) == n


@pytest.mark.parametrize("stderr", [{"message": "denied"}, ["x"], 7])
def test_codex_non_str_stderr_does_not_raise(stderr):
    parser = CodexParser()
    parser.parse_line({"timestamp": "2026-10-24T10:00:00Z", "type": "session_meta",
                       "payload": {"id": "s", "cwd": "/x", "cli_version": "1"}})
    parser.parse_line({"timestamp": "2026-10-24T10:00:01Z", "type": "response_item",
                       "payload": {"type": "function_call", "call_id": "c1",
                                   "name": "shell",
                                   "arguments": json.dumps({"command": ["ls"]})}})
    parser.parse_line({"timestamp": "2026-10-24T10:00:02Z", "type": "event_msg",
                       "payload": {"type": "exec_command_end", "call_id": "c1",
                                   "exit_code": 1, "status": "failed",
                                   "stderr": stderr, "formatted_output": ""}})
    err = parser._pending["c1"].action.error_message
    assert isinstance(err, str) and err.startswith("exit 1")
