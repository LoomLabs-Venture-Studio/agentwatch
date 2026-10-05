"""Unrecognised or binary logs must give a clean "unsupported log format"
error, never be parsed as Claude Code or crash (#39).

Fixtures are synthetic: they copy only the record *shape* of a Gemini CLI
transcript (header line with sessionId, then type="gemini" records) and of a
SQLite store, not any real content.
"""

import json
import sqlite3

import pytest
from click.testing import CliRunner

from agentwatch import agents
from agentwatch.agents.base import sniff_jsonl_format
from agentwatch.cli import cli
from agentwatch.parser.logs import UnsupportedLogFormatError, detect_log_format, parse_file
from agentwatch.parser.watcher import LogWatcher, MultiLogWatcher

GEMINI_HEADER = {
    "sessionId": "00000000-0000-0000-0000-000000000001",
    "projectHash": "abc123",
    "startTime": "2026-01-01T00:00:00.000Z",
    "lastUpdated": "2026-01-01T00:00:00.000Z",
    "kind": "main",
}
GEMINI_MESSAGE = {
    "id": "m1",
    "timestamp": "2026-01-01T00:00:01.000Z",
    "type": "gemini",
    "content": "done",
    "tokens": {"input": 10, "output": 2, "total": 12},
    "model": "some-model",
    "toolCalls": [{"id": "c1", "name": "run_shell_command", "args": {"command": "ls"}}],
}

CLAUDE_ASSISTANT = {
    "type": "assistant",
    "sessionId": "s1",
    "timestamp": "2026-01-01T00:00:00Z",
    "message": {
        "role": "assistant",
        "content": [
            {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/a.py"}}
        ],
    },
}


def _gemini_log(tmp_path):
    p = tmp_path / "session-2026-01-01.jsonl"
    lines = [GEMINI_HEADER] + [dict(GEMINI_MESSAGE, id=f"m{i}") for i in range(5)]
    p.write_text("".join(json.dumps(e) + "\n" for e in lines), encoding="utf-8")
    return p


def _sqlite_db(tmp_path):
    p = tmp_path / "store.db"
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE part (id INTEGER PRIMARY KEY, data TEXT)")
    con.executemany("INSERT INTO part (data) VALUES (?)", [("{}",), ("42",), ("[1]",)])
    con.commit()
    con.close()
    return p


class TestDetect:
    def test_gemini_records_are_unknown(self):
        assert detect_log_format(GEMINI_HEADER) == "unknown"
        assert detect_log_format(GEMINI_MESSAGE) == "unknown"

    @pytest.mark.parametrize("value", [42, "text", [1, 2], None, 1.5, True])
    def test_non_dict_is_unknown(self, value):
        assert detect_log_format(value) == "unknown"

    def test_claude_metadata_lines_skip(self):
        # Current Claude Code logs often open with these untyped-message lines.
        for t in ("mode", "last-prompt", "agent-setting", "queue-operation", "attachment"):
            assert detect_log_format({"type": t, "sessionId": "s1"}) == "skip"
        assert detect_log_format({"type": "file-history-delta", "messageId": "x"}) == "skip"

    def test_claude_current_and_flat_still_detected(self):
        assert detect_log_format(CLAUDE_ASSISTANT) == "claude_code"
        flat = {"sessionId": "s1", "timestamp": "2026-01-01T00:00:00", "tool": "Read"}
        assert detect_log_format(flat) == "claude_code"
        assert detect_log_format({"costUSD": 0.1, "timestamp": "t"}) == "claude_code"


class TestSniffAndParse:
    def test_gemini_sniffs_unknown_and_is_unclaimed(self, tmp_path):
        p = _gemini_log(tmp_path)
        assert sniff_jsonl_format(p) == "unknown"
        assert agents.adapter_for(p) is None

    def test_gemini_parse_raises(self, tmp_path):
        p = _gemini_log(tmp_path)
        with pytest.raises(UnsupportedLogFormatError, match="unsupported log format"):
            list(parse_file(p))

    def test_binary_parse_raises(self, tmp_path):
        p = _sqlite_db(tmp_path)
        assert sniff_jsonl_format(p) == "unknown"
        with pytest.raises(UnsupportedLogFormatError, match="binary"):
            list(parse_file(p))

    def test_non_dict_lines_are_skipped(self, tmp_path):
        p = tmp_path / "s.jsonl"
        p.write_text(
            "42\n\"str\"\n[1, 2]\nnull\n" + json.dumps(CLAUDE_ASSISTANT) + "\n7\n",
            encoding="utf-8",
        )
        assert sniff_jsonl_format(p) == "claude_code"
        actions = list(parse_file(p))
        assert [a.tool_name for a in actions] == ["Read"]

        w = LogWatcher(p)
        assert [a.tool_name for a in w._read_new_lines()] == ["Read"]


class TestWatchers:
    def test_log_watcher_ignores_unknown_format(self, tmp_path):
        # A tailed file that turns out to be unknown yields nothing, never
        # Claude-Code UNKNOWN actions.
        assert LogWatcher(_gemini_log(tmp_path))._read_new_lines() == []

    def test_multi_watcher_skips_unknown_file(self, tmp_path):
        gem = _gemini_log(tmp_path)
        good = tmp_path / "good.jsonl"
        good.write_text(json.dumps(CLAUDE_ASSISTANT) + "\n", encoding="utf-8")
        mw = MultiLogWatcher([tmp_path])
        assert isinstance(mw._make_watcher(good), LogWatcher)
        with pytest.raises(UnsupportedLogFormatError):
            mw._make_watcher(gem)


class TestCli:
    @pytest.mark.parametrize("command", ["check", "security-scan", "watch"])
    @pytest.mark.parametrize("make", [_gemini_log, _sqlite_db])
    def test_clean_error(self, tmp_path, command, make):
        p = make(tmp_path)
        result = CliRunner().invoke(cli, [command, "--log", str(p)])
        assert result.exit_code == 1
        assert isinstance(result.exception, SystemExit)  # no traceback
        assert "unsupported log format" in result.output
        assert str(p) in result.output

    def test_audit_skips_unsupported_file(self, tmp_path, monkeypatch):
        proj = tmp_path / "proj"
        proj.mkdir()
        _gemini_log(proj)
        (proj / "ok.jsonl").write_text(json.dumps(CLAUDE_ASSISTANT) + "\n", encoding="utf-8")
        import agentwatch.cc_stats as cc_stats

        monkeypatch.setattr(cc_stats, "find_all_project_dirs", lambda: [proj])
        result = CliRunner().invoke(cli, ["audit", "--all", "--json"])
        assert not isinstance(result.exception, UnsupportedLogFormatError), result.output
        assert result.exit_code == 0
