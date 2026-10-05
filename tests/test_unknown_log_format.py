"""Unrecognised or binary logs must give a clean "unsupported log format"
error, never be parsed as Claude Code or crash (#39).

Fixtures are synthetic: they copy only the record *shape* of a Gemini CLI
transcript (header line with sessionId, then type="gemini" records) and of a
SQLite store, not any real content.
"""

import asyncio
import json
import sqlite3

import pytest
from click.testing import CliRunner

from agentwatch import agents
from agentwatch.agents.base import sniff_jsonl_format
from agentwatch.agents.claude_code import ClaudeCodeAdapter
from agentwatch.cli import cli
from agentwatch.parser.logs import (
    FORMAT_SNIFF_LINES,
    UnsupportedLogFormatError,
    detect_log_format,
    parse_file,
)
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


# --- Format-sniff window ------------------------------------------------------
# One stray unrecognised line must not lock the format: up to
# FORMAT_SNIFF_LINES unknown entries are skipped like "skip" entries and the
# first recognised entry decides. sniff_jsonl_format (claims()), _parse_jsonl
# and LogWatcher must all agree.

STRAY = {"note": "not an agent record"}
SKIP = {"type": "mode", "sessionId": "s1"}


def _claude_lines(n=3):
    out = []
    for i in range(n):
        a = json.loads(json.dumps(CLAUDE_ASSISTANT))
        a["message"]["content"][0]["id"] = f"t{i}"
        a["message"]["content"][0]["input"]["file_path"] = f"/f{i}.py"
        out.append(a)
    return out


def _strays(n):
    return [dict(STRAY, i=i) for i in range(n)]


def _write(p, entries):
    p.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")
    return p


def _append(p, entries):
    with open(p, "a", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def _tools(actions):
    return [a.tool_name for a in actions]


def _all_agree_claude(p, expected_tools):
    """sniff/claims, parse_file and a fresh LogWatcher all treat *p* as Claude Code."""
    assert sniff_jsonl_format(p) == "claude_code"
    assert ClaudeCodeAdapter().claims(p)
    assert agents.adapter_for(p) is not None
    assert _tools(parse_file(p)) == expected_tools
    assert _tools(LogWatcher(p)._read_new_lines()) == expected_tools


def _all_agree_unknown(p):
    """sniff/claims, parse_file and a fresh LogWatcher all reject *p*."""
    assert sniff_jsonl_format(p) == "unknown"
    assert not ClaudeCodeAdapter().claims(p)
    assert agents.adapter_for(p) is None
    with pytest.raises(UnsupportedLogFormatError, match="no recognised agent log records"):
        list(parse_file(p))
    assert LogWatcher(p)._read_new_lines() == []


class TestSniffWindow:
    def test_window_size(self):
        assert FORMAT_SNIFF_LINES == 50

    # (a) stray unknown first line + valid Claude Code lines
    def test_stray_first_line_parses_as_claude(self, tmp_path):
        p = _write(tmp_path / "s.jsonl", [STRAY] + _claude_lines())
        _all_agree_claude(p, ["Read", "Read", "Read"])

    def test_stray_gemini_records_then_claude(self, tmp_path):
        p = _write(tmp_path / "s.jsonl", [GEMINI_HEADER, GEMINI_MESSAGE] + _claude_lines(2))
        _all_agree_claude(p, ["Read", "Read"])

    def test_check_cli_with_stray_first_line(self, tmp_path):
        p = _write(tmp_path / "s.jsonl", [STRAY] + _claude_lines())
        result = CliRunner().invoke(cli, ["check", "--log", str(p), "--json"])
        assert "unsupported log format" not in result.output, result.output
        assert "No actions found" not in result.output, result.output
        assert not isinstance(result.exception, UnsupportedLogFormatError)
        assert result.exit_code in (0, 1, 2), result.output
        report = json.loads(result.output)
        assert report

    def test_unknown_just_inside_window_then_claude(self, tmp_path):
        p = _write(tmp_path / "s.jsonl", _strays(FORMAT_SNIFF_LINES - 1) + _claude_lines(1))
        _all_agree_claude(p, ["Read"])

    def test_skip_lines_do_not_use_up_window(self, tmp_path):
        entries = [SKIP] * (FORMAT_SNIFF_LINES + 10) + [STRAY] + _claude_lines(1)
        p = _write(tmp_path / "s.jsonl", entries)
        _all_agree_claude(p, ["Read"])

    def test_undecodable_and_non_dict_lines_do_not_use_up_window(self, tmp_path):
        p = tmp_path / "s.jsonl"
        junk = "not json\n42\n[1]\n" * FORMAT_SNIFF_LINES
        p.write_text(junk + json.dumps(STRAY) + "\n" + json.dumps(CLAUDE_ASSISTANT) + "\n",
                     encoding="utf-8")
        _all_agree_claude(p, ["Read"])

    def test_recognised_format_stays_locked(self, tmp_path):
        # Once Claude Code is locked, later odd lines go through its parser
        # as before -- no mid-file raise.
        p = _write(tmp_path / "s.jsonl", _claude_lines(1) + _strays(3) + _claude_lines(1))
        assert _tools(parse_file(p)).count("Read") == 2

    # (b) only unknown lines: still rejected with the existing error
    def test_only_unknown_lines_still_rejected(self, tmp_path):
        _all_agree_unknown(_gemini_log(tmp_path))

    def test_single_unknown_line_file_rejected(self, tmp_path):
        _all_agree_unknown(_write(tmp_path / "s.jsonl", [STRAY]))

    # (d) more than the window of unknown lines, then a valid one
    def test_more_than_window_unknown_then_valid_stays_unknown(self, tmp_path):
        p = _write(tmp_path / "s.jsonl", _strays(FORMAT_SNIFF_LINES + 5) + _claude_lines(2))
        _all_agree_unknown(p)

    def test_exactly_window_unknown_then_valid_is_unknown(self, tmp_path):
        p = _write(tmp_path / "s.jsonl", _strays(FORMAT_SNIFF_LINES) + _claude_lines(1))
        _all_agree_unknown(p)

    def test_only_skip_lines_and_empty_stay_undecided(self, tmp_path):
        skip = _write(tmp_path / "skip.jsonl", [SKIP] * (FORMAT_SNIFF_LINES + 5))
        empty = tmp_path / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
        for p in (skip, empty):
            assert sniff_jsonl_format(p) is None
            assert ClaudeCodeAdapter().claims(p)
            assert list(parse_file(p)) == []
            assert LogWatcher(p)._read_new_lines() == []

    def test_binary_still_rejected_immediately(self, tmp_path):
        p = tmp_path / "s.jsonl"
        p.write_bytes(b"\0\0\n" + (json.dumps(CLAUDE_ASSISTANT) + "\n").encode())
        assert sniff_jsonl_format(p) == "unknown"
        with pytest.raises(UnsupportedLogFormatError, match="binary"):
            list(parse_file(p))


class TestLiveWatcherWindow:
    # (c) live LogWatcher: bad first line, then valid lines arrive
    def test_bad_first_line_then_valid_lines_appended(self, tmp_path):
        p = _write(tmp_path / "live.jsonl", [STRAY])
        w = LogWatcher(p)
        assert w._read_new_lines() == []
        _append(p, _claude_lines(2))
        assert _tools(w._read_new_lines()) == ["Read", "Read"]

    async def test_bad_first_line_then_valid_via_watch(self, tmp_path):
        p = _write(tmp_path / "live.jsonl", [STRAY, GEMINI_MESSAGE] + _claude_lines(2))
        agen = LogWatcher(p).watch()
        try:
            got = [await asyncio.wait_for(agen.__anext__(), 5) for _ in range(2)]
        finally:
            await agen.aclose()
        assert _tools(got) == ["Read", "Read"]

    def test_window_counter_persists_across_reads(self, tmp_path):
        p = _write(tmp_path / "live.jsonl", [])
        w = LogWatcher(p)
        half = FORMAT_SNIFF_LINES // 2
        _append(p, _strays(half))
        assert w._read_new_lines() == []
        _append(p, _strays(FORMAT_SNIFF_LINES - half))
        assert w._read_new_lines() == []
        # Window used up across two reads: a valid line no longer recovers it.
        _append(p, _claude_lines(1))
        assert w._read_new_lines() == []

    def test_recovers_inside_window_across_reads(self, tmp_path):
        p = _write(tmp_path / "live.jsonl", [])
        w = LogWatcher(p)
        _append(p, _strays(FORMAT_SNIFF_LINES - 1))
        assert w._read_new_lines() == []
        _append(p, _claude_lines(1))
        assert _tools(w._read_new_lines()) == ["Read"]
