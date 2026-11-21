"""Nothing to scan exits 3, not 1 (#242).

A missing log, or a log with no actions, used to exit 1, the same code as a
warning / at-risk result, so a CI gate couldn't tell them apart.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from agentwatch import cc_stats
from agentwatch.cli import EXIT_NO_DATA, _build_guard_cli, cli
from agentwatch.parser import logs as parser_logs

# Commands that read one log (--log, else the newest session).
LOG_COMMANDS = ["check", "security-scan", "tools", "ledger"]
# agentguard aliases that read one log.
GUARD_LOG_COMMANDS = ["check", "scan", "ledger"]


@pytest.fixture
def empty_home(tmp_path, monkeypatch) -> Path:
    """A fake home and config dir with no session logs; cwd is an empty dir."""
    home = (tmp_path / "home").resolve()
    (home / ".claude").mkdir(parents=True)
    config = (tmp_path / "config").resolve()
    config.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(config))
    monkeypatch.delitem(vars(cc_stats), "CLAUDE_PROJECTS_DIR", raising=False)
    monkeypatch.delitem(vars(parser_logs), "DEFAULT_SEARCH_PATHS", raising=False)
    monkeypatch.chdir(work)
    return home


@pytest.fixture
def empty_log(tmp_path) -> Path:
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    return p


def test_constant_is_3():
    assert EXIT_NO_DATA == 3


@pytest.mark.parametrize("command", [*LOG_COMMANDS, "subagents"])
def test_no_log_exits_3(empty_home, command):
    r = CliRunner().invoke(cli, [command])
    assert r.exit_code == EXIT_NO_DATA, r.output
    assert "No log files found" in r.output


@pytest.mark.parametrize("command", LOG_COMMANDS)
def test_empty_log_exits_3(empty_log, command):
    r = CliRunner().invoke(cli, [command, "--log", str(empty_log)])
    assert r.exit_code == EXIT_NO_DATA, r.output
    assert "No actions found" in r.output


def test_check_security_empty_log_exits_3(empty_log):
    r = CliRunner().invoke(cli, ["check", "--security", "--log", str(empty_log)])
    assert r.exit_code == EXIT_NO_DATA, r.output


@pytest.mark.parametrize("command", ["check", "security-scan", "tools"])
def test_json_empty_log_exits_3_and_prints_nothing(empty_log, command):
    r = CliRunner().invoke(cli, [command, "--log", str(empty_log), "--json"])
    assert r.exit_code == EXIT_NO_DATA
    assert r.stdout == ""  # the message is on stderr; no JSON was ever printed


def test_subagents_json_no_log_exits_3(empty_home):
    r = CliRunner().invoke(cli, ["subagents", "--json"])
    assert r.exit_code == EXIT_NO_DATA
    assert r.stdout == ""


@pytest.mark.parametrize("command", GUARD_LOG_COMMANDS)
def test_agentguard_no_log_exits_3(empty_home, command):
    r = CliRunner().invoke(_build_guard_cli(), [command])
    assert r.exit_code == EXIT_NO_DATA, r.output


@pytest.mark.parametrize("command", GUARD_LOG_COMMANDS)
def test_agentguard_empty_log_exits_3(empty_log, command):
    r = CliRunner().invoke(_build_guard_cli(), [command, "--log", str(empty_log)])
    assert r.exit_code == EXIT_NO_DATA, r.output


@pytest.mark.parametrize("group", [cli, _build_guard_cli()], ids=["agentwatch", "agentguard"])
@pytest.mark.parametrize("args", [["audit"], ["audit", "--all"], ["audit", "--json"]])
def test_audit_no_sessions_exits_3(empty_home, group, args):
    r = CliRunner().invoke(group, args)
    assert r.exit_code == EXIT_NO_DATA, r.output
    assert "No Claude Code session logs found" in r.output


def test_audit_empty_project_dir_exits_3(empty_home, tmp_path):
    # This project has a transcript dir in the config dir, but no session in it.
    from agentwatch.path_encoding import encode_path_for_claude

    config = Path(tmp_path / "config").resolve()
    (config / "projects" / encode_path_for_claude(Path.cwd().resolve())).mkdir(parents=True)
    r = CliRunner().invoke(cli, ["audit"])
    assert r.exit_code == EXIT_NO_DATA, r.output


@pytest.mark.parametrize("command", LOG_COMMANDS)
def test_unsupported_log_still_exits_1(tmp_path, command):
    # A real error keeps exit 1: only "nothing to scan" moved to 3.
    from test_unknown_log_format import _unknown_log

    r = CliRunner().invoke(cli, [command, "--log", str(_unknown_log(tmp_path))])
    assert r.exit_code == 1, r.output
    assert "unsupported log format" in r.output


def test_stats_no_logs_keeps_exit_1(empty_home):
    # stats is a usage report, not a CI gate: unchanged (#242).
    r = CliRunner().invoke(cli, ["stats"])
    assert r.exit_code == 1, r.output


# ---------------------------------------------------------------------------
# Text that isn't JSONL is an unsupported format (1), not "no actions" (3)
# ---------------------------------------------------------------------------

CLEAN = Path(__file__).parent / "fixtures" / "check_security_clean.jsonl"


@pytest.fixture
def garbage_jsonl(tmp_path) -> Path:
    p = tmp_path / "garbage.jsonl"
    p.write_text("garbage {{{\nmore garbage {{{\n", encoding="utf-8")
    return p


@pytest.fixture
def text_file(tmp_path) -> Path:
    p = tmp_path / "notes.txt"
    p.write_text("hello\n", encoding="utf-8")
    return p


@pytest.fixture
def blank_log(tmp_path) -> Path:
    p = tmp_path / "blank.jsonl"
    p.write_text("\n   \n\t\n", encoding="utf-8")
    return p


@pytest.mark.parametrize("command", LOG_COMMANDS)
@pytest.mark.parametrize("make", ["garbage_jsonl", "text_file"])
def test_non_json_file_exits_1(request, command, make):
    path = request.getfixturevalue(make)
    r = CliRunner().invoke(cli, [command, "--log", str(path)])
    assert r.exit_code == 1, r.output
    assert "unsupported log format" in r.output
    assert "No actions found" not in r.output


@pytest.mark.parametrize("command", LOG_COMMANDS)
def test_blank_only_log_exits_3(blank_log, command):
    r = CliRunner().invoke(cli, [command, "--log", str(blank_log)])
    assert r.exit_code == EXIT_NO_DATA, r.output
    assert "No actions found" in r.output


@pytest.mark.parametrize("command", LOG_COMMANDS)
def test_good_lines_among_bad_ones_still_parse(tmp_path, command):
    good = CLEAN.read_text(encoding="utf-8").splitlines()
    mixed = tmp_path / "mixed.jsonl"
    mixed.write_text(
        "garbage {{{\n" + "\nnot json either\n".join(good) + "\n{truncated\n", encoding="utf-8")
    expected = CliRunner().invoke(cli, [command, "--log", str(CLEAN)])
    r = CliRunner().invoke(cli, [command, "--log", str(mixed)])
    assert r.exit_code == expected.exit_code, r.output
    assert r.exit_code not in (1, EXIT_NO_DATA), r.output


def test_parse_file_mixed_lines_same_actions(tmp_path):
    from agentwatch.parser.logs import parse_file

    good = CLEAN.read_text(encoding="utf-8").splitlines()
    mixed = tmp_path / "mixed.jsonl"
    mixed.write_text("oops {{{\n" + "\n".join(good) + "\n", encoding="utf-8")
    want = [(a.tool_name, a.timestamp) for a in parse_file(CLEAN)]
    assert want
    assert [(a.tool_name, a.timestamp) for a in parse_file(mixed)] == want


def test_parse_file_raises_for_text_only(text_file):
    from agentwatch.parser.logs import UnsupportedLogFormatError, parse_file

    with pytest.raises(UnsupportedLogFormatError, match="no JSON lines"):
        list(parse_file(text_file))


def test_aider_markdown_is_not_treated_as_bad_jsonl(tmp_path):
    # .md goes to the Aider parser, never the JSONL path: plain text is fine there.
    from agentwatch.parser.logs import parse_file

    md = tmp_path / ".aider.chat.history.md"
    md.write_text("# aider chat started at 2026-01-01 10:00:00\n\nhello\n", encoding="utf-8")
    list(parse_file(md))  # no UnsupportedLogFormatError


async def test_live_tail_never_raises_on_a_half_written_line(tmp_path):
    # The one-shot check is parse_file only; LogWatcher reads a growing file.
    from agentwatch.parser.watcher import LogWatcher

    log = tmp_path / "live.jsonl"
    log.write_text('{"type": "user", "message": {"role": "user", "cont', encoding="utf-8")
    watcher = LogWatcher(log)
    assert watcher._read_new_lines() == []
    log.write_text("garbage {{{\n", encoding="utf-8")
    assert watcher._read_new_lines() == []


def test_subagents_with_an_empty_log_exits_0(empty_log):
    # subagents never parses the session log: no subagents is a normal result.
    r = CliRunner().invoke(cli, ["subagents", "--log", str(empty_log)])
    assert r.exit_code == 0, r.output
