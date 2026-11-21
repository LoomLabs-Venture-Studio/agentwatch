"""Context window fill and git branch per session (research item 9):
session_info, the ps CTX/BRANCH columns and JSON fields, visual's chip and
watch-all's CTX colour and Selected title. Fixtures in tmp dirs only."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from agentwatch import cli, session_info
from agentwatch.discovery import AgentProcess
from agentwatch.parser.models import Action, ActionBuffer, SessionStats, ToolType
from agentwatch.posture import Posture


@pytest.fixture(autouse=True)
def _fresh_cache():
    session_info._CACHE.clear()
    yield
    session_info._CACHE.clear()


def _claude_line(model: str, fresh: int, read: int = 0, written: int = 0,
                 branch: str | None = None, i: int = 0) -> dict:
    entry = {
        "type": "assistant", "timestamp": "2026-11-20T10:00:00Z", "sessionId": "s",
        "message": {
            "id": f"m{i}", "role": "assistant", "model": model,
            "content": [{"type": "tool_use", "id": f"t{i}", "name": "Read",
                         "input": {"file_path": "/a"}}],
            "usage": {"input_tokens": fresh, "cache_read_input_tokens": read,
                      "cache_creation_input_tokens": written, "output_tokens": 5},
        },
    }
    if branch is not None:
        entry["gitBranch"] = branch
    return entry


def _write(path: Path, entries: list[dict], prefix: bytes = b"") -> Path:
    path.write_bytes(prefix + "".join(json.dumps(e) + "\n" for e in entries).encode())
    return path


def _codex_line(t: int, kind: str, payload: dict) -> dict:
    return {"timestamp": f"2026-11-20T10:00:{t:02d}Z", "type": kind, "payload": payload}


def _codex(tmp_path: Path, tokens: int, window: int | None) -> Path:
    info = {"last_token_usage": {"input_tokens": tokens, "cached_input_tokens": tokens // 2,
                                 "output_tokens": 9}}
    if window is not None:
        info["model_context_window"] = window
    return _write(tmp_path / "rollout-x.jsonl", [
        _codex_line(0, "session_meta", {"id": "s1", "cwd": "/x", "cli_version": "0.162.0"}),
        _codex_line(1, "event_msg", {"type": "token_count", "info": info}),
    ])


def _repo(path: Path, head: str = "ref: refs/heads/main\n") -> Path:
    (path / ".git").mkdir(parents=True)
    (path / ".git" / "HEAD").write_text(head)
    return path


# -- context ---------------------------------------------------------------


def test_context_usage_formula_and_unknown_window():
    stats = SessionStats(context_window=200_000, last_context_tokens=84_000,
                         peak_context_tokens=90_000)
    assert session_info.context_usage(stats) == {
        "used_tokens": 84_000, "window": 200_000, "percent": 42}
    assert session_info.context_usage(SessionStats(last_context_tokens=5)) is None
    assert session_info.context_usage(SessionStats(context_window=1000)) is None


def test_claude_1m_model_uses_latest_call_not_peak(tmp_path):
    log = _write(tmp_path / "s.jsonl", [
        _claude_line("claude-opus-4-6", 10, read=600_000, i=0),  # the peak
        _claude_line("claude-opus-4-6", 10, read=400_000, written=90, i=1),
    ])
    ctx = session_info.log_context(log, "claude-code")
    assert ctx == {"used_tokens": 400_100, "window": 1_000_000, "percent": 40}


def test_claude_200k_model_window_unknown_until_proven(tmp_path):
    small = _write(tmp_path / "a.jsonl", [_claude_line("claude-sonnet-4-5", 100, read=50_000)])
    assert session_info.log_context(small, "claude-code") is None  # never a guess
    big = _write(tmp_path / "b.jsonl", [
        _claude_line("claude-sonnet-4-5", 100, read=250_000, i=0),  # proves a 1M window
        _claude_line("claude-sonnet-4-5", 100, read=99_900, i=1),
    ])
    assert session_info.log_context(big, "claude-code")["percent"] == 10


def test_claude_desktop_reads_the_same_transcript(tmp_path):
    log = _write(tmp_path / "s.jsonl", [_claude_line("claude-opus-4-6", 0, read=950_000)])
    assert session_info.log_context(log, "claude-desktop")["percent"] == 95


def test_codex_reported_window(tmp_path):
    ctx = session_info.log_context(_codex(tmp_path, 100_000, 258_400), "codex")
    assert ctx == {"used_tokens": 100_000, "window": 258_400, "percent": 38}


def test_codex_missing_window_is_null(tmp_path):
    assert session_info.log_context(_codex(tmp_path, 100_000, None), "codex") is None


def test_unsupported_agent_or_missing_log_is_null(tmp_path):
    log = _write(tmp_path / "s.jsonl", [_claude_line("claude-opus-4-6", 0, read=1000)])
    assert session_info.log_context(log, "cursor") is None
    assert session_info.log_context(None, "claude-code") is None
    assert session_info.log_context(tmp_path / "gone.jsonl", "claude-code") is None


def test_only_a_bounded_tail_is_read(tmp_path, monkeypatch):
    monkeypatch.setattr(session_info, "CONTEXT_TAIL_BYTES", 4096)
    early = json.dumps(_claude_line("claude-opus-4-6", 0, read=900_000, i=0)) + "\n"
    log = _write(tmp_path / "s.jsonl", [_claude_line("claude-opus-4-6", 0, read=1000, i=1)],
                 prefix=(early + "x" * 8000 + "\n").encode())
    ctx = session_info.log_context(log, "claude-code")
    assert ctx["used_tokens"] == 1000  # the 900K call is outside the tail


def test_cached_per_size_and_mtime(tmp_path, monkeypatch):
    log = _write(tmp_path / "s.jsonl", [_claude_line("claude-opus-4-6", 0, read=10_000)])
    calls = []
    real = session_info._tail_stats
    monkeypatch.setattr(session_info, "_tail_stats",
                        lambda *a: calls.append(a) or real(*a))
    session_info.log_context(log, "claude-code")
    session_info.log_context(log, "claude-code")
    assert len(calls) == 1
    with open(log, "a") as f:
        f.write(json.dumps(_claude_line("claude-opus-4-6", 0, read=20_000, i=2)) + "\n")
    assert session_info.log_context(log, "claude-code")["used_tokens"] == 20_000
    assert len(calls) == 2


DEEP = "[" * 100_000 + "]" * 100_000  # json.loads raises RecursionError


def test_deeply_nested_usage_line_is_skipped(tmp_path):
    log = _write(tmp_path / "s.jsonl", [_claude_line("claude-opus-4-6", 0, read=10_000)])
    with open(log, "a") as f:
        f.write('{"usage":' + DEEP + "}\n")
    assert session_info.log_context(log, "claude-code")["used_tokens"] == 10_000


def test_deeply_nested_git_branch_line_is_skipped(tmp_path):
    log = _write(tmp_path / "s.jsonl", [_claude_line("claude-opus-4-6", 1, branch="ok")])
    with open(log, "a") as f:
        f.write('{"gitBranch":' + "[" * 20_000 + "]" * 20_000 + "}\n")  # inside the 64 KB tail
    with pytest.raises(RecursionError):
        json.loads("[" * 20_000 + "]" * 20_000)
    assert session_info.log_git_branch(log) == "ok"


def test_any_error_fails_closed_per_log(tmp_path, monkeypatch):
    log = _write(tmp_path / "s.jsonl", [_claude_line("claude-opus-4-6", 1, read=10, branch="b")])

    def boom(*_a):
        raise RuntimeError("bad log")

    monkeypatch.setattr(session_info, "_tail_stats", boom)
    monkeypatch.setattr(session_info, "_log_branch", boom)
    monkeypatch.setattr(session_info, "git_branch", boom)
    agent = AgentProcess(pid=1, agent_type="claude-code", working_directory=tmp_path,
                         log_file=log)
    assert session_info.context_of(agent) is None
    assert session_info.branch_of(agent) is None
    monkeypatch.setattr(session_info, "log_context", boom)
    assert session_info.context_of(agent) is None


@pytest.mark.skipif(not hasattr(__import__("os"), "mkfifo"), reason="no FIFOs")
def test_fifo_head_git_file_or_log_never_blocks(tmp_path):
    import os

    repo = tmp_path / "r"
    (repo / ".git").mkdir(parents=True)
    os.mkfifo(repo / ".git" / "HEAD")
    assert session_info.git_branch(repo) is None
    wt = tmp_path / "wt"
    wt.mkdir()
    os.mkfifo(wt / ".git")  # a FIFO where the gitdir: file would be
    assert session_info.git_branch(wt) is None
    pointed = tmp_path / "pointed"
    (pointed / "HEAD").parent.mkdir(parents=True)
    os.mkfifo(pointed / "HEAD")
    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / ".git").write_text(f"gitdir: {pointed}\n")
    assert session_info.git_branch(linked) is None
    log = tmp_path / "log.jsonl"
    os.mkfifo(log)
    assert session_info.log_context(log, "claude-code") is None
    assert session_info.log_git_branch(log) is None


def test_over_window_shows_more_than_100(tmp_path):
    log = _write(tmp_path / "s.jsonl", [_claude_line("claude-opus-4-6", 0, read=1_200_000)])
    ctx = session_info.log_context(log, "claude-code")
    assert ctx["percent"] == 100 and session_info.context_text(ctx) == ">100%"
    assert session_info.context_text(None) == "-"
    exact = {"used_tokens": 1000, "window": 1000, "percent": 100}
    assert session_info.context_text(exact) == "100%"


def test_context_tone():
    assert [session_info.context_tone(p) for p in (None, 79, 80, 94, 95, 100)] == [
        None, None, "warn", "warn", "bad", "bad"]


# -- branch ----------------------------------------------------------------


def test_branch_from_git_head_walking_up(tmp_path):
    repo = _repo(tmp_path / "repo", "ref: refs/heads/feature/x\n")
    sub = repo / "src" / "pkg"
    sub.mkdir(parents=True)
    assert session_info.git_branch(sub) == "feature/x"


def test_branch_worktree_git_file(tmp_path):
    main = _repo(tmp_path / "main")
    wt_dir = main / ".git" / "worktrees" / "wt"
    wt_dir.mkdir(parents=True)
    (wt_dir / "HEAD").write_text("ref: refs/heads/topic\n")
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / ".git").write_text(f"gitdir: {wt_dir}\n")
    assert session_info.git_branch(wt) == "topic"
    sub = tmp_path / "sub"  # a submodule-style relative gitdir
    sub.mkdir()
    (sub / ".git").write_text("gitdir: ../main/.git/worktrees/wt\n")
    assert session_info.git_branch(sub) == "topic"


def test_branch_detached(tmp_path):
    repo = _repo(tmp_path / "r", "0123456789abcdef0123456789abcdef01234567\n")
    assert session_info.git_branch(repo) == "(detached 0123456)"


def test_branch_no_repo_within_depth(tmp_path, monkeypatch):
    _repo(tmp_path)  # a repo 3 levels up ...
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    monkeypatch.setattr(session_info, "GIT_MAX_DEPTH", 2)  # ... out of reach
    assert session_info.git_branch(deep) is None
    assert session_info.git_branch(None) is None


def test_branch_unreadable_or_odd(tmp_path):
    repo = tmp_path / "r"
    (repo / ".git" / "HEAD").mkdir(parents=True)  # HEAD unreadable as a file
    assert session_info.git_branch(repo) is None
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / ".git").write_text("not a gitdir line\n")
    assert session_info.git_branch(bad) is None
    gone = tmp_path / "gone"
    gone.mkdir()
    (gone / ".git").write_text("gitdir: /nonexistent/x\n")
    assert session_info.git_branch(gone) is None
    junk = _repo(tmp_path / "junk", "garbage\n")
    assert session_info.git_branch(junk) is None


def test_claude_git_branch_preferred_and_head_falls_back(tmp_path):
    repo = _repo(tmp_path / "repo")
    log = _write(tmp_path / "s.jsonl", [
        _claude_line("claude-opus-4-6", 1, branch="old", i=0),
        _claude_line("claude-opus-4-6", 1, branch="feat/recorded", i=1),
    ])
    agent = AgentProcess(pid=1, agent_type="claude-code", working_directory=repo, log_file=log)
    assert session_info.branch_of(agent) == "feat/recorded"
    detached = _write(tmp_path / "d.jsonl", [_claude_line("claude-opus-4-6", 1, branch="HEAD")])
    agent.log_file = detached
    assert session_info.branch_of(agent) == "main"  # .git/HEAD of the cwd
    codex = AgentProcess(pid=2, agent_type="codex", working_directory=repo, log_file=log)
    assert session_info.branch_of(codex) == "main"  # gitBranch is Claude Code's only


def test_branch_is_one_safe_line(tmp_path):
    repo = _repo(tmp_path / "r", "ref: refs/heads/evil\x1b[31mred\n")
    agent = AgentProcess(pid=1, agent_type="codex", working_directory=repo)
    branch = session_info.branch_of(agent)
    assert "\x1b" not in branch and branch.startswith("evil")


# -- ps --------------------------------------------------------------------


@pytest.fixture
def agent(tmp_path, monkeypatch):
    repo = _repo(tmp_path / "proj", "ref: refs/heads/feature/a-very-long-branch-name\n")
    log = _write(tmp_path / "s.jsonl", [_claude_line("claude-opus-4-6", 0, read=420_000)])
    a = AgentProcess(pid=4294967295, agent_type="claude-code", working_directory=repo,
                     log_file=log, session_id="abcdef0123", memory_mb=12345, team_id=4294967295)
    monkeypatch.setattr(cli, "find_running_agents", lambda: [a])
    monkeypatch.setattr(cli, "posture_of", lambda _a: Posture("auto", "none", "high"))
    return a


def test_ps_json_context_and_branch(agent):
    rows = json.loads(CliRunner().invoke(cli.cli, ["ps", "--json"]).output)
    assert rows[0]["context"] == {"used_tokens": 420_000, "window": 1_000_000, "percent": 42}
    assert rows[0]["branch"] == "feature/a-very-long-branch-name"


def test_ps_json_nulls(tmp_path, monkeypatch):
    a = AgentProcess(pid=1, agent_type="cursor", working_directory=None)
    monkeypatch.setattr(cli, "find_running_agents", lambda: [a])
    monkeypatch.setattr(cli, "posture_of", lambda _a: Posture())
    rows = json.loads(CliRunner().invoke(cli.cli, ["ps", "--json"]).output)
    assert rows[0]["context"] is None and rows[0]["branch"] is None


def test_ps_text_columns_fit_100(agent):
    out = CliRunner().invoke(cli.cli, ["ps"]).output
    lines = out.splitlines()
    header = next(line for line in lines if "POSTURE" in line)
    row = next(line for line in lines if "4294967295" in line)
    assert "STATUS" not in header and "CPU" not in header  # dropped to fit (both in --json)
    for col in ("BRANCH", "CTX"):
        assert col in header
    assert "feature/a..." in row and "42%" in row
    assert header.index("POSTURE") == row.index("auto-review")
    assert header.index("CTX") == row.index("42%")  # right-aligned under CTX
    assert len(row) <= 100  # the longest posture label, a 10-digit pid, 5-digit MB


def test_ps_context_colours(agent, tmp_path):
    for read, colour in ((800_000, "\x1b[33m"), (960_000, "\x1b[31m")):
        session_info._CACHE.clear()
        _write(agent.log_file, [_claude_line("claude-opus-4-6", 0, read=read)])
        out = CliRunner().invoke(cli.cli, ["ps"], color=True).output
        row = next(line for line in out.splitlines() if "4294967295" in line)
        assert colour in row and f"  {read // 10_000}%\x1b[0m" in row


def test_ps_ascii_theme(agent, monkeypatch):
    from agentwatch import themes

    monkeypatch.setattr(themes, "get_current_theme_name", lambda: "ascii")
    out = CliRunner().invoke(cli.cli, ["ps"]).output
    row = next(line for line in out.splitlines() if "4294967295" in line)
    assert row.isascii() and "42%" in row


def test_teams_view_rows_aligned(agent, capsys):
    sub = AgentProcess(pid=4294967296, agent_type="claude-code",
                       working_directory=agent.working_directory, parent_agent_pid=agent.pid,
                       team_id=agent.pid, depth=1)
    cli._print_teams_view([agent, sub])
    lines = [click.unstyle(line) for line in capsys.readouterr().out.splitlines()]
    header = next(line for line in lines if "POSTURE" in line)
    root = next(line for line in lines if "4294967295" in line)
    assert header.index("POSTURE") == root.index("auto-review")
    assert header.index("BRANCH") == root.index("feature/a...")
    # The team view keeps its 2-column indent and ROLE: 107 at the worst
    # case (10-digit pid, 5-digit MB, longest posture), 100 with "yolo · no sandbox".
    assert len(root) <= 107


def test_teams_view_deep_rows_keep_a_gap(agent, capsys):
    agent.working_directory = agent.working_directory.rename(
        agent.working_directory.parent / "averyveryverylongproject")
    subs = [AgentProcess(pid=500 + d, agent_type="claude-code",
                         working_directory=agent.working_directory, parent_agent_pid=agent.pid,
                         team_id=agent.pid, depth=d) for d in (1, 2, 3, 5)]
    cli._print_teams_view([agent, *subs])
    lines = [click.unstyle(line) for line in capsys.readouterr().out.splitlines()]
    header = next(line for line in lines if "POSTURE" in line)
    col = header.index("BRANCH")
    for d in (1, 2, 3, 5):
        row = next(line for line in lines if line.lstrip().startswith(str(500 + d)))
        assert row[col - 1] == " ", row  # project cell ends before BRANCH
        assert row[col:].startswith("feature/a...")


def test_ps_text_over_window(agent):
    _write(agent.log_file, [_claude_line("claude-opus-4-6", 0, read=1_100_000)])
    out = CliRunner().invoke(cli.cli, ["ps"]).output
    row = next(line for line in out.splitlines() if "4294967295" in line)
    assert ">100%" in row and len(row) <= 100
    rows = json.loads(CliRunner().invoke(cli.cli, ["ps", "--json"]).output)
    assert rows[0]["context"]["percent"] == 100


# -- visual ----------------------------------------------------------------


def test_visual_ps_carries_context_and_redacted_branch(agent):
    from agentwatch import visual

    secret = "ghp_" + "a" * 36
    (agent.working_directory / ".git" / "HEAD").write_text(f"ref: refs/heads/{secret}\n")
    data = visual.redact(visual._ps(False))
    assert data[0]["context"]["percent"] == 42
    assert secret not in json.dumps(data)
    assert "ctxChip(a)" in visual.PAGE


# -- watch-all -------------------------------------------------------------


def _usage(tokens: int) -> Action:
    return Action(timestamp=datetime.now(timezone.utc).replace(tzinfo=None), tool_name="Read",
                  tool_type=ToolType.READ, success=True, cache_read_tokens=tokens,
                  context_window=1_000_000)


async def test_watch_all_ctx_colour_and_branch_title():
    from test_multi_app_table import _screen, _seed

    from agentwatch.ui.multi_app import MultiAgentWatchApp

    app = MultiAgentWatchApp()
    async with app.run_test(size=(140, 40)) as pilot:
        for name, tokens in (("full", 960_000), ("warm", 850_000), ("cool", 100_000),
                             ("over", 1_100_000)):
            _seed(app, name, pid=None)
            buffer: ActionBuffer = app.agents[Path(f"{name}.jsonl")]["buffer"]
            buffer.add(_usage(tokens))
        app._branches = {Path("full.jsonl"): "feature/branch-in-title"}
        app.selected_path = Path("full.jsonl")
        app.refresh_ui()
        await pilot.pause()
        table = app.query_one("#sessions")
        full = table.get_cell("full.jsonl", "ctx")
        assert full.plain == "96%" and "red" in str(full.get_style_at_offset(app.console, 0))
        warm = table.get_cell("warm.jsonl", "ctx")
        assert "yellow" in str(warm.get_style_at_offset(app.console, 0))
        cool = table.get_cell("cool.jsonl", "ctx")
        assert cool.plain == "10%" and not str(cool.get_style_at_offset(app.console, 0)).strip(
            "none ")
        assert "git:feature/branch-in-title" in _screen(app)
        assert table.get_cell("over.jsonl", "ctx").plain == "100+"  # CTX is 4 wide


def test_scan_processes_reads_branches_off_the_event_loop(tmp_path, monkeypatch):
    from agentwatch.ui import multi_app
    from agentwatch.ui.multi_app import MultiAgentWatchApp

    repo = _repo(tmp_path / "repo", "ref: refs/heads/dev\n")
    log = _write(tmp_path / "s.jsonl", [_claude_line("claude-opus-4-6", 1)])
    proc = AgentProcess(pid=7, agent_type="codex", working_directory=repo, log_file=log)
    monkeypatch.setattr(multi_app, "find_running_agents", lambda cache=None: [proc])
    monkeypatch.setattr(multi_app.subagents, "with_subagents", lambda ps: ps)
    monkeypatch.setattr(multi_app._posture, "posture", lambda p: Posture())
    app = MultiAgentWatchApp()
    _, postures, branches = app._scan_processes()
    assert branches == {log: "dev"} and 7 in postures
