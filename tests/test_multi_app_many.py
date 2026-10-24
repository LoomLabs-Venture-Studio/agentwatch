"""watch-all with many sessions (Sprint 36, PR 6): the --all-logs 24h window,
idle folding (`a`), the `/` filter, project names from transcripts, and
team grouping."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click
import pytest
from click.testing import CliRunner
from test_multi_app_table import _order, _seed, _wait, _warning

from agentwatch import cc_stats
from agentwatch.cli import _parse_since, cli
from agentwatch.detectors.base import Severity
from agentwatch.discovery import AgentProcess
from agentwatch.ui.detail import DetailScreen
from agentwatch.ui.multi_app import MultiAgentWatchApp, window_label

SIZES = [(120, 40), (80, 24)]
DAY = 86400


def _screen(app) -> str:
    return "\n".join(strip.text for strip in app.screen._compositor.render_strips())


def _feed(app) -> list[str]:
    return [line.plain.split(" ", 1)[1] for line in app._events]


def _log(path: Path, cwd: str | None = None, ago_s: float = 30, age_days: float = 0) -> Path:
    """A Claude Code transcript (3 Bash calls *ago_s* back); mtime *age_days* old."""
    path.parent.mkdir(parents=True, exist_ok=True)
    base = datetime.now(timezone.utc) - timedelta(seconds=ago_s)
    entries = []
    for i in range(3):
        ts = (base + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = {"type": "assistant", "sessionId": path.stem, "timestamp": ts,
                 "message": {"role": "assistant", "content": [
                     {"type": "tool_use", "id": f"t{i}", "name": "Bash",
                      "input": {"command": f"ls {i}"}}]}}
        if cwd:
            entry["cwd"] = cwd
        entries.append(entry)
    path.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")
    if age_days:
        old = time.time() - age_days * DAY
        os.utime(path, (old, old))
    return path


def _loaded(app, n: int) -> bool:
    return len(app.agents) == n and all(
        d["buffer"].stats.action_count for d in app.agents.values())


def _rows(app) -> list[str]:
    return [str(row.key.value) for row in app.query_one("#sessions").ordered_rows]


def _cursor_key(app) -> str:
    table = app.query_one("#sessions")
    return table.coordinate_to_cell_key((table.cursor_row, 0)).row_key.value


# -- 24h window -----------------------------------------------------------


def test_since_values():
    assert [_parse_since(v) for v in (None, "24h", "2d", "ALL", " 6H ")] == [
        None, DAY, 2 * DAY, "all", 6 * 3600
    ]
    for bad in ("0h", "3x", "24", "-1d", "1w"):
        with pytest.raises(click.BadParameter):
            _parse_since(bad)
    assert [window_label(s) for s in (DAY, 2 * DAY, 6 * 3600, 36 * 3600)] == [
        "24h", "2d", "6h", "36h"
    ]


@pytest.mark.parametrize(("args", "since"), [
    ([], DAY), (["--since", "all"], None), (["--since", "2d"], 2 * DAY),
])
def test_all_logs_defaults_to_24h(monkeypatch, tmp_path, args, since):
    seen = {}

    class App:
        def __init__(self, **kwargs):
            seen.update(kwargs)

        def run(self, **kwargs):
            pass

    monkeypatch.setattr("agentwatch.ui.multi_app.MultiAgentWatchApp", App)
    monkeypatch.setattr("agentwatch.parser.logs.DEFAULT_SEARCH_PATHS", [tmp_path], raising=False)
    result = CliRunner().invoke(cli, ["watch-all", "--all-logs", *args])
    assert result.exit_code == 0, result.output
    assert seen["since"] == since


def test_since_needs_all_logs():
    result = CliRunner().invoke(cli, ["watch-all", "--since", "2d"])
    assert result.exit_code == 2 and "--since applies to --all-logs only" in result.output


@pytest.mark.parametrize("size", SIZES)
async def test_window_skips_old_logs_and_picks_them_up_when_written(tmp_path, size):
    _log(tmp_path / "new.jsonl")
    _log(tmp_path / "day1.jsonl", age_days=1.5)
    old = _log(tmp_path / "old.jsonl", age_days=3)
    app = MultiAgentWatchApp(watch_paths=[tmp_path], since=DAY)
    parsed = []
    orig = app.watcher._make_watcher
    app.watcher._make_watcher = lambda p: (parsed.append(p.name), orig(p))[1]
    async with app.run_test(size=size) as pilot:
        await _wait(pilot, lambda: len(app.agents) == 1)
        app._loaded_until = 0.0
        app.refresh_ui()
        assert _feed(app)[0] == "1 session loaded (last 24h of 3 logs)"
        assert "Sessions (last 24h)" in _screen(app)
        assert parsed == ["new.jsonl"]  # old logs are not loaded at all

        with old.open("a", encoding="utf-8") as f:  # written to again: picked up
            f.write("\n")
        await _wait(pilot, lambda: old in app.agents)
        assert set(parsed) == {"new.jsonl", "old.jsonl"}


async def test_since_all_and_2d(tmp_path):
    _log(tmp_path / "new.jsonl")
    _log(tmp_path / "day1.jsonl", age_days=1.5)
    _log(tmp_path / "old.jsonl", age_days=3)
    for since, n in ((2 * DAY, 2), (None, 3)):
        app = MultiAgentWatchApp(watch_paths=[tmp_path], since=since)
        async with app.run_test(size=(120, 40)) as pilot:
            await _wait(pilot, lambda: len(app.agents) == n)
            await pilot.pause(0.6)  # another scan: still n
            assert len(app.agents) == n


# -- idle folding ---------------------------------------------------------


@pytest.mark.parametrize("size", SIZES)
async def test_idle_sessions_fold_and_a_shows_them(size):
    app = MultiAgentWatchApp()
    async with app.run_test(size=size) as pilot:
        _seed(app, "busy", ago=1)
        _seed(app, "recent", ago=600)  # idle (○) but under 15 min: not folded
        _seed(app, "old", ago=900, warnings=[_warning(Severity.CRITICAL)])
        _seed(app, "older", ago=5000)
        _seed(app, "stopped", ago=1, stopped=True)
        app.refresh_ui()
        await pilot.pause()
        assert _order(app) == ["busy", "recent", "(a to show)"]
        assert app.query_one("#sessions").get_cell("fold", "agent").plain == "… 3 idle"
        assert "… 3 idle" in _screen(app) and "(a to show)" in _screen(app)
        assert "5 sessions" in _screen(app)  # the header still counts them

        await pilot.press("a")
        assert _order(app) == ["busy", "stopped", "recent", "old", "older", "(a to fold)"]
        await pilot.press("a")
        assert _order(app) == ["busy", "recent", "(a to show)"]

        # a folded session that becomes active is shown again
        app.agents[Path("older.jsonl")]["buffer"].add(
            app.agents[Path("busy.jsonl")]["buffer"].actions[-1])
        app.refresh_ui()
        assert _order(app) == ["busy", "older", "recent", "(a to show)"]


async def test_idle_subagents_fold_under_an_active_parent_and_vice_versa():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        def sub(name, ago, parent):
            path = _seed(app, name, ago=ago, depth=1, team_id=parent, pid=parent + len(app.agents))
            app.agents[path]["item"].parent_agent_pid = parent
            return path

        _seed(app, "live", ago=1, team_id=10, pid=10)
        sub("live-old", 5000, 10)
        sub("live-new", 2, 10)
        _seed(app, "sleepy", ago=5000, team_id=20, pid=20)
        sub("sleepy-busy", 3, 20)
        sub("sleepy-old", 5000, 20)
        app.refresh_ui()
        await pilot.pause()
        assert _order(app) == ["live", "live-new", "sleepy", "sleepy-busy", "(a to show)"]
        assert app.query_one("#sessions").get_cell("fold", "agent").plain == "… 2 idle"
        await pilot.press("a")
        assert _order(app) == ["live", "live-new", "live-old", "sleepy", "sleepy-busy",
                               "sleepy-old", "(a to fold)"]


async def test_fold_keeps_cursor_on_selected_or_moves_to_nearest():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        a = _seed(app, "a", ago=1)
        b = _seed(app, "b", ago=2)
        c = _seed(app, "c", ago=3)
        app.refresh_ui()
        await pilot.pause()
        await pilot.press("down")
        await pilot.pause()
        assert app.selected_path == b

        _age = lambda p, s: setattr(  # noqa: E731
            app.agents[p]["buffer"].stats, "last_action_time",
            datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=s))
        _age(a, 1000)  # another row folds: the cursor stays on b
        app.refresh_ui()
        await pilot.pause()
        assert _order(app) == ["b", "c", "(a to show)"]
        assert app.selected_path == b and _cursor_key(app) == "b.jsonl"

        _age(b, 1000)  # the selected row folds: nearest shown session
        app.refresh_ui()
        await pilot.pause()
        assert _order(app) == ["c", "(a to show)"]
        assert app.selected_path == c and _cursor_key(app) == "c.jsonl"
        assert "Selected: c" in str(app.query_one("#selected").render())

        _age(c, 1000)  # nothing left to show: the cursor sits on the fold row
        app.refresh_ui()
        await pilot.pause()
        assert _rows(app) == ["fold"] and _cursor_key(app) == "fold"
        await pilot.press("enter")
        assert not isinstance(app.screen, DetailScreen)
        await pilot.press("a")
        await pilot.pause()
        assert _cursor_key(app) == "c.jsonl"


# -- filter ---------------------------------------------------------------


@pytest.mark.parametrize("size", SIZES)
async def test_slash_filters_live_enter_keeps_esc_clears(size):
    app = MultiAgentWatchApp()
    async with app.run_test(size=size) as pilot:
        _seed(app, "alpha", ago=1)
        _seed(app, "beta[b]", ago=2, warnings=[_warning(Severity.HIGH, tool="Grep")])
        _seed(app, "gamma", ago=3)
        app.refresh_ui()
        await pilot.pause()
        filt = app.query_one("#filter")
        assert not filt.display

        await pilot.press("slash")
        assert filt.display and app.focused is filt
        await pilot.press("B", "e")
        assert _order(app) == ["beta[b]"]  # project, case-insensitive, live
        assert "filter: Be" in _screen(app)
        await pilot.press("backspace", "backspace", "g", "r", "e", "p")
        assert _order(app) == ["beta[b]"]  # top signal "loop: Grep"
        await pilot.press("backspace", "backspace", "backspace", "backspace", "c", "l")
        assert _order(app) == ["beta[b]", "alpha", "gamma"]  # agent "Claude Code"
        for _ in range(2):
            await pilot.press("backspace")
        await pilot.press("q", "a", "[", "/")  # app keys type into the filter
        assert app.is_running and filt.value == "qa[/"
        assert _order(app) == [] and "filter: qa[/" in _screen(app)  # literal text

        await pilot.press(*["backspace"] * 4, "m", "m")
        await pilot.press("enter")  # keep it, back to the table
        await pilot.pause()
        assert not filt.display and app.focused is app.query_one("#sessions")
        assert not isinstance(app.screen, DetailScreen)
        assert _order(app) == ["gamma"] and app.selected_path == Path("gamma.jsonl")
        assert "filter: mm" in _screen(app) and "sort: attention" in _screen(app)

        await pilot.press("slash")
        assert filt.value == "mm"
        await pilot.press("escape")  # clears it
        await pilot.pause()
        assert not filt.display and app.focused is app.query_one("#sessions")
        assert _order(app) == ["beta[b]", "alpha", "gamma"]
        assert "filter:" not in _screen(app)
        assert app.selected_path == Path("gamma.jsonl") and _cursor_key(app) == "gamma.jsonl"

        await pilot.press("slash", "a", "l", "enter")
        assert _order(app) == ["alpha"]
        await pilot.press("escape")  # on the table, Esc clears a kept filter too
        assert _order(app) == ["beta[b]", "alpha", "gamma"]


# -- project names --------------------------------------------------------


async def test_all_logs_project_names_from_transcripts(tmp_path, monkeypatch):
    projects = tmp_path / "projects"
    monkeypatch.setattr(cc_stats, "CLAUDE_PROJECTS_DIR", projects, raising=False)
    wt = _log(projects / "-x-wt" / "s1.jsonl", cwd="/x/agentwatch/.claude/worktrees/agent-1")
    home = _log(projects / "-home-u" / "s2.jsonl", cwd=str(Path.home()), ago_s=60)
    plain = _log(projects / "-x-shop" / "s3.jsonl", cwd="/srv/shop", ago_s=90)
    nocwd = _log(projects / "-x-y-kiosk" / "s4.jsonl", ago_s=120)  # from the dir name
    sub = _log(projects / "-x-shop" / "s3" / "subagents" / "agent-a1.jsonl", cwd="/srv/shop",
               ago_s=10)
    outside = _log(tmp_path / "logs" / "s5.jsonl", cwd="/srv/api", ago_s=150)
    app = MultiAgentWatchApp(watch_paths=[projects, tmp_path / "logs"])
    async with app.run_test(size=(120, 40)) as pilot:
        await _wait(pilot, lambda: _loaded(app, 6))
        app.refresh_ui()
        names = {p: app.agents[p]["item"].project_name for p in app.agents}
        assert names == {wt: "agentwatch", home: "~", plain: "shop", nocwd: "kiosk",
                         sub: "shop", outside: "api"}
        assert _order(app) == ["shop", "shop", "agentwatch", "~", "kiosk", "api"]
        table = app.query_one("#sessions")
        assert table.get_cell(str(sub), "agent").plain.startswith("└ sub Claude")
        assert [table.get_row_index(str(k)) for k in (plain, sub)] == [0, 1]

        app.selected_path = plain
        app.refresh_ui()
        assert "Selected: shop · Claude Code" in str(app.query_one("#selected").render())
        app.push_screen(DetailScreen(plain))
        await _wait(pilot, lambda: getattr(app.screen, "ready", False))
        app.refresh_ui()
        await pilot.pause()
        assert str(app.screen.query_one("#detail-title").render()).startswith("shop · ")
        assert str(plain) in str(app.screen.query_one("#d-process").render()).replace(
            "\n" + " " * 11, "")


# -- team grouping --------------------------------------------------------


def _proc(tmp_path: Path, pid: int, parent: int | None = None, depth: int = 0,
          team: int | None = None, name: str | None = None) -> AgentProcess:
    log = _log(tmp_path / f"{name or pid}.jsonl", ago_s=pid % 7)
    return AgentProcess(pid=pid, agent_type="claude-code", working_directory=Path("/w/proj"),
                        log_file=log, parent_agent_pid=parent, depth=depth,
                        team_id=team if team is not None else pid)


async def test_teams_group_members_and_follow_scans(tmp_path, monkeypatch):
    solo = _proc(tmp_path, 50)
    root = _proc(tmp_path, 10)
    kid = _proc(tmp_path, 11, parent=10, depth=1, team=10)
    grandkid = _proc(tmp_path, 13, parent=11, depth=2, team=10)
    kid2 = _proc(tmp_path, 12, parent=10, depth=1, team=10)
    app = MultiAgentWatchApp(agent_processes=[solo, root, kid, grandkid, kid2])
    scan = [solo, root, kid, grandkid, kid2]
    monkeypatch.setattr("agentwatch.ui.multi_app.find_running_agents", lambda cache: list(scan))
    async with app.run_test(size=(120, 40)) as pilot:
        await _wait(pilot, lambda: _loaded(app, 5))
        k = {p.pid: str(p.log_file) for p in scan}
        app.agents[kid.log_file]["registry"].check_all = lambda b: [_warning(Severity.CRITICAL)]
        app.agents[kid.log_file]["_last_count"] = -1
        app.refresh_ui()
        # the team sorts by its worst member; the tree under its header
        assert _rows(app) == ["team:10", k[10], k[11], k[13], k[12], k[50]]

        # a team that forms after startup: header with its members under it
        late_root = _proc(tmp_path, 60)
        scan.append(late_root)
        await app._refresh_processes()
        await _wait(pilot, lambda: _loaded(app, 6))
        late_kid = _proc(tmp_path, 61, parent=60, depth=1, team=60)
        scan.append(late_kid)
        await app._refresh_processes()
        app.refresh_ui()
        k.update({60: str(late_root.log_file), 61: str(late_kid.log_file)})
        rows = _rows(app)
        at = rows.index("team:60")
        assert rows[at:at + 3] == ["team:60", k[60], k[61]]
        assert app.query_one("#sessions").get_cell(k[61], "agent").plain.startswith("└ sub")

        # the team's sessions are gone: its header row goes too
        scan[:] = [solo, root, kid, grandkid, kid2]
        app.watcher.reap_stopped = lambda timeout: [late_root.log_file, late_kid.log_file]
        await app._refresh_processes()
        app.refresh_ui()
        assert "team:60" not in _rows(app) and 60 not in app.teams
        assert _rows(app)[0] == "team:10"
