"""watch-all narrow layout and `?` help (Sprint 36, PR 7): columns, the
Selected strip and the Events panel follow the terminal size; a resize keeps
the selection and filter; `?` lists the keys, columns, icons and flags."""

from __future__ import annotations

from pathlib import Path

import pytest
from test_multi_app_table import _order, _screen, _seed, _wait, _warning
from textual.widgets import Footer

from agentwatch.alerts import Alerter
from agentwatch.detectors.base import Severity
from agentwatch.discovery import AgentProcess, AgentTeam
from agentwatch.ui.detail import DetailScreen
from agentwatch.ui.help import HelpScreen
from agentwatch.ui.multi_app import MultiAgentWatchApp

LONG = "a-very-long-tool-name-that-would-not-fit"


def _cursor_key(app) -> str:
    table = app.query_one("#sessions")
    return table.coordinate_to_cell_key((table.cursor_row, 0)).row_key.value


def _many(app, n: int = 20) -> None:
    _seed(app, "top", ago=1, warnings=[_warning(Severity.CRITICAL, tool=LONG, count=7)])
    for i in range(1, n):
        _seed(app, f"s{i:02d}", ago=i + 1)
    app.refresh_ui()


# (size, narrow, Events panel height or 0 for hidden)
LAYOUTS = [
    ((120, 40), False, 7), ((100, 30), False, 7), ((99, 30), True, 7),
    ((80, 24), True, 5), ((80, 18), True, 0), ((60, 20), True, 5),
]


@pytest.mark.parametrize(("size", "narrow", "feed"), LAYOUTS)
async def test_layout_follows_the_terminal_size(size, narrow, feed):
    app = MultiAgentWatchApp(alerter=Alerter(budget=5.0))
    async with app.run_test(size=size) as pilot:
        _many(app)
        await pilot.pause()
        table = app.query_one("#sessions")
        expected = (["dot", "project", "health", "cost", "last", "signal"] if narrow else
                    ["dot", "agent", "project", "health", "cost", "ctx", "last", "signal"])
        assert [c.value for c in table.columns] == expected
        assert app.query_one("#selected").display == (not narrow)
        events = app.query_one("#feed")
        assert events.display == bool(feed)
        if feed:
            assert events.outer_size.height == feed
        assert table.max_scroll_x == 0  # TOP SIGNAL in view, no horizontal scroll
        screen = _screen(app)
        assert "TOP SIGNAL" in screen and "⚠ loop: a-" in screen
        assert ("Selected: top" in screen) == (not narrow)
        rows = table.size.height - 1  # minus the column headers
        assert rows >= (8 if size[1] >= 20 else 6), rows
        if size == (80, 24):
            assert rows >= 13
        print(f"\n--- {size[0]}x{size[1]} ---\n{screen}")


async def test_narrow_rows_put_tree_team_and_fold_in_project_literally():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(80, 24)) as pilot:
        root = AgentProcess(pid=10, agent_type="t", working_directory=Path("/x/[b]"))
        app.teams[10] = AgentTeam(team_id=10, root=root, members=[root, root])
        _seed(app, "lead", ago=1, team_id=10, pid=10)
        sub = _seed(app, "p[b]", ago=2, depth=1, team_id=10, pid=11)
        app.agents[sub]["item"].parent_agent_pid = 10
        _seed(app, "old", ago=5000)
        app.refresh_ui()
        await pilot.pause()
        table = app.query_one("#sessions")
        assert table.get_cell("team:10", "project").plain == "TEAM t:[b]"
        assert table.get_cell(str(sub), "project").plain == "└ p[b]"
        assert table.get_cell("fold", "project").plain == "… 1 idle"
        assert _order(app) == ["TEAM t:[b]", "lead", "└ p[b]", "(a to show)"]
        screen = _screen(app)
        assert "TEAM t:[b]" in screen and "└ p[b]" in screen and "(a to show)" in screen

        await pilot.press("slash", "c", "l", "a", "u")  # AGENT is hidden but still filters
        assert _order(app) == ["TEAM t:[b]", "lead", "└ p[b]", "(a to show)"]


async def test_resize_across_thresholds_keeps_selection_cursor_and_filter():
    app = MultiAgentWatchApp(alerter=Alerter(budget=5.0))
    async with app.run_test(size=(120, 40)) as pilot:
        for name in ("alpha", "beta", "bravo", "gamma"):
            _seed(app, name, ago=len(app.agents) + 1)
        app.refresh_ui()
        await pilot.pause()
        await pilot.press("slash", "b", "enter")
        await pilot.press("down")
        await pilot.pause()
        assert _order(app) == ["beta", "bravo"] and app.selected_path == Path("bravo.jsonl")
        for width, height in ((80, 24), (80, 18), (99, 30), (100, 30), (60, 20), (120, 40)):
            await pilot.resize_terminal(width, height)
            await pilot.pause()
            assert _order(app) == ["beta", "bravo"], (width, height)
            assert app.selected_path == Path("bravo.jsonl") and _cursor_key(app) == "bravo.jsonl"
            assert "filter: b" in _screen(app)
            assert ("agent" in app.query_one("#sessions").columns) == (width >= 100)
            cost = app.query_one("#sessions").get_cell("bravo.jsonl", "cost").plain
            assert ("/ $5.00" in cost) == (width >= 100), cost
        await pilot.press("escape")  # the kept filter still clears
        assert _order(app) == ["alpha", "beta", "bravo", "gamma"]


async def test_layout_is_decided_on_resize_only(monkeypatch):
    app = MultiAgentWatchApp()
    async with app.run_test(size=(80, 24)) as pilot:
        _many(app, 5)
        await pilot.pause()
        calls = []
        orig = app._layout
        monkeypatch.setattr(app, "_layout", lambda *a: calls.append(a) or orig(*a))
        cleared = []
        clear = app._table.clear
        monkeypatch.setattr(app._table, "clear", lambda **k: cleared.append(k) or clear(**k))
        for _ in range(3):
            app.refresh_ui()
        assert calls == [] and cleared == []
        await pilot.resize_terminal(90, 24)  # TOP SIGNAL is wider: columns rebuilt
        await pilot.pause()
        assert calls == [(90, 24)] and len(cleared) == 1


async def test_e_shows_hidden_events_in_place_of_the_table():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(80, 18)) as pilot:
        _many(app, 3)
        app._event("hello [b]events[/b]")
        await pilot.pause()
        table, feed = app.query_one("#sessions"), app.query_one("#feed")
        assert not feed.display and table.display
        for back in ("e", "escape"):
            await pilot.press("e")
            await pilot.pause()
            assert feed.display and not table.display and app.focused is feed
            assert "hello [b]events[/b]" in _screen(app)
            await pilot.press(back)
            await pilot.pause()
            assert not feed.display and table.display and app.focused is table

        await pilot.press("e")  # open, then the terminal grows: panel at its height
        await pilot.resize_terminal(80, 24)
        await pilot.pause()
        assert feed.display and table.display and feed.outer_size.height == 5


@pytest.mark.parametrize("close", ["escape", "question_mark", "q"])
async def test_question_mark_opens_help_and_closes(close):
    app = MultiAgentWatchApp()
    async with app.run_test(size=(80, 24)) as pilot:
        _many(app, 3)
        await pilot.pause()
        await pilot.press("question_mark")
        await _wait(pilot, lambda: isinstance(app.screen, HelpScreen))
        text = str(app.screen.query_one("#help Static").render())
        for item in ("Enter", "filter", "show / fold idle", "sort: attention, cost, recent",
                     "Events panel", "security detectors", "quit", "Tab, 1-4",
                     "● ○", "▲ ▼", "⚠", "⛔", "▮▮▮▯", "… N idle", "Sort (o)",
                     "--all-logs", "--since Nh|Nd|all", "--budget USD", "--notify",
                     "--webhook URL", "--headless"):
            assert item in text, item
        assert "Keys" in _screen(app)
        await pilot.press("enter")  # Detail is off under help
        assert isinstance(app.screen, HelpScreen)
        await pilot.press(close)
        await _wait(pilot, lambda: not isinstance(app.screen, HelpScreen))
        assert app.is_running and app.selected_path == Path("top.jsonl")


async def test_help_from_the_detail_view():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(80, 24)) as pilot:
        _many(app, 2)
        await pilot.pause()
        await pilot.press("enter")
        await _wait(pilot, lambda: isinstance(app.screen, DetailScreen))
        await pilot.press("question_mark")
        await _wait(pilot, lambda: isinstance(app.screen, HelpScreen))
        await pilot.press("escape")
        await _wait(pilot, lambda: isinstance(app.screen, DetailScreen))
        await pilot.resize_terminal(120, 40)  # re-laid out under the detail view
        await pilot.pause()
        await pilot.press("escape")
        await _wait(pilot, lambda: not isinstance(app.screen, DetailScreen))
        assert "agent" in app.query_one("#sessions").columns
        assert _cursor_key(app) == "top.jsonl" and "Selected: top" in _screen(app)


@pytest.mark.parametrize("width", [80, 120])
async def test_footer_most_important_keys_first(width):
    app = MultiAgentWatchApp()
    async with app.run_test(size=(width, 24)) as pilot:
        await pilot.pause()
        footer = _screen(app).splitlines()[-1]
        keys = ["Detail", "Filter", "Idle", "? Help", "Quit", "Sort", "Events", "Security"]
        assert [footer.index(k) for k in keys] == sorted(footer.index(k) for k in keys)
        assert "palette" not in footer and app.screen.query_one(Footer)


async def test_narrow_header_keeps_counts_spend_and_budget():
    app = MultiAgentWatchApp(alerter=Alerter(budget=5.0))
    async with app.run_test(size=(80, 24)) as pilot:
        _many(app, 12)
        app.agents[Path("top.jsonl")]["buffer"].stats.total_cost = 14.2
        app.refresh_ui()
        await pilot.pause()
        header = str(app.query_one("#header").render()).rstrip()
        assert header == "12 sess · 1 need you  spent $14.20  alerts 0  blocks 0  " \
                         "budget $5.00/session", header


async def test_detail_loop_breaker_line_wraps_at_80_columns():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(80, 24)) as pilot:
        _many(app, 1)
        data = app.agents[Path("top.jsonl")]
        data["_coach_key"], data["_coach_file"] = "sid", None
        await pilot.pause()
        await pilot.press("enter")
        await _wait(pilot, lambda: isinstance(app.screen, DetailScreen) and app.screen.ready)
        app.refresh_ui()
        await pilot.pause()
        lines = str(app.screen.query_one("#d-loop").render()).splitlines()
        assert len(lines) == 2 and lines[1].startswith(" " * 16), lines
        assert "is the agentwatch plugin installed?)" in " ".join(" ".join(lines).split())
        assert all(len(line) <= 78 for line in lines)
        screen = _screen(app)
        assert "Health  Security  Network  Process" in screen
