"""The watch-all detail view (Sprint 36, PR 4): Enter opens one session full
screen with Health/Security/Network/Process tabs, Esc returns to the same
row. The scoring fixes that ship with it are in test_multi_app_refresh.py."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from test_multi_app_table import _now, _screen, _seed, _wait, _warning
from textual.containers import VerticalScroll
from textual.widgets import TabbedContent, TabPane

from agentwatch.detectors.base import Severity
from agentwatch.parser.models import Action, ToolType
from agentwatch.ui.detail import TABS, DetailScreen
from agentwatch.ui.multi_app import MultiAgentWatchApp

SIZES = ((120, 40), (80, 24))


def _cursor_key(app) -> str:
    table = app.query_one("#sessions")
    return table.coordinate_to_cell_key((table.cursor_row, 0)).row_key.value


async def _shows(pilot, app, *texts: str) -> str:
    """The screen text once it shows every one of *texts* (a repaint can lag
    a pause under load)."""
    try:
        await _wait(pilot, lambda: all(t in _screen(app) for t in texts))
    except AssertionError:
        raise AssertionError(f"{texts} not on screen:\n{_screen(app)}") from None
    return _screen(app)


async def _warnings_in_view(pilot, app) -> None:
    """At 80x24 the Health tab's graphs and bars put the warnings below the
    fold (the pane scrolls): scroll them to the top."""
    await _wait(pilot, lambda: isinstance(app.screen, DetailScreen) and app.screen.ready)
    app.screen.query_one("#d-warnings").scroll_visible(animate=False, top=True)
    await pilot.pause()


async def _open(app, pilot, *names, select: int = 0):
    paths = [_seed(app, n, ago=i + 1) for i, n in enumerate(names)]
    app.refresh_ui()
    await pilot.pause()
    for _ in range(select):
        await pilot.press("down")
    await pilot.pause()
    await pilot.press("enter")
    await _wait(pilot, lambda: isinstance(app.screen, DetailScreen) and app.screen.ready)
    return paths


@pytest.mark.parametrize("size", SIZES)
async def test_enter_opens_detail_tabs_switch_and_back_keeps_selection(size):
    for back in ("escape", "backspace", "q"):
        app = MultiAgentWatchApp()
        async with app.run_test(size=size) as pilot:
            paths = await _open(app, pilot, "a", "b", "c", select=1)
            screen = app.screen
            assert isinstance(screen, DetailScreen) and screen.path == paths[1]
            assert [p.id for p in screen.query(TabPane)] == list(TABS)
            await _shows(pilot, app, "b · Claude Code", "Health", "Security", "Network",
                         "Process", "Back", "Health [")  # Health tab first

            tabs = screen.query_one(TabbedContent)
            keys = (("2", "security"), ("tab", "network"), ("shift+tab", "security"),
                    ("4", "process"), ("tab", "health"), ("3", "network"))
            for key, want in keys if back == "escape" else keys[-1:]:
                await pilot.press(key)
                await pilot.pause()
                assert tabs.active == want, (key, want)

            await pilot.press(back)
            await _wait(pilot, lambda: not isinstance(app.screen, DetailScreen))
            assert app.selected_path == paths[1] and _cursor_key(app) == str(paths[1])
            assert app.is_running  # q goes back in the detail view, not quit


async def test_enter_on_team_header_row_does_nothing():
    from agentwatch.discovery import AgentProcess, AgentTeam

    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        root = AgentProcess(pid=1, agent_type="claude-code", working_directory=Path("/p"),
                            team_id=1)
        app.teams[1] = AgentTeam(team_id=1, root=root, members=[root, root])
        _seed(app, "a", pid=1, team_id=1)
        app.refresh_ui()
        await pilot.pause()
        await pilot.press("up")
        await pilot.pause()
        assert _cursor_key(app) == "team:1"
        await pilot.press("enter")
        await pilot.pause()
        assert not isinstance(app.screen, DetailScreen)


@pytest.mark.parametrize("size", SIZES)
async def test_long_warning_list_scrolls_nothing_clipped(size):
    app = MultiAgentWatchApp()
    async with app.run_test(size=size) as pilot:
        warnings = [_warning(Severity.MEDIUM, f"sig{i}") for i in range(40)]
        for w in warnings:
            w.suggestion = "Re-read the failing test output before editing again. " * 3
        _seed(app, "a", warnings=warnings)
        app.refresh_ui()
        await pilot.pause()
        await pilot.press("enter")
        await _warnings_in_view(pilot, app)
        await _shows(pilot, app, "sig0 warning")
        pane = app.screen.query_one("#health .pane", VerticalScroll)
        assert pane.max_scroll_y > 0
        assert "sig39 warning" not in _screen(app)
        await pilot.press("pagedown", "down")
        await pilot.pause()
        assert pane.scroll_y > 0
        while pane.scroll_y < pane.max_scroll_y:
            await pilot.press("pagedown")
            await pilot.pause()
        text = await _shows(pilot, app, "sig39 warning")
        assert "more" not in text  # all 40, no "... and N more"
        assert "before editing again." in text  # suggestions are wrapped, not cut


async def test_health_tab_is_compact():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await _open(app, pilot, "a")
        text = await _shows(pilot, app, "Health [", "Duration:")
        status = app.agents[Path("a.jsonl")]["_last_report"].status.upper()
        assert text.count(status) == 1  # one status word: the overall one
        assert "Status:" not in text and "State:" not in text
        assert not re.search(r"\] +[01]\.\d\d", text)  # no raw 0-1 numbers by bars
        assert "Duration: 0m" in text


@pytest.mark.parametrize("size", SIZES)
async def test_security_tab_wording(size):
    app = MultiAgentWatchApp()
    async with app.run_test(size=size) as pilot:
        await _open(app, pilot, "a")
        await pilot.press("2")
        await _shows(pilot, app, "Security mode is off: press s to turn it on.",
                     "Credential file accesses", "Injection-like messages")
        await pilot.press("s")
        text = await _shows(pilot, app, "Security: clean")
        assert "Security mode is off" not in text
        for word in ("PRODUCTIVE", "STRUGGLING", "SPINNING", "STUCK"):
            assert word not in text.split("Health  Security")[-1]


async def test_detail_is_literal_text():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        w = _warning(Severity.HIGH, "loop", tool="[b]Bash[/b]")
        w.message = "loop on [/] [link=x]y[/link]"
        _seed(app, "p[/]", warnings=[w])
        app.refresh_ui()
        await pilot.pause()
        await pilot.press("enter")
        await _shows(pilot, app, "p[/] · Claude Code", "loop on [/] [link=x]y[/link]")


async def test_detail_updates_live_only_when_changed():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        (path,) = await _open(app, pilot, "a")
        widget = app.screen.query_one("#d-warnings")
        calls = []
        original = widget.update
        widget.update = lambda *a, **k: (calls.append(1), original(*a, **k))
        app.refresh_ui()
        app.refresh_ui()
        assert calls == []  # nothing new: no update
        data = app.agents[path]
        data["registry"].check_all = lambda buffer: [_warning(Severity.HIGH, "fresh_signal")]
        data["buffer"].add(Action(timestamp=_now(), tool_name="Read", tool_type=ToolType.READ,
                                  success=True, file_path="x.py"))
        app.refresh_ui()
        assert calls == [1]
        await _shows(pilot, app, "fresh_signal warning")


def test_module_bars_that_round_to_empty_are_left_out():
    from agentwatch.health.rot import MetricResult, RotReport, RotState
    from agentwatch.ui.rot_widget import ContextHealthWidget

    widget = ContextHealthWidget()
    modules = {"behavioral": MetricResult("behavioral", 0.04),
               "thrash": MetricResult("thrash", 0.3)}
    widget._report = RotReport(0.1, 0.1, RotState.HEALTHY, modules)
    text = widget._build_content()
    assert "Behavioral" not in text and "Tool Thrash  [███░░░░░░░]" in text


async def test_wrapped_detail_lines_keep_their_indent():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(80, 24)) as pilot:
        w = _warning(Severity.MEDIUM)
        w.suggestion = "Re-read the failing test output before editing again. " * 3
        path = _seed(app, "a", warnings=[w])
        long_path = Path("/very/long/" + "d" * 50 + "/" + "x" * 60 + ".jsonl")
        app.agents[path]["item"].log_path = long_path
        app.refresh_ui()
        await pilot.pause()
        await pilot.press("enter")
        await _warnings_in_view(pilot, app)
        text = await _shows(pilot, app, "editing again. Re-read")
        tip = [line for line in text.splitlines() if "test output" in line]
        assert "💡" in tip[0] and tip[1].startswith(" " * 8 + "failing"), tip
        await pilot.press("4")
        text = await _shows(pilot, app, "xxxxx.jsonl")
        log = text[text.index("Log      /very"):].splitlines()[:2]
        assert log[1].startswith(" " * 11 + "x"), log
