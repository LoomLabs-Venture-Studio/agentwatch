"""The watch-all header line and live event feed (Sprint 36, PR 3)."""

from __future__ import annotations

from test_multi_app_table import _action, _screen, _seed, _warning

from agentwatch.alerts import Alerter
from agentwatch.detectors.base import Severity
from agentwatch.ui.multi_app import MultiAgentWatchApp


def _feed(app) -> list[str]:
    return [line.plain.split(" ", 1)[1] for line in app._events]


def _end_baselines(app) -> None:
    """Skip the startup window and each session's history baseline."""
    app._loaded_until = 0.0
    for data in app.agents.values():
        if "_feed_until" in data:
            data["_feed_until"] = 0.0


def _header(app) -> str:
    return str(app.query_one("#header").render())


async def test_header_counts():
    for size in ((120, 40), (80, 24)):
        app = MultiAgentWatchApp()
        async with app.run_test(size=size) as pilot:
            app.agents[_seed(app, "crit", ago=1, warnings=[_warning(Severity.CRITICAL)])][
                "buffer"].stats.total_cost = 1.25
            app.agents[_seed(app, "high", ago=1, warnings=[_warning(Severity.HIGH)])][
                "buffer"].stats.total_cost = 0.5
            _seed(app, "medium", ago=1, warnings=[_warning(Severity.MEDIUM)])
            _seed(app, "idle", ago=900)
            _seed(app, "stopped", ago=1, stopped=True)
            _seed(app, "stopped-crit", ago=1, stopped=True,  # stopped: doesn't need you
                  warnings=[_warning(Severity.CRITICAL)])
            app.refresh_ui()
            await pilot.pause()
            header = _header(app)
            assert "6 sessions · 3 active · 2 need you" in header, header
            wide = size[0] == 120
            assert "  spent $1.75  " in header  # every loaded session, folded ones too
            assert "alerts 0" in header and "blocks 0" in header
            # 80 columns: the clock goes first, then the title
            assert (header.rstrip()[-8:].count(":") == 2) == wide  # HH:MM:SS
            assert header.startswith("agentwatch") == wide, header
            assert "AgentWatch - Multi-Agent Dashboard" not in _screen(app)


async def test_new_warning_is_one_feed_line_and_clearing_is_another():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        _seed(app, "sel", ago=1)
        a = _seed(app, "proj", ago=1)
        data = app.agents[a]
        data["registry"].check_all = lambda buffer: (
            [_warning(Severity.HIGH, count=7)] if buffer.stats.action_count == 2 else []
        )
        app.refresh_ui()
        _end_baselines(app)
        app.refresh_ui()
        assert _feed(app) == ["2 sessions loaded"]

        data["buffer"].add(_action(0, 1))  # the warning-causing action
        app.refresh_ui()
        app.refresh_ui()
        assert _feed(app)[0].endswith("proj: loop (7x)") and len(_feed(app)) == 2
        assert "alerts 1" in _header(app)  # no alert sinks: new HIGH+ findings

        data["buffer"].add(_action(0, 2))
        app.refresh_ui()
        assert _feed(app)[0] == "✓ proj: loop cleared" and len(_feed(app)) == 3
        await pilot.pause()
        assert "✓ proj: loop cleared" in _screen(app)


async def test_startup_does_not_flood():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)):
        paths = [_seed(app, f"s{i}", ago=1, warnings=[_warning(Severity.HIGH)])
                 for i in range(20)]
        app.refresh_ui()
        assert _feed(app) == []  # history loading: silent
        _end_baselines(app)
        for i, path in enumerate(paths):  # new actions, same findings
            app.agents[path]["buffer"].add(_action(0, i))
        app.refresh_ui()
        assert _feed(app) == ["20 sessions loaded"]


async def test_alerts_and_budget_reach_the_feed():
    alerter = Alerter(notify=True, notify_existing=True, notify_min="high", budget=1.0)
    alerter._desktop = lambda title, body: None  # fake sink
    app = MultiAgentWatchApp(alerter=alerter)
    async with app.run_test(size=(120, 40)):
        a = _seed(app, "proj", ago=1)
        data = app.agents[a]
        app.refresh_ui()
        _end_baselines(app)
        data["registry"].check_all = lambda buffer: [_warning(Severity.CRITICAL)]
        data["buffer"].stats.total_cost = 0.85
        data["buffer"].add(_action(0, 1))
        app.refresh_ui()
        feed = _feed(app)
        assert "$ proj: 80% of budget $1.00 ($0.85)" in feed
        assert "→ alert (desktop): Claude Code · proj — loop" in feed
        data["buffer"].stats.total_cost = 1.2
        data["buffer"].add(_action(0, 2))
        app.refresh_ui()
        assert _feed(app)[:2] == [
            "$ proj: budget $1.00 hit ($1.20)",
            "→ alert (desktop): Claude Code · proj — budget $1.00 hit",
        ]
        assert "alerts 2" in _header(app)


async def test_budget_at_startup_is_one_summary_line():
    """Sessions already over --budget when loaded: one feed line, not one
    budget line plus one alert line each. Alert delivery is unchanged."""
    sent = []
    alerter = Alerter(notify=True, budget=1.0)
    alerter._desktop = lambda title, body: sent.append(title)
    app = MultiAgentWatchApp(alerter=alerter)
    async with app.run_test(size=(120, 40)):
        for i in range(30):
            path = _seed(app, f"s{i}", ago=1)
            app.agents[path]["buffer"].stats.total_cost = 0.9 if i >= 25 else 2.0
        app.refresh_ui()
        assert _feed(app) == [] and len(sent) == 25  # every alert still delivered
        app._loaded_until = 0.0
        app.refresh_ui()
        assert _feed(app) == [
            "$ 25 sessions over budget $1.00; 25 alerts sent (desktop)",
            "30 sessions loaded",
        ]
        assert "alerts 25" in _header(app)
        for data in app.agents.values():  # session windows end; new actions
            data["_feed_until"] = 0.0
            data["buffer"].add(_action(0, 1))
        app.refresh_ui()
        assert len(_feed(app)) == 2  # held 80% lines are not shown later


async def test_session_started_over_budget_after_startup_is_one_line():
    sent = []
    alerter = Alerter(notify=True, budget=1.0)
    alerter._desktop = lambda title, body: sent.append(title)
    app = MultiAgentWatchApp(alerter=alerter)
    async with app.run_test(size=(120, 40)):
        app._loaded_until = None  # startup over
        path = _seed(app, "late", ago=1)
        app.agents[path]["buffer"].stats.total_cost = 2.0
        app.refresh_ui()
        assert _feed(app) == [
            "$ late: over budget $1.00 ($2.00)",
            "→ alert (desktop): Claude Code · late — budget $1.00 hit",
        ]
        assert len(sent) == 1


async def test_feed_and_header_are_literal():
    app = MultiAgentWatchApp(security_mode=True)
    async with app.run_test(size=(120, 40)) as pilot:
        a = _seed(app, "p[/]x", ago=1)
        app.refresh_ui()
        _end_baselines(app)
        app.agents[a]["registry"].check_all = lambda buffer: [
            _warning(Severity.HIGH, signal="[b]sig[/b]")
        ]
        app.agents[a]["buffer"].add(_action(0, 1))
        app.refresh_ui()
        await pilot.pause()
        screen = _screen(app)
        assert "p[/]x: [b]sig[/b]" in screen
        assert "agentwatch [SECURITY]" in screen


async def test_e_toggles_feed_focus_and_escape_returns():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        table, feed = app.query_one("#sessions"), app.query_one("#feed")
        await pilot.pause()
        assert app.focused is table
        await pilot.press("e")
        assert app.focused is feed
        await pilot.press("e")
        assert app.focused is table
        await pilot.press("e")
        await pilot.press("escape")
        assert app.focused is table
