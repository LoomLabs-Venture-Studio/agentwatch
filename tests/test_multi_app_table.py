"""The watch-all sessions table (Sprint 36, PR 2): one row per session,
attention sort, `o` cycles the sort, the cursor follows its session, and a
tick updates only changed cells (the table is never cleared)."""

from __future__ import annotations

import json
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from agentwatch.detectors import create_registry
from agentwatch.detectors.base import Category, Severity, Warning
from agentwatch.parser.models import Action, ActionBuffer, ToolType
from agentwatch.themes import get_theme
from agentwatch.ui.multi_app import STOPPED_STYLE, AgentItem, MultiAgentWatchApp, _ago

HEADERS = ("AGENT", "PROJECT", "HEALTH", "COST", "CTX", "LAST", "TOP SIGNAL")


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _action(ago_s: float = 0.0, i: int = 0) -> Action:
    return Action(
        timestamp=_now() - timedelta(seconds=ago_s),
        tool_name="Read",
        tool_type=ToolType.READ,
        success=True,
        file_path=f"f{i}.py",
    )


def _warning(severity: Severity, signal: str = "loop", **details) -> Warning:
    return Warning(
        category=Category.PROGRESS, severity=severity, signal=signal,
        message=f"{signal} warning", details=details,
    )


def _seed(app, name, *, ago=1.0, warnings=(), depth=0, team_id=None, pid=None, stopped=False):
    path = Path(f"{name}.jsonl")
    item = AgentItem(
        path, agent_type="claude-code", project_name=name, pid=pid, depth=depth,
        team_id=team_id,
    )
    if stopped:
        item.process_status = "stopped"
    buffer = ActionBuffer()
    buffer.add(_action(ago))
    registry = create_registry(mode="health")
    registry.check_all = lambda buffer, w=list(warnings): list(w)
    app.agents[path] = app._new_agent_state(
        buffer=buffer, registry=registry, item=item, pid=pid, team_id=team_id,
        log_path=path, agent_type="claude-code",
    )
    if app.selected_path is None:
        app.selected_path = path
    return path


def _order(app) -> list[str]:
    """PROJECT top to bottom; the idle fold row as its "(a to show)" (in
    TOP SIGNAL when there is no AGENT column, under 100 columns)."""
    table = app.query_one("#sessions")
    narrow = "agent" not in table.columns
    return [table.get_cell(key, "signal" if key == "fold" and narrow else "project").plain
            for key in (row.key.value for row in table.ordered_rows)]


def _screen(app) -> str:
    return "\n".join(strip.text for strip in app.screen._compositor.render_strips())


def _write_logs(directory: Path, n: int) -> None:
    base = _now() - timedelta(seconds=30)
    for s in range(n):
        entries = []
        for i in range(3):
            ts = (base + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%SZ")
            entries.append({"type": "assistant", "sessionId": f"s{s}", "timestamp": ts,
                            "message": {"role": "assistant", "content": [
                                {"type": "tool_use", "id": f"t{i}", "name": "Bash",
                                 "input": {"command": f"ls {i}"}}]}})
        (directory / f"session{s}.jsonl").write_text(
            "".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8"
        )


async def _wait(pilot, cond):
    for _ in range(100):
        if cond():
            return
        await pilot.pause(0.05)
    raise AssertionError("condition never met")


def test_ago_units():
    assert [_ago(None), _ago(-3), _ago(3), _ago(240), _ago(7200), _ago(2 * 86400)] == [
        "-", "0s", "3s", "4m", "2h", "2d"
    ]


async def test_one_row_per_session_with_columns(tmp_path):
    _write_logs(tmp_path, 3)
    for size in ((120, 40), (80, 24)):
        app = MultiAgentWatchApp(watch_paths=[tmp_path])
        async with app.run_test(size=size) as pilot:
            table = app.query_one("#sessions")
            await _wait(pilot, lambda: table.row_count == 3)
            await pilot.pause(1.1)
            assert table.row_count == 3
            screen = _screen(app)
            narrow = size[0] == 80  # no AGENT/CTX column, no Selected strip
            for header in HEADERS:
                assert (header in screen) == (not narrow or header not in ("AGENT", "CTX")), (
                    size, header)
            assert ("Selected: session" in screen) == (not narrow)
            assert "sort: attention" in screen


async def test_attention_sort_and_o_cycles():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        _seed(app, "idle", ago=900, warnings=[_warning(Severity.CRITICAL)])
        _seed(app, "quiet", ago=5)
        _seed(app, "medium", ago=2, warnings=[_warning(Severity.MEDIUM)])
        _seed(app, "critical", ago=50, warnings=[_warning(Severity.CRITICAL)])
        _seed(app, "high", ago=1, warnings=[_warning(Severity.HIGH, count=7, tool="Bash")])
        _seed(app, "stopped", ago=1, stopped=True)
        _seed(app, "fresh", ago=1)
        app.refresh_ui()
        assert _order(app) == ["critical", "high", "medium", "fresh", "quiet", "(a to show)"]
        await pilot.press("a")  # idle 15+ min and stopped sessions: folded until `a`
        assert _order(app) == ["critical", "high", "medium", "fresh", "quiet", "stopped", "idle",
                               "(a to fold)"]
        table = app.query_one("#sessions")
        assert table.get_cell("high.jsonl", "signal").plain == "⚠ loop: Bash (7x)"
        assert table.get_cell("fresh.jsonl", "signal").plain == "ok"
        assert table.get_cell("idle.jsonl", "dot").plain == "○"
        assert table.get_cell("fresh.jsonl", "dot").plain == "●"

        await pilot.press("o")
        assert app.sort_mode == "cost" and table.border_subtitle == "sort: cost"
        await pilot.press("o")
        assert app.sort_mode == "recent"
        assert _order(app)[-4:-1] == ["quiet", "critical", "idle"]
        await pilot.press("o")
        assert app.sort_mode == "attention"
        assert _order(app)[0] == "critical"


async def test_cursor_stays_on_session_when_rows_reorder():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        _seed(app, "a", ago=1)
        b = _seed(app, "b", ago=2)
        app.refresh_ui()
        await pilot.pause()
        await pilot.press("down")
        await pilot.pause()
        assert app.selected_path == b and _order(app) == ["a", "b"]

        app.agents[b]["registry"].check_all = lambda buffer: [_warning(Severity.HIGH)]
        app.agents[b]["buffer"].add(_action(2, 1))  # rescored only on new actions
        app.refresh_ui()
        await pilot.pause()
        table = app.query_one("#sessions")
        assert _order(app) == ["b", "a"]
        assert table.cursor_row == 0 and app.selected_path == b
        assert "Selected: b" in str(app.query_one("#selected").render())


async def test_tick_updates_changed_cells_only():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        a = _seed(app, "a", ago=1)
        _seed(app, "b", ago=600)
        app.refresh_ui()
        table = app.query_one("#sessions")
        calls = {"clear": 0, "add_row": 0, "updated": []}
        orig_update = table.update_cell
        table.clear = lambda *a, **k: calls.__setitem__("clear", calls["clear"] + 1)
        table.add_row = lambda *a, **k: calls.__setitem__("add_row", calls["add_row"] + 1)
        table.update_cell = lambda row, col, value, **k: (
            calls["updated"].append((row, col)), orig_update(row, col, value, **k)
        )

        app.refresh_ui()
        assert calls["updated"] == []  # nothing changed
        app.agents[a]["registry"].check_all = lambda buffer: [_warning(Severity.MEDIUM)]
        app.agents[a]["buffer"].add(_action(0, 1))
        app.refresh_ui()
        await pilot.pause()
        assert calls["clear"] == 0 and calls["add_row"] == 0
        assert table.row_count == 2
        rows = {row for row, _ in calls["updated"]}
        assert rows == {"a.jsonl"}
        # the changed row is bold for a moment
        assert "bold" in str(table.get_cell("a.jsonl", "signal").style)
        assert "bold" not in str(table.get_cell("b.jsonl", "signal").style)


def _age_scores(data: dict, seconds: float) -> None:
    data["_hist"] = deque(((t - seconds, *v) for t, *v in data["_hist"]), maxlen=60)


async def test_health_trend_arrow_vs_a_minute_ago():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)):
        _seed(app, "sel", ago=1)  # selected; "a" is not, so it is only rescored on new actions
        a = _seed(app, "a", ago=1)
        data = app.agents[a]
        app.refresh_ui()
        table = app.query_one("#sessions")
        health = lambda: table.get_cell("a.jsonl", "health").plain  # noqa: E731

        def change(severity, i):
            data["registry"].check_all = lambda buffer: [_warning(severity)]
            data["buffer"].add(_action(0, i))
            app.refresh_ui()

        # a drop while the session settles (history loading) is the reference
        change(Severity.MEDIUM, 1)
        _age_scores(data, 10)
        change(Severity.CRITICAL, 2)
        assert health().endswith("%")  # nothing until a minute of history
        _age_scores(data, 51)
        app.refresh_ui()
        assert health().endswith("▼")  # vs the score 60s ago
        _age_scores(data, 5)
        app.refresh_ui()
        assert health().endswith("▼")  # stays while it holds
        _age_scores(data, 5)
        app.refresh_ui()  # no rescore: the arrow clears from the kept scores
        assert health().endswith("%")
        change(Severity.MEDIUM, 3)
        assert health().endswith("▲")


async def test_stopped_rows_are_grey_and_idle_rows_are_not():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)):
        _seed(app, "stopped", ago=1, stopped=True)
        _seed(app, "idle", ago=900)
        app._show_idle = True
        app.refresh_ui()
        table = app.query_one("#sessions")
        assert str(table.get_cell("stopped.jsonl", "project").style) == STOPPED_STYLE
        assert str(table.get_cell("stopped.jsonl", "dot").style) == STOPPED_STYLE
        assert str(table.get_cell("idle.jsonl", "project").style) == ""
        assert table.get_cell("idle.jsonl", "dot").plain == "○"


def test_team_score_zero_is_not_healthy():
    app = MultiAgentWatchApp()
    team = SimpleNamespace(team_id=1, name="t", member_count=2, subagent_count=0)
    theme = get_theme()
    app._team_scores[1] = 0
    assert app._team_cells(team)["health"] == (
        "0%", "bold " + theme.color_for(theme.status_from_score(0))
    )


async def test_agent_column_shows_display_names():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)):
        a = _seed(app, "a", ago=1)
        b = _seed(app, "b", ago=1)
        app.agents[b]["item"].agent_type = "opencode"
        c = _seed(app, "c", ago=1)
        app.agents[c]["item"].agent_type = None
        app.agents[c]["agent_name"] = "kilo-code"
        app.refresh_ui()
        table = app.query_one("#sessions")
        assert [table.get_cell(str(p), "agent").plain for p in (a, b, c)] == [
            "Claude Code", "OpenCode", "Kilo Code"
        ]


async def test_subagent_rows_sit_under_parent():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)):
        _seed(app, "other", ago=1, warnings=[_warning(Severity.HIGH)])
        _seed(app, "child", ago=1, depth=1, team_id=10, pid=11,
              warnings=[_warning(Severity.CRITICAL)])
        _seed(app, "root", ago=1, team_id=10, pid=10)
        app.refresh_ui()
        assert _order(app) == ["root", "child", "other"]
        cell = app.query_one("#sessions").get_cell("child.jsonl", "agent").plain
        assert cell.startswith("└ sub")


async def test_signal_and_project_render_literally():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        _seed(app, "p[/]", ago=1, warnings=[_warning(Severity.HIGH, tool="[b]Bash[/b]")])
        app.refresh_ui()
        await pilot.pause()
        screen = _screen(app)
        assert "p[/]" in screen and "loop: [b]Bash[/b]" in screen


async def test_keys_q_s_o_and_no_clear_cache():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        keys = {b[0] if isinstance(b, tuple) else b.key for b in app.BINDINGS}
        assert keys == {"q", "s", "o", "e", "a", "slash", "escape", "enter", "question_mark",
                        "d", "w"}
        assert not hasattr(app, "action_clear_cache")
        await pilot.pause()
        screen = _screen(app)
        assert "Security" in screen and "Sort" in screen and "Clear Cache" not in screen


async def test_refresh_after_screens_are_gone_is_a_no_op():
    """A RowHighlighted or tick queued during shutdown must not raise."""
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)):
        _seed(app, "a", ago=1)
    assert not app.screen_stack
    app.refresh_ui()
