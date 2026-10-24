"""The watch-all sessions table (Sprint 36, PR 2): one row per session,
attention sort, `o` cycles the sort, the cursor follows its session, and a
tick updates only changed cells (the table is never cleared)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agentwatch.detectors import create_registry
from agentwatch.detectors.base import Category, Severity, Warning
from agentwatch.parser.models import Action, ActionBuffer, ToolType
from agentwatch.ui.multi_app import AgentItem, MultiAgentWatchApp, _ago

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
    table = app.query_one("#sessions")
    return [table.get_cell_at((i, 2)).plain for i in range(table.row_count)]


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
            for header in HEADERS[: 4 if size[0] == 80 else None]:
                assert header in screen, (size, header)
            assert "Selected: session" in screen
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
        assert _order(app) == ["critical", "high", "medium", "fresh", "quiet", "stopped", "idle"]
        table = app.query_one("#sessions")
        assert table.get_cell("high.jsonl", "signal").plain == "⚠ loop: Bash (7x)"
        assert table.get_cell("fresh.jsonl", "signal").plain == "ok"
        assert table.get_cell("idle.jsonl", "dot").plain == "○"
        assert table.get_cell("fresh.jsonl", "dot").plain == "●"

        await pilot.press("o")
        assert app.sort_mode == "cost" and table.border_subtitle == "sort: cost"
        await pilot.press("o")
        assert app.sort_mode == "recent"
        assert _order(app)[-3:] == ["quiet", "critical", "idle"]
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
        _seed(app, "b", ago=3600)
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


async def test_health_trend_arrow():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)):
        a = _seed(app, "a", ago=1)
        app.refresh_ui()
        table = app.query_one("#sessions")
        assert table.get_cell("a.jsonl", "health").plain.endswith("%")
        app.agents[a]["registry"].check_all = lambda buffer: [_warning(Severity.CRITICAL)]
        app.refresh_ui()
        assert table.get_cell("a.jsonl", "health").plain.endswith("▼")


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
        assert keys == {"q", "s", "o"}
        assert not hasattr(app, "action_clear_cache")
        await pilot.pause()
        screen = _screen(app)
        assert "Toggle Security" in screen and "Sort" in screen and "Clear Cache" not in screen
