"""watch-all loop-breaker blocks, budget column and the `s` summary line
(Sprint 36, PR 5)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from test_multi_app_detail import _open, _shows
from test_multi_app_feed import _end_baselines, _feed, _header
from test_multi_app_table import _order, _screen, _seed, _warning

import agentwatch.ui.multi_app as multi_app
from agentwatch.alerts import Alerter
from agentwatch.detectors.base import Category, Severity, Warning
from agentwatch.ui.multi_app import MultiAgentWatchApp

SIZES = ((120, 40), (80, 24))


@pytest.fixture(autouse=True)
def state(tmp_path, monkeypatch):
    """Coach state dir for the app; reads are not throttled in tests."""
    directory = tmp_path / "coach"
    directory.mkdir()
    monkeypatch.setattr(multi_app, "state_dirs", lambda: [directory])
    monkeypatch.setattr(multi_app, "COACH_EVERY_S", 0.0)
    monkeypatch.delenv("AGENTWATCH_LOOP_BREAKER", raising=False)
    return directory


def _write(directory: Path, key: str, blocked: bool, loop_id="abc123", count=6, cost=1.4,
           mtime: float | None = None) -> None:
    path = directory / f"{key}.json"
    armed = {"loop_id": loop_id, "count": count, "blocked": blocked, "cost_usd": cost}
    path.write_text(json.dumps({"reported": [], "warnings": [], "armed": armed}))
    if mtime is not None:
        os.utime(path, (mtime, mtime))


def _signal(app, name: str) -> str:
    table = app.query_one("#sessions")
    return table.get_cell(f"{name}.jsonl", "signal").plain


@pytest.mark.parametrize("size", SIZES)
async def test_armed_then_blocked_is_signal_one_feed_line_header_and_sort(state, size):
    app = MultiAgentWatchApp()
    async with app.run_test(size=size) as pilot:
        _seed(app, "calm", ago=1)
        _seed(app, "high", ago=1, warnings=[_warning(Severity.HIGH)])
        loop = _warning(Severity.HIGH, tool="Bash", count=7, loop_id="abc123")
        _seed(app, "loopy", ago=2, warnings=[loop])
        _write(state, "loopy", blocked=False)
        app.refresh_ui()
        _end_baselines(app)
        app.refresh_ui()
        assert _feed(app) == ["3 sessions loaded"]
        assert _signal(app, "loopy").startswith("⚠ loop: Bash (7x)")
        assert "blocks 0" in _header(app)

        _write(state, "loopy", blocked=True, mtime=os.path.getmtime(state / "loopy.json") + 1)
        app.refresh_ui()
        app.refresh_ui()
        assert _feed(app)[0] == "⛔ loopy loop breaker blocked a repeated call (~$1.40)"
        assert len(_feed(app)) == 2
        assert _signal(app, "loopy") == "⛔ loop blocked: Bash (7x) $1.40"
        assert _order(app)[0] == "loopy"  # ranks with Critical, above the HIGH session
        assert "blocks 1" in _header(app) and "1 need you" not in _header(app)
        await pilot.pause()
        screen = _screen(app)
        assert "⛔ loop" in screen and "blocks 1" in screen
        print(f"\n--- {size[0]}x{size[1]} blocked ---\n{screen}")


async def test_blocked_without_a_loop_warning_uses_the_state_count(state):
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)):
        _seed(app, "s", ago=1)
        _write(state, "s", blocked=True, count=6, cost="x")  # bad cost: not shown
        app.refresh_ui()
        assert _signal(app, "s") == "⛔ loop blocked (6x)"


async def test_already_blocked_at_startup_is_counted_in_the_summary(state):
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)):
        for i in range(5):
            _seed(app, f"s{i}", ago=1)
            _write(state, f"s{i}", blocked=i < 3, loop_id=f"l{i}")
        app.refresh_ui()
        assert _feed(app) == []
        app._loaded_until = 0.0
        app.refresh_ui()
        assert _feed(app) == ["5 sessions loaded; 3 loop blocks so far"]
        assert "blocks 3" in _header(app)


async def test_state_is_read_only_when_its_mtime_changes(state, monkeypatch):
    reads = []
    real = Path.read_text
    monkeypatch.setattr(Path, "read_text", lambda self, *a, **k: (
        reads.append(self.name), real(self, *a, **k))[1])
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)):
        _seed(app, "s", ago=1)
        _write(state, "s", blocked=False, mtime=1_000_000)
        for _ in range(5):
            app.refresh_ui()
        assert reads.count("s.json") == 1
        _write(state, "s", blocked=True, mtime=1_000_001)
        for _ in range(5):
            app.refresh_ui()
        assert reads.count("s.json") == 2


async def test_missing_and_corrupt_state_files_are_ignored(state):
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)):
        _seed(app, "missing", ago=1)
        _seed(app, "corrupt", ago=1)
        _seed(app, "notdict", ago=1)
        _seed(app, "armedlist", ago=1)
        (state / "corrupt.json").write_text("{not json")
        (state / "notdict.json").write_text("[1, 2]")
        (state / "armedlist.json").write_text('{"armed": [true]}')
        app.refresh_ui()
        app._loaded_until = 0.0
        app.refresh_ui()
        assert _feed(app) == ["4 sessions loaded"]
        assert "blocks 0" in _header(app)


@pytest.mark.parametrize(("body", "signal"), [
    (b'{"armed": {"blocked": "true", "loop_id": "x"}}', "ok"),  # not a bool: not blocked
    (b'{"armed": {"blocked": true, "loop_id": ["a"], "count": "9", "cost_usd": 1e308}}',
     "\u26d4 loop blocked"),
    (b'{"armed": {"blocked": true, "loop_id": {"a": 1}, "count": true, "cost_usd": NaN}}',
     "\u26d4 loop blocked"),
    (b'{"armed": null}', "ok"), (b'""', "ok"), (b"null", "ok"), (b"\x00\xff", "ok"), (b"", "ok"),
])
async def test_odd_state_files_never_crash(state, body, signal):
    """QA #161: odd values show no count or cost, never raise."""
    app = MultiAgentWatchApp()
    async with app.run_test(size=(80, 24)) as pilot:
        _seed(app, "w", ago=1)
        _end_baselines(app)
        (state / "w.json").write_bytes(body)
        app.refresh_ui()
        await pilot.pause()
        assert app.is_running and _signal(app, "w") == signal
        assert f"blocks {int(signal != 'ok')}" in _header(app)


async def test_markup_project_reblock_and_deleted_state(state):
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        path = _seed(app, "m", ago=1)
        app.agents[path]["item"].project_name = "[b]x[/b][@click=app.quit]"
        _end_baselines(app)
        now = time.time()
        for blocked, mtime in ((True, now - 10), (False, now - 5), (True, now)):
            _write(state, "m", blocked=blocked, loop_id="L1", mtime=mtime)
            app.refresh_ui()
            await pilot.pause()
        assert _feed(app)[0].startswith("\u26d4 [b]x[/b][@click=app.quit] loop breaker blocked")
        os.unlink(state / "m.json")
        app.refresh_ui()
        await pilot.pause()
        assert app.is_running and _signal(app, "m") == "ok"


async def test_other_agents_are_not_read(state):
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)):
        path = _seed(app, "aider", ago=1)
        app.agents[path]["item"].agent_type = "aider"
        _write(state, "aider", blocked=True)
        app.refresh_ui()
        assert "blocks 0" in _header(app)


def test_subagent_log_uses_the_coach_key():
    app = MultiAgentWatchApp()
    path = Path("proj/sess-1/subagents/agent-a1b2.jsonl")
    data = {"item": multi_app.AgentItem(path, agent_type="claude-code"),
            "buffer": multi_app.ActionBuffer()}
    assert app._coach_key(data) == "sess-1.a1b2"


@pytest.mark.parametrize("env, expected", [
    (None, "Loop breaker: blocked once"),
    ("off", "Loop breaker: off in this shell (AGENTWATCH_LOOP_BREAKER=off)"),
])
async def test_detail_health_tab_loop_breaker_line(state, monkeypatch, env, expected):
    if env:
        monkeypatch.setenv("AGENTWATCH_LOOP_BREAKER", env)
    _write(state, "a", blocked=True)
    _write(state, "b", blocked=False, count=7)
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await _open(app, pilot, "a", "b")
        await _shows(pilot, app, expected)
        await pilot.press("escape")
        await pilot.press("down", "enter")
        if not env:
            await _shows(pilot, app, "Loop breaker: armed (7x)")


@pytest.mark.parametrize("cost, text, style", [
    (2.5, "$2.50 / $5.00 ▮▮▯▯", ""),
    (4.25, "$4.25 / $5.00 ▮▮▮▯", "yellow"),
    (5.0, "$5.00 / $5.00 ▮▮▮▮", "bold red"),
    (None, "n/a", ""),
])
def test_budget_cell(cost, text, style):
    assert multi_app._budget_cell(cost, 5.0) == (text, style)
    narrow = text.replace(" / $5.00", "")
    assert multi_app._budget_cell(cost, 5.0, narrow=True) == (narrow, style)


@pytest.mark.parametrize("size", SIZES)
async def test_budget_column_and_header(size):
    app = MultiAgentWatchApp(alerter=Alerter(budget=5.0))
    async with app.run_test(size=size) as pilot:
        for name, cost in (("half", 2.5), ("most", 4.25), ("over", 7.0), ("free", None)):
            path = _seed(app, name, ago=1)
            stats = app.agents[path]["buffer"].stats
            if cost is None:
                stats.unpriced, stats.billed_tokens = 1, 0
            else:
                stats.total_cost = cost
        app.refresh_ui()
        await pilot.pause()
        table = app.query_one("#sessions")
        cells = {n: table.get_cell(f"{n}.jsonl", "cost") for n in ("half", "most", "over")}
        limit = " / $5.00" if size[0] == 120 else ""  # narrow: the header has the budget
        assert cells["half"].plain == f"$2.50{limit} ▮▮▯▯"
        assert cells["most"].plain == f"$4.25{limit} ▮▮▮▯" and "yellow" in str(cells["most"].style)
        assert cells["over"].plain == f"$7.00{limit} ▮▮▮▮" and "red" in str(cells["over"].style)
        screen = _screen(app)
        label = "COST / BUDGET" if size[0] == 120 else "COST/BUDGT"
        assert label in screen and "budget $5.00/session" in _header(app)
        if size[0] == 80:
            assert "spent $13.75" in _header(app)
        print(f"\n--- {size[0]}x{size[1]} budget ---\n{screen}")


async def test_budget_column_follows_a_resize_across_100_columns():
    """QA #161: the COST / BUDGET column form is not fixed at startup."""
    app = MultiAgentWatchApp(alerter=Alerter(budget=5.0))
    async with app.run_test(size=(120, 40)) as pilot:
        stats = app.agents[_seed(app, "a", ago=1)]["buffer"].stats
        stats.total_cost = 2.5
        app.refresh_ui()
        table = app.query_one("#sessions")
        for width, label, cell in ((80, "COST/BUDGT", "$2.50 ▮▮▯▯"),
                                   (100, "COST / BUDGET", "$2.50 / $5.00 ▮▮▯▯"),
                                   (99, "COST/BUDGT", "$2.50 ▮▮▯▯")):
            await pilot.resize_terminal(width, 30)
            await pilot.pause()
            assert table.get_cell("a.jsonl", "cost").plain == cell
            assert label in _screen(app) and "TOP SIGNAL" in _screen(app), width


async def test_no_budget_keeps_the_plain_cost_column():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        path = _seed(app, "a", ago=1)
        app.agents[path]["buffer"].stats.total_cost = 2.5
        app.refresh_ui()
        await pilot.pause()
        assert "COST / BUDGET" not in _screen(app) and "budget" not in _header(app)
        assert app.query_one("#sessions").get_cell("a.jsonl", "cost").plain == "$2.50"


async def test_s_toggle_counts_findings_and_off_is_one_line(monkeypatch):
    secret = Warning(category=Category.CREDENTIAL, severity=Severity.CRITICAL,
                     signal="secret_leak", message="secret")
    real = multi_app.create_registry

    def registry(mode):
        reg = real(mode=mode)
        reg.check_all = (lambda buffer: [secret]) if mode == "all" else (lambda buffer: [])
        return reg

    monkeypatch.setattr(multi_app, "create_registry", registry)
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        for i in range(3):
            _seed(app, f"s{i}", ago=1)
        app.refresh_ui()
        _end_baselines(app)
        app.refresh_ui()
        start = _feed(app)
        await pilot.press("s")
        assert _feed(app) == ["security on: 3 findings", *start]
        await pilot.press("s")
        assert _feed(app) == ["security off", "security on: 3 findings", *start]


async def test_real_hook_block_shows_in_watch_all(tmp_path, monkeypatch):
    """End to end: the real `agentwatch hook` arms and blocks a loop in a
    synthetic transcript (CLAUDE_PLUGIN_DATA in a temp dir); watch-all shows it."""
    from test_loop_breaker import CMD, _transcript

    monkeypatch.undo()  # this test reads the real coach dirs, from the env below
    env = {**os.environ, "CLAUDE_PLUGIN_DATA": str(tmp_path / "plugin"),
           "XDG_CACHE_HOME": str(tmp_path / "cache")}
    env.pop("AGENTWATCH_LOOP_BREAKER", None)
    t = _transcript(tmp_path, [("Bash", {"command": CMD})] * 6, name="sess-1.jsonl")

    def hook(event: str, tool_use_id: str) -> str:
        payload = {"session_id": "sess-1", "transcript_path": str(t), "hook_event_name": event,
                   "tool_name": "Bash", "tool_input": {"command": CMD},
                   "tool_use_id": tool_use_id}
        return subprocess.run(
            [sys.executable, "-c", "from agentwatch._entry import main; main()", "hook"],
            input=json.dumps(payload), capture_output=True, text=True, env=env, check=True,
        ).stdout

    hook("PostToolUse", "t5")
    assert "deny" in hook("PreToolUse", "tnext")
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", env["CLAUDE_PLUGIN_DATA"])
    monkeypatch.setenv("XDG_CACHE_HOME", env["XDG_CACHE_HOME"])
    monkeypatch.delenv("AGENTWATCH_LOOP_BREAKER", raising=False)

    app = MultiAgentWatchApp(watch_paths=[t])
    async with app.run_test(size=(120, 40)) as pilot:
        for _ in range(100):
            await pilot.pause(0.05)
            if app._blocks:
                break
        app._loaded_until = 0.0
        app.refresh_ui()
        await pilot.pause()
        assert _feed(app)[0] == "1 session loaded; 1 loop block so far"
        await pilot.press("a")  # the transcript's actions are old: folded as idle
        assert "⛔ loop blocked: Bash (6x)" in _screen(app)
