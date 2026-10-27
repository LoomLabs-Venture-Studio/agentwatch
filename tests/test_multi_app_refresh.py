"""Headless Textual pilot test for MultiAgentWatchApp's per-tick refresh.

Added alongside the fix that (a) added action-count-based change detection
so an idle agent's buffer isn't fully re-scanned by all detectors on every
1s refresh tick, and (b) replaced the O(T*N) team-aggregation linear scan
with a precomputed pid -> team_id map. Drives the real app via Textual's
headless pilot (``App.run_test()``) and manually seeds agent state the way
``_watch_loop``/``_refresh_processes`` would, so it exercises the actual
``refresh_ui()`` / ``_do_refresh_ui()`` path end to end rather than mocking
it away.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from test_multi_app_table import _now, _seed

from agentwatch.detectors import create_registry
from agentwatch.health.rot import RotScorer
from agentwatch.parser.models import Action, ActionBuffer, ToolType
from agentwatch.ui.multi_app import AgentItem, MultiAgentWatchApp


def _make_action(i: int) -> Action:
    return Action(
        timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
        tool_name="Read",
        tool_type=ToolType.READ,
        success=True,
        file_path=f"file_{i}.py",
    )


async def test_idle_agent_skips_recompute_until_buffer_changes():
    """An agent whose buffer hasn't grown since the last tick should reuse
    its cached report instead of paying for another full detector/efficiency
    /rot pass — but must still recompute the moment new actions arrive."""
    app = MultiAgentWatchApp(watch_paths=[], security_mode=False)

    async with app.run_test():
        selected_path = Path("selected.jsonl")
        idle_path = Path("idle.jsonl")

        selected_buffer = ActionBuffer(max_size=2000)
        idle_buffer = ActionBuffer(max_size=2000)
        for i in range(5):
            idle_buffer.add(_make_action(i))

        idle_registry = create_registry(mode="health")
        call_count = {"n": 0}
        original_check_all = idle_registry.check_health

        def counting_check_all(buffer):
            call_count["n"] += 1
            return original_check_all(buffer)

        idle_registry.check_health = counting_check_all

        selected_item = AgentItem(selected_path, pid=100, team_id=100)
        idle_item = AgentItem(idle_path, pid=200, team_id=100)

        app.agents[selected_path] = {
            "buffer": selected_buffer,
            "registry": create_registry(mode="health"),
            "item": selected_item,
            "rot_scorer": RotScorer(),
            "pid": 100,
            "team_id": 100,
            "_last_count": -1,
            "_last_report": None,
        }
        app.agents[idle_path] = {
            "buffer": idle_buffer,
            "registry": idle_registry,
            "item": idle_item,
            "rot_scorer": RotScorer(),
            "pid": 200,
            "team_id": 100,
            "_last_count": -1,
            "_last_report": None,
        }
        app._team_by_pid[100] = 100
        app._team_by_pid[200] = 100
        app.selected_path = selected_path

        # First tick: idle agent has never been scored -> must recompute once.
        app.refresh_ui()
        assert call_count["n"] == 1
        assert app.query_one("#sessions").row_count == 2

        # Second and third ticks: idle agent's buffer hasn't changed -> the
        # cached report is reused, no additional detector run.
        app.refresh_ui()
        app.refresh_ui()
        assert call_count["n"] == 1

        # New actions arrive for the idle agent -> next tick must recompute.
        idle_buffer.add(_make_action(99))
        app.refresh_ui()
        assert call_count["n"] == 2


async def test_team_header_updates_from_grouped_reports():
    """Team health headers should reflect member reports via the
    precomputed pid -> team_id map (replacing the old O(T*N) linear scan)."""
    app = MultiAgentWatchApp(watch_paths=[], security_mode=False)

    async with app.run_test():
        from agentwatch.discovery import AgentProcess, AgentTeam

        root_proc = AgentProcess(
            pid=100, agent_type="claude-code", working_directory=Path("/tmp/proj"),
            depth=0, team_id=100,
        )
        sub_proc = AgentProcess(
            pid=200, agent_type="claude-code", working_directory=Path("/tmp/proj"),
            depth=1, parent_agent_pid=100, team_id=100,
        )
        team = AgentTeam(team_id=100, root=root_proc, members=[root_proc, sub_proc])
        app.teams[100] = team

        root_path = Path("root.jsonl")
        sub_path = Path("sub.jsonl")
        root_item = AgentItem(root_path, pid=100, team_id=100)
        sub_item = AgentItem(sub_path, pid=200, team_id=100)

        root_buffer = ActionBuffer(max_size=2000)
        sub_buffer = ActionBuffer(max_size=2000)
        for i in range(5):
            root_buffer.add(_make_action(i))
            sub_buffer.add(_make_action(i))

        app.agents[root_path] = {
            "buffer": root_buffer,
            "registry": create_registry(mode="health"),
            "item": root_item,
            "rot_scorer": RotScorer(),
            "pid": 100,
            "team_id": 100,
            "_last_count": -1,
            "_last_report": None,
        }
        app.agents[sub_path] = {
            "buffer": sub_buffer,
            "registry": create_registry(mode="health"),
            "item": sub_item,
            "rot_scorer": RotScorer(),
            "pid": 200,
            "team_id": 100,
            "_last_count": -1,
            "_last_report": None,
        }
        app._team_by_pid[100] = 100
        app._team_by_pid[200] = 100
        app.selected_path = root_path

        app.refresh_ui()

        # calculate_team_health() ran against the grouped member reports
        # produced via self._team_by_pid, and the team header row shows it.
        score = app._team_scores[100]
        assert 0 <= score <= 100
        table = app.query_one("#sessions")
        assert table.get_row_index("team:100") == 0
        assert table.get_cell("team:100", "health").plain == f"{score}%"


# -- Sprint 36 PR 4: `s` rescores every session; no rescoring without new actions


def _real_session(app, name: str, actions: list[Action]) -> Path:
    path = _seed(app, name)
    buffer = ActionBuffer()
    for a in actions:
        buffer.add(a)
    data = app.agents[path]
    data["buffer"] = buffer
    data["registry"] = create_registry(mode="all" if app.security_mode else "health")
    return path


def _read(file_path: str) -> Action:
    return Action(timestamp=_now(), tool_name="Read", tool_type=ToolType.READ, success=True,
                  file_path=file_path)


async def test_s_rescores_unselected_idle_sessions_on_next_tick():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        _real_session(app, "selected", [_read("a.py")])
        idle = _real_session(app, "idle", [_read("notes.txt")] * 3 + [_read(".env")])
        app.refresh_ui()
        await pilot.pause()
        assert app.selected_path != idle
        before = app.agents[idle]["_last_report"]
        assert not before.security_warnings

        await pilot.press("s")
        await pilot.pause()
        after = app.agents[idle]["_last_report"]
        assert after is not before and after.security_warnings
        app.refresh_ui()  # and the next tick reuses the new report
        assert app.agents[idle]["_last_report"] is after


async def test_selected_session_is_not_refed_to_rotscorer_without_new_actions():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        actions = [_read(f"f{i % 2}.py") for i in range(30)]  # repetitive: rot > 0
        path = _real_session(app, "selected", actions)
        data = app.agents[path]
        scorer = data["rot_scorer"]
        calls = []
        original = scorer.update
        scorer.update = lambda buffer: (calls.append(1), original(buffer))[1]
        app.refresh_ui()
        await pilot.pause()
        assert app.selected_path == path and calls == [1]
        rot, score = data["_rot"].smoothed_score, data["_last_report"].overall_score
        state = scorer._state

        for _ in range(5):
            app.refresh_ui()
            await pilot.pause()
        assert calls == [1]
        assert data["_rot"].smoothed_score == rot and scorer._state == state
        assert data["_last_report"].overall_score == score

        await pilot.press("s")  # rescores (new registry) but rot is not re-fed
        await pilot.pause()
        assert calls == [1]

        data["buffer"].add(_read("new.py"))
        app.refresh_ui()
        assert calls == [1, 1]
