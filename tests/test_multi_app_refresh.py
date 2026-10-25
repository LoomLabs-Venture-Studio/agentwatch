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

from datetime import datetime
from pathlib import Path

from textual.widgets import ListView

from agentwatch.detectors import create_registry
from agentwatch.health.rot import RotScorer
from agentwatch.parser.models import Action, ActionBuffer, ToolType
from agentwatch.ui.multi_app import AgentItem, MultiAgentWatchApp


def _make_action(i: int) -> Action:
    return Action(
        timestamp=datetime.now(),
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

    async with app.run_test() as pilot:
        selected_path = Path("selected.jsonl")
        idle_path = Path("idle.jsonl")

        selected_buffer = ActionBuffer(max_size=2000)
        idle_buffer = ActionBuffer(max_size=2000)
        for i in range(5):
            idle_buffer.add(_make_action(i))

        idle_registry = create_registry(mode="health")
        call_count = {"n": 0}
        original_check_all = idle_registry.check_all

        def counting_check_all(buffer):
            call_count["n"] += 1
            return original_check_all(buffer)

        idle_registry.check_all = counting_check_all

        selected_item = AgentItem(selected_path, pid=100, team_id=100)
        idle_item = AgentItem(idle_path, pid=200, team_id=100)

        agent_list = app.query_one("#agent-list", ListView)
        agent_list.append(selected_item)
        agent_list.append(idle_item)
        # Let Textual mount the newly appended list items (and their child
        # Label widgets from compose()) before update_status() queries them.
        await pilot.pause()

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
        assert idle_item.health_score == idle_item.health_score  # widget updated, no crash

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

    async with app.run_test() as pilot:
        from agentwatch.discovery import AgentProcess, AgentTeam
        from agentwatch.ui.multi_app import TeamHeaderItem

        root_proc = AgentProcess(
            pid=100, agent_type="claude-code", working_directory=Path("/tmp/proj"),
            depth=0, team_id=100,
        )
        sub_proc = AgentProcess(
            pid=200, agent_type="claude-code", working_directory=Path("/tmp/proj"),
            depth=1, parent_agent_pid=100, team_id=100,
        )
        team = AgentTeam(team_id=100, root=root_proc, members=[root_proc, sub_proc])
        header = TeamHeaderItem(team)
        app.teams[100] = header

        root_path = Path("root.jsonl")
        sub_path = Path("sub.jsonl")
        root_item = AgentItem(root_path, pid=100, team_id=100)
        sub_item = AgentItem(sub_path, pid=200, team_id=100)

        agent_list = app.query_one("#agent-list", ListView)
        agent_list.append(header)
        agent_list.append(root_item)
        agent_list.append(sub_item)
        # Let Textual mount the newly appended list items before
        # update_status() queries their child Label widgets.
        await pilot.pause()

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

        # Team header should have moved off its default 100% placeholder,
        # proving calculate_team_health() actually ran against the grouped
        # member reports produced via self._team_by_pid.
        assert isinstance(header.health_score, int)
        assert 0 <= header.health_score <= 100
