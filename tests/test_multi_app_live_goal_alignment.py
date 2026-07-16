"""Headless Textual pilot tests for the live-TUI Tier-2 goal-alignment
advisory wiring in `MultiAgentWatchApp` (`ui/multi_app.py`), mirroring
`test_app_live_goal_alignment.py`'s single-agent coverage but for the
per-agent structure `test_multi_app_live_wiring.py` already establishes.

Unlike `AgentWatchApp`, `MultiAgentWatchApp.on_mount()` does not call
`refresh_ui()` synchronously (it only starts background workers/interval
timers -- confirmed by reading `on_mount()` directly), so there's no
mount-time "free tick" to rewind here the way the single-agent tests must.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from textual.widgets import ListView

from agentwatch.parser.models import Action, ActionBuffer, ToolType
from agentwatch.ui.app import WarningsList
from agentwatch.ui.live_integrations import LLM_ASSESSMENT_INTERVAL_SECONDS
from agentwatch.ui.multi_app import AgentItem, MultiAgentWatchApp


def _make_action(i: int, incoming_message: str | None = None) -> Action:
    return Action(
        timestamp=datetime.now(),
        tool_name="Read",
        tool_type=ToolType.READ,
        success=True,
        file_path=f"file_{i}.py",
        incoming_message=incoming_message,
    )


class _FakeOllamaClient:
    def __init__(self, list_raises=None):
        self._list_raises = list_raises
        self.chat_call_count = 0

    def __call__(self, host=None):
        return self

    def list(self):
        if self._list_raises is not None:
            raise self._list_raises
        return SimpleNamespace(models=[SimpleNamespace(model="llama3.2:latest")])

    def chat(self, **kwargs):
        self.chat_call_count += 1
        return SimpleNamespace(
            message=SimpleNamespace(
                content='{"aligned": true, "confidence": "medium", '
                '"drift_summary": "Still working the stated task."}'
            )
        )


async def _seed_agent(app: MultiAgentWatchApp, pilot, path: Path, pid: int) -> None:
    from agentwatch.detectors import create_registry

    buffer = ActionBuffer(max_size=2000)
    item = AgentItem(path, pid=pid, team_id=pid)
    agent_list = app.query_one("#agent-list", ListView)
    agent_list.append(item)
    await pilot.pause()

    app.agents[path] = app._new_agent_state(
        buffer=buffer,
        registry=create_registry(mode="all"),
        item=item,
        pid=pid,
        team_id=pid,
        log_path=path,
        agent_type="claude-code",
    )
    app.selected_path = path


class TestPerAgentGoalAlignmentThrottle:
    async def test_goal_alignment_dispatched_once_per_interval_not_every_tick(
        self, tmp_path, monkeypatch
    ):
        import agentwatch.ui.live_integrations as live_mod

        clock = {"t": 0.0}
        monkeypatch.setattr(live_mod, "_monotonic", lambda: clock["t"])
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: _FakeOllamaClient())

        app = MultiAgentWatchApp(watch_paths=[], security_mode=False, llm=True)

        async with app.run_test() as pilot:
            path = Path("agent.jsonl")
            await _seed_agent(app, pilot, path, pid=100)

            call_count = {"n": 0}

            async def fake_run_goal_alignment_batch(assessor, buffer, agent_label):
                call_count["n"] += 1

            app._run_goal_alignment_batch = fake_run_goal_alignment_batch
            app.agents[path]["buffer"].add(_make_action(0, incoming_message="Fix the bug"))

            app.refresh_ui()
            assert call_count["n"] == 0  # dispatched via worker, not inline
            await pilot.pause()
            assert call_count["n"] == 1

            clock["t"] += 5
            app.refresh_ui()
            await pilot.pause()
            assert call_count["n"] == 1  # still within the throttle window

            clock["t"] += LLM_ASSESSMENT_INTERVAL_SECONDS
            app.refresh_ui()
            await pilot.pause()
            assert call_count["n"] == 2

    async def test_two_agents_have_independent_throttle_state(self, tmp_path, monkeypatch):
        """Each tracked agent gets its own `LiveLlmAssessor` instance
        (`_new_agent_state`) with its own `_last_goal_run` clock -- mutating
        one must never mutate the other. (`refresh_ui()` itself processes
        every changed agent in one tick via the "other agents" loop in
        `_do_refresh_ui`, not just the selected one -- see that method --
        so this asserts object-level state independence directly rather
        than dispatch timing, which the shared render tick would conflate.)
        """
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: _FakeOllamaClient())

        app = MultiAgentWatchApp(watch_paths=[], security_mode=False, llm=True)

        async with app.run_test() as pilot:
            path_a = Path("agent_a.jsonl")
            path_b = Path("agent_b.jsonl")
            await _seed_agent(app, pilot, path_a, pid=100)
            await _seed_agent(app, pilot, path_b, pid=200)

            assessor_a = app.agents[path_a]["llm_assessor"]
            assessor_b = app.agents[path_b]["llm_assessor"]
            assert assessor_a is not assessor_b

            assessor_a.mark_goal_run(now=12345.0)
            assert assessor_b._last_goal_run != 12345.0
            assert assessor_b.goal_alignment_due(now=0.0) is True  # untouched, still due


class TestPerAgentGoalAlignmentNoStatedTask:
    async def test_no_stated_task_shows_no_advisory_for_selected_agent(
        self, tmp_path, monkeypatch
    ):
        fake = _FakeOllamaClient()
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: fake)

        app = MultiAgentWatchApp(watch_paths=[], security_mode=False, llm=True)

        async with app.run_test() as pilot:
            path = Path("agent.jsonl")
            await _seed_agent(app, pilot, path, pid=100)
            app.agents[path]["buffer"].add(_make_action(0, incoming_message=None))

            app.refresh_ui()
            await pilot.pause()
            app.refresh_ui()
            await pilot.pause()

            assert fake.chat_call_count == 0
            warnings_widget = app.query_one("#warnings-list", WarningsList)
            rendered = warnings_widget._build_content()
            assert "GOAL ALIGNMENT" not in rendered


class TestPerAgentGoalAlignmentNonBlocking:
    async def test_runs_off_render_path_via_worker(self, tmp_path, monkeypatch):
        fake = _FakeOllamaClient()
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: fake)

        app = MultiAgentWatchApp(watch_paths=[], security_mode=False, llm=True)

        async with app.run_test() as pilot:
            path = Path("agent.jsonl")
            await _seed_agent(app, pilot, path, pid=100)
            app.agents[path]["buffer"].add(_make_action(0, incoming_message="Fix the bug"))

            app.refresh_ui()  # must return immediately, not block on Ollama
            assert fake.chat_call_count == 0
            await pilot.pause()
            assert fake.chat_call_count == 1

            app.refresh_ui()
            warnings_widget = app.query_one("#warnings-list", WarningsList)
            rendered = warnings_widget._build_content()
            assert "TIER-2 GOAL ALIGNMENT (advisory, not scored)" in rendered
            assert "[ALIGNED]" in rendered
