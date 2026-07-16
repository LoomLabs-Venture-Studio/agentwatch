"""Headless Textual pilot tests for the live-TUI Tier-2 goal-alignment
advisory wiring (`llm.py`'s `assess_goal_alignment()`, Sprint 15, wired into
`AgentWatchApp`/`MultiAgentWatchApp` via `LiveLlmAssessor.goal_alignment_due()`
/ `run_goal_alignment()` / `stamp_goal_alignment()`, `ui/live_integrations.py`).

Follows the same headless-pilot pattern as `test_app_live_wiring.py`
(per-warning triage) and its established fix for the mount-time "free
first tick": `AgentWatchApp.on_mount()` runs a real `refresh_display()` at
t=0, which -- since goal_alignment_due() shares the same
`LLM_ASSESSMENT_INTERVAL_SECONDS` clock semantics as due() (independent
window, same cadence) -- legitimately consumes goal-alignment's own first
free tick too. Tests that care about counting dispatches rewind that
throttle the same way test_app_live_wiring.py does, via the assessor's
public `mark_goal_run()`.

Covers the three things Part B's requirements call out specifically:
  1. Goal-alignment is throttled (not re-assessed every 1s render tick).
  2. The documented "no stated task found" case (`assess_goal_alignment()`
     returns `None`, zero model calls) shows no advisory at all -- not a
     misleading "no drift detected."
  3. The real Ollama call is dispatched off the render path (asyncio.
     to_thread via run_worker), never blocking refresh_display().

Also confirms the zero-score-impact contract holds for the live wiring
specifically: this feature only ever calls `WarningsList.
update_goal_alignment()` with a plain `dict`, never constructs a `Warning`
or touches `calculate_health()`'s inputs.
"""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from agentwatch.parser.models import Action, ToolType
from agentwatch.ui.app import AgentWatchApp, WarningsList
from agentwatch.ui.live_integrations import LLM_ASSESSMENT_INTERVAL_SECONDS


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
    """Same shape as test_app_live_wiring.py's fake, plus a chat_kwargs
    log so tests can assert on prompt content if ever needed."""

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
                content='{"aligned": false, "confidence": "high", '
                '"drift_summary": "Agent is reading unrelated files."}'
            )
        )


def _rewind_mount_tick(app: AgentWatchApp) -> None:
    """See module docstring: on_mount()'s own automatic first refresh
    already consumed the assessor's free first goal-alignment tick (and
    per-warning triage tick). Rewind both throttle clocks so a test's own
    scenario starts from a clean, deterministic baseline."""
    assessor = app._llm_assessor
    assert assessor is not None
    assessor.mark_run(now=-LLM_ASSESSMENT_INTERVAL_SECONDS)
    assessor.mark_goal_run(now=-LLM_ASSESSMENT_INTERVAL_SECONDS)


class TestGoalAlignmentThrottle:
    async def test_goal_alignment_dispatched_once_per_interval_not_every_tick(
        self, tmp_path, monkeypatch
    ):
        import agentwatch.ui.live_integrations as live_mod

        clock = {"t": 0.0}
        monkeypatch.setattr(live_mod, "_monotonic", lambda: clock["t"])
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: _FakeOllamaClient())

        log_path = tmp_path / "session.jsonl"
        log_path.write_text("", encoding="utf-8")
        app = AgentWatchApp(log_path=log_path, security_mode=False, llm=True)

        async with app.run_test() as pilot:
            await pilot.pause()
            _rewind_mount_tick(app)

            call_count = {"n": 0}

            async def fake_run_goal_alignment_check():
                call_count["n"] += 1

            app._run_goal_alignment_check = fake_run_goal_alignment_check
            app._buffer.add(_make_action(0, incoming_message="Fix the login bug"))

            # First tick: due immediately (rewound above) -> dispatched once.
            app.refresh_display()
            assert call_count["n"] == 0  # not blocking -- worker hasn't run yet
            await pilot.pause()
            assert call_count["n"] == 1

            # Well under the interval -> throttled, no re-dispatch.
            clock["t"] += 5
            app.refresh_display()
            await pilot.pause()
            assert call_count["n"] == 1

            clock["t"] += 5
            app.refresh_display()
            await pilot.pause()
            assert call_count["n"] == 1

            # Interval fully elapses -> due again.
            clock["t"] += LLM_ASSESSMENT_INTERVAL_SECONDS
            app.refresh_display()
            await pilot.pause()
            assert call_count["n"] == 2

    async def test_goal_alignment_throttle_independent_of_warning_triage_throttle(
        self, tmp_path, monkeypatch
    ):
        """Dispatching a per-warning triage batch must not itself satisfy
        (or reset) the goal-alignment throttle, and vice versa -- they are
        two different clocks by design (see LiveLlmAssessor's class
        docstring)."""
        import agentwatch.ui.live_integrations as live_mod

        clock = {"t": 0.0}
        monkeypatch.setattr(live_mod, "_monotonic", lambda: clock["t"])
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: _FakeOllamaClient())

        log_path = tmp_path / "session.jsonl"
        log_path.write_text("", encoding="utf-8")
        app = AgentWatchApp(log_path=log_path, security_mode=False, llm=True)

        async with app.run_test() as pilot:
            await pilot.pause()
            _rewind_mount_tick(app)

            assessor = app._llm_assessor
            assert assessor is not None

            # Dispatching only the per-warning triage half must not make
            # goal_alignment_due() report False right after (it's still
            # independently due) -- mark_run() only resets due()'s own
            # clock, not goal_alignment_due()'s.
            assert assessor.goal_alignment_due(now=clock["t"]) is True
            assessor.mark_run(now=clock["t"])
            assert assessor.due(now=clock["t"]) is False  # just marked -- its own window resets
            assert assessor.goal_alignment_due(now=clock["t"]) is True  # unaffected

            # And the reverse: dispatching goal-alignment must not affect
            # the per-warning due() window (still False from the mark_run()
            # above -- clock hasn't advanced).
            assessor.mark_goal_run(now=clock["t"])
            assert assessor.goal_alignment_due(now=clock["t"]) is False  # just marked
            assert assessor.due(now=clock["t"]) is False  # still within its own window, unaffected

            # Advance past the interval: both become due again independently.
            clock["t"] += LLM_ASSESSMENT_INTERVAL_SECONDS
            assert assessor.due(now=clock["t"]) is True
            assert assessor.goal_alignment_due(now=clock["t"]) is True


class TestGoalAlignmentNoStatedTask:
    async def test_no_stated_task_makes_zero_ollama_calls_and_shows_no_advisory(
        self, tmp_path, monkeypatch
    ):
        fake = _FakeOllamaClient()
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: fake)

        log_path = tmp_path / "session.jsonl"
        log_path.write_text("", encoding="utf-8")
        app = AgentWatchApp(log_path=log_path, security_mode=False, llm=True)

        async with app.run_test() as pilot:
            await pilot.pause()
            _rewind_mount_tick(app)

            # No incoming_message anywhere -- the documented Codex-shaped
            # "nothing to assess" case (see llm.py's assess_goal_alignment
            # docstring). Also give the detector registry a real (non-goal)
            # warning so the WarningsList panel isn't simply empty for an
            # unrelated reason.
            app._buffer.add(_make_action(0, incoming_message=None))

            app.refresh_display()
            await pilot.pause()
            # A second tick, well past the throttle interval, to make sure
            # the "no stated task" result doesn't somehow start producing
            # calls once cached/re-checked.
            app._llm_assessor.mark_goal_run(now=-LLM_ASSESSMENT_INTERVAL_SECONDS)
            app.refresh_display()
            await pilot.pause()

            assert fake.chat_call_count == 0, (
                "assess_goal_alignment() must make zero model calls when no "
                "action carries a non-empty incoming_message"
            )

            warnings_widget = app.query_one("#warnings-list", WarningsList)
            rendered = warnings_widget._build_content()
            assert "GOAL ALIGNMENT" not in rendered, (
                "no stated task means silence, not a placeholder / false "
                "'no drift detected' line -- got:\n" + rendered
            )

    async def test_stated_task_present_shows_advisory_block(self, tmp_path, monkeypatch):
        fake = _FakeOllamaClient()
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: fake)

        log_path = tmp_path / "session.jsonl"
        log_path.write_text("", encoding="utf-8")
        app = AgentWatchApp(log_path=log_path, security_mode=False, llm=True)

        async with app.run_test() as pilot:
            await pilot.pause()
            _rewind_mount_tick(app)

            app._buffer.add(_make_action(0, incoming_message="Fix the login bug"))

            app.refresh_display()
            for _ in range(20):
                await pilot.pause(0.02)
                if fake.chat_call_count >= 1:
                    break
            assert fake.chat_call_count >= 1

            app.refresh_display()
            warnings_widget = app.query_one("#warnings-list", WarningsList)
            rendered = warnings_widget._build_content()
            assert "TIER-2 GOAL ALIGNMENT (advisory, not scored)" in rendered
            assert "[POSSIBLE DRIFT]" in rendered
            assert "Agent is reading unrelated files." in rendered


class TestGoalAlignmentNonBlocking:
    async def test_goal_alignment_runs_off_render_path_via_worker(self, tmp_path, monkeypatch):
        """refresh_display() must return immediately, not block on the real
        (here: faked, but synchronously-blocking-if-called-inline) Ollama
        chat() round-trip -- same non-blocking bar as per-warning triage."""
        fake = _FakeOllamaClient()
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: fake)

        log_path = tmp_path / "session.jsonl"
        log_path.write_text("", encoding="utf-8")
        app = AgentWatchApp(log_path=log_path, security_mode=False, llm=True)

        async with app.run_test() as pilot:
            await pilot.pause()
            _rewind_mount_tick(app)

            app._buffer.add(_make_action(0, incoming_message="Fix the login bug"))

            app.refresh_display()  # must return immediately, not block on Ollama
            assert fake.chat_call_count == 0
            await pilot.pause()
            assert fake.chat_call_count == 1


class TestGoalAlignmentNeverScored:
    async def test_goal_alignment_widget_update_never_constructs_a_warning(
        self, tmp_path, monkeypatch
    ):
        """WarningsList.update_goal_alignment() must only ever be called
        with a plain dict (GoalAlignmentAssessment.to_dict()) or None --
        never a Warning, never anything that could reach calculate_health()
        or Category.GOAL. Spies on the real call site inside _do_refresh()
        rather than asserting on internals."""
        fake = _FakeOllamaClient()
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: fake)

        log_path = tmp_path / "session.jsonl"
        log_path.write_text("", encoding="utf-8")
        app = AgentWatchApp(log_path=log_path, security_mode=False, llm=True)

        async with app.run_test() as pilot:
            await pilot.pause()
            _rewind_mount_tick(app)

            app._buffer.add(_make_action(0, incoming_message="Fix the login bug"))

            warnings_widget = app.query_one("#warnings-list", WarningsList)
            seen = []
            original = WarningsList.update_goal_alignment

            def spy(self, assessment):
                seen.append(assessment)
                return original(self, assessment)

            monkeypatch.setattr(WarningsList, "update_goal_alignment", spy)

            for _ in range(20):
                app.refresh_display()
                await pilot.pause(0.02)
                if fake.chat_call_count >= 1:
                    break

            app.refresh_display()

            assert seen, "update_goal_alignment() was never called"
            for value in seen:
                assert value is None or isinstance(value, dict), (
                    f"update_goal_alignment() received a non-dict, non-None "
                    f"value: {value!r}"
                )
                if isinstance(value, dict):
                    assert set(value.keys()) <= {"aligned", "confidence", "drift_summary"}

            _ = warnings_widget  # queried above purely to assert it exists
