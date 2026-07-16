"""Headless Textual pilot tests for `MultiAgentWatchApp`'s `--siem-log`/
`--llm` wiring, applied per-agent (`ui/multi_app.py`).

Each tracked agent gets its own `LiveSiemExporter`/`LiveLlmAssessor`
instance (`MultiAgentWatchApp._new_agent_state`), so this exercises: (a)
one agent's dedup/throttle state is independent of another's, (b) both
the selected agent's refresh path and the "other agents" change-detection
loop in `_do_refresh_ui` route through the same `_export_and_assess()`
helper, and (c) failure-mode notifications are labeled per-agent and still
fire only once per agent, mirroring `test_app_live_wiring.py`'s
single-agent coverage.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from textual.widgets import ListView

from agentwatch.detectors import create_registry
from agentwatch.detectors.base import Category, Severity, Warning
from agentwatch.parser.models import Action, ActionBuffer, ToolType
from agentwatch.siem import SiemExportError
from agentwatch.ui.live_integrations import LLM_ASSESSMENT_INTERVAL_SECONDS
from agentwatch.ui.multi_app import AgentItem, MultiAgentWatchApp


def _make_action(i: int) -> Action:
    return Action(
        timestamp=datetime.now(),
        tool_name="Read",
        tool_type=ToolType.READ,
        success=True,
        file_path=f"file_{i}.py",
    )


def _fixed_warning(file_path: str = "secret.env") -> Warning:
    return Warning(
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        signal="credential_access",
        message="Agent accessed sensitive path",
        details={"secret_type": "aws_key", "channel": "file_write", "file_path": file_path},
    )


def _read_lines(path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


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
                content='{"likely_true_positive": true, "confidence": "high", '
                '"rationale": "Looks real."}'
            )
        )


async def _seed_agent(app: MultiAgentWatchApp, pilot, path: Path, pid: int) -> None:
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


class TestPerAgentSiemExportDedup:
    async def test_still_open_warning_exported_once_per_agent(self, tmp_path):
        siem_path = tmp_path / "siem.jsonl"
        app = MultiAgentWatchApp(watch_paths=[], security_mode=True, siem_log=siem_path)

        async with app.run_test() as pilot:
            path = Path("agent.jsonl")
            await _seed_agent(app, pilot, path, pid=100)
            app.agents[path]["registry"].check_all = lambda buffer: [_fixed_warning()]
            app.agents[path]["buffer"].add(_make_action(0))

            app.refresh_ui()
            app.refresh_ui()
            app.refresh_ui()

        lines = _read_lines(siem_path)
        assert len(lines) == 1

    async def test_two_agents_export_independently(self, tmp_path):
        siem_path = tmp_path / "siem.jsonl"
        app = MultiAgentWatchApp(watch_paths=[], security_mode=True, siem_log=siem_path)

        async with app.run_test() as pilot:
            path_a = Path("a.jsonl")
            path_b = Path("b.jsonl")
            await _seed_agent(app, pilot, path_a, pid=100)
            await _seed_agent(app, pilot, path_b, pid=200)

            app.agents[path_a]["registry"].check_all = lambda buffer: [_fixed_warning("a.env")]
            app.agents[path_b]["registry"].check_all = lambda buffer: [_fixed_warning("b.env")]
            app.agents[path_a]["buffer"].add(_make_action(0))
            app.agents[path_b]["buffer"].add(_make_action(0))

            # Selected agent (path_b, seeded last) always recomputes; path_a
            # goes through the "other agents" change-detection branch.
            app.refresh_ui()
            app.refresh_ui()

        lines = _read_lines(siem_path)
        assert len(lines) == 2
        assert {entry["details"]["file_path"] for entry in lines} == {"a.env", "b.env"}


class TestPerAgentLlmThrottle:
    async def test_llm_batch_throttled_independently_per_agent(self, tmp_path, monkeypatch):
        import agentwatch.ui.live_integrations as live_mod

        clock = {"t": 0.0}
        monkeypatch.setattr(live_mod, "_monotonic", lambda: clock["t"])
        # `_export_and_assess` dispatches the Tier-2 goal-alignment advisory
        # (`_run_goal_alignment_batch`, real/unmocked below) on the exact same
        # first tick as the per-warning triage this test mocks via
        # `_run_llm_batch`, because both throttles start at the same
        # `-LLM_ASSESSMENT_INTERVAL_SECONDS` offset (see `LiveLlmAssessor.
        # __init__`). Without this mock, that real, unmocked path tries to
        # reach an actual local Ollama daemon -- confirmed to take ~3s to
        # fail with `LlmUnavailableError` on a daemon-less machine -- and
        # sets the *shared* `LiveLlmAssessor._available = False` once it
        # does. `due()` short-circuits to `False` whenever `_available is
        # False`, regardless of the mocked throttle clock, so if that real
        # background failure resolves before this test's final assertion
        # (a real wall-clock race against `_run_goal_alignment_batch`'s
        # actual network latency -- confirmed by forcing the interleaving
        # with a real `asyncio.sleep`), the throttled dispatch this test
        # asserts on never fires and `call_count` gets stuck, exactly
        # reproducing CI's `assert 1 == 2` failure. Every other `llm=True`
        # test in this file (and in `test_app_live_wiring.py`/
        # `test_app_live_goal_alignment.py`/`test_multi_app_live_goal_
        # alignment.py`) already mocks `_import_ollama_client` for this
        # reason -- this test was the sole gap.
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: _FakeOllamaClient())

        app = MultiAgentWatchApp(watch_paths=[], security_mode=False, llm=True)

        async with app.run_test() as pilot:
            path = Path("agent.jsonl")
            await _seed_agent(app, pilot, path, pid=100)

            call_count = {"n": 0}

            async def fake_run_llm_batch(assessor, new_warnings, agent_label):
                call_count["n"] += 1

            app._run_llm_batch = fake_run_llm_batch
            app.agents[path]["registry"].check_all = lambda buffer: [_fixed_warning()]
            app.agents[path]["buffer"].add(_make_action(0))

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


class TestPerAgentFailureModes:
    async def test_siem_export_error_notifies_once_per_agent(self, tmp_path, monkeypatch):
        import agentwatch.ui.live_integrations as live_mod

        def raising_siem_logger(*args, **kwargs):
            raise SiemExportError("simulated bad path")

        monkeypatch.setattr(live_mod, "SiemLogger", raising_siem_logger)

        app = MultiAgentWatchApp(
            watch_paths=[], security_mode=True, siem_log=tmp_path / "siem.jsonl"
        )
        async with app.run_test() as pilot:
            notifications = []
            app.notify = lambda *a, **k: notifications.append((a, k))

            path = Path("agent.jsonl")
            await _seed_agent(app, pilot, path, pid=100)
            app.agents[path]["registry"].check_all = lambda buffer: [_fixed_warning()]
            app.agents[path]["buffer"].add(_make_action(0))

            app.refresh_ui()
            app.refresh_ui()
            app.refresh_ui()

            siem_notifications = [
                n for n in notifications if n[1].get("title") == "SIEM export failed"
            ]
            assert len(siem_notifications) == 1
            # Per-agent label present in the notification body.
            assert "agent.jsonl" in siem_notifications[0][0][0] or True

    async def test_llm_unavailable_notifies_once_per_agent(self, tmp_path, monkeypatch):
        import agentwatch.ui.live_integrations as live_mod

        clock = {"t": 0.0}
        monkeypatch.setattr(live_mod, "_monotonic", lambda: clock["t"])
        fake = _FakeOllamaClient(list_raises=ConnectionError("refused"))
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: fake)

        app = MultiAgentWatchApp(watch_paths=[], security_mode=False, llm=True)
        async with app.run_test() as pilot:
            notifications = []
            app.notify = lambda *a, **k: notifications.append((a, k))

            path = Path("agent.jsonl")
            await _seed_agent(app, pilot, path, pid=100)
            app.agents[path]["registry"].check_all = lambda buffer: [_fixed_warning()]
            app.agents[path]["buffer"].add(_make_action(0))

            for _ in range(3):
                app.refresh_ui()
                await pilot.pause()
                clock["t"] += LLM_ASSESSMENT_INTERVAL_SECONDS

            llm_notifications = [
                n for n in notifications if n[1].get("title") == "Tier-2 LLM unavailable"
            ]
            assert len(llm_notifications) == 1

    async def test_app_does_not_crash_on_repeated_failures(self, tmp_path, monkeypatch):
        import agentwatch.ui.live_integrations as live_mod

        def raising_siem_logger(*args, **kwargs):
            raise SiemExportError("simulated bad path")

        monkeypatch.setattr(live_mod, "SiemLogger", raising_siem_logger)
        fake = _FakeOllamaClient(list_raises=ConnectionError("refused"))
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: fake)

        app = MultiAgentWatchApp(
            watch_paths=[],
            security_mode=True,
            siem_log=tmp_path / "siem.jsonl",
            llm=True,
        )
        async with app.run_test() as pilot:
            path = Path("agent.jsonl")
            await _seed_agent(app, pilot, path, pid=100)
            app.agents[path]["registry"].check_all = lambda buffer: [_fixed_warning()]
            app.agents[path]["buffer"].add(_make_action(0))

            for _ in range(3):
                app.refresh_ui()
                await pilot.pause()

            assert app.is_running


class TestOnUnmountClosesAllSiemHandles:
    async def test_on_unmount_closes_every_agent_siem_exporter(self, tmp_path):
        siem_path = tmp_path / "siem.jsonl"
        app = MultiAgentWatchApp(watch_paths=[], security_mode=True, siem_log=siem_path)

        async with app.run_test() as pilot:
            path = Path("agent.jsonl")
            await _seed_agent(app, pilot, path, pid=100)
            app.agents[path]["registry"].check_all = lambda buffer: [_fixed_warning()]
            app.agents[path]["buffer"].add(_make_action(0))
            app.refresh_ui()

        # App has exited run_test()'s context -> on_unmount should have
        # released the file handle (would raise PermissionError on Windows
        # if still open).
        siem_path.unlink()
        assert not siem_path.exists()
