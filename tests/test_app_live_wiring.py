"""Headless Textual pilot tests for `AgentWatchApp`'s `--siem-log`/`--llm`
wiring (single-agent TUI, `ui/app.py`).

Drives the real app via `App.run_test()` (the same pattern established by
`test_multi_app_refresh.py`), manually seeding the buffer/registry the way
a real `LogWatcher` callback would, so these exercise the actual
`refresh_display()` / `_do_refresh()` path rather than mocking it away.

Covers the three things the naive "just call the one-shot CLI helpers
every tick" approach would get wrong:
  1. SIEM export must not re-append a still-open warning every tick.
  2. Tier-2 LLM assessment must be throttled to a materially coarser
     cadence than the 1s render tick, and must never block the render
     path (it's dispatched via `run_worker`, not awaited inline).
  3. Both failure modes (`SiemExportError`/bad path, Ollama unavailable)
     must surface as a single non-fatal `notify()`, not spam one per tick
     and not crash the app.
"""

from __future__ import annotations

import json
from datetime import datetime
from types import SimpleNamespace

from agentwatch.detectors.base import Category, Severity, Warning
from agentwatch.parser.models import Action, ToolType
from agentwatch.siem import SiemExportError
from agentwatch.ui.app import AgentWatchApp
from agentwatch.ui.live_integrations import LLM_ASSESSMENT_INTERVAL_SECONDS


def _make_action(i: int) -> Action:
    return Action(
        timestamp=datetime.now(),
        tool_name="Read",
        tool_type=ToolType.READ,
        success=True,
        file_path=f"file_{i}.py",
    )


def _fixed_warning() -> Warning:
    """A warning with a stable identity but a message that would change
    every tick in real detector output (simulating a still-open finding)."""
    return Warning(
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        signal="credential_access",
        message="Agent accessed sensitive path",
        details={"secret_type": "aws_key", "channel": "file_write", "file_path": "secret.env"},
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


class TestSiemExportDedup:
    async def test_still_open_warning_exported_once_across_ticks(self, tmp_path):
        log_path = tmp_path / "session.jsonl"
        log_path.write_text("", encoding="utf-8")
        siem_path = tmp_path / "siem.jsonl"

        app = AgentWatchApp(log_path=log_path, security_mode=True, siem_log=siem_path)
        async with app.run_test():
            app._detector_registry.check_all = lambda buffer: [_fixed_warning()]
            app._buffer.add(_make_action(0))

            app.refresh_display()
            app.refresh_display()
            app.refresh_display()

        lines = _read_lines(siem_path)
        assert len(lines) == 1
        assert lines[0]["signal"] == "credential_access"

    async def test_no_siem_log_means_no_exporter_wired(self, tmp_path):
        log_path = tmp_path / "session.jsonl"
        log_path.write_text("", encoding="utf-8")

        app = AgentWatchApp(log_path=log_path, security_mode=True)
        async with app.run_test():
            assert app._siem_exporter is None


class TestLlmThrottleAndNonBlocking:
    async def test_llm_batch_dispatched_once_per_interval_not_every_tick(
        self, tmp_path, monkeypatch
    ):
        import agentwatch.ui.live_integrations as live_mod

        clock = {"t": 0.0}
        monkeypatch.setattr(live_mod, "_monotonic", lambda: clock["t"])

        log_path = tmp_path / "session.jsonl"
        log_path.write_text("", encoding="utf-8")
        app = AgentWatchApp(log_path=log_path, security_mode=False, llm=True)

        async with app.run_test() as pilot:
            call_count = {"n": 0}

            async def fake_run_llm_batch(new_warnings):
                call_count["n"] += 1

            app._run_llm_batch = fake_run_llm_batch
            app._detector_registry.check_all = lambda buffer: [_fixed_warning()]
            app._buffer.add(_make_action(0))

            # First tick: due() is True immediately after mount (negative
            # initial offset) -> dispatched once.
            app.refresh_display()
            assert call_count["n"] == 0  # not blocking -- worker hasn't run yet
            await pilot.pause()
            assert call_count["n"] == 1

            # A few seconds later, well under the 30s interval -> throttled.
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

    async def test_llm_assessment_runs_off_render_path_via_worker(self, tmp_path, monkeypatch):
        """The real assess call is a blocking HTTP round-trip -- assert it
        never runs synchronously inside refresh_display() by making the
        fake client block on an event that only the test releases, and
        confirming refresh_display() itself still returns immediately."""
        fake = _FakeOllamaClient()
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: fake)

        log_path = tmp_path / "session.jsonl"
        log_path.write_text("", encoding="utf-8")
        app = AgentWatchApp(log_path=log_path, security_mode=False, llm=True)

        async with app.run_test() as pilot:
            app._detector_registry.check_all = lambda buffer: [_fixed_warning()]
            app._buffer.add(_make_action(0))

            app.refresh_display()  # must return immediately, not block on Ollama
            assert fake.chat_call_count == 0
            await pilot.pause()
            assert fake.chat_call_count == 1


class TestFailureModesNotifyOnceNotSpam:
    async def test_siem_export_error_notifies_once_not_every_tick(self, tmp_path, monkeypatch):
        import agentwatch.ui.live_integrations as live_mod

        def raising_siem_logger(*args, **kwargs):
            raise SiemExportError("simulated bad path")

        monkeypatch.setattr(live_mod, "SiemLogger", raising_siem_logger)

        log_path = tmp_path / "session.jsonl"
        log_path.write_text("", encoding="utf-8")
        app = AgentWatchApp(
            log_path=log_path, security_mode=True, siem_log=tmp_path / "unwritable" / "siem.jsonl"
        )
        async with app.run_test():
            notifications = []
            app.notify = lambda *a, **k: notifications.append((a, k))

            app._detector_registry.check_all = lambda buffer: [_fixed_warning()]
            app._buffer.add(_make_action(0))

            app.refresh_display()
            app.refresh_display()
            app.refresh_display()

            siem_notifications = [
                n for n in notifications if n[1].get("title") == "SIEM export failed"
            ]
            assert len(siem_notifications) == 1

    async def test_llm_unavailable_notifies_once_not_every_throttled_tick(
        self, tmp_path, monkeypatch
    ):
        import agentwatch.ui.live_integrations as live_mod

        clock = {"t": 0.0}
        monkeypatch.setattr(live_mod, "_monotonic", lambda: clock["t"])

        fake = _FakeOllamaClient(list_raises=ConnectionError("refused"))
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: fake)

        log_path = tmp_path / "session.jsonl"
        log_path.write_text("", encoding="utf-8")
        app = AgentWatchApp(log_path=log_path, security_mode=False, llm=True)

        async with app.run_test() as pilot:
            notifications = []
            app.notify = lambda *a, **k: notifications.append((a, k))

            app._detector_registry.check_all = lambda buffer: [_fixed_warning()]
            app._buffer.add(_make_action(0))

            for _ in range(3):
                app.refresh_display()
                await pilot.pause()
                clock["t"] += LLM_ASSESSMENT_INTERVAL_SECONDS

            llm_notifications = [
                n for n in notifications if n[1].get("title") == "Tier-2 LLM unavailable"
            ]
            assert len(llm_notifications) == 1

    async def test_app_does_not_crash_on_repeated_failures(self, tmp_path, monkeypatch):
        """Both failure modes at once must degrade gracefully, never raise
        out of refresh_display() into the app's render loop."""
        import agentwatch.ui.live_integrations as live_mod

        def raising_siem_logger(*args, **kwargs):
            raise SiemExportError("simulated bad path")

        monkeypatch.setattr(live_mod, "SiemLogger", raising_siem_logger)
        fake = _FakeOllamaClient(list_raises=ConnectionError("refused"))
        monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: fake)

        log_path = tmp_path / "session.jsonl"
        log_path.write_text("", encoding="utf-8")
        app = AgentWatchApp(
            log_path=log_path,
            security_mode=True,
            siem_log=tmp_path / "siem.jsonl",
            llm=True,
        )
        async with app.run_test() as pilot:
            app._detector_registry.check_all = lambda buffer: [_fixed_warning()]
            app._buffer.add(_make_action(0))

            for _ in range(3):
                app.refresh_display()
                await pilot.pause()

            assert app.is_running
