"""End-to-end live-exercise of `--siem-log`/`--llm` alongside the
`ActionBuffer` truthiness fix (PLAYBOOK Sprint 13 re-verification).

Every existing SIEM/LLM live-wiring test (``test_app_live_wiring.py``)
manually seeds ``app._buffer`` and replaces ``app._detector_registry.
check_all`` with a fixture warning -- exactly the pattern that let the
``ActionBuffer`` truthiness bug (fixed in ``fix/actionbuffer-truthiness-
guard``, ``ui/app.py``'s ``_on_action``/``refresh_display``) go undetected
for years, since unit tests never drove the real watcher -> ``_on_action``
callback path.

This test deliberately does neither: it points a real ``AgentWatchApp`` at
a real JSONL fixture file containing an action that trips a REAL security
detector (``CredentialAccessDetector``, via a `.env` file read), drives the
actual ``LogWatcher.watch_with_callbacks()`` -> ``_on_action`` -> real
``check_all()`` -> real ``LiveSiemExporter``/``LiveLlmAssessor`` pipeline
end-to-end via a headless Textual pilot run, and confirms:

1. The real warning actually reaches disk via the real ``SiemLogger``
   (not a mocked exporter).
2. The Tier-2 LLM assessment actually gets dispatched and its result
   actually gets attached to the rendered warning (via a faked, but
   otherwise-real, Ollama client -- no network dependency).
3. Neither SIEM export nor LLM assessment silently no-ops because of a
   bare-truthy guard anywhere in this path (the same class of bug as the
   ``ActionBuffer`` one) -- if either did, the assertions below would fail
   exactly the way ``test_app_on_action_regression.py`` demonstrated for
   the original bug.
"""

from __future__ import annotations

import json
from pathlib import Path
from time import monotonic as _monotonic
from types import SimpleNamespace

from agentwatch.ui.app import AgentWatchApp, WarningsList
from agentwatch.ui.live_integrations import LLM_ASSESSMENT_INTERVAL_SECONDS


class _FakeOllamaClient:
    """Same shape as test_app_live_wiring.py's fake -- duplicated locally
    since this test intentionally stays independent of that file's fixture
    setup (it's driving a different, real-watcher-based code path)."""

    def __init__(self):
        self.chat_call_count = 0

    def __call__(self, host=None):
        return self

    def list(self):
        return SimpleNamespace(models=[SimpleNamespace(model="llama3.2:latest")])

    def chat(self, **kwargs):
        self.chat_call_count += 1
        return SimpleNamespace(
            message=SimpleNamespace(
                content='{"likely_true_positive": true, "confidence": "high", '
                '"rationale": "Reading a .env file is a real credential-access risk."}'
            )
        )


def _write_fixture_log(path: Path) -> None:
    """A real flat-format Claude Code JSONL log (same shape as
    test_app_on_action_regression.py's fixture) whose single action reads
    `.env` -- a real `SENSITIVE_PATHS` match (parser/security_patterns.py)
    that `CredentialAccessDetector.check()` will genuinely flag."""
    line = json.dumps(
        {
            "sessionId": "s1",
            "timestamp": "2026-01-01T12:00:00",
            "tool": "Read",
            "file": ".env",
            "input_tokens": 100,
        }
    )
    path.write_text(line + "\n", encoding="utf-8")


async def test_siem_and_llm_populate_via_real_watcher_and_real_detector(tmp_path, monkeypatch):
    fake = _FakeOllamaClient()
    monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: fake)

    log_path = tmp_path / "session.jsonl"
    _write_fixture_log(log_path)
    siem_path = tmp_path / "siem.jsonl"

    app = AgentWatchApp(
        log_path=log_path,
        security_mode=True,
        siem_log=siem_path,
        llm=True,
    )

    async with app.run_test() as pilot:
        # Let the real watcher deliver the fixture's one action through the
        # real _on_action callback (no manual buffer seeding).
        for _ in range(40):
            await pilot.pause(0.05)
            if app._buffer is not None and len(app._buffer) >= 1:
                break
        assert app._buffer is not None and len(app._buffer) == 1, (
            "real watcher -> _on_action delivered no actions -- the "
            "ActionBuffer truthiness bug (or a regression of it) would "
            "produce exactly this symptom"
        )

        # on_mount() already ran one real refresh_display() at t=0, before
        # the watcher had delivered any action yet -- LiveLlmAssessor.due()
        # fires on elapsed real time regardless of whether there was
        # anything to assess, so it already consumed the "free first tick"
        # against zero warnings (see test_app_live_wiring.py's throttle test
        # for the same interaction, confirmed there in detail). Rewind the
        # real wall-clock throttle via the assessor's own public mark_run()
        # so the *real* warning collected above gets its own fair dispatch
        # opportunity without this test needing to sleep 30 real seconds.
        assert app._llm_assessor is not None
        app._llm_assessor.mark_run(now=_monotonic() - LLM_ASSESSMENT_INTERVAL_SECONDS - 1)

        # Drive real refreshes (real check_all(), real detector, real
        # LiveSiemExporter/LiveLlmAssessor) until the SIEM file and the LLM
        # assessment both show up, or we give up.
        for _ in range(40):
            app.refresh_display()
            await pilot.pause(0.05)
            if siem_path.exists() and siem_path.read_text(encoding="utf-8").strip():
                break

        # 1. SIEM export actually wrote the real warning to disk.
        assert siem_path.exists(), "SIEM log was never created -- export silently no-op'd"
        lines = [
            json.loads(line)
            for line in siem_path.read_text(encoding="utf-8").splitlines()
            if line
        ]
        assert len(lines) == 1, f"expected exactly 1 exported warning, got {len(lines)}"
        assert lines[0]["signal"] == "credential_access"

        # Re-running refresh_display() several more times must NOT re-export
        # the same still-open warning (dedup, not just first-write luck).
        for _ in range(5):
            app.refresh_display()
            await pilot.pause(0.02)
        lines_after = [
            line for line in siem_path.read_text(encoding="utf-8").splitlines() if line
        ]
        assert len(lines_after) == 1, (
            f"still-open warning was re-exported across ticks: {len(lines_after)} lines"
        )

        # 2. Tier-2 LLM assessment actually ran (off the render path) and its
        # verdict actually got attached to the rendered warning.
        for _ in range(60):
            await pilot.pause(0.05)
            if fake.chat_call_count >= 1:
                break
        assert fake.chat_call_count >= 1, (
            "LiveLlmAssessor never dispatched a real assess call -- either "
            "the throttle/dispatch wiring or a bare-truthy guard silently "
            "swallowed it"
        )

        app.refresh_display()
        warnings_widget = app.query_one("#warnings-list", WarningsList)
        rendered = warnings_widget._build_content()
        assert "[Tier-2]" in rendered, (
            f"LLM assessment ran ({fake.chat_call_count} call(s)) but its "
            f"verdict never made it into the rendered warnings list:\n{rendered}"
        )
