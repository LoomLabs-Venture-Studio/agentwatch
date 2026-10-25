"""Regression test for the ActionBuffer truthiness bug in
``AgentWatchApp._on_action`` (src/agentwatch/ui/app.py).

Root cause: ``ActionBuffer`` (parser/models.py) defines ``__len__`` but not
``__bool__``, so Python falls back to length-based truthiness -- a freshly
constructed, empty ``ActionBuffer()`` is falsy (``len() == 0``). Since
``AgentWatchApp._buffer`` starts life as exactly that (set in ``on_mount``),
the original guard ``if self._buffer:`` in ``_on_action`` silently dropped
the very first action ever delivered by the watcher. Because it was
dropped, the buffer never gained any actions, so the guard kept evaluating
``False`` forever -- the single-agent ``agentwatch watch`` TUI has never
displayed live action/health data for any agent type, since the project's
first commit (confirmed via ``git log -S "if self._buffer:"``).

Every pre-existing TUI-adjacent test (e.g. ``tests/test_multi_app_refresh.py``)
seeds ``app._buffer``/``agent_data["buffer"]`` directly or calls a refresh
method manually, bypassing ``_on_action`` entirely -- which is exactly why
this bug survived undetected. This test deliberately does neither: it points
a real ``AgentWatchApp`` at a real JSONL fixture file and drives the actual
``LogWatcher.watch_with_callbacks()`` -> ``_on_action`` wiring via a headless
Textual pilot run (``App.run_test()``), the same pattern already used
elsewhere in this codebase.

Confirmed to FAIL against the pre-fix code (manually verified by reverting
the fix locally): with the bug, ``app._buffer`` stays permanently empty
(``len(app._buffer) == 0``, ``action_count == 0``) no matter how many
actions the watcher reads from the fixture file.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentwatch.ui.app import AgentWatchApp, StatsPanel


def _write_fixture_log(path: Path, count: int = 3) -> None:
    """Write a small flat-format Claude Code JSONL log (same shape used by
    tests/test_peak_context_tokens.py's CLI test) so LogWatcher's format
    auto-detection resolves it as claude_code via _parse_claude_code_flat."""
    base = "2026-01-01T12:00:00"
    lines = [
        json.dumps(
            {
                "sessionId": "s1",
                "timestamp": base,
                "tool": "Read",
                "file": f"f{i}.txt",
                "input_tokens": 100 * (i + 1),
            }
        )
        for i in range(count)
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


async def test_on_action_populates_buffer_via_real_watcher(tmp_path):
    """Actions delivered through the real watcher -> _on_action callback
    must actually land in app._buffer (not be silently dropped)."""
    log_path = tmp_path / "session.jsonl"
    _write_fixture_log(log_path, count=3)

    app = AgentWatchApp(log_path=log_path, security_mode=False)

    async with app.run_test() as pilot:
        # on_mount() starts self.watcher.watch_with_callbacks() as a
        # background worker. Give it real event-loop time to read the
        # fixture file's existing content and dispatch through _on_action.
        for _ in range(40):
            await pilot.pause(0.05)
            if app._buffer is not None and len(app._buffer) >= 3:
                break

        assert app._buffer is not None
        assert len(app._buffer) == 3, (
            f"expected 3 actions delivered via the real watcher -> "
            f"_on_action path, got {len(app._buffer)} -- a count stuck at "
            f"0 means the ActionBuffer truthiness guard bug has regressed"
        )
        assert app._buffer.stats.action_count == 3

        # Drive a real refresh (not a manually-seeded one) and confirm the
        # UI widgets actually reflect the delivered actions.
        app.refresh_display()
        stats_widget = app.query_one("#stats-display", StatsPanel)
        assert stats_widget._action_count == 3
