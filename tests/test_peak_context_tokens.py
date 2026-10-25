"""Tests for surfacing `SessionStats.peak_context_tokens` (Sprint 14 --
finishing scaffolding that was computed on every `ActionBuffer.add()` call
but never read/displayed anywhere).

Placement decision under test: `ui/rot_widget.py`'s `ContextHealthWidget`
(TUI) and `cli.py`'s `print_health_report` (plain-CLI `check` output) --
both purely additive/display-only, never folded into `report.overall_score`
or the rot score/state, which stay a function of the 5 weighted
behavioral/repetition/thrash/progress/constraint modules only.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from agentwatch.health.rot import MetricResult, RotReport, RotState
from agentwatch.parser.models import Action, ActionBuffer, ToolType
from agentwatch.themes import set_theme


def _make_action(tokens_in: int, offset: int = 0) -> Action:
    return Action(
        timestamp=datetime(2026, 1, 1, 12, 0) + timedelta(seconds=offset),
        tool_name="Read",
        tool_type=ToolType.READ,
        success=True,
        tokens_in=tokens_in,
    )


def _fake_rot_report() -> RotReport:
    zero = MetricResult(name="zero", value=0.0)
    return RotReport(
        raw_score=0.05,
        smoothed_score=0.05,
        state=RotState.LEVEL_0,
        modules={
            "behavioral": zero,
            "repetition": zero,
            "thrash": zero,
            "progress": zero,
            "constraint": zero,
        },
        top_reasons=[],
    )


class TestSessionStatsPeakContextTokens:
    """Sanity check on the already-existing computation this sprint surfaces."""

    def test_high_water_mark_across_actions(self):
        buffer = ActionBuffer()
        buffer.add(_make_action(1000, offset=0))
        buffer.add(_make_action(5000, offset=1))
        buffer.add(_make_action(2000, offset=2))
        assert buffer.stats.peak_context_tokens == 5000


class TestContextHealthWidgetPeakContextTokens:
    def test_displays_peak_context_tokens_when_provided(self):
        from agentwatch.ui.rot_widget import ContextHealthWidget

        set_theme("agent")
        widget = ContextHealthWidget()
        widget.update_report(_fake_rot_report(), peak_context_tokens=45230)
        rendered = widget._build_content()
        assert "45,230" in rendered
        assert "Peak context" in rendered

    def test_omits_peak_context_line_when_zero_or_none(self):
        from agentwatch.ui.rot_widget import ContextHealthWidget

        set_theme("agent")
        widget = ContextHealthWidget()
        widget.update_report(_fake_rot_report())  # peak_context_tokens defaults to None
        rendered = widget._build_content()
        assert "Peak context" not in rendered

        widget2 = ContextHealthWidget()
        widget2.update_report(_fake_rot_report(), peak_context_tokens=0)
        assert "Peak context" not in widget2._build_content()

    def test_does_not_affect_rot_score_or_state(self):
        """peak_context_tokens is display-only -- it must never change the
        smoothed score or state shown alongside it."""
        from agentwatch.ui.rot_widget import ContextHealthWidget

        set_theme("agent")
        report = _fake_rot_report()
        widget_a = ContextHealthWidget()
        widget_a.update_report(report, peak_context_tokens=None)
        widget_b = ContextHealthWidget()
        widget_b.update_report(report, peak_context_tokens=999_999)

        # Same state/score line in both, only the peak-context line differs.
        rendered_a = widget_a._build_content()
        rendered_b = widget_b._build_content()
        assert "State: PRODUCTIVE".upper() in rendered_a.upper() or "State:" in rendered_a
        # Strip the peak-context line and compare the rest for equality.
        lines_a = [ln for ln in rendered_a.splitlines() if "Peak context" not in ln]
        lines_b = [ln for ln in rendered_b.splitlines() if "Peak context" not in ln]
        assert lines_a == lines_b


class TestPrintHealthReportPeakContextTokens:
    def test_check_command_prints_peak_context_line(self, tmp_path, capsys):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        log_path = tmp_path / "session.jsonl"
        base = "2026-01-01T12:00:00"
        lines = [
            json.dumps(
                {
                    "sessionId": "s1",
                    "timestamp": base,
                    "tool": "Read",
                    "file": f"f{i}.txt",
                    "input_tokens": 5000 * (i + 1),
                }
            )
            for i in range(3)
        ]
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--log", str(log_path)])
        assert result.exit_code in (0, 1, 2), result.output
        assert "Peak context:" in result.output
