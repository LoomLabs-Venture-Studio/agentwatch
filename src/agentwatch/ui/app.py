"""Widgets and helpers shared by the dashboard (multi_app) and its detail view."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

from rich.cells import cell_len
from textual.app import App
from textual.reactive import reactive
from textual.widgets import Static

from agentwatch.health.score import MIN_RATE_MINUTES
from agentwatch.themes import (
    ascii_safe,
    get_theme,
    security_label_from_score,
    security_status_from_score,
)
from agentwatch.ui.rot_widget import _mini_bar

if TYPE_CHECKING:
    from agentwatch.detectors.base import Warning
    from agentwatch.health.score import EfficiencyReport


def hang(line: str, width: int, indent: int) -> str:
    """*line* wrapped to *width* with continuation lines indented *indent*
    (a widget's own wrap starts them at column 0). One cell of slack: an
    emoji is two cells but one character."""
    if width <= indent + 10 or len(line) < width:
        return line
    return textwrap.fill(line, width - 1, subsequent_indent=" " * indent)


def show(widget: Static, content: str) -> None:
    """`Static.update` only when the text changed (an update re-lays out)."""
    if content != widget.content:
        widget.update(content)


def _hm(minutes: float) -> str:
    """A duration as "2h 05m" / "45m"."""
    h, m = divmod(int(minutes), 60)
    return f"{h}h {m:02d}m" if h else f"{m}m"


class HealthBar(Static):
    """Widget showing overall health as a progress bar."""

    score = reactive(100)
    status = reactive("")

    def __init__(self, **kwargs):
        super().__init__(markup=False, **kwargs)
        # Initialize status with theme's best status
        self.status = get_theme().level_0

    def render(self) -> str:
        # Create a simple ASCII progress bar
        filled = int(self.score / 5)  # 20 chars total
        bar = "█" * filled + "░" * (20 - filled)

        theme = get_theme()
        emoji = theme.emoji_for(self.status)

        return f"  {emoji} Health [{bar}] {self.score}%  {self.status.upper()}"


class SecurityStatus(Static):
    """Widget showing security status (no health words: those are for
    HealthBar)."""

    score = reactive(100)
    alert_count = reactive(0)

    def __init__(self, **kwargs):
        super().__init__(markup=False, **kwargs)

    def render(self) -> str:
        # Theme-driven, following the same pattern HealthBar (above) already
        # uses correctly -- see security_status_from_score()'s docstring for
        # why this is a dedicated 3-way (100/>50/else) mapping rather than
        # StatusTheme.status_from_score()'s 4-way 80/60/40 banding.
        theme = get_theme()
        status = security_status_from_score(self.score)
        emoji = theme.emoji_for(status)
        label = security_label_from_score(self.score)

        n = self.alert_count
        found = f"{n} finding{'s' * (n != 1)}" if n else "clean"
        return f"  {emoji} Security: {found}  {label} (score {self.score}%)"


class EfficiencyBar(Static):
    """Widget showing session efficiency as a progress bar with category breakdown."""

    def __init__(self, **kwargs):
        super().__init__(
            "  Efficiency: waiting for data" + ascii_safe("…", "..."),
            markup=False,
            **kwargs,
        )
        self._report: EfficiencyReport | None = None

    def update_efficiency(self, report: "EfficiencyReport") -> None:
        self._report = report
        show(self, self._build_content())

    def _build_content(self) -> str:
        r = self._report
        if r is None:
            return "  Efficiency: waiting for data" + ascii_safe("…", "...")

        filled = int(r.score / 5)  # 20 chars total
        bar = "█" * filled + "░" * (20 - filled)

        # No status word or recommendation: HealthBar has the one status.
        lines = [f"  {get_theme().emoji_for(r.status)} Efficiency [{bar}] {r.score}%"]

        # Per-category mini bars with detail
        # Rates over a near-zero duration are meaningless (#45).
        warm = r.duration_minutes >= MIN_RATE_MINUTES
        burn = f"{r.token_burn_rate / 1000:.1f}k" if warm else "--"
        cost_rate = f"${r.cost_velocity:.2f}" if warm and r.cost_velocity is not None else "--"
        categories = [
            (
                "Pressure",
                r.penalty_context,
                f"{r.context_usage_pct:.0f}% ctx, {burn} tok/min",
            ),
            ("Cache", r.penalty_cache, f"{r.cache_hit_rate * 100:.0f}% hit rate"),
            (
                "Pacing",
                r.penalty_pacing,
                f"{_hm(r.duration_minutes)}, {r.actions_per_turn:.1f} act/turn",
            ),
        ]
        for label, penalty, detail in categories:
            mini = _mini_bar(penalty)
            lines.append(f"    {label:12s} [{mini}]  {detail}")
        # Cost is informational — not scored (no log-reported cost data yet)
        if r.cost_total is None:
            lines.append("  Est. cost: n/a (no price for this model)")
        else:
            lines.append(f"  Est. cost: ${r.cost_total:.2f} ({cost_rate}/min)")

        return "\n".join(lines)


class WarningsList(Static):
    """Widget showing list of active warnings."""

    limit: int | None = 8  # warnings shown; None: all (the scrollable detail view)

    def __init__(self, **kwargs):
        super().__init__("  No active warnings", markup=False, **kwargs)
        self._warnings: list[Warning] = []
        self._goal_alignment: dict | None = None

    def on_mount(self) -> None:
        show(self, self._build_content())

    def update_warnings(self, warnings: list["Warning"]) -> None:
        self._warnings = warnings
        show(self, self._build_content())

    def on_resize(self) -> None:
        show(self, self._build_content())

    def update_goal_alignment(self, assessment: dict | None) -> None:
        """Update the Tier-2 goal-alignment advisory block (`llm.py`'s
        `assess_goal_alignment()`, Sprint 15; wired live here via
        `LiveLlmAssessor.stamp_goal_alignment()`).

        *assessment* is `None` both when no assessment has completed yet
        and when the last one found no stated task to compare against --
        both render as "show nothing," matching `check`/`security-scan
        --llm`'s `_print_goal_alignment()` silence-is-honest behavior
        (`cli.py`) exactly rather than a misleading "no drift detected."

        Advisory-only, purely a rendering concern: never reads or writes
        `self._warnings`, never touches score/health calculation, and
        `assessment` is a plain `dict` (`GoalAlignmentAssessment.to_dict()`),
        never a `Warning` -- this widget has no way to feed `Category.GOAL`
        even by accident.
        """
        self._goal_alignment = assessment
        show(self, self._build_content())

    def _build_content(self) -> str:
        lines: list[str] = list(self._build_goal_alignment_block())

        if not self._warnings:
            lines.append("  No active warnings")
            return "\n".join(lines)

        lines.append("  Active Warnings:")
        lines.append("")
        for w in self._warnings[: self.limit]:
            cost = f"  {w.cost_label}" if w.cost_label else ""
            width = self.size.width
            lines.append(hang(f"  {w.emoji} [{w.signal:20}] {w.message}{cost}", width, 5))

            # Show key details inline
            detail_line = self._format_details(w)
            if detail_line:
                lines.append(hang(f"     {ascii_safe('→', '->')} {detail_line}", width, 8))

            # Show suggestion
            if w.suggestion:  # wrapped (hanging indent), not cut
                tip = ascii_safe("💡", "[TIP]")
                lines.append(hang(f"     {tip} {w.suggestion}", width, 5 + cell_len(tip) + 1))

            # Show Tier-2 LLM triage, if --llm assessed this warning
            # (LiveLlmAssessor.stamp() attaches it before we get here)
            if "llm_assessment" in w.details:
                verdict = w.details["llm_assessment"]
                ltp = verdict.get("likely_true_positive")
                verdict_label = (
                    "likely real"
                    if ltp is True
                    else "likely false positive"
                    if ltp is False
                    else "unclear"
                )
                lines.append(
                    f"     [Tier-2] {verdict_label} ({verdict.get('confidence', '?')} confidence)"
                )

            lines.append("")  # Blank line between warnings

        if self.limit is not None and len(self._warnings) > self.limit:
            lines.append(f"  ... and {len(self._warnings) - self.limit} more")

        return "\n".join(lines)

    def _build_goal_alignment_block(self) -> list[str]:
        """Render the Tier-2 goal-alignment advisory, if any.

        Mirrors `cli.py`'s `_print_goal_alignment()` label mapping and
        header text exactly (`[ALIGNED]` / `[POSSIBLE DRIFT]` / `[UNCLEAR]`,
        "TIER-2 GOAL ALIGNMENT (advisory, not scored)") so `check`/
        `security-scan --llm` and live `watch --llm` present this the same
        way. ASCII-only, plain bracketed labels by design -- same reasoning
        as `_print_goal_alignment()`'s docstring: this deliberately does not
        route through `themes.py`.

        Returns `[]` (nothing rendered) when there's no cached assessment,
        covering both "never run yet" and "last run found no stated task"
        -- silence, not a placeholder line, matching the CLI's behavior.
        """
        a = self._goal_alignment
        if a is None:
            return []

        aligned = a.get("aligned")
        if aligned is True:
            label = "[ALIGNED]"
        elif aligned is False:
            label = "[POSSIBLE DRIFT]"
        else:
            label = "[UNCLEAR]"

        summary = a.get("drift_summary") or "(model response could not be parsed)"

        return [
            "  TIER-2 GOAL ALIGNMENT (advisory, not scored)",
            "  " + "-" * 48,
            f"  {label} {summary}",
            "",
        ]

    @staticmethod
    def _format_details(w: "Warning") -> str:
        """Extract the most useful detail from a warning for inline display."""
        d = w.details
        if not d:
            return ""

        # Secret leak — show type, channel, file, and safe prefix
        if w.signal == "secret_leak":
            parts = []
            if "secret_type" in d:
                parts.append(f"Type: {d['secret_type']}")
            if "channel" in d:
                parts.append(f"Channel: {d['channel']}")
            if d.get("file_path"):
                parts.append(f"File: {d['file_path']}")
            if "matched_prefix" in d:
                parts.append(f"Match: {d['matched_prefix']}")
            return " | ".join(parts)

        # Show the actual error/command that's causing problems
        if "last_error" in d and d["last_error"]:
            return f"Error: {d['last_error'][:100]}"
        if "last_command" in d and d["last_command"]:
            last_error = d.get("last_error", "")
            arrow = ascii_safe("→", "->")
            err = f" {arrow} {last_error[:60]}" if last_error else ""
            return f"Command: {d['last_command'][:80]}{err}"
        if "error_pattern" in d:
            return f"Error: {d['error_pattern'][:100]}"
        if "sample_errors" in d and d["sample_errors"]:
            val = d["sample_errors"]
            if isinstance(val, list) and val:
                return f"Error: {val[0][:100]}"
        if "recent_errors" in d and d["recent_errors"]:
            val = d["recent_errors"]
            if isinstance(val, list) and val:
                return f"Error: {val[0][:100]}"
            elif isinstance(val, int):
                return f"Errors: {val}"
        if "files_being_read" in d:
            return f"Files: {', '.join(d['files_being_read'][:4])}"
        if "files" in d and isinstance(d["files"], list):
            return f"Files: {', '.join(d['files'][:4])}"
        if "file" in d:
            return f"File: {d['file']}"
        if "error_class" in d:
            occurrences = d.get("occurrences", d.get("failure_count", "?"))
            return f"Error type: {d['error_class']} ({occurrences}x)"

        return ""


class StatsPanel(Static):
    """Widget showing session statistics."""

    def __init__(self, **kwargs):
        super().__init__("  Actions: 0  Errors: 0  Duration: 0m", markup=False, **kwargs)
        self._action_count = 0
        self._error_count = 0
        self._duration = 0.0
        self._network = ""

    def on_mount(self) -> None:
        show(self, self._build_content())

    def update_stats(
        self, action_count: int, error_count: int, duration: float, network: str = ""
    ) -> None:
        self._action_count = action_count
        self._error_count = error_count
        self._duration = duration
        self._network = network
        show(self, self._build_content())

    def _build_content(self) -> str:
        line = (
            f"  Actions: {self._action_count}  Errors: {self._error_count}  "
            f"Duration: {_hm(self._duration)}"
        )
        return f"{line}  {self._network}" if self._network else line


def plain_notify(app: App, message: str, **kwargs) -> None:
    """`App.notify` defaults to markup; toasts here carry log-derived text."""
    kwargs.setdefault("markup", False)
    App.notify(app, message, **kwargs)
