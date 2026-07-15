"""Context Health widget for the TUI – displays rot score and breakdown."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.widgets import Static

from agentwatch.themes import ascii_safe, get_theme

if TYPE_CHECKING:
    from agentwatch.health.rot import RotReport


def _mini_bar(value: float, width: int = 10) -> str:
    """Render a mini progress bar █░ of *width* characters."""
    filled = int(round(value * width))
    return "█" * filled + "░" * (width - filled)


class ContextHealthWidget(Static):
    """Displays the composite rot score, state, per-module bars, and top reasons."""

    def __init__(self, **kwargs):
        super().__init__("  Context Health: loading" + ascii_safe("…", "..."), **kwargs)
        self._report: RotReport | None = None
        self._peak_context_tokens: int | None = None

    def update_report(
        self,
        report: "RotReport",
        peak_context_tokens: int | None = None,
    ) -> None:
        """Update with a fresh `RotReport`.

        `peak_context_tokens` (`SessionStats.peak_context_tokens`, the
        high-water mark of any single action's context size -- survives
        compaction) is display-only here: it does NOT feed into the rot
        score/state above, which stays purely a function of the 5 weighted
        behavioral/repetition/thrash/progress/constraint modules.
        """
        self._report = report
        self._peak_context_tokens = peak_context_tokens
        self.update(self._build_content())

    def _build_content(self) -> str:
        r = self._report
        if r is None:
            return "  Context Health: waiting for data" + ascii_safe("…", "...")

        theme = get_theme()
        state_label = r.state.label  # Theme-aware label
        emoji = theme.emoji_for(state_label)
        score_pct = int(round((1.0 - r.smoothed_score) * 100))

        lines: list[str] = []
        mini_bar = _mini_bar(1.0 - r.smoothed_score, 20)
        lines.append(f"  {emoji} Context Health: [{mini_bar}] {score_pct}%")
        lines.append(f"  State: {state_label.upper()}")
        if self._peak_context_tokens:
            lines.append(f"  Peak context: {self._peak_context_tokens:,} tokens (single action)")
        lines.append("")

        # Per-module mini bars
        module_labels = {
            "behavioral": "Behavioral",
            "repetition": "Repetition",
            "thrash": "Tool Thrash",
            "progress": "Progress",
            "constraint": "Constraints",
        }
        for key, label in module_labels.items():
            m = r.modules.get(key)
            if m is not None:
                bar = _mini_bar(m.value)
                lines.append(f"    {label:12s} [{bar}] {m.value:.2f}")

        # Top 3 reasons
        if r.top_reasons:
            lines.append("")
            lines.append("  Top signals:")
            bullet = ascii_safe("•", "*")
            for reason in r.top_reasons[:3]:
                # Truncate long evidence strings
                if len(reason) > 80:
                    reason = reason[:77] + "..."
                lines.append(f"    {bullet} {reason}")

        return "\n".join(lines)
