"""Context Health widget for the TUI – displays rot score and breakdown."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.widgets import Static

from agentwatch.themes import get_theme

if TYPE_CHECKING:
    from agentwatch.health.rot import RotReport, RotState


def _mini_bar(value: float, width: int = 10) -> str:
    """Render a mini progress bar █░ of *width* characters."""
    filled = int(round(value * width))
    return "█" * filled + "░" * (width - filled)


class ContextHealthWidget(Static):
    """Displays the composite rot score, state, per-module bars, and top reasons."""

    def __init__(self, **kwargs):
        super().__init__("  Context Health: loading…", **kwargs)
        self._report: RotReport | None = None

    def update_report(self, report: "RotReport") -> None:
        self._report = report
        self.update(self._build_content())

    def _build_content(self) -> str:
        r = self._report
        if r is None:
            return "  Context Health: waiting for data…"

        theme = get_theme()
        state_label = r.state.label  # Theme-aware label
        emoji = theme.emoji_for(state_label)
        score_pct = int(round((1.0 - r.smoothed_score) * 100))

        lines: list[str] = []
        lines.append(f"  {emoji} Context Health: [{_mini_bar(1.0 - r.smoothed_score, 20)}] {score_pct}%")
        lines.append(f"  State: {state_label.upper()}")
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
            for reason in r.top_reasons[:3]:
                # Truncate long evidence strings
                if len(reason) > 80:
                    reason = reason[:77] + "..."
                lines.append(f"    • {reason}")

        return "\n".join(lines)
