"""Textual TUI application for real-time monitoring."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Footer, Header, Static

from agentwatch.themes import get_theme
from agentwatch.ui.rot_widget import ContextHealthWidget, _mini_bar

if TYPE_CHECKING:
    from agentwatch.detectors.base import Warning
    from agentwatch.health.score import EfficiencyReport, HealthReport


class HealthBar(Static):
    """Widget showing overall health as a progress bar."""

    score = reactive(100)
    status = reactive("")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Initialize status with theme's best status
        self.status = get_theme().level_0

    def render(self) -> str:
        # Create a simple ASCII progress bar
        filled = int(self.score / 5)  # 20 chars total
        bar = "█" * filled + "░" * (20 - filled)

        theme = get_theme()
        emoji = theme.emoji_for(self.status)

        return f"""
  {emoji} Overall Health: [{bar}] {self.score}%
  Status: {self.status.upper()}
"""


class SecurityStatus(Static):
    """Widget showing security status."""
    
    score = reactive(100)
    alert_count = reactive(0)
    
    def render(self) -> str:
        if self.score == 100:
            status = "🛡️  SECURE"
            color = "green"
        elif self.score > 50:
            status = "⚠️  AT RISK"
            color = "yellow"
        else:
            status = "🚨 COMPROMISED"
            color = "red"
        
        return f"""
  Security Score: {self.score}%
  Status: {status}
  Active Alerts: {self.alert_count}
"""


class EfficiencyBar(Static):
    """Widget showing session efficiency as a progress bar with category breakdown."""

    def __init__(self, **kwargs):
        theme = get_theme()
        super().__init__(f"  Efficiency: [████████████████████] 100%  Status: {theme.level_0.upper()}\n  Session is {theme.level_0}", **kwargs)
        self._report: EfficiencyReport | None = None

    def update_efficiency(self, report: "EfficiencyReport") -> None:
        self._report = report
        self.update(self._build_content())

    def _build_content(self) -> str:
        r = self._report
        if r is None:
            return "  Efficiency: waiting for data…"

        filled = int(r.score / 5)  # 20 chars total
        bar = "█" * filled + "░" * (20 - filled)

        theme = get_theme()
        emoji = theme.emoji_for(r.status)
        lines: list[str] = []
        lines.append(
            f"  {emoji} Efficiency: [{bar}] {r.score}%  "
            f"Status: {r.status.upper()}"
        )
        lines.append("")

        # Per-category mini bars with detail
        burn_k = r.token_burn_rate / 1000
        categories = [
            ("Pressure", r.penalty_context, f"{r.context_usage_pct:.0f}% ctx, {burn_k:.1f}k tok/min"),
            ("Cache", r.penalty_cache, f"{r.cache_hit_rate * 100:.0f}% hit rate"),
            ("Pacing", r.penalty_pacing, f"{r.duration_minutes:.0f}min, {r.actions_per_turn:.1f} act/turn"),
        ]
        for label, penalty, detail in categories:
            mini = _mini_bar(penalty)
            lines.append(f"    {label:12s} [{mini}] {penalty:.2f}   {detail}")

        lines.append("")
        # Cost is informational — not scored (no log-reported cost data yet)
        lines.append(f"  Est. cost: ${r.cost_total:.2f} (${r.cost_velocity:.2f}/min)")
        lines.append(f"  {r.recommendation}")

        return "\n".join(lines)


class WarningsList(Static):
    """Widget showing list of active warnings."""

    def __init__(self, **kwargs):
        super().__init__("  No active warnings", **kwargs)
        self._warnings: list[Warning] = []

    def on_mount(self) -> None:
        self.update(self._build_content())

    def update_warnings(self, warnings: list["Warning"]) -> None:
        self._warnings = warnings
        self.update(self._build_content())

    def _build_content(self) -> str:
        if not self._warnings:
            return "  No active warnings"

        lines = ["  Active Warnings:", ""]
        for w in self._warnings[:8]:
            lines.append(f"  {w.emoji} [{w.signal:20}] {w.message}")

            # Show key details inline
            detail_line = self._format_details(w)
            if detail_line:
                lines.append(f"     → {detail_line}")

            # Show suggestion
            if w.suggestion:
                # Wrap long suggestions
                suggestion = w.suggestion
                if len(suggestion) > 90:
                    suggestion = suggestion[:87] + "..."
                lines.append(f"     💡 {suggestion}")

            lines.append("")  # Blank line between warnings

        if len(self._warnings) > 8:
            lines.append(f"  ... and {len(self._warnings) - 8} more")

        return "\n".join(lines)

    @staticmethod
    def _format_details(w: "Warning") -> str:
        """Extract the most useful detail from a warning for inline display."""
        d = w.details
        if not d:
            return ""

        # Show the actual error/command that's causing problems
        if "last_error" in d and d["last_error"]:
            return f"Error: {d['last_error'][:100]}"
        if "last_command" in d and d["last_command"]:
            err = f" → {d.get('last_error', '')[:60]}" if d.get("last_error") else ""
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
            return f"Error type: {d['error_class']} ({d.get('occurrences', d.get('failure_count', '?'))}x)"

        return ""


class StatsPanel(Static):
    """Widget showing session statistics."""

    def __init__(self, **kwargs):
        super().__init__("  Actions: 0  Errors: 0  Duration: 0m", **kwargs)
        self._action_count = 0
        self._error_count = 0
        self._duration = 0.0

    def on_mount(self) -> None:
        self.update(self._build_content())

    def update_stats(self, action_count: int, error_count: int, duration: float) -> None:
        self._action_count = action_count
        self._error_count = error_count
        self._duration = duration
        self.update(self._build_content())

    def _build_content(self) -> str:
        return f"  Actions: {self._action_count}  Errors: {self._error_count}  Duration: {int(self._duration)}m"


class AgentWatchApp(App):
    """Main TUI application for AgentWatch."""
    
    CSS = """
    Screen {
        layout: grid;
        grid-size: 2 3;
        grid-rows: auto 1fr auto;
    }
    
    #health-panel {
        column-span: 1;
        border: solid green;
        padding: 1;
    }
    
    #security-panel {
        column-span: 1;
        border: solid yellow;
        padding: 1;
    }
    
    #efficiency-panel {
        column-span: 2;
        border: solid cyan;
        padding: 1;
    }

    #context-health-panel {
        column-span: 2;
        border: solid magenta;
        padding: 1;
    }

    #warnings-panel {
        column-span: 2;
        border: solid red;
        padding: 1;
    }

    #stats-panel {
        column-span: 2;
        border: solid blue;
        padding: 1;
    }
    
    .hidden {
        display: none;
    }
    """
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("s", "toggle_security", "Toggle Security"),
    ]
    
    def __init__(
        self,
        log_path: Path,
        security_mode: bool = False,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.log_path = log_path
        self.security_mode = security_mode
        self._buffer = None
        self._detector_registry = None
        self._rot_scorer = None
        self._refreshing = False
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        yield Container(
            HealthBar(id="health-bar"),
            id="health-panel",
        )
        
        yield Container(
            SecurityStatus(id="security-status"),
            id="security-panel",
            classes="" if self.security_mode else "hidden",
        )

        yield Container(
            EfficiencyBar(id="efficiency-bar"),
            id="efficiency-panel",
        )

        yield Container(
            ContextHealthWidget(id="context-health"),
            id="context-health-panel",
        )

        yield Container(
            WarningsList(id="warnings-list"),
            id="warnings-panel",
        )
        
        yield Container(
            StatsPanel(id="stats-display"),
            id="stats-panel",
        )
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Called when app starts."""
        self.title = f"AgentWatch - {self.log_path.name}"
        if self.security_mode:
            self.title += " [SECURITY]"
        
        # Initialize components
        from agentwatch.detectors import create_registry
        from agentwatch.health.rot import RotScorer
        from agentwatch.parser import ActionBuffer, LogWatcher

        self._buffer = ActionBuffer()
        mode = "all" if self.security_mode else "health"
        self._detector_registry = create_registry(mode=mode)
        self._rot_scorer = RotScorer()
        
        # Set up log watcher
        self.watcher = LogWatcher(self.log_path)
        self.watcher.on_action(self._on_action)
        
        # Start watching in background
        self.run_worker(self.watcher.watch_with_callbacks())
        
        self.refresh_display()
        
        # Set up periodic refresh as backup (1s for responsive feel)
        self.set_interval(1.0, self.refresh_display)
    
    def _on_action(self, action: Action) -> None:
        """Callback for new actions from watcher."""
        if self._buffer:
            self._buffer.add(action)
            # The 1s interval timer handles refreshes — don't pile up extra
            # calls via call_after_refresh, which was causing sporadic updates
            # when compute time exceeded the interval.
    
    def refresh_display(self) -> None:
        """Update all widgets with current data."""
        if not self._buffer or not self._detector_registry:
            return
        if self._refreshing:
            return  # prevent overlapping refreshes
        self._refreshing = True
        try:
            self._do_refresh()
        finally:
            self._refreshing = False

    def _do_refresh(self) -> None:
        """Inner refresh logic, guarded by _refreshing flag."""

        from agentwatch.health import (
            calculate_efficiency,
            calculate_health,
            calculate_security_score,
        )

        # Run detectors
        warnings = self._detector_registry.check_all(self._buffer)

        # Compute efficiency and rot first so they feed into overall health
        eff = calculate_efficiency(warnings, self._buffer)

        rot_report = None
        rot_value: float | None = None
        if self._rot_scorer:
            rot_report = self._rot_scorer.update(self._buffer)
            rot_value = rot_report.smoothed_score

        report = calculate_health(
            warnings,
            include_security=self.security_mode,
            efficiency_score=eff.score,
            rot_score=rot_value,
        )

        # Update health bar
        health_bar = self.query_one("#health-bar", HealthBar)
        health_bar.score = report.overall_score
        health_bar.status = report.status

        # Update security status if enabled
        if self.security_mode:
            security_status = self.query_one("#security-status", SecurityStatus)
            security_status.score = calculate_security_score(warnings)
            security_status.alert_count = len(report.security_warnings)

        # Update efficiency bar
        self.query_one("#efficiency-bar", EfficiencyBar).update_efficiency(eff)

        # Update context health
        if rot_report is not None:
            self.query_one("#context-health", ContextHealthWidget).update_report(rot_report)

        # Update warnings list
        warnings_list = self.query_one("#warnings-list", WarningsList)
        warnings_list.update_warnings(warnings)
        
        # Update stats
        stats = self.query_one("#stats-display", StatsPanel)
        stats.update_stats(
            self._buffer.stats.action_count,
            self._buffer.stats.error_count,
            self._buffer.stats.duration_minutes,
        )
    
    def action_refresh(self) -> None:
        """Manual refresh action."""
        self.refresh_display()
    
    def action_toggle_security(self) -> None:
        """Toggle security panel visibility."""
        self.security_mode = not self.security_mode
        
        security_panel = self.query_one("#security-panel")
        if self.security_mode:
            security_panel.remove_class("hidden")
            self.title = f"AgentWatch - {self.log_path.name} [SECURITY]"
        else:
            security_panel.add_class("hidden")
            self.title = f"AgentWatch - {self.log_path.name}"
        
        # Recreate registry with new mode
        from agentwatch.detectors import create_registry
        mode = "all" if self.security_mode else "health"
        self._detector_registry = create_registry(mode=mode)
        
        self.refresh_display()
