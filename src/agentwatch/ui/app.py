"""Textual TUI application for real-time monitoring."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Footer, Header, Static

if TYPE_CHECKING:
    from agentwatch.detectors.base import Warning
    from agentwatch.health.score import HealthReport


class HealthBar(Static):
    """Widget showing overall health as a progress bar."""
    
    score = reactive(100)
    status = reactive("healthy")
    
    def render(self) -> str:
        # Create a simple ASCII progress bar
        filled = int(self.score / 5)  # 20 chars total
        bar = "█" * filled + "░" * (20 - filled)
        
        status_emoji = {
            "healthy": "✅",
            "warning": "⚠️",
            "critical": "🔴",
        }
        
        return f"""
  {status_emoji.get(self.status, '❓')} Overall Health: [{bar}] {self.score}%
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
    """Widget showing session efficiency as a progress bar."""

    def __init__(self, **kwargs):
        super().__init__("  Efficiency: [████████████████████] 100%  Status: EFFICIENT\n  Session is healthy", **kwargs)
        self._score = 100
        self._status = "efficient"
        self._recommendation = "Session is healthy"

    def update_efficiency(self, score: int, status: str, recommendation: str) -> None:
        self._score = score
        self._status = status
        self._recommendation = recommendation
        self.update(self._build_content())

    def _build_content(self) -> str:
        filled = int(self._score / 5)  # 20 chars total
        bar = "█" * filled + "░" * (20 - filled)

        status_emoji = {
            "efficient": "⚡",
            "degraded": "⚠️",
            "wasteful": "🔴",
        }

        emoji = status_emoji.get(self._status, "❓")
        return (
            f"  {emoji} Efficiency: [{bar}] {self._score}%  "
            f"Status: {self._status.upper()}\n"
            f"  {self._recommendation}"
        )


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
        from agentwatch.parser import ActionBuffer, LogWatcher
        
        self._buffer = ActionBuffer()
        mode = "all" if self.security_mode else "health"
        self._detector_registry = create_registry(mode=mode)
        
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
            # Request refresh on next idle
            self.call_after_refresh(self.refresh_display)
    
    def refresh_display(self) -> None:
        """Update all widgets with current data."""
        if not self._buffer or not self._detector_registry:
            return
        
        from agentwatch.health import calculate_health, calculate_security_score
        
        # Run detectors
        warnings = self._detector_registry.check_all(self._buffer)
        report = calculate_health(warnings, include_security=self.security_mode)
        
        # Update health bar
        health_bar = self.query_one("#health-bar", HealthBar)
        health_bar.score = report.overall_score
        health_bar.status = report.status
        
        # Update security status if enabled
        if self.security_mode:
            security_status = self.query_one("#security-status", SecurityStatus)
            security_status.score = calculate_security_score(warnings)
            security_status.alert_count = len(report.security_warnings)
        
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
