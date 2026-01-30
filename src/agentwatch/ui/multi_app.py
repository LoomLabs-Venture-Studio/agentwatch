"""Textual TUI application for multi-agent monitoring."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Footer, Header, Static, ListItem, ListView, Label

from agentwatch.detectors import create_registry
from agentwatch.discovery import AgentProcess, find_running_agents
from agentwatch.parser import ActionBuffer, MultiLogWatcher
from agentwatch.health import calculate_efficiency, calculate_health, calculate_security_score
from agentwatch.ui.app import EfficiencyBar, HealthBar, SecurityStatus, WarningsList, StatsPanel

if TYPE_CHECKING:
    from agentwatch.parser.models import Action
    from agentwatch.detectors.base import Warning


class AgentItem(ListItem):
    """An item in the agent list representing a single session."""

    def __init__(
        self,
        log_path: Path,
        agent_type: str | None = None,
        project_name: str | None = None,
        pid: int | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.log_path = log_path
        self.agent_type = agent_type
        self.project_name = project_name
        self.pid = pid
        self.health_score = 100
        self.status = "healthy"
        self.cpu_percent: float = 0.0
        self.memory_mb: float = 0.0
        self.process_status: str = "active"  # "active" or "stopped"

    def compose(self) -> ComposeResult:
        if self.agent_type and self.project_name:
            yield Label(
                f"[{self.agent_type}] {self.project_name}", id="agent-name-label"
            )
            pid_text = f"PID {self.pid}" if self.pid else ""
            yield Label(pid_text, id="pid-label")
        else:
            yield Label(f"📄 {self.log_path.name}", id="agent-name-label")
            yield Label("", id="pid-label")
        yield Label(f"Health: {self.health_score}%", id="health-label")

    def update_status(self, score: int, status: str):
        self.health_score = score
        self.status = status
        label = self.query_one("#health-label", Label)
        health_text = f"Health: {score}%"
        if self.process_status == "stopped":
            health_text += " (stopped)"
        if self.cpu_percent > 0 or self.memory_mb > 0:
            health_text += f"  CPU:{self.cpu_percent:.1f}% MEM:{self.memory_mb:.0f}MB"
        label.update(health_text)

        # Color based on status
        if self.process_status == "stopped":
            self.styles.color = "grey"
        elif status == "healthy":
            self.styles.color = "green"
        elif status == "warning":
            self.styles.color = "yellow"
        else:
            self.styles.color = "red"

    def update_process_info(self, proc: AgentProcess) -> None:
        """Update live process metrics."""
        self.cpu_percent = proc.cpu_percent
        self.memory_mb = proc.memory_mb
        if proc.command == "(stopped)":
            self.process_status = "stopped"
        else:
            self.process_status = "active"


class MultiAgentWatchApp(App):
    """Unified dashboard for monitoring all active agents."""
    
    CSS = """
    Screen {
        layout: horizontal;
    }

    #agent-sidebar {
        width: 1fr;
        max-width: 40;
        border: solid $accent;
        padding: 1;
    }

    #detail-area {
        width: 3fr;
        border-left: tall $primary;
    }

    #health-bar {
        height: auto;
        border-bottom: solid green;
        padding: 1;
    }

    #efficiency-bar {
        height: auto;
        border-bottom: solid cyan;
        padding: 1;
    }

    #security-status {
        height: auto;
        border-bottom: solid yellow;
        padding: 1;
    }

    #warnings-list {
        height: 1fr;
        padding: 1;
        overflow-y: scroll;
        border-bottom: solid red;
    }

    #stats-display {
        height: auto;
        padding: 1;
        border-top: solid blue;
        background: $surface;
    }

    .hidden {
        display: none;
    }
    """
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "toggle_security", "Toggle Security"),
        ("c", "clear_cache", "Clear Cache"),
    ]
    
    def __init__(
        self,
        watch_paths: list[Path] | None = None,
        security_mode: bool = False,
        agent_processes: list[AgentProcess] | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.watch_paths = watch_paths or []
        self.security_mode = security_mode
        self.agents: dict[Path, dict] = {}  # path -> {buffer, registry, item}
        self.selected_path: Path | None = None
        self._process_mode = agent_processes is not None

        if agent_processes is not None:
            self.watcher = MultiLogWatcher.from_processes(agent_processes)
        else:
            self.watcher = MultiLogWatcher(self.watch_paths)
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with Vertical(id="agent-sidebar"):
            yield Label("Active Agents", variant="title")
            yield ListView(id="agent-list")
            
        with Vertical(id="detail-area"):
            yield HealthBar(id="health-bar")
            yield EfficiencyBar(id="efficiency-bar")
            yield SecurityStatus(
                id="security-status",
                classes="" if self.security_mode else "hidden",
            )
            yield WarningsList(id="warnings-list")
            yield StatsPanel(id="stats-display")
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Called when app starts."""
        self.title = "AgentWatch - Multi-Agent Dashboard"
        if self.security_mode:
            self.title += " [SECURITY]"

        # Start the multi-watcher
        self.run_worker(self._watch_loop())

        # Periodic UI update (1s for responsive feel)
        self.set_interval(1.0, self.refresh_ui)

        # Periodic process re-scan if in process mode
        if self._process_mode:
            self.set_interval(5.0, self._refresh_processes)

    async def _watch_loop(self) -> None:
        """Background loop to process events from the multi-watcher."""
        async for event_type, data in self.watcher.watch():
            if event_type == "agent_added":
                log_path = data
                if log_path not in self.agents:
                    # Initialize new agent state
                    buffer = ActionBuffer(max_size=2000)
                    mode = "all" if self.security_mode else "health"
                    registry = create_registry(mode=mode)

                    # Get process metadata if available
                    proc = self.watcher.get_process_meta(log_path)
                    if proc:
                        item = AgentItem(
                            log_path,
                            agent_type=proc.agent_type,
                            project_name=proc.project_name,
                            pid=proc.pid,
                        )
                        item.cpu_percent = proc.cpu_percent
                        item.memory_mb = proc.memory_mb
                    else:
                        item = AgentItem(log_path)

                    self.agents[log_path] = {
                        "buffer": buffer,
                        "registry": registry,
                        "item": item,
                    }

                    # Add to sidebar
                    agent_list = self.query_one("#agent-list", ListView)
                    agent_list.append(item)

                    # Auto-select if first
                    if self.selected_path is None:
                        self.selected_path = log_path
                        agent_list.index = 0

            elif event_type == "action":
                action, path = data
                if path in self.agents:
                    self.agents[path]["buffer"].add(action)
                    # Trigger immediate UI update for the active agent
                    if path == self.selected_path:
                        self.call_after_refresh(self.refresh_ui)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle selection of an agent in the sidebar."""
        item = event.item
        if isinstance(item, AgentItem):
            self.selected_path = item.log_path
            self.refresh_ui()

    def refresh_ui(self) -> None:
        """Update the main detail area based on selected agent."""
        if self.selected_path is None or self.selected_path not in self.agents:
            return
            
        agent_data = self.agents[self.selected_path]
        buffer = agent_data["buffer"]
        registry = agent_data["registry"]
        
        # Run detectors
        warnings = registry.check_all(buffer)
        report = calculate_health(warnings, include_security=self.security_mode)
        
        # Update sidebar item status
        agent_data["item"].update_status(report.overall_score, report.status)
        
        # Update main widgets
        self.query_one("#health-bar", HealthBar).score = report.overall_score
        self.query_one("#health-bar", HealthBar).status = report.status

        # Update efficiency
        eff = calculate_efficiency(warnings, buffer)
        self.query_one("#efficiency-bar", EfficiencyBar).update_efficiency(
            eff.score, eff.status, eff.recommendation,
        )

        if self.security_mode:
            security_status = self.query_one("#security-status", SecurityStatus)
            security_status.score = calculate_security_score(warnings)
            security_status.alert_count = len(report.security_warnings)
            
        self.query_one("#warnings-list", WarningsList).update_warnings(warnings)
        
        stats = self.query_one("#stats-display", StatsPanel)
        stats.update_stats(
            buffer.stats.action_count,
            buffer.stats.error_count,
            buffer.stats.duration_minutes,
        )

    def _refresh_processes(self) -> None:
        """Periodically re-scan running processes and update agent list."""
        if not self._process_mode:
            return

        processes = find_running_agents()
        new_agents = self.watcher.refresh_processes(processes)

        # Add new agents to sidebar
        agent_list = self.query_one("#agent-list", ListView)
        for proc in new_agents:
            if proc.log_file and proc.log_file not in self.agents:
                buffer = ActionBuffer(max_size=2000)
                mode = "all" if self.security_mode else "health"
                registry = create_registry(mode=mode)
                item = AgentItem(
                    proc.log_file,
                    agent_type=proc.agent_type,
                    project_name=proc.project_name,
                    pid=proc.pid,
                )
                item.cpu_percent = proc.cpu_percent
                item.memory_mb = proc.memory_mb
                self.agents[proc.log_file] = {
                    "buffer": buffer,
                    "registry": registry,
                    "item": item,
                }
                agent_list.append(item)

                # Start watching the new file
                if proc.log_file not in self.watcher._active_files:
                    from agentwatch.parser.watcher import LogWatcher as _LogWatcher

                    self.watcher._active_files.add(proc.log_file)
                    log_watcher = _LogWatcher(proc.log_file, session_id=proc.session_id)
                    self.watcher.watchers[proc.log_file] = log_watcher

        # Update process info on existing items
        for log_path, agent_data in self.agents.items():
            proc = self.watcher.get_process_meta(log_path)
            if proc:
                agent_data["item"].update_process_info(proc)

        # Remove agents that have been stopped for over 60 seconds
        expired = self.watcher.reap_stopped(timeout=60.0)
        for log_path in expired:
            agent_data = self.agents.pop(log_path, None)
            if agent_data:
                agent_data["item"].remove()
            if self.selected_path == log_path:
                self.selected_path = next(iter(self.agents), None)

    def action_toggle_security(self) -> None:
        """Toggle security mode across all agents."""
        self.security_mode = not self.security_mode

        security_panel = self.query_one("#security-status")
        if self.security_mode:
            security_panel.remove_class("hidden")
            self.title = "AgentWatch - Multi-Agent Dashboard [SECURITY]"
        else:
            security_panel.add_class("hidden")
            self.title = "AgentWatch - Multi-Agent Dashboard"

        # Recreate registries for all agents
        for path, data in self.agents.items():
            mode = "all" if self.security_mode else "health"
            data["registry"] = create_registry(mode=mode)

        self.refresh_ui()

    def action_clear_cache(self) -> None:
        """Clear Python bytecode caches."""
        import shutil
        package_dir = Path(__file__).resolve().parent.parent
        count = 0
        for cache_dir in package_dir.rglob("__pycache__"):
            shutil.rmtree(cache_dir)
            count += 1
        self.notify(f"Cleared {count} __pycache__ dir(s)")
        self.refresh_ui()
