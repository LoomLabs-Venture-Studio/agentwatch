"""Textual TUI application for real-time monitoring."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.reactive import reactive
from textual.widgets import Footer, Header, Static

from agentwatch.llm import DEFAULT_OLLAMA_MODEL
from agentwatch.themes import ascii_safe, get_theme, security_status_from_score
from agentwatch.ui.rot_widget import ContextHealthWidget, _mini_bar

if TYPE_CHECKING:
    from agentwatch.detectors.base import Warning
    from agentwatch.health.score import EfficiencyReport
    from agentwatch.parser.models import Action


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
        # Theme-driven, following the same pattern HealthBar (above) already
        # uses correctly -- see security_status_from_score()'s docstring for
        # why this is a dedicated 3-way (100/>50/else) mapping rather than
        # StatusTheme.status_from_score()'s 4-way 80/60/40 banding.
        theme = get_theme()
        status = security_status_from_score(self.score)
        emoji = theme.emoji_for(status)

        return f"""
  Security Score: {self.score}%
  Status: {emoji} {status.upper()}
  Active Alerts: {self.alert_count}
"""


class EfficiencyBar(Static):
    """Widget showing session efficiency as a progress bar with category breakdown."""

    def __init__(self, **kwargs):
        theme = get_theme()
        super().__init__(
            f"  Efficiency: [████████████████████] 100%  Status: {theme.level_0.upper()}\n"
            f"  Session is {theme.level_0}",
            **kwargs,
        )
        self._report: EfficiencyReport | None = None

    def update_efficiency(self, report: "EfficiencyReport") -> None:
        self._report = report
        self.update(self._build_content())

    def _build_content(self) -> str:
        r = self._report
        if r is None:
            return "  Efficiency: waiting for data" + ascii_safe("…", "...")

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
            (
                "Pressure",
                r.penalty_context,
                f"{r.context_usage_pct:.0f}% ctx, {burn_k:.1f}k tok/min",
            ),
            ("Cache", r.penalty_cache, f"{r.cache_hit_rate * 100:.0f}% hit rate"),
            (
                "Pacing",
                r.penalty_pacing,
                f"{r.duration_minutes:.0f}min, {r.actions_per_turn:.1f} act/turn",
            ),
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
                lines.append(f"     {ascii_safe('→', '->')} {detail_line}")

            # Show suggestion
            if w.suggestion:
                # Wrap long suggestions
                suggestion = w.suggestion
                if len(suggestion) > 90:
                    suggestion = suggestion[:87] + "..."
                lines.append(f"     {ascii_safe('💡', '[TIP]')} {suggestion}")

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

        if len(self._warnings) > 8:
            lines.append(f"  ... and {len(self._warnings) - 8} more")

        return "\n".join(lines)

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
        return (
            f"  Actions: {self._action_count}  Errors: {self._error_count}  "
            f"Duration: {int(self._duration)}m"
        )


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
        siem_log: Path | None = None,
        llm: bool = False,
        llm_model: str = DEFAULT_OLLAMA_MODEL,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.log_path = log_path
        self.security_mode = security_mode
        self.siem_log = siem_log
        self.llm = llm
        self.llm_model = llm_model
        self._buffer = None
        self._detector_registry = None
        self._rot_scorer = None
        self._refreshing = False
        self._alerted_signals: set[str] = set()
        self._siem_exporter = None
        self._llm_assessor = None

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
        from agentwatch.parser import ActionBuffer, AiderLogWatcher, CursorWatcher, LogWatcher

        self._buffer = ActionBuffer()
        mode = "all" if self.security_mode else "health"
        self._detector_registry = create_registry(mode=mode)
        self._rot_scorer = RotScorer()

        if self.siem_log is not None or self.llm:
            from agentwatch.ui.live_integrations import LiveLlmAssessor, LiveSiemExporter

            if self.siem_log is not None:
                self._siem_exporter = LiveSiemExporter(
                    self.siem_log, source_log=str(self.log_path)
                )
            if self.llm:
                self._llm_assessor = LiveLlmAssessor(self.llm_model)

        # Set up log watcher. .md is an Aider Markdown chat-history transcript
        # (PLAYBOOK Sprint 6 item 6 / Sprint 7 -- live tailing); .vscdb is a
        # Cursor state.vscdb store (closes the "single-agent watch --log
        # <state.vscdb>" gap PLAYBOOK Sprint 7 explicitly left out of scope);
        # everything else is JSONL (Claude Code/Moltbot/Codex), handled by
        # LogWatcher's own format auto-detection.
        self.watcher = None
        if self.log_path.suffix == ".md":
            self.watcher = AiderLogWatcher(self.log_path)
        elif self.log_path.suffix == ".vscdb":
            composer_id = self._resolve_cursor_composer_id()
            if composer_id is None:
                # No crash: mirrors how LogWatcher/AiderLogWatcher degrade to
                # an empty, idle dashboard (0 actions, default 100% health)
                # when their target file is missing/unreadable -- surfaced
                # here via a toast since a Cursor DB with no matching
                # composer wouldn't otherwise produce any visible signal.
                self.notify(
                    "No active Cursor agent-mode conversation found in this "
                    "state.vscdb (Cursor may not be running, or the DB has "
                    "no agent-mode composer yet) -- showing an idle "
                    "dashboard.",
                    title="Cursor",
                    severity="warning",
                    timeout=10,
                )
            else:
                self.watcher = CursorWatcher(self.log_path, composer_id_filter=composer_id)
        else:
            self.watcher = LogWatcher(self.log_path)

        # Start watching in background (skipped entirely for the "no
        # matching Cursor composer" case above -- self.watcher stays None
        # and the dashboard just renders its idle/default state).
        if self.watcher is not None:
            self.watcher.on_action(self._on_action)
            self.run_worker(self.watcher.watch_with_callbacks())

        self.refresh_display()

        # Set up periodic refresh as backup (1s for responsive feel)
        self.set_interval(1.0, self.refresh_display)

    def _resolve_cursor_composer_id(self) -> str | None:
        """Auto-pick the most-recently-active agent-mode composer for a
        single-agent Cursor ``--log <state.vscdb>`` watch.

        Mirrors ``cursor_source.parse_cursor_session()``'s auto-detect
        convention (which ``parser/logs.py::parse_file()``'s ``.vscdb``
        dispatch already uses for the one-shot ``check``/``security-scan``
        path) rather than reinventing selection logic:
        ``select_latest_agent_composer()`` picks the newest non-archived,
        non-draft, ``unifiedMode == "agent"`` composer.

        Returns ``None`` (never raises) for every failure mode -- DB file
        missing/unreadable (e.g. an explicit path that doesn't actually
        exist, or a genuinely corrupt file), or no qualifying composer in
        an otherwise-readable DB -- so ``on_mount`` can degrade to an idle
        dashboard instead of crashing the TUI on startup.
        """
        from agentwatch.parser.cursor_source import (
            fetch_composer_headers,
            open_readonly,
            select_latest_agent_composer,
        )

        try:
            conn = open_readonly(self.log_path)
        except Exception:
            return None
        try:
            headers = fetch_composer_headers(conn)
        except Exception:
            return None
        finally:
            conn.close()
        return select_latest_agent_composer(headers)

    def _on_action(self, action: Action) -> None:
        """Callback for new actions from watcher."""
        # NOTE: must be `is not None`, not a bare truthy check. ActionBuffer
        # defines __len__ but not __bool__, so a freshly-created *empty*
        # buffer (len 0, but very much initialized -- see on_mount) is
        # falsy. A bare `if self._buffer:` here silently drops the first
        # action delivered after on_mount, which means the buffer never
        # gains any actions, which means it stays empty (and falsy)
        # forever -- no action is ever recorded.
        if self._buffer is not None:
            self._buffer.add(action)
            # The 1s interval timer handles refreshes — don't pile up extra
            # calls via call_after_refresh, which was causing sporadic updates
            # when compute time exceeded the interval.

    def refresh_display(self) -> None:
        """Update all widgets with current data."""
        # Same ActionBuffer __len__-without-__bool__ pitfall as _on_action
        # above: this guard means "have _buffer/_detector_registry been
        # initialized" (they're set together in on_mount), not "is the
        # buffer non-empty" -- so it must check identity against None
        # rather than truthiness, or the very first refresh_display() call
        # in on_mount (before any action has arrived) skips rendering.
        if self._buffer is None or self._detector_registry is None:
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

        # SIEM export (new warnings only, by content-based dedup key -- see
        # live_integrations module docstring for why) and throttled Tier-2
        # LLM triage. Both degrade to a one-time notify() rather than
        # raising -- neither may ever crash this long-running dashboard.
        if self._siem_exporter is not None:
            session_id = self._buffer.actions[0].session_id if self._buffer.actions else None
            siem_error = self._siem_exporter.export_new(warnings, session_id=session_id)
            if siem_error:
                self.notify(siem_error, title="SIEM export failed", severity="error", timeout=10)

        if self._llm_assessor is not None:
            # Re-attach any previously-cached verdict before this tick's
            # warnings render -- check_all() built brand new Warning objects,
            # so nothing survives from a prior tick without this.
            self._llm_assessor.stamp(warnings)
            if self._llm_assessor.due():
                new_warnings = self._llm_assessor.new_warnings(warnings)
                self._llm_assessor.mark_run()
                self.run_worker(self._run_llm_batch(new_warnings))

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
            self._fire_secret_alerts(warnings)

        # Update efficiency bar
        self.query_one("#efficiency-bar", EfficiencyBar).update_efficiency(eff)

        # Update context health
        if rot_report is not None:
            self.query_one("#context-health", ContextHealthWidget).update_report(
                rot_report, peak_context_tokens=self._buffer.stats.peak_context_tokens
            )

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

    async def _run_llm_batch(self, new_warnings: list["Warning"]) -> None:
        """Run Tier-2 assessment for *new_warnings* off the render path.

        `LiveLlmAssessor.run_batch` makes real blocking Ollama HTTP calls;
        `asyncio.to_thread` keeps that off the event loop so a slow/hanging
        local model can never stall the TUI's render tick.
        """
        assessor = self._llm_assessor
        if assessor is None:
            return
        error = await asyncio.to_thread(assessor.run_batch, new_warnings)
        if error:
            self.notify(error, title="Tier-2 LLM unavailable", severity="warning", timeout=10)

    def on_unmount(self) -> None:
        """Flush and release the SIEM log file handle on app exit."""
        if self._siem_exporter is not None:
            self._siem_exporter.close()

    def _fire_secret_alerts(self, warnings: list["Warning"]) -> None:
        """Fire toast notifications for new secret leak warnings."""
        for w in warnings:
            if w.signal != "secret_leak":
                continue
            d = w.details
            key = (
                f"secret_leak:{d.get('secret_type', '')}:"
                f"{d.get('channel', '')}:{d.get('file_path', '')}"
            )
            if key in self._alerted_signals:
                continue
            self._alerted_signals.add(key)
            msg = f"{d.get('secret_type', 'secret')} in {d.get('channel', 'unknown')}"
            if d.get("file_path"):
                msg += f"\n{d['file_path']}"
            if d.get("remediation"):
                msg += f"\n{d['remediation']}"
            self.notify(msg, title="SECURITY ALERT", severity="error", timeout=15)
            if w.severity.value == "critical":
                self.bell()

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
