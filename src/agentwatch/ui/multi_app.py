"""Textual TUI application for multi-agent monitoring."""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.widgets import DataTable, Footer, Static

from agentwatch.agents import adapter_for, display_name
from agentwatch.alerts import BASELINE_S, _label, _usd, tui_warn, who
from agentwatch.coach import state_path
from agentwatch.detectors import create_registry
from agentwatch.detectors.base import Severity, format_usd, warning_dedup_key
from agentwatch.discovery import (
    AgentProcess,
    AgentTeam,
    DiscoveryCache,
    build_teams,
    find_running_agents,
)
from agentwatch.health import (
    calculate_efficiency,
    calculate_health,
    calculate_security_score,
    calculate_team_health,
)
from agentwatch.health.rot import RotScorer
from agentwatch.llm import DEFAULT_OLLAMA_MODEL
from agentwatch.net_sampler import (
    NOT_ATTRIBUTABLE,
    NetSampler,
    attach,
    attributable,
    endpoint_summary,
)
from agentwatch.parser import ActionBuffer, MultiLogWatcher
from agentwatch.statusline import _cost, state_dirs
from agentwatch.themes import ascii_safe, get_theme
from agentwatch.ui.app import WarningsList, _hm, plain_notify
from agentwatch.ui.detail import DetailScreen
from agentwatch.ui.live_integrations import LiveLlmAssessor, LiveSiemExporter

if TYPE_CHECKING:
    from agentwatch.alerts import Alerter
    from agentwatch.detectors.base import Warning
    from agentwatch.health.score import HealthReport

# (key, header, width or None for auto). Cells are rich Text, never markup.
COLUMNS = (
    ("dot", "", 1),
    ("agent", "AGENT", 14),
    ("project", "PROJECT", 14),
    ("health", "HEALTH", 6),
    ("cost", "COST", 8),
    ("ctx", "CTX", 4),
    ("last", "LAST", 4),
    ("signal", "TOP SIGNAL", None),
)
SORTS = ("attention", "cost", "recent")
IDLE_AFTER_S = 300  # no action for this long: shown as idle (○), sorted last
FLASH_S = 2.0  # a row whose data changed is shown bold this long
TREND_POINTS = 5  # HEALTH gets ▲/▼ when it moved this much ...
TREND_WINDOW_S = 60.0  # ... against its score this long ago
TREND_SETTLE_S = 5.0  # a session's first seconds (log history loading) set the reference
SIGNAL_WIDTH = 40
STOPPED_STYLE = "grey50"
FEED_MAX = 200  # event feed lines kept
BUDGET_WARN = 0.8  # feed line when a session reaches this share of --budget
BUDGET_WIDTH = 18  # COST / BUDGET column: "$4.12 / $5.00 ▮▮▮▯" ...
BUDGET_NARROW = 10  # ... or "$4.12 ▮▮▮▯" when started under 100 columns
COACH_EVERY_S = 2.0  # coach state files are stat'ed this often, read only when changed
_WIDTHS = {key: width for key, _, width in COLUMNS}
_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red", Severity.HIGH: "red",
    Severity.MEDIUM: "yellow", Severity.LOW: "dim",
}


@dataclass
class AgentItem:
    """One watched session's identity (a row of the sessions table)."""

    log_path: Path
    agent_type: str | None = None
    project_name: str | None = None
    pid: int | None = None
    depth: int = 0
    parent_agent_pid: int | None = None
    team_id: int | None = None
    uptime: str = ""
    process_status: str = "active"  # "active" or "stopped"

    def update_process_info(self, proc: AgentProcess) -> None:
        self.uptime = proc.uptime
        self.process_status = "stopped" if proc.command == "(stopped)" else "active"


def _ago(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    s = max(0, int(seconds))
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= size:
            return f"{s // size}{unit}"
    return f"{s}s"


def _age(buffer: ActionBuffer) -> float | None:
    """Seconds since the session's last action (log timestamps are naive UTC)."""
    last = buffer.stats.last_action_time
    if last is None:
        return None
    now = datetime.now(last.tzinfo or timezone.utc)
    if last.tzinfo is None:
        now = now.replace(tzinfo=None)
    return (now - last).total_seconds()


def _context_pct(buffer: ActionBuffer) -> int | None:
    """Window fill of the latest call; None when the window is unknown."""
    stats = buffer.stats
    window = stats.known_context_window
    if not (stats.last_context_tokens and window):
        return None
    return min(100, int(stats.last_context_tokens / window * 100))


def _top_warnings(warnings: list["Warning"], n: int) -> list["Warning"]:
    return sorted(warnings, key=lambda w: _SEVERITY_RANK[w.severity])[:n]


def _signal(warnings: list["Warning"]) -> tuple[str, str]:
    if not warnings:
        return "ok", "green"
    w = _top_warnings(warnings, 1)[0]
    label = w.signal.replace("_", " ")
    if w.details.get("tool"):
        label += f": {w.details['tool']}"
    count = w.details.get("count") or w.details.get("occurrences")
    if count:
        label += f" ({count}x)"
    if len(warnings) > 1:
        label += f" +{len(warnings) - 1}"
    return f"{ascii_safe('⚠', '!')} {label}", _SEVERITY_STYLE[w.severity]


def _text(column: str, value: str, style: str, width: int | None = None) -> Text:
    """A table cell: literal text (never markup), cut to its column."""
    text = Text(value, style=style, no_wrap=True)
    text.truncate(width or _WIDTHS[column] or SIGNAL_WIDTH, overflow="ellipsis")
    return text


def _budget_cell(cost: float | None, budget: float, narrow: bool = False) -> tuple[str, str]:
    """'$4.12 / $5.00 ▮▮▮▯' ('$4.12 ▮▮▮▯' narrow): amber from BUDGET_WARN, red when hit."""
    if cost is None:
        return "n/a", ""
    share = cost / budget
    full = min(4, int(share * 4))
    bar = ascii_safe("▮", "#") * full + ascii_safe("▯", "-") * (4 - full)
    style = "bold red" if share >= 1 else "yellow" if share >= BUDGET_WARN else ""
    limit = "" if narrow else f" / {_usd(budget)}"
    return f"{_usd(cost)}{limit} {bar}", style


def _loop_breaker_off() -> bool:
    return os.environ.get("AGENTWATCH_LOOP_BREAKER", "").strip().lower() == "off"


class MultiAgentWatchApp(App):
    """Unified dashboard for monitoring all active agents."""

    notify = plain_notify

    CSS = """
    #header {
        height: 1;
        padding: 0 1;
        background: $panel;
        text-wrap: nowrap;
        text-overflow: ellipsis;
    }

    #feed {
        height: 7;
        padding: 0 1;
        border: round $secondary;
        border-title-align: left;
    }

    #feed:focus {
        border: round $accent;
    }

    #feed-lines {
        width: 100%;
        text-wrap: nowrap;
        text-overflow: ellipsis;
    }

    #sessions {
        height: 1fr;
        border: round $accent;
        border-title-align: left;
        border-subtitle-align: right;
    }

    #selected {
        height: auto;
        max-height: 7;
        border: round $primary;
        padding: 0 1;
        text-wrap: nowrap;
        text-overflow: ellipsis;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "toggle_security", "Toggle Security"),
        ("o", "cycle_sort", "Sort"),
        ("e", "toggle_feed", "Events"),
        Binding("enter", "open_detail", "Detail", priority=True),
        Binding("escape", "focus_table", "Table", show=False),
    ]

    def __init__(
        self,
        watch_paths: list[Path] | None = None,
        security_mode: bool = False,
        agent_processes: list[AgentProcess] | None = None,
        siem_log: Path | None = None,
        llm: bool = False,
        llm_model: str = DEFAULT_OLLAMA_MODEL,
        alerter: Alerter | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.alerter = alerter
        self.watch_paths = watch_paths or []
        self.security_mode = security_mode
        self.siem_log = siem_log
        self.llm = llm
        self.llm_model = llm_model
        self.agents: dict[Path, dict] = {}  # path -> {buffer, registry, item, pid, team_id}
        self.teams: dict[int, AgentTeam] = {}  # team_id -> team (shown as a header row)
        self._team_scores: dict[int, int] = {}
        self._team_by_pid: dict[int, int] = {}  # pid -> team_id, kept in sync with self.agents
        self._refreshing = False
        self._scanning = False
        self._discovery_cache = DiscoveryCache()
        self.selected_path: Path | None = None
        self._alerted_signals: set[str] = set()
        self._process_mode = agent_processes is not None
        self._net_sampler = NetSampler()
        self.sort_mode = SORTS[0]
        self._cells: dict[str, dict[str, tuple[str, str]]] = {}  # row key -> shown cells
        self._dots: dict[str, Text] = {}  # row key -> its dot cell (identifies it to sort)
        self._data_sig: dict[str, tuple] = {}  # row key -> data shown (for the flash)
        self._flash_until: dict[str, float] = {}
        self._order: list[str] = []
        self._events: deque[Text] = deque(maxlen=FEED_MAX)  # newest first
        # Sessions seen before this (startup) are "loaded", later ones "started".
        self._loaded_until: float | None = float("inf")
        self._alerts = 0  # alerts sent this run (or new HIGH+ findings, no alert sinks)
        self._summary: tuple[int, int, int, float | None] = (0, 0, 0, None)
        # Budget crossings and alerts sent in a session's startup window: one
        # summary feed line (_flush_held) instead of one line each.
        self._held_budget: list[tuple[str, float]] = []  # (project, cost)
        self._held_alerts = 0
        self._holding = False  # at startup, an Alerter pass for a session in its window
        self._header_text = ""
        self._blocks = 0  # loop-breaker blocks seen this run (incl. already at startup)
        self._held_blocks = 0  # ... of those, seen in the startup window
        self._coach_next = 0.0  # monotonic time of the next coach state pass
        self._muted = False  # `s` rescoring: no per-finding feed lines
        self._budget_width: int | None = None  # COST / BUDGET column width (--budget)

        if agent_processes is not None:
            self._initial_processes = agent_processes
            self.watcher = MultiLogWatcher.from_processes(agent_processes)
        else:
            self._initial_processes = []
            self.watcher = MultiLogWatcher(self.watch_paths)

    @property
    def _budget(self) -> float | None:
        return self.alerter.budget if self.alerter is not None else None

    def compose(self) -> ComposeResult:
        self._header = Static(id="header", markup=False)
        yield self._header
        self._table = table = DataTable(id="sessions", cursor_type="row")
        table.border_title = "Sessions"
        table.border_subtitle = f"sort: {self.sort_mode}"
        for key, label, width in COLUMNS:
            if key == "cost" and self._budget is not None:
                # ponytail: chosen at startup; a later resize keeps it.
                self._budget_width = BUDGET_WIDTH if self.size.width >= 100 else BUDGET_NARROW
                narrow = self._budget_width == BUDGET_NARROW
                label, width = "COST/BUDGT" if narrow else "COST / BUDGET", self._budget_width
            table.add_column(label, key=key, width=width)
        yield table
        self._selected = Static(
            "Waiting for sessions" + ascii_safe("…", "..."), id="selected", markup=False
        )
        yield self._selected
        self._feed_lines = Static(id="feed-lines", markup=False)
        self._feed = VerticalScroll(self._feed_lines, id="feed")
        self._feed.border_title = "Events"
        yield self._feed
        yield Footer()

    def _new_agent_state(
        self,
        *,
        buffer: ActionBuffer,
        registry,
        item: AgentItem,
        pid: int | None,
        team_id: int | None,
        log_path: Path,
        agent_type: str | None,
    ) -> dict:
        """Build a fresh per-agent state dict.

        Each tracked agent gets its own `LiveSiemExporter`/`LiveLlmAssessor`
        instance (when `--siem-log`/`--llm` are set) -- these carry
        per-agent dedup/throttle state, so one agent's SIEM export or LLM
        throttle timer is fully independent of every other agent's.
        """
        return {
            "buffer": buffer,
            "registry": registry,
            "item": item,
            "rot_scorer": RotScorer(),
            "pid": pid,
            "team_id": team_id,
            "_last_count": -1,
            "_last_report": None,
            "siem_exporter": (
                LiveSiemExporter(self.siem_log, agent_type=agent_type, source_log=str(log_path))
                if self.siem_log is not None
                else None
            ),
            "llm_assessor": LiveLlmAssessor(self.llm_model) if self.llm else None,
        }

    def _add_agent(self, log_path: Path, proc: AgentProcess | None) -> None:
        """Start tracking *log_path* (its table row appears on the next tick)."""
        if proc:
            item = AgentItem(
                log_path,
                agent_type=proc.agent_type,
                project_name=proc.project_name,
                pid=proc.pid,
                depth=proc.depth,
                parent_agent_pid=proc.parent_agent_pid,
                team_id=proc.team_id,
                uptime=proc.uptime,
            )
        else:
            item = AgentItem(log_path)
        state = self._new_agent_state(
            buffer=ActionBuffer(max_size=2000),
            registry=create_registry(mode="all" if self.security_mode else "health"),
            item=item,
            pid=item.pid,
            team_id=item.team_id,
            log_path=log_path,
            agent_type=item.agent_type,
        )
        if not proc:  # --all-logs: name the agent for the table only (alerts keep None)
            adapter = adapter_for(log_path)
            state["agent_name"] = adapter.name if adapter else None
        self.agents[log_path] = state
        self._track_net(state, proc)
        if item.pid is not None and item.team_id is not None:
            self._team_by_pid[item.pid] = item.team_id
        if self.selected_path is None:
            self.selected_path = log_path
        if self._loaded_until is None:
            name = who(item.agent_type or state.get("agent_name"), item.project_name)
            self._event(f"{ascii_safe('▶', '>')} {name} started")

    def _track_net(self, state: dict, proc: AgentProcess | None) -> None:
        """Sample *proc*'s sockets if it is a real per-agent process."""
        if proc and attributable(proc):
            self._net_sampler.track(proc.pid)
            state["net_sampled"] = True

    def _repid(self, state: dict, proc: AgentProcess) -> None:
        """A new process took over this log: drop the old pid, sample the new."""
        old = state["pid"]
        state["pid"] = proc.pid
        if old is not None and not any(d.get("pid") == old for d in self.agents.values()):
            self._team_by_pid.pop(old, None)
            self._net_sampler.untrack(old)
        if proc.team_id is not None:
            self._team_by_pid[proc.pid] = proc.team_id
        state["net_sampled"] = False
        self._track_net(state, proc)

    def on_mount(self) -> None:
        """Called when app starts."""
        self.title = "AgentWatch - Multi-Agent Dashboard"
        if self.security_mode:
            self.title += " [SECURITY]"
        self._loaded_until = time.monotonic() + BASELINE_S
        if self.alerter is not None:
            self.alerter.on_send = self._alert_sent
            if not self.is_headless:
                self.alerter.warn = tui_warn(self)

        # Team header rows for the initial processes
        for team in build_teams(self._initial_processes):
            if team.member_count > 1:
                self.teams[team.team_id] = team

        # Start the multi-watcher
        self.run_worker(self._watch_loop())

        # Periodic UI update (1s for responsive feel)
        self.set_interval(1.0, self.refresh_ui)

        # Periodic process re-scan if in process mode
        if self._process_mode:
            self._net_sampler.start()  # --all-logs has no pids: no sampling
            self.set_interval(5.0, self._refresh_processes)

    async def _watch_loop(self) -> None:
        """Background loop to process events from the multi-watcher."""
        async for event_type, data in self.watcher.watch():
            if event_type == "agent_added":
                if data not in self.agents:
                    self._add_agent(data, self.watcher.get_process_meta(data))

            elif event_type == "action":
                action, path = data
                if path in self.agents:
                    state = self.agents[path]
                    if state.get("net_sampled"):
                        state["net_prev_end"] = attach(
                            self._net_sampler, state["pid"], action, state.get("net_prev_end")
                        )
                    state["buffer"].add(action)
                    # The 1s interval timer handles refreshes — don't pile up
                    # extra calls that cause sporadic update behaviour.

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Cursor moved (arrows/click): select that session. A highlight
        already superseded by a later cursor move (rows added, then the
        cursor put back on the selected session) is ignored."""
        if event.cursor_row != self._table.cursor_row:
            return
        path = Path(event.row_key.value)
        if path in self.agents and path != self.selected_path:
            self.selected_path = path
            self.refresh_ui()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Enter (or a click on the highlighted row): open that session."""
        path = Path(event.row_key.value)
        if path in self.agents:  # not a team header row
            self.selected_path = path
            self.action_open_detail()

    def action_open_detail(self) -> None:
        """Enter: the selected session full screen (not on a team header row)."""
        table = self._table
        if self.selected_path not in self.agents or isinstance(self.screen, DetailScreen):
            return
        if table.row_count:
            row = table.coordinate_to_cell_key((table.cursor_row, 0)).row_key
            if row.value != str(self.selected_path):
                return
        self.push_screen(DetailScreen(self.selected_path))

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        """Main-screen keys are off (and out of the footer) in the detail view."""
        detail = isinstance(self.screen, DetailScreen)
        return not (detail and action in ("cycle_sort", "toggle_feed", "open_detail"))

    def refresh_ui(self) -> None:
        """Rescore what changed, then update the table, the Selected strip
        and the header."""
        # Shutting down: a queued RowHighlighted or timer tick can still
        # arrive while the screens' widgets are removed or after they are popped.
        if self._refreshing or not self.is_running or not self.screen_stack:
            return
        self._refreshing = True
        try:
            self._read_coach()
            if self.agents or self.teams:
                self._do_refresh_ui()
            if self._loaded_until is not None and time.monotonic() >= self._loaded_until:
                self._loaded_until = None
                n, blocks = len(self.agents), self._held_blocks
                line = f"{n} session{'s' * (n != 1)} loaded"
                if blocks:
                    line += f"; {blocks} loop block{'s' * (blocks != 1)} so far"
                self._event(line)
            self._flush_held()
            self._update_header()
        finally:
            self._refreshing = False

    # -- loop breaker (coach state) ----------------------------------------

    def _coach_key(self, data: dict) -> str | None:
        """The coach's state key for a Claude Code session: its session id, or
        `<session>.<agent_id>` for a subagent log; None for other agents."""
        item: AgentItem = data["item"]
        if (item.agent_type or data.get("agent_name")) != "claude-code":
            return None
        path = item.log_path
        if path.parent.name == "subagents" and path.stem.startswith("agent-"):
            return f"{path.parent.parent.name}.{path.stem.removeprefix('agent-')}"
        proc = self.watcher.get_process_meta(path) if self._process_mode else None
        actions = data["buffer"].actions
        return (proc and proc.session_id) or (actions and actions[0].session_id) or path.stem

    def _read_coach(self) -> None:
        """Every COACH_EVERY_S: stat each Claude Code session's coach state
        file and re-read only the ones whose mtime changed (read-only; a
        missing or corrupt file is no state). A block (armed.blocked on a
        new loop_id) is one feed line, or held for the startup line."""
        now = time.monotonic()
        if now < self._coach_next:
            return
        self._coach_next = now + COACH_EVERY_S
        listed = []  # one listdir per dir: only existing state files are stat'ed
        for directory in state_dirs():
            try:
                listed.append((directory, set(os.listdir(directory))))
            except OSError:
                pass
        for data in self.agents.values():
            if "_coach_name" not in data:
                key = data["_coach_key"] = self._coach_key(data)
                data["_coach_name"] = key and state_path(Path(), key).name
            name = data["_coach_name"]
            if name is None:
                continue
            newest = None
            for directory, names in listed:
                if name not in names:
                    continue
                path = directory / name
                try:
                    mtime = path.stat().st_mtime
                except OSError:
                    continue
                if newest is None or mtime > newest[1]:
                    newest = (path, mtime)
            if newest == data.get("_coach_file"):
                continue
            data["_coach_file"] = newest
            armed = {}
            try:
                if newest is not None:
                    armed = json.loads(newest[0].read_text(encoding="utf-8")).get("armed")
            except (OSError, ValueError, AttributeError):
                pass
            data["_armed"] = armed = armed if isinstance(armed, dict) else {}
            blocked = armed.get("loop_id") if armed.get("blocked") is True else None
            if blocked and blocked != data.get("_blocked_id"):
                self._blocks += 1
                if self._loaded_until is not None:
                    self._held_blocks += 1
                else:
                    project = data["item"].project_name or data["item"].log_path.name
                    cost = _cost(armed.get("cost_usd")).strip()
                    self._event(f"{ascii_safe('⛔', 'X')} {project} loop breaker blocked a "
                                f"repeated call{f' ({cost})' if cost else ''}", "bold red")
            data["_blocked_id"] = blocked

    @staticmethod
    def _blocked_signal(data: dict, warnings: list["Warning"]) -> tuple[str, str] | None:
        """TOP SIGNAL for a blocked session: tool and count from its loop
        warning when there is one (state holds only a hash, never the command)."""
        if not data.get("_blocked_id"):
            return None
        armed = data["_armed"]
        loop = next((w for w in warnings if w.signal == "loop"
                     and w.details.get("loop_id") == armed["loop_id"]), None)
        tool = loop.details.get("tool") if loop else None
        count = (loop.details.get("count") if loop else None) or armed.get("count")
        label = f"{ascii_safe('⛔', 'X')} loop blocked" + (f": {tool}" if tool else "")
        if isinstance(count, int) and not isinstance(count, bool):
            label += f" ({count}x)"
        cost = _cost(armed.get("cost_usd")).replace("~", "")
        return label + cost, "bold red"

    def _loop_breaker_text(self, data: dict) -> str:
        if _loop_breaker_off():
            state = "off (AGENTWATCH_LOOP_BREAKER=off)"
        elif data.get("_coach_key") is None:
            state = "n/a (Claude Code sessions only)"
        elif data.get("_coach_file") is None:
            state = "no coach state for this session (is the agentwatch plugin installed?)"
        elif data.get("_blocked_id"):
            state = "blocked once"
        elif data["_armed"].get("loop_id"):
            count = data["_armed"].get("count")
            state = "armed" + (f" ({count}x)" if isinstance(count, int) else "")
        else:
            state = "not armed"
        return f"  Loop breaker: {state}"

    def _score(self, data: dict) -> "HealthReport":
        """One agent's report, rescored only when it has new actions
        (action_count only grows) or its cache was dropped (`s`). Selected or
        not, so every session scores the same way. RotScorer is fed only new
        actions: each update() advances its EMA and state machine."""
        buffer = data["buffer"]
        count = buffer.stats.action_count
        if count == data["_last_count"] and data["_last_report"] is not None:
            return data["_last_report"]
        warnings = data["registry"].check_all(buffer)
        self._export_and_assess(data, warnings)
        eff = calculate_efficiency(warnings, buffer)
        rot_scorer = data.get("rot_scorer")
        if rot_scorer and count != data.get("_rot_count"):
            data["_rot"], data["_rot_count"] = rot_scorer.update(buffer), count
        rot = data.get("_rot")
        report = calculate_health(
            warnings,
            include_security=self.security_mode,
            efficiency_score=eff.score,
            rot_score=rot.smoothed_score if rot else None,
        )
        if self.security_mode:
            self._fire_secret_alerts(warnings, self._agent_label(data))
        self._holding = self._loaded_until is not None and self._in_window(data)
        try:
            self._alert(data, warnings, report)
        finally:
            self._holding = False
        self._feed_findings(data, warnings)
        data["_last_count"] = count
        data["_last_report"] = report
        data["_last_eff"] = eff.score
        data["_last_eff_report"] = eff
        return report

    def _do_refresh_ui(self) -> None:
        """Inner refresh logic, guarded by _refreshing flag."""
        reports = {path: self._score(data) for path, data in self.agents.items()}
        self._update_teams(reports)
        self._sync_table(reports)
        if self.selected_path in self.agents:
            self._update_selected(self.agents[self.selected_path], reports[self.selected_path])
        self._update_detail()

    def _update_teams(self, reports: dict[Path, "HealthReport"]) -> None:
        """Team health from member reports, grouped in one O(N) pass via the
        precomputed pid -> team_id map (self._team_by_pid)."""
        reports_by_team: dict[int, dict[int, "HealthReport"]] = {}
        for path, report in reports.items():
            pid = self.agents[path].get("pid")
            team_id = self._team_by_pid.get(pid) if pid is not None else None
            if team_id in self.teams:
                reports_by_team.setdefault(team_id, {})[pid] = report
        for team_id, members in reports_by_team.items():
            team = self.teams[team_id]
            team_report = calculate_team_health(members, root_pid=team_id, team_name=team.name)
            self._team_scores[team_id] = team_report.overall_score

    # -- sessions table ---------------------------------------------------

    @staticmethod
    def _trend(data: dict, score: int, now: float) -> str:
        """▲/▼ when *score* is TREND_POINTS off its value TREND_WINDOW_S ago.
        Scores are kept as (time, score) at each change; the reference is the
        newest one at least the window old; nothing is shown until the session
        has a window of history. Its first TREND_SETTLE_S with actions only
        set the reference (its log history is loading). Evaluated every tick,
        so an arrow clears on time for rows that are not rescored."""
        if not data["buffer"].stats.action_count:
            return ""
        scores: deque = data.setdefault("_scores", deque())
        if not scores or (len(scores) == 1 and now - scores[0][0] < TREND_SETTLE_S):
            start = scores[0][0] if scores else now
            scores.clear()
            scores.append((start, score))
        elif score != scores[-1][1]:
            scores.append((now, score))
        while len(scores) > 1 and scores[1][0] <= now - TREND_WINDOW_S:
            scores.popleft()
        if scores[0][0] > now - TREND_WINDOW_S:
            return ""
        diff = score - scores[0][1]
        if diff >= TREND_POINTS:
            return ascii_safe("▲", "^")
        if -diff >= TREND_POINTS:
            return ascii_safe("▼", "v")
        return ""

    @staticmethod
    def _agent_name(data: dict) -> str:
        agent = data["item"].agent_type or data.get("agent_name")
        return display_name(agent) if agent else "?"

    def _row_cells(
        self, data: dict, report: "HealthReport", age: float | None, now: float | None = None
    ) -> dict[str, tuple[str, str]]:
        """{column: (text, style)}; text is cut to the column when shown."""
        item: AgentItem = data["item"]
        buffer: ActionBuffer = data["buffer"]
        theme = get_theme()
        color = theme.color_for(report.status)
        active = item.process_status != "stopped" and age is not None and age < IDLE_AFTER_S

        score = report.overall_score
        trend = self._trend(data, score, time.monotonic() if now is None else now)
        agent = self._agent_name(data)
        if item.depth > 0:
            agent = "  " * (item.depth - 1) + f"{ascii_safe('└', '`-')} sub {agent}"
        cost = buffer.stats.estimated_cost
        ctx = _context_pct(buffer)
        cells = {
            "dot": (ascii_safe("●", "*") if active else ascii_safe("○", "o"), color),
            "agent": (agent, ""),
            "project": (item.project_name or item.log_path.name, ""),
            "health": (f"{score}% {trend}".rstrip(), color),
            "cost": ("n/a" if cost is None else format_usd(cost).lstrip("~"), "")
            if self._budget is None
            else _budget_cell(cost, self._budget, self._budget_width == BUDGET_NARROW),
            "ctx": ("-" if ctx is None else f"{ctx}%", ""),
            "last": (_ago(age), ""),
            "signal": self._blocked_signal(data, report.warnings) or _signal(report.warnings),
        }
        if item.process_status == "stopped":  # grey, so stopped differs from idle
            cells = {col: (v, STOPPED_STYLE) for col, (v, _) in cells.items()}
        return cells

    def _team_cells(self, team: AgentTeam) -> dict[str, tuple[str, str]]:
        score = self._team_scores.get(team.team_id)
        theme = get_theme()
        color = theme.color_for(theme.status_from_score(100 if score is None else score))
        members = f"{team.member_count} agents"
        if team.subagent_count:
            members += f", {team.subagent_count} sub"
        cells = dict.fromkeys(_WIDTHS, ("", ""))
        cells["agent"] = (f"TEAM {team.name}", "bold " + color)
        cells["project"] = (members, "")
        cells["health"] = ("" if score is None else f"{score}%", "bold " + color)
        return cells

    def _sort_key(self, data: dict, report: "HealthReport", age: float | None) -> tuple:
        """Lower sorts first."""
        recency = age if age is not None else float("inf")
        if self.sort_mode == "cost":
            cost = data["buffer"].stats.estimated_cost
            return (cost is None, -(cost or 0.0), recency)
        if self.sort_mode == "recent":
            return (recency,)
        idle = data["item"].process_status == "stopped" or recency >= IDLE_AFTER_S
        severities = {w.severity for w in report.warnings}
        if idle:
            bucket = 4
        elif (Severity.CRITICAL in severities or report.overall_score < 40
              or data.get("_blocked_id")):
            bucket = 0
        elif Severity.HIGH in severities:
            bucket = 1
        elif severities:
            bucket = 2
        else:
            bucket = 3
        return (bucket, recency)

    def _ordered_keys(self, keys: dict[Path, tuple]) -> list[str]:
        """Row keys in display order: groups (a team, or one session) by
        their most urgent member; in a group the team header, then members
        by depth so subagents sit under their parent."""
        groups: dict[object, list[Path]] = {}
        for path in keys:
            team_id = self.agents[path]["item"].team_id
            groups.setdefault(team_id if team_id is not None else path, []).append(path)
        for team_id in self.teams:
            groups.setdefault(team_id, [])

        def group_key(item):
            _, members = item
            return min((keys[p] for p in members), default=(9,))

        order: list[str] = []
        for gid, members in sorted(groups.items(), key=group_key):
            if gid in self.teams:
                order.append(f"team:{gid}")
            members.sort(key=lambda p: (self.agents[p]["item"].depth, str(p)))
            order.extend(str(p) for p in members)
        return order

    def _sync_table(self, reports: dict[Path, "HealthReport"]) -> None:
        """Update only the cells that changed; add rows for new sessions;
        reorder only when the order changed, keeping the cursor on the same
        session. Never clears the table."""
        table = self._table
        now = time.monotonic()
        rows: dict[str, dict[str, tuple[str, str]]] = {}
        sort_keys: dict[Path, tuple] = {}
        active = need_you = 0
        spend: float | None = None
        critical = get_theme().level_3
        for path, data in self.agents.items():
            age = _age(data["buffer"])
            report = reports[path]
            rows[str(path)] = cells = self._row_cells(data, report, age, now)
            sort_keys[path] = self._sort_key(data, report, age)
            active += cells["dot"][0] == ascii_safe("●", "*")
            need_you += data["item"].process_status != "stopped" and (
                report.status == critical
                or bool(data.get("_blocked_id"))
                or any(_SEVERITY_RANK[w.severity] <= 1 for w in report.warnings)
            )
            cost = data["buffer"].stats.estimated_cost
            if cost is not None:
                spend = (spend or 0.0) + cost
        self._summary = (len(self.agents), active, need_you, spend)
        for team_id, team in self.teams.items():
            rows[f"team:{team_id}"] = self._team_cells(team)

        for key, cells in rows.items():
            data_sig = tuple(v for col, v in cells.items() if col != "last")
            old_sig = self._data_sig.get(key)
            self._data_sig[key] = data_sig
            if old_sig is not None and old_sig != data_sig:
                self._flash_until[key] = now + FLASH_S
            if self._flash_until.get(key, 0) > now:
                cells = {col: (v, f"bold {style}") for col, (v, style) in cells.items()}
            shown = self._cells.get(key)
            if shown is None:
                texts = [_text(col, *v, self._width(col)) for col, v in cells.items()]
                table.add_row(*texts, key=key)
                self._dots[key] = texts[0]
            else:
                for col, v in cells.items():
                    if v != shown[col]:
                        text = _text(col, *v, self._width(col))
                        table.update_cell(key, col, text, update_width=col == "signal")
                        if col == "dot":
                            self._dots[key] = text
            self._cells[key] = cells

        order = self._ordered_keys(sort_keys)
        if order != self._order:
            self._order = order
            rank = {id(self._dots[key]): i for i, key in enumerate(order)}
            table.sort("dot", key=lambda dot: rank[id(dot)])
            if self.selected_path is not None:
                selected = str(self.selected_path)
                if selected in self._cells:
                    table.move_cursor(row=table.get_row_index(selected), animate=False)

    def _width(self, column: str) -> int | None:
        return self._budget_width if column == "cost" else None

    def _drop_row(self, path: Path) -> None:
        key = str(path)
        if key in self._cells:
            self._table.remove_row(key)
        for cache in (self._cells, self._data_sig, self._flash_until, self._dots):
            cache.pop(key, None)
        self._order = []

    # -- header and event feed --------------------------------------------

    def _update_header(self) -> None:
        """One line; redrawn only when its text changes (the clock: each second)."""
        n, active, need_you, spend = self._summary
        dot = ascii_safe(" · ", " | ")
        spent = "n/a" if spend is None else _usd(spend) if spend else "$0.00"
        parts = [
            f"{n} session{'s' * (n != 1)}{dot}{active} active{dot}{need_you} need you",
            f"on screen {spent}",
            f"alerts {self._alerts}",
            f"blocks {self._blocks}",
            *([f"budget {_usd(self._budget)}"] if self._budget is not None else []),
            f"{datetime.now():%H:%M:%S}",
        ]
        body = "   ".join(parts)
        title = "agentwatch" + (" [SECURITY]" if self.security_mode else "")
        room = self.size.width - 2
        if len(title) + 2 + len(body) > room:
            title = ""  # narrow: the counts and the clock matter more
            if len(body) > room:  # tighter, then without the clock
                parts[1] = spent
                body = "  ".join(parts)
                if len(body) > room:
                    body = "  ".join(parts[:-1])
        text = f"{title}  {body}" if title else body
        if text != self._header_text:
            self._header_text = text
            line = Text(text, no_wrap=True)
            line.stylize("bold", 0, len(title))
            self._header.update(line)

    def _event(self, message: str, style: str = "") -> None:
        """Add one line to the top of the event feed (literal text)."""
        line = Text(f"{datetime.now():%H:%M:%S} ", style="dim", no_wrap=True)
        line.append(message, style)
        self._events.appendleft(line)
        self._feed_lines.update(Text("\n").join(self._events))

    def _alert_sinks(self) -> list[str]:
        a = self.alerter
        return [] if a is None else [k for k, on in (("desktop", a.notify),
                                                     ("webhook", a.webhook)) if on]

    def _alert_sent(self, title: str, body: str) -> None:
        """Alerter.on_send: an alert was queued for its sinks."""
        sinks = self._alert_sinks()
        if sinks:
            self._alerts += 1
            if self._holding:
                self._held_alerts += 1
                return
            self._event(f"{ascii_safe('→', '->')} alert ({', '.join(sinks)}): "
                        f"{title.removeprefix('agentwatch: ')}", "magenta")

    def _feed_findings(self, data: dict, warnings: list["Warning"]) -> None:
        """Feed lines for one session's new and cleared findings (one per
        warning_dedup_key) and its --budget crossings. Like the Alerter, what
        a session shows in its first BASELINE_S with actions (its log history)
        is recorded silently."""
        item: AgentItem = data["item"]
        stats = data["buffer"].stats
        project = item.project_name or item.log_path.name
        quiet = self._in_window(data)
        found = {warning_dedup_key(w): w for w in warnings}
        if not (quiet or self._muted):
            shown: dict[str, str] = data.get("_feed_keys", {})
            count_alerts = not self._alert_sinks()
            for key, w in found.items():
                if key in shown:
                    continue
                n = w.details.get("count") or w.details.get("occurrences")
                cost = f" {w.cost_label}" if w.cost_label else ""
                self._event(f"{w.emoji} {project}: {_label(w.signal)}"
                            f"{f' ({n}x)' if n else ''}{cost}", _SEVERITY_STYLE[w.severity])
                self._alerts += count_alerts and _SEVERITY_RANK[w.severity] <= 1
            for key, label in shown.items():
                if key not in found:
                    self._event(f"{ascii_safe('✓', 'ok')} {project}: {label} cleared", "green")
        data["_feed_keys"] = {key: _label(w.signal) for key, w in found.items()}

        budget = self._budget
        cost = stats.estimated_cost
        if budget is None or cost is None or data.get("_budget_hit"):
            return
        if cost >= budget:
            data["_budget_hit"] = data["_budget_warned"] = True
            if quiet:
                self._held_budget.append((project, cost))
            else:
                self._event(f"$ {project}: budget {_usd(budget)} hit ({_usd(cost)})", "bold red")
        elif cost >= BUDGET_WARN * budget and not data.get("_budget_warned"):
            data["_budget_warned"] = True
            if not quiet:
                self._event(f"$ {project}: {BUDGET_WARN:.0%} of budget {_usd(budget)} "
                        f"({_usd(cost)})", "yellow")

    @staticmethod
    def _in_window(data: dict) -> bool:
        """True in a session's first BASELINE_S with actions (its log history
        loading) or before it has any; starts that clock."""
        now = time.monotonic()
        if data["buffer"].stats.action_count and "_feed_until" not in data:
            data["_feed_until"] = now + BASELINE_S
        return now < data.get("_feed_until", float("inf"))

    def _flush_held(self) -> None:
        """One feed line for the budget crossings and alerts held back in
        startup windows; at startup, after the "N sessions loaded" line."""
        if self._loaded_until is not None or not (self._held_budget or self._held_alerts):
            return
        held, self._held_budget = self._held_budget, []
        alerts, self._held_alerts = self._held_alerts, 0
        budget = self.alerter.budget if self.alerter is not None else None
        line = ""
        if len(held) == 1:
            line = f"$ {held[0][0]}: over budget {_usd(budget)} ({_usd(held[0][1])})"
        elif held:
            line = f"$ {len(held)} sessions over budget {_usd(budget)}"
        if alerts:
            sent = f"{alerts} alert{'s' * (alerts != 1)} sent ({', '.join(self._alert_sinks())})"
            line = f"{line}; {sent}" if line else f"{ascii_safe('→', '->')} {sent}"
        self._event(line, "bold red" if held else "magenta")

    def action_toggle_feed(self) -> None:
        """`e`: focus the event feed (to scroll it); again: back to the table."""
        (self._table if self.focused is self._feed else self._feed).focus()

    def action_focus_table(self) -> None:
        self._table.focus()

    # -- Selected strip ---------------------------------------------------

    def _title(self, data: dict) -> str:
        item: AgentItem = data["item"]
        title = [item.project_name or item.log_path.name, self._agent_name(data)]
        if item.pid:
            title.append(f"pid {item.pid}")
        if item.uptime:
            title.append(item.uptime)
        if item.process_status == "stopped":
            title.append("stopped")
        return ascii_safe(" · ", " | ").join(title)

    def _update_selected(self, data: dict, report: "HealthReport") -> None:
        buffer: ActionBuffer = data["buffer"]
        stats = buffer.stats
        ctx = _context_pct(buffer)
        cost = stats.estimated_cost
        cost_text = "n/a" if cost is None else format_usd(cost)
        if cost and stats.duration_minutes >= 1:
            cost_text += f" ({format_usd(cost / stats.duration_minutes)}/min)"
        security = str(len(report.security_warnings)) if self.security_mode else "off"
        net = endpoint_summary(buffer.actions) if data.get("net_sampled") else NOT_ATTRIBUTABLE
        lines = [
            "Selected: " + self._title(data),
            f"Health {report.overall_score}%  Efficiency {data.get('_last_eff', 100)}%  "
            f"Context {'n/a' if ctx is None else f'{ctx}%'}  Cost {cost_text}  "
            f"Security {security}  {net}",
        ]
        assessor: LiveLlmAssessor | None = data.get("llm_assessor")
        goal = assessor.stamp_goal_alignment() if assessor else None
        if goal is not None:
            label = {True: "[ALIGNED]", False: "[POSSIBLE DRIFT]"}.get(
                goal.get("aligned"), "[UNCLEAR]"
            )
            summary = goal.get("drift_summary") or "(model response could not be parsed)"
            lines.append(f"Tier-2 goal (advisory): {label} {summary}")
        arrow = ascii_safe("→", "->")
        for w in _top_warnings(report.warnings, 3 - (goal is not None)):
            detail = WarningsList._format_details(w)
            lines.append(f"{w.emoji} {w.message}" + (f" {arrow} {detail}" if detail else ""))
        if not report.warnings:
            lines.append("No active warnings")
        self._selected.update("\n".join(lines))

    # -- detail view -----------------------------------------------------

    def _update_detail(self) -> None:
        """Fill the open detail view from its session's cached scoring (no
        rescoring here). Each widget is updated only if its text changed."""
        screen = self.screen
        if not (isinstance(screen, DetailScreen) and screen.ready and screen.path in self.agents):
            return
        data = self.agents[screen.path]
        report: HealthReport | None = data["_last_report"]
        if report is None:
            return
        buffer: ActionBuffer = data["buffer"]
        stats = buffer.stats
        assessor: LiveLlmAssessor | None = data.get("llm_assessor")
        if assessor is not None:  # Tier-2 verdicts that arrived since the last scoring
            assessor.stamp(report.warnings)

        screen.text("detail-title", self._title(data) + f"  (health {report.overall_score}%)")
        health = screen.query_one("#d-health")
        health.score, health.status = report.overall_score, report.status
        if data.get("_last_eff_report") is not None:
            screen.query_one("#d-efficiency").update_efficiency(data["_last_eff_report"])
        if data.get("_rot") is not None:
            screen.query_one("#d-context").update_report(
                data["_rot"], peak_context_tokens=stats.peak_context_tokens
            )
        screen.query_one("#d-stats").update_stats(
            stats.activity_count, stats.error_count, stats.duration_minutes
        )
        warnings = screen.query_one("#d-warnings")
        warnings.update_goal_alignment(assessor.stamp_goal_alignment() if assessor else None)
        warnings.update_warnings(report.warnings)

        security = screen.query_one("#d-security")
        security.display = self.security_mode
        security.score = calculate_security_score(report.warnings)
        security.alert_count = len(report.security_warnings)
        counters = (
            f"  Raw counters (all actions, either mode):\n"
            f"    Credential file accesses  {stats.credential_accesses}\n"
            f"    Privilege commands        {stats.privilege_commands}\n"
            f"    Network actions           {stats.network_connections}\n"
            f"    Injection-like messages   {stats.injection_attempts}"
        )
        if not self.security_mode:
            counters = "  Security mode is off: press s to turn it on.\n\n" + counters
        screen.text("d-counters", counters)
        findings = screen.query_one("#d-findings")
        findings.display = self.security_mode
        findings.update_warnings(report.security_warnings)

        screen.text("d-loop", self._loop_breaker_text(data))
        screen.text("d-net", self._net_text(data))
        screen.text("d-process", self._process_text(data))

    def _net_text(self, data: dict) -> str:
        if not data.get("net_sampled"):
            why = "" if self._process_mode else " (--all-logs: no process to sample)"
            return f"  {NOT_ATTRIBUTABLE}{why}"
        actions = data["buffer"].actions
        seen = sorted({ep for a in actions for ep in a.observed_endpoints or ()})
        lines = [f"  {endpoint_summary(actions)} (remote ip:port seen during its actions)"]
        lines += [f"    {ip}:{port}" for ip, port in seen]
        return "\n".join(lines)

    def _process_text(self, data: dict) -> str:
        item: AgentItem = data["item"]
        actions = data["buffer"].actions
        proc = self.watcher.get_process_meta(item.log_path) if self._process_mode else None
        session = (proc and proc.session_id) or (actions[0].session_id if actions else None)
        rows = [("Type", self._agent_name(data))]
        if proc is None:
            rows += [(k, "n/a") for k in ("PID", "Uptime", "CWD", "CPU", "Memory", "Team")]
        else:
            if proc.depth:
                team = f"subagent (depth {proc.depth}) of pid {proc.parent_agent_pid}"
            else:
                team = "root"
            if proc.team_id is not None and proc.team_id != proc.pid:
                team += f", team {proc.team_id}"
            rows += [
                ("PID", str(proc.pid)),
                ("Uptime", proc.uptime or "n/a"),
                ("CWD", str(proc.working_directory or "n/a")),
                ("CPU", f"{proc.cpu_percent:.1f}%"),
                ("Memory", f"{proc.memory_mb:.0f} MB"),
                ("Team", team),
                ("Status", item.process_status),
            ]
        rows += [
            ("Session", session or "n/a"),
            ("Active", _hm(data["buffer"].stats.duration_minutes)),
            ("Log", str(item.log_path)),
        ]
        return "\n".join(f"  {k:8s} {v}" for k, v in rows)

    def _alert(self, agent_data: dict, warnings: list["Warning"], report: "HealthReport") -> None:
        """Feed one agent's scoring pass to `--notify`/`--webhook`/`--headless`."""
        if self.alerter is None:
            return
        item = agent_data["item"]
        stats = agent_data["buffer"].stats
        self.alerter.observe(
            str(item.log_path), item.agent_type, item.project_name or item.log_path.name,
            warnings, report, actions=stats.action_count, cost=stats.estimated_cost,
        )

    def _export_and_assess(self, agent_data: dict, warnings: list["Warning"]) -> None:
        """Per-agent SIEM export (new warnings only) + throttled Tier-2 LLM
        triage, mirroring `AgentWatchApp._do_refresh`'s wiring but scoped to
        one agent's own `LiveSiemExporter`/`LiveLlmAssessor` instance --
        each tracked agent's dedup/throttle state is fully independent of
        every other agent's (see `_new_agent_state`). Both failure paths
        degrade to a one-time `notify()`, never raising into the caller.
        """
        siem_exporter: LiveSiemExporter | None = agent_data.get("siem_exporter")
        if siem_exporter is not None:
            buffer = agent_data["buffer"]
            session_id = buffer.actions[0].session_id if buffer.actions else None
            error = siem_exporter.export_new(warnings, session_id=session_id)
            if error:
                label = self._agent_label(agent_data)
                self.notify(
                    f"[{label}] {error}", title="SIEM export failed", severity="error", timeout=10
                )

        llm_assessor: LiveLlmAssessor | None = agent_data.get("llm_assessor")
        if llm_assessor is not None:
            llm_assessor.stamp(warnings)
            if llm_assessor.due():
                new_warnings = llm_assessor.new_warnings(warnings)
                llm_assessor.mark_run()
                label = self._agent_label(agent_data)
                self.run_worker(self._run_llm_batch(llm_assessor, new_warnings, label))

            # Tier-2 goal-alignment advisory (Sprint 15's assess_goal_
            # alignment(), wired live here), dispatched per-agent just like
            # per-warning triage above -- each tracked agent's throttle
            # clock/cached advisory is independent (LiveLlmAssessor.
            # goal_alignment_due()/mark_goal_run()), so a background agent's
            # advisory stays fresh even while a different agent is selected
            # in the sidebar. Rendering the cached result into the widget is
            # the caller's job (only the *selected* agent's advisory is
            # ever shown -- see _do_refresh_ui), not this per-agent helper's.
            if llm_assessor.goal_alignment_due():
                llm_assessor.mark_goal_run()
                buffer = agent_data["buffer"]
                label = self._agent_label(agent_data)
                self.run_worker(self._run_goal_alignment_batch(llm_assessor, buffer, label))

    async def _run_llm_batch(
        self, assessor: LiveLlmAssessor, new_warnings: list["Warning"], agent_label: str
    ) -> None:
        """Run Tier-2 assessment for one agent's *new_warnings* off the
        render path -- `asyncio.to_thread` keeps the blocking Ollama HTTP
        calls off the event loop so a slow/hanging local model can never
        stall the dashboard's render tick, no matter how many agents are
        being watched concurrently.
        """
        error = await asyncio.to_thread(assessor.run_batch, new_warnings)
        if error:
            self.notify(
                f"[{agent_label}] {error}", title="Tier-2 LLM unavailable", severity="warning",
                timeout=10,
            )

    async def _run_goal_alignment_batch(
        self, assessor: LiveLlmAssessor, buffer: ActionBuffer, agent_label: str
    ) -> None:
        """Run one agent's Tier-2 goal-alignment advisory off the render
        path. Mirrors `_run_llm_batch` exactly (same `asyncio.to_thread`
        dispatch, same shared-assessor unavailable-notification dedup via
        `LiveLlmAssessor._ensure_analyzer`) but for `run_goal_alignment`'s
        single session-level assessment against *buffer* instead of a batch
        of per-warning triage calls.
        """
        error = await asyncio.to_thread(assessor.run_goal_alignment, buffer)
        if error:
            self.notify(
                f"[{agent_label}] {error}", title="Tier-2 LLM unavailable", severity="warning",
                timeout=10,
            )

    def on_unmount(self) -> None:
        """Flush and release every agent's SIEM log file handle on app exit,
        and stop the net sampler."""
        self._net_sampler.stop()
        for data in self.agents.values():
            siem_exporter: LiveSiemExporter | None = data.get("siem_exporter")
            if siem_exporter is not None:
                siem_exporter.close()

    @staticmethod
    def _agent_label(agent_data: dict) -> str:
        """Derive a short label for an agent from its table item."""
        item = agent_data.get("item")
        if item and getattr(item, "project_name", None):
            pid = getattr(item, "pid", None)
            return f"{item.project_name} (PID {pid})" if pid else item.project_name
        return str(agent_data.get("pid", "unknown"))

    def _fire_secret_alerts(self, warnings: list["Warning"], agent_label: str = "") -> None:
        """Fire toast notifications for new secret leak warnings."""
        for w in warnings:
            if w.signal != "secret_leak":
                continue
            d = w.details
            key = (
                f"secret_leak:{d.get('secret_type', '')}:"
                f"{d.get('channel', '')}:{d.get('file_path', '')}:{agent_label}"
            )
            if key in self._alerted_signals:
                continue
            self._alerted_signals.add(key)
            prefix = f"[{agent_label}] " if agent_label else ""
            msg = f"{prefix}{d.get('secret_type', 'secret')} in {d.get('channel', 'unknown')}"
            if d.get("file_path"):
                msg += f"\n{d['file_path']}"
            if d.get("remediation"):
                msg += f"\n{d['remediation']}"
            self.notify(msg, title="SECURITY ALERT", severity="error", timeout=15)
            if w.severity.value == "critical":
                self.bell()

    async def _refresh_processes(self) -> None:
        """Periodically re-scan running processes and update agent list."""
        if not self._process_mode:
            return
        if self._scanning:
            return  # a slow psutil scan is still in flight — don't stack ticks
        self._scanning = True
        try:
            # Only the blocking psutil-based process scan runs off the event
            # loop; the cache makes already-known PIDs skip cwd resolution
            # entirely on repeat scans. Everything below touches Textual
            # widgets/app state and must stay on the event loop, so we don't
            # offload any further.
            processes = await asyncio.to_thread(find_running_agents, self._discovery_cache)
        finally:
            self._scanning = False

        new_agents = self.watcher.refresh_processes(processes)

        for proc in new_agents:
            if proc.log_file and proc.log_file not in self.agents:
                self._add_agent(proc.log_file, proc)

        # Update process info on existing items
        for log_path, agent_data in self.agents.items():
            proc = self.watcher.get_process_meta(log_path)
            if proc:
                if proc.pid != agent_data["pid"]:
                    self._repid(agent_data, proc)
                item = agent_data["item"]
                was = item.process_status
                item.update_process_info(proc)
                if was != item.process_status == "stopped":
                    name = who(item.agent_type, item.project_name)
                    self._event(f"{ascii_safe('■', '#')} {name} stopped", "dim")

        # Remove agents that have been stopped for over 60 seconds
        expired = self.watcher.reap_stopped(timeout=60.0)
        for log_path in expired:
            agent_data = self.agents.pop(log_path, None)
            if agent_data:
                self._drop_row(log_path)
                reaped_pid = agent_data.get("pid")
                if reaped_pid is not None:
                    self._team_by_pid.pop(reaped_pid, None)
                    if not any(d.get("pid") == reaped_pid for d in self.agents.values()):
                        self._net_sampler.untrack(reaped_pid)
            if self.selected_path == log_path:
                self.selected_path = next(iter(self.agents), None)

    def action_toggle_security(self) -> None:
        """Toggle security mode across all agents."""
        self.security_mode = not self.security_mode
        self.title = "AgentWatch - Multi-Agent Dashboard"
        if self.security_mode:
            self.title += " [SECURITY]"

        # New registries, and drop every cached report so each session is
        # rescored on this refresh (RotScorer is not re-fed: no new actions).
        for data in self.agents.values():
            mode = "all" if self.security_mode else "health"
            data["registry"] = create_registry(mode=mode)
            data["_last_count"] = -1

        # The rescoring's new/cleared findings are one summary line, not a burst.
        self._muted = True
        try:
            self.refresh_ui()
        finally:
            self._muted = False
        if self.security_mode:
            n = sum(len(d["_last_report"].security_warnings) for d in self.agents.values()
                    if d["_last_report"] is not None)
            self._event(f"security on: {n} finding{'s' * (n != 1)}")
        else:
            self._event("security off")

    def action_cycle_sort(self) -> None:
        """`o`: attention -> cost -> recent."""
        self.sort_mode = SORTS[(SORTS.index(self.sort_mode) + 1) % len(SORTS)]
        self._table.border_subtitle = f"sort: {self.sort_mode}"
        self.refresh_ui()
