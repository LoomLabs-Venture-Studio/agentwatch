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
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.widgets import DataTable, Footer, Input, Static, TabbedContent

from agentwatch.agents import DISPLAY_NAMES, adapter_for, display_name
from agentwatch.alerts import BASELINE_S, _label, _usd, tui_warn, who
from agentwatch.coach import state_path
from agentwatch.detectors import create_registry
from agentwatch.detectors.base import Severity, format_usd, warning_dedup_key
from agentwatch.detectors.registry import SessionScan
from agentwatch.detectors.security.network import _flaggable
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
from agentwatch.themes import ascii_safe, get_current_theme_name, get_theme
from agentwatch.ui import machine
from agentwatch.ui.app import WarningsList, _hm, hang, plain_notify, show
from agentwatch.ui.detail import DetailScreen
from agentwatch.ui.help import HelpScreen
from agentwatch.ui.live_integrations import LiveLlmAssessor, LiveSiemExporter

if TYPE_CHECKING:
    from agentwatch.alerts import Alerter
    from agentwatch.detectors.base import Warning
    from agentwatch.health.score import HealthReport

TREND_WIDTH = 8  # the TREND column: a sparkline of the last 8 samples
# (key, header, width or None for auto). Cells are rich Text, never markup.
COLUMNS = (
    ("dot", "", 1),
    ("agent", "AGENT", 14),
    ("project", "PROJECT", 14),
    ("health", "HEALTH", 6),
    ("cost", "COST", 8),
    ("trend", "TREND", TREND_WIDTH),  # label: _layout (health, or cost under cost sort)
    ("ctx", "CTX", 4),
    ("last", "LAST", 4),
    ("signal", "TOP SIGNAL", None),
)
SORTS = ("attention", "cost", "recent")
IDLE_AFTER_S = 300  # no action for this long: shown as idle (○), sorted last
WATCH_SLICE_S = 0.02  # longest the watch loop runs before yielding to the UI
IDLE_FOLD_S = 900  # no action for this long (or stopped): folded into one row (`a` shows)
FOLD_KEY = "fold"  # row key of the "N idle sessions" row
FLASH_S = 2.0  # a row whose data changed is shown bold this long
TREND_POINTS = 5  # HEALTH gets ▲/▼ when it moved this much ...
TREND_WINDOW_S = 60.0  # ... against its score this long ago
TREND_SETTLE_S = 5.0  # a session's first seconds (log history loading) set the reference
# History (memory only): a (time, health, cost, ctx) sample when they changed,
# at most every SAMPLE_S (a TREND_POINTS move: at once). 15s: HISTORY_MAX
# samples cover 15+ min, enough for a session's arc and the 60s arrow, and a
# busy session redraws its graphs at most 4x a minute.
SAMPLE_S = 15.0
HISTORY_MAX = 60
SPARK = "▁▂▃▄▅▆▇█"
SPARK_ASCII = "_.:-=+*#"
SPARK_STRIP = 16  # Selected strip graph width; the TREND column's is its width
GAUGE_WIDTH = 10
# TREND goes before TOP SIGNAL gets narrower than this: at 80 columns TOP SIGNAL
# keeps its 33 (a loop block's tool, count and cost); at 120 TREND shows, also
# with --budget. Narrow, TREND shows from 82 columns (84 with --budget).
SIGNAL_MIN = 25
NARROW_BELOW = 100  # columns: no AGENT/CTX columns, no Selected strip
SHORT_BELOW = 30  # rows: the Events panel shows 3 lines ...
TINY_BELOW = 20  # ... or is hidden (`e` shows it in the table's place)
PROJECT_NARROW = 12
STOPPED_STYLE = "grey50"
FEED_MAX = 200  # event feed lines kept
BUDGET_WARN = 0.8  # feed line when a session reaches this share of --budget
BUDGET_WIDTH = 18  # COST / BUDGET column: "$4.12 / $5.00 ▮▮▮▯" ...
BUDGET_NARROW = 10  # ... or "$4.12 ▮▮▮▯" under NARROW_BELOW columns
COACH_EVERY_S = 2.0  # coach state files are stat'ed this often, read only when changed
NAME_EVERY_S = 5.0  # Network tab: host names and listeners (~40ms psutil) refreshed this often
_WIDTHS = {key: width for key, _, width in COLUMNS}
_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red", Severity.HIGH: "dark_orange",
    Severity.MEDIUM: "yellow", Severity.LOW: "dim",
}
# One colour per known agent (AGENT column, Selected title): blues and
# purples, so none reads as a health or severity colour; readable on dark
# and light backgrounds.
_AGENT_PALETTE = ("dodger_blue2", "medium_purple2", "dark_cyan", "orchid", "steel_blue",
                  "slate_blue1")
AGENT_COLORS = {agent: _AGENT_PALETTE[i % len(_AGENT_PALETTE)]
                for i, agent in enumerate(DISPLAY_NAMES)}


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
        self.depth, self.parent_agent_pid = proc.depth, proc.parent_agent_pid
        self.team_id = proc.team_id


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


def _color(status_color: str) -> str:
    """A theme colour as a Rich colour: "orange" is a CSS name Rich does not
    know (a DataTable cell drops it)."""
    return "dark_orange" if status_color == "orange" else status_color


def _health_color(score: float) -> str:
    theme = get_theme()
    return _color(theme.color_for(theme.status_from_score(score)))


def _text(cell: tuple, width: int) -> Text:
    """A table cell (text, style[, spans]): literal text (never markup), cut
    to its column. Spans are (start, end, style) over the text."""
    text = Text(cell[0], style=cell[1], no_wrap=True)
    for start, end, style in cell[2] if len(cell) > 2 else ():
        text.stylize(style, start, end)
    text.truncate(width, overflow="ellipsis")
    return text


def _spark(values: list, width: int, lo: float | None = None,
           hi: float | None = None) -> str:
    """The last *width* values as a sparkline, newest right, padded left;
    scaled lo..hi (default: their min..max, a flat series at the bottom).
    None is a gap; "" when nothing is known. ASCII under --theme ascii."""
    values = values[-width:]
    known = [v for v in values if v is not None]
    if not known:
        return ""
    lo = min(known) if lo is None else lo
    hi = max(known) if hi is None else hi
    chars = ascii_safe(SPARK, SPARK_ASCII)
    top = len(chars) - 1

    def level(v: float) -> int:
        return 0 if hi <= lo else max(0, min(top, int((v - lo) / (hi - lo) * top + 0.5)))

    return "".join(" " if v is None else chars[level(v)] for v in values).rjust(width)


def _gauge(share: float, health: bool = False, pct: bool = True) -> tuple[str, str]:
    """('▮▮▮▮▮▮▮▮▯▯ 82%', style); `[########..] 82%` under --theme ascii.
    Green under BUDGET_WARN, amber to 100%, red from 100%; *health*: its
    status colour (red when low). *pct*: the share after the bar."""
    full = max(0, min(GAUGE_WIDTH, int(share * GAUGE_WIDTH)))
    if get_current_theme_name() == "ascii":
        bar = f"[{'#' * full}{'.' * (GAUGE_WIDTH - full)}]"
    else:
        bar = "▮" * full + "▯" * (GAUGE_WIDTH - full)
    if health:
        style = _health_color(share * 100)
    else:
        style = "green" if share < BUDGET_WARN else "yellow" if share < 1 else "bold red"
    return bar + (f" {round(share * 100)}%" if pct else ""), style


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


def window_label(seconds: float) -> str:
    """'24h', '2d': a --since window."""
    days, rest = divmod(int(seconds), 86400)
    return f"{days}d" if days >= 2 and not rest else f"{int(seconds) // 3600}h"


def _project_of(adapter, log_path: Path) -> str | None:
    """--all-logs: the project a log belongs to, as `agentwatch history` names
    it (a Claude Code transcript's recorded cwd, worktrees as their project,
    "~" for home; else its projects dir); None when unknown."""
    try:
        name = adapter.history_meta(log_path)[1]
        if name is None and adapter.name == "claude-code":
            from agentwatch.cc_stats import project_name, recorded_cwd

            name = project_name(recorded_cwd(log_path))
        return name
    except Exception:  # an adapter's reader must not stop the dashboard
        return None


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

    #filter {
        height: 1;
        border: none;
        padding: 0 1;
        display: none;
    }

    #filter:focus {
        border: none;
    }

    #sessions {
        height: 1fr;
        border: round $accent;
        border-title-align: left;
        border-subtitle-align: right;
    }

    #selected {
        height: auto;
        max-height: 8;
        border: round $primary;
        padding: 0 1;
        text-wrap: nowrap;
        text-overflow: ellipsis;
    }
    """

    BINDINGS = [  # footer order: most important first; all fit 80 columns
        Binding("enter", "open_detail", "Detail", priority=True),
        ("slash", "filter", "Filter"),
        ("a", "toggle_idle", "Idle"),
        ("question_mark", "help", "Help"),
        ("q", "quit", "Quit"),
        ("o", "cycle_sort", "Sort"),
        ("e", "toggle_feed", "Events"),
        ("s", "toggle_security", "Security"),
        ("d", "other_ai", "AI"),  # other AI on this machine (short: 80 columns)
        ("w", "report", "Report"),
        Binding("escape", "focus_table", "Table", show=False),
    ]

    # Other AI (ai_detect.detect) and the history sync + report: worker
    # threads / a subprocess on these intervals. Off: tests (conftest) and
    # --headless (nothing shows them).
    MACHINE_CHECKS = True
    DETECT_EVERY_S = 30.0
    HISTORY_EVERY_S = 300.0

    def __init__(
        self,
        watch_paths: list[Path] | None = None,
        security_mode: bool = False,
        agent_processes: list[AgentProcess] | None = None,
        siem_log: Path | None = None,
        llm: bool = False,
        llm_model: str = DEFAULT_OLLAMA_MODEL,
        alerter: Alerter | None = None,
        since: float | None = None,
        machine_checks: bool = True,
        session: Path | None = None,
        session_proc: AgentProcess | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._machine_checks = machine_checks and self.MACHINE_CHECKS
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
        # `watch` (session=) is process mode too, scoped to its one log
        self._process_mode = agent_processes is not None or session is not None
        self._net_sampler = NetSampler()
        self.sort_mode = SORTS[0]
        self._cells: dict[str, dict[str, tuple[str, str]]] = {}  # row key -> shown cells
        self._dots: dict[str, Text] = {}  # row key -> its dot cell (identifies it to sort)
        self._data_sig: dict[str, tuple] = {}  # row key -> data shown (for the flash)
        self._flash_until: dict[str, float] = {}
        self._order: list[str] = []
        self._parent_of: dict[Path, Path] = {}  # session -> its parent's (as of the last tick)
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
        self._selected_sig: tuple = ()  # what the Selected strip shows (_update_selected)
        self._blocks = 0  # loop-breaker blocks seen this run (incl. already at startup)
        self._held_blocks = 0  # ... of those, seen in the startup window
        self._coach_next = 0.0  # monotonic time of the next coach state pass
        self._muted = False  # `s` rescoring: no per-finding feed lines
        self._replay = None  # the security-toggle replay worker, while it runs
        # (narrow, Events height or 0, table columns): _layout, set on resize
        self._layout_now: tuple = ()
        self._widths: dict[str, int] = {}  # shown column -> width
        self._term_width = 0
        self._feed_open = False  # Events hidden (short terminal) and `e` shows it
        self.since = since  # --all-logs window in seconds (None: every log)
        self._show_idle = False  # `a`: idle sessions shown instead of folded
        self._filter = ""  # `/`: rows whose project/agent/signal contain this
        # Network tab (worker): host names by IP, net.Namer made on first use
        self._namer = None
        self._names: dict[str, tuple[str, str, str | None]] = {}
        self._naming = False
        self._name_next = 0.0
        # `d`: the last ai_detect result (None: failed), when, unmonitored names seen
        self._detected = None
        self._detected_at: float | None = None
        self._detecting = False
        self._unmonitored: set[str] | None = None  # running now (None: check failed)
        self._ai_seen: set[str] | None = None  # every one seen this run (None: no baseline)
        # `w` and the header: (today's spend, 7-day report) from history
        self._history: tuple[dict, dict] | None = None
        self._history_at: float | None = None
        self._history_failed = False
        self._syncing = False
        self._sync_proc: asyncio.subprocess.Process | None = None
        self.sync_seconds: float | None = None  # the last sync's duration
        # `watch`: the one log followed, opened in the detail view when it
        # appears; session_proc is its running agent, if one was found.
        self.session = session

        if session is not None:
            self._initial_processes = []
            self.watcher = MultiLogWatcher([session])
            if session_proc is not None:  # its pid, project, Cursor composer
                self.watcher._process_meta[session] = session_proc
        elif agent_processes is not None:
            self._initial_processes = agent_processes
            self.watcher = MultiLogWatcher.from_processes(agent_processes)
        else:
            self._initial_processes = []
            self.watcher = MultiLogWatcher(self.watch_paths, since=since)

    @property
    def _budget(self) -> float | None:
        return self.alerter.budget if self.alerter is not None else None

    @property
    def _narrow(self) -> bool:
        return bool(self._layout_now and self._layout_now[0])

    def compose(self) -> ComposeResult:
        self._header = Static(id="header", markup=False)
        yield self._header
        self._table = table = DataTable(id="sessions", cursor_type="row")
        table.border_title = "Sessions" + (
            f" (last {window_label(self.since)})" if self.since is not None else "")
        self._update_subtitle()
        yield table
        self._selected = Static(
            "Waiting for sessions" + ascii_safe("…", "..."), id="selected", markup=False
        )
        yield self._selected
        self._feed_lines = Static(id="feed-lines", markup=False)
        self._feed = VerticalScroll(self._feed_lines, id="feed")
        self._feed.border_title = "Events"
        yield self._feed
        self._filter_input = Input(id="filter", placeholder="filter: project, agent or signal")
        yield self._filter_input
        yield Footer(show_command_palette=False, compact=True)  # ^p still opens it
        self._apply_layout(self.size)

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
            "scan": SessionScan(registry),
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
            item.project_name = _project_of(adapter, log_path) if adapter else None
            if state["agent_name"] == "claude-code" and log_path.parent.name == "subagents":
                item.depth = 1  # <session>/subagents/agent-<id>.jsonl, under <session>.jsonl
                state["parent_log"] = log_path.parent.parent.with_suffix(".jsonl")
        self.agents[log_path] = state
        self._track_net(state, proc)
        if item.pid is not None and item.team_id is not None:
            self._team_by_pid[item.pid] = item.team_id
        if self.selected_path is None:
            self.selected_path = log_path
        if log_path == self.session:
            self.push_screen(DetailScreen(log_path))
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

        if self._machine_checks:
            self.run_worker(self._detect_ai())
            self.set_interval(self.DETECT_EVERY_S, self._detect_ai)
            self.run_worker(self._sync_history())
            self.set_interval(self.HISTORY_EVERY_S, self._sync_history)

    async def _watch_loop(self) -> None:
        """Background loop to process events from the multi-watcher."""
        slice_start = time.monotonic()
        async for event_type, data in self.watcher.watch():
            # A history burst arrives without the watcher ever suspending, and
            # each action is scanned: hand the loop back every WATCH_SLICE_S.
            if time.monotonic() - slice_start > WATCH_SLICE_S:
                await asyncio.sleep(0)
                slice_start = time.monotonic()
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
                    self._session_scan(state).add(state["buffer"], action)
                    # The 1s interval timer handles refreshes — don't pile up
                    # extra calls that cause sporadic update behaviour.

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Cursor moved (arrows/click): select that session. A highlight
        already superseded by a later cursor move (rows added, then the
        cursor put back on the selected session, or rows folded) is ignored."""
        table = self._table
        if event.cursor_row != table.cursor_row or not table.row_count or (
            table.coordinate_to_cell_key((table.cursor_row, 0)).row_key != event.row_key
        ):
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
        if not table.row_count or table.coordinate_to_cell_key(
                (table.cursor_row, 0)).row_key.value != str(self.selected_path):
            return  # a team or fold row, or a filter that matches nothing
        self.push_screen(DetailScreen(self.selected_path))

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        """Main-screen keys are off (and out of the footer) in the detail view."""
        if isinstance(self.screen, HelpScreen):
            return False  # q closes it (its own footer: "esc Close")
        if isinstance(self.screen, DetailScreen):
            return action not in ("cycle_sort", "toggle_feed", "open_detail",
                                  "toggle_idle", "filter")
        # Typing a filter: Enter submits it (no detail view).
        return not (action == "open_detail" and self.focused is self._filter_input)

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
                if self.since is not None:
                    line += f" (last {window_label(self.since)} of {self.watcher.total_logs} logs)"
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
            state = "off in this shell (AGENTWATCH_LOOP_BREAKER=off)"
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

    @staticmethod
    def _session_scan(data: dict) -> SessionScan:
        """The agent's scan object (kept findings), made on first use."""
        scan = data.get("scan")
        if scan is None:
            scan = data["scan"] = SessionScan(data["registry"])
        return scan

    def _score(self, data: dict) -> "HealthReport":
        """One agent's report, rescored only when its buffer changed (new
        actions, or a tool result landing on one; `revision` only grows) or its
        cache was dropped (`s`). Selected or
        not, so every session scores the same way. RotScorer is fed only new
        actions: each update() advances its EMA and state machine."""
        buffer = data["buffer"]
        count = buffer.revision
        scan = self._session_scan(data)
        if count == data["_last_count"] and data["_last_report"] is not None and not scan.pending:
            return data["_last_report"]
        warnings = scan.warnings(buffer)
        self._export_and_assess(data, warnings)
        eff = calculate_efficiency(warnings, buffer)
        rot_scorer = data.get("rot_scorer")
        actions_seen = buffer.stats.action_count
        if rot_scorer and actions_seen != data.get("_rot_count"):
            data["_rot"], data["_rot_count"] = rot_scorer.update(buffer), actions_seen
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
        if self.selected_path in self.agents and self._selected.display:
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
    def _sample(data: dict, values: tuple, now: float) -> tuple | None:
        """Keep the session's history (data["_hist"], HISTORY_MAX samples of
        (time, health, cost, ctx), memory only): a sample when *values*
        changed, at most every SAMPLE_S, at once for a TREND_POINTS move in
        health or context. Its first TREND_SETTLE_S with actions only set the
        first sample (its log history is loading). data["_samples"] counts
        appends (graphs are redrawn only when it moves).

        Returns the reference for the arrows: the newest sample at least
        TREND_WINDOW_S old, None until the session has that much history.
        Evaluated every tick, so an arrow clears on time without a sample."""
        if not data["buffer"].stats.action_count:
            return None
        hist = data.get("_hist")
        if hist is None:
            hist = data["_hist"] = deque(maxlen=HISTORY_MAX)
        last = hist[-1] if hist else None
        if last is None or (len(hist) == 1 and now - last[0] < TREND_SETTLE_S):
            if last is None or last[1:] != values:
                hist.clear()
                hist.append((now if last is None else last[0], *values))
                data["_samples"] = data.get("_samples", 0) + 1
        elif last[1:] != values and (now - last[0] >= SAMPLE_S or any(
                a is not None and b is not None and abs(a - b) >= TREND_POINTS
                for a, b in ((values[0], last[1]), (values[2], last[3])))):
            hist.append((now, *values))
            data["_samples"] += 1
        cutoff = now - TREND_WINDOW_S
        if hist[0][0] > cutoff:
            return None
        return next(s for s in reversed(hist) if s[0] <= cutoff)

    @staticmethod
    def _arrows(ref: tuple | None, values: tuple) -> dict[str, tuple[str, str]]:
        """{health|cost|ctx: (arrow, style)} vs *ref* (a minute ago): health
        ▲ green / ▼ red on a TREND_POINTS move; cost ▲ amber when it grew a
        cent; context ▲ amber / ▼ green on a TREND_POINTS move."""
        arrows = dict.fromkeys(("health", "cost", "ctx"), ("", ""))
        if ref is None:
            return arrows
        up, down = ascii_safe("▲", "^"), ascii_safe("▼", "v")
        for kind, now, then, step, rise, fall in (
            ("health", values[0], ref[1], TREND_POINTS, "green", "red"),
            ("cost", values[1], ref[2], 0.01, "yellow", "green"),
            ("ctx", values[2], ref[3], TREND_POINTS, "yellow", "green"),
        ):
            if now is None or then is None:
                continue
            if now - then >= step - 1e-9:
                arrows[kind] = (up, rise)
            elif then - now >= step - 1e-9:
                arrows[kind] = (down, fall)
        return arrows

    @staticmethod
    def _spark_cell(data: dict, kind: str, width: int) -> tuple:
        """(sparkline, style, spans) of the session's *kind* history; health
        and context scaled 0-100, health coloured by status per point; cost
        min..max. Cached until the next sample."""
        cache = data.setdefault("_sparks", {})
        n = data.get("_samples", 0)
        hit = cache.get((kind, width))
        if hit is not None and hit[0] == n:
            return hit[1]
        index = {"health": 1, "cost": 2, "ctx": 3}[kind]
        values = [s[index] for s in data.get("_hist", ())][-width:]
        if kind == "cost":
            cell: tuple = (_spark(values, width), "")
        else:
            text = _spark(values, width, 0, 100)
            spans = ()
            if kind == "health" and text:
                pad = width - len(values)
                spans = tuple((pad + i, pad + i + 1, _health_color(v))
                              for i, v in enumerate(values) if v is not None)
            cell = (text, "", spans)
        cache[(kind, width)] = (n, cell)
        return cell

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
        color = _health_color(report.overall_score)
        active = item.process_status != "stopped" and age is not None and age < IDLE_AFTER_S

        score = report.overall_score
        cost = buffer.stats.estimated_cost
        ctx = _context_pct(buffer)
        values = (score, None if cost is None else round(cost, 2), ctx)
        ref = self._sample(data, values, time.monotonic() if now is None else now)
        data["_arrows"] = arrows = self._arrows(ref, values)
        trend, trend_style = arrows["health"]
        agent = self._agent_name(data)
        project = item.project_name or item.log_path.name
        if item.depth > 0:
            indent = "  " * (item.depth - 1) + ascii_safe("└", "`-")
            agent = f"{indent} sub {agent}"
            if self._narrow:  # no AGENT column: the tree is in PROJECT
                project = f"{indent} {project}"
        health = f"{score}%"
        cells = {
            "dot": (ascii_safe("●", "*") if active else ascii_safe("○", "o"), color),
            "agent": (agent, AGENT_COLORS.get(item.agent_type or data.get("agent_name"), "")),
            "project": (project, ""),
            "health": (f"{health} {trend}", color, ((len(health) + 1, len(health) + 2,
                                                   trend_style),)) if trend else (health, color),
            "cost": ("n/a" if cost is None else format_usd(cost).lstrip("~"), "")
            if self._budget is None
            else _budget_cell(cost, self._budget, self._narrow),
            "trend": self._spark_cell(data, "cost" if self.sort_mode == "cost" else "health",
                                      _WIDTHS["trend"]),
            "ctx": ("-" if ctx is None else f"{ctx}%", ""),
            "last": (_ago(age), ""),
            "signal": self._blocked_signal(data, report.warnings) or _signal(report.warnings),
        }
        if item.process_status == "stopped":  # grey, so stopped differs from idle
            cells = {col: (v[0], STOPPED_STYLE) for col, v in cells.items()}
        return cells

    def _team_cells(self, team: AgentTeam) -> dict[str, tuple[str, str]]:
        score = self._team_scores.get(team.team_id)
        color = _health_color(100 if score is None else score)
        members = f"{team.member_count} agents"
        if team.subagent_count:
            members += f", {team.subagent_count} sub"
        cells = dict.fromkeys(_WIDTHS, ("", ""))
        cells["agent"] = (f"TEAM {team.name}", "bold " + color)
        cells["project"] = (members, "")
        cells["health"] = ("" if score is None else f"{score}%", "bold " + color)
        if self._narrow:
            cells["project"], cells["signal"] = cells["agent"], cells["project"]
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

    def _groups(self, keys: dict[Path, tuple]) -> list[tuple[int | None, list[Path]]]:
        """[(team id or None, member paths)] in display order. A group is a
        team, or a session with its subagents; groups sort by their most
        urgent member. In a group each session's subagents sit under it,
        siblings in sort order."""
        agents = self.agents
        by_pid = None
        parent_of: dict[Path, Path] = {}
        for path in keys:
            data = agents[path]
            parent = data.get("parent_log")
            if parent is None and data["item"].parent_agent_pid is not None:
                if by_pid is None:
                    by_pid = {d["pid"]: p for p, d in agents.items() if d["pid"] is not None}
                parent = by_pid.get(data["item"].parent_agent_pid)
            if parent is not None and parent != path and parent in keys:
                parent_of[path] = parent
        self._parent_of = parent_of

        def top(path: Path) -> Path:
            for _ in range(len(keys)):  # ponytail: bounded walk, a parent cycle can't hang
                if path not in parent_of:
                    break
                path = parent_of[path]
            return path

        groups: dict[object, list[Path]] = {}
        for path in keys:
            team_id = agents[path]["item"].team_id
            gid = team_id if team_id is not None else top(path) if path in parent_of else path
            groups.setdefault(gid, []).append(path)
        children: dict[Path, list[Path]] = {}
        for path in sorted(parent_of, key=keys.__getitem__):
            children.setdefault(parent_of[path], []).append(path)

        result = []
        for gid, members in sorted(groups.items(),
                                   key=lambda g: min(keys[p] for p in g[1])):
            if len(members) > 1:
                inside = set(members)
                ordered: dict[Path, None] = {}  # insertion-ordered set

                def walk(path: Path) -> None:
                    ordered[path] = None
                    for child in children.get(path, ()):
                        if child in inside and child not in ordered:
                            walk(child)

                for path in sorted(members, key=lambda p: (agents[p]["item"].depth, keys[p])):
                    if parent_of.get(path) not in inside:
                        walk(path)
                ordered.update(dict.fromkeys(members))  # a parent cycle: not reached above
                members = list(ordered)
            result.append((gid if gid in self.teams else None, members))
        return result

    def _matches(self, cells: dict[str, tuple[str, str]]) -> bool:
        needle = self._filter.lower()
        return not needle or any(needle in cells[col][0].lower()
                                 for col in ("agent", "project", "signal"))

    def _fold_cells(self, n: int) -> dict[str, tuple[str, str]]:
        cells = dict.fromkeys(_WIDTHS, ("", ""))
        cells["dot"] = (ascii_safe("○", "o"), "dim")
        cells["agent"] = (f"{ascii_safe('…', '...')} {n} idle", "dim")
        cells["project"] = (f"(a to {'fold' if self._show_idle else 'show'})", "dim")
        if self._narrow:
            cells["project"], cells["signal"] = cells["agent"], cells["project"]
        return cells

    def _sync_table(self, reports: dict[Path, "HealthReport"]) -> None:
        """Update only the cells that changed; add rows for new sessions;
        reorder only when the order changed, keeping the cursor on the same
        session. Never clears the table."""
        table = self._table
        now = time.monotonic()
        rows: dict[str, dict[str, tuple[str, str]]] = {}
        sort_keys: dict[Path, tuple] = {}
        folding: set[Path] = set()  # no action for IDLE_FOLD_S+ (not: none yet), or stopped
        active = need_you = 0
        spend: float | None = None
        critical = get_theme().level_3
        for path, data in self.agents.items():
            age = _age(data["buffer"])
            report = reports[path]
            rows[str(path)] = cells = self._row_cells(data, report, age, now)
            sort_keys[path] = self._sort_key(data, report, age)
            if data["item"].process_status == "stopped" or (age or 0) >= IDLE_FOLD_S:
                folding.add(path)
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

        # Shown: filter matches and their parents; sessions idle IDLE_FOLD_S+
        # (or stopped) are one "N idle" row unless `a`, except the parents of
        # shown subagents.
        groups = self._groups(sort_keys)
        awake = set()
        for path in sort_keys.keys() - folding:
            while path is not None and path not in awake:
                awake.add(path)
                path = self._parent_of.get(path)
        order: list[str] = []
        idle = 0
        for team_id, members in groups:
            hits = [p for p in members if self._matches(rows[str(p)])]
            asleep = sum(p not in awake for p in hits)
            idle += asleep
            if asleep and not self._show_idle and self.session is None:  # `watch` never folds
                hits = [p for p in hits if p in awake]
            keep: set[Path] = set()  # the hits and their parents (a subagent never alone)
            for path in hits:
                while path is not None and path not in keep:
                    keep.add(path)
                    path = self._parent_of.get(path)
            members = [p for p in members if p in keep]
            if not members:
                continue
            if team_id is not None:
                key = f"team:{team_id}"
                rows[key] = self._team_cells(self.teams[team_id])
                order.append(key)
            order.extend(str(p) for p in members)
        if idle and self.session is None:
            rows[FOLD_KEY] = self._fold_cells(idle)
            order.append(FOLD_KEY)

        shown_keys = set(order)
        for key in [k for k in self._cells if k not in shown_keys]:
            table.remove_row(key)
            del self._cells[key], self._dots[key]
        for key in self._data_sig.keys() - rows.keys():  # gone teams / fold row
            self._data_sig.pop(key)
            self._flash_until.pop(key, None)

        for key, cells in rows.items():
            # LAST ticks; TREND is a late copy of HEALTH/COST: neither flashes
            data_sig = tuple(v for col, v in cells.items() if col not in ("last", "trend"))
            old_sig = self._data_sig.get(key)
            self._data_sig[key] = data_sig
            if old_sig is not None and old_sig != data_sig:
                self._flash_until[key] = now + FLASH_S
            if key not in shown_keys:
                continue
            if self._flash_until.get(key, 0) > now:
                cells = {col: (v[0], f"bold {v[1]}", *v[2:]) for col, v in cells.items()}
            shown = self._cells.get(key)
            if shown is None:
                texts = [_text(cells[col], width) for col, width in self._widths.items()]
                table.add_row(*texts, key=key)
                self._dots[key] = texts[0]
            else:
                for col, width in self._widths.items():
                    if cells[col] != shown[col]:
                        text = _text(cells[col], width)
                        table.update_cell(key, col, text)
                        if col == "dot":
                            self._dots[key] = text
            self._cells[key] = cells

        reordered = order != self._order
        if reordered:
            self._order = order
            rank = {id(self._dots[key]): i for i, key in enumerate(order)}
            table.sort("dot", key=lambda dot: rank[id(dot)])
        selected = str(self.selected_path) if self.selected_path is not None else None
        if selected is not None and selected not in shown_keys:
            # Folded or filtered out: the nearest shown session in the full order.
            pos = {str(p): i for i, p in enumerate(p for _, ms in groups for p in ms)}
            at = pos.get(selected, 0)
            near = min((k for k in pos if k in shown_keys),
                       key=lambda k: (abs(pos[k] - at), pos[k] > at), default=None)
            if near is not None:
                self.selected_path, selected, reordered = Path(near), near, True
        if reordered and selected in shown_keys:
            table.move_cursor(row=table.get_row_index(selected), animate=False)

    # -- layout ---------------------------------------------------------

    def _layout(self, width: int, height: int) -> tuple:
        """The one place that decides the layout from the terminal size:
        (narrow, Events panel height or 0 for hidden, table columns as
        (key, label, width)). Under NARROW_BELOW columns AGENT and CTX go
        (Enter shows them) and PROJECT is shorter; TREND goes when it would
        leave TOP SIGNAL under SIGNAL_MIN; TOP SIGNAL gets the rest. TREND's
        label names what it shows (the sort decides)."""
        narrow = width < NARROW_BELOW
        columns = []
        for key, label, size in COLUMNS:
            if narrow and key in ("agent", "ctx"):
                continue
            if key == "project" and narrow:
                size = PROJECT_NARROW
            if key == "cost" and self._budget is not None:
                label, size = ("COST/BUDGT", BUDGET_NARROW) if narrow else (
                    "COST / BUDGET", BUDGET_WIDTH)
            if key == "trend":
                label = "TREND $" if self.sort_mode == "cost" else "TREND H"
            columns.append((key, label, size))

        def rest() -> int:  # cell padding 1+1 per column, the border 2, the scrollbar 2
            return width - sum(size or 0 for _, _, size in columns) - 2 * len(columns) - 4

        if rest() < SIGNAL_MIN:
            columns = [c for c in columns if c[0] != "trend"]
        columns[-1] = (*columns[-1][:2], max(10, rest()))
        feed = 7 if height >= SHORT_BELOW else 5 if height >= TINY_BELOW else 0
        return narrow, feed, tuple(columns)

    def on_resize(self, event: events.Resize) -> None:
        """Re-lay out when the size changes the layout. (Runs before
        App._on_resize: self.size is still the old size.)"""
        self._apply_layout(event.size)

    def _apply_layout(self, size) -> None:
        """Show/hide the Selected strip and Events panel; rebuild the table's
        columns when they changed (rows are re-added by refresh_ui, the
        cursor put back on the selected session)."""
        self._term_width = size.width
        layout = self._layout(size.width, size.height)
        if layout == self._layout_now:
            self._update_header()
            return
        old, self._layout_now = self._layout_now, layout
        narrow, feed, columns = layout
        self._selected.display = not narrow
        self._show_feed()
        if old and old[2] == columns:
            self._update_header()
            return
        self._widths = {key: size for key, _, size in columns}
        table = self._table
        table.clear(columns=True)
        for key, label, width in columns:
            table.add_column(label, key=key, width=width)
        for cache in (self._cells, self._dots, self._data_sig, self._flash_until):
            cache.clear()  # mode-dependent cells: no flash for a re-layout
        self._order = []
        self.refresh_ui()

    def _show_feed(self) -> None:
        """Events panel at the layout's height; hidden in a short terminal,
        where `e` shows it in place of the table."""
        feed = self._layout_now[1]
        opened = self._feed_open and not feed
        self._table.display = not opened
        self._feed.display = bool(feed) or opened
        self._feed.styles.height = feed or "1fr"

    def _drop_row(self, path: Path) -> None:
        key = str(path)
        if key in self._cells:
            self._table.remove_row(key)
        for cache in (self._cells, self._data_sig, self._flash_until, self._dots):
            cache.pop(key, None)
        self._order = []

    # -- header and event feed --------------------------------------------

    def _update_header(self) -> None:
        """One line; redrawn only when its text changes (the clock: each second).
        When it does not fit, in turn: wide gaps, the clock, the title,
        (100+ columns: "N sess · M need you"), today/week, "N sess · M need
        you", the budget (its column shows it); then it is cut."""
        if not self._layout_now:
            return
        n, active, need_you, spend = self._summary
        dot = ascii_safe(" · ", " | ")
        money = "n/a" if spend is None else _usd(spend) if spend else "$0.00"
        title = "agentwatch" + (" [SECURITY]" if self.security_mode else "")
        counts = f"{n} session{'s' * (n != 1)}{dot}{active} active{dot}{need_you} need you"
        short = f"{n} sess{dot}{need_you} need you"
        week = [machine.week_label(*self._history)] if self._history else []
        n_ai = len(self._unmonitored or ())
        mid = [f"spent {money}", *([f"+{n_ai} unmonitored AI"] if n_ai else []),
               f"alerts {self._alerts}", f"blocks {self._blocks}"]
        budget = [f"budget {_usd(self._budget)}/session"] if self._budget is not None else []
        full = [counts, *mid[:1], *week, *mid[1:], *budget]
        clock = f"{datetime.now():%H:%M:%S}"
        forms = [
            (title, "   ".join([*full, clock])),
            (title, "  ".join([*full, clock])),
            (title, "  ".join(full)),
            ("", "  ".join(full)),
            # under NARROW_BELOW columns today/week go before the counts are cut
            *([("", "  ".join([short, *full[1:]]))] if week and not self._narrow else []),
            ("", "  ".join([counts, *mid, *budget])),
            ("", "  ".join([short, *mid, *budget])),
            ("", "  ".join([short, *mid])),
        ]
        room = self._term_width - 2
        title, body = next((f for f in forms if len(f[0]) + 2 * bool(f[0]) + len(f[1]) <= room),
                           forms[-1])
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
        """`e`: focus the event feed (to scroll it; shown in place of the
        table when the terminal is too short for it); again: back."""
        if self.focused is self._feed:
            self.action_focus_table()
            return
        self._feed_open = True
        self._show_feed()
        self._feed.focus()

    def action_focus_table(self) -> None:
        """Esc: back to the table; in the filter line (or on the table with
        a filter kept) it clears the filter."""
        if self.focused is self._filter_input or (self.focused is self._table and self._filter):
            self._filter_input.value = ""
            self._filter_input.display = False
            self.on_input_changed(Input.Changed(self._filter_input, ""))
        if self._feed_open:
            self._feed_open = False
            self._show_feed()
        self._table.focus()

    def action_help(self) -> None:
        """`?`: the keys, columns, icons and flags."""
        self.push_screen(HelpScreen())

    def action_other_ai(self) -> None:
        """`d`: programs using AI on this machine (the last detect() result)."""
        text = machine.detect_text(self._detected, self._detected_at, self.DETECT_EVERY_S)
        self.push_screen(HelpScreen(text, "Other AI on this machine", 100))

    def action_report(self) -> None:
        """`w`: the last 7 days from the history DB (the last sync's report)."""
        week = self._history[1] if self._history else None
        text = machine.report_text(week, self._history_at, self._history_failed,
                                   self.HISTORY_EVERY_S)
        self.push_screen(HelpScreen(text, "Weekly report", 100))

    # -- machine checks (worker threads; results applied on the event loop) --

    async def _detect_ai(self) -> None:
        """ai_detect.detect() on a thread; one feed line per unmonitored AI
        program not seen before (the first result is the baseline)."""
        if self._detecting:
            return
        self._detecting = True
        try:
            from agentwatch import ai_detect  # call-time lookup: tests monkeypatch detect

            result = await asyncio.to_thread(ai_detect.detect)
            names = machine.unmonitored(result)
        except Exception:  # a failed check hides the count; the next one retries
            result = names = None
        finally:
            self._detecting = False
        self._detected, self._detected_at = result, time.time()
        if names is not None:
            if self._ai_seen is not None:
                for name in sorted(names - self._ai_seen):
                    self._event(f"new unmonitored AI program: {name}", "yellow")
            self._ai_seen = (self._ai_seen or set()) | names
        self._unmonitored = names  # the header counts the ones running now
        self._update_header()

    async def _sync_history(self) -> None:
        """`history.sync` in a subprocess, then today's spend and the 7-day
        report on a thread. A failure hides the figures (one feed line)."""
        if self._syncing:
            return
        self._syncing = True
        try:
            start = time.monotonic()
            self._sync_proc = proc = await asyncio.create_subprocess_exec(
                *machine.SYNC_ARGS, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                **machine.GROUP_KWARGS)
            if await proc.wait():
                raise OSError(f"history sync exited {proc.returncode}")
            self.sync_seconds = time.monotonic() - start
            figures = await asyncio.to_thread(machine.history_figures)
        except Exception:
            figures = None
        finally:
            if self._sync_proc is not None and self._sync_proc.returncode is None:
                # cancelled (the app is quitting; it runs before on_unmount)
                machine.kill_group(self._sync_proc.pid)
            self._syncing, self._sync_proc = False, None
        if figures is None:
            if not self._history_failed:
                self._event("history unavailable", "dim")
            self._history, self._history_failed = None, True
        else:
            self._history, self._history_at, self._history_failed = figures, time.time(), False
        self._update_header()

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

    def _title_text(self, data: dict) -> Text:
        """_title() with the agent in its colour."""
        item: AgentItem = data["item"]
        title = Text(self._title(data))
        color = AGENT_COLORS.get(item.agent_type or data.get("agent_name"))
        if color:
            start = len(item.project_name or item.log_path.name) + len(ascii_safe(" · ", " | "))
            title.stylize(color, start, start + len(self._agent_name(data)))
        return title

    def _graph_rows(self, data: dict, report: "HealthReport", width: int,
                    indent: str = "") -> list[Text]:
        """health / cost / ctx rows: value, a *width* sparkline of the
        history, the arrow vs a minute ago, a gauge (cost: with --budget)."""
        buffer: ActionBuffer = data["buffer"]
        score = report.overall_score
        cost = buffer.stats.estimated_cost
        ctx = _context_pct(buffer)
        arrows = data.get("_arrows") or self._arrows(None, ())
        budget = self._budget
        rows = []
        for kind, label, value, gauge in (
            ("health", "health", f"{score}%", _gauge(score / 100, health=True, pct=False)),
            ("cost", "cost", "n/a" if cost is None else _usd(cost),
             None if budget is None or cost is None else _gauge(cost / budget)),
            ("ctx", "ctx", "n/a" if ctx is None else f"{ctx}%",
             None if ctx is None else _gauge(ctx / 100, pct=False)),
        ):
            line = Text(indent, no_wrap=True).append(f"{label:<7}", "bold")
            line.append(f"{value:>7} ", _health_color(score) if kind == "health" else "")
            line.append_text(_text(self._spark_cell(data, kind, width), width))
            arrow, style = arrows[kind]
            line.append(f" {arrow or ' '}", style)
            if gauge is not None:
                line.append("  budget " if kind == "cost" else "  ")
                line.append(*gauge)
            rows.append(line)
        return rows

    def _update_selected(self, data: dict, report: "HealthReport") -> None:
        """Title; health / cost / ctx graphs (efficiency, security and net
        after health, $/min after cost); the top signal, coloured by
        severity, and the next warning (or the Tier-2 goal). Six lines.
        Rebuilt only when what it shows changed (like the table's cells)."""
        buffer: ActionBuffer = data["buffer"]
        stats = buffer.stats
        assessor: LiveLlmAssessor | None = data.get("llm_assessor")
        goal = assessor.stamp_goal_alignment() if assessor else None
        # report: rescored on new actions (or `s`); samples/arrows: graphs;
        # coach state, Tier-2 verdicts and goal, the title's pid/uptime/status
        sig = (self.selected_path, id(report), self.security_mode, stats.action_count,
               data.get("_samples"), tuple(data.get("_arrows", {}).values()),
               self._title(data), data.get("_blocked_id"), id(data.get("_armed")),
               data.get("net_sampled"), assessor and len(assessor._assessments), repr(goal))
        if sig == self._selected_sig:
            return
        self._selected_sig = sig
        cost = stats.estimated_cost
        security = str(len(report.security_warnings)) if self.security_mode else "off"
        net = endpoint_summary(buffer.actions) if data.get("net_sampled") else NOT_ATTRIBUTABLE
        health, cost_row, ctx_row = self._graph_rows(data, report, SPARK_STRIP)
        health.append(f"   Efficiency {data.get('_last_eff', 100)}%  Security {security}  {net}",
                      "dim")
        if cost and stats.duration_minutes >= 1:
            cost_row.append(f"   {format_usd(cost / stats.duration_minutes)}/min", "dim")
        lines = [Text("Selected: ").append_text(self._title_text(data)), health, cost_row,
                 ctx_row]
        blocked = self._blocked_signal(data, report.warnings)
        if blocked:
            lines.append(Text(*blocked))
        arrow = ascii_safe("→", "->")
        for w in _top_warnings(report.warnings, 6 - len(lines) - (goal is not None)):
            detail = WarningsList._format_details(w)
            lines.append(Text(f"{w.emoji} {w.message}" + (f" {arrow} {detail}" if detail else ""),
                              _SEVERITY_STYLE[w.severity]))
        if goal is not None:
            label = {True: "[ALIGNED]", False: "[POSSIBLE DRIFT]"}.get(
                goal.get("aligned"), "[UNCLEAR]"
            )
            summary = goal.get("drift_summary") or "(model response could not be parsed)"
            lines.append(Text(f"Tier-2 goal (advisory): {label} {summary}"))
        if not report.warnings and not blocked:
            lines.append(Text("No active warnings", "green"))
        show(self._selected, Text("\n").join(lines))

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

        screen.text("detail-title", self._title_text(data).append(
            f"  (health {report.overall_score}%)"))
        # every sample (up to HISTORY_MAX) while the screen has room for it
        width = max(TREND_WIDTH, min(len(data.get("_hist") or ()), screen.size.width - 42))
        screen.text("d-graphs", Text("\n").join(self._graph_rows(data, report, width, "  ")))
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

        # The screen's width: a hidden tab's widgets have none.
        width = screen.size.width - 2
        screen.text("d-loop", hang(self._loop_breaker_text(data), width, 16))
        screen.text("d-net", self._net_text(data, screen.query_one(TabbedContent).active, width))
        screen.text("d-process", self._process_text(data, width))

    def _net_text(self, data: dict, tab: str, width: int = 0) -> str:
        """The Network tab: the NetSampler's endpoints for the session's pid
        (no second sampler), named and its listeners read on a worker while
        the tab is shown (every NAME_EVERY_S)."""
        if not self._process_mode:
            return "  Network: n/a (no process)"
        if not data.get("net_sampled"):
            return f"  {NOT_ATTRIBUTABLE}"
        pid = data["pid"]
        # what `agentwatch net` shows: no loopback, link-local, multicast (local DNS)
        spans = [e for e in self._net_sampler.spans(pid) or [] if _flaggable(e.ip)]
        now = time.monotonic()
        if tab == "network" and not self._naming and now >= self._name_next:
            self._name_next = now + NAME_EVERY_S
            ips = sorted({e.ip for e in spans if self._names.get(e.ip, ("", "ip"))[1] == "ip"})
            self._naming = True
            self.run_worker(self._name_endpoints(data, pid, ips))
        return machine.net_text(pid, spans, self._names, data.get("_listeners"),
                                endpoint_summary(data["buffer"].actions), width)

    async def _name_endpoints(self, data: dict, pid: int, ips: list[str]) -> None:
        """Worker: name *ips* (net.Namer, cached across calls) and read
        *pid*'s listeners. A failure leaves bare IPs / no listener list."""
        def work():
            if self._namer is None:
                from agentwatch.net import Namer

                self._namer = Namer()
            return machine.name_ips(self._namer, ips), machine.listeners_of(pid)

        try:
            names, listeners = await asyncio.to_thread(work)
            self._names.update(names)
            if data.get("pid") == pid:
                data["_listeners"] = listeners
        except Exception:
            pass
        finally:
            self._naming = False

    def _process_text(self, data: dict, width: int = 0) -> str:
        """Rows of `  Key      value`; a value longer than *width* (a log
        path) continues on indented lines."""
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
        room = max(20, width - 11)
        return "\n".join(f"  {k:8s} " + f"\n{' ' * 11}".join(
            v[i:i + room] for i in range(0, len(v), room)) for k, v in rows)

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
        if self._sync_proc is not None and self._sync_proc.returncode is None:
            # its pool workers too; the next start's sync redoes its logs
            machine.kill_group(self._sync_proc.pid)
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
        if self.session is not None:  # `watch`: only its own agent, never others
            processes = [p for p in processes if p.log_file == self.session]

        new_agents = self.watcher.refresh_processes(processes)
        scanned = {t.team_id: t for t in build_teams(processes) if t.member_count > 1}

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
        # `watch` keeps its one session after the agent stops
        expired = [] if self.session is not None else self.watcher.reap_stopped(timeout=60.0)
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

        # Teams as of this scan (new ones too); a team whose sessions are all
        # gone is dropped (its header row goes on the next tick).
        tracked = {d["item"].team_id for d in self.agents.values()}
        self.teams = {tid: team for tid, team in {**self.teams, **scanned}.items()
                      if tid in tracked}

    async def _replay_scans(self, sessions: list[dict]) -> None:
        """Check, on the UI loop and in WATCH_SLICE_S slices shared by all
        *sessions* (one worker, so N sessions are not N slices per loop
        turn), what arrived while security was off (everything, the first
        time it is on). The ledger is shown as it grows; detectors never
        leave this thread."""
        slice_start = time.monotonic()
        for data in sessions:
            scan, buffer = self._session_scan(data), data["buffer"]
            context, to_check = scan.plan_resume(buffer)
            seen = scan.version
            for _ in scan.replay_steps(context, to_check, buffer.max_size):
                if time.monotonic() - slice_start > WATCH_SLICE_S:
                    if scan.version != seen:  # rescore with what has merged so far
                        data["_last_count"], seen = -1, scan.version
                    await asyncio.sleep(0)
                    slice_start = time.monotonic()
            scan.finish_resume()
            if scan.version != seen:
                data["_last_count"] = -1
        self._replay = None

    def action_toggle_security(self) -> None:
        """Toggle security mode across all agents."""
        self.security_mode = not self.security_mode
        self.title = "AgentWatch - Multi-Agent Dashboard"
        if self.security_mode:
            self.title += " [SECURITY]"

        if self._replay is not None:
            self._replay.cancel()  # a half-done replay resumes from the old mark
            self._replay = None
        # New registries, and drop every cached report so each session is
        # rescored on this refresh (RotScorer is not re-fed: no new actions).
        for data in self.agents.values():
            mode = "all" if self.security_mode else "health"
            data["registry"] = create_registry(mode=mode)
            scan = self._session_scan(data)
            if not self.security_mode:
                scan.suspend(data["buffer"].stats.action_count)
            scan.rebind(data["registry"])  # the ledger is kept, hidden while off
            data["_last_count"] = -1

        if self.security_mode and self.agents:
            self._replay = self.run_worker(self._replay_scans(list(self.agents.values())))

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
        self._update_subtitle()
        self._apply_layout(self.size)  # TREND's label (and cells) follow the sort
        self.refresh_ui()

    def _update_subtitle(self) -> None:
        dot = ascii_safe(" · ", " | ")
        text = f"sort: {self.sort_mode}" + (f"{dot}filter: {self._filter}" if self._filter else "")
        self._table.border_subtitle = Text(text)  # Text: the filter is literal

    def action_toggle_idle(self) -> None:
        """`a`: show the folded idle sessions; again: fold them."""
        self._show_idle = not self._show_idle
        self.refresh_ui()

    def action_filter(self) -> None:
        """`/`: type a filter in the line at the bottom."""
        self._filter_input.display = True
        self._filter_input.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Rows filter as you type."""
        if event.value != self._filter:
            self._filter = event.value
            self._update_subtitle()
            self.refresh_ui()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Enter: keep the filter, back to the table."""
        self._filter_input.display = False
        self._table.focus()
