"""watch-all session detail view (Sprint 36, PR 4): Enter on a session row.

A full screen with Health / Security / Network / Process tabs for one
session. The app fills it on its 1s tick (`MultiAgentWatchApp._update_detail`)
and only for the shown session; widgets are updated only when their text
changed. All text is literal (never markup).
"""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Static, TabbedContent, TabPane

from agentwatch.ui.app import (
    EfficiencyBar,
    HealthBar,
    SecurityStatus,
    StatsPanel,
    WarningsList,
    show,
)
from agentwatch.ui.rot_widget import ContextHealthWidget

TABS = ("health", "security", "network", "process")


class DetailScreen(Screen):
    """One session, full screen. Esc/Backspace/q go back to the table."""

    CSS = """
    #detail-title {
        height: 1;
        padding: 0 1;
        background: $panel;
        text-wrap: nowrap;
        text-overflow: ellipsis;
    }

    #detail-tabs {
        height: 1fr;
    }

    #detail-tabs TabPane {
        padding: 0;
    }

    .pane {
        height: 1fr;
    }

    .pane > Static {
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        Binding("escape,backspace,q", "back", "Back"),
        Binding("tab", "next_tab(1)", "Next tab", priority=True),
        Binding("shift+tab", "next_tab(-1)", "Prev tab", show=False, priority=True),
        Binding("1", "tab(0)", "Tabs", key_display="1-4"),
        Binding("2", "tab(1)", show=False),
        Binding("3", "tab(2)", show=False),
        Binding("4", "tab(3)", show=False),
        Binding("up", "scroll('up')", show=False, priority=True),
        Binding("down", "scroll('down')", show=False, priority=True),
        Binding("pageup", "scroll('page_up')", show=False, priority=True),
        Binding("pagedown", "scroll('page_down')", show=False, priority=True),
    ]

    def __init__(self, path: Path) -> None:
        super().__init__()
        self.path = path
        self.ready = False  # widgets mounted (the app's tick may come first)

    def compose(self) -> ComposeResult:
        yield Static(id="detail-title", markup=False)
        with TabbedContent(id="detail-tabs"):
            with TabPane("Health", id="health"), VerticalScroll(classes="pane"):
                yield Static(id="d-graphs", markup=False)
                yield HealthBar(id="d-health")
                yield EfficiencyBar(id="d-efficiency")
                yield ContextHealthWidget(id="d-context")
                yield StatsPanel(id="d-stats")
                yield Static(id="d-loop", markup=False)
                warnings = WarningsList(id="d-warnings")
                warnings.limit = None
                yield warnings
            with TabPane("Security", id="security"), VerticalScroll(classes="pane"):
                yield SecurityStatus(id="d-security")
                yield Static(id="d-counters", markup=False)
                findings = WarningsList(id="d-findings")
                findings.limit = None
                yield findings
            with TabPane("Network", id="network"), VerticalScroll(classes="pane"):
                yield Static(id="d-net", markup=False)
            with TabPane("Process", id="process"), VerticalScroll(classes="pane"):
                yield Static(id="d-process", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self.ready = True
        self.app._update_detail()

    def text(self, widget_id: str, content: str) -> None:
        show(self.query_one(f"#{widget_id}", Static), content)

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_tab(self, index: int) -> None:
        self.query_one(TabbedContent).active = TABS[index]

    def action_next_tab(self, step: int) -> None:
        tabs = self.query_one(TabbedContent)
        self.action_tab((TABS.index(tabs.active) + step) % len(TABS))

    def action_scroll(self, how: str) -> None:
        pane = self.query_one(f"#{self.query_one(TabbedContent).active} .pane", VerticalScroll)
        getattr(pane, f"scroll_{how}")()
