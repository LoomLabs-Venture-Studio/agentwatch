"""watch-all `?` help (Sprint 36, PR 7): keys, columns, icons and flags."""

from __future__ import annotations

import re
import textwrap

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Footer, Static

from agentwatch.themes import ascii_safe
from agentwatch.ui.app import show


def help_text() -> str:
    a = ascii_safe
    return f"""\
Keys
  {a('↑ ↓', '^ v')}         select a session
  Enter       open it full screen (detail view)
  /           filter by project, agent or top warning
              (Enter keeps it, Esc clears it)
  a           show / fold idle sessions
  o           sort: attention, cost, recent
  e           Events panel (scroll it; e or Esc back)
  s           security detectors on / off
  d           other AI on this machine (agentwatch detect)
  w           weekly report (agentwatch report)
  ?           this help
  q           quit

Detail view
  Tab, 1-4    tabs: Health, Security, Network, Process
  Network     the session's process (agentwatch net): endpoints seen
              in the last 30 min with host names and AI-provider
              flags, and its listeners (EXPOSED: reachable from other
              machines); n/a with --all-logs (no process)
  {a('↑ ↓', '^ v')} PgUp PgDn  scroll
  Esc, q      back to the table

Columns
  {a('● ○', '* o')}         active / idle 5+ min (grey: stopped)
  HEALTH      score; {a('▲ ▼', '^ v')} when 5+ points off a minute ago
  COST        estimated (n/a: no known price for the model)
  COST/BUDGET  with --budget: {a('▮▮▮▯', '###-')} share of it, amber from 80%,
               red once hit
  CTX         context window fill
  LAST        time since the last action
  TOP SIGNAL  ok, {a('⚠', '!')} top warning (+N more), or
              {a('⛔', 'X')} the loop breaker blocked a call
  {a('○ …', 'o ...')} N idle  sessions idle 15+ min or stopped, folded (a)
  Under 100 columns AGENT, CTX and the Selected strip are hidden
  (Enter shows them); under 30 rows Events is 3 lines, under 20
  it is hidden (e shows it).

Sort (o)
  attention   Critical and loop-blocked first, then HIGH, other
              warnings, active by recency, idle last
  cost        costliest first
  recent      most recent action first

Header
  sessions, active, need you (Critical, HIGH+ or loop-blocked; not
  stopped ones), spent (estimated, every session loaded this run,
  folded and filtered ones too), alerts and loop breaker blocks
  this run, --budget per session
  today $X    spend today from the history DB (synced at start and
              every 5 min; logs written in the last minute wait)
  week $Y {a('▲', '^')}Z%  the last 7 days, change vs the 7 days before (w: the
               report). Both hidden if history is unavailable; under
               100 columns they go before the counts are shortened.
  +N unmonitored AI  programs using AI that agentwatch cannot
              monitor (checked every 30s; d lists them)

Main flags (watch-all --help lists them all)
  --all-logs          every log in the known log dirs (not running
                      processes)
  --since Nh|Nd|all   with --all-logs: the window (default 24h)
  --budget USD        per-session budget column and alert
  --notify            desktop alerts
  --webhook URL       Slack-compatible alerts
  --headless          no dashboard: one line per new warning
  --security          security detectors on from the start

Esc, ? or q closes this help."""


_KEY = re.compile(r"\s*\S.*?\s{2,}(?=\S)")  # "  key   " before a description


def _unwrap(text: str) -> list[str]:
    """help_text()'s logical lines: a line indented 14+ continues the one
    before it, and so does a 2-indented prose line after a prose line."""
    lines: list[str] = []
    prose = False
    for line in text.split("\n"):
        indent = len(line) - len(line.lstrip())
        if lines and line.strip() and (indent >= 14 or (
                prose and indent == 2 and not _KEY.match(line))):
            lines[-1] += " " + line.strip()
            continue
        lines.append(line)
        prose = indent == 2 and not _KEY.match(line)
    return lines


def hang(text: str, width: int, unwrap: bool = False) -> str:
    """*text* as is if it fits *width*; else each longer line wrapped with
    its continuation lines indented to its description column (after its
    first gap of 2+ spaces), else to its own indent. *unwrap*: help_text()'s
    hand-wrapped lines are joined first."""
    if width < 20 or all(len(line) <= width for line in text.split("\n")):
        return text
    out = []
    for line in _unwrap(text) if unwrap else text.split("\n"):
        if len(line) <= width:
            out.append(line)
            continue
        key = _KEY.match(line)
        indent = len(key.group()) if key and len(key.group()) <= width // 2 else (
            len(line) - len(line.lstrip()))
        out.append(textwrap.fill(line, width, subsequent_indent=" " * indent,
                                 break_on_hyphens=False))
    return "\n".join(out)


class HelpScreen(ModalScreen):
    """`?`: what the keys, columns and icons mean; also the `d`/`w` overlays
    (*text*, *title*). Esc, ?, q, d or w close it."""

    CSS = """
    HelpScreen {
        align: center middle;
    }

    #help {
        width: 76;
        max-width: 100%;
        height: auto;
        max-height: 100%;
        border: round $accent;
        border-title-align: left;
        padding: 0 1;
        background: $surface;
    }
    """

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("question_mark,q,d,w", "close", show=False),
    ]

    def __init__(self, text: str | None = None, title: str = "agentwatch watch-all help",
                 width: int = 76) -> None:
        super().__init__()
        self._text, self._title, self._width = text, title, width

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="help") as scroll:
            scroll.border_title = self._title
            scroll.styles.width = self._width
            yield Static(self._wrapped(self.app.size.width), id="help-text", markup=False)
        yield Footer(show_command_palette=False)  # "esc Close", over the table's

    def _wrapped(self, width: int) -> str:
        """Wrapped to the box (border and padding: 4 cells; a scrollbar when it
        scrolls: 2 more), hanging indents."""
        text = help_text() if self._text is None else self._text
        return hang(text, min(self._width, width) - 6, unwrap=self._text is None)

    def on_resize(self, event) -> None:
        show(self.query_one("#help-text", Static), self._wrapped(event.size.width))

    def action_close(self) -> None:
        self.dismiss()
