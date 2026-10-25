"""watch-all's machine-wide views (Sprint 36, PR 8): the Network tab (what
`agentwatch net` shows, for one session's process), other AI on this machine
(`agentwatch detect`) and the weekly report (`agentwatch report`) behind the
header's today/week figures.

net, ai_detect, history and report are reused read-only. The functions that
block (DNS, psutil, SQLite) run on worker threads, never the UI thread; the
rest only format text, shown literally (never markup).
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
from datetime import datetime

from agentwatch.alerts import _usd
from agentwatch.themes import ascii_safe

SYNC_DAYS = 14  # the week and the week before it (`agentwatch report` syncs 2x its days)
# `history.sync` runs in its own process: its parse pool must not fork this
# (threaded) one, and its parsing stays off the UI process.
# It runs in its own process group (see kill_group) and exits with its parent.
SYNC_ARGS = (sys.executable, "-c", "from agentwatch.ui.machine import sync_main; sync_main()")
# start the sync in a new group, so one kill reaches its pool workers too
GROUP_KWARGS = (
    {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform == "win32"
    else {"start_new_session": True}
)


def exit_with_parent() -> None:
    """If this process's parent dies (SIGKILL, crash), kill this process
    within a second: its whole group (pool workers included) when it leads
    one, else only itself. POSIX only."""
    if sys.platform == "win32":
        return
    parent = os.getppid()

    def watchdog() -> None:
        while os.getppid() == parent:
            time.sleep(1)
        if os.getpgid(0) == os.getpid():
            os.killpg(0, signal.SIGKILL)
        os.kill(os.getpid(), signal.SIGKILL)

    threading.Thread(target=watchdog, daemon=True).start()


def sync_main() -> None:
    """The sync subprocess: `history.sync`, gone with watch-all."""
    from agentwatch.history import connect, sync

    exit_with_parent()
    sync(connect(), days=SYNC_DAYS)


def kill_group(pid: int, grace: float = 0.5) -> None:
    """Stop the sync process *pid* and its pool workers: SIGTERM its process
    group, SIGKILL whatever is left after *grace* seconds. Windows: taskkill
    the tree. Never raises."""
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)],
                           capture_output=True, timeout=5, check=False)
            return
        os.killpg(pid, signal.SIGTERM)
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            os.killpg(pid, 0)  # ProcessLookupError once the group is gone
            time.sleep(0.05)
        os.killpg(pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass  # already gone (ProcessLookupError), or nothing more we can do


def _clock(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).strftime("%H:%M:%S")


def _hostport(ip: str, port: int) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _table(rows: list[tuple[str, ...]], indent: str = "    ") -> list[str]:
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    return [indent + "  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in rows]


# -- Network tab -----------------------------------------------------------

def name_ips(namer, ips) -> dict[str, tuple[str, str, str | None]]:
    """ip -> (host, source, AI provider or None), as `agentwatch net` names
    them (net.Tracker._rename). Blocking (known-host lookups): worker thread
    only. Reverse lookups are not waited for: the bare IP until a later call."""
    names = namer.name_many(ips, wait=0)
    return {ip: (*names[ip], namer.providers(ip)) for ip in ips}


def listeners_of(pid: int) -> list[tuple[str, int, str, bool]]:
    """(ip, port, scope, exposed) of the TCP listeners in *pid*'s tree now.
    psutil: worker thread only."""
    from agentwatch.net import listener_scope, tree_sockets

    found = {(s.laddr[0], s.laddr[1]) for s in tree_sockets(pid)
             if s.status == "LISTEN" and s.kind == "tcp" and s.laddr}
    return [(ip, port, scope, scope != "loopback")
            for ip, port in sorted(found) for scope in (listener_scope(ip),)]


def _endpoint_table(rows: list[tuple[str, ...]], width: int) -> list[str]:
    """The Outgoing table. Too wide for *width*: each AI-PROVIDER flag goes on
    its own line under the ENDPOINT column, then FIRST SEEN goes, then HOST is
    cut short if needed."""
    table = _table(rows)
    if width <= 20 or max(map(len, table)) < width:
        return table
    for keep in ((0, 1, 2, 3), (0, 1, 3)):
        table = _table([tuple(r[i] for i in keep) for r in rows])
        if max(map(len, table)) < width:
            break
    else:  # still too wide: HOST cut with an ellipsis, one line per endpoint
        dots = ascii_safe("…", "...")
        cut = max(10, max(len(r[0]) for r in rows) - (max(map(len, table)) - width + 1))
        rows = [(r[0] if len(r[0]) <= cut else r[0][:cut - len(dots)] + dots, *r[1:])
                for r in rows]
        table = _table([(r[0], r[1], r[3]) for r in rows])
    hang = " " * (4 + max(len(r[0]) for r in rows) + 2)
    out = []
    for line, row in zip(table, rows):
        out += [line, hang + row[4]] if row[4] else [line]
    return out


def net_text(pid: int, spans, names: dict, listeners, seen_in_actions: str,
             width: int = 0) -> str:
    """The Network tab: *spans* (NetSampler.spans) by endpoint, named from
    *names* (name_ips), and *listeners* (listeners_of; None: not read yet).
    Lines longer than *width* continue indented."""
    merged: dict[tuple[str, int], list[float]] = {}
    for e in spans:
        span = merged.setdefault((e.ip, e.port), [e.first_seen, e.last_seen])
        span[0], span[1] = min(span[0], e.first_seen), max(span[1], e.last_seen)
    lines = [f"  {seen_in_actions} (remote ip:port seen during its actions)", "",
             f"  Outgoing: pid {pid} and its children, last 30 min (polled every second)"]
    providers = 0
    if not merged:
        lines.append("    none seen yet")
    else:
        rows = [("HOST", "ENDPOINT", "FIRST SEEN", "LAST SEEN", "")]
        for (ip, port), (first, last) in sorted(merged.items(), key=lambda kv: kv[1][0]):
            host, source, provider = names.get(ip, (ip, "ip", None))
            providers += provider is not None
            rows.append((f"{host} [{source}]", _hostport(ip, port), _clock(first), _clock(last),
                         f"AI-PROVIDER {provider}" if provider else ""))
        lines += _endpoint_table(rows, width)
    lines += ["", "  Listening now"]
    exposed = 0
    if listeners is None:
        lines.append("    checking" + ascii_safe("…", "..."))
    elif not listeners:
        lines.append("    none")
    else:
        rows = [("ADDRESS", "SCOPE")]
        for ip, port, scope, is_exposed in listeners:
            exposed += is_exposed
            rows.append((_hostport(ip, port), f"EXPOSED ({scope})" if is_exposed else scope))
        lines += _table(rows)
    lines += ["", f"  {len(merged)} endpoint(s), {providers} to AI providers; "
                  f"{exposed} listener(s) reachable from other machines"]
    if width > 20:
        lines = [textwrap.fill(line, width - 1, subsequent_indent=" " * 6,
                               break_on_hyphens=False) if len(line) >= width else line
                 for line in lines]
    return "\n".join(lines)


# -- Other AI on this machine ---------------------------------------------

def unmonitored(result) -> set[str]:
    """Names of the programs using AI that agentwatch cannot monitor (no
    adapter): what `agentwatch detect` counts as "not monitored"."""
    from agentwatch.net import _printable  # process names can carry control chars

    return {_printable(u.name) for u in result.usages if u.adapter is None}


def detect_text(result, at: float | None, every_s: float) -> str:
    """The `d` overlay: `agentwatch detect`'s table."""
    from agentwatch.net import _printable

    head = f"Checked every {every_s:.0f}s" + (f", last at {_clock(at)}" if at else "")
    if at is None:
        return f"{head}.\n\nChecking" + ascii_safe("…", "...")
    if result is None:
        return f"{head}.\n\nUnavailable: the check failed (it is retried)."
    if not result.usages:
        lines = ["No programs using AI found."]
    else:
        rows = [("PID", "PROGRAM", "PROVIDERS", "CONNS", "LOCAL", "SUPPORTED")]  # as `detect`
        rows += [(str(u.pid), _printable(u.name), ",".join(sorted(u.providers)) or "-",
                  str(u.connections), u.local_runtime or "-", u.adapter or "no")
                 for u in result.usages]
        n = len(unmonitored(result))
        lines = _table(rows, "") + [
            "", f"{len(result.usages)} program(s) using AI ({n} not monitored by agentwatch)"]
    if result.partial:
        lines.append("Partial scan: run as administrator/root to see all processes")
    if result.unresolved:
        lines.append(f"Could not resolve: {', '.join(result.unresolved)}")
    return f"{head} (agentwatch detect).\n\n" + "\n".join(lines)


# -- weekly report ----------------------------------------------------------

def history_figures(now: float | None = None) -> tuple[dict, dict]:
    """(today's report totals, the 7-day report.build) from the history DB as synced.
    SQLite: worker thread only. Raises when the DB cannot be opened."""
    from agentwatch import history, report

    now = datetime.now() if now is None else datetime.fromtimestamp(now)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    conn = history.connect()
    try:
        # ponytail: "today" is the 24h from local midnight; on a 25-hour (DST)
        # day its last hour is left out. Exact: a report.build start/end window.
        today = report.build(conn, 1, now=midnight + 86400)["totals"]
        return today, report.build(conn, 7, now=now.timestamp())
    finally:
        conn.close()


def _money(totals: dict) -> str:
    """Spend of report totals: $0.00 with no session, n/a with none priced."""
    x = totals["cost_usd"]
    return "$0.00" if not totals["sessions"] else "n/a" if x is None else _usd(x)


def week_label(today: dict, week: dict) -> str:
    """'today $9.80 · week $61.00 ▲12%' (vs the 7 days before; no arrow
    without a previous week's spend)."""
    cost, prev = week["totals"]["cost_usd"], week["previous"]["cost_usd"]
    trend = ""
    if cost is not None and prev:
        pct = round((cost - prev) / prev * 100)
        trend = f" {ascii_safe('▲', '^') if pct >= 0 else ascii_safe('▼', 'v')}{abs(pct)}%"
    return f"today {_money(today)}{ascii_safe(' · ', ' | ')}week {_money(week['totals'])}{trend}"


def report_text(week: dict | None, synced_at: float | None, failed: bool,
                every_s: float) -> str:
    """The `w` overlay: `agentwatch report`'s lines for the last 7 days."""
    from agentwatch.report import render

    if failed:
        return "History unavailable: the history DB could not be synced or read."
    if week is None:
        return "Syncing history" + ascii_safe("…", "...")
    # first and one line: in view without scrolling (80x24)
    note = (f"History DB synced at {_clock(synced_at)} (every {every_s / 60:.0f} min; "
            "the last minute's logs wait).")
    return note + "\n\n" + "\n".join(render(week, limit=3))
