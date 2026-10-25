"""watch-all network, other AI and weekly report (Sprint 36, PR 8): the
detail view's Network tab names the NetSampler's endpoints and lists the
process's listeners; detect() and the history sync + report run on workers
and show in the header, the `d`/`w` overlays and one feed line each."""

from __future__ import annotations

import asyncio
import os
import re
import sqlite3
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import pytest
from test_multi_app_table import _screen, _seed, _wait

from agentwatch import ai_detect, history
from agentwatch.ai_detect import AiUsage, DetectResult
from agentwatch.net_sampler import Endpoint
from agentwatch.ui import machine, multi_app
from agentwatch.ui.detail import DetailScreen
from agentwatch.ui.help import HelpScreen
from agentwatch.ui.multi_app import MultiAgentWatchApp

NOW = time.time()


class FakeSampler:
    """NetSampler's surface: spans() of one pid, no thread, no psutil."""

    def __init__(self, spans):
        self._spans = spans

    def spans(self, pid):
        return self._spans.get(pid)

    def track(self, pid): ...
    def untrack(self, pid): ...
    def start(self): ...
    def stop(self): ...

    def endpoints(self, pid, start, end):
        return None


class FakeNamer:
    def __init__(self, gate=None):
        self.gate, self.calls = gate, 0

    def name_many(self, ips, wait=0):
        self.calls += 1
        if self.gate is not None:
            self.gate.wait(10)  # a slow lookup, until the test releases it
        return {ip: ("api.anthropic.com", "known") if ip == "160.79.104.10"
                else ("[b]evil[/b].example", "rdns") for ip in ips}

    def providers(self, ip):
        return "anthropic" if ip == "160.79.104.10" else None


def _header(app) -> str:
    return str(app.query_one("#header").render()).rstrip()


def _feed(app) -> str:
    return str(app.query_one("#feed-lines").render())


def _overlay(app) -> str:
    return str(app.screen.query_one("#help Static").render())


async def _network_tab(app, pilot, sampled=True):
    _seed(app, "proj", pid=4242)
    app.agents[Path("proj.jsonl")]["net_sampled"] = sampled
    app.refresh_ui()
    await pilot.pause()
    await pilot.press("enter")
    await _wait(pilot, lambda: isinstance(app.screen, DetailScreen) and app.screen.ready)
    await pilot.press("3")


def _process_app(monkeypatch, spans, namer, listeners):
    monkeypatch.setattr(multi_app, "find_running_agents", lambda cache=None: [])
    monkeypatch.setattr(machine, "listeners_of", lambda pid: listeners)
    app = MultiAgentWatchApp(agent_processes=[])
    app._net_sampler = FakeSampler(spans)
    app._namer = namer
    return app


SPANS = {4242: [
    Endpoint("160.79.104.10", 443, NOW - 120, NOW - 60),
    Endpoint("203.0.113.9", 8443, NOW - 30, NOW - 5),
    Endpoint("160.79.104.10", 443, NOW - 20, NOW - 1),  # the same endpoint again: one row
    Endpoint("127.0.0.53", 53, NOW - 20, NOW - 1),  # local DNS: hidden, as by `agentwatch net`
    Endpoint("fe80::1", 5353, NOW - 20, NOW - 1),  # link-local: hidden too
]}
LISTENERS = [("0.0.0.0", 3000, "all interfaces", True), ("127.0.0.1", 9229, "loopback", False)]


@pytest.mark.parametrize("size", [(120, 40), (80, 24)])
async def test_network_tab_names_endpoints_flags_providers_and_lists_listeners(
        monkeypatch, size):
    app = _process_app(monkeypatch, SPANS, FakeNamer(), LISTENERS)
    async with app.run_test(size=size) as pilot:
        await _network_tab(app, pilot)
        await _wait(pilot, lambda: "api.anthropic.com" in _screen(app)
                    and "EXPOSED" in _screen(app))
        text = str(app.screen.query_one("#d-net").render())
        assert "Outgoing: pid 4242 and its children, last 30 min" in text
        # 80 columns: the flag goes on its own line, under ENDPOINT
        rows = [line for line in re.sub(r"\n +AI-", " AI-", text).splitlines() if ":443" in line]
        assert len(rows) == 1 and "api.anthropic.com [known]" in rows[0]
        assert "AI-PROVIDER anthropic" in rows[0]
        assert datetime.fromtimestamp(NOW - 120).strftime("%H:%M:%S") in rows[0]  # first
        assert datetime.fromtimestamp(NOW - 1).strftime("%H:%M:%S") in rows[0]  # last
        assert "[b]evil[/b].example [rdns]  203.0.113.9:8443" in text  # literal
        assert "0.0.0.0:3000    EXPOSED (all interfaces)" in text
        assert "127.0.0.1:9229  loopback" in text
        assert "2 endpoint(s), 1 to AI providers; 1 listener(s) reachable" in text
        assert "127.0.0.53" not in text and "fe80::1" not in text
        lines = text.splitlines()
        header = next(line for line in lines if "ENDPOINT" in line)
        flag = next(line for line in lines if "AI-PROVIDER" in line)
        assert flag.index("AI-PROVIDER") >= header.index("ENDPOINT")  # never under HOST
        print(f"\n--- Network tab {size[0]}x{size[1]} ---\n{_screen(app)}")


def test_network_tab_cuts_long_hosts_one_row_per_endpoint_at_80_columns():
    spans = [Endpoint("203.0.113.9", 8443, NOW - 30, NOW - 5),
             Endpoint("2001:db8::1", 443, NOW - 20, NOW - 1)]
    host = "ec2-203-0-113-9.eu-west-1.compute.amazonaws.example.com"
    names = {"203.0.113.9": (host, "rdns", None), "2001:db8::1": (host, "rdns", None)}
    text = machine.net_text(4242, spans, names, [], "Net: 2 endpoints", 80)
    lines = text.splitlines()
    rows = [line for line in lines if line.startswith("    ec2-")]
    assert len(rows) == 2 and all(len(line) < 80 and "…" in line for line in rows), text
    assert datetime.fromtimestamp(NOW - 1).strftime("%H:%M:%S") in rows[1]  # LAST SEEN kept
    assert "FIRST SEEN" not in text
    assert lines[lines.index(rows[1]) + 1].strip() == ""  # nothing wrapped onto a 2nd line


async def test_network_tab_names_on_a_worker_and_the_ui_stays_responsive(monkeypatch):
    gate = threading.Event()
    namer = FakeNamer(gate)
    app = _process_app(monkeypatch, SPANS, namer, LISTENERS)
    async with app.run_test(size=(120, 40)) as pilot:
        await _network_tab(app, pilot)
        await _wait(pilot, lambda: app._naming)
        t = time.monotonic()
        await pilot.press("1")
        await _wait(pilot, lambda: "Health [" in _screen(app))
        await pilot.press("3")
        await _wait(pilot, lambda: "160.79.104.10:443" in _screen(app))  # bare IP for now
        assert time.monotonic() - t < 2.0 and app._naming
        gate.set()
        await _wait(pilot, lambda: "api.anthropic.com" in _screen(app))


async def test_network_tab_without_a_process(monkeypatch):
    app = MultiAgentWatchApp()  # --all-logs
    async with app.run_test(size=(80, 24)) as pilot:
        await _network_tab(app, pilot)
        await _wait(pilot, lambda: "Network: n/a (no process)" in _screen(app))
    app = _process_app(monkeypatch, {}, FakeNamer(), [])
    async with app.run_test(size=(80, 24)) as pilot:  # an editor-hosted session
        await _network_tab(app, pilot, sampled=False)
        await _wait(pilot, lambda: "Net: n/a (not attributable)" in _screen(app))


# -- other AI on this machine ---------------------------------------------

def _usage(pid, name, adapter=None, providers=("openai",), conns=2):
    return AiUsage(pid=pid, name=name, providers=set(providers), connections=conns,
                   adapter=adapter)


@pytest.fixture
def machine_on(monkeypatch):
    """Workers on, fast; the history sync is a no-op unless a test sets one."""
    monkeypatch.setattr(MultiAgentWatchApp, "MACHINE_CHECKS", True)
    monkeypatch.setattr(MultiAgentWatchApp, "DETECT_EVERY_S", 0.2)


async def _no_sync(self):
    return None


async def test_unmonitored_ai_header_overlay_and_one_feed_line_per_new_program(
        monkeypatch, machine_on):
    monkeypatch.setattr(MultiAgentWatchApp, "_sync_history", _no_sync)
    results = [
        [_usage(1, "claude", adapter="claude-code", providers=("anthropic",)),
         _usage(2, "[b]py[/b]thon")],
        [_usage(1, "claude", adapter="claude-code"), _usage(2, "[b]py[/b]thon"),
         _usage(3, "ollama", providers=())],
    ]
    calls = []

    def detect():
        calls.append(1)
        return DetectResult(results[min(len(calls), 2) - 1], unresolved=["api.x.ai"])

    monkeypatch.setattr(ai_detect, "detect", detect)
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        _seed(app, "proj")
        await _wait(pilot, lambda: "+1 unmonitored AI" in _header(app))
        assert "unmonitored AI program" not in _feed(app)  # the first result is the baseline
        await _wait(pilot, lambda: "+2 unmonitored AI" in _header(app))
        await _wait(pilot, lambda: len(calls) >= 4)
        assert _feed(app).count("new unmonitored AI program") == 1
        assert "new unmonitored AI program: ollama" in _feed(app)
        await pilot.press("d")
        await _wait(pilot, lambda: isinstance(app.screen, HelpScreen))
        text = _overlay(app)
        assert "Checked every 0s" in text and "(agentwatch detect)" in text
        assert "[b]py[/b]thon" in text and "claude-code" in text and "SUPPORTED" in text
        assert "3 program(s) using AI (2 not monitored by agentwatch)" in text
        assert "Could not resolve: api.x.ai" in text
        await pilot.press("enter")  # main keys are off under it
        assert isinstance(app.screen, HelpScreen)
        await pilot.press("d")
        await _wait(pilot, lambda: not isinstance(app.screen, HelpScreen))


async def test_detect_failure_hides_the_count_and_ui_stays_responsive(monkeypatch, machine_on):
    monkeypatch.setattr(MultiAgentWatchApp, "_sync_history", _no_sync)
    gate = threading.Event()
    mode = {"fail": False}

    def detect():
        gate.wait(10)  # slow, off the UI thread
        if mode["fail"]:
            raise OSError("no socket table")
        return DetectResult([_usage(2, "python")])

    monkeypatch.setattr(ai_detect, "detect", detect)
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        _seed(app, "proj")
        await _wait(pilot, lambda: app._detecting)
        t = time.monotonic()
        await pilot.press("question_mark")
        await _wait(pilot, lambda: isinstance(app.screen, HelpScreen))
        await pilot.press("escape")
        await _wait(pilot, lambda: not isinstance(app.screen, HelpScreen))
        assert time.monotonic() - t < 2.0 and app._detecting  # detect() still running
        gate.set()
        await _wait(pilot, lambda: "+1 unmonitored AI" in _header(app))
        mode["fail"] = True
        await _wait(pilot, lambda: "unmonitored" not in _header(app))
        await pilot.press("d")
        await _wait(pilot, lambda: "Unavailable: the check failed" in _screen(app))
        assert app.is_running


# -- weekly report ------------------------------------------------------------

def _midnight() -> float:
    return datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()


def _synthetic_history() -> None:
    conn = history.connect()
    today = max(_midnight() + 1, NOW - 60)
    rows = [  # (name, agent, project, ended, cost, waste)
        ("a", "claude-code", "web", today, 2.5, 0.5),
        ("b", "codex", "api", NOW - 3 * 86400, 10.0, 1.0),
        ("c", "claude-code", "web", NOW - 10 * 86400, 10.0, 0.0),  # the week before
    ]
    with conn:
        for name, agent, project, ended, cost, waste in rows:
            conn.execute(
                "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (name, agent, name, project, ended - 600, ended, 40, 1000, cost, 1, 100,
                 waste, 80, "healthy", 1, 1, NOW))
        conn.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
                     ("b", "k1", "loop", "high", "progress", "loop: Bash", 1.0, 100, NOW))
    conn.close()


@pytest.fixture
def history_on(monkeypatch, machine_on, tmp_path):
    """History in tmp: no real HOME, XDG dir or log is read or written."""
    for var, sub in (("HOME", "home"), ("USERPROFILE", "home"), ("XDG_CONFIG_HOME", "cfg"),
                     ("APPDATA", "appdata")):
        monkeypatch.setenv(var, str(tmp_path / sub))
    monkeypatch.setattr(ai_detect, "detect", lambda: DetectResult([]))
    assert str(history.db_path()).startswith(str(tmp_path))


async def test_header_today_week_trend_and_report_overlay(monkeypatch, history_on, tmp_path):
    _synthetic_history()
    monkeypatch.setattr(machine, "SYNC_ARGS", (sys.executable, "-c", "pass"))
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        _seed(app, "proj")
        app.refresh_ui()
        await _wait(pilot, lambda: "week" in _header(app))
        header = _header(app)
        assert "today $2.50 · week $12.50 ▲25%" in header, header
        assert "1 session · 1 active · 0 need you" in header and "spent" in header
        print(f"\n--- header 120x40 ---\n{header}")
        await pilot.press("w")
        await _wait(pilot, lambda: isinstance(app.screen, HelpScreen))
        text = _overlay(app)
        for line in ("agentwatch report: last 7 days", "Sessions 2", "Spend ~$12.50",
                     "Waste: ~$1.50", "vs previous 7 days: spend +$2.50",
                     "Costliest findings", "loop", "By agent", "codex", "By project",
                     "History DB synced at", "every 5 min"):
            assert line in text, (line, text)
        print(f"\n--- report overlay 120x40 ---\n{_screen(app)}")
        await pilot.resize_terminal(80, 24)
        await pilot.pause()
        screen = _screen(app)
        assert "│ History DB synced at" in screen.splitlines()[1], screen  # in view, no scrolling
        print(f"\n--- report overlay 80x24 ---\n{screen}")
        await pilot.resize_terminal(80, 18)  # too short for it: it scrolls
        await pilot.pause()
        scroll = app.screen.query_one("#help")
        assert scroll.max_scroll_y > 0
        await pilot.press("pagedown")
        await _wait(pilot, lambda: scroll.scroll_y > 0)
        await pilot.resize_terminal(80, 24)
        await pilot.press("escape")
        await _wait(pilot, lambda: not isinstance(app.screen, HelpScreen))
        await pilot.pause()
        header = _header(app)  # 80 columns: today/week go first, counts kept
        assert "week" not in header and "1 session · 1 active · 0 need you" in header, header
        print(f"\n--- header 80x24 ---\n{header}")


async def test_real_sync_subprocess_writes_only_the_tmp_db(monkeypatch, history_on, tmp_path):
    db = history.db_path()
    assert not db.exists()
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await _wait(pilot, lambda: app._history is not None or app._history_failed)
        for _ in range(100):
            if app._history is not None:
                break
            await pilot.pause(0.1)
        assert app._history is not None and app.sync_seconds is not None
        assert "today $0.00 · week $0.00" in _header(app), _header(app)
    assert db.exists() and db.is_relative_to(tmp_path)
    assert sqlite3.connect(db).execute("SELECT count(*) FROM sessions").fetchone() == (0,)
    assert os.environ["XDG_DATA_HOME"].startswith(str(tmp_path))


async def test_history_failure_hides_figures_with_one_feed_line(monkeypatch, history_on):
    monkeypatch.setattr(machine, "SYNC_ARGS", (sys.executable, "-c", "raise SystemExit(1)"))
    monkeypatch.setattr(MultiAgentWatchApp, "HISTORY_EVERY_S", 0.3)
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await _wait(pilot, lambda: "history unavailable" in _feed(app))
        await pilot.pause(1.0)  # more failed syncs: still one line
        assert _feed(app).count("history unavailable") == 1
        assert "week" not in _header(app) and "today" not in _header(app)
        await pilot.press("w")
        await _wait(pilot, lambda: "History unavailable" in _screen(app))
        print(f"\n--- report overlay, history unavailable ---\n{_screen(app)}")


async def test_header_order_when_tight():
    app = MultiAgentWatchApp(alerter=None)
    week = {"totals": {"sessions": 9, "cost_usd": 61.0},
            "previous": {"sessions": 9, "cost_usd": 70.0}}
    async with app.run_test(size=(120, 40)) as pilot:
        for i in range(12):
            _seed(app, f"s{i}")
        app._history = ({"sessions": 2, "cost_usd": 9.8}, week)
        app._unmonitored = {"x", "y"}
        app.refresh_ui()
        await pilot.pause()
        wide = _header(app)
        assert "today $9.80 · week $61.00 ▼13%" in wide and "+2 unmonitored AI" in wide, wide
        assert wide.startswith("12 sess · 0 need you"), wide  # 100+ columns: counts cut first
        for width, has_week in ((99, False), (80, False)):
            await pilot.resize_terminal(width, 30)
            await pilot.pause()
            header = _header(app)
            assert ("week" in header) == has_week, (width, header)
            assert "+2 unmonitored AI" in header and "need you" in header, (width, header)
            if width == 99:  # under 100: today/week go, the counts stay
                assert header.startswith("12 sessions · 12 active"), header


# QA B1: a sync's pool workers never outlive watch-all ------------------------

# A stand-in for the sync: its own pool workers (sleeping), like history.sync's.
_POOL = ("import time\n"
         "from concurrent.futures import ProcessPoolExecutor\n"
         "pool = ProcessPoolExecutor(2)\n"
         "futures = [pool.submit(time.sleep, 60) for _ in range(2)]\n"
         "time.sleep(60)\n")
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="process groups")


def _tree(pid: int, n: int = 3, timeout: float = 15.0) -> list:
    """*pid* and its descendants, once there are at least *n* processes."""
    import psutil

    proc, procs = psutil.Process(pid), []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        procs = [proc, *proc.children(recursive=True)]
        if len(procs) >= n:
            return procs
        time.sleep(0.05)
    raise AssertionError(f"sync tree never reached {n} processes: {procs}")


def _all_gone(procs: list, timeout: float = 5.0) -> list:
    """The processes still running after *timeout* (zombies count as gone)."""
    import psutil

    deadline = time.monotonic() + timeout
    alive = procs
    while alive and time.monotonic() < deadline:
        alive = [p for p in alive if p.is_running() and p.status() != psutil.STATUS_ZOMBIE]
        time.sleep(0.05)
    for p in alive:  # never leave them behind, even on failure
        p.kill()
    return alive


@posix_only
async def test_quit_mid_sync_leaves_no_pool_workers(monkeypatch, history_on):
    monkeypatch.setattr(machine, "SYNC_ARGS", (sys.executable, "-c", _POOL))
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await _wait(pilot, lambda: app._sync_proc is not None)
        procs = await asyncio.to_thread(_tree, app._sync_proc.pid)
        await pilot.press("q")
    assert _all_gone(procs) == []


@posix_only
def test_sync_exits_when_watch_all_is_killed(tmp_path):
    """watch-all SIGKILLed mid-sync: the sync and its workers follow."""
    import signal
    import subprocess

    child = ("from agentwatch.ui.machine import exit_with_parent\n"
             "exit_with_parent()\n" + _POOL)
    parent = subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess, sys, time\n"
         f"p = subprocess.Popen([sys.executable, '-c', {child!r}], start_new_session=True)\n"
         "print(p.pid, flush=True)\n"
         "time.sleep(60)\n"],
        stdout=subprocess.PIPE, text=True)
    try:
        sync_pid = int(parent.stdout.readline())
        procs = _tree(sync_pid)
    finally:
        parent.send_signal(signal.SIGKILL)
        parent.wait()
    assert _all_gone(procs) == [], "sync tree outlived its parent"
