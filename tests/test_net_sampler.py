"""NetSampler with faked psutil: no live sockets, no real processes."""

from __future__ import annotations

import threading
import time
from collections import namedtuple
from datetime import datetime, timedelta, timezone

import psutil
import pytest

from agentwatch.discovery import AgentProcess
from agentwatch.net_sampler import NetSampler, attributable, window
from agentwatch.parser.models import IDLE_GAP_CAP, Action, ToolType

Addr = namedtuple("Addr", "ip port")
Conn = namedtuple("Conn", "pid laddr raddr status")


def conn(pid, ip, port, status="ESTABLISHED"):
    return Conn(pid, Addr("127.0.0.1", 50000), Addr(ip, port) if ip else (), status)


class FakeProc:
    def __init__(self, pid, conns=(), children=(), error=None):
        self.pid, self.conns, self.kids, self.error = pid, list(conns), list(children), error

    def children(self, recursive=False):
        assert recursive
        if self.error and self.pid == 1:
            raise self.error(self.pid)
        return self.kids

    def net_connections(self, kind="inet"):
        if self.error:
            raise self.error(self.pid)
        return self.conns


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def make(procs, *, global_ok=True, clock=None):
    """Sampler over FakeProcs; global table built from the same conns."""
    table = {p.pid: p for p in procs}
    calls = []

    def connections(kind):
        calls.append(kind)
        if not global_ok:
            raise psutil.AccessDenied()
        return [c for p in procs for c in p.conns]

    def process(pid):
        if pid not in table:
            raise psutil.NoSuchProcess(pid)
        return table[pid]

    s = NetSampler(1.0, connections=connections, process=process, clock=clock or Clock())
    return s, calls


def test_root_and_descendant_sockets_recorded_listen_and_unconnected_skipped():
    child = FakeProc(2, [conn(2, "::ffff:1.2.3.4", 443), conn(2, None, 0)])
    root = FakeProc(1, [conn(1, "5.6.7.8", 80), conn(1, "9.9.9.9", 22, psutil.CONN_LISTEN)],
                    [child])
    other = FakeProc(3, [conn(3, "8.8.8.8", 53)])  # not in the tree
    s, _ = make([root, child, other])
    s.track(1)
    s.sample()
    assert s.endpoints(1, 1000, 1000) == [("1.2.3.4", 443), ("5.6.7.8", 80)]


def test_global_table_denied_falls_back_and_is_not_retried():
    root = FakeProc(1, [conn(1, "5.6.7.8", 443)])
    s, calls = make([root], global_ok=False)
    s.track(1)
    s.sample()
    s.sample()
    assert calls == ["inet"]
    assert s.endpoints(1, 1000, 1000) == [("5.6.7.8", 443)]


@pytest.mark.parametrize("error", [psutil.NoSuchProcess, psutil.AccessDenied])
def test_child_errors_skipped(error):
    bad = FakeProc(2, [conn(2, "6.6.6.6", 1)], error=error)
    root = FakeProc(1, [conn(1, "5.6.7.8", 443)], [bad])
    s, _ = make([root, bad], global_ok=False)
    s.track(1)
    s.sample()
    assert s.endpoints(1, 1000, 1000) == [("5.6.7.8", 443)]


def test_dead_root_is_empty_and_others_still_recorded():
    root = FakeProc(1, error=psutil.NoSuchProcess)
    other = FakeProc(5, [conn(5, "5.6.7.8", 443)])
    s, _ = make([root, other])
    s.track(1)
    s.track(5)
    s.track(42)  # never existed
    s.sample()
    assert s.endpoints(1, 1000, 1000) == []
    assert s.endpoints(42, 1000, 1000) == []
    assert s.endpoints(5, 1000, 1000) == [("5.6.7.8", 443)]


def test_gap_splits_spans_and_window_in_gap_excludes():
    clock = Clock()
    root = FakeProc(1, [conn(1, "5.6.7.8", 443)])
    s, _ = make([root], clock=clock)
    s.track(1)
    for t, up in [(1000, True), (1001, True), (1002, False), (1010, False), (1020, True)]:
        clock.t = t
        root.conns = [conn(1, "5.6.7.8", 443)] if up else []
        s.sample()
    assert [(e.first_seen, e.last_seen) for e in s._spans[1]] == [(1000, 1001), (1020, 1020)]
    assert s.endpoints(1, 1005, 1015) == []
    assert s.endpoints(1, 1002, 1002) == [("5.6.7.8", 443)]  # within one interval of slack


def test_old_spans_pruned():
    clock = Clock()
    root = FakeProc(1, [conn(1, "5.6.7.8", 443)])
    s, _ = make([root], clock=clock)
    s.track(1)
    s.sample()
    root.conns = []
    clock.t += IDLE_GAP_CAP.total_seconds() + 1
    s.sample()
    assert s._spans[1] == []


def test_endpoints_none_when_untracked_or_before_tracking():
    clock = Clock(1000)
    s, _ = make([FakeProc(1)], clock=clock)
    assert s.endpoints(1, 0, 2000) is None
    s.track(1)
    assert s.endpoints(1, 900, 999) is None
    assert s.endpoints(1, 900, 1000) == []
    s.untrack(1)
    assert s.endpoints(1, 900, 1000) is None


def act(ts, duration_ms=0):
    return Action(ts, "Bash", ToolType.BASH, True, duration_ms=duration_ms)


UTC_TS = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
END = UTC_TS.timestamp()


def test_window_duration():
    assert window(act(UTC_TS, 2500), 1.0) == (END - 2.5, END)


def test_window_previous_ts_then_point():
    assert window(act(UTC_TS), END - 7) == (END - 7, END)
    assert window(act(UTC_TS), None) == (END, END)


def test_window_naive_is_utc():
    assert window(act(UTC_TS.replace(tzinfo=None)), None) == (END, END)


def test_window_none_timestamp_uses_now():
    start, end = window(act(None), None)
    assert start == end and abs(end - time.time()) < 5


def test_window_capped():
    cap = IDLE_GAP_CAP.total_seconds()
    assert window(act(UTC_TS), END - cap * 3) == (END - cap, END)
    ts = UTC_TS + timedelta(hours=5)
    assert window(act(ts, int(cap * 4000)), None) == (ts.timestamp() - cap, ts.timestamp())


def proc(agent_type, command=""):
    return AgentProcess(pid=1, agent_type=agent_type, working_directory=None, command=command)


@pytest.mark.parametrize("p, expected", [
    (proc("claude-code", "claude"), True),
    (proc("kilo-code", "kilo"), True),
    (proc("codex", "codex exec"), True),
    (proc("cursor"), False),
    (proc("copilot-vscode"), False),
    (proc("cline"), False),
    (proc("claude-desktop"), False),
    (proc("codex", "codex.exe app-server --listen"), False),
    (proc("kilo-code", "/ext/bin/kilo serve --port 0"), False),
    (proc("nope", "x"), False),
])
def test_attributable(p, expected):
    assert attributable(p) is expected


def test_thread_samples_survives_errors_and_stops():
    ran = threading.Event()
    s = NetSampler(0.01)
    s.stop()  # safe before start
    calls = []

    def sample():
        calls.append(1)
        if len(calls) >= 2:
            ran.set()
        raise RuntimeError("boom")  # must not kill the thread

    s.sample = sample
    s.start()
    assert ran.wait(0.2)
    s.stop()
    s.stop()
    n = len(calls)
    time.sleep(0.03)
    assert len(calls) == n


def test_sample_with_nothing_tracked_reads_no_socket_table():
    def boom(kind="inet"):
        raise AssertionError("socket table read with nothing tracked")

    NetSampler(connections=boom).sample()
