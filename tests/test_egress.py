"""Tests for agentwatch.egress (per-agent egress sampler, #130) and the
UndeclaredEgressDetector. Every OS/network call is a fake.
"""

from __future__ import annotations

import socket
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from agentwatch import egress
from agentwatch.detectors.security.network import UndeclaredEgressDetector
from agentwatch.parser.models import Action, ActionBuffer, ToolType

CLAUDE = ["C:\\Users\\x\\.local\\bin\\claude.exe"]
T0 = datetime(2026, 10, 15, 12, 0)


def conn(ip, port=443, status="ESTABLISHED", udp=False, lport=50000):
    return SimpleNamespace(
        laddr=SimpleNamespace(ip="10.0.0.2", port=lport),
        raddr=SimpleNamespace(ip=ip, port=port) if ip else (),
        status=status,
        type=socket.SOCK_DGRAM if udp else socket.SOCK_STREAM,
    )


class FakeProc:
    def __init__(self, pid, conns=(), kids=(), cmdline=CLAUDE, created=1.0, deny=False):
        self.pid, self._conns, self._kids = pid, list(conns), list(kids)
        self._cmdline, self._created, self._deny = cmdline, created, deny

    def name(self):
        return Path(self._cmdline[0]).name

    def cmdline(self):
        return self._cmdline

    def create_time(self):
        return self._created

    def children(self, recursive=False):
        return [d for k in self._kids for d in (k, *k.children(recursive=True))]

    def net_connections(self, kind):
        if self._deny:
            raise psutil.AccessDenied(self.pid)
        return self._conns


def table(*procs):
    by_pid = {p.pid: p for p in procs}

    def process(pid):
        if pid not in by_pid:
            raise psutil.NoSuchProcess(pid)
        return by_pid[pid]

    return process


IPS = {"api.anthropic.com": "160.79.104.10", "example.com": "93.184.215.14",
       "pypi.org": "151.101.0.223"}


def fake_resolve(host, port):
    if host not in IPS:
        raise socket.gaierror(host)
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (IPS[host], port))]


@pytest.fixture(autouse=True)
def clear_dns_cache():
    egress._host_ips.cache_clear()
    egress._provider_ips.cache_clear()


# --- sampler ---------------------------------------------------------------

def test_tree_sockets_returns_full_records_including_listen():
    child = FakeProc(11, [conn("::ffff:93.184.215.14", 80), conn("8.8.8.8", 53, "NONE", udp=True)])
    root = FakeProc(10, [conn("160.79.104.10"), conn(None, status="LISTEN", lport=11434)],
                    kids=[child])
    assert set(egress.tree_sockets(10, process=table(root, child))) == {
        egress.SocketInfo(10, ("10.0.0.2", 50000), ("160.79.104.10", 443), "ESTABLISHED", "tcp"),
        egress.SocketInfo(10, ("10.0.0.2", 11434), (), "LISTEN", "tcp"),
        egress.SocketInfo(11, ("10.0.0.2", 50000), ("93.184.215.14", 80), "ESTABLISHED", "tcp"),
        egress.SocketInfo(11, ("10.0.0.2", 50000), ("8.8.8.8", 53), "NONE", "udp"),
    }


def test_is_local_address():
    for ip in ("127.0.0.1", "::1", "0.0.0.0", "::", "169.254.1.1", "fe80::1",
               "224.0.0.251", "ff02::fb", "not-an-ip"):
        assert egress.is_local_address(ip), ip
    for ip in ("160.79.104.10", "2001:db8::5", "192.168.1.1"):
        assert not egress.is_local_address(ip), ip


def test_remote_endpoints_cover_tree_and_drop_local_and_listen():
    grandchild = FakeProc(12, [conn("151.101.0.223")])
    child = FakeProc(11, [conn("::ffff:93.184.215.14", 80)], kids=[grandchild])
    root = FakeProc(10, [
        conn("160.79.104.10"),
        conn(None, status="LISTEN"),  # no remote
        conn("127.0.0.1"),
        conn("169.254.1.1"),
        conn("224.0.0.251", udp=True),
    ], kids=[child])
    sockets = egress.tree_sockets(10, {10}, table(root))
    assert egress.remote_endpoints(sockets) == {
        ("160.79.104.10", 443), ("93.184.215.14", 80), ("151.101.0.223", 443),
    }


def test_tracked_child_agent_and_its_subtree_are_excluded():
    sub_tool = FakeProc(21, [conn("8.8.4.4")])
    sub_agent = FakeProc(20, [conn("8.8.8.8")], kids=[sub_tool])
    root = FakeProc(10, [conn("160.79.104.10")], kids=[sub_agent])
    assert {s.pid for s in egress.tree_sockets(10, {10, 20}, table(root))} == {10}


def test_vanished_or_denied_process_is_skipped():
    class Gone(FakeProc):
        def net_connections(self, kind):
            raise psutil.NoSuchProcess(self.pid)

    root = FakeProc(10, [conn("160.79.104.10")],
                    kids=[Gone(11), FakeProc(12, [conn("1.1.1.1")], deny=True)])
    assert {s.pid for s in egress.tree_sockets(10, process=table(root))} == {10}
    assert egress.tree_sockets(99, process=table(root)) == []


def test_falls_back_to_connections_on_old_psutil():
    class OldProc(FakeProc):
        net_connections = None

        def connections(self, kind):
            return self._conns

    sockets = egress.tree_sockets(10, process=table(OldProc(10, [conn("1.1.1.1")])))
    assert egress.remote_endpoints(sockets) == {("1.1.1.1", 443)}


# --- real-pid check --------------------------------------------------------

def test_synthetic_pid_is_never_sampled():
    # A CRC32 synthetic pid (Cursor composer) that happens to hit a real,
    # unrelated process: the adapter check rejects it.
    unrelated = FakeProc(4242, [conn("1.1.1.1")], cmdline=["C:\\Windows\\notepad.exe"])
    verdicts: dict = {}
    out = egress.sample([("k", 4242, "cursor", set())], verdicts,
                        process=table(unrelated), resolve=fake_resolve)
    assert out == {}
    assert egress.is_agent_pid(4242, "cursor", verdicts, table(unrelated)) is False


def test_missing_pid_is_skipped():
    assert egress.sample([("k", 99, "claude-code", set())], {},
                         process=table(), resolve=fake_resolve) == {}


def test_only_real_agent_pids_excluded_from_tree_walks():
    # A synthetic Cursor pid that collides with a child of the claude tree
    # must not cut that child out; a real tracked sub-agent still is.
    sub_agent = FakeProc(20, [conn("8.8.8.8")])
    tool = FakeProc(4242, [conn("151.101.0.223")], cmdline=["C:\tools\node.exe"])
    root = FakeProc(10, [conn("160.79.104.10")], kids=[sub_agent, tool])
    out = egress.sample(
        [("root", 10, "claude-code", set()), ("sub", 20, "claude-code", set()),
         ("cursor", 4242, "cursor", set())],
        {}, process=table(root, sub_agent, tool), resolve=fake_resolve)
    assert out.keys() == {"root", "sub"}
    assert out["root"][0] == {("160.79.104.10", 443), ("151.101.0.223", 443)}
    assert out["sub"][0] == {("8.8.8.8", 443)}


def test_verdict_cached_per_pid_and_create_time(monkeypatch):
    calls = []
    real = egress.match_process_adapter
    monkeypatch.setattr(egress, "match_process_adapter",
                        lambda c, n: calls.append(n) or real(c, n))
    verdicts: dict = {}
    proc = FakeProc(10)
    for _ in range(3):
        assert egress.is_agent_pid(10, "claude-code", verdicts, table(proc)) is True
    assert len(calls) == 1
    # Same pid reused by a new process: checked again.
    reused = FakeProc(10, cmdline=["C:\\Windows\\notepad.exe"], created=2.0)
    assert egress.is_agent_pid(10, "claude-code", verdicts, table(reused)) is False
    assert len(calls) == 2


# --- allow-list ------------------------------------------------------------

def _act(**kw):
    return Action(timestamp=T0, tool_name=kw.pop("tool", "Bash"), tool_type=ToolType.BASH,
                  success=True, **kw)


def test_declared_hosts_from_network_host_and_command_urls():
    actions = [
        _act(tool="WebFetch", network_host="example.com"),
        _act(command="curl -s 'https://user:pw@PyPI.org:8443/simple/?token=x' | head"),
        _act(command="echo http://[2001:db8::1]/ and ftp://ignored.example"),
        _act(command="ls -la"),
    ]
    assert egress.declared_hosts(actions) == {"example.com", "pypi.org", "2001:db8::1"}


@pytest.mark.parametrize("tool_input, expected", [
    ({"host": 1234}, None),
    ({"host": ["evil.example"]}, None),
    ({"host": 1234, "url": "https://example.com/x?token=s"}, "example.com"),
    ({"host": "api.example.com"}, "api.example.com"),
])
def test_non_str_host_in_log_gives_no_network_host(tool_input, expected):
    from agentwatch.parser.logs import parse_moltbot_entry

    entry = {"type": "tool", "tool_call": {"name": "net", "input": tool_input}}
    action = parse_moltbot_entry(entry)
    assert action is not None
    assert action.network_host == expected
    egress.declared_hosts([action])  # no AttributeError on .lower()


def test_allowed_ips_providers_plus_declared_dns_failures_ignored():
    allowed = egress.allowed_ips({"example.com", "no-such-host.invalid"}, fake_resolve)
    assert {"160.79.104.10", "93.184.215.14"} <= allowed
    assert "151.101.0.223" not in allowed


def test_dns_lookups_cached_per_host():
    seen = []

    def counting(host, port):
        seen.append(host)
        return fake_resolve(host, port)

    egress.allowed_ips({"example.com"}, counting)
    first = len(seen)
    egress.allowed_ips({"example.com"}, counting)
    assert len(seen) == first


def test_dns_failures_not_cached():
    calls = {}

    def flaky(host, port):  # every lookup fails the first time, then works
        calls[host] = calls.get(host, 0) + 1
        if calls[host] == 1:
            raise OSError(host)
        return fake_resolve(host, port)

    assert egress.allowed_ips({"example.com"}, flaky) == frozenset()
    assert {"160.79.104.10", "93.184.215.14"} <= egress.allowed_ips({"example.com"}, flaky)


def test_sample_returns_endpoints_and_allowed_for_real_pid():
    root = FakeProc(10, [conn("160.79.104.10"), conn("151.101.0.223")])
    out = egress.sample([("k", 10, "claude-code", {"example.com"})], {},
                        process=table(root), resolve=fake_resolve)
    observed, allowed = out["k"]
    assert observed == {("160.79.104.10", 443), ("151.101.0.223", 443)}
    assert {"160.79.104.10", "93.184.215.14"} <= allowed


# --- Egress state + detector -----------------------------------------------

def test_merge_tracks_first_last_seen_and_reports_change():
    e = egress.Egress()
    ep = ("151.101.0.223", 443)
    assert e.merge({ep}, frozenset({"160.79.104.10"}), T0) is True
    later = T0 + timedelta(seconds=2)
    assert e.merge({ep}, frozenset({"160.79.104.10"}), later) is False
    assert e.endpoints[ep] == [T0, later]
    # Allowed set only grows (an evicted action still explains its endpoint).
    assert e.merge(set(), frozenset({"151.101.0.223"}), later) is True
    assert e.merge(set(), frozenset(), later) is False
    assert e.undeclared() == {}


def test_detector_noop_without_sampler_data():
    buf = ActionBuffer()
    assert buf.egress is None
    assert UndeclaredEgressDetector().check(buf) is None


def test_detector_quiet_when_all_endpoints_declared():
    buf = ActionBuffer()
    buf.egress = egress.Egress()
    buf.egress.merge({("160.79.104.10", 443)}, frozenset({"160.79.104.10"}), T0)
    assert UndeclaredEgressDetector().check(buf) is None


def test_detector_fires_on_undeclared_endpoint():
    buf = ActionBuffer()
    buf.egress = egress.Egress()
    observed = {("160.79.104.10", 443)} | {(f"203.0.113.{i}", 443) for i in range(7)}
    buf.egress.merge(observed, frozenset({"160.79.104.10"}), T0)
    later = T0 + timedelta(seconds=2)
    buf.egress.merge({("2001:db8::5", 8443)}, frozenset(), later)
    w = UndeclaredEgressDetector().check(buf)
    assert w is not None
    assert w.signal == "undeclared_egress"
    assert w.severity.value == "low"
    assert w.category.value == "network"
    assert w.details["count"] == 8
    assert "8 endpoint(s)" in w.message
    assert len(w.details["endpoints"]) == 5
    # Most recently seen first; IPv6 bracketed.
    assert w.details["endpoints"][0] == {
        "endpoint": "[2001:db8::5]:8443",
        "first_seen": later.isoformat(), "last_seen": later.isoformat(),
    }
    assert "160.79.104.10:443" not in {e["endpoint"] for e in w.details["endpoints"]}


def test_dedup_key_follows_undeclared_set():
    from agentwatch.detectors.base import warning_dedup_key

    def key(observed):
        buf = ActionBuffer()
        buf.egress = egress.Egress()
        buf.egress.merge(observed, frozenset(), T0)
        return warning_dedup_key(UndeclaredEgressDetector().check(buf))

    a = {("203.0.113.1", 443)}
    b = a | {("203.0.113.2", 443)}
    assert key(a) == key(set(a)) != key(b)
    assert key(b) == key(set(b))


def test_detector_registered():
    from agentwatch.detectors.security import get_all_security_detectors
    assert "undeclared_egress" in [d.name for d in get_all_security_detectors()]


# --- multi_app merge path --------------------------------------------------

async def test_multi_app_samples_off_loop_and_merges(monkeypatch):
    from agentwatch.detectors import create_registry
    from agentwatch.discovery import AgentProcess
    from agentwatch.health.rot import RotScorer
    from agentwatch.ui import multi_app
    from agentwatch.ui.multi_app import AgentItem, MultiAgentWatchApp

    calls = []

    def fake_sample(targets, verdicts):
        calls.append(targets)
        return {targets[0][0]: ({("203.0.113.9", 443)}, frozenset({"160.79.104.10"}))}

    monkeypatch.setattr(multi_app.egress, "sample", fake_sample)

    app = MultiAgentWatchApp(agent_processes=[], security_mode=True)
    async with app.run_test():
        real, synthetic, gone = Path("real.jsonl"), Path("cursor.vscdb#x"), Path("gone.jsonl")
        metas = {
            real: AgentProcess(pid=10, agent_type="claude-code", working_directory=None),
            synthetic: AgentProcess(pid=3000000001, agent_type="cursor", working_directory=None),
        }
        monkeypatch.setattr(app.watcher, "get_process_meta", metas.get)
        for path in (real, synthetic, gone):
            buf = ActionBuffer()
            buf.add(_act(tool="WebFetch", network_host="example.com"))
            app.agents[path] = {
                "buffer": buf, "registry": create_registry(mode="all"),
                "item": AgentItem(path), "rot_scorer": RotScorer(), "pid": None,
                "team_id": None, "_last_count": 1, "_last_report": object(),
            }

        await app._sample_egress()

        targets = calls[0]
        assert [(t[0], t[1], t[2]) for t in targets] == [
            (real, 10, "claude-code"), (synthetic, 3000000001, "cursor")]
        assert targets[0][3] == {"example.com"}
        assert app.agents[real]["buffer"].egress.undeclared().keys() == {("203.0.113.9", 443)}
        assert app.agents[real]["_last_count"] == -1          # forces a recompute
        assert app.agents[synthetic]["buffer"].egress is None  # never sampled
        assert app.agents[gone]["buffer"].egress is None

        # Security off: no sampling at all.
        app.security_mode = False
        await app._sample_egress()
        assert len(calls) == 1


def _app_with_agents(monkeypatch, metas):
    from agentwatch.detectors import create_registry
    from agentwatch.health.rot import RotScorer
    from agentwatch.ui.multi_app import AgentItem, MultiAgentWatchApp

    app = MultiAgentWatchApp(agent_processes=[], security_mode=True)

    def install():
        monkeypatch.setattr(app.watcher, "get_process_meta", metas.get)
        for path in metas:
            app.agents[path] = {
                "buffer": ActionBuffer(), "registry": create_registry(mode="all"),
                "item": AgentItem(path), "rot_scorer": RotScorer(), "pid": None,
                "team_id": None, "_last_count": 1, "_last_report": object(),
            }

    return app, install


@pytest.mark.parametrize("where", ["sample", "declared_hosts"])
async def test_multi_app_survives_sampler_error(monkeypatch, where):
    from agentwatch.discovery import AgentProcess
    from agentwatch.ui import multi_app

    def boom(*a):
        raise RuntimeError("cmdline secret")

    monkeypatch.setattr(multi_app.egress, where, boom)
    path = Path("real.jsonl")
    app, install = _app_with_agents(monkeypatch, {
        path: AgentProcess(pid=10, agent_type="claude-code", working_directory=None)})
    async with app.run_test():
        install()
        await app._sample_egress()  # must not raise
        assert app._sampling is False
        assert app.agents[path]["buffer"].egress is None


async def test_multi_app_in_flight_guard(monkeypatch):
    from agentwatch.discovery import AgentProcess
    from agentwatch.ui import multi_app

    calls = []
    monkeypatch.setattr(multi_app.egress, "sample", lambda *a: calls.append(a) or {})
    app, install = _app_with_agents(monkeypatch, {
        Path("real.jsonl"): AgentProcess(pid=10, agent_type="claude-code",
                                         working_directory=None)})
    async with app.run_test():
        install()
        app._sampling = True
        await app._sample_egress()
        assert calls == []
        assert app._sampling is True  # left to the in-flight call to reset
        app._sampling = False
        await app._sample_egress()
        assert len(calls) == 1


async def test_multi_app_skips_agent_reaped_during_sample(monkeypatch):
    from agentwatch.discovery import AgentProcess
    from agentwatch.ui import multi_app

    keep, reaped = Path("keep.jsonl"), Path("reaped.jsonl")
    app, install = _app_with_agents(monkeypatch, {
        keep: AgentProcess(pid=10, agent_type="claude-code", working_directory=None),
        reaped: AgentProcess(pid=11, agent_type="claude-code", working_directory=None)})

    def fake_sample(targets, verdicts):
        app.agents.pop(reaped)  # reaped on the loop while the thread ran
        return {t[0]: ({("203.0.113.9", 443)}, frozenset()) for t in targets}

    monkeypatch.setattr(multi_app.egress, "sample", fake_sample)
    async with app.run_test():
        install()
        await app._sample_egress()
        assert reaped not in app.agents
        assert app.agents[keep]["buffer"].egress.undeclared().keys() == {("203.0.113.9", 443)}


async def test_multi_app_does_not_sample_stopped_agent(monkeypatch):
    from agentwatch.discovery import AgentProcess
    from agentwatch.ui import multi_app

    calls = []
    monkeypatch.setattr(multi_app.egress, "sample", lambda t, v: calls.append(t) or {})
    live, stopped = Path("live.jsonl"), Path("stopped.jsonl")
    app, install = _app_with_agents(monkeypatch, {
        live: AgentProcess(pid=10, agent_type="claude-code", working_directory=None),
        stopped: AgentProcess(pid=11, agent_type="claude-code", working_directory=None,
                              command="(stopped)")})
    async with app.run_test():
        install()
        await app._sample_egress()
        assert [t[0] for t in calls[0]] == [live]
