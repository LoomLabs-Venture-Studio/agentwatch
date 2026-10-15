"""Tests for agentwatch.net (`agentwatch net`, Sprint 34 B1) and the runtime
table in ai_detect. Every OS/network call is a fake.
"""

from __future__ import annotations

import json
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import psutil
import pytest
from click.testing import CliRunner

from agentwatch import net
from agentwatch.ai_detect import AI_PROVIDERS, LOCAL_LLM_PORTS, LOCAL_RUNTIMES, runtime_of
from agentwatch.cli import cli
from agentwatch.detectors.security.network import KNOWN_AGENT_HOSTS, _flaggable

T0 = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def conn(ip, port=443, udp=False, status="ESTABLISHED", lport=50000):
    return SimpleNamespace(
        laddr=SimpleNamespace(ip="10.0.0.2", port=lport),
        raddr=SimpleNamespace(ip=ip, port=port) if ip else (),
        status=status,
        type=socket.SOCK_DGRAM if udp else socket.SOCK_STREAM,
    )


class FakeProc:
    def __init__(self, pid, name, conns=(), kids=(), cmdline=(), exe="", deny=False):
        self.pid, self._name, self._conns, self._kids = pid, name, list(conns), list(kids)
        self._cmdline, self._exe, self._deny = list(cmdline), exe, deny
        self._parent = None
        for k in self._kids:
            k._parent = self

    def name(self):
        return self._name

    def cmdline(self):
        if self._deny:
            raise psutil.AccessDenied(self.pid)
        return self._cmdline

    def exe(self):
        if self._deny:
            raise psutil.AccessDenied(self.pid)
        return self._exe

    def parents(self):
        p, out = self._parent, []
        while p:
            out, p = [*out, p], p._parent
        return out

    def children(self, recursive=False):
        return [d for k in self._kids for d in (k, *k.children(recursive=True))]

    def net_connections(self, kind):
        return self._conns


def table(*procs):
    by_pid = {p.pid: p for p in procs}

    def process(pid):
        if pid not in by_pid:
            raise psutil.NoSuchProcess(pid)
        return by_pid[pid]

    return by_pid, process


# -- runtime table -------------------------------------------------------------

@pytest.mark.parametrize("name, runtime", [
    ("ollama.exe", "ollama"), ("ollama app.exe", "ollama"), ("Ollama", "ollama"),
    ("llama-server.exe", "llama.cpp"), ("LM Studio.exe", "lm-studio"),
    ("lms.exe", "lm-studio"), ("llmster", "lm-studio"), ("Jan-Desktop.exe", "jan"),
    ("jan-llama-worker", "jan"), ("gpt4all", "gpt4all"), ("msty-local.exe", "msty"),
    ("MstySidecar_x64.exe", "msty"), ("Msty Studio.exe", "msty"),
])
def test_runtime_names_exact_case_and_exe(name, runtime):
    assert runtime_of(name) == runtime


@pytest.mark.parametrize("name", [
    "ollamafoo.exe", "myollama", "chatty.exe", "lmstudio-helper", "janitor", "helms.exe",
    "llama-server2", "python.exe", "chat.exe",
])
def test_no_substring_or_ungated_match(name):
    assert runtime_of(name, FakeProc(1, name)) is None


def test_weak_names_need_their_gate():
    py = FakeProc(1, "python.exe", cmdline=["python", "-m", "llama_cpp.server"])
    assert runtime_of("python.exe", py) == "llama-cpp-python"
    assert runtime_of("python3.12", py) == "llama-cpp-python"
    assert runtime_of("python.exe", FakeProc(1, "python.exe", cmdline=["python", "x.py"])) is None
    assert runtime_of("python.exe") is None  # no proc -> gate can't be read
    chat = FakeProc(2, "chat.exe", exe=r"C:\Users\x\gpt4all\bin\chat.exe")
    assert runtime_of("chat.exe", chat) == "gpt4all"
    assert runtime_of("chat.exe", FakeProc(2, "chat.exe", exe=r"C:\Slack\chat.exe")) is None
    assert runtime_of("chat.exe", FakeProc(2, "chat.exe", deny=True)) is None


def test_ports_map_to_one_runtime_each():
    assert sum(len(r.ports) for r in LOCAL_RUNTIMES.values()) == len(LOCAL_LLM_PORTS)
    assert (LOCAL_LLM_PORTS[11434], LOCAL_LLM_PORTS[1234], LOCAL_LLM_PORTS[8000]) == (
        "ollama", "lm-studio", "llama-cpp-python")


# -- targets -------------------------------------------------------------------

def test_targets_dedup_ancestor_and_extra_pid():
    worker = FakeProc(3, "llama-server.exe")
    serve = FakeProc(2, "ollama.exe", kids=[worker])
    app = FakeProc(1, "ollama app.exe", kids=[serve])
    other = FakeProc(9, "claude.exe")
    by_pid, process = table(app, serve, worker, other, FakeProc(5, "lms.exe"))
    found = net.find_targets([9, 1, 404], process_iter=lambda: list(by_pid.values()),
                             process=process)
    assert found == [net.Target(1, "ollama", "ollama app.exe"),
                     net.Target(5, "lm-studio", "lms.exe"),
                     net.Target(9, "pid", "claude.exe")]


# -- collector (moved from closed PR #132's egress.py) ---------------------------

def test_tree_sockets_returns_full_records_including_listen():
    child = FakeProc(11, "c", [conn("::ffff:93.184.215.14", 80),
                               conn("8.8.8.8", 53, status="NONE", udp=True)])
    root = FakeProc(10, "r", [conn("160.79.104.10"), conn(None, status="LISTEN", lport=11434)],
                    kids=[child])
    assert set(net.tree_sockets(10, process=table(root, child)[1])) == {
        net.SocketInfo(10, ("10.0.0.2", 50000), ("160.79.104.10", 443), "ESTABLISHED", "tcp"),
        net.SocketInfo(10, ("10.0.0.2", 11434), (), "LISTEN", "tcp"),
        net.SocketInfo(11, ("10.0.0.2", 50000), ("93.184.215.14", 80), "ESTABLISHED", "tcp"),
        net.SocketInfo(11, ("10.0.0.2", 50000), ("8.8.8.8", 53), "NONE", "udp"),
    }


def test_excluded_child_and_its_subtree_are_skipped():
    sub_tool = FakeProc(21, "t", [conn("8.8.4.4")])
    sub_agent = FakeProc(20, "a", [conn("8.8.8.8")], kids=[sub_tool])
    root = FakeProc(10, "r", [conn("160.79.104.10")], kids=[sub_agent])
    assert {s.pid for s in net.tree_sockets(10, {20}, table(root)[1])} == {10}


def test_vanished_or_denied_process_is_skipped():
    class Gone(FakeProc):
        def net_connections(self, kind):
            raise psutil.NoSuchProcess(self.pid)

    class Denied(FakeProc):
        def net_connections(self, kind):
            raise psutil.AccessDenied(self.pid)

    root = FakeProc(10, "r", [conn("160.79.104.10")],
                    kids=[Gone(11, "g"), Denied(12, "d", [conn("1.1.1.1")])])
    assert {s.pid for s in net.tree_sockets(10, process=table(root)[1])} == {10}
    assert net.tree_sockets(99, process=table(root)[1]) == []


def test_falls_back_to_connections_on_old_psutil():
    class OldProc(FakeProc):
        net_connections = None

        def connections(self, kind):
            return self._conns

    [s] = net.tree_sockets(10, process=table(OldProc(10, "o", [conn("1.1.1.1")]))[1])
    assert s.raddr == ("1.1.1.1", 443)



def test_local_addresses_are_never_endpoints():
    # net reuses the detector's _flaggable(): exactly "not loopback/unspecified/
    # link-local/multicast" (unparseable counts as local).
    for ip in ("127.0.0.1", "::1", "0.0.0.0", "::", "169.254.1.1", "fe80::1",
               "224.0.0.251", "ff02::fb", "not-an-ip"):
        assert not _flaggable(ip), ip
    for ip in ("160.79.104.10", "2001:db8::5", "192.168.1.1"):
        assert _flaggable(ip), ip


# -- outgoing ------------------------------------------------------------------

class FakeNamer:
    def __init__(self):
        self.calls = []

    def name(self, ip):
        self.calls.append(ip)
        return f"host-{ip}", "rdns"


def test_poll_filters_local_tags_lan_and_tracks_seen(monkeypatch):
    kid = FakeProc(3, "llama-server.exe", conns=[conn("104.18.1.1")])
    root = FakeProc(2, "ollama.exe", kids=[kid], conns=[
        conn("127.0.0.1", 11434), conn("::1"), conn("169.254.1.1"), conn(None),
        conn("192.168.0.7", 80), conn("8.8.8.8", 53, udp=True),
    ])
    _, process = table(root, kid)
    tracker = net.Tracker(FakeNamer(), process=process)
    target = [net.Target(2, "ollama", "ollama.exe")]

    new = tracker.poll(target, T0)
    got = {(e.pid, e.process, e.ip, e.port, e.kind, e.lan) for e in new}
    assert got == {(3, "llama-server.exe", "104.18.1.1", 443, "tcp", False),
                   (2, "ollama.exe", "192.168.0.7", 80, "tcp", True),
                   (2, "ollama.exe", "8.8.8.8", 53, "udp", False)}
    assert all(e.runtime == "ollama" and e.target_pid == 2 for e in new)

    later = T0 + timedelta(seconds=5)
    assert tracker.poll(target, later) == []  # nothing new
    ep = tracker.endpoints[(2, 3, "104.18.1.1", 443, "tcp")]
    assert (ep.first_seen, ep.last_seen) == (T0, later)
    assert len(tracker.namer.calls) == 3  # named once per endpoint


def test_allow_listed_hosts_are_still_reported():
    # Board 2026-10-15: KNOWN_AGENT_HOSTS / AI_PROVIDERS never hide anything here.
    assert "downloads.claude.ai" in KNOWN_AGENT_HOSTS and "api.anthropic.com" in (
        AI_PROVIDERS["anthropic"])
    names = {"34.36.57.103": "downloads.claude.ai", "160.79.104.10": "api.anthropic.com"}
    root = FakeProc(2, "ollama.exe", [conn(ip) for ip in names])
    tracker = net.Tracker(net.Namer(dns_cache=lambda: names, rdns=no_rdns),
                          process=table(root)[1])
    new = tracker.poll([net.Target(2, "ollama", "ollama.exe")], T0)
    assert {(e.ip, e.host, e.host_source) for e in new} == {
        (ip, host, "dns-cache") for ip, host in names.items()}


def test_every_tree_is_sampled_before_any_naming():
    log = []

    class Logged(FakeProc):
        def net_connections(self, kind):
            log.append(f"read {self.pid}")
            return self._conns

    class SlowNamer:
        def name(self, ip):
            log.append(f"name {ip}")
            return ip, "ip"

    a, b = Logged(1, "ollama.exe", [conn("1.1.1.1")]), Logged(2, "lms.exe", [conn("2.2.2.2")])
    tracker = net.Tracker(SlowNamer(), process=table(a, b)[1])
    tracker.poll([net.Target(1, "ollama", "ollama.exe"), net.Target(2, "lm-studio", "lms.exe")])
    assert log == ["read 1", "read 2", "name 1.1.1.1", "name 2.2.2.2"]


def test_vanished_owner_named_question_mark():
    tracker = net.Tracker(FakeNamer(), process=table()[1])
    assert tracker._name(77) == "?"


# -- naming --------------------------------------------------------------------

def no_rdns(ip):
    raise socket.herror(1, "not found")


def test_naming_order_dns_cache_then_rdns_then_ip():
    namer = net.Namer(dns_cache=lambda: {"1.1.1.1": "one.one.one.one"},
                      rdns=lambda ip: ("rdns.example", [], [ip]) if ip == "2.2.2.2"
                      else no_rdns(ip))
    assert namer.name("1.1.1.1") == ("one.one.one.one", "dns-cache")
    assert namer.name("2.2.2.2") == ("rdns.example", "rdns")
    assert namer.name("3.3.3.3") == ("3.3.3.3", "ip")


def test_dns_cache_refresh_throttled_and_miss_not_final():
    snapshots = iter([{}, {"5.5.5.5": "late.example"}])
    calls, clock, rdns_calls = [], [100.0], []

    def dns():
        calls.append(clock[0])
        return next(snapshots)

    def rdns(ip):
        rdns_calls.append(ip)
        raise OSError

    namer = net.Namer(dns_cache=dns, rdns=rdns, clock=lambda: clock[0])
    assert namer.name("5.5.5.5") == ("5.5.5.5", "ip")
    clock[0] += 1
    assert namer.name("5.5.5.5") == ("5.5.5.5", "ip")  # within 5 s: no refresh
    assert len(calls) == 1 and rdns_calls == ["5.5.5.5"]  # rdns failure cached
    clock[0] += 5
    assert namer.name("5.5.5.5") == ("late.example", "dns-cache")
    assert len(calls) == 2


def test_names_from_network_are_made_printable():
    namer = net.Namer(dns_cache=lambda: {}, rdns=lambda ip: ("evil\x1b[2Jhost", [], [ip]))
    assert namer.name("6.6.6.6") == ("evil?[2Jhost", "rdns")


def ps(stdout):
    return lambda args, **kw: subprocess.CompletedProcess(args, 0, stdout=stdout)


def test_dns_cache_parses_list_and_single_object():
    rows = [
        {"Entry": "registry.ollama.ai", "Data": "104.18.1.1", "Type": 1},
        {"Entry": "ollama.com", "Data": "2606:4700::1", "Type": 28},
        {"Entry": "www.x.com", "Data": "x.cdn.net", "Type": 5},  # CNAME skipped
        {"Entry": "gateway.docker.internal", "Data": None, "Type": 28},
    ]
    assert net.dns_cache_snapshot(ps(json.dumps(rows))) == {
        "104.18.1.1": "registry.ollama.ai", "2606:4700::1": "ollama.com"}
    one = json.dumps({"Entry": "a.example", "Data": "9.9.9.9", "Type": 1})
    assert net.dns_cache_snapshot(ps(one)) == {"9.9.9.9": "a.example"}


def test_dns_cache_failures_are_empty():
    def boom(args, **kw):
        raise subprocess.TimeoutExpired(args, 10)

    def missing(args, **kw):
        raise FileNotFoundError("powershell")

    assert net.dns_cache_snapshot(boom) == {}
    assert net.dns_cache_snapshot(missing) == {}
    assert net.dns_cache_snapshot(ps("")) == {}
    assert net.dns_cache_snapshot(ps("not json")) == {}


def test_powershell_called_with_fixed_argument_list():
    seen = {}

    def run(args, **kw):
        seen.update(args=args, **kw)
        return subprocess.CompletedProcess(args, 0, stdout="[]")

    net.dns_cache_snapshot(run)
    assert seen["args"][0] == "powershell" and "shell" not in seen
    assert seen["timeout"] == 10


# -- CLI -----------------------------------------------------------------------

def fake_cli(monkeypatch, targets, sockets=()):
    monkeypatch.setattr(net, "find_targets", lambda pids: list(targets))
    monkeypatch.setattr(net, "tree_sockets", lambda pid, **kw: [
        net.SocketInfo(pid, ("10.0.0.2", 50000), raddr, "ESTABLISHED", "tcp") for raddr in sockets])
    namer = net.Namer
    monkeypatch.setattr(net, "Namer", lambda: namer(
        dns_cache=lambda: {"104.18.1.1": "registry.ollama.ai"}, rdns=no_rdns))


def test_cli_once_json_shape(monkeypatch):
    fake_cli(monkeypatch, [net.Target(7, "ollama", "ollama.exe")],
             [("104.18.1.1", 443), ("127.0.0.1", 11434)])
    result = CliRunner().invoke(cli, ["net", "--once", "--json"])
    assert result.exit_code == 0, result.output
    doc = json.loads(result.output)
    assert doc["targets"] == [{"pid": 7, "runtime": "ollama", "process": "ollama.exe"}]
    [ep] = doc["outgoing"]
    first_seen = ep.pop("first_seen")
    assert datetime.fromisoformat(first_seen) == datetime.fromisoformat(ep.pop("last_seen"))
    assert ep == {"runtime": "ollama", "target_pid": 7, "pid": 7, "process": "ollama.exe",
                  "ip": "104.18.1.1", "port": 443, "kind": "tcp",
                  "host": "registry.ollama.ai", "host_source": "dns-cache", "lan": False}
    assert "message" not in doc


def test_cli_once_text_table(monkeypatch):
    fake_cli(monkeypatch, [net.Target(7, "ollama", "ollama.exe")], [("104.18.1.1", 443)])
    out = CliRunner().invoke(cli, ["net", "--once"]).output
    assert "registry.ollama.ai [dns-cache]" in out and "104.18.1.1:443/tcp" in out
    assert "1 outgoing endpoint(s)" in out


def test_cli_no_runtime_text_and_json(monkeypatch):
    fake_cli(monkeypatch, [])
    text = CliRunner().invoke(cli, ["net", "--once"])
    assert text.exit_code == 0 and "No local AI runtime running" in text.output
    doc = json.loads(CliRunner().invoke(cli, ["net", "--once", "--json"]).output)
    assert doc["targets"] == [] and doc["outgoing"] == []
    assert "No local AI runtime running" in doc["message"]


def test_cli_stream_json_events_and_summary_on_ctrl_c(monkeypatch):
    fake_cli(monkeypatch, [net.Target(7, "ollama", "ollama.exe")], [("104.18.1.1", 443)])
    ticks = iter([None, KeyboardInterrupt])

    def sleep(s):
        if next(ticks):
            raise KeyboardInterrupt

    monkeypatch.setattr("time.sleep", sleep)
    result = CliRunner().invoke(cli, ["net", "--json"])
    assert result.exit_code == 0, result.output
    events = [json.loads(line) for line in result.output.splitlines()]
    assert [e["event"] for e in events] == ["target", "outgoing", "summary"]
    assert events[0]["state"] == "started" and events[1]["host"] == "registry.ollama.ai"
    assert len(events[2]["outgoing"]) == 1
