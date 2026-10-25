"""Tests for agentwatch.net (`agentwatch net`, Sprint 34 B1-B3) and the runtime
table in ai_detect. Every OS/network call is a fake.
"""

from __future__ import annotations

import json
import signal
import socket
import subprocess
import threading
import time
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
    def __init__(self, pid, name, conns=(), kids=(), cmdline=(), exe="", deny=False,
                 created=1.0):
        self.pid, self._name, self._conns, self._kids = pid, name, list(conns), list(kids)
        self._cmdline, self._exe, self._deny = list(cmdline), exe, deny
        self._created, self.cmdline_reads = created, 0
        self._parent = None
        for k in self._kids:
            k._parent = self

    def name(self):
        return self._name

    def create_time(self):
        return self._created

    def cmdline(self):
        self.cmdline_reads += 1
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
    ("lm-studio", "lm-studio"), ("lmstudio.exe", "lm-studio"), ("LM Studio", "lm-studio"),
    ("LM Studio Helper", "lm-studio"), ("LM Studio Helper (Renderer)", "lm-studio"),
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


def test_exiting_process_is_not_promoted_to_target():
    # Live 2026-10-15: Ollama's llama-server child, exiting as the model
    # unloaded, failed its parent lookup and showed up as its own target.
    class Exiting(FakeProc):
        def parents(self):
            raise psutil.NoSuchProcess(self.pid)

    class Zombie(FakeProc):
        def parents(self):
            raise psutil.ZombieProcess(self.pid)

    class Denied(FakeProc):
        def parents(self):
            raise psutil.AccessDenied(self.pid)

    procs = [Exiting(3, "llama-server.exe"), Zombie(4, "ollama.exe"), Denied(5, "lms.exe")]
    by_pid, process = table(*procs)
    found = net.find_targets(process_iter=lambda: list(by_pid.values()), process=process)
    assert found == [net.Target(5, "lm-studio", "lms.exe")]  # denied: kept


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

    def name_many(self, ips, wait=None):
        return {ip: self.name(ip) for ip in ips}

    def providers(self, ip):
        return None


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
    tracker = net.Tracker(net.Namer(dns_cache=lambda: names, rdns=no_rdns, resolve=no_resolve),
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

    class SlowNamer(FakeNamer):
        def name(self, ip):
            log.append(f"name {ip}")
            return ip, "ip"

    a, b = Logged(1, "ollama.exe", [conn("1.1.1.1")]), Logged(2, "lms.exe", [conn("2.2.2.2")])
    tracker = net.Tracker(SlowNamer(), process=table(a, b)[1])
    tracker.poll([net.Target(1, "ollama", "ollama.exe"), net.Target(2, "lm-studio", "lms.exe")])
    assert log == ["read 1", "read 2", "name 1.1.1.1", "name 2.2.2.2"]


def test_lan_includes_private_and_shared_cgnat():
    for ip in ("192.168.0.7", "10.1.2.3", "fd00::1", "100.64.0.1", "100.127.255.254"):
        assert net._is_lan(ip), ip
    for ip in ("100.63.255.255", "100.128.0.1", "104.18.1.1", "2606:4700::1", "::6440:101"):
        assert not net._is_lan(ip), ip


def test_vanished_owner_named_question_mark():
    tracker = net.Tracker(FakeNamer(), process=table()[1])
    assert tracker._name(77) == "?"


# -- naming --------------------------------------------------------------------

def no_rdns(ip):
    raise socket.herror(1, "not found")


def no_resolve(host, port):
    raise socket.gaierror(host)


def resolver(table_, calls=None):
    """Fake getaddrinfo over {host: [ip, ...]}; unknown hosts fail."""
    def resolve(host, port):
        if calls is not None:
            calls.append(host)
        if host not in table_:
            raise socket.gaierror(host)
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 (ip, port)) for ip in table_[host]]
    return resolve


def test_naming_order_dns_cache_then_rdns_then_ip():
    namer = net.Namer(dns_cache=lambda: {"1.1.1.1": "one.one.one.one"},
                      rdns=lambda ip: ("rdns.example", [], [ip]) if ip == "2.2.2.2"
                      else no_rdns(ip), resolve=no_resolve)
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

    namer = net.Namer(dns_cache=dns, rdns=rdns, clock=lambda: clock[0], resolve=no_resolve)
    assert namer.name("5.5.5.5") == ("5.5.5.5", "ip")
    clock[0] += 1
    assert namer.name("5.5.5.5") == ("5.5.5.5", "ip")  # within 5 s: no refresh
    assert len(calls) == 1 and rdns_calls == ["5.5.5.5"]  # rdns failure cached
    clock[0] += 5
    assert namer.name("5.5.5.5") == ("late.example", "dns-cache")
    assert len(calls) == 2


def test_names_from_network_are_made_printable():
    namer = net.Namer(dns_cache=lambda: {}, rdns=lambda ip: ("evil\x1b[2Jhost", [], [ip]),
                      resolve=no_resolve)
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

def test_reverse_lookups_run_concurrently():
    both = threading.Barrier(2, timeout=2)  # passes only if both lookups run at once

    def rdns(ip):
        both.wait()
        return f"r-{ip}", [], [ip]

    namer = net.Namer(dns_cache=lambda: {}, rdns=rdns, resolve=no_resolve)
    assert namer.name_many(["1.1.1.1", "2.2.2.2"]) == {
        "1.1.1.1": ("r-1.1.1.1", "rdns"), "2.2.2.2": ("r-2.2.2.2", "rdns")}


def test_slow_reverse_lookup_capped_then_finishes_into_cache():
    release = threading.Event()

    def rdns(ip):
        if ip == "2.2.2.2":
            release.wait(5)
        return f"r-{ip}", [], [ip]

    namer = net.Namer(dns_cache=lambda: {}, rdns=rdns, resolve=no_resolve)
    start = time.monotonic()
    assert namer.name_many(["1.1.1.1", "2.2.2.2"], wait=0.2) == {
        "1.1.1.1": ("r-1.1.1.1", "rdns"), "2.2.2.2": ("2.2.2.2", "ip")}
    assert time.monotonic() - start < 1.5
    release.set()
    assert namer.name("2.2.2.2") == ("r-2.2.2.2", "rdns")  # same lookup, not a new one


def test_known_host_names_ip_and_joins_shared_cdn_ips():
    namer = net.Namer(dns_cache=lambda: {}, rdns=no_rdns, resolve=resolver({
        "ollama.com": ["104.21.0.1", "2606:4700::1"],
        "registry.ollama.ai": ["104.21.0.1"],
        "huggingface.co": ["::ffff:3.3.3.3"],
    }), known_hosts=("huggingface.co", "ollama.com", "registry.ollama.ai"))
    assert namer.name("104.21.0.1") == ("ollama.com|registry.ollama.ai", "known")
    assert namer.name("2606:4700::1") == ("ollama.com", "known")
    assert namer.name("3.3.3.3") == ("huggingface.co", "known")
    assert namer.name("9.9.9.9") == ("9.9.9.9", "ip")


def test_known_order_between_dns_cache_and_rdns():
    namer = net.Namer(dns_cache=lambda: {"1.1.1.1": "cached.example"},
                      rdns=lambda ip: ("rdns.example", [], [ip]),
                      resolve=resolver({"ollama.com": ["1.1.1.1", "2.2.2.2"]}),
                      known_hosts=("ollama.com",))
    assert namer.name("1.1.1.1") == ("cached.example", "dns-cache")  # dns-cache beats known
    assert namer.name("2.2.2.2") == ("ollama.com", "known")  # known beats rdns
    assert namer.name("3.3.3.3") == ("rdns.example", "rdns")


def test_known_refresh_after_ttl_unions_and_retries_failures():
    tables = iter([{"ollama.com": ["1.1.1.1"]},  # huggingface.co fails the first time
                   {"ollama.com": ["5.5.5.5"], "huggingface.co": ["6.6.6.6"]}])
    current, calls, clock = [next(tables)], [], [0.0]
    namer = net.Namer(dns_cache=lambda: {}, rdns=no_rdns, clock=lambda: clock[0],
                      resolve=lambda h, p: resolver(current[0], calls)(h, p),
                      known_hosts=("huggingface.co", "ollama.com"))
    assert namer.name("1.1.1.1") == ("ollama.com", "known")
    assert namer.name("5.5.5.5") == ("5.5.5.5", "ip")  # no refresh within 300 s
    assert len(calls) == 2
    clock[0] += net.KNOWN_REFRESH_S
    current[0] = next(tables)
    assert namer.name("5.5.5.5") == ("ollama.com", "known")
    assert namer.name("6.6.6.6") == ("huggingface.co", "known")  # failure retried
    assert namer.name("1.1.1.1") == ("ollama.com", "known")  # old IP kept (union)
    assert len(calls) == 4


def test_known_resolver_failure_falls_through_to_rdns():
    namer = net.Namer(dns_cache=lambda: {}, rdns=lambda ip: ("rdns.example", [], [ip]),
                      resolve=no_resolve, known_hosts=("ollama.com",))
    assert namer.name("1.1.1.1") == ("rdns.example", "rdns")


def test_known_hosts_cover_providers_agent_hosts_and_runtimes():
    hosts = set(net.KNOWN_HOSTS)
    assert {"api.anthropic.com", "downloads.claude.ai", "registry.ollama.ai",
            "llmster.lmstudio.ai", "apps.jan.ai", "gpt4all.io", "msty.studio"} <= hosts
    assert len(net.KNOWN_HOSTS) == len(hosts)  # deduped


def fake_cli(monkeypatch, targets, sockets=()):
    monkeypatch.setattr(net, "find_targets", lambda pids: list(targets))
    monkeypatch.setattr(net, "tree_sockets", lambda pid, **kw: [
        net.SocketInfo(pid, ("10.0.0.2", 50000), raddr, "ESTABLISHED", "tcp") for raddr in sockets])
    namer = net.Namer
    monkeypatch.setattr(net, "Namer", lambda: namer(
        dns_cache=lambda: {"104.18.1.1": "registry.ollama.ai"}, rdns=no_rdns,
        resolve=no_resolve))


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
                  "host": "registry.ollama.ai", "host_source": "dns-cache", "lan": False,
                  "ai_provider": None}
    assert "message" not in doc and doc["missing_pids"] == [] and doc["unwatched_agents"] == []


def test_cli_once_waits_for_rdns_only_in_the_poll(monkeypatch):
    real = net.Namer  # fake_cli swaps net.Namer for a factory of this class
    fake_cli(monkeypatch, [net.Target(7, "ollama", "ollama.exe")], [("104.18.1.1", 443)])
    waits, name_many = [], real.name_many
    monkeypatch.setattr(real, "name_many",
                        lambda self, ips, wait=net.RDNS_WAIT_S: waits.append(wait)
                        or name_many(self, ips, wait))
    assert CliRunner().invoke(cli, ["net", "--once"]).exit_code == 0
    assert waits == [net.RDNS_WAIT_S, 0]


def test_cli_once_text_table(monkeypatch):
    fake_cli(monkeypatch, [net.Target(7, "ollama", "ollama.exe")], [("104.18.1.1", 443)])
    out = CliRunner().invoke(cli, ["net", "--once"]).output
    assert "registry.ollama.ai [dns-cache]" in out and "104.18.1.1:443/tcp" in out
    assert "1 outgoing endpoint(s)" in out


def test_cli_text_process_names_made_printable(monkeypatch):
    fake_cli(monkeypatch, [net.Target(7, "pid", "evil\x1b[2J")], [("104.18.1.1", 443)])
    out = CliRunner().invoke(cli, ["net", "--once"]).output
    assert "evil?[2J(7)" in out and "\x1b" not in out


def test_cli_once_text_lists_watched_targets_without_endpoints(monkeypatch):
    fake_cli(monkeypatch, [net.Target(7, "ollama", "ollama.exe")])
    out = CliRunner().invoke(cli, ["net", "--once"]).output
    assert "Watched: ollama ollama.exe(7)" in out
    assert "No outgoing connections seen." in out


def test_cli_duration_stops_with_summary(monkeypatch):
    fake_cli(monkeypatch, [net.Target(7, "ollama", "ollama.exe")], [("104.18.1.1", 443)])
    polls, clock = [], [0.0]
    find = net.find_targets
    monkeypatch.setattr(net, "find_targets", lambda pids: polls.append(clock[0]) or find(pids))
    monkeypatch.setattr("time.monotonic", lambda: clock[0])
    monkeypatch.setattr("time.sleep", lambda s: clock.__setitem__(0, clock[0] + s))
    before = signal.getsignal(signal.SIGTERM)
    result = CliRunner().invoke(cli, ["net", "--json", "--duration", "2.5", "--interval", "1"])
    assert result.exit_code == 0, result.output
    assert signal.getsignal(signal.SIGTERM) == before  # SIGTERM -> summary handler undone
    assert polls == [0.0, 1.0, 2.0, 2.5]
    events = [json.loads(line) for line in result.output.splitlines()]
    assert events[-1]["event"] == "summary"
    assert events[-1]["targets"] == [{"pid": 7, "runtime": "ollama", "process": "ollama.exe"}]
    [ep] = events[-1]["outgoing"]
    assert ep["host"] == "registry.ollama.ai"


def test_cli_no_runtime_text_and_json(monkeypatch):
    fake_cli(monkeypatch, [])
    text = CliRunner().invoke(cli, ["net", "--once"])
    assert text.exit_code == 0 and "No local AI runtime running" in text.output
    doc = json.loads(CliRunner().invoke(cli, ["net", "--once", "--json"]).output)
    assert doc["targets"] == [] and doc["outgoing"] == []
    assert "No local AI runtime running" in doc["message"]


def test_cli_missing_pid_reported(monkeypatch):
    fake_cli(monkeypatch, [])
    monkeypatch.setattr(net, "missing_pids", lambda pids: sorted(pids))
    text = CliRunner().invoke(cli, ["net", "--once", "--pid", "4242", "--pid", "4242"])
    assert text.exit_code == 1 and "pid 4242 not found" in text.output  # stderr
    js = CliRunner().invoke(cli, ["net", "--once", "--json", "--pid", "4242"])
    assert js.exit_code == 1 and json.loads(js.stdout)["missing_pids"] == [4242]

    monkeypatch.setattr("time.sleep", lambda s: (_ for _ in ()).throw(KeyboardInterrupt))
    out = CliRunner().invoke(cli, ["net", "--json", "--pid", "4242"]).stdout
    events = [json.loads(line) for line in out.splitlines()]
    assert [e["event"] for e in events] == ["missing", "waiting", "summary"]
    assert events[0]["missing_pids"] == [4242] and events[-1]["missing_pids"] == [4242]


def test_cli_once_some_pids_found_exits_zero(monkeypatch):
    fake_cli(monkeypatch, [net.Target(7, "pid", "x.exe")])
    monkeypatch.setattr(net, "missing_pids", lambda pids: [4242])
    for extra in ([], ["--json"]):
        result = CliRunner().invoke(cli, ["net", "--once", *extra, "--pid", "4242", "--pid", "7"])
        assert result.exit_code == 0, result.output


def test_missing_pids_uses_pid_exists(monkeypatch):
    monkeypatch.setattr(psutil, "pid_exists", lambda pid: pid == 4)
    assert net.missing_pids([8, 4, 8]) == [8]


@pytest.mark.parametrize("args", [["--pid", "0"], ["--once", "--duration", "5"]])
def test_cli_usage_errors(monkeypatch, args):
    fake_cli(monkeypatch, [])
    result = CliRunner().invoke(cli, ["net", *args])
    assert result.exit_code == 2  # click UsageError


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


# -- incoming (B2) -------------------------------------------------------------

def sock(pid, laddr, raddr=(), status="ESTABLISHED", kind="tcp"):
    return net.SocketInfo(pid, laddr, raddr, status, kind)


def global_table(rows, calls=None, deny=False, procs=()):
    """Fake (net_connections, process_iter); rows are (pid, laddr ip, laddr port)
    for TCP, or (pid, ip, port, "udp")."""
    def connections(kind):
        if calls is not None:
            calls.append(kind)
        if deny:
            raise psutil.AccessDenied()
        return [SimpleNamespace(
            pid=pid, laddr=SimpleNamespace(ip=ip, port=port), raddr=(),
            type=socket.SOCK_DGRAM if udp else socket.SOCK_STREAM,
            status="NONE" if udp else "ESTABLISHED")
            for pid, ip, port, *udp in rows]
    return connections, lambda: list(procs)


def name_table(names):
    def process(pid):
        if pid not in names:
            raise psutil.NoSuchProcess(pid)
        return SimpleNamespace(name=lambda: names[pid])
    return process


def incoming_tracker(monkeypatch, trees, rows=(), names=None, **table_kw):
    """Tracker over fake trees {target pid: [SocketInfo]} and a fake global table."""
    monkeypatch.setattr(net, "tree_sockets", lambda pid, **kw: list(trees.get(pid, [])))
    connections, process_iter = global_table(rows, **table_kw)
    return net.Tracker(FakeNamer(), process=name_table(names or {}), connections=connections,
                       process_iter=process_iter)


def clients_of(records):
    return [r for r in records if isinstance(r, net.Client)]


SERVE = net.Target(10, "ollama", "ollama.exe")
LISTEN = sock(10, ("127.0.0.1", 11434), status="LISTEN")


@pytest.mark.parametrize("ip, scope", [
    ("0.0.0.0", "all interfaces"), ("::", "all interfaces"), ("192.168.1.5", "lan"),
    ("10.0.0.2", "lan"), ("203.0.113.9", "lan"), ("fe80::1%5", "lan"),
    ("127.0.0.1", "loopback"), ("::1", "loopback"), ("::ffff:127.0.0.1", "loopback"),
])
def test_listener_scope(ip, scope):
    assert net.listener_scope(ip) == scope


def test_listeners_flag_exposed_list_loopback_and_track_seen(monkeypatch):
    trees = {10: [LISTEN, sock(10, ("0.0.0.0", 8080), status="LISTEN"),
                  sock(11, ("192.168.1.5", 9000), status="LISTEN"),
                  sock(10, ("0.0.0.0", 5353), status="NONE", kind="udp")]}
    tracker = incoming_tracker(monkeypatch, trees, names={11: "llama-server.exe"})
    new = tracker.poll([SERVE], T0)
    assert {(r.pid, r.process, r.ip, r.port, r.exposed, r.scope) for r in new} == {
        (10, "ollama.exe", "127.0.0.1", 11434, False, "loopback"),
        (10, "ollama.exe", "0.0.0.0", 8080, True, "all interfaces"),
        (11, "llama-server.exe", "192.168.1.5", 9000, True, "lan")}
    assert all(isinstance(r, net.Listener) and r.runtime == "ollama" and r.target_pid == 10
               for r in new)
    later = T0 + timedelta(seconds=3)
    assert tracker.poll([SERVE], later) == []
    lst = tracker.listeners[(10, 10, "127.0.0.1", 11434)]
    assert (lst.first_seen, lst.last_seen) == (T0, later)


def test_local_client_named_by_process_via_global_table(monkeypatch):
    trees = {10: [LISTEN, sock(10, ("127.0.0.1", 11434), ("127.0.0.1", 52001))]}
    tracker = incoming_tracker(monkeypatch, trees, rows=[(4321, "127.0.0.1", 52001)],
                               names={4321: "curl.exe"})
    [c] = clients_of(tracker.poll([SERVE], T0))
    assert (c.scope, c.pid, c.process, c.listener_ip, c.listener_port, c.ip, c.port) == (
        "local", 4321, "curl.exe", "127.0.0.1", 11434, "127.0.0.1", 52001)
    assert (c.host, c.host_source) == (None, None)
    assert tracker.namer.calls == []  # local clients are never DNS-named


def test_global_table_denied_falls_back_to_per_process(monkeypatch):
    curl = FakeProc(4321, "curl.exe", [SimpleNamespace(
        laddr=SimpleNamespace(ip="127.0.0.1", port=52001), raddr=(), status="ESTABLISHED",
        type=socket.SOCK_STREAM)])
    trees = {10: [LISTEN, sock(10, ("127.0.0.1", 11434), ("127.0.0.1", 52001))]}
    tracker = incoming_tracker(monkeypatch, trees, names={4321: "curl.exe"}, deny=True,
                               procs=[curl])
    [c] = clients_of(tracker.poll([SERVE], T0))
    assert (c.scope, c.pid, c.process) == ("local", 4321, "curl.exe")


@pytest.mark.parametrize("order", [1, -1])
def test_udp_socket_on_same_ip_port_does_not_steal_client(monkeypatch, order):
    trees = {10: [LISTEN, sock(10, ("127.0.0.1", 11434), ("127.0.0.1", 52001))]}
    rows = [(4321, "127.0.0.1", 52001), (999, "127.0.0.1", 52001, "udp")][::order]
    tracker = incoming_tracker(monkeypatch, trees, rows=rows,
                               names={4321: "curl.exe", 999: "dns.exe"})
    [c] = clients_of(tracker.poll([SERVE], T0))
    assert (c.pid, c.process) == (4321, "curl.exe")


def test_loopback_client_with_unseen_owner_is_still_local(monkeypatch):
    # macOS non-root fallback can't see other users' processes.
    trees = {10: [LISTEN, sock(10, ("127.0.0.1", 11434), ("127.0.0.1", 52001))]}
    tracker = incoming_tracker(monkeypatch, trees, deny=True)
    [c] = clients_of(tracker.poll([SERVE], T0))
    assert (c.scope, c.pid, c.process, c.host) == ("local", None, "?", None)


def test_internal_client_skipped_other_target_client_listed(monkeypatch):
    # serve(10) -> its llama-server child(11) on 127.0.0.1:50500: internal.
    # `ollama run` CLI (20, another target) -> serve on 11434: listed.
    trees = {
        10: [LISTEN, sock(11, ("127.0.0.1", 50500), status="LISTEN"),
             sock(11, ("127.0.0.1", 50500), ("127.0.0.1", 52100)),
             sock(10, ("127.0.0.1", 52100), ("127.0.0.1", 50500)),
             sock(10, ("127.0.0.1", 11434), ("127.0.0.1", 52200))],
        20: [sock(20, ("127.0.0.1", 52200), ("127.0.0.1", 11434))],
    }
    rows = [(11, "127.0.0.1", 50500), (11, "127.0.0.1", 50500), (10, "127.0.0.1", 52100),
            (10, "127.0.0.1", 11434), (20, "127.0.0.1", 52200)]
    tracker = incoming_tracker(monkeypatch, trees, rows=rows,
                               names={11: "llama-server.exe", 20: "ollama.exe"})
    clients = clients_of(tracker.poll([SERVE, net.Target(20, "ollama", "ollama.exe")], T0))
    assert [(c.target_pid, c.listener_port, c.pid, c.process) for c in clients] == [
        (10, 11434, 20, "ollama.exe")]


def test_tree_sockets_reports_walked_pids_even_when_denied():
    class Denied(FakeProc):
        def net_connections(self, kind):
            raise psutil.AccessDenied(self.pid)

    root = FakeProc(10, "r", [conn("1.1.1.1")], kids=[Denied(11, "d"), FakeProc(12, "x")])
    pids = set()
    net.tree_sockets(10, process=table(root)[1], pids=pids)
    assert pids == {10, 11, 12}
    assert {s.pid for s in net.tree_sockets(10, process=table(root)[1])} == {10}


def test_denied_child_connection_is_internal_not_a_client():
    # llama-server child(11) can't be read; its connection to serve(10) is
    # still internal: the walk, not the socket owners, defines the tree.
    class Denied(FakeProc):
        def net_connections(self, kind):
            raise psutil.AccessDenied(self.pid)

    def tcp(lip, lport, rip=None, rport=0, status="ESTABLISHED"):
        return SimpleNamespace(laddr=SimpleNamespace(ip=lip, port=lport),
                               raddr=SimpleNamespace(ip=rip, port=rport) if rip else (),
                               status=status, type=socket.SOCK_STREAM)

    root = FakeProc(10, "ollama.exe", [tcp("127.0.0.1", 11434, status="LISTEN"),
                                       tcp("127.0.0.1", 11434, "127.0.0.1", 52300)],
                    kids=[Denied(11, "llama-server.exe")])
    connections, process_iter = global_table([(11, "127.0.0.1", 52300)])
    tracker = net.Tracker(FakeNamer(), process=table(root)[1], connections=connections,
                          process_iter=process_iter)
    assert clients_of(tracker.poll([SERVE], T0)) == []


def test_remote_client_named_and_tagged_lan(monkeypatch):
    trees = {10: [sock(10, ("0.0.0.0", 11434), status="LISTEN"),
                  sock(10, ("192.168.1.5", 11434), ("192.168.1.20", 60001)),
                  sock(10, ("192.168.1.5", 11434), ("8.8.4.4", 60002))]}
    tracker = incoming_tracker(monkeypatch, trees, rows=[(10, "192.168.1.5", 11434)])
    clients = clients_of(tracker.poll([SERVE], T0))
    assert {(c.ip, c.port, c.scope, c.pid, c.process, c.host, c.host_source,
             c.listener_ip) for c in clients} == {
        ("192.168.1.20", 60001, "lan", None, None, "host-192.168.1.20", "rdns", "192.168.1.5"),
        ("8.8.4.4", 60002, "public", None, None, "host-8.8.4.4", "rdns", "192.168.1.5")}
    assert tracker.endpoints == {}  # an accepted connection is not outgoing


def test_client_on_this_machines_lan_ip_is_local(monkeypatch):
    trees = {10: [sock(10, ("0.0.0.0", 11434), status="LISTEN"),
                  sock(10, ("192.168.1.5", 11434), ("192.168.1.5", 60010))]}
    tracker = incoming_tracker(monkeypatch, trees, rows=[(4321, "192.168.1.5", 60010)],
                               names={4321: "curl.exe"})
    [c] = clients_of(tracker.poll([SERVE], T0))
    assert (c.scope, c.pid, c.process, c.host) == ("local", 4321, "curl.exe", None)
    assert tracker.namer.calls == []


def test_remote_client_cgnat_is_lan_and_names_printable(monkeypatch):
    trees = {10: [sock(10, ("0.0.0.0", 11434), status="LISTEN"),
                  sock(10, ("192.168.1.5", 11434), ("100.64.0.9", 60003))]}
    monkeypatch.setattr(net, "tree_sockets", lambda pid, **kw: list(trees[pid]))
    connections, process_iter = global_table([])
    tracker = net.Tracker(
        net.Namer(dns_cache=lambda: {}, rdns=lambda ip: ("evil\x1b[2Jhost", [], [ip]),
                  resolve=no_resolve),
        process=name_table({}), connections=connections, process_iter=process_iter)
    [c] = clients_of(tracker.poll([SERVE], T0))
    assert (c.scope, c.host, c.host_source) == ("lan", "evil?[2Jhost", "rdns")


def test_summary_renames_endpoints_and_clients_in_one_wait(monkeypatch):
    trees = {10: [LISTEN, sock(10, ("0.0.0.0", 8080), status="LISTEN"),
                  sock(10, ("192.168.1.5", 8080), ("192.168.1.20", 60001)),
                  sock(10, ("10.0.0.2", 50000), ("104.18.1.1", 443))]}
    tracker = incoming_tracker(monkeypatch, trees)
    tracker.poll([SERVE], T0)
    waits = []
    tracker.namer.name_many = lambda ips, wait: waits.append((sorted(ips), wait)) or {
        ip: (f"late-{ip}", "rdns") for ip in ips}
    tracker.summary(wait=0)
    assert waits == [(["104.18.1.1", "192.168.1.20"], 0)]
    _, [c] = tracker.incoming()
    assert c.host == "late-192.168.1.20" and len(waits) == 1


@pytest.mark.parametrize("status", ["FIN_WAIT2", "CLOSE_WAIT", "SYN_RECV", "LAST_ACK"])
def test_accepted_socket_in_other_states_is_neither_client_nor_outgoing(monkeypatch, status):
    calls = []
    trees = {10: [sock(10, ("0.0.0.0", 11434), status="LISTEN"),
                  sock(10, ("192.168.1.5", 11434), ("192.168.1.20", 60001), status=status)]}
    tracker = incoming_tracker(monkeypatch, trees, calls=calls)
    assert clients_of(tracker.poll([SERVE], T0)) == []
    assert tracker.endpoints == {} and tracker.clients == {} and calls == []


def test_client_must_match_listener_ip_unless_unspecified(monkeypatch):
    # Listener on 127.0.0.1:11434 only: a socket on 10.0.0.2:11434 is no client.
    calls = []
    trees = {10: [LISTEN, sock(10, ("10.0.0.2", 11434), ("8.8.8.8", 443))]}
    tracker = incoming_tracker(monkeypatch, trees, calls=calls)
    assert clients_of(tracker.poll([SERVE], T0)) == [] and calls == []
    assert [e.ip for e in tracker.endpoints.values()] == ["8.8.8.8"]


def test_no_global_table_read_without_client_sockets(monkeypatch):
    calls = []
    trees = {10: [LISTEN, sock(10, ("10.0.0.2", 50000), ("104.18.1.1", 443))]}
    tracker = incoming_tracker(monkeypatch, trees, calls=calls)
    tracker.poll([SERVE], T0)
    assert calls == []
    trees[10].append(sock(10, ("127.0.0.1", 11434), ("127.0.0.1", 52001)))
    trees[10].append(sock(10, ("127.0.0.1", 11434), ("127.0.0.1", 52002)))
    tracker.poll([SERVE], T0)
    assert calls == ["inet"]  # once per poll, not per client


def test_local_client_dedup_across_ephemeral_ports(monkeypatch):
    trees = {10: [LISTEN, sock(10, ("127.0.0.1", 11434), ("127.0.0.1", 52001))]}
    rows = [(4321, "127.0.0.1", 52001), (4321, "127.0.0.1", 52002)]
    tracker = incoming_tracker(monkeypatch, trees, rows=rows, names={4321: "ollama.exe"})
    assert len(clients_of(tracker.poll([SERVE], T0))) == 1
    trees[10][1] = sock(10, ("127.0.0.1", 11434), ("127.0.0.1", 52002))  # reconnect
    later = T0 + timedelta(seconds=2)
    assert tracker.poll([SERVE], later) == []
    [c] = tracker.clients.values()
    assert (c.port, c.first_seen, c.last_seen) == (52001, T0, later)


def fake_incoming_cli(monkeypatch, socks, rows=(), names=None):
    monkeypatch.setattr(net, "find_targets", lambda pids: [net.Target(7, "ollama", "ollama.exe")])
    monkeypatch.setattr(net, "tree_sockets", lambda pid, **kw: list(socks))
    namer, tracker = net.Namer, net.Tracker
    connections, process_iter = global_table(rows)
    monkeypatch.setattr(net, "Namer", lambda: namer(
        dns_cache=lambda: {"192.168.1.20": "laptop.lan"}, rdns=no_rdns, resolve=no_resolve))
    monkeypatch.setattr(net, "Tracker", lambda nm: tracker(
        nm, process=name_table(names or {}), connections=connections,
        process_iter=process_iter))


INCOMING = [sock(7, ("0.0.0.0", 11434), status="LISTEN"),
            sock(7, ("127.0.0.1", 11434), ("127.0.0.1", 52001)),
            sock(7, ("192.168.1.5", 11434), ("192.168.1.20", 60001))]
CURL = {"rows": [(4321, "127.0.0.1", 52001)], "names": {4321: "curl.exe"}}
LISTENER_DOC = {"runtime": "ollama", "target_pid": 7, "pid": 7, "process": "ollama.exe",
                "ip": "0.0.0.0", "port": 11434, "exposed": True, "scope": "all interfaces"}
CLIENT_DOCS = [
    {"runtime": "ollama", "target_pid": 7, "listener_ip": "127.0.0.1", "listener_port": 11434,
     "ip": "127.0.0.1", "port": 52001, "scope": "local", "pid": 4321, "process": "curl.exe",
     "host": None, "host_source": None},
    {"runtime": "ollama", "target_pid": 7, "listener_ip": "192.168.1.5", "listener_port": 11434,
     "ip": "192.168.1.20", "port": 60001, "scope": "lan", "pid": None, "process": None,
     "host": "laptop.lan", "host_source": "dns-cache"},
]


def doc_of(d):
    d = {k: v for k, v in d.items() if k != "event"}
    assert datetime.fromisoformat(d.pop("first_seen")) <= datetime.fromisoformat(
        d.pop("last_seen"))
    return d


def test_cli_once_json_has_listeners_and_clients(monkeypatch):
    fake_incoming_cli(monkeypatch, INCOMING, **CURL)
    doc = json.loads(CliRunner().invoke(cli, ["net", "--once", "--json"]).output)
    assert doc["outgoing"] == []
    assert [doc_of(d) for d in doc["listeners"]] == [LISTENER_DOC]
    assert [doc_of(d) for d in doc["clients"]] == CLIENT_DOCS


def test_cli_stream_json_listener_client_events_and_summary(monkeypatch):
    fake_incoming_cli(monkeypatch, INCOMING, **CURL)
    result = CliRunner().invoke(cli, ["net", "--json", "--duration", "0.01"])
    assert result.exit_code == 0, result.output
    events = [json.loads(line) for line in result.output.splitlines()]
    assert [e["event"] for e in events] == ["target", "listener", "client", "client", "summary"]
    assert doc_of(events[1]) == LISTENER_DOC
    assert [doc_of(e) for e in events[2:4]] == CLIENT_DOCS
    assert [doc_of(d) for d in events[-1]["listeners"]] == [LISTENER_DOC]
    assert [doc_of(d) for d in events[-1]["clients"]] == CLIENT_DOCS
    assert events[-1]["outgoing"] == []


def test_cli_text_lines_tables_and_exposed_count(monkeypatch):
    fake_incoming_cli(monkeypatch, [*INCOMING, sock(7, ("127.0.0.1", 9000), status="LISTEN")],
                      **CURL)
    out = CliRunner().invoke(cli, ["net", "--duration", "0.01"]).output
    assert "LISTEN  ollama  ollama.exe(7) 0.0.0.0:11434  EXPOSED (all interfaces)" in out
    assert "LISTEN  ollama  ollama.exe(7) 127.0.0.1:9000  loopback" in out
    assert "IN  ollama  127.0.0.1:11434 <- curl.exe(4321) [local]" in out
    assert ("IN  ollama  192.168.1.5:11434 <- 192.168.1.20:60001 [lan] laptop.lan [dns-cache]"
            in out)
    summary = out.split("No outgoing connections seen.")[1]
    assert "LISTENERS" in summary and "CLIENTS" in summary
    assert summary.rstrip().endswith("1 listener(s) reachable from other machines")


def test_cli_process_names_made_printable(monkeypatch):
    fake_incoming_cli(monkeypatch, [sock(7, ("127.0.0.1", 9000), status="LISTEN"),
                                    sock(7, ("127.0.0.1", 9000), ("127.0.0.1", 52001))],
                      rows=[(4321, "127.0.0.1", 52001)], names={4321: "bad\x1b[2J.exe"})
    out = CliRunner().invoke(cli, ["net", "--duration", "0.01"]).output
    assert "\x1b[2J" not in out and out.count("bad?[2J.exe(4321) [local]") == 2


def test_cli_once_text_loopback_only_has_no_exposed_line(monkeypatch):
    fake_incoming_cli(monkeypatch, [sock(7, ("127.0.0.1", 11434), status="LISTEN")])
    out = CliRunner().invoke(cli, ["net", "--once"]).output
    assert "LISTENERS" in out and "loopback" in out and "No clients seen." in out
    assert "reachable from other machines" not in out


# -- --local (B3) --------------------------------------------------------------

def agent(pid, agent_type):
    return SimpleNamespace(pid=pid, agent_type=agent_type)


def test_agent_pid_verdict_match_mismatch_vanished_denied():
    by_pid, process = table(
        FakeProc(40, "aider", cmdline=["aider"]),
        FakeProc(41, "opencode.exe", cmdline=[r"C:\x\opencode.exe", "serve"]),
        FakeProc(42, "Cursor.exe", cmdline=["Cursor.exe"]),  # an editor's real pid
        FakeProc(43, "claude.exe", deny=True))
    found = net.LocalAgents(find=list, process=process)
    assert found.is_agent_pid(40, "aider")
    assert found.is_agent_pid(41, "opencode")  # `opencode serve` too (unlike attributable())
    assert not found.is_agent_pid(41, "aider")  # another adapter's process
    assert not found.is_agent_pid(42, "cursor")  # no process adapter matches an editor
    assert not found.is_agent_pid(43, "claude-code")  # denied: unproven
    assert not found.is_agent_pid(999, "codex")  # vanished / synthetic


def test_agent_pid_verdict_cached_per_pid_and_create_time():
    procs = {40: FakeProc(40, "aider", cmdline=["aider"])}

    def process(pid):
        if pid not in procs:
            raise psutil.NoSuchProcess(pid)
        return procs[pid]

    found = net.LocalAgents(find=list, process=process)
    assert found.is_agent_pid(40, "aider") and found.is_agent_pid(40, "aider")
    assert procs[40].cmdline_reads == 1
    procs[40] = FakeProc(40, "notepad.exe", cmdline=["notepad.exe"], created=2.0)  # pid reused
    assert not found.is_agent_pid(40, "aider")
    assert procs[40].cmdline_reads == 1


def test_scan_watches_real_pids_counts_synthetic_and_includes_aider():
    _, process = table(FakeProc(40, "aider", cmdline=["aider"]),
                       FakeProc(50, "claude.exe", cmdline=[r"C:\bin\claude.exe"]))
    agents = [agent(40, "aider"), agent(50, "claude-code"), agent(3141592653, "cursor"),
              agent(2718281828, "cline"), agent(1618033988, "codex")]
    found = net.LocalAgents(find=lambda: agents, process=process)
    found.scan()
    assert found.targets == [(40, "agent:aider"), (50, "agent:claude-code")]
    assert found.unwatched == ["cline", "codex", "cursor"]


def test_discovery_in_background_first_scan_waits():
    clock, gate, calls = [0.0], threading.Event(), []
    results = iter([[agent(40, "aider")], [agent(40, "aider"), agent(41, "opencode")]])

    def find():
        calls.append(clock[0])
        if len(calls) > 1:
            gate.wait(5)  # a slow discovery (1.85-5.2 s live)
        return next(results)

    _, process = table(FakeProc(40, "aider", cmdline=["aider"]),
                       FakeProc(41, "opencode", cmdline=["opencode"]))
    found = net.LocalAgents(find=find, process=process, clock=lambda: clock[0])
    found.scan()
    assert found.targets == [(40, "agent:aider")]  # the first scan (--once) waited
    found.scan()
    assert len(calls) == 1  # not due yet
    clock[0] = net.AGENT_REFRESH_S
    start = time.monotonic()
    found.scan()  # starts the slow discovery, doesn't wait for it
    clock[0] += 3 * net.AGENT_REFRESH_S
    found.scan()  # one in flight: no second one
    assert time.monotonic() - start < 1 and calls == [0.0, net.AGENT_REFRESH_S]
    assert found.targets == [(40, "agent:aider")]  # polls use the last completed result
    gate.set()
    found._thread.join(5)
    assert found.targets == [(40, "agent:aider"), (41, "agent:opencode")]  # a later poll


def test_failed_discovery_keeps_last_result():
    clock, answers = [0.0], iter([[agent(40, "aider")], OSError("boom")])

    def find():
        answer = next(answers)
        if isinstance(answer, Exception):
            raise answer
        return answer

    found = net.LocalAgents(find=find, process=table(FakeProc(40, "aider", cmdline=["aider"]))[1],
                            clock=lambda: clock[0])
    found.scan()
    clock[0] = net.AGENT_REFRESH_S
    found.scan()
    found._thread.join(5)
    assert found.targets == [(40, "agent:aider")]


def test_known_host_lookups_run_concurrently():
    both = threading.Barrier(2, timeout=2)  # passes only if both lookups run at once

    def resolve(host, port):
        both.wait()
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"9.9.9.{len(host)}", port))]

    namer = net.Namer(dns_cache=lambda: {}, rdns=no_rdns, resolve=resolve,
                      known_hosts=("a.example", "bb.example"))
    assert namer.name("9.9.9.9") == ("a.example", "known")


def test_only_a_runtime_absorbs_a_runtime():
    # QA #136: Ollama started from a Claude Code shell was reported as agent traffic.
    llama = FakeProc(61, "llama-server.exe")
    serve = FakeProc(60, "ollama.exe", kids=[llama])
    sub = FakeProc(51, "claude.exe")
    agent_ = FakeProc(50, "claude.exe", kids=[sub, serve])
    lms = FakeProc(91, "lms.exe")
    shell = FakeProc(90, "pwsh.exe", kids=[lms])
    by_pid, process = table(agent_, sub, serve, llama, shell, lms)
    found = net.find_targets([50, 90], [(50, "agent:claude-code"), (51, "agent:claude-code")],
                             process_iter=lambda: list(by_pid.values()), process=process)
    assert found == [net.Target(50, "agent:claude-code", "claude.exe"),  # agent beats --pid
                     net.Target(51, "agent:claude-code", "claude.exe"),
                     net.Target(60, "ollama", "ollama.exe"),  # llama-server deduped into it
                     net.Target(90, "pid", "pwsh.exe"),
                     net.Target(91, "lm-studio", "lms.exe")]


def tcp(lip, lport, rip=None, rport=None, status="ESTABLISHED"):
    return SimpleNamespace(laddr=SimpleNamespace(ip=lip, port=lport),
                           raddr=SimpleNamespace(ip=rip, port=rport) if rip else (),
                           status=status, type=socket.SOCK_STREAM)


def test_runtime_under_agent_kept_apart_no_duplicates_agent_child_is_client():
    curl = FakeProc(70, "curl.exe", [tcp("127.0.0.1", 52300, "127.0.0.1", 11434)])
    serve = FakeProc(60, "ollama.exe", [
        tcp("127.0.0.1", 11434, status="LISTEN"),
        tcp("127.0.0.1", 11434, "127.0.0.1", 52300),
        tcp("10.0.0.2", 50001, "34.36.133.15", 443)])
    agent_ = FakeProc(50, "claude.exe", [tcp("10.0.0.2", 50002, "160.79.104.10", 443)],
                      kids=[serve, curl])
    by_pid, process = table(agent_, serve, curl)
    connections, process_iter = global_table([(70, "127.0.0.1", 52300),
                                              (60, "127.0.0.1", 11434)])
    tracker = net.Tracker(FakeNamer(), process=process, connections=connections,
                          process_iter=process_iter)
    targets = net.find_targets((), [(50, "agent:claude-code")],
                               process_iter=lambda: list(by_pid.values()), process=process)
    records = tracker.poll(targets, T0)
    assert sorted((e.runtime, e.pid, e.ip) for e in tracker.endpoints.values()) == [
        ("agent:claude-code", 50, "160.79.104.10"), ("ollama", 60, "34.36.133.15")]
    assert [(r.runtime, r.pid, r.port) for r in tracker.listeners.values()] == [
        ("ollama", 60, 11434)]
    # curl runs in the agent's tree, not the runtime's: a client, not internal
    assert [(c.runtime, c.pid, c.process) for c in clients_of(records)] == [
        ("ollama", 70, "curl.exe")]


def provider_tracker():
    resolve_calls = []
    namer = net.Namer(dns_cache=lambda: {}, rdns=no_rdns, resolve=resolver({
        "api.anthropic.com": ["160.79.104.10"], "downloads.claude.ai": ["34.36.57.103"],
        "http-intake.logs.us5.datadoghq.com": ["34.149.66.137"]}, resolve_calls),
        known_hosts=("api.anthropic.com", "downloads.claude.ai",
                     "http-intake.logs.us5.datadoghq.com"))
    root = FakeProc(50, "claude.exe", [conn(ip) for ip in (
        "160.79.104.10", "34.36.57.103", "34.149.66.137", "9.9.9.9")])
    return net.Tracker(namer, process=table(root)[1]), resolve_calls


def test_ai_provider_flag_set_from_ip_map_none_otherwise_nothing_hidden():
    tracker, resolve_calls = provider_tracker()
    target = [net.Target(50, "agent:claude-code", "claude.exe")]
    new = tracker.poll(target, T0)
    assert {(e.ip, e.host, e.ai_provider) for e in new} == {
        ("160.79.104.10", "api.anthropic.com", "anthropic"),  # flagged, still reported
        ("34.36.57.103", "downloads.claude.ai", None),  # KNOWN_AGENT_HOSTS: reported, unflagged
        ("34.149.66.137", "http-intake.logs.us5.datadoghq.com", None),
        ("9.9.9.9", "9.9.9.9", None)}
    tracker.poll(target, T0 + timedelta(seconds=1))
    assert len(resolve_calls) == 3  # one resolution shared by naming and flagging


def test_ai_provider_from_dns_cache_name_and_any_target():
    namer = net.Namer(dns_cache=lambda: {"1.2.3.4": "API.OpenAI.com"}, rdns=no_rdns,
                      resolve=no_resolve)
    root = FakeProc(2, "ollama.exe", [conn("1.2.3.4")])
    [ep] = net.Tracker(namer, process=table(root)[1]).poll(
        [net.Target(2, "ollama", "ollama.exe")], T0)
    assert (ep.runtime, ep.ai_provider) == ("ollama", "openai")


def test_known_agent_hosts_are_never_provider_domains():
    # The flag is AI_PROVIDERS only; KNOWN_AGENT_HOSTS just names.
    assert not set(KNOWN_AGENT_HOSTS) & set(net._PROVIDER_OF)


def test_agent_loopback_to_runtime_listed_as_client(monkeypatch):
    # Aider (30, a --local target) -> Ollama serve (10, a runtime target) on 11434.
    trees = {10: [LISTEN, sock(10, ("127.0.0.1", 11434), ("127.0.0.1", 52300))],
             30: [sock(30, ("127.0.0.1", 52300), ("127.0.0.1", 11434))]}
    tracker = incoming_tracker(monkeypatch, trees, rows=[(10, "127.0.0.1", 11434),
                                                         (30, "127.0.0.1", 52300)],
                               names={30: "aider.exe"})
    records = tracker.poll([SERVE, net.Target(30, "agent:aider", "aider.exe")], T0)
    assert [(c.runtime, c.listener_port, c.scope, c.pid, c.process)
            for c in clients_of(records)] == [("ollama", 11434, "local", 30, "aider.exe")]
    assert tracker.endpoints == {}  # the agent's side is loopback, not outgoing


def fake_local_cli(monkeypatch):
    claude = FakeProc(50, "claude.exe", cmdline=[r"C:\bin\claude.exe"])
    _, process = table(claude)
    agents = [agent(50, "claude-code"), agent(3141592653, "cursor")]
    real_agents, real_find = net.LocalAgents, net.find_targets
    monkeypatch.setattr(net, "LocalAgents",
                        lambda: real_agents(find=lambda: agents, process=process))
    monkeypatch.setattr(net, "find_targets", lambda pids, agents=(): real_find(
        pids, agents, process_iter=lambda: [], process=process))
    monkeypatch.setattr(net, "tree_sockets", lambda pid, **kw: [
        net.SocketInfo(pid, ("10.0.0.2", 50000), raddr, "ESTABLISHED", "tcp")
        for raddr in (("160.79.104.10", 443), ("34.36.57.103", 443))])
    namer = net.Namer
    monkeypatch.setattr(net, "Namer", lambda: namer(dns_cache=lambda: {
        "160.79.104.10": "api.anthropic.com", "34.36.57.103": "downloads.claude.ai"},
        rdns=no_rdns, resolve=no_resolve))


def test_cli_local_once_json_shape(monkeypatch):
    fake_local_cli(monkeypatch)
    result = CliRunner().invoke(cli, ["net", "--local", "--once", "--json"])
    assert result.exit_code == 0, result.output
    doc = json.loads(result.output)
    assert doc["targets"] == [{"pid": 50, "runtime": "agent:claude-code", "process": "claude.exe"}]
    assert doc["unwatched_agents"] == ["cursor"]
    assert [(e["runtime"], e["host"], e["ai_provider"]) for e in doc["outgoing"]] == [
        ("agent:claude-code", "api.anthropic.com", "anthropic"),
        ("agent:claude-code", "downloads.claude.ai", None)]


def test_cli_local_once_text_flags_and_counts(monkeypatch):
    fake_local_cli(monkeypatch)
    out = CliRunner().invoke(cli, ["net", "--local", "--once"]).output
    assert "Watched: agent:claude-code claude.exe(50)" in out
    assert "api.anthropic.com [dns-cache] AI-PROVIDER anthropic" in out
    assert "downloads.claude.ai [dns-cache] " in out and out.count("AI-PROVIDER") == 1
    assert "1 connection(s) to cloud AI providers (from agent:claude-code claude.exe(50))" in out
    assert ("1 agent(s) without a verifiable own process not watched (editor-hosted, "
            "Codex app-server threads, or unreadable; use --pid <pid>)") in out


def test_cli_local_stream_reports_unwatched_once(monkeypatch):
    fake_local_cli(monkeypatch)
    clock = [0.0]
    monkeypatch.setattr("time.monotonic", lambda: clock[0])
    monkeypatch.setattr("time.sleep", lambda s: clock.__setitem__(0, clock[0] + s))
    result = CliRunner().invoke(cli, ["net", "--local", "--json", "--duration", "3"])
    assert result.exit_code == 0, result.output
    events = [json.loads(line) for line in result.output.splitlines()]
    assert [e["event"] for e in events].count("unwatched") == 1
    assert events[0]["unwatched_agents"] == ["cursor"]
    assert [e["ai_provider"] for e in events if e["event"] == "outgoing"] == ["anthropic", None]
    assert events[-1]["unwatched_agents"] == ["cursor"]
    assert events[-1]["targets"][0]["runtime"] == "agent:claude-code"


def test_cli_local_no_target_message(monkeypatch):
    fake_cli(monkeypatch, [])
    monkeypatch.setattr(net, "LocalAgents",
                        lambda: SimpleNamespace(scan=lambda: None, targets=[], unwatched=[]))
    monkeypatch.setattr(net, "find_targets", lambda pids, agents=(): [])
    doc = json.loads(CliRunner().invoke(cli, ["net", "--local", "--once", "--json"]).output)
    assert doc["message"] == net.NO_TARGET_LOCAL and doc["unwatched_agents"] == []
