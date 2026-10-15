"""Outgoing connections of local AI runtimes (`agentwatch net`, Sprint 34 B1).

Answers "does a LOCAL AI talk to external servers, and if so, to whom?".
Targets are runtime processes matched by name (ai_detect.LOCAL_RUNTIMES)
plus any --pid; each target's process tree is sampled with tree_sockets
(moved here from closed PR #132). Nothing is allow-listed: every non-local
remote endpoint is reported, private (LAN) ones tagged; KNOWN_AGENT_HOSTS
and AI_PROVIDERS never hide one (board 2026-10-15). Unprivileged.

# ponytail: polling misses connections shorter than one interval and never
# sees ICMP or unconnected UDP; DoH/VPN/proxy hide hostnames (the proxy or
# resolver IP shows instead); reverse lookups slower than RDNS_WAIT_S show as
# the bare IP until a later poll or the summary. Upgrade: ETW/eBPF capture.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

import psutil

from agentwatch.ai_detect import _PROC_ERRORS, AI_PROVIDERS, LOCAL_RUNTIMES, runtime_of
from agentwatch.detectors.security.network import KNOWN_AGENT_HOSTS, _flaggable

NO_RUNTIME = (
    f"No local AI runtime running ({', '.join(LOCAL_RUNTIMES)}). "
    "Use --pid N to watch any other process."
)
DNS_REFRESH_S = 5.0
KNOWN_REFRESH_S = 300.0  # CDN IPs rotate
RDNS_WAIT_S = 2.0  # per poll, for all its new endpoints' reverse lookups
RDNS_WORKERS = 4
# Forward-resolved for naming only ("known" = a guess from a shared IP); never
# used to hide an endpoint.
KNOWN_HOSTS: tuple[str, ...] = tuple(sorted(
    {d for ds in AI_PROVIDERS.values() for d in ds}
    | set(KNOWN_AGENT_HOSTS)
    | {h for rt in LOCAL_RUNTIMES.values() for h in rt.hosts}
))
# Fixed argument list: nothing from the network or the process table goes in.
_PS_DNS = [
    "powershell", "-NoProfile", "-NonInteractive", "-Command",
    "Get-DnsClientCache | Select-Object Entry,Data,Type | ConvertTo-Json -Compress",
]


@dataclass(frozen=True)
class SocketInfo:
    """One inet socket of a process tree. Addresses are (ip, port) or ()."""

    pid: int
    laddr: tuple
    raddr: tuple
    status: str
    kind: str  # "tcp" | "udp"


def _addr(a) -> tuple:
    return (a.ip.removeprefix("::ffff:"), a.port) if a else ()


def tree_sockets(root_pid: int, exclude: set[int] = frozenset(),
                 process=psutil.Process) -> list[SocketInfo]:
    """Every inet socket (LISTEN included) of *root_pid* and its descendants.

    Descendants in *exclude*, and their subtrees, are skipped. Vanished or
    denied processes are skipped.
    """
    try:
        root = process(root_pid)
        kids = root.children(recursive=True)
    except _PROC_ERRORS:
        return []
    skip: set[int] = set()
    for kid in kids:
        if kid.pid in exclude:
            skip.add(kid.pid)
            try:
                skip.update(g.pid for g in kid.children(recursive=True))
            except _PROC_ERRORS:
                pass
    found: list[SocketInfo] = []
    for p in (root, *kids):
        if p.pid in skip:
            continue
        try:
            get = getattr(p, "net_connections", None) or p.connections
            conns = get(kind="inet")
        except _PROC_ERRORS:
            continue
        found.extend(
            SocketInfo(p.pid, _addr(c.laddr), _addr(c.raddr), c.status,
                       "udp" if c.type == socket.SOCK_DGRAM else "tcp")
            for c in conns
        )
    return found


@dataclass(frozen=True)
class Target:
    pid: int
    runtime: str  # LOCAL_RUNTIMES key, or "pid" for --pid
    process: str


def find_targets(extra_pids=(), *, process_iter=psutil.process_iter,
                 process=psutil.Process) -> list[Target]:
    """Local AI runtime processes running now, plus *extra_pids*.

    A target whose ancestor is also a target is dropped: the ancestor's
    tree_sockets walk already covers it (e.g. Ollama's llama-server child).
    """
    found: dict[int, tuple[Target, object]] = {}
    for p in process_iter():
        try:
            name = p.name()
        except _PROC_ERRORS:
            continue
        runtime = runtime_of(name, p)
        if runtime:
            found[p.pid] = (Target(p.pid, runtime, name), p)
    for pid in extra_pids:
        if pid not in found:
            try:
                p = process(pid)
                found[pid] = (Target(pid, "pid", p.name()), p)
            except _PROC_ERRORS:
                continue
    targets = []
    for t, p in found.values():
        try:
            ancestors = {a.pid for a in p.parents()}
        except psutil.NoSuchProcess:  # ZombieProcess too: exiting, e.g. a model unloading
            continue
        except _PROC_ERRORS:  # denied: can't prove a target ancestor, keep it
            ancestors = set()
        if not ancestors & found.keys():
            targets.append(t)
    return sorted(targets, key=lambda t: t.pid)


def dns_cache_snapshot(run=subprocess.run) -> dict[str, str]:
    """Windows DNS client cache: A/AAAA record IP -> queried name; {} on failure."""
    try:
        out = run(_PS_DNS, capture_output=True, text=True, errors="replace",
                  timeout=10, check=False).stdout or ""
        rows = json.loads(out) if out.strip() else []
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}
    if isinstance(rows, dict):  # ConvertTo-Json unwraps a single record
        rows = [rows]
    return {
        str(r["Data"]).lower(): str(r["Entry"])
        for r in rows
        if isinstance(r, dict) and r.get("Type") in (1, 28) and r.get("Data") and r.get("Entry")
    }


def _printable(s: str) -> str:
    # PTR / cache names come from the network: no terminal escapes.
    return "".join(c if c.isprintable() else "?" for c in s)


class Namer:
    """IP -> (name, source): DNS client cache (Windows), KNOWN_HOSTS forward
    lookups ("known"), reverse DNS, bare IP."""

    def __init__(self, dns_cache=None, rdns=socket.gethostbyaddr, clock=time.monotonic,
                 resolve=socket.getaddrinfo, known_hosts=KNOWN_HOSTS):
        if dns_cache is None and sys.platform == "win32":
            dns_cache = dns_cache_snapshot
        self._dns_cache, self._rdns, self._clock = dns_cache, rdns, clock
        self._resolve, self._known_hosts = resolve, known_hosts
        self._names: dict[str, str] = {}  # dns-cache hits, merged across refreshes
        self._refreshed: float | None = None
        self._known: dict[str, set[str]] = {}  # IP -> known hosts, unioned across refreshes
        self._known_at: float | None = None
        self._rdns_cache: dict[str, str | None] = {}  # written by lookup threads
        self._pending: dict[str, threading.Event] = {}
        self._slots = threading.BoundedSemaphore(RDNS_WORKERS)

    def _start_rdns(self, ip: str) -> threading.Event:
        # Daemon threads, not a ThreadPoolExecutor: its atexit join would make
        # a straggling lookup block exit.
        done = threading.Event()

        def lookup():
            with self._slots:
                try:
                    host = self._rdns(ip)[0] or None
                except (OSError, UnicodeError):
                    host = None
            self._rdns_cache[ip] = host
            done.set()

        self._pending[ip] = done
        threading.Thread(target=lookup, name="agentwatch-rdns", daemon=True).start()
        return done

    def _known_name(self, ip: str) -> str | None:
        # ponytail: resolves every known host serially on refresh (blocking,
        # after sampling); thread it if the list grows.
        if self._known_at is None or self._clock() - self._known_at >= KNOWN_REFRESH_S:
            self._known_at = self._clock()
            for host in self._known_hosts:
                try:
                    infos = self._resolve(host, 443)
                except (OSError, UnicodeError):
                    continue  # retried at the next refresh
                for info in infos:
                    addr = info[4][0].removeprefix("::ffff:").lower()
                    self._known.setdefault(addr, set()).add(host)
        hosts = self._known.get(ip)
        return "|".join(sorted(hosts)) if hosts else None  # shared CDN IP: all of them

    def _quick(self, ip: str) -> tuple[str, str] | None:
        # A cache miss is not final: a later refresh (>= DNS_REFRESH_S on) may have it.
        if self._dns_cache and ip not in self._names and (
            self._refreshed is None or self._clock() - self._refreshed >= DNS_REFRESH_S
        ):
            self._names.update(self._dns_cache())
            self._refreshed = self._clock()
        if ip in self._names:
            return _printable(self._names[ip]), "dns-cache"
        known = self._known_name(ip)
        return (known, "known") if known else None

    def _from_rdns(self, ip: str) -> tuple[str, str]:
        host = self._rdns_cache.get(ip)  # absent: lookup still running
        return (_printable(host), "rdns") if host else (ip, "ip")

    def name(self, ip: str) -> tuple[str, str]:
        return self.name_many([ip])[ip]

    def name_many(self, ips, wait: float = RDNS_WAIT_S) -> dict[str, tuple[str, str]]:
        """Name *ips*; their reverse lookups run concurrently, waiting at most
        *wait* s in all. A lookup not done in time leaves the bare IP and
        finishes into the cache for a later call."""
        out: dict[str, tuple[str, str]] = {}
        slow = []
        for ip in dict.fromkeys(ips):
            hit = self._quick(ip)
            if hit:
                out[ip] = hit
            elif ip in self._rdns_cache:
                out[ip] = self._from_rdns(ip)
            else:
                slow.append(ip)
        events = [self._pending.get(ip) or self._start_rdns(ip) for ip in slow]
        deadline = time.monotonic() + wait
        for done in events:
            done.wait(max(0.0, deadline - time.monotonic()))
        out.update((ip, self._from_rdns(ip)) for ip in slow)
        return out


@dataclass
class Endpoint:
    runtime: str
    target_pid: int
    pid: int
    process: str
    ip: str
    port: int
    kind: str
    host: str
    host_source: str
    lan: bool
    first_seen: datetime
    last_seen: datetime

    def to_dict(self) -> dict:
        d = asdict(self)
        d["first_seen"], d["last_seen"] = self.first_seen.isoformat(), self.last_seen.isoformat()
        return d


class Tracker:
    """Outgoing endpoints across polls, keyed (target pid, pid, ip, port, kind)."""

    def __init__(self, namer: Namer, process=psutil.Process):
        self.namer, self._process = namer, process
        self.endpoints: dict[tuple, Endpoint] = {}
        self._names: dict[int, str] = {}

    def _name(self, pid: int) -> str:
        if pid not in self._names:
            try:
                self._names[pid] = self._process(pid).name()
            except _PROC_ERRORS:
                self._names[pid] = "?"
        return self._names[pid]

    def poll(self, targets: list[Target], now: datetime | None = None) -> list[Endpoint]:
        """Sample every target's tree once; returns the endpoints not seen before.

        All trees are read first (owner names at once, before short-lived
        owners exit), then the new endpoints are named: a slow reverse lookup
        never delays a socket read.
        """
        now = now or datetime.now(timezone.utc)
        new = []
        for t in targets:
            self._names.setdefault(t.pid, t.process)
            for s in tree_sockets(t.pid, process=self._process):
                if not s.raddr or not _flaggable(s.raddr[0]):  # loopback etc.
                    continue
                ip, port = s.raddr
                key = (t.pid, s.pid, ip, port, s.kind)
                if key in self.endpoints:
                    self.endpoints[key].last_seen = now
                    continue
                ep = Endpoint(t.runtime, t.pid, s.pid, self._name(s.pid), ip, port, s.kind,
                              ip, "ip", ipaddress.ip_address(ip).is_private, now, now)
                self.endpoints[key] = ep
                new.append(ep)
        self._rename(new)
        return new

    def _rename(self, endpoints) -> None:
        names = self.namer.name_many([ep.ip for ep in endpoints])
        for ep in endpoints:
            ep.host, ep.host_source = names[ep.ip]

    def summary(self) -> list[Endpoint]:
        """All endpoints, oldest first; names retried (the DNS cache or a
        finished reverse lookup may have them now)."""
        self._rename([ep for ep in self.endpoints.values() if ep.host_source != "dns-cache"])
        return sorted(self.endpoints.values(), key=lambda e: (e.first_seen, e.runtime, e.ip))
