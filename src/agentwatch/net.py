"""Outgoing connections of local AI runtimes (`agentwatch net`, Sprint 34 B1).

Answers "does a LOCAL AI talk to external servers, and if so, to whom?".
Targets are runtime processes matched by name (ai_detect.LOCAL_RUNTIMES)
plus any --pid; each target's process tree is sampled with tree_sockets
(moved here from closed PR #132). Nothing is allow-listed: every non-local
remote endpoint is reported, private (LAN) ones tagged; KNOWN_AGENT_HOSTS
and AI_PROVIDERS never hide one (board 2026-10-15). Unprivileged.

# ponytail: polling misses connections shorter than one interval and never
# sees ICMP or unconnected UDP; DoH/VPN/proxy hide hostnames (the proxy or
# resolver IP shows instead); gethostbyaddr blocks the poll on a slow reverse
# lookup. Upgrade: ETW/eBPF capture, lookups off the poll thread.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

import psutil

from agentwatch.ai_detect import _PROC_ERRORS, LOCAL_RUNTIMES, runtime_of
from agentwatch.detectors.security.network import _flaggable

NO_RUNTIME = (
    f"No local AI runtime running ({', '.join(LOCAL_RUNTIMES)}). "
    "Use --pid N to watch any other process."
)
DNS_REFRESH_S = 5.0
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
        except _PROC_ERRORS:
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
    """IP -> (name, source): DNS client cache (Windows), reverse DNS, bare IP."""

    def __init__(self, dns_cache=None, rdns=socket.gethostbyaddr, clock=time.monotonic):
        if dns_cache is None and sys.platform == "win32":
            dns_cache = dns_cache_snapshot
        self._dns_cache, self._rdns, self._clock = dns_cache, rdns, clock
        self._names: dict[str, str] = {}  # dns-cache hits, merged across refreshes
        self._refreshed: float | None = None
        self._rdns_cache: dict[str, str | None] = {}

    def name(self, ip: str) -> tuple[str, str]:
        # A cache miss is not final: a later refresh (>= DNS_REFRESH_S on) may have it.
        if self._dns_cache and ip not in self._names and (
            self._refreshed is None or self._clock() - self._refreshed >= DNS_REFRESH_S
        ):
            self._names.update(self._dns_cache())
            self._refreshed = self._clock()
        if ip in self._names:
            return _printable(self._names[ip]), "dns-cache"
        if ip not in self._rdns_cache:
            try:
                self._rdns_cache[ip] = self._rdns(ip)[0] or None
            except (OSError, UnicodeError):
                self._rdns_cache[ip] = None
        host = self._rdns_cache[ip]
        return (_printable(host), "rdns") if host else (ip, "ip")


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
        """Sample every target's tree once; returns the endpoints not seen before."""
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
                owner = self._name(s.pid)  # before naming: a DNS lookup can outlive the owner
                host, source = self.namer.name(ip)
                ep = Endpoint(t.runtime, t.pid, s.pid, owner, ip, port, s.kind,
                              host, source, ipaddress.ip_address(ip).is_private, now, now)
                self.endpoints[key] = ep
                new.append(ep)
        return new

    def summary(self) -> list[Endpoint]:
        """All endpoints, oldest first; names retried (the DNS cache may have them now)."""
        for ep in self.endpoints.values():
            if ep.host_source != "dns-cache":
                ep.host, ep.host_source = self.namer.name(ep.ip)
        return sorted(self.endpoints.values(), key=lambda e: (e.first_seen, e.runtime, e.ip))
