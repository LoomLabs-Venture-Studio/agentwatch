"""Outgoing and incoming connections of local AI runtimes (`agentwatch net`,
Sprint 34 B1 outgoing, B2 incoming, B3 `--local` agents).

Answers "does a LOCAL AI talk to external servers, and if so, to whom?".
Targets are runtime processes matched by name (ai_detect.LOCAL_RUNTIMES)
plus any --pid; each target's process tree is sampled with tree_sockets
(moved here from closed PR #132). Nothing is allow-listed: every non-local
remote endpoint is reported, private (LAN) ones tagged; KNOWN_AGENT_HOSTS
and AI_PROVIDERS never hide one (board 2026-10-15). Incoming: every TCP
listener in the tree (`exposed` unless loopback-only) and its clients, local
ones by owning process. `--local` adds running agents that have their own
OS process (LocalAgents); every outgoing endpoint whose IP belongs to an
AI_PROVIDERS domain carries `ai_provider` (flagged, still reported).
Unprivileged.

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

from agentwatch.ai_detect import (
    _PROC_ERRORS,
    AI_PROVIDERS,
    LOCAL_RUNTIMES,
    _connections_by_pid,
    runtime_of,
)
from agentwatch.detectors.security.network import KNOWN_AGENT_HOSTS, _flaggable
from agentwatch.discovery import DiscoveryCache, find_running_agents, match_process_adapter

NO_RUNTIME = (
    f"No local AI runtime running ({', '.join(LOCAL_RUNTIMES)}). "
    "Use --pid N to watch any other process."
)
NO_TARGET_LOCAL = (
    f"No local AI runtime ({', '.join(LOCAL_RUNTIMES)}) or agent with its own process "
    "running. Use --pid N to watch any other process."
)
DNS_REFRESH_S = 5.0
AGENT_SLOW_S = 0.5  # a find_running_agents() slower than this...
AGENT_REFRESH_S = 5.0  # ...runs at most this often (1.2 s measured on Windows)
KNOWN_REFRESH_S = 300.0  # CDN IPs rotate
RDNS_WAIT_S = 2.0  # per poll, for all its new endpoints' reverse lookups
RDNS_WORKERS = 4
_SHARED = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598 CGNAT; Tailscale lives here
# Forward-resolved for naming only ("known" = a guess from a shared IP); never
# used to hide an endpoint.
KNOWN_HOSTS: tuple[str, ...] = tuple(sorted(
    {d for ds in AI_PROVIDERS.values() for d in ds}
    | set(KNOWN_AGENT_HOSTS)
    | {h for rt in LOCAL_RUNTIMES.values() for h in rt.hosts}
))
_PROVIDER_OF = {d: p for p, ds in AI_PROVIDERS.items() for d in ds}
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
    # ponytail: on Windows psutil builds each process's net_connections() from
    # the whole system table, so one poll costs a full read per tree process
    # (~0.65 s measured with 315 processes). Upgrade: one psutil.net_connections()
    # per poll, filtered by the trees' pids.
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
    runtime: str  # LOCAL_RUNTIMES key, "agent:<agent_type>" (--local), or "pid" for --pid
    process: str


def find_targets(extra_pids=(), agents=(), *, process_iter=psutil.process_iter,
                 process=psutil.Process) -> list[Target]:
    """Local AI runtime processes running now, plus *agents* ((pid, runtime
    label) pairs, LocalAgents.targets) and *extra_pids*.

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
    for pid, runtime in (*agents, *((pid, "pid") for pid in extra_pids)):
        if pid not in found:
            try:
                p = process(pid)
                found[pid] = (Target(pid, runtime, p.name()), p)
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


def _is_lan(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return a.is_private or (a.version == 4 and a in _SHARED)


def missing_pids(pids) -> list[int]:
    """The --pid values with no live process."""
    return sorted({p for p in pids if not psutil.pid_exists(p)})


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

    def _refresh_known(self) -> None:
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

    def _known_name(self, ip: str) -> str | None:
        self._refresh_known()
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

    def providers(self, ip: str) -> str | None:
        """AI_PROVIDERS name(s) of *ip* ("|"-joined), from the known forward
        lookups (the AI_PROVIDERS domains are known hosts) or its DNS-cache
        name; None otherwise. A flag only: nothing is hidden."""
        self._refresh_known()
        hosts = self._known.get(ip, set()) | {self._names.get(ip, "").lower()}
        return "|".join(sorted({_PROVIDER_OF[h] for h in hosts if h in _PROVIDER_OF})) or None

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
    ai_provider: str | None = None  # Namer.providers(): flagged, never hidden

    def to_dict(self) -> dict:
        d = asdict(self)
        d["first_seen"], d["last_seen"] = self.first_seen.isoformat(), self.last_seen.isoformat()
        return d


def listener_scope(ip: str) -> str:
    """"all interfaces" (0.0.0.0 / ::), "loopback", or "lan": any other bind
    address (LAN, public or link-local; unparseable too, so it is flagged)."""
    try:
        a = ipaddress.ip_address(ip.removeprefix("::ffff:"))
    except ValueError:
        return "lan"
    if a.is_unspecified:
        return "all interfaces"
    return "loopback" if a.is_loopback else "lan"


@dataclass
class Listener:
    """A LISTEN TCP socket in a target's tree; exposed unless loopback-only."""

    runtime: str
    target_pid: int
    pid: int
    process: str
    ip: str
    port: int
    exposed: bool
    scope: str  # listener_scope()
    first_seen: datetime
    last_seen: datetime
    to_dict = Endpoint.to_dict


@dataclass
class Client:
    """A connection accepted by a listener in a target's tree.

    listener_ip/port: the local address the client reached; ip/port: the
    client (port as first seen: a local client is keyed by its process).
    """

    runtime: str
    target_pid: int
    listener_ip: str
    listener_port: int
    ip: str
    port: int
    scope: str  # "local" | "lan" | "public"
    pid: int | None  # local owner; None when remote or not visible
    process: str | None  # "?" for a local owner that isn't visible
    host: str | None  # remote only, named like an outgoing endpoint
    host_source: str | None
    first_seen: datetime
    last_seen: datetime
    to_dict = Endpoint.to_dict


def _accepted(laddr: tuple, listening: set[tuple]) -> bool:
    return any(laddr[1] == port and (laddr[0] == ip or listener_scope(ip) == "all interfaces")
               for ip, port in listening)


class Tracker:
    """Outgoing endpoints across polls, keyed (target pid, pid, ip, port, kind);
    listeners keyed (target pid, pid, ip, port); clients keyed (target pid,
    listener port, client ip, owner pid, client port if no owner pid)."""

    def __init__(self, namer: Namer, process=psutil.Process,
                 connections=psutil.net_connections, process_iter=psutil.process_iter):
        self.namer, self._process = namer, process
        self._connections, self._process_iter = connections, process_iter
        self.endpoints: dict[tuple, Endpoint] = {}
        self.listeners: dict[tuple, Listener] = {}
        self.clients: dict[tuple, Client] = {}
        self._names: dict[int, str] = {}

    def _name(self, pid: int) -> str:
        if pid not in self._names:
            try:
                self._names[pid] = self._process(pid).name()
            except _PROC_ERRORS:
                self._names[pid] = "?"
        return self._names[pid]

    def poll(self, targets: list[Target], now: datetime | None = None) -> list:
        """Sample every target's tree once; returns the endpoints, listeners
        and clients not seen before, in that order.

        All trees are read first (owner names at once, before short-lived
        owners exit), then the global socket table for client owners (only
        if there are clients), then the new endpoints are named: a slow
        reverse lookup never delays a socket read.
        """
        now = now or datetime.now(timezone.utc)
        new, listeners, accepted = [], [], []
        for t in targets:
            self._names.setdefault(t.pid, t.process)
            socks = tree_sockets(t.pid, process=self._process)
            listening = {s.laddr for s in socks
                         if s.status == "LISTEN" and s.kind == "tcp" and s.laddr}
            tree = {t.pid} | {s.pid for s in socks}
            for s in socks:
                if s.status == "LISTEN":
                    if s.kind == "tcp" and s.laddr:
                        self._listener(t, s, now, listeners)
                    continue
                if (s.kind == "tcp" and s.status == "ESTABLISHED" and s.raddr and s.laddr
                        and _accepted(s.laddr, listening)):
                    accepted.append((t, tree, s))  # incoming, not outgoing
                    continue
                if not s.raddr or not _flaggable(s.raddr[0]):  # loopback etc.
                    continue
                ip, port = s.raddr
                key = (t.pid, s.pid, ip, port, s.kind)
                if key in self.endpoints:
                    self.endpoints[key].last_seen = now
                    continue
                ep = Endpoint(t.runtime, t.pid, s.pid, self._name(s.pid), ip, port, s.kind,
                              ip, "ip", _is_lan(ip), now, now)
                self.endpoints[key] = ep
                new.append(ep)
        clients = self._clients(accepted, now) if accepted else []
        self._rename(new + [c for c in clients if c.host_source])
        return new + listeners + clients

    def _listener(self, t: Target, s: SocketInfo, now: datetime, out: list) -> None:
        key = (t.pid, s.pid, *s.laddr)
        if key in self.listeners:
            self.listeners[key].last_seen = now
            return
        scope = listener_scope(s.laddr[0])
        self.listeners[key] = lst = Listener(t.runtime, t.pid, s.pid, self._name(s.pid),
                                             *s.laddr, scope != "loopback", scope, now, now)
        out.append(lst)

    def _clients(self, accepted, now: datetime) -> list[Client]:
        # One global-table read per poll: who owns each client's (ip, port).
        pairs, _ = _connections_by_pid(self._connections, self._process_iter)
        owners: dict[tuple, int | None] = {}
        for pid, c in pairs:
            a = _addr(c.laddr)
            if a and (pid or a not in owners):  # a real pid beats 0/None (TIME_WAIT etc.)
                owners[a] = pid
        out = []
        for t, tree, s in accepted:
            ip, port = s.raddr
            pid = owners.get(s.raddr) or None
            if pid in tree:  # e.g. ollama serve <-> its llama-server child
                continue
            key = (t.pid, s.laddr[1], ip, pid, None if pid else port)
            if key in self.clients:
                self.clients[key].last_seen = now
                continue
            if s.raddr in owners or listener_scope(ip) == "loopback":
                scope, process, host, source = "local", self._name(pid) if pid else "?", None, None
            else:
                scope, process, host, source = "lan" if _is_lan(ip) else "public", None, ip, "ip"
            self.clients[key] = c = Client(t.runtime, t.pid, *s.laddr, ip, port, scope, pid,
                                           process, host, source, now, now)
            out.append(c)
        return out

    def _rename(self, endpoints, wait: float = RDNS_WAIT_S) -> None:
        names = self.namer.name_many([ep.ip for ep in endpoints], wait)
        for ep in endpoints:
            ep.host, ep.host_source = names[ep.ip]
            if isinstance(ep, Endpoint):
                ep.ai_provider = self.namer.providers(ep.ip)

    def summary(self, wait: float = RDNS_WAIT_S) -> list[Endpoint]:
        """All endpoints, oldest first; names of endpoints and remote clients
        retried (the DNS cache or a finished reverse lookup may have them
        now), waiting at most *wait* s in all."""
        self._rename([r for r in (*self.endpoints.values(), *self.clients.values())
                      if r.host_source and r.host_source != "dns-cache"], wait)
        return sorted(self.endpoints.values(), key=lambda e: (e.first_seen, e.runtime, e.ip))

    def incoming(self) -> tuple[list[Listener], list[Client]]:
        """All listeners and clients, oldest first (summary() renames clients)."""
        return (
            sorted(self.listeners.values(), key=lambda r: (r.first_seen, r.runtime, r.port, r.ip)),
            sorted(self.clients.values(),
                   key=lambda c: (c.first_seen, c.runtime, c.listener_port, c.ip, c.port)),
        )


class LocalAgents:
    """`--local`: running agents (discovery.find_running_agents) that have
    their own OS process, as find_targets() *agents*.

    A pid counts only if it is alive and its own cmdline/name match the
    adapter it was discovered as. That rules out synthetic pids (Cursor,
    Copilot in VS Code, Cline, Claude Desktop/Cowork, Codex app-server
    threads), which are counted in *unwatched* instead. Not
    net_sampler.attributable(): that also drops Aider and `opencode serve`
    for timestamp reasons, and Aider on Ollama is the case --local is for.
    """

    def __init__(self, find=None, process=psutil.Process, clock=time.monotonic):
        if find is None:
            cache = DiscoveryCache()

            def find():
                return find_running_agents(cache)

        self._find, self._process, self._clock = find, process, clock
        self._verdicts: dict[tuple[int, float], str | None] = {}  # adapter name
        self._due = 0.0
        self.targets: list[tuple[int, str]] = []  # (pid, "agent:<agent_type>")
        self.unwatched: list[str] = []  # agent_type of each agent not watched

    def is_agent_pid(self, pid: int, agent_type: str) -> bool:
        try:
            p = self._process(pid)
            key = (pid, p.create_time())  # a reused pid gets a new verdict
        except _PROC_ERRORS:
            return False
        if key not in self._verdicts:
            try:  # cmdline is read in memory only: never stored or logged
                adapter = match_process_adapter(p.cmdline(), p.name())
                self._verdicts[key] = adapter.name if adapter else None
            except _PROC_ERRORS:  # denied: can't prove it is the agent's own process
                self._verdicts[key] = None
        return self._verdicts[key] == agent_type

    def scan(self) -> None:
        """Re-discover, unless the last discovery was slow and is younger
        than AGENT_REFRESH_S."""
        start = self._clock()
        if start < self._due:
            return
        agents = self._find()
        if self._clock() - start >= AGENT_SLOW_S:
            self._due = start + AGENT_REFRESH_S
        real = [a for a in agents if self.is_agent_pid(a.pid, a.agent_type)]
        self.targets = [(a.pid, f"agent:{a.agent_type}") for a in real]
        self.unwatched = sorted(a.agent_type for a in agents if a not in real)
        live = {a.pid for a in agents}
        self._verdicts = {k: v for k, v in self._verdicts.items() if k[0] in live}
