"""Per-agent egress sampler (#130, option 1 of
docs/research/network-tracking-2026-10-14.md).

Samples which remote endpoints an agent process tree is connected to, and
which IPs its own actions (plus the AI providers) explain, so
UndeclaredEgressDetector can flag the rest. Unprivileged: per-process
socket tables only. Reads cmdline in memory to confirm the pid is the
agent's real process; never stores or logs it.

# ponytail: polling (watch-all ticks ~2 s) misses connections opened and
# closed between samples; the DNS allow-list resolves each host once, so a
# CDN rotating IPs later reads as undeclared; children(recursive=True) walks
# the whole tree every tick. Upgrade: ETW/eBPF event capture if any of
# these bites.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache

import psutil

from agentwatch.ai_detect import _PROC_ERRORS, _resolve_ips
from agentwatch.discovery import match_process_adapter
from agentwatch.parser.logs import url_hostname

_URL = re.compile(r"https?://[^\s'\"<>|;`)]+", re.IGNORECASE)


@dataclass
class Egress:
    """Endpoints seen on the wire for one agent, and the IPs that explain them."""

    # (ip, port) -> [first_seen, last_seen]
    endpoints: dict[tuple[str, int], list[datetime]] = field(default_factory=dict)
    allowed: frozenset[str] = frozenset()

    def merge(self, observed: set[tuple[str, int]], allowed: frozenset[str], now: datetime) -> bool:
        """Fold one sample in. True when the detector's verdict may have changed."""
        changed = not allowed <= self.allowed
        # Only grows: an action evicted from the buffer still explains its endpoint.
        self.allowed |= allowed
        for ep in observed:
            if ep in self.endpoints:
                self.endpoints[ep][1] = now
            else:
                self.endpoints[ep] = [now, now]
                changed = True
        return changed

    def undeclared(self) -> dict[tuple[str, int], list[datetime]]:
        return {ep: seen for ep, seen in self.endpoints.items() if ep[0] not in self.allowed}


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

    Descendants in *exclude*, and their subtrees, are skipped (a tracked
    sub-agent samples its own tree). Vanished/denied processes are skipped.
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


def is_local_address(ip: str) -> bool:
    """Loopback, unspecified, link-local, multicast (or unparseable)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_loopback or a.is_unspecified or a.is_link_local or a.is_multicast


def remote_endpoints(sockets: list[SocketInfo]) -> set[tuple[str, int]]:
    """Distinct non-local remote (ip, port) pairs."""
    return {s.raddr for s in sockets if s.raddr and not is_local_address(s.raddr[0])}


def is_agent_pid(pid: int, agent_type: str, verdicts: dict, process=psutil.Process) -> bool:
    """True if the process at *pid* really is *agent_type*'s.

    Synthetic pids (Cursor, Copilot in VS Code, Cline, Cowork, Codex app
    threads) can't be told from real ones by value; whatever process, if any,
    sits at that pid won't match the agent's adapter. Verdict cached per
    (pid, create_time) so a reused pid is checked again.
    """
    try:
        proc = process(pid)
        key = (pid, proc.create_time())
        if key not in verdicts:
            adapter = match_process_adapter(proc.cmdline(), proc.name())
            verdicts[key] = adapter is not None and adapter.name == agent_type
    except _PROC_ERRORS:
        return False
    return verdicts[key]


def declared_hosts(actions) -> set[str]:
    """Hosts the actions declare: network_host, and http(s) URL hosts in commands."""
    hosts: set[str] = set()
    for a in actions:
        if a.network_host:
            hosts.add(a.network_host.lower())
        if a.command:
            hosts.update(h for h in map(url_hostname, _URL.findall(a.command)) if h)
    return hosts


@lru_cache(maxsize=4096)
def _host_ips(host: str, resolve) -> frozenset[str]:
    try:
        return frozenset(i[4][0].removeprefix("::ffff:") for i in resolve(host, 443))
    except (OSError, ValueError):  # ValueError: UnicodeError from IDNA encoding
        return frozenset()


@lru_cache(maxsize=1)
def _provider_ips(resolve) -> frozenset[str]:
    return frozenset(_resolve_ips(resolve)[0])


def allowed_ips(hosts: set[str], resolve=socket.getaddrinfo) -> frozenset[str]:
    """IPs of AI_PROVIDERS plus *hosts*. Blocking DNS: call off the event loop."""
    return _provider_ips(resolve).union(*(_host_ips(h, resolve) for h in hosts))


def sample(targets, tracked: set[int], verdicts: dict, *, process=psutil.Process,
           resolve=socket.getaddrinfo) -> dict:
    """One tick, run in a worker thread: {key: (endpoints, allowed_ips)}.

    *targets* is [(key, pid, agent_type, declared_hosts)]; pids that aren't
    the agent's real process are left out.
    """
    out = {}
    for key, pid, agent_type, hosts in targets:
        if is_agent_pid(pid, agent_type, verdicts, process):
            sockets = tree_sockets(pid, tracked, process)
            out[key] = (remote_endpoints(sockets), allowed_ips(hosts, resolve))
    return out
