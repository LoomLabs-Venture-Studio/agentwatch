"""Per-agent network endpoint sampler (#130).

Polls the sockets of each tracked agent process and its descendants every
``interval`` seconds, unprivileged (psutil), and records the remote
(ip, port) endpoints seen, as spans of continuous observation. Actions then
ask which endpoints overlapped their time window.

Limits: connections that open and close between polls (shorter than
``interval``) are missed; no byte counts; a shared keep-alive socket (one
HTTP/2 connection to the LLM API) is attributed by time window only.
Design: docs/research/network-tracking-2026-10-14.md
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import timezone

import psutil

from agentwatch import agents
from agentwatch.ai_detect import _PROC_ERRORS, _connections_by_pid, _remote_ip
from agentwatch.parser.models import IDLE_GAP_CAP

# ponytail: spans older than IDLE_GAP_CAP (30 min) are dropped, so an action
# replayed later than that finds nothing; keep per-session history if needed.
_RETENTION = IDLE_GAP_CAP.total_seconds()


@dataclass
class Endpoint:
    ip: str
    port: int
    first_seen: float  # epoch seconds
    last_seen: float


def _denied(kind):
    raise psutil.AccessDenied()


def _own_pids(root: int, trees: dict[int, list]) -> set[int]:
    """Pids whose sockets are charged to *root*: its whole tree minus the
    subtrees of any other tracked root nested inside it. A nested tracked
    root (and its descendants) is attributed to that root alone, so traffic
    is never counted under both the parent and the child."""
    own = {p.pid for p in trees[root]}
    for other in trees:
        if other != root and other in own:
            own -= {other} | {p.pid for p in trees[other]}
    return own


class NetSampler:
    def __init__(
        self,
        interval: float = 1.0,
        *,
        connections=psutil.net_connections,
        process=psutil.Process,
        clock=time.time,
    ):
        self._interval = interval
        self._connections = connections
        self._process = process
        self._clock = clock
        self._lock = threading.Lock()
        self._started: dict[int, float] = {}  # root pid -> tracking start
        self._created: dict[int, float | None] = {}  # root pid -> create_time()
        self._spans: dict[int, list[Endpoint]] = {}
        self._live: dict[int, dict[tuple[str, int], Endpoint]] = {}  # seen last tick
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def track(self, pid: int) -> None:
        try:
            created = self._process(pid).create_time()
        except _PROC_ERRORS:
            created = None
        with self._lock:
            if pid not in self._started:
                self._started[pid] = self._clock()
                self._created[pid] = created
                self._spans[pid], self._live[pid] = [], {}

    def untrack(self, pid: int) -> None:
        with self._lock:
            for d in (self._started, self._created, self._spans, self._live):
                d.pop(pid, None)

    def sample(self) -> None:
        """One poll of every tracked root and its descendants."""
        now = self._clock()
        with self._lock:
            roots = dict(self._created)
        if not roots:
            return  # nothing tracked: don't read the machine's socket table
        trees: dict[int, list] = {}
        for root, created in roots.items():
            try:
                proc = self._process(root)
                if created is not None and proc.create_time() != created:
                    raise psutil.NoSuchProcess(root)  # pid reused: never sample the newcomer
                trees[root] = [proc, *proc.children(recursive=True)]
            except _PROC_ERRORS:
                trees[root] = []  # dead or denied root: empty this tick
        procs = [p for tree in trees.values() for p in tree]
        pairs, partial = _connections_by_pid(self._connections, lambda: procs)
        if partial:  # macOS non-root denies the global table every time
            self._connections = _denied
        seen_by_pid: dict[int, set[tuple[str, int]]] = {}
        for pid, c in pairs:
            ip = _remote_ip(c)
            if ip and c.status != psutil.CONN_LISTEN:
                seen_by_pid.setdefault(pid, set()).add((ip, c.raddr.port))
        with self._lock:
            for root, tree in trees.items():
                if root not in self._started:
                    continue  # untracked while polling
                own = _own_pids(root, trees)
                seen = set().union(*(seen_by_pid.get(pid, ()) for pid in own))
                live, spans = self._live[root], self._spans[root]
                fresh = {}
                for ip, port in seen:
                    ep = live.get((ip, port))
                    if ep:
                        ep.last_seen = now
                    else:
                        ep = Endpoint(ip, port, now, now)
                        spans.append(ep)
                    fresh[(ip, port)] = ep
                self._live[root] = fresh
                self._spans[root] = [e for e in spans if e.last_seen >= now - _RETENTION]

    def endpoints(self, pid: int, start: float, end: float) -> list[tuple[str, int]] | None:
        """Endpoints seen in [start, end], with one poll interval of slack each
        side. None if *pid* is untracked or the window ends before tracking
        began (not sampled, as opposed to nothing seen)."""
        lo, hi = start - self._interval, end + self._interval
        with self._lock:
            began = self._started.get(pid)
            if began is None or end < began:
                return None
            return sorted({
                (e.ip, e.port) for e in self._spans[pid] if e.first_seen <= hi and e.last_seen >= lo
            })

    def spans(self, pid: int) -> list[Endpoint] | None:
        """Copies of *pid*'s endpoint spans (the last _RETENTION s), oldest
        first; None if *pid* is untracked."""
        with self._lock:
            if pid not in self._spans:
                return None
            return [Endpoint(e.ip, e.port, e.first_seen, e.last_seen) for e in self._spans[pid]]

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="net-sampler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.sample()
            except Exception:  # a bad tick must never kill the sampler thread
                pass
            self._stop.wait(self._interval)


def window(action, previous_ts: float | None) -> tuple[float, float]:
    """(start, end) epoch seconds of *action*'s network window.

    end is the action's timestamp (now if missing); naive timestamps are
    treated as UTC, which most parsers produce. Aider's naive timestamps are
    local time, so its windows are offset on non-UTC machines (known). start
    is end - duration_ms, else *previous_ts*, else end. Capped at
    IDLE_GAP_CAP.
    """
    ts = action.timestamp
    if ts is None:
        end = time.time()
    else:
        end = (ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts).timestamp()
    if action.duration_ms > 0:
        start = end - action.duration_ms / 1000
    else:
        start = previous_ts if previous_ts is not None else end
    return max(end - IDLE_GAP_CAP.total_seconds(), min(start, end)), end


NOT_ATTRIBUTABLE = "Net: n/a (not attributable)"


def attach(sampler: NetSampler, pid: int, action, previous_ts: float | None) -> float:
    """Set *action*.observed_endpoints for its window; return the window end,
    the next action's *previous_ts*."""
    start, end = window(action, previous_ts)
    action.observed_endpoints = sampler.endpoints(pid, start, end)
    return end


def endpoint_summary(actions) -> str:
    """Stats-line text: distinct (ip, port) across *actions*."""
    n = len({ep for a in actions for ep in a.observed_endpoints or ()})
    return f"Net: {n} endpoints"


def attributable(proc) -> bool:
    """True only for a real per-agent OS process (not an editor host, a Codex
    app-server thread's synthetic pid, a shared ``kilo serve``/``opencode
    serve``, or Aider, whose timestamps are synthesized from session start +
    ordinal so its windows are meaningless)."""
    adapter = agents.get(proc.agent_type)
    words = proc.command.split()
    if adapter is None or adapter.kind != "process" or proc.agent_type == "aider":
        return False
    if proc.agent_type == "codex" and "app-server" in words:
        return False
    return not (proc.agent_type in ("kilo-code", "opencode") and "serve" in words)
