"""Process-based discovery of running AI agent processes."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import psutil

from agentwatch.path_encoding import encode_path_for_claude

# Agent detection patterns: maps agent_type to (process name regex, excludes)
AGENT_PATTERNS: dict[str, dict] = {
    "claude-code": {
        "pattern": r"\bclaude\b",
        "exclude": r"Claude\.app|Claude Helper|claude-code-guide|shell-snapshots",
    },
    "aider": {
        "pattern": r"\baider\b",
        "exclude": None,
    },
    "codex": {
        "pattern": r"\bcodex\b",
        "exclude": None,
    },
}


@dataclass
class AgentProcess:
    """Represents a running AI agent process."""

    pid: int
    agent_type: str  # "claude-code", "aider", "codex", etc.
    working_directory: Path
    log_file: Path | None = None
    session_id: str | None = None
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    uptime: str = ""
    command: str = ""
    parent_pid: int | None = None  # Raw OS PPID from ps
    parent_agent_pid: int | None = None  # Nearest ancestor that is also a discovered agent
    depth: int = 0  # Nesting level: 0 = root agent, 1 = subagent, etc.
    team_id: int | None = None  # PID of the root ancestor (team identifier)
    # Real state.vscdb path for agent_type == "cursor" entries. Cursor has no
    # per-session log file the way Claude Code/Aider/Codex do -- every
    # composer across every workspace lives in one shared SQLite file, so
    # log_file holds a synthetic, never-created-on-disk per-composer
    # identity key instead (see cursor_discovery.py::_cursor_synthetic_log_key)
    # -- MultiLogWatcher keys its tracking dicts by log_file, and every
    # composer would otherwise collide on the one real db path. Real I/O
    # always goes through this field.
    cursor_db_path: Path | None = None

    @property
    def project_name(self) -> str:
        """Extract project name from working directory."""
        return self.working_directory.name

    @property
    def is_root(self) -> bool:
        return self.depth == 0

    @property
    def is_subagent(self) -> bool:
        return self.depth > 0


@dataclass
class AgentTeam:
    """A group of agents sharing a common root ancestor."""

    team_id: int  # PID of the root agent
    root: AgentProcess  # The root agent
    members: list[AgentProcess] = field(default_factory=list)  # All members including root

    @property
    def name(self) -> str:
        return f"{self.root.agent_type}:{self.root.project_name}"

    @property
    def member_count(self) -> int:
        return len(self.members)

    @property
    def subagent_count(self) -> int:
        return sum(1 for m in self.members if m.is_subagent)

    @property
    def max_depth(self) -> int:
        return max((m.depth for m in self.members), default=0)


@dataclass
class DiscoveryCache:
    """Memoizes per-PID cwd/log-file resolution across repeated discovery scans.

    ``find_running_agents()`` is called on a fixed poll interval (e.g. every
    5s from the multi-agent UI). Without a cache, every already-known PID
    pays the full blocking resolution cost (cwd + open-jsonl lookup) again
    on every single scan. This cache lets already-resolved PIDs skip that
    work, re-resolving only when the cached log path has gone stale.
    """

    cwd_by_pid: dict[int, Path] = field(default_factory=dict)
    log_by_pid: dict[int, tuple[Path | None, str | None]] = field(default_factory=dict)

    def prune(self, live_pids: set[int]) -> None:
        """Drop cache entries for PIDs that are no longer running."""
        for pid in self.cwd_by_pid.keys() - live_pids:
            self.cwd_by_pid.pop(pid, None)
            self.log_by_pid.pop(pid, None)


def find_running_agents(cache: DiscoveryCache | None = None) -> list[AgentProcess]:
    """Discover running AI agent processes on the local machine.

    Uses ``psutil.process_iter()`` to find processes matching known agent
    patterns (including PPID for subagent detection), then
    ``psutil.Process.cwd()`` (via ``_get_process_cwd``) to resolve each
    process's working directory.

    When *cache* is provided, already-known PIDs reuse their previously
    resolved cwd/log-file instead of re-resolving cwd every scan.
    """
    # Materialize once: psutil caches each attrs snapshot on `.info`, so
    # both passes below read already-fetched data with no further syscalls.
    procs = list(
        psutil.process_iter(
            attrs=[
                "pid",
                "ppid",
                "cmdline",
                "name",
                "memory_info",
                "cpu_percent",
                "create_time",
            ]
        )
    )

    # First pass: build complete PID -> PPID map for ancestor walking
    pid_to_ppid: dict[int, int] = {}
    for proc in procs:
        try:
            info = proc.info
            pid_to_ppid[info["pid"]] = info["ppid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Second pass: find agent processes
    agents: list[AgentProcess] = []
    seen_pids: set[int] = set()

    for proc in procs:
        try:
            info = proc.info
            pid = info["pid"]
            ppid = info["ppid"]
            cmdline = info["cmdline"] or []
            name = info["name"] or ""
            command = " ".join(cmdline) or name
            mem_info = info["memory_info"]
            memory_mb = (mem_info.rss / (1024.0 * 1024.0)) if mem_info else 0.0
            cpu_percent = info["cpu_percent"] or 0.0
            create_time = info["create_time"]
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

        for agent_type, config in AGENT_PATTERNS.items():
            pattern = config["pattern"]
            exclude = config["exclude"]

            if not re.search(pattern, command):
                continue
            if exclude and re.search(exclude, command):
                continue

            if pid in seen_pids:
                continue
            seen_pids.add(pid)

            etime = _format_etime(time.time() - create_time) if create_time else ""

            # Get working directory (cached across scans when a
            # DiscoveryCache is provided — avoids re-resolving cwd for
            # every already-known PID on each poll tick).
            if cache is not None:
                cwd = cache.cwd_by_pid.get(pid) or _get_process_cwd(pid)
                if pid not in cache.cwd_by_pid and cwd is not None:
                    cache.cwd_by_pid[pid] = cwd
            else:
                cwd = _get_process_cwd(pid)
            if cwd is None:
                continue

            # Resolve log file based on agent type. Reuse the cached
            # resolution unless it's missing or the cached path no longer
            # exists on disk (e.g. log rotated), in which case re-resolve.
            log_file = None
            session_id = None
            cache_hit = False
            if cache is not None and pid in cache.log_by_pid:
                cached_log, cached_session = cache.log_by_pid[pid]
                if cached_log is not None and cached_log.exists():
                    log_file, session_id = cached_log, cached_session
                    cache_hit = True

            if not cache_hit:
                if agent_type == "claude-code":
                    log_file, session_id = _resolve_claude_code_log(cwd, pid=pid)
                elif agent_type == "aider":
                    log_file, session_id = _resolve_aider_log(cwd)
                elif agent_type == "codex":
                    log_file, session_id = _resolve_codex_log(cwd, pid=pid)
                if cache is not None:
                    cache.log_by_pid[pid] = (log_file, session_id)

            agents.append(
                AgentProcess(
                    pid=pid,
                    agent_type=agent_type,
                    working_directory=cwd,
                    log_file=log_file,
                    session_id=session_id,
                    cpu_percent=cpu_percent,
                    memory_mb=memory_mb,
                    uptime=etime,
                    command=command,
                    parent_pid=ppid,
                )
            )

    # Post-process: resolve parent-child relationships between agents
    agent_pids = {a.pid for a in agents}
    for agent in agents:
        ancestor = _walk_to_ancestor_agent(agent.pid, pid_to_ppid, agent_pids)
        if ancestor is not None:
            agent.parent_agent_pid = ancestor

    # Cursor composers have no OS-process ancestry to walk (the whole IDE,
    # not a per-session process, hosts every composer across every
    # workspace) -- appended after the PPID-based ancestor walk above so
    # they never get spuriously matched against pid_to_ppid, but before
    # depth/team assignment so they still get a valid depth=0/team_id=self
    # like any other rootless agent. Lazy import mirrors the logs.py <->
    # codex.py pattern: avoids a module-load-time cycle since
    # cursor_discovery.py imports AgentProcess from this module.
    try:
        from agentwatch.cursor_discovery import find_cursor_agents

        agents.extend(find_cursor_agents())
    except Exception:
        pass

    _compute_depths(agents)
    _assign_team_ids(agents)

    if cache is not None:
        cache.prune(seen_pids)

    return agents


def _walk_to_ancestor_agent(
    pid: int,
    pid_to_ppid: dict[int, int],
    agent_pids: set[int],
    max_hops: int = 50,
) -> int | None:
    """Walk the PPID chain upward from *pid* to find the nearest ancestor agent.

    Traverses through intermediate non-agent processes (shells, node
    workers, etc.).  Returns the ancestor's PID or ``None`` if no
    ancestor is a known agent.
    """
    current = pid_to_ppid.get(pid)
    visited: set[int] = {pid}
    hops = 0
    while current is not None and current not in visited and hops < max_hops:
        if current in agent_pids:
            return current
        visited.add(current)
        current = pid_to_ppid.get(current)
        hops += 1
    return None


def _compute_depths(agents: list[AgentProcess]) -> None:
    """Set ``depth`` on each agent: 0 for roots, parent.depth + 1 for children."""
    agent_by_pid: dict[int, AgentProcess] = {a.pid: a for a in agents}
    resolved: set[int] = set()

    # Mark roots (no parent_agent_pid)
    for agent in agents:
        if agent.parent_agent_pid is None:
            agent.depth = 0
            resolved.add(agent.pid)

    # Iteratively resolve children
    changed = True
    while changed:
        changed = False
        for agent in agents:
            if agent.pid in resolved:
                continue
            parent = agent_by_pid.get(agent.parent_agent_pid)  # type: ignore[arg-type]
            if parent and parent.pid in resolved:
                agent.depth = parent.depth + 1
                resolved.add(agent.pid)
                changed = True

    # Promote any unresolved agents (orphaned subagents) to root
    for agent in agents:
        if agent.pid not in resolved:
            agent.parent_agent_pid = None
            agent.depth = 0


def build_agent_tree(agents: list[AgentProcess]) -> list[AgentProcess]:
    """Return *agents* sorted in tree-display order.

    Parents appear before their children; siblings are sorted by PID.
    """
    by_parent: dict[int | None, list[AgentProcess]] = {}
    for a in agents:
        by_parent.setdefault(a.parent_agent_pid, []).append(a)

    for children in by_parent.values():
        children.sort(key=lambda a: a.pid)

    result: list[AgentProcess] = []

    def _walk(parent_pid: int | None) -> None:
        for agent in by_parent.get(parent_pid, []):
            result.append(agent)
            _walk(agent.pid)

    _walk(None)
    return result


def _assign_team_ids(agents: list[AgentProcess]) -> None:
    """Set ``team_id`` on each agent to its root ancestor's PID."""
    agent_by_pid: dict[int, AgentProcess] = {a.pid: a for a in agents}

    for agent in agents:
        if agent.is_root:
            agent.team_id = agent.pid
        else:
            # Walk up the parent chain to find root
            current = agent
            while current.parent_agent_pid is not None:
                parent = agent_by_pid.get(current.parent_agent_pid)
                if parent is None:
                    break
                current = parent
            agent.team_id = current.pid


def build_teams(agents: list[AgentProcess]) -> list[AgentTeam]:
    """Group agents into teams by their root ancestor.

    Each tree of agents (root + all descendants) forms one team.
    Solo agents form single-member teams.
    """
    _assign_team_ids(agents)

    teams_by_id: dict[int, AgentTeam] = {}
    for agent in agents:
        tid = agent.team_id
        if tid is None:
            tid = agent.pid
        if tid not in teams_by_id:
            # Find root agent for this team
            root = next((a for a in agents if a.pid == tid), agent)
            teams_by_id[tid] = AgentTeam(team_id=tid, root=root, members=[])
        teams_by_id[tid].members.append(agent)

    # Sort teams by root PID, members within each team by tree order
    result = sorted(teams_by_id.values(), key=lambda t: t.team_id)
    for team in result:
        team.members = build_agent_tree(team.members)
    return result


def _get_process_cwd(pid: int) -> Path | None:
    """Get the current working directory of a process using psutil."""
    try:
        path = Path(psutil.Process(pid).cwd())
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

    return path if path.is_dir() else None


def _format_etime(elapsed_seconds: float) -> str:
    """Format elapsed seconds into a ``ps -eo etime``-compatible string.

    Mirrors ``ps``'s ``[[DD-]HH:]MM:SS`` shape so downstream consumers
    (``cli.py``'s JSON output, ``parser/watcher.py``'s stale-process
    fallback) keep receiving the same string format regardless of whether
    the value came from ``ps`` (POSIX) or ``create_time``-based computation
    (all platforms, via psutil).
    """
    total_seconds = max(0, int(elapsed_seconds))
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    if days > 0:
        return f"{days:02d}-{hours:02d}:{minutes:02d}:{seconds:02d}"
    if hours > 0:
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"


def _find_open_jsonl(pid: int, project_dir: Path) -> Path | None:
    """Find which .jsonl file under project_dir a specific PID has open.

    Uses ``psutil.Process.open_files()`` (cross-platform) instead of
    shelling out to ``lsof``, which doesn't exist on Windows.
    """
    try:
        open_files = psutil.Process(pid).open_files()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

    project_dir = project_dir.resolve()
    for f in open_files:
        path = Path(f.path)
        if path.suffix != ".jsonl":
            continue
        try:
            path.resolve().relative_to(project_dir)
        except ValueError:
            continue
        if path.exists():
            return path
    return None


def _resolve_claude_code_log(
    cwd: Path, pid: int | None = None
) -> tuple[Path | None, str | None]:
    """Resolve the active Claude Code session log for a working directory.

    When *pid* is provided, uses ``lsof`` to find the exact ``.jsonl``
    file that process has open — this avoids cross-contamination when
    multiple agents share the same project directory.  Falls back to
    most-recently-modified when ``lsof`` can't determine the file.
    """
    encoded = encode_path_for_claude(cwd)
    project_dir = Path.home() / ".claude" / "projects" / encoded

    if not project_dir.is_dir():
        return None, None

    jsonl_files = list(project_dir.glob("*.jsonl"))
    if not jsonl_files:
        return None, None

    # Prefer lsof-based resolution for the specific PID
    log_file: Path | None = None
    if pid is not None:
        log_file = _find_open_jsonl(pid, project_dir)

    # Fallback: most recently modified file
    if log_file is None:
        log_file = max(jsonl_files, key=lambda f: f.stat().st_mtime)

    session_id = log_file.stem

    # Try to get session metadata from sessions-index.json
    index_file = project_dir / "sessions-index.json"
    if index_file.exists():
        try:
            with open(index_file, "r") as f:
                index_data = json.loads(f.read())
            # sessions-index.json may have session info keyed by ID
            if isinstance(index_data, dict) and session_id in index_data:
                session_meta = index_data[session_id]
                if isinstance(session_meta, dict) and "id" in session_meta:
                    session_id = session_meta["id"]
        except (json.JSONDecodeError, OSError):
            pass

    return log_file, session_id


def _resolve_aider_log(cwd: Path) -> tuple[Path | None, str | None]:
    """Resolve the active Aider session log for a working directory.

    Looks for .aider.chat.history.md -- the only confirmed real Aider
    transcript file (see below for why a ``.aider/logs/`` fallback that
    used to live here was removed).
    """
    # Check for chat history file
    history_file = cwd / ".aider.chat.history.md"
    if history_file.exists():
        return history_file, None

    # NOTE (PLAYBOOK Sprint 6, 2026-07-14): this function previously also
    # fell back to the most recently modified file under a `.aider/logs/`
    # directory when no `.aider.chat.history.md` existed. That fallback
    # was removed after researching Aider's real current source
    # (github.com/Aider-AI/aider @ main) turned up no evidence it's a real
    # convention:
    #   - `gh search code` across the repo for `.aider/logs` / `aider/logs`
    #     returns zero hits.
    #   - `aider/args.py` (the full CLI flag surface) only defines
    #     `--chat-history-file` (default `.aider.chat.history.md`),
    #     `--llm-history-file`, `--input-history-file`, and
    #     `--analytics-log` -- all arbitrary user-supplied paths or the one
    #     confirmed Markdown default; none default into a `.aider/logs/`
    #     directory.
    #   - `aider/website/docs/config/options.md` and `sample.aider.conf.yml`
    #     document the same four options with the same defaults.
    #   - The closest real reference found is GitHub issue
    #     Aider-AI/aider#3574 ("Feature Suggestion: Better organized aider
    #     logs"), which is still OPEN and unimplemented, and proposes a
    #     *different* directory name (`.ai-chats/`) as a third-party
    #     wrapper around `--chat-history-file` -- not anything Aider itself
    #     writes.
    # Conclusion: `.aider/logs/*.log` was very likely a hallucinated or
    # conflated convention, not a real one. Removed rather than left as a
    # dead path that would silently resolve to an unparseable file of
    # unknown format. If a real convention like this is ever confirmed
    # (e.g. a future Aider release implements #3574), re-add a fallback
    # branch here alongside a parser for whatever format it turns out to
    # be -- do not guess the format in advance.

    return None, None


def _read_codex_session_meta(path: Path, max_lines: int = 5) -> dict | None:
    """Read the leading ``session_meta`` line from a Codex rollout file.

    ``session_meta`` is documented to appear once near the top of the
    file, so this short-circuits after *max_lines* instead of reading the
    whole (potentially large) rollout file. Returns the unwrapped
    ``payload`` dict (or the raw entry itself for the "oldest"/flat
    schema era — see ``parser/codex.py::_detect_codex_era``), or ``None``
    if no session_meta line is found/readable.

    Must never raise into ``find_running_agents()``'s scan loop — all
    file/JSON errors are swallowed.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for _ in range(max_lines):
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("type") == "session_meta":
                    payload = entry.get("payload", entry)
                    return payload if isinstance(payload, dict) else None
    except OSError:
        return None
    return None


def _find_open_codex_rollout(pid: int, sessions_root: Path) -> Path | None:
    """Find which ``rollout-*.jsonl`` file under *sessions_root* a specific
    Codex PID has open.

    Mirrors ``_find_open_jsonl``'s exact approach (``psutil.Process.
    open_files()``, cross-platform, no ``lsof`` dependency) but matches
    against the whole date-bucketed ``sessions/`` tree rather than a single
    cwd-keyed directory, and requires the ``rollout-`` filename prefix
    (Codex's real rollout naming convention — see module docstring) rather
    than just a ``.jsonl`` suffix, since arbitrary other ``.jsonl`` files
    could in principle live under the same root.
    """
    try:
        open_files = psutil.Process(pid).open_files()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

    sessions_root = sessions_root.resolve()
    for f in open_files:
        path = Path(f.path)
        if path.suffix != ".jsonl" or not path.name.startswith("rollout-"):
            continue
        try:
            path.resolve().relative_to(sessions_root)
        except ValueError:
            continue
        if path.exists():
            return path
    return None


def _resolve_codex_log(cwd: Path, pid: int | None = None) -> tuple[Path | None, str | None]:
    """Resolve the active Codex CLI session log for a working directory.

    Codex sessions live under a date-bucketed tree
    (``~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl``), not a cwd-keyed
    directory the way Claude Code's are — so unlike
    ``_resolve_claude_code_log``, there is no free directory-name match.

    When *pid* is provided, first tries ``_find_open_codex_rollout`` —
    ``psutil.Process(pid).open_files()`` matched against the live process's
    actually-open file handles, mirroring ``_find_open_jsonl``'s approach
    for Claude Code (PRD Open Question #5, implemented). This is
    authoritative: if a real Codex process has a specific rollout file
    open, that's the session, full stop — it bypasses the heuristics below
    entirely. Falls back to reading each candidate file's leading
    ``session_meta`` line (bounded to the day-window most likely to contain
    a live session) to match on ``payload.cwd`` when no PID match is found
    (or no PID was given), and finally to most-recently-modified when no
    ``session_meta`` line is readable or matches.

    NOTE: honors ``CODEX_HOME`` if set (root becomes ``$CODEX_HOME``
    instead of ``~/.codex``). Whether ``CODEX_HOME`` supports a
    comma-separated list of multiple roots is NOT confirmed (PRD Open
    Question #2) — this implementation only supports a single root, the
    confirmed-safe subset.

    NOTE: per openai/codex issue #21660, rollout files are created
    world-readable (``0o666 & ~umask``) on Unix rather than the tighter
    ``0o600`` one might expect for a file containing full conversation
    content — this is Codex's own permission looseness, not something
    AgentWatch introduces or needs to work around.
    """
    codex_home_env = os.environ.get("CODEX_HOME")
    codex_home = Path(codex_home_env) if codex_home_env else (Path.home() / ".codex")
    sessions_root = codex_home / "sessions"
    if not sessions_root.is_dir():
        return None, None

    # Prefer PID-based resolution: authoritative if the live process has a
    # specific rollout file open, bypassing the cwd-matching/mtime fallback
    # heuristics below entirely.
    if pid is not None:
        open_log = _find_open_codex_rollout(pid, sessions_root)
        if open_log is not None:
            meta = _read_codex_session_meta(open_log)
            session_id = (meta or {}).get("session_id") or (meta or {}).get("id")
            return open_log, session_id

    # Bound the scan: check today and yesterday's date buckets only (a
    # session spanning midnight still opens its file in one bucket).
    candidates: list[Path] = []
    for days_back in (0, 1):
        day = datetime.now() - timedelta(days=days_back)
        bucket = sessions_root / f"{day:%Y}" / f"{day:%m}" / f"{day:%d}"
        if bucket.is_dir():
            candidates.extend(bucket.glob("rollout-*.jsonl"))

    if not candidates:
        return None, None

    resolved_cwd = cwd.resolve()
    for path in sorted(candidates, key=lambda f: f.stat().st_mtime, reverse=True):
        meta = _read_codex_session_meta(path)
        if meta and meta.get("cwd"):
            try:
                if Path(meta["cwd"]).resolve() == resolved_cwd:
                    return path, meta.get("session_id") or meta.get("id")
            except OSError:
                pass

    # Fallback: most-recently-modified candidate, cwd unverified — same
    # trade-off _resolve_claude_code_log accepts when lsof can't resolve.
    log_file = max(candidates, key=lambda f: f.stat().st_mtime)
    meta = _read_codex_session_meta(log_file)
    session_id = (meta or {}).get("session_id") or (meta or {}).get("id")
    return log_file, session_id
