"""Process-based discovery of running AI agent processes."""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psutil

from agentwatch import agents as _agents
from agentwatch.path_encoding import encode_path_for_claude

logger = logging.getLogger(__name__)

# Back-compat: read-only view derived from the adapter registry. New agents
# are added in agentwatch/agents/, not here.
AGENT_PATTERNS: dict[str, dict] = {
    a.name: {"pattern": a.process_pattern, "exclude": a.process_exclude}
    for a in _agents.process_adapters()
}

_INTERPRETER = re.compile(r"(node|nodejs|bun|deno|pythonw?[\d.]*)(\.exe)?", re.IGNORECASE)


def program_path(cmdline: list[str], name: str = "") -> str:
    """The program a process runs: argv[0], or the script/module after an interpreter.

    Agents are identified by this, never by their arguments: ``copilot --model
    gpt-5.1-codex`` is Copilot, not Codex.
    """
    if not cmdline:
        return name
    if not _INTERPRETER.fullmatch(re.split(r"[/\\]", cmdline[0])[-1]):
        return cmdline[0]
    # ponytail: interpreter flags taking a separate value (`node -r x`) are not skipped.
    args = iter(cmdline[1:])
    for arg in args:
        if arg == "-m":
            return next(args, cmdline[0])
        if arg in ("-c", "-e", "--eval", "-p", "--print"):
            return cmdline[0]  # inline code, no script
        if not arg.startswith("-"):
            return arg
    return cmdline[0]


def _is_program_dir(cwd: Path, cmdline: list[str], name: str = "") -> bool:
    """Whether *cwd* is the directory of the process's own executable."""
    try:
        exe_dir = Path(program_path(cmdline, name)).parent
        if not exe_dir.is_absolute():
            return False
        return os.path.normcase(exe_dir.resolve()) == os.path.normcase(cwd.resolve())
    except (OSError, ValueError, RuntimeError):
        return False


def match_process_adapter(cmdline: list[str], name: str = "") -> _agents.AgentAdapter | None:
    """First process adapter whose pattern matches the program.

    Excludes see the program prefixed by its interpreter (``node /x/bin/copilot``),
    never the arguments, so a session's own args can't hide it.
    """
    program = program_path(cmdline, name)
    launcher = cmdline[0] if cmdline else name
    command = program if launcher == program else f"{launcher} {program}"
    for adapter in _agents.process_adapters():
        if not adapter.process_pattern or not re.search(adapter.process_pattern, program):
            continue
        if adapter.process_exclude and re.search(adapter.process_exclude, command):
            continue
        if adapter.process_exclude_args.intersection(cmdline[1:]):
            continue
        return adapter
    return None


@dataclass
class AgentProcess:
    """Represents a running AI agent process."""

    pid: int
    agent_type: str  # "claude-code", "aider", "codex", etc.
    working_directory: Path | None  # None: no project known (#94)
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
        """Extract project name from working directory ("" when unknown)."""
        return self.working_directory.name if self.working_directory else ""

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
        return f"{self.root.agent_type}:{self.root.project_name or '---'}"

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
    # Claude Code: the session id in the process's live-session record when its
    # log was resolved (None: no record). A different id on a later scan means
    # the session changed inside the process (/clear, /resume): re-resolve.
    claude_session_by_pid: dict[int, str | None] = field(default_factory=dict)
    # Process start time per pid: a pid the OS hands to a new process must not
    # inherit the old process's cached cwd and log.
    started_by_pid: dict[int, float] = field(default_factory=dict)

    def forget(self, pid: int) -> None:
        """Drop every cache entry for *pid*."""
        for entries in (
            self.cwd_by_pid, self.log_by_pid, self.claude_session_by_pid, self.started_by_pid
        ):
            entries.pop(pid, None)

    def prune(self, live_pids: set[int]) -> None:
        """Drop cache entries for PIDs that are no longer running."""
        known = (
            self.cwd_by_pid.keys() | self.log_by_pid.keys()
            | self.claude_session_by_pid.keys() | self.started_by_pid.keys()
        )
        for pid in known - live_pids:
            self.forget(pid)


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
    # Claude Code processes seen this scan: start time, and whether each has a
    # live-session record (for _assign_claude_logs).
    claude_started: dict[int, float | None] = {}
    claude_registered: set[int] = set()

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

        adapter = match_process_adapter(cmdline, name)
        if adapter is not None and pid not in seen_pids:
            agent_type = adapter.name
            seen_pids.add(pid)

            etime = _format_etime(time.time() - create_time) if create_time else ""

            # Get working directory (cached across scans when a
            # DiscoveryCache is provided — avoids re-resolving cwd for
            # every already-known PID on each poll tick).
            if cache is not None:
                if create_time:
                    if cache.started_by_pid.get(pid, create_time) != create_time:
                        cache.forget(pid)  # pid reused by a new process
                    cache.started_by_pid[pid] = create_time
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
            # A Claude Code session can change inside a running process
            # (/clear, /resume). The live-session record is a small JSON file,
            # so it is read on every scan to check the cached log still holds.
            claude_record = None
            if agent_type == "claude-code":
                claude_record = _read_claude_session_record(pid, create_time)
                claude_started[pid] = create_time
                if claude_record is not None:
                    claude_registered.add(pid)
            # An app-server's open threads change between scans: always re-resolve (#105).
            app_server = agent_type == "codex" and "app-server" in cmdline[1:]
            if cache is not None and pid in cache.log_by_pid and not app_server:
                cached_log, cached_session = cache.log_by_pid[pid]
                if (
                    cached_log is not None
                    and cached_log.exists()
                    and (
                        agent_type != "claude-code"
                        or _claude_cache_current(cache, pid, claude_record)
                    )
                ):
                    log_file, session_id = cached_log, cached_session
                    cache_hit = True

            if not cache_hit:
                try:
                    log_file, session_id = adapter.resolve_log(cwd, pid)
                except Exception:
                    logger.debug("resolve_log failed for adapter %s", adapter.name, exc_info=True)
                    log_file, session_id = None, None
                # A Codex rollout's session_meta cwd is the real project: the
                # ChatGPT desktop app-server's own cwd is its bin\<hash> dir.
                # Same value as the process cwd for the CLI.
                if agent_type == "codex" and log_file is not None:
                    meta_cwd = (_read_codex_session_meta(log_file) or {}).get("cwd")
                    if isinstance(meta_cwd, str) and meta_cwd:
                        cwd = Path(meta_cwd)
                if cache is not None:
                    cache.log_by_pid[pid] = (log_file, session_id)
                    cache.cwd_by_pid[pid] = cwd
                    if agent_type == "claude-code":
                        cache.claude_session_by_pid[pid] = (
                            claude_record.session_id if claude_record else None
                        )

            # Without a rollout cwd, the app-server's cwd is its own bin\<hash>
            # dir: no project (#94). The cache keeps that cwd for resolve_log.
            project: Path | None = cwd
            if agent_type == "codex" and _is_program_dir(cwd, cmdline, name):
                project = None

            agents.append(
                AgentProcess(
                    pid=pid,
                    agent_type=agent_type,
                    working_directory=project,
                    log_file=log_file,
                    session_id=session_id,
                    cpu_percent=cpu_percent,
                    memory_mb=memory_mb,
                    uptime=etime,
                    command=command,
                    parent_pid=ppid,
                )
            )
            if app_server and log_file is not None:
                agents[-1:] = _codex_app_server_threads(agents[-1])

    _assign_claude_logs(agents, claude_started, claude_registered)

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
    # like any other rootless agent. Editor-kind adapters (Cursor, ...) do
    # their own discovery; adapters import cursor_discovery lazily to avoid
    # a module-load-time cycle (it imports AgentProcess from this module).
    for editor in _agents.editor_adapters():
        try:
            agents.extend(editor.discover())
        except Exception:
            # One broken editor integration must not hide the others.
            logger.debug("discover failed for adapter %s", editor.name, exc_info=True)
            continue

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


def _claude_home() -> Path:
    return Path.home() / ".claude"


def _claude_project_dir(cwd: Path) -> Path:
    """Where Claude Code keeps the transcripts of sessions started in *cwd*."""
    return _claude_home() / "projects" / encode_path_for_claude(cwd)


@dataclass(frozen=True)
class _ClaudeSessionRecord:
    """A live Claude Code process's entry in ``~/.claude/sessions/<pid>.json``."""

    session_id: str | None  # None: the record exists but names no readable session
    cwd: Path | None = None


# Claude Code's own reader of these records stops at 256 KiB.
_SESSION_RECORD_MAX_BYTES = 256 * 1024
_SAFE_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
# `ps -o lstart` has one-second resolution.
_LSTART_TOLERANCE_S = 2.0
# startedAt is the wall clock when the record was written, a little after the
# process started; allow for clock steps between the two readings.
_STARTED_AT_SLACK_S = 30.0
_MONTHS = {
    m: i for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}


def _parse_lstart(value: object) -> float | None:
    """Epoch seconds from ``LC_ALL=C TZ=UTC ps -o lstart=`` text, e.g.
    ``"Sat Oct 24 00:32:05 2026"``. Parsed by hand: ``strptime``'s ``%a``/``%b``
    follow the current locale, the text does not."""
    if not isinstance(value, str):
        return None
    parts = value.split()
    if len(parts) != 5:
        return None
    _, month, day, hms, year = parts
    try:
        hour, minute, second = (int(x) for x in hms.split(":"))
        return datetime(
            int(year), _MONTHS[month], int(day), hour, minute, second, tzinfo=timezone.utc
        ).timestamp()
    except (KeyError, ValueError):
        return None


def _record_started_with(record: dict, create_time: float) -> bool:
    """Whether a session record was written by the process started at *create_time*.

    Records are deleted on exit, but one left by a crash can name a pid the OS
    has since given to another process. ``procStart`` is the process's own
    start time (POSIX); Windows records have only ``startedAt``, written just
    after start, so a record older than the process belongs to an earlier one.
    """
    started = _parse_lstart(record.get("procStart"))
    if started is not None:
        return abs(started - create_time) <= _LSTART_TOLERANCE_S
    started_at = record.get("startedAt")
    if isinstance(started_at, (int, float)) and not isinstance(started_at, bool):
        return started_at > 0 and started_at / 1000 >= create_time - _STARTED_AT_SLACK_S
    return False


def _read_claude_session_record(
    pid: int, create_time: float | None
) -> _ClaudeSessionRecord | None:
    """The live-session record Claude Code keeps for *pid*, or ``None``.

    Claude Code (2.1.x) writes ``~/.claude/sessions/<pid>.json`` when a
    session starts (``pid``, ``sessionId``, ``cwd``, ``startedAt``,
    ``procStart`` and more), rewrites ``sessionId`` in place when the
    conversation changes (/clear, /resume) and deletes the file on exit.
    ``None`` means the process has no record of its own: none on disk, or a
    stale one from an earlier process with the same pid. A record that is
    present but unreadable (caught mid-rewrite) comes back with
    ``session_id=None``. Only these few fields are read.
    """
    path = _claude_home() / "sessions" / f"{pid}.json"
    try:
        with open(path, "rb") as f:
            raw = f.read(_SESSION_RECORD_MAX_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError:
        return _ClaudeSessionRecord(session_id=None)
    try:
        record = json.loads(raw) if len(raw) <= _SESSION_RECORD_MAX_BYTES else None
    except ValueError:
        record = None
    if not isinstance(record, dict):
        return _ClaudeSessionRecord(session_id=None)
    if record.get("pid", pid) != pid:
        return None
    if create_time is not None and not _record_started_with(record, create_time):
        return None
    session_id = record.get("sessionId")
    if not isinstance(session_id, str) or not _SAFE_SESSION_ID.fullmatch(session_id):
        session_id = None
    cwd = record.get("cwd")
    return _ClaudeSessionRecord(
        session_id=session_id,
        cwd=Path(cwd) if isinstance(cwd, str) and cwd not in ("", "?") else None,
    )


def _claude_cache_current(
    cache: DiscoveryCache, pid: int, record: _ClaudeSessionRecord | None
) -> bool:
    """Whether a Claude Code pid's cached log was resolved for its current session."""
    if record is not None and record.session_id is None:
        return True  # unreadable this scan: keep what we had
    current = record.session_id if record is not None else None
    return cache.claude_session_by_pid.get(pid) == current


def _process_create_time(pid: int) -> float | None:
    try:
        return psutil.Process(pid).create_time()
    except psutil.Error:
        return None


def _find_claude_transcript(session_id: str, project_dirs: list[Path]) -> Path | None:
    """The ``<session_id>.jsonl`` transcript, looked for in *project_dirs* first."""
    for project_dir in project_dirs:
        path = project_dir / f"{session_id}.jsonl"
        if path.is_file():
            return path
    # A resumed session keeps writing to the project dir it began in, which
    # need not match the process's cwd. session_id has no glob characters.
    projects = _claude_home() / "projects"
    return next((p for p in projects.glob(f"*/{session_id}.jsonl") if p.is_file()), None)


def _newest_claude_log(
    project_dir: Path,
    claimed: set[Path] | frozenset[Path] = frozenset(),
    claimed_sessions: set[str] | frozenset[str] = frozenset(),
    since: float | None = None,
) -> Path | None:
    """The most recently modified transcript in *project_dir*, skipping
    *claimed* paths and session ids, and any last written before *since*."""
    newest, newest_mtime = None, 0.0
    for path in project_dir.glob("*.jsonl"):
        if path in claimed or path.stem in claimed_sessions:
            continue
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if since is not None and mtime < since:
            continue
        if newest is None or mtime > newest_mtime:
            newest, newest_mtime = path, mtime
    return newest


def _claude_session_id(log_file: Path) -> str:
    """Session id of a transcript: its file name, unless sessions-index.json maps it."""
    session_id = log_file.stem
    index_file = log_file.parent / "sessions-index.json"
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
    return session_id


def _resolve_claude_code_log(
    cwd: Path, pid: int | None = None
) -> tuple[Path | None, str | None]:
    """Resolve the Claude Code session log of process *pid* running in *cwd*.

    With *pid*, only signals that name that process's own session count:

    1. the ``.jsonl`` the process holds open (``_find_open_jsonl``). Claude
       Code appends to its transcript without keeping it open, so this
       rarely matches, but it is exact when it does;
    2. its live-session record (``_read_claude_session_record``), whose
       ``sessionId`` names the transcript.

    No match gives no log, never another session's: several processes can
    share one project dir. ``find_running_agents()`` (``_assign_claude_logs``)
    decides whether a process with no record can still take the newest
    unclaimed log. Without *pid* there is no process to match, so this is
    the most recently modified log in the project dir.
    """
    project_dir = _claude_project_dir(cwd)

    if pid is None:
        log_file = _newest_claude_log(project_dir)
        return (log_file, _claude_session_id(log_file)) if log_file else (None, None)

    if project_dir.is_dir():
        log_file = _find_open_jsonl(pid, project_dir)
        if log_file is not None:
            return log_file, _claude_session_id(log_file)

    record = _read_claude_session_record(pid, _process_create_time(pid))
    if record is None or record.session_id is None:
        return None, None
    project_dirs = [project_dir]
    if record.cwd is not None:
        project_dirs.append(_claude_project_dir(record.cwd))
    return _find_claude_transcript(record.session_id, project_dirs), record.session_id


def _assign_claude_logs(
    agents: list[AgentProcess],
    started: dict[int, float | None],
    registered: set[int],
) -> None:
    """Make the Claude Code process -> session log mapping one-to-one.

    *started* holds the start time of every Claude Code process in *agents*;
    *registered* the pids with a live-session record.

    1. Two processes resolved to the same session (both records name it, as
       when one takes a session over from another) never share it: the
       newest process keeps it, the other is left unresolved.
    2. A process with no record and no open log (older Claude Code, or a mode
       that does not write one) gets the newest log in its project dir only
       if nothing else can own it: no other process claims it, it was written
       after this process started, and no other such process shares the dir.
       Otherwise it stays unresolved.
    """
    claude = [a for a in agents if a.agent_type == "claude-code" and a.pid in started]

    seen_logs: set[Path] = set()
    seen_sessions: set[str] = set()
    displaced: set[int] = set()
    for agent in sorted(claude, key=lambda a: (started[a.pid] or 0.0, a.pid), reverse=True):
        if (agent.log_file is not None and agent.log_file in seen_logs) or (
            agent.session_id is not None and agent.session_id in seen_sessions
        ):
            agent.log_file = agent.session_id = None
            displaced.add(agent.pid)
            continue
        if agent.log_file is not None:
            seen_logs.add(agent.log_file)
        if agent.session_id is not None:
            seen_sessions.add(agent.session_id)

    unmatched: dict[Path, list[AgentProcess]] = {}
    for agent in claude:
        if (
            agent.log_file is None
            and agent.pid not in registered
            and agent.pid not in displaced
            and agent.working_directory is not None
        ):
            unmatched.setdefault(_claude_project_dir(agent.working_directory), []).append(agent)

    claimed = {a.log_file for a in agents if a.log_file is not None}
    for project_dir, group in unmatched.items():
        if len(group) != 1:
            continue  # cannot tell whose log is whose
        agent = group[0]
        since = started[agent.pid]
        log_file = _newest_claude_log(
            project_dir,
            claimed=claimed,
            claimed_sessions=seen_sessions,
            since=since - _LSTART_TOLERANCE_S if since else None,
        )
        if log_file is not None:
            agent.log_file, agent.session_id = log_file, _claude_session_id(log_file)
            claimed.add(log_file)


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
    """The most recently written rollout a Codex PID has open, or ``None``."""
    return next(iter(_find_open_codex_rollouts(pid, sessions_root)), None)


def _find_open_codex_rollouts(pid: int, sessions_root: Path) -> list[Path]:
    """Every ``rollout-*.jsonl`` file under *sessions_root* a specific
    Codex PID has open, most recently written first.

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
        return []

    # The ChatGPT desktop app-server serves every thread from one PID and
    # holds one rollout open per loaded thread (see _codex_app_server_threads).
    sessions_root = sessions_root.resolve()
    found: dict[Path, float] = {}
    for f in open_files:
        path = Path(f.path)
        if path.suffix != ".jsonl" or not path.name.startswith("rollout-"):
            continue
        try:
            path.resolve().relative_to(sessions_root)
            mtime = path.stat().st_mtime
        except (ValueError, OSError):
            continue
        found[path] = mtime
    return sorted(found, key=found.__getitem__, reverse=True)


def _codex_sessions_root() -> Path:
    codex_home_env = os.environ.get("CODEX_HOME")
    codex_home = Path(codex_home_env) if codex_home_env else (Path.home() / ".codex")
    return codex_home / "sessions"


def _codex_app_server_threads(primary: AgentProcess) -> list[AgentProcess]:
    """One entry per rollout a Codex app-server holds open (#105).

    The app-server keeps one live recorder per loaded thread, and each
    recorder's writer task holds its rollout file open until the thread is
    shut down (openai/codex @ 6f47fcb0bea40155ba00a352fd833c2df2738076:
    ``codex-rs/thread-store/src/local/mod.rs`` L149 ``live_recorders:
    HashMap<ThreadId, LiveRecorderEntry>``; ``codex-rs/rollout/src/recorder.rs``
    L1790-1800 ``RolloutWriterState.writer``, L1880-1891 ``ensure_writer_open``
    keeps the handle, L996-998 resume opens it at once, L984-985 a new thread
    defers it to first materialization; ``thread-store/src/local/
    live_writer.rs`` L169-207 ``shutdown_thread`` drops it). So open_files()
    lists exactly the loaded, materialized threads.

    Every thread gets a stable synthetic CRC32 pid like Cursor composers: pid
    keys team/depth assignment and the multi-agent TUI's per-pid report maps,
    which the TUI stores once per row, so a shared real pid (or one that
    moves to whichever thread is newest) would collide. ``parent_pid`` stays
    the app-server's real PPID. With no open rollout, *primary*'s fallback
    log gets the same treatment.
    """
    from agentwatch.cursor_discovery import _synthetic_pid

    paths = _find_open_codex_rollouts(primary.pid, _codex_sessions_root())
    threads = []
    for path in paths or [primary.log_file]:
        meta = _read_codex_session_meta(path) or {}
        session_id = meta.get("session_id") or meta.get("id")
        cwd = meta.get("cwd")
        threads.append(replace(
            primary,
            pid=_synthetic_pid(session_id or str(path)),
            log_file=path,
            session_id=session_id,
            working_directory=Path(cwd) if isinstance(cwd, str) and cwd else None,
        ))
    return threads


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
    instead of ``~/.codex``). **PRD Open Question #2 — RESOLVED, comma-
    separated multi-root support does NOT exist.** Checked two primary
    sources directly (2026-07-15):
      - ``developers.openai.com/codex/environment-variables`` (redirects to
        ``learn.chatgpt.com/docs/config-file/environment-variables``)
        documents ``CODEX_HOME`` as: "Sets the root for Codex state,
        including config, auth, logs, sessions, skills, and standalone
        package metadata. If you set it, the directory must already
        exist." — singular "the directory", no mention of a list or
        multiple roots.
      - ``codex-rs/utils/home-dir/src/lib.rs`` (github.com/openai/codex
        @ main, ``find_codex_home_from_env``) reads ``CODEX_HOME`` via a
        single ``std::env::var("CODEX_HOME")`` call, wraps the raw value in
        one ``PathBuf::from(val)`` with no delimiter-splitting anywhere,
        and ``std::fs::metadata`` + ``is_dir()``-checks that *one* path,
        erroring (``NotFound``/``InvalidInput``) if it isn't a single
        existing directory. There is no code path that could parse a
        comma-separated (or any other multi-value) string.
    This implementation's single-root handling is therefore not a
    conservative subset of a richer real feature — it now matches Codex's
    actual, confirmed behavior exactly. No multi-root implementation is
    needed here.

    NOTE: per openai/codex issue #21660, rollout files are created
    world-readable (``0o666 & ~umask``) on Unix rather than the tighter
    ``0o600`` one might expect for a file containing full conversation
    content — this is Codex's own permission looseness, not something
    AgentWatch introduces or needs to work around.
    """
    sessions_root = _codex_sessions_root()
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
