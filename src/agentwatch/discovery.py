"""Process-based discovery of running AI agent processes."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


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


def find_running_agents() -> list[AgentProcess]:
    """Discover running AI agent processes on the local machine.

    Uses ``ps -eo`` to find processes matching known agent patterns
    (including PPID for subagent detection), then ``lsof`` to resolve
    each process's working directory.
    """
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,ppid,%cpu,rss,etime,args"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    if result.returncode != 0:
        return []

    lines = result.stdout.strip().splitlines()[1:]  # skip header

    # First pass: build complete PID -> PPID map for ancestor walking
    pid_to_ppid: dict[int, int] = {}
    for line in lines:
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        try:
            pid_to_ppid[int(parts[0])] = int(parts[1])
        except ValueError:
            continue

    # Second pass: find agent processes
    agents: list[AgentProcess] = []
    seen_pids: set[int] = set()

    for line in lines:
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue

        pid_str, ppid_str, cpu, rss, etime, command = parts

        for agent_type, config in AGENT_PATTERNS.items():
            pattern = config["pattern"]
            exclude = config["exclude"]

            if not re.search(pattern, command):
                continue
            if exclude and re.search(exclude, command):
                continue

            try:
                pid = int(pid_str)
            except ValueError:
                continue

            if pid in seen_pids:
                continue
            seen_pids.add(pid)

            try:
                ppid = int(ppid_str)
            except ValueError:
                ppid = None

            # Parse memory: RSS is in KB
            try:
                memory_mb = float(rss) / 1024.0
            except ValueError:
                memory_mb = 0.0

            try:
                cpu_percent = float(cpu)
            except ValueError:
                cpu_percent = 0.0

            # Get working directory via lsof
            cwd = _get_process_cwd(pid)
            if cwd is None:
                continue

            # Resolve log file based on agent type
            log_file = None
            session_id = None
            if agent_type == "claude-code":
                log_file, session_id = _resolve_claude_code_log(cwd, pid=pid)
            elif agent_type == "aider":
                log_file, session_id = _resolve_aider_log(cwd)

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

    _compute_depths(agents)
    _assign_team_ids(agents)

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
    """Get the current working directory of a process using lsof."""
    try:
        result = subprocess.run(
            ["lsof", "-a", "-d", "cwd", "-p", str(pid), "-Fn"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    if result.returncode != 0:
        return None

    # lsof -Fn outputs lines like:
    # p<PID>
    # n<path>
    for line in result.stdout.strip().splitlines():
        if line.startswith("n") and line != "n":
            path = Path(line[1:])
            if path.is_dir():
                return path

    return None


def _encode_path_for_claude(path: Path) -> str:
    """Encode a filesystem path to Claude Code's project directory format.

    Claude Code encodes paths by replacing `/` with `-`.
    e.g., /Users/zaid/Projects/agentwatch -> -Users-zaid-Projects-agentwatch
    """
    return str(path).replace("/", "-")


def _find_open_jsonl(pid: int, project_dir: Path) -> Path | None:
    """Use lsof to find which .jsonl file a specific PID has open."""
    try:
        result = subprocess.run(
            ["lsof", "-a", "-p", str(pid), "-Fn", "+D", str(project_dir)],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    if result.returncode != 0:
        return None

    for line in result.stdout.strip().splitlines():
        if line.startswith("n") and line.endswith(".jsonl"):
            path = Path(line[1:])
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
    encoded = _encode_path_for_claude(cwd)
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

    Looks for .aider.chat.history.md or .aider/logs/ patterns.
    """
    # Check for chat history file
    history_file = cwd / ".aider.chat.history.md"
    if history_file.exists():
        return history_file, None

    # Check for logs directory
    logs_dir = cwd / ".aider" / "logs"
    if logs_dir.is_dir():
        log_files = sorted(logs_dir.iterdir(), key=lambda f: f.stat().st_mtime)
        if log_files:
            return log_files[-1], None

    return None, None
