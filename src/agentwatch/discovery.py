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

    @property
    def project_name(self) -> str:
        """Extract project name from working directory."""
        return self.working_directory.name


def find_running_agents() -> list[AgentProcess]:
    """Discover running AI agent processes on the local machine.

    Uses `ps aux` to find processes matching known agent patterns,
    then `lsof -a -d cwd -p <PID>` to resolve each process's
    working directory.
    """
    try:
        result = subprocess.run(
            ["ps", "aux"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    if result.returncode != 0:
        return []

    agents: list[AgentProcess] = []
    seen_pids: set[int] = set()

    for line in result.stdout.strip().splitlines()[1:]:  # skip header
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue

        user, pid_str, cpu, mem, vsz, rss, tty, stat, start, time_str, command = parts

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
                log_file, session_id = _resolve_claude_code_log(cwd)
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
                    uptime=time_str,
                    command=command,
                )
            )

    return agents


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


def _resolve_claude_code_log(cwd: Path) -> tuple[Path | None, str | None]:
    """Resolve the active Claude Code session log for a working directory.

    Converts CWD to ~/.claude/projects/<encoded-path>/ and finds the
    most recently modified .jsonl file. Also reads sessions-index.json
    for metadata.
    """
    encoded = _encode_path_for_claude(cwd)
    project_dir = Path.home() / ".claude" / "projects" / encoded

    if not project_dir.is_dir():
        return None, None

    # Find the most recently modified .jsonl file
    jsonl_files = list(project_dir.glob("*.jsonl"))
    if not jsonl_files:
        return None, None

    latest_log = max(jsonl_files, key=lambda f: f.stat().st_mtime)
    session_id = latest_log.stem

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

    return latest_log, session_id


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
