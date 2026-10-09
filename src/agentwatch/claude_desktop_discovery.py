"""App-gated discovery of Claude Desktop Cowork (local agent mode) sessions.

Cowork sessions have no per-session host process we can map to a log, so
like Cursor this gates on the desktop app running and then reads session
metadata from disk: ``local-agent-mode-sessions/<a>/<b>/local_<id>.json``
plus the Claude Code JSONL transcript at
``local_<id>/.claude/projects/*/<cliSessionId>.jsonl``. The transcript is
found by ``cliSessionId`` (never by mtime: a projects dir can hold other
``.jsonl`` files) and is parsed by the claude-code adapter unchanged.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import psutil

from .cursor_discovery import _synthetic_pid
from .discovery import AgentProcess

# ponytail: fixed 30 min window, make it a CLI option if users need it
ACTIVITY_WINDOW_SECONDS = 1800

# Exact, case-sensitive: lowercase claude.exe is Claude Code, and
# cowork-svc.exe is a Windows service that runs with the app closed.
_APP_PROCESS_NAMES = {"Claude.exe", "Claude"}


def claude_desktop_roots() -> list[Path]:
    """Claude Desktop data roots that hold ``local-agent-mode-sessions/``.

    Windows MSIX (``%LOCALAPPDATA%\\Packages\\Claude_*\\LocalCache\\Roaming\\
    Claude``) is verified against a real install; ``%APPDATA%\\Claude``
    (non-Store Windows) and ``~/Library/Application Support/Claude`` (macOS)
    are unverified.
    """
    candidates: list[Path] = []
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            candidates += sorted(
                (Path(local) / "Packages").glob("Claude_*/LocalCache/Roaming/Claude")
            )
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(Path(appdata) / "Claude")
    elif sys.platform == "darwin":
        candidates.append(Path.home() / "Library" / "Application Support" / "Claude")
    return [r for r in candidates if (r / "local-agent-mode-sessions").is_dir()]


def is_claude_desktop_running() -> bool:
    """Check whether the Claude Desktop app (not Claude Code) is running."""
    try:
        for proc in psutil.process_iter(attrs=["name"]):
            try:
                name = proc.info.get("name") or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            if name in _APP_PROCESS_NAMES:
                return True
    except Exception:
        return False
    return False


def find_claude_desktop_agents(now: float | None = None) -> list[AgentProcess]:
    """Recently active, non-archived Cowork sessions as synthetic AgentProcesses.

    Never raises: a bad metadata file or missing transcript skips that session.
    """
    if not is_claude_desktop_running():
        return []
    now = time.time() if now is None else now

    agents: list[AgentProcess] = []
    for root in claude_desktop_roots():
        for meta_path in (root / "local-agent-mode-sessions").glob("*/*/local_*.json"):
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8", errors="ignore"))
                cli_id = meta["cliSessionId"]
                cwd = meta["cwd"]
                last_ms = meta["lastActivityAt"]
                if (
                    meta.get("isArchived")
                    or not isinstance(cli_id, str)
                    or not isinstance(cwd, str)
                    or not isinstance(last_ms, (int, float))
                    or now - last_ms / 1000 > ACTIVITY_WINDOW_SECONDS
                ):
                    continue
            except (OSError, ValueError, KeyError, TypeError):
                continue
            projects = meta_path.with_suffix("") / ".claude" / "projects"
            transcript = next(projects.glob(f"*/{cli_id}.jsonl"), None)
            if transcript is None:
                continue
            agents.append(
                AgentProcess(
                    pid=_synthetic_pid(meta_path.stem),
                    agent_type="claude-desktop",
                    working_directory=Path(cwd),
                    log_file=transcript,
                    session_id=cli_id,
                    command="Claude Desktop (Cowork)",
                )
            )
    return agents
