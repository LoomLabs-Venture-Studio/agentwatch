"""GitHub Copilot in VS Code adapter (editor-kind: chats live inside VS Code,
one mutation-log ``.jsonl`` per session; see ``parser/copilot_vscode.py``)."""

from __future__ import annotations

import re
import time
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import psutil

from .base import BaseAdapter, Watcher, sniff_jsonl_format, source_path

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action


# VS Code keeps every old chat; only recently written sessions count as live.
COPILOT_VSCODE_ACTIVE_WINDOW_S = 1800
# Windows Code.exe, Linux code. The macOS process name is unverified.
_CODE_PROCESS_RE = re.compile(r"^code(\.exe)?$", re.IGNORECASE)


def _vscode_running() -> bool:
    try:
        return any(
            _CODE_PROCESS_RE.match(p.info.get("name") or "")
            for p in psutil.process_iter(attrs=["name"])
        )
    except Exception:
        return False


def find_copilot_vscode_agents(
    *, user_dir: Path | None = None, require_running: bool = True, now: float | None = None
) -> list[AgentProcess]:
    """Recent Copilot chat sessions of a running VS Code, one entry per session.

    ``log_file`` is the session's real ``.jsonl``; ``pid`` is synthetic (the
    IDE, not a per-session process, hosts the chat). Sessions in an
    unresolvable workspace (empty window) or with no requests are skipped.
    Never raises.
    """
    try:
        if require_running and not _vscode_running():
            return []
        from agentwatch.cursor_discovery import _synthetic_pid, build_workspace_map
        from agentwatch.discovery import AgentProcess, _format_etime
        from agentwatch.parser.copilot_vscode import replay
        from agentwatch.vscode_paths import default_user_dir

        user_dir = user_dir or default_user_dir("Code")
        now = time.time() if now is None else now
        workspaces: dict[str, Path] | None = None
        agents: list[AgentProcess] = []
        for log in (user_dir / "workspaceStorage").glob("*/chatSessions/*.jsonl"):
            try:
                if now - log.stat().st_mtime > COPILOT_VSCODE_ACTIVE_WINDOW_S:
                    continue
            except OSError:
                continue
            if workspaces is None:
                workspaces = build_workspace_map(user_dir)
            cwd = workspaces.get(log.parent.parent.name)
            if cwd is None:
                continue
            state = replay(log)
            if not state or not state.get("requests"):
                continue
            created = state.get("creationDate")
            agents.append(AgentProcess(
                pid=_synthetic_pid(log.stem),
                agent_type="copilot-vscode",
                working_directory=cwd,
                log_file=log,
                session_id=log.stem,
                uptime=_format_etime(now - created / 1000)
                if isinstance(created, (int, float)) else "",
                command="vscode (copilot)",
            ))
        return agents
    except Exception:
        return []


class CopilotVscodeAdapter(BaseAdapter):
    name = "copilot-vscode"
    kind = "editor"

    def discover(self) -> list[AgentProcess]:
        return find_copilot_vscode_agents()

    def claims(self, path: Path) -> bool:
        return path.suffix == ".jsonl" and sniff_jsonl_format(path) == "copilot_vscode"

    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher:
        from agentwatch.parser.watcher import CopilotVscodeWatcher

        return CopilotVscodeWatcher(source_path(source), session_id=session_id)

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        from agentwatch.parser.copilot_vscode import parse_copilot_vscode

        yield from parse_copilot_vscode(path, session_id)
