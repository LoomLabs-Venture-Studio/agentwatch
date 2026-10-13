"""Cline adapter (editor-kind). Two task stores; see ``parser/cline.py`` and
``docs/superpowers/specs/2026-10-12-cline-adapter-design.md``.

- Legacy VS Code extension: ``<VS Code User>/globalStorage/
  saoudrizwan.claude-dev/tasks/<id>/api_conversation_history.json``. VS Code
  stable only (other editors: #116).
- SDK store, shared by the new VS Code extension, the Cline CLI, JetBrains
  and Cline desktop: ``~/.cline/data/sessions/<id>/``. The manifest's
  ``source`` tells them apart.

Fixture-verified only: no live Cline install (board decision, #104).
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import psutil

from .base import BaseAdapter, Watcher, source_path
from .copilot_vscode import COPILOT_VSCODE_ACTIVE_WINDOW_S, _vscode_running

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action


LEGACY_EXTENSION_ID = "saoudrizwan.claude-dev"
# Non-terminal session statuses: cline/cline main @ a484089
# sdk/packages/core/src/types/common.ts:7-11.
_LIVE_STATUSES = ("idle", "running", "pending")


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def cline_sessions_dir() -> Path:
    """Cline's resolveSessionDataDir / resolveClineDataDir / resolveClineDir
    (cline/cline main @ a484089 ``sdk/packages/shared/src/storage/paths.ts:
    158-167``, ``186-200``), read from agentwatch's own environment."""
    if _env("CLINE_SESSION_DATA_DIR"):
        return Path(_env("CLINE_SESSION_DATA_DIR"))
    if _env("CLINE_DATA_DIR"):
        return Path(_env("CLINE_DATA_DIR")) / "sessions"
    return Path(_env("CLINE_DIR") or Path.home() / ".cline") / "data" / "sessions"


def _recent(path: Path, now: float) -> bool:
    try:
        return now - path.stat().st_mtime <= COPILOT_VSCODE_ACTIVE_WINDOW_S
    except OSError:
        return False


def _read_json(path: Path) -> Any:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _storage_owner(path: Path) -> str | None:
    """``<ext-id>`` of a ``.../globalStorage/<ext-id>/tasks/<id>/<file>`` path,
    else None. Cline forks (Roo Code #117, Kilo Code #118) use the same file
    names under their own extension id."""
    p = path.parents
    if len(p) > 3 and p[1].name == "tasks" and p[3].name.lower() == "globalstorage":
        return p[2].name.lower()
    return None


def _legacy_agents(user_dir: Path, now: float) -> list[AgentProcess]:
    from agentwatch.cursor_discovery import _synthetic_pid
    from agentwatch.discovery import AgentProcess

    root = user_dir / "globalStorage" / LEGACY_EXTENSION_ID
    cwds: dict[str, str] | None = None
    agents = []
    for log in (root / "tasks").glob("*/api_conversation_history.json"):
        if not _recent(log, now):
            continue
        if cwds is None:  # state/taskHistory.json: HistoryItem[] (L shared/HistoryItem.ts)
            history = _read_json(root / "state" / "taskHistory.json")
            cwds = {
                h["id"]: h["cwdOnTaskInitialization"]
                for h in (history if isinstance(history, list) else [])
                if isinstance(h, dict) and isinstance(h.get("id"), str)
                and isinstance(h.get("cwdOnTaskInitialization"), str)
            }
        task_id = log.parent.name
        cwd = cwds.get(task_id)
        agents.append(AgentProcess(
            pid=_synthetic_pid(task_id),
            agent_type="cline",
            working_directory=Path(cwd) if cwd else None,
            log_file=log,
            session_id=task_id,
            command="vscode (cline)",
        ))
    return agents


def _sdk_agents(sessions: Path, now: float) -> list[AgentProcess]:
    from agentwatch.cursor_discovery import _synthetic_pid
    from agentwatch.discovery import AgentProcess, _format_etime

    agents = []
    for manifest in sessions.glob("*/*.json"):
        sid = manifest.parent.name
        if manifest.stem != sid:  # root manifest only, not messages/compaction/subagents
            continue
        data = _read_json(manifest)
        if not isinstance(data, dict) or data.get("status") not in _LIVE_STATUSES:
            continue
        # Cline's own rule: a non-terminal session whose pid is dead is over
        # (N core/src/session/services/persistence-service.ts:430-445).
        pid = data.get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or not psutil.pid_exists(pid):
            continue
        # Not the manifest's absolute messages_path: stay inside the sessions dir.
        log = manifest.parent / f"{sid}.messages.json"
        if not _recent(log, now):  # an idle session in a still-open host stays "idle"
            continue
        uptime = ""
        try:
            uptime = _format_etime(now - datetime.fromisoformat(data["started_at"]).timestamp())
        except (KeyError, TypeError, ValueError):
            pass
        cwd = data.get("cwd")
        agents.append(AgentProcess(
            pid=_synthetic_pid(sid),  # sessions share one host pid; keys must be unique
            agent_type="cline",
            working_directory=Path(cwd) if isinstance(cwd, str) and cwd else None,
            log_file=log,
            session_id=sid,
            uptime=uptime,
            command=f"cline ({data.get('source') or 'sdk'})",
        ))
    return agents


def find_cline_agents(
    *,
    user_dir: Path | None = None,
    sessions_dir: Path | None = None,
    require_running: bool = True,
    now: float | None = None,
) -> list[AgentProcess]:
    """Recent Cline tasks from both stores, one entry per task. Never raises."""
    now = time.time() if now is None else now
    agents: list[AgentProcess] = []
    try:
        if not require_running or _vscode_running():
            from agentwatch.vscode_paths import default_user_dir

            agents += _legacy_agents(user_dir or default_user_dir("Code"), now)
    except Exception:
        pass
    try:
        agents += _sdk_agents(sessions_dir or cline_sessions_dir(), now)
    except Exception:
        pass
    return agents


class ClineAdapter(BaseAdapter):
    name = "cline"
    kind = "editor"

    def discover(self) -> list[AgentProcess]:
        return find_cline_agents()

    def claims(self, path: Path) -> bool:
        if path.name == "api_conversation_history.json":
            # Outside globalStorage (e.g. a copied file) there is no owner to check.
            return _storage_owner(path) in (None, LEGACY_EXTENSION_ID)
        if not path.name.endswith(".messages.json"):
            return False
        from agentwatch.parser.cline import load

        loaded = load(path)
        return loaded is not None and loaded[1]

    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher:
        from agentwatch.parser.watcher import ClineWatcher

        return ClineWatcher(source_path(source), session_id=session_id)

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        from agentwatch.parser.cline import parse_cline

        yield from parse_cline(path, session_id)
