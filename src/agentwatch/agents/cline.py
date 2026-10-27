"""Cline adapter (editor-kind). Two task stores; see ``parser/cline.py`` and
``docs/superpowers/specs/2026-10-12-cline-adapter-design.md``.

- Legacy VS Code extension: ``<VS Code User>/globalStorage/
  saoudrizwan.claude-dev/tasks/<id>/api_conversation_history.json``, read
  from each editor in ``_legacy_editors()`` whose process is running (#116).
- SDK store, shared by the new VS Code extension, the Cline CLI, JetBrains
  and Cline desktop: ``~/.cline/data/sessions/<id>/``. The manifest's
  ``source`` tells them apart.

Fixture-verified only: no live Cline install (board decision, #104).
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import psutil

from .base import BaseAdapter, Watcher, folder_name, source_path
from .copilot_vscode import _CODE_PROCESS_RE, COPILOT_VSCODE_ACTIVE_WINDOW_S

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action


LEGACY_EXTENSION_ID = "saoudrizwan.claude-dev"
# Non-terminal session statuses: cline/cline main @ a484089
# sdk/packages/core/src/types/common.ts:7-11.
_LIVE_STATUSES = ("idle", "running", "pending")


def _legacy_editors() -> tuple[tuple[str, str, re.Pattern[str]], ...]:
    """(label, User-data folder, main-process regex) per editor (#116).
    Folder = product ``nameShort`` fed to VS Code's getDefaultUserDataPath
    (microsoft/vscode @ 1985b99 src/main.ts:60). Source-verified, not live:
    - Code - Insiders: vscode-docs @ 78bab45 docs/configure/profiles.md:413;
      exes ``Code - Insiders.exe``/``code-insiders``/``Code - Insiders``
      (microsoft/vscode-test @ d661ec1 lib/util.ts:156-162, 170-172).
    - VSCodium: VSCodium/vscodium @ f33df00 prepare_vscode.sh:96-98,
      docs/migration.md:22-24; ``VSCodium.exe`` (docs/troubleshooting.md:142),
      ``codium`` (linuxExecutableName = applicationName, vscode build/lib/
      electron.ts:239), macOS ``VSCodium`` (darwinExecutable = nameShort, :148).
    - Cursor: see cursor_discovery.default_cursor_user_dir.
    Windsurf is left out: no public source for its User folder (#116)."""
    from agentwatch.cursor_discovery import _CURSOR_PROCESS_RE  # lazy: import cycle

    return (
        ("vscode", "Code", _CODE_PROCESS_RE),
        ("vscode-insiders", "Code - Insiders",
         re.compile(r"^code(-| - )insiders(\.exe)?$", re.IGNORECASE)),
        ("vscodium", "VSCodium", re.compile(r"^(vs)?codium(\.exe)?$", re.IGNORECASE)),
        ("cursor", "Cursor", _CURSOR_PROCESS_RE),
    )


def _running_editors() -> set[str]:
    """Labels of ``_legacy_editors()`` with a live process; empty on error."""
    try:
        names = {p.info.get("name") or "" for p in psutil.process_iter(attrs=["name"])}
    except Exception:
        return set()
    return {label for label, _, rx in _legacy_editors() if any(rx.match(n) for n in names)}


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
    # Resolve a relative tasks/<id>/<file> so it still has an owner.
    p = (path if path.is_absolute() else path.absolute()).parents
    if len(p) > 3 and p[1].name == "tasks" and p[3].name.lower() == "globalstorage":
        return p[2].name.lower()
    return None


def _legacy_agents(user_dir: Path, now: float, editor: str = "vscode") -> list[AgentProcess]:
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
            # Editor in the seed so one task id under two editors can't collide;
            # not for stable, whose pids predate #116.
            pid=_synthetic_pid(task_id if editor == "vscode" else f"{editor}:{task_id}"),
            agent_type="cline",
            working_directory=Path(cwd) if cwd else None,
            log_file=log,
            session_id=task_id,
            command=f"{editor} (cline)",
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
    """Recent Cline tasks from both stores, one entry per task. Never raises.
    *user_dir* overrides the legacy store with one VS Code stable User dir."""
    now = time.time() if now is None else now
    agents: list[AgentProcess] = []
    try:
        from agentwatch.vscode_paths import default_user_dir

        running = _running_editors() if require_running else None
        for label, folder, _ in _legacy_editors():
            if (user_dir is not None and label != "vscode") or (
                running is not None and label not in running
            ):
                continue
            try:
                agents += _legacy_agents(user_dir or default_user_dir(folder), now, label)
            except Exception:
                pass
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
            owner = _storage_owner(path)
            if owner is not None:
                return owner == LEGACY_EXTENSION_ID
            # No owner (a copy, or a fork's customStoragePath store). Roo Code
            # >= 3.49.0 writes history_item.json beside every task file
            # (RooCodeInc/Roo-Code @ b867ec9 src/shared/globalFileNames.ts:7,
            # core/task-persistence/TaskHistoryStore.ts:160-170, 551-563);
            # Cline never does (cline/cline GlobalFileNames, v3.20.0..main).
            # ponytail: Kilo 5.x and Roo < 3.49 have no such marker, still read as Cline.
            return not os.path.exists(path.with_name("history_item.json"))  # never raises
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

    def history_logs(self) -> Iterator[Path]:
        from agentwatch.vscode_paths import default_user_dir

        for _, folder, _ in _legacy_editors():
            root = default_user_dir(folder) / "globalStorage" / LEGACY_EXTENSION_ID
            yield from (root / "tasks").glob("*/api_conversation_history.json")
        for log in cline_sessions_dir().glob("*/*.messages.json"):
            if log.name == f"{log.parent.name}.messages.json":  # root session, as _sdk_agents
                yield log

    def history_meta(self, path: Path) -> tuple[str, str | None]:
        sid = path.parent.name
        if path.name == "api_conversation_history.json":  # legacy: state/taskHistory.json
            history = _read_json(path.parents[2] / "state" / "taskHistory.json")
            items = history if isinstance(history, list) else []
            cwd = next((
                h.get("cwdOnTaskInitialization") for h in items
                if isinstance(h, dict) and h.get("id") == sid
            ), None)
        else:
            manifest = _read_json(path.with_name(f"{sid}.json"))
            cwd = manifest.get("cwd") if isinstance(manifest, dict) else None
        return sid, folder_name(cwd)
