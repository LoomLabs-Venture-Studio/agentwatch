"""Process-gated discovery of running Cursor IDE agent-mode composers.

Cursor (a VS Code fork) is not spawned as a per-session CLI process the way
Claude Code/Aider/Codex CLI are -- the whole IDE hosts every composer across
every workspace in one shared ``state.vscdb`` SQLite file (see
``parser/cursor_source.py``'s module docstring for the schema this reads).
So unlike ``discovery.py::AGENT_PATTERNS``' per-process regex matching,
Cursor needs its own discovery mechanism: gate on whether Cursor is running
at all, then query the shared DB for composers worth watching.

**Board decision (PLAYBOOK Sprint 7, 2026-07-14): gate discovery on
Cursor.exe actually running**, not on ``state.vscdb`` merely existing on
disk -- this matches how every other agent is discovered (via a live
process) rather than surfacing stale/background composer data whenever
Cursor has ever been installed. ``state.vscdb`` persists after Cursor
closes (confirmed in the architecture review), so without this gate,
``agentwatch ps``/``watch-all`` would report Cursor "agents" forever after
the user's last real session.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import unquote, urlparse

import psutil

from .discovery import AgentProcess, _format_etime
from .parser.cursor_source import fetch_composer_headers, open_readonly

_CURSOR_PROCESS_RE = re.compile(r"^cursor(\.exe)?$", re.IGNORECASE)


def is_cursor_running() -> bool:
    """Check whether any Cursor process is currently running.

    Cursor is a multi-process Electron app (main, renderer, GPU, utility
    processes all typically share the same ``Cursor``/``Cursor.exe`` image
    name) -- this only needs to confirm *at least one* is alive, not
    identify a specific "main" process, since composer data lives in a
    shared DB rather than being owned by any single process.
    """
    try:
        for proc in psutil.process_iter(attrs=["name"]):
            try:
                name = proc.info.get("name") or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            if _CURSOR_PROCESS_RE.match(name):
                return True
    except Exception:
        return False
    return False


def default_cursor_user_dir() -> Path:
    """Resolve Cursor's per-OS ``User`` storage directory.

    Only the Windows path (``%APPDATA%\\Cursor\\User``) has been verified
    against a real install (this machine). The macOS/Linux paths are not
    independently confirmed against a live Cursor install the way the
    Windows path is, but as of Sprint 9 (2026-07-14) they're no longer a
    same-convention guess either: fetched VS Code's own real
    ``getDefaultUserDataPath`` (``src/vs/platform/environment/node/
    userDataPath.ts``, github.com/microsoft/vscode @ main -- Cursor is a
    VS Code fork and, absent evidence it stripped this generic per-OS
    switch, inherits it) and matched this function against it exactly:

    - macOS: ``join(homedir(), 'Library', 'Application Support')`` --
      confirmed identical to what this function already returned.
    - Linux: ``process.env['XDG_CONFIG_HOME'] || join(homedir(), '.config')``
      -- this function previously hardcoded ``~/.config`` unconditionally,
      ignoring ``XDG_CONFIG_HOME``. Fixed to match the real source.

    Deliberately NOT implemented (real features of the source read above,
    but Cursor-specific env var names/behavior are unconfirmed, so
    replicating them would be guessing, not confirming): VS Code's
    ``VSCODE_PORTABLE``/``VSCODE_APPDATA`` overrides and portable-mode
    support. If Cursor forks these under different env var names (e.g.
    ``CURSOR_PORTABLE``), that's unconfirmed and out of scope here.
    """
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
        return base / "Cursor" / "User"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Cursor" / "User"
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg_config_home) if xdg_config_home else Path.home() / ".config"
    return base / "Cursor" / "User"


def _file_uri_to_path(uri: str) -> Path | None:
    """Decode a ``workspace.json`` ``folder`` field into a filesystem Path.

    Confirmed real shape on this machine: ``file:///c%3A/Users/Zaid/Desktop/
    claude%20work/agentwatch/agentwatch-main`` -- URL-encoded, with a
    percent-encoded drive-letter colon on Windows. ``urlparse`` + ``unquote``
    handles the encoding; the leading ``/`` before a Windows drive letter
    (an artifact of the URI's triple-slash authority-less form) is stripped
    separately, since POSIX ``file://`` URIs keep that leading ``/`` as a
    real path root.
    """
    if not uri.startswith("file:"):
        return None
    parsed = urlparse(uri)
    raw = unquote(parsed.path)
    if re.match(r"^/[A-Za-z]:/", raw):
        raw = raw[1:]
    return Path(raw)


def build_workspace_map(user_dir: Path) -> dict[str, Path]:
    """Map ``workspaceId`` -> resolved project path.

    Reads every ``workspaceStorage/<id>/workspace.json``'s ``folder`` field.
    Entries with no ``workspace.json`` (confirmed real cases on this
    machine: ``empty-window/`` and a bare numeric id with only a
    ``state.vscdb`` and no ``workspace.json`` at all) are skipped rather
    than erroring -- both represent a workspace with no folder open.
    """
    mapping: dict[str, Path] = {}
    storage_root = user_dir / "workspaceStorage"
    if not storage_root.is_dir():
        return mapping

    for entry in storage_root.iterdir():
        if not entry.is_dir():
            continue
        workspace_json = entry / "workspace.json"
        if not workspace_json.is_file():
            continue
        try:
            data = json.loads(workspace_json.read_text(encoding="utf-8", errors="ignore"))
        except (json.JSONDecodeError, OSError):
            continue
        folder = data.get("folder") if isinstance(data, dict) else None
        if not isinstance(folder, str):
            continue
        path = _file_uri_to_path(folder)
        if path is not None:
            mapping[entry.name] = path

    return mapping


def _synthetic_pid(composer_id: str) -> int:
    """Stable, deterministic pseudo-PID derived from *composer_id*.

    Cursor composers have no real OS PID -- unlike Claude Code/Aider/Codex,
    the whole IDE (not a per-session process) hosts them. ``AgentProcess.pid``
    is used elsewhere as a dict/set key for team assignment
    (``discovery.py::_assign_team_ids``/``build_teams``) and must be a
    stable, unique int; this hash-based synthesis satisfies that without
    claiming to be a real PID. Masked to a positive 31-bit int so it
    prints/sorts sanely alongside real PIDs in ``ps`` output.
    """
    return hash(composer_id) & 0x7FFFFFFF


def _cursor_synthetic_log_key(db_path: Path, composer_id: str) -> Path:
    """Synthetic per-composer identity key for ``MultiLogWatcher``'s
    Path-keyed tracking dicts (``_process_meta``/``_active_files``/
    ``watchers``).

    Cursor's real content lives in one shared ``state.vscdb`` per install,
    not one file per session -- so the real db path can't double as
    ``MultiLogWatcher``'s per-agent identity key without every composer in
    the DB colliding on the same dict slot. This path is never opened for
    I/O; real access always goes through ``AgentProcess.cursor_db_path`` /
    ``CursorWatcher``'s ``composer_id_filter``.
    """
    return db_path.with_name(f"{db_path.stem}__cursor__{composer_id}{db_path.suffix}")


def find_cursor_agents(
    *,
    user_dir: Path | None = None,
    require_running: bool = True,
) -> list[AgentProcess]:
    """Discover Cursor agent-mode composers as synthetic ``AgentProcess``
    entries.

    Gated on Cursor actually running (see module docstring) unless
    *require_running* is explicitly disabled -- only tests supplying a
    fixture DB without a live Cursor process should do that. Only
    non-archived, ``unifiedMode == "agent"`` composers that have actually
    been messaged (``lastUpdatedAt`` not ``None``) and whose workspace
    resolves to a real path are surfaced; everything else is silently
    skipped, matching the existing "no cwd -> continue" convention used by
    every other agent type in ``discovery.py::find_running_agents``.

    Never raises: every failure mode (no Cursor running, no DB, unreadable
    DB, malformed rows) degrades to an empty list, since this is called
    from inside ``find_running_agents()``'s scan loop where a Cursor-specific
    problem must never break discovery of every other agent type.
    """
    if require_running and not is_cursor_running():
        return []

    user_dir = user_dir or default_cursor_user_dir()
    db_path = user_dir / "globalStorage" / "state.vscdb"
    if not db_path.is_file():
        return []

    workspace_map = build_workspace_map(user_dir)

    try:
        conn = open_readonly(db_path)
    except Exception:
        return []
    try:
        try:
            headers = fetch_composer_headers(conn)
        except Exception:
            return []
    finally:
        conn.close()

    agents: list[AgentProcess] = []
    for composer_id, header in headers.items():
        if header.get("isArchived"):
            continue
        if header.get("isDraft"):
            # Confirmed real on a live install (2026-07-14): Cursor creates
            # a placeholder composer (id "empty-state-draft") with a real
            # lastUpdatedAt but zero bubbles -- surfacing it would show a
            # phantom empty agent in `ps`/`watch-all`. See
            # cursor_source.py::select_latest_agent_composer for the same
            # fix applied to the one-shot check/security-scan path.
            continue
        if header.get("unifiedMode") != "agent":
            continue
        last_updated = header.get("lastUpdatedAt")
        if last_updated is None:
            continue  # composer exists but was never actually messaged

        workspace_id = header.get("workspaceId")
        working_directory = workspace_map.get(workspace_id) if workspace_id else None
        if working_directory is None:
            continue  # unresolvable workspace (empty-window, deleted folder)

        created_at_ms = header.get("createdAt")
        uptime = ""
        if isinstance(created_at_ms, (int, float)):
            uptime = _format_etime(time.time() - created_at_ms / 1000.0)

        agents.append(
            AgentProcess(
                pid=_synthetic_pid(composer_id),
                agent_type="cursor",
                working_directory=working_directory,
                log_file=_cursor_synthetic_log_key(db_path, composer_id),
                session_id=composer_id,
                cpu_percent=0.0,
                memory_mb=0.0,
                uptime=uptime,
                command="cursor (agent)",
                cursor_db_path=db_path,
            )
        )

    return agents
