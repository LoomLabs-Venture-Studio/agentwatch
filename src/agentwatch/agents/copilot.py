"""GitHub Copilot CLI adapter."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import BaseAdapter, Watcher, sniff_jsonl_format, source_path

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action


def _session_start_cwd(path: Path) -> str | None:
    """``context.cwd`` from an ``events.jsonl``'s leading ``session.start`` line."""
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            entry = json.loads(f.readline())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(entry, dict) or entry.get("type") != "session.start":
        return None
    context = (entry.get("data") or {}).get("context") or {}
    return context.get("cwd") if isinstance(context, dict) else None


def resolve_copilot_log(cwd: Path, pid: int | None = None) -> tuple[Path | None, str | None]:
    """Resolve the active Copilot CLI ``events.jsonl`` for a working directory.

    Sessions live at ``$COPILOT_HOME/session-state/<session-id>/events.jsonl``
    (``COPILOT_HOME`` defaults to ``~/.copilot``, per ``copilot help
    environment``). A running CLI writes ``inuse.<pid>.lock`` into its own
    session dir at startup (seen live, 1.0.90), so that is checked first;
    ``events.jsonl`` only appears after the first message, so until then the
    log is ``None`` and discovery re-resolves on the next scan. Without a
    lock: the newest session whose ``session.start`` ``context.cwd`` matches,
    then the newest session overall.
    """
    root = Path(os.environ.get("COPILOT_HOME") or Path.home() / ".copilot") / "session-state"
    if not root.is_dir():
        return None, None

    if pid is not None:
        for lock in root.glob(f"*/inuse.{pid}.lock"):
            log = lock.parent / "events.jsonl"
            return (log if log.exists() else None), lock.parent.name

    candidates = sorted(root.glob("*/events.jsonl"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not candidates:
        return None, None
    resolved_cwd = cwd.resolve()
    # ponytail: only the 20 newest sessions are checked for a cwd match.
    for path in candidates[:20]:
        session_cwd = _session_start_cwd(path)
        if session_cwd:
            try:
                if Path(session_cwd).resolve() == resolved_cwd:
                    return path, path.parent.name
            except OSError:
                pass
    return candidates[0], candidates[0].parent.name


class CopilotAdapter(BaseAdapter):
    name = "copilot"
    kind = "process"
    # Match only an executable named exactly `copilot`. A bare \bcopilot\b
    # also caught VS Code's `copilot-runtime --headless` and any shell command
    # mentioning the word. The CLI runs as `node .../bin/copilot` (a loader)
    # that spawnSync()s the native `@github/copilot-<platform>/copilot`
    # binary; exclude the node loader so one session isn't listed twice.
    process_pattern = r"(^|[/\\])copilot(\.exe)?(\s|$)"
    process_exclude = r"^\S*node(\.exe)?\s"

    def resolve_log(self, cwd: Path, pid: int | None) -> tuple[Path | None, str | None]:
        return resolve_copilot_log(cwd, pid=pid)

    def claims(self, path: Path) -> bool:
        return path.suffix == ".jsonl" and sniff_jsonl_format(path) == "copilot"

    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher:
        # LogWatcher auto-detects Copilot and, like Codex, never flushes on poll.
        from agentwatch.parser.watcher import LogWatcher

        return LogWatcher(source_path(source), session_id=session_id)

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        from agentwatch.parser.logs import _parse_jsonl

        return _parse_jsonl(path, session_id)
