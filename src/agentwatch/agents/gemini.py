"""Gemini CLI adapter."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import BaseAdapter, Watcher, sniff_jsonl_format, source_path

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action


def resolve_gemini_log(cwd: Path, pid: int | None = None) -> tuple[Path | None, str | None]:
    """Newest ``session-*.jsonl`` of the Gemini CLI project for *cwd*.

    Per gemini-cli v0.62.0 (``packages/core/src/config/{storage,projectRegistry}.ts``,
    ``utils/paths.ts``): the home is ``$GEMINI_CLI_HOME`` or ``~``; the
    project's short id is ``projects.json``'s ``projects[<abs cwd>]`` (path
    lowercased on Windows); its chats are ``.gemini/tmp/<short-id>/chats/``.
    The session file records no pid, so the newest one is taken.
    """
    # ponytail: newest-by-mtime; two live sessions in one project pick the same file.
    gemini_dir = Path(os.environ.get("GEMINI_CLI_HOME") or Path.home()) / ".gemini"
    try:
        projects = json.loads((gemini_dir / "projects.json").read_text(encoding="utf-8"))
        key = os.path.abspath(cwd)  # node's path.resolve(): no symlink resolution
        short_id = projects["projects"][key.lower() if sys.platform == "win32" else key]
    except (OSError, ValueError, KeyError, TypeError):
        return None, None
    chats = gemini_dir / "tmp" / str(short_id) / "chats"
    sessions = sorted(chats.glob("session-*.jsonl"), key=lambda f: f.stat().st_mtime)
    return (sessions[-1], None) if sessions else (None, None)


class GeminiAdapter(BaseAdapter):
    name = "gemini"
    kind = "process"
    # The npm bin is `@google/gemini-cli/bundle/gemini.js`, run by node
    # (program_path() sees the script), or `.bin/gemini` under npx.
    process_pattern = r"(^|[/\\])gemini(\.exe|\.js)?$"
    process_exclude = None

    def resolve_log(self, cwd: Path, pid: int | None) -> tuple[Path | None, str | None]:
        return resolve_gemini_log(cwd, pid=pid)

    def claims(self, path: Path) -> bool:
        return path.suffix == ".jsonl" and sniff_jsonl_format(path) == "gemini"

    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher:
        from agentwatch.parser.watcher import LogWatcher

        return LogWatcher(source_path(source), session_id=session_id)

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        from agentwatch.parser.logs import _parse_jsonl

        return _parse_jsonl(path, session_id)
