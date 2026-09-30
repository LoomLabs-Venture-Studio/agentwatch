"""Claude Code adapter (also owns Moltbot-format JSONL, which is a log
format, not a discoverable agent)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import BaseAdapter, Watcher, sniff_jsonl_format, source_path

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action


class ClaudeCodeAdapter(BaseAdapter):
    name = "claude-code"
    kind = "process"
    process_pattern = r"\bclaude\b"
    process_exclude = r"Claude\.app|Claude Helper|claude-code-guide|shell-snapshots"

    def resolve_log(self, cwd: Path, pid: int | None) -> tuple[Path | None, str | None]:
        from agentwatch import discovery  # call-time lookup: tests monkeypatch this

        return discovery._resolve_claude_code_log(cwd, pid=pid)

    def claims(self, path: Path) -> bool:
        # Every JSONL that isn't Codex -- including missing/undecidable files,
        # which parse_file() has always treated as Claude Code/Moltbot.
        return path.suffix == ".jsonl" and sniff_jsonl_format(path) != "codex"

    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher:
        from agentwatch.parser.watcher import LogWatcher

        return LogWatcher(source_path(source), session_id=session_id)

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        from agentwatch.parser.logs import _parse_jsonl

        return _parse_jsonl(path, session_id)
