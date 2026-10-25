"""Claude Desktop adapter (editor-kind: Cowork sessions, app-gated discovery).

Cowork transcripts are Claude Code JSONL, so watching and parsing delegate
to the claude-code adapter; claims() stays False so adapter_for() keeps
routing those .jsonl files to claude-code.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import BaseAdapter, Watcher
from .claude_code import ClaudeCodeAdapter

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action

_CLAUDE_CODE = ClaudeCodeAdapter()


class ClaudeDesktopAdapter(BaseAdapter):
    name = "claude-desktop"
    kind = "editor"

    def discover(self) -> list[AgentProcess]:
        import agentwatch.claude_desktop_discovery as cdd  # call-time lookup

        return cdd.find_claude_desktop_agents()

    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher:
        return _CLAUDE_CODE.make_watcher(source, session_id)

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        return _CLAUDE_CODE.parse_file(path, session_id, **opts)
