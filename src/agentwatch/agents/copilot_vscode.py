"""GitHub Copilot in VS Code adapter (editor-kind: chats live inside VS Code,
one mutation-log ``.jsonl`` per session; see ``parser/copilot_vscode.py``)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import BaseAdapter, sniff_jsonl_format

if TYPE_CHECKING:
    from agentwatch.parser.models import Action


class CopilotVscodeAdapter(BaseAdapter):
    name = "copilot-vscode"
    kind = "editor"

    def claims(self, path: Path) -> bool:
        return path.suffix == ".jsonl" and sniff_jsonl_format(path) == "copilot_vscode"

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        from agentwatch.parser.copilot_vscode import parse_copilot_vscode

        yield from parse_copilot_vscode(path, session_id)
