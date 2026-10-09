"""Registry of supported coding-agent adapters.

Order matters: process matching is first-match-wins per PID, in this order
(preserves the historical AGENT_PATTERNS order), and adapter_for() returns the
first adapter whose claims() is true. To add an agent: create agents/<name>.py
with a BaseAdapter subclass and register it here. Caveat: claude-code's claims()
is the JSONL catch-all (any .jsonl not sniffed as codex/copilot/agy/gemini), so a new
JSONL-logging adapter must be inserted BEFORE it (only safe if its process
pattern does not overlap claude-code/aider/codex) or claude-code's claims() must
be narrowed (as done for copilot, agy and gemini).
"""

from __future__ import annotations

from pathlib import Path

from .agy import AgyAdapter
from .aider import AiderAdapter
from .base import AgentAdapter, BaseAdapter, Watcher
from .claude_code import ClaudeCodeAdapter
from .claude_desktop import ClaudeDesktopAdapter
from .codex import CodexAdapter
from .copilot import CopilotAdapter
from .cursor import CursorAdapter
from .gemini import GeminiAdapter
from .opencode import OpencodeAdapter

ADAPTERS: list[AgentAdapter] = [
    ClaudeCodeAdapter(),
    AiderAdapter(),
    CodexAdapter(),
    CursorAdapter(),
    CopilotAdapter(),
    AgyAdapter(),
    OpencodeAdapter(),
    GeminiAdapter(),
    ClaudeDesktopAdapter(),
]


def get(name: str | None) -> AgentAdapter | None:
    for adapter in ADAPTERS:
        if adapter.name == name:
            return adapter
    return None


def adapter_for(path: Path) -> AgentAdapter | None:
    """First adapter (in registry order) that claims *path*."""
    for adapter in ADAPTERS:
        if adapter.claims(path):
            return adapter
    return None


def process_adapters() -> list[AgentAdapter]:
    return [a for a in ADAPTERS if a.kind == "process"]


def editor_adapters() -> list[AgentAdapter]:
    return [a for a in ADAPTERS if a.kind == "editor"]


def register(adapter: AgentAdapter) -> None:
    if get(adapter.name) is not None:
        raise ValueError(f"adapter {adapter.name!r} already registered")
    ADAPTERS.append(adapter)


__all__ = [
    "ADAPTERS",
    "AgentAdapter",
    "BaseAdapter",
    "Watcher",
    "adapter_for",
    "editor_adapters",
    "get",
    "process_adapters",
    "register",
]
