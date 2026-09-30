"""Registry of supported coding-agent adapters.

Order matters: process matching is first-match-wins per PID, in this order
(preserves the historical AGENT_PATTERNS order). To add an agent: create
agents/<name>.py with a BaseAdapter subclass and append it here.
"""

from __future__ import annotations

from pathlib import Path

from .aider import AiderAdapter
from .base import AgentAdapter, BaseAdapter, Watcher
from .claude_code import ClaudeCodeAdapter
from .codex import CodexAdapter
from .cursor import CursorAdapter

ADAPTERS: list[AgentAdapter] = [
    ClaudeCodeAdapter(),
    AiderAdapter(),
    CodexAdapter(),
    CursorAdapter(),
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
