"""Log parsing utilities for AI agent monitoring."""

from .aider import (
    AiderSession,
    parse_aider_analytics,
    parse_aider_log,
    parse_aider_markdown,
    parse_aider_sessions,
)
from .codex import CodexParser, classify_codex_tool
from .cursor_source import (
    bubble_to_action,
    classify_cursor_tool,
    fetch_bubbles,
    fetch_checkpoint,
    fetch_composer_headers,
    open_readonly,
    parse_cursor_session,
    select_latest_agent_composer,
)
from .logs import (
    SENSITIVE_PATH_REGEX,
    find_latest_session,
    find_log_files,
    is_sensitive_path,
    parse_file,
)
from .models import Action, ActionBuffer, SessionStats, ToolType
from .watcher import AiderLogWatcher, CursorWatcher, LogWatcher, MultiLogWatcher

__all__ = [
    "Action",
    "ActionBuffer",
    "SessionStats",
    "ToolType",
    "CodexParser",
    "classify_codex_tool",
    "AiderLogWatcher",
    "CursorWatcher",
    "bubble_to_action",
    "classify_cursor_tool",
    "fetch_bubbles",
    "fetch_checkpoint",
    "fetch_composer_headers",
    "open_readonly",
    "parse_cursor_session",
    "select_latest_agent_composer",
    "LogWatcher",
    "MultiLogWatcher",
    "find_latest_session",
    "find_log_files",
    "is_sensitive_path",
    "parse_file",
    "AiderSession",
    "parse_aider_analytics",
    "parse_aider_log",
    "parse_aider_markdown",
    "parse_aider_sessions",
    "SENSITIVE_PATH_REGEX",
]

# Discovery re-exports, for convenience. Lazy (PEP 562): cursor_discovery
# imports parser.cursor_source, so an eager import here is circular whenever
# cursor_discovery is imported before the parser.
_DISCOVERY = {
    "AgentProcess": "agentwatch.discovery",
    "find_running_agents": "agentwatch.discovery",
    "find_cursor_agents": "agentwatch.cursor_discovery",
}


def __getattr__(name: str):
    if name not in _DISCOVERY:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    return getattr(importlib.import_module(_DISCOVERY[name]), name)


__all__ += [
    "AgentProcess",
    "find_running_agents",
    "find_cursor_agents",
]
