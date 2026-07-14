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

# Re-export discovery module for convenience
from agentwatch.cursor_discovery import find_cursor_agents
from agentwatch.discovery import AgentProcess, find_running_agents

__all__ += [
    "AgentProcess",
    "find_running_agents",
    "find_cursor_agents",
]
