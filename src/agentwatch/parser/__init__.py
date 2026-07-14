"""Log parsing utilities for AI agent monitoring."""

from .logs import (
    find_latest_session,
    find_log_files,
    is_sensitive_path,
    parse_file,
    SENSITIVE_PATH_REGEX,
)
from .models import Action, ActionBuffer, SessionStats, ToolType
from .watcher import LogWatcher, MultiLogWatcher

__all__ = [
    "Action",
    "ActionBuffer",
    "SessionStats",
    "ToolType",
    "LogWatcher",
    "MultiLogWatcher",
    "find_latest_session",
    "find_log_files",
    "is_sensitive_path",
    "parse_file",
    "SENSITIVE_PATH_REGEX",
]

# Re-export discovery module for convenience
from agentwatch.discovery import AgentProcess, find_running_agents

__all__ += [
    "AgentProcess",
    "find_running_agents",
]
