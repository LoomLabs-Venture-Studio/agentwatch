"""Data models for agent actions and events."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class ToolType(Enum):
    """Types of tools an agent can use."""
    READ = "read"
    WRITE = "write"
    EDIT = "edit"
    BASH = "bash"
    SEARCH = "search"
    LIST = "list"
    BROWSER = "browser"
    MCP = "mcp"
    UNKNOWN = "unknown"


@dataclass
class Action:
    """Represents a single agent action parsed from logs."""
    
    timestamp: datetime
    tool_name: str
    tool_type: ToolType
    success: bool
    file_path: str | None = None
    command: str | None = None
    error_message: str | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    duration_ms: int = 0
    
    # Security-relevant fields
    incoming_message: str | None = None  # For prompt injection detection
    outgoing_data: str | None = None     # For exfiltration detection
    network_host: str | None = None      # For C2 detection
    network_port: int | None = None
    user_id: str | None = None           # For audit trail
    skill_name: str | None = None        # For supply chain detection
    
    raw: dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_file_read(self) -> bool:
        return self.tool_type == ToolType.READ
    
    @property
    def is_file_edit(self) -> bool:
        return self.tool_type in (ToolType.WRITE, ToolType.EDIT)
    
    @property
    def is_bash(self) -> bool:
        return self.tool_type == ToolType.BASH
    
    @property
    def is_network(self) -> bool:
        return self.network_host is not None or self.network_port is not None


@dataclass
class SessionStats:
    """Aggregated statistics for a session."""
    
    start_time: datetime | None = None
    action_count: int = 0
    total_tokens: int = 0
    total_cost: float = 0.0
    error_count: int = 0
    files_touched: set[str] = field(default_factory=set)
    
    # Security stats
    credential_accesses: int = 0
    privilege_commands: int = 0
    network_connections: int = 0
    injection_attempts: int = 0
    
    @property
    def duration_minutes(self) -> float:
        if not self.start_time:
            return 0.0
        # Handle timezone-aware vs naive datetimes
        now = datetime.now(self.start_time.tzinfo) if self.start_time.tzinfo else datetime.now()
        delta = now - self.start_time
        return delta.total_seconds() / 60
    
    @property
    def estimated_cost(self) -> float:
        # Rough estimate: $3 per 1M input tokens, $15 per 1M output
        return (self.total_tokens / 1_000_000) * 5  # Blended rate


class ActionBuffer:
    """Rolling buffer of recent actions with query methods."""
    
    def __init__(self, max_size: int = 500):
        self.max_size = max_size
        self.actions: deque[Action] = deque(maxlen=max_size)
        self._file_access_counts: dict[str, int] = {}
        self._error_messages: list[str] = []
        self._stats = SessionStats()
    
    def __len__(self) -> int:
        return len(self.actions)
    
    def add(self, action: Action) -> None:
        """Add an action to the buffer."""
        self.actions.append(action)
        
        # Update stats
        self._stats.action_count += 1
        self._stats.total_tokens += action.tokens_in + action.tokens_out
        
        if not self._stats.start_time:
            self._stats.start_time = action.timestamp
        
        if action.file_path:
            self._file_access_counts[action.file_path] = (
                self._file_access_counts.get(action.file_path, 0) + 1
            )
            self._stats.files_touched.add(action.file_path)
        
        if not action.success and action.error_message:
            self._stats.error_count += 1
            self._error_messages.append(action.error_message)
    
    def last(self, n: int) -> list[Action]:
        """Get the last n actions."""
        return list(self.actions)[-n:]
    
    def first(self, n: int) -> list[Action]:
        """Get the first n actions."""
        return list(self.actions)[:n]
    
    @property
    def stats(self) -> SessionStats:
        return self._stats
    
    def file_access_count(self, path: str) -> int:
        """How many times a file has been accessed."""
        return self._file_access_counts.get(path, 0)
    
    def files_in_window(self, n: int) -> set[str]:
        """Get unique files accessed in last n actions."""
        return {a.file_path for a in self.last(n) if a.file_path}
    
    def early_files(self, n: int) -> set[str]:
        """Get unique files from first n actions."""
        return {a.file_path for a in self.first(n) if a.file_path}
    
    def recent_errors(self, n: int = 10) -> list[str]:
        """Get recent error messages."""
        return self._error_messages[-n:]
    
    def actions_by_file(self, path: str) -> list[Action]:
        """Get all actions involving a specific file."""
        return [a for a in self.actions if a.file_path == path]
    
    def bash_commands(self, n: int | None = None) -> list[str]:
        """Get recent bash commands."""
        cmds = [a.command for a in self.actions if a.command and a.is_bash]
        return cmds[-n:] if n else cmds
    
    def network_actions(self) -> list[Action]:
        """Get actions with network activity."""
        return [a for a in self.actions if a.is_network]
