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
    cost_usd: float = 0.0
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0
    
    # Security-relevant fields
    incoming_message: str | None = None  # For prompt injection detection
    outgoing_data: str | None = None     # For exfiltration detection
    network_host: str | None = None      # For C2 detection
    network_port: int | None = None
    user_id: str | None = None           # For audit trail
    skill_name: str | None = None        # For supply chain detection

    session_id: str | None = None
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
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cache_creation: int = 0
    total_cache_read: int = 0
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
        # Prefer real cost accumulated from log entries
        if self.total_cost > 0:
            return self.total_cost
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
        self._stats.total_input_tokens += action.tokens_in
        self._stats.total_output_tokens += action.tokens_out
        self._stats.total_cost += action.cost_usd
        self._stats.total_cache_creation += action.cache_creation_tokens
        self._stats.total_cache_read += action.cache_read_tokens
        
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


# ---------------------------------------------------------------------------
# Turn abstraction – groups actions between model output boundaries
# ---------------------------------------------------------------------------

@dataclass
class Turn:
    """A turn is a group of actions between two model-output boundaries.

    In Claude Code logs, a turn starts with an assistant message containing
    tool_use blocks and ends just before the next assistant message.  The
    ``model_output`` field carries any textual content the model produced
    (e.g. ``outgoing_data``) during the turn.
    """

    index: int
    actions: list[Action] = field(default_factory=list)
    model_output: str = ""

    @property
    def has_edit(self) -> bool:
        return any(a.is_file_edit for a in self.actions)

    @property
    def has_successful_bash(self) -> bool:
        return any(a.is_bash and a.success for a in self.actions)

    @property
    def edited_files(self) -> set[str]:
        return {a.file_path for a in self.actions if a.is_file_edit and a.file_path}

    @property
    def touched_files(self) -> set[str]:
        return {a.file_path for a in self.actions if a.file_path}

    @property
    def failed_actions(self) -> list[Action]:
        return [a for a in self.actions if not a.success]


def turns_from_actions(actions: list[Action]) -> list[Turn]:
    """Build a list of Turns from a flat action sequence.

    Heuristic: a new turn starts whenever we encounter an action that carries
    ``outgoing_data`` (model textual output) *or* when the sequence begins.
    All subsequent tool-call actions belong to the same turn until the next
    model output.
    """
    if not actions:
        return []

    turns: list[Turn] = []
    current = Turn(index=0)

    for action in actions:
        # An action with outgoing_data marks a model-output boundary
        if action.outgoing_data and current.actions:
            # Close current turn and start a new one
            turns.append(current)
            current = Turn(index=len(turns), model_output=action.outgoing_data)
        elif action.outgoing_data:
            current.model_output = action.outgoing_data

        current.actions.append(action)

    # Don't forget the last open turn
    if current.actions:
        turns.append(current)

    return turns


def turns_from_buffer(buffer: "ActionBuffer", last_n: int | None = None) -> list[Turn]:
    """Convenience: build turns from the buffer's action sequence."""
    actions = list(buffer.actions)
    if last_n is not None:
        actions = actions[-last_n:]
    return turns_from_actions(actions)


# ---------------------------------------------------------------------------
# MetricResult – uniform output for every rot-metric module
# ---------------------------------------------------------------------------

@dataclass
class MetricResult:
    """Uniform output produced by each rot-metric module."""

    name: str
    value: float  # 0.0 .. 1.0  (0 = healthy, 1 = fully degraded)
    evidence: list[str] = field(default_factory=list)
    contributors: list["MetricResult"] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.name,
            "value": round(self.value, 4),
            "evidence": self.evidence,
        }
        if self.contributors:
            d["contributors"] = [c.to_dict() for c in self.contributors]
        return d
