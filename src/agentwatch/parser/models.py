"""Data models for agent actions and events."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from itertools import islice
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

from agentwatch.cc_stats import usage_cost_usd

from .security_patterns import (
    is_credential_like_path,
    is_injection_like,
    is_privilege_command,
)


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


# `tool_name` sentinels used by parsers whose source format has no real
# per-action tool name to report (e.g. Cursor's `state.vscdb` bubbles only
# carry a user/assistant role, not a tool invocation -- see
# `cursor_source.py::bubble_to_action`). These are role labels, not repeated
# tool calls, so repetition-based detectors (`detectors/health/loops.py`)
# must exclude them from their counts to avoid flagging every multi-turn
# conversation as a "loop".
# Claude Code's "system" and "queue-operation" entries and "text_output"
# blocks stay actions (detectors scan their content) but are not tool calls.
NON_TOOL_ROLE_LABELS = frozenset({
    "user_message", "assistant_message", "unknown_bubble",
    "system", "queue-operation", "text_output",
})

# Token-usage-only records (Codex `token_count` events). Kept in the buffer so
# their tokens count and `action_count` still moves (the dashboards' change
# detection), but they are not agent activity: `activity_count` and
# actions-per-turn leave them out (#82).
USAGE_RECORD = "token_count"


@dataclass
class Action:
    """Represents a single agent action parsed from logs."""

    timestamp: datetime | None  # None: missing or unparseable (#44)
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
    context_window: int = 0  # model's window when the log reports it
    unpriced: bool = False  # no known price for this model: don't estimate cost
    model: str | None = None  # model id of the API call, for pricing
    # API call this action came from. Copies of one call (Claude Code writes a
    # line per content block, each with the full usage) share it.
    message_id: str | None = None
    cache_creation_1h_tokens: int = 0  # part of cache_creation_tokens on the 1h TTL

    # Security-relevant fields
    incoming_message: str | None = None  # For prompt injection detection
    outgoing_data: str | None = None     # For exfiltration detection
    network_host: str | None = None      # For C2 detection
    network_port: int | None = None
    # (remote ip, port) seen on the wire in this action's window; None = not sampled
    observed_endpoints: list[tuple[str, int]] | None = None
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


# ponytail: a fixed cap on idle gaps between actions. A single tool call that
# runs longer than this undercounts; per-agent or user-tunable caps if needed.
IDLE_GAP_CAP = timedelta(minutes=30)


@dataclass
class SessionStats:
    """Aggregated statistics for a session."""

    start_time: datetime | None = None
    last_action_time: datetime | None = None
    action_count: int = 0
    usage_records: int = 0  # USAGE_RECORD entries included in action_count
    context_window: int = 0  # latest log-reported window; 0 = infer
    unpriced: bool = False
    total_tokens: int = 0
    total_cost: float = 0.0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cache_creation: int = 0
    total_cache_read: int = 0
    peak_context_tokens: int = 0  # high-water mark of per-action context size
    last_context_tokens: int = 0  # context size of the latest action that reported usage
    active_seconds: float = 0.0  # span covered by actions, idle gaps capped
    error_count: int = 0
    files_touched: set[str] = field(default_factory=set)
    # Usage per API call, each call once (copies share Action.message_id).
    billed_tokens: int = 0
    billed_cost: float | None = 0.0  # None once a call with tokens had no price

    # Security stats -- DESIGN DECISION (Sprint 14, resolved not guessed):
    # these are RAW per-action pattern-match counts, not "how many times a
    # detector fired a Warning". Rationale: the field names ("accesses" /
    # "commands" / "connections" / "attempts") read as raw occurrence
    # counts, matching the existing precedent set by `error_count` above
    # (incremented on every failed action in `ActionBuffer.add()`,
    # independent of whether any error-related detector's own
    # window/threshold logic decides to raise a Warning about it).
    # `detectors/security/{credentials,privilege,network,injection}.py`
    # apply additional windowing/threshold/severity logic on top of these
    # same raw signals (sharing the exact same regexes via
    # `security_patterns.py` where applicable) -- that's a separate,
    # higher-level decision from "did this action's raw content look
    # credential/privilege/network/injection-like", which is all these
    # running counters track. See `ActionBuffer.add()` for the increments.
    credential_accesses: int = 0
    privilege_commands: int = 0
    network_connections: int = 0
    injection_attempts: int = 0

    @property
    def duration_minutes(self) -> float:
        """Active session time: the span covered by the actions' timestamps,
        with each idle gap capped at ``IDLE_GAP_CAP`` (see ActionBuffer.add).

        Deliberately derived from the actions' own timestamps rather than
        ``datetime.now()`` so that analysis of a fixed log (e.g. ``agentwatch
        check`` run twice against the same file) is reproducible and doesn't
        depend on how long ago the session happened or how long analysis
        takes to run.
        """
        return self.active_seconds / 60

    @property
    def activity_count(self) -> int:
        """Actions excluding token-usage-only records (#82)."""
        return self.action_count - self.usage_records

    @property
    def estimated_cost(self) -> float | None:
        # Priced per call from the model's rates (or the agent's own cost)
        if self.billed_tokens and self.billed_cost is not None:
            return self.billed_cost
        # Prefer real cost accumulated from log entries
        if self.total_cost > 0:
            return self.total_cost
        if self.unpriced:
            return None  # e.g. Codex: no price for its models here (#82)
        # No model name: estimate at Sonnet 4.6 rates (session display only;
        # per-finding cost never estimates).
        if self.total_cache_creation or self.total_cache_read:
            return usage_cost_usd(
                "claude-sonnet-4-6",
                self.total_input_tokens,
                self.total_output_tokens,
                self.total_cache_creation,
                self.total_cache_read,
            )
        # Fallback: blended rate when no breakdown is available
        return (self.total_tokens / 1_000_000) * 5


def call_tokens(action: Action) -> int:
    """All tokens of the API call *action* carries usage for (0 = none)."""
    return (
        action.tokens_in
        + action.tokens_out
        + action.cache_creation_tokens
        + action.cache_read_tokens
    )


def call_cost(action: Action) -> float | None:
    """USD of the call *action* carries usage for: the agent's own reported
    cost, else the model's listed rates; None when neither is known."""
    if action.cost_usd > 0:
        return action.cost_usd
    if action.unpriced:
        return None
    return usage_cost_usd(
        action.model,
        action.tokens_in,
        action.tokens_out,
        action.cache_creation_tokens,
        action.cache_read_tokens,
        action.cache_creation_1h_tokens,
    )


def calls_of(actions: Iterable[Action], buffer: "ActionBuffer") -> dict[Any, Action]:
    """The API calls behind *actions*, as {call key: action carrying its usage}.

    An action is charged to the call it came from: its ``message_id``, or for
    a Claude Code error result (no usage of its own) the call that issued the
    ``tool_use`` it answers. Actions of one call count once. Actions with no
    usage and no link to a call are left out.
    """
    usage: dict[str, Action] = {}  # message_id -> copy with the most tokens
    tool_call: dict[str, str] = {}  # tool_use id -> message_id
    for b in buffer.actions:
        if b.message_id is None:
            continue
        best = usage.get(b.message_id)
        if best is None or call_tokens(b) > call_tokens(best):
            usage[b.message_id] = b
        raw = b.raw if isinstance(b.raw, dict) else {}
        if raw.get("type") == "tool_use" and raw.get("id"):
            tool_call[raw["id"]] = b.message_id
    calls: dict[Any, Action] = {}
    for a in actions:
        raw = a.raw if isinstance(a.raw, dict) else {}
        mid = a.message_id or tool_call.get(raw.get("tool_use_id"))
        if mid is not None:
            if mid in usage:
                calls[mid] = usage[mid]
        elif call_tokens(a):
            calls[id(a)] = a
    return calls


def calls_usage(calls: Iterable[Action]) -> tuple[int | None, float | None]:
    """(tokens, usd) of *calls*. Tokens None when none carry usage; usd None
    when any call with tokens has no price -- never a partial sum or a guess."""
    tokens, cost = 0, 0.0
    for c in calls:
        t = call_tokens(c)
        if not t:
            continue
        tokens += t
        c_cost = call_cost(c)
        cost = None if cost is None or c_cost is None else cost + c_cost
    if not tokens:
        return None, None
    return tokens, cost


class ActionBuffer:
    """Rolling buffer of recent actions with query methods."""

    def __init__(self, max_size: int = 500):
        self.max_size = max_size
        self.actions: deque[Action] = deque(maxlen=max_size)
        self._file_access_counts: dict[str, int] = {}
        self._error_messages: list[str] = []
        self._stats = SessionStats()
        # message_id -> (tokens, cost) already counted for that call
        self._billed: dict[str, tuple[int, float]] = {}

    def __len__(self) -> int:
        return len(self.actions)

    def add(self, action: Action) -> None:
        """Add an action to the buffer."""
        self.actions.append(action)

        # Update stats
        self._stats.action_count += 1
        if action.tool_name == USAGE_RECORD:
            self._stats.usage_records += 1
        if action.context_window:
            self._stats.context_window = action.context_window
        self._stats.unpriced |= action.unpriced
        self._stats.total_tokens += action.tokens_in + action.tokens_out
        self._stats.total_input_tokens += action.tokens_in
        self._stats.total_output_tokens += action.tokens_out
        self._stats.total_cost += action.cost_usd
        self._stats.total_cache_creation += action.cache_creation_tokens
        self._stats.total_cache_read += action.cache_read_tokens
        # Each call once; a later copy with more tokens (streamed output)
        # replaces the earlier count, as calls_of keeps the largest copy.
        tokens = call_tokens(action)
        counted = self._billed.get(action.message_id) if action.message_id else None
        if tokens and (counted is None or tokens > counted[0]):
            cost = call_cost(action)
            old_tokens, old_cost = counted or (0, 0.0)
            self._stats.billed_tokens += tokens - old_tokens
            if cost is None:
                self._stats.billed_cost = None
            elif self._stats.billed_cost is not None:
                self._stats.billed_cost += cost - old_cost
            if action.message_id:
                self._billed[action.message_id] = (tokens, cost or 0.0)
        # Track high-water mark of per-action context size (survives compaction)
        action_context = action.tokens_in + action.cache_creation_tokens + action.cache_read_tokens
        if action_context > self._stats.peak_context_tokens:
            self._stats.peak_context_tokens = action_context
        # Latest window fill; usage-less actions (e.g. tool errors) don't reset it.
        if action_context > 0:
            self._stats.last_context_tokens = action_context

        # Extend the covered span at either end. Gaps are capped so a session
        # resumed hours or days later doesn't count the idle time (#38).
        ts = action.timestamp
        cap = IDLE_GAP_CAP.total_seconds()
        if ts is None:
            pass  # untimed: still counted and scanned, but adds no duration (#44)
        elif self._stats.start_time is None:
            self._stats.start_time = self._stats.last_action_time = ts
        elif ts > self._stats.last_action_time:
            gap = (ts - self._stats.last_action_time).total_seconds()
            self._stats.active_seconds += min(gap, cap)
            self._stats.last_action_time = ts
        elif ts < self._stats.start_time:
            gap = (self._stats.start_time - ts).total_seconds()
            self._stats.active_seconds += min(gap, cap)
            self._stats.start_time = ts

        if action.file_path:
            self._file_access_counts[action.file_path] = (
                self._file_access_counts.get(action.file_path, 0) + 1
            )
            self._stats.files_touched.add(action.file_path)

        if not action.success and action.error_message:
            self._stats.error_count += 1
            self._error_messages.append(action.error_message)

        # Raw per-action security-stat counters -- see the design-decision
        # comment on `SessionStats` above for why these count raw pattern
        # matches rather than detector-fired Warnings. Each check reuses the
        # exact same regex/logic as its corresponding detector (imported
        # from `security_patterns.py`, or `Action.is_network` itself for
        # network activity) rather than reimplementing new detection logic.
        if action.file_path and is_credential_like_path(action.file_path):
            self._stats.credential_accesses += 1
        if action.command and is_privilege_command(action.command):
            self._stats.privilege_commands += 1
        if action.is_network:
            self._stats.network_connections += 1
        if action.incoming_message and is_injection_like(action.incoming_message):
            self._stats.injection_attempts += 1

    def last(self, n: int) -> list[Action]:
        """Get the last n actions (chronological order)."""
        if n <= 0:
            return []
        return list(reversed(list(islice(reversed(self.actions), n))))

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
    def has_code_exploration(self) -> bool:
        """True if turn contains Read or Search actions (code exploration)."""
        return any(
            a.tool_type in (ToolType.READ, ToolType.SEARCH)
            for a in self.actions
        )

    @property
    def edited_files(self) -> set[str]:
        return {a.file_path for a in self.actions if a.is_file_edit and a.file_path}


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
