"""Adaptive window sizing for rot metric modules.

Windows scale with session length so that longer sessions scan a
proportionally larger history, preventing short fixed windows from
missing degradation patterns buried in hundreds of actions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentwatch.parser.models import ActionBuffer


def scaled_action_window(buffer: "ActionBuffer", base: int = 20, fraction: float = 0.15, cap: int = 100) -> int:
    """Return an action-count window that grows with buffer size.

    Formula: max(base, min(cap, int(len(buffer) * fraction)))

    For a 20-action session this returns 20 (the base).
    For a 200-action session this returns 30.
    For a 500-action session this returns 75.
    For a 700+ action session this returns 100 (the cap).
    """
    return max(base, min(cap, int(len(buffer) * fraction)))


def scaled_turn_window(turn_count: int, base: int = 8, fraction: float = 0.20, cap: int = 30) -> int:
    """Return a turn-count window that grows with total turns.

    Formula: max(base, min(cap, int(turn_count * fraction)))

    For a 10-turn session this returns 8 (the base).
    For a 40-turn session this returns 8.
    For a 80-turn session this returns 16.
    For a 150+ turn session this returns 30 (the cap).
    """
    return max(base, min(cap, int(turn_count * fraction)))


def session_maturity_factor(
    turns: list,
    ramp_turns: int = 10,
    exploration_threshold: int = 3,
) -> float:
    """Return a 0.0-1.0 scaling factor for progress-based penalties.

    Immediately returns 1.0 (full penalties) if:
    - Any turn has a file edit (coding has started)
    - OR 3+ turns have code exploration (Read/Search) without edits
      (agent is exploring but not delivering)

    Otherwise returns a gradual ramp from 0.0 to 1.0 over ``ramp_turns``,
    allowing early conversation without penalizing lack of edits.

    This prevents casual greetings like "sup" from tanking health scores
    while still catching agents that explore code but never produce edits.
    """
    if not turns:
        return 0.0

    # Coding activity detected → full penalties immediately
    if any(t.has_edit for t in turns):
        return 1.0

    # Code exploration (Read/Search) without edits →
    # after threshold turns, expect coding to start
    exploration_turns = sum(1 for t in turns if t.has_code_exploration)
    if exploration_turns >= exploration_threshold:
        return 1.0

    # Pure conversation → gradual ramp
    return min(len(turns) / ramp_turns, 1.0)
