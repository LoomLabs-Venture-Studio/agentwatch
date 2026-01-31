"""Module C: Tool thrash & stall metrics (deterministic).

Wraps signals from existing detectors (LoopDetector, ErrorBlindnessDetector,
ThrashDetector, StallDetector) into the 0..1 MetricResult format and adds a
turn-level ``turns_since_progress`` sub-metric.
"""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING

from agentwatch.parser.models import MetricResult, Turn, turns_from_buffer
from agentwatch.detectors.health._window import scaled_action_window, scaled_turn_window

if TYPE_CHECKING:
    from agentwatch.parser.models import ActionBuffer

_NORMALIZE_RE = re.compile(r"(line \d+|0x[0-9a-f]+|/[\w./\-]+|\d{2,})")


def _normalize_error(msg: str) -> str:
    """Strip volatile parts from error messages to get a stable signature."""
    return _NORMALIZE_RE.sub("<X>", msg.lower()).strip()


def _tool_call_hash(action) -> str:
    """Produce a short hash of tool name + normalized arguments."""
    key = f"{action.tool_name}|{action.file_path or ''}|{action.command or ''}"
    return hashlib.md5(key.encode(), usedforsecurity=False).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Sub-metrics
# ---------------------------------------------------------------------------

def _repeated_tool_calls(buffer: "ActionBuffer", window: int = 20) -> tuple[float, list[str]]:
    """Score for repeated identical tool calls in the last *window* actions.

    Returns (score 0..1, evidence list).
    """
    recent = buffer.last(window)
    if len(recent) < 4:
        return 0.0, []

    hashes: dict[str, int] = {}
    for a in recent:
        h = _tool_call_hash(a)
        hashes[h] = hashes.get(h, 0) + 1

    max_count = max(hashes.values()) if hashes else 0
    # 4 repeats = 0.5, 8+ repeats = 1.0
    score = min(max(max_count - 3, 0) / 5.0, 1.0)

    evidence: list[str] = []
    if score > 0:
        worst = max(hashes, key=hashes.get)  # type: ignore[arg-type]
        # Find a representative action for the hash
        for a in reversed(recent):
            if _tool_call_hash(a) == worst:
                desc = a.tool_name
                if a.file_path:
                    desc += f" on {a.file_path}"
                elif a.command:
                    desc += f": {a.command[:60]}"
                evidence.append(f"'{desc}' repeated {max_count}x in last {window} actions")
                break

    return score, evidence


def _repeated_errors(buffer: "ActionBuffer", window: int = 20) -> tuple[float, list[str]]:
    """Score for repeated normalized error signatures."""
    recent = buffer.last(window)
    errors = [_normalize_error(a.error_message) for a in recent if a.error_message]
    if not errors:
        return 0.0, []

    counts: dict[str, int] = {}
    for e in errors:
        counts[e] = counts.get(e, 0) + 1

    max_count = max(counts.values())
    # 3 same errors = 0.4, 6+ = 1.0
    score = min(max(max_count - 2, 0) / 4.0, 1.0)

    evidence: list[str] = []
    if score > 0:
        worst = max(counts, key=counts.get)  # type: ignore[arg-type]
        evidence.append(f"error repeated {max_count}x: '{worst[:80]}'")

    return score, evidence


def _turns_since_progress(buffer: "ActionBuffer") -> tuple[float, list[str]]:
    """Count turns since the last turn that had a file edit + successful bash.

    Returns (score 0..1, evidence).
    Score mapping: 3 turns = 0.3, 6 turns = 0.6, 10+ = 1.0
    """
    turns = turns_from_buffer(buffer)
    if not turns:
        return 0.0, []

    stale_count = 0
    for turn in reversed(turns):
        if turn.has_edit and turn.has_successful_bash:
            break
        stale_count += 1

    if stale_count <= 1:
        return 0.0, []

    score = min(stale_count / 10.0, 1.0)
    evidence: list[str] = []
    if score > 0.1:
        evidence.append(f"{stale_count} turns since last productive change")

    return score, evidence


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_tool_thrash(buffer: "ActionBuffer") -> MetricResult:
    """Compute the tool-thrash & stall metric."""

    window = scaled_action_window(buffer)
    tool_score, tool_ev = _repeated_tool_calls(buffer, window=window)
    err_score, err_ev = _repeated_errors(buffer, window=window)
    stall_score, stall_ev = _turns_since_progress(buffer)

    tool_result = MetricResult(name="repeated_tool_calls", value=round(tool_score, 4), evidence=tool_ev)
    err_result = MetricResult(name="repeated_errors", value=round(err_score, 4), evidence=err_ev)
    stall_result = MetricResult(name="turns_since_progress", value=round(stall_score, 4), evidence=stall_ev)

    # Weighted combination
    combined = 0.35 * tool_score + 0.35 * err_score + 0.30 * stall_score

    evidence = tool_ev + err_ev + stall_ev

    return MetricResult(
        name="thrash",
        value=round(min(combined, 1.0), 4),
        evidence=evidence,
        contributors=[tool_result, err_result, stall_result],
    )
