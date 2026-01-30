"""Rot score aggregation with EMA smoothing and state machine.

This module sits alongside the existing ``score.py`` health/efficiency
scores.  It does NOT replace them — it adds a new "context rot" composite
metric that integrates the five deterministic metric modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from agentwatch.detectors.health.behavioral import compute_behavioral
from agentwatch.detectors.health.constraints import compute_constraints
from agentwatch.detectors.health.progress import compute_progress
from agentwatch.detectors.health.repetition import compute_repetition
from agentwatch.detectors.health.tool_thrash import compute_tool_thrash
from agentwatch.parser.models import MetricResult

if TYPE_CHECKING:
    from agentwatch.parser.models import ActionBuffer


# ---------------------------------------------------------------------------
# Weights (must sum to 1.0)
# ---------------------------------------------------------------------------

W_BEHAVIORAL = 0.20
W_REPETITION = 0.20
W_THRASH = 0.25
W_PROGRESS = 0.25
W_CONSTRAINT = 0.10


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

class RotState(Enum):
    HEALTHY = "Healthy"
    WARMING = "Warming"
    ROTTING = "Rotting"
    CRITICAL = "Critical"


@dataclass
class RotReport:
    """Full rot-score report including per-module breakdown."""

    raw_score: float          # unsmoothed 0..1
    smoothed_score: float     # EMA-smoothed 0..1
    state: RotState
    modules: dict[str, MetricResult] = field(default_factory=dict)
    top_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "raw_score": round(self.raw_score, 4),
            "smoothed_score": round(self.smoothed_score, 4),
            "state": self.state.value,
            "modules": {k: v.to_dict() for k, v in self.modules.items()},
            "top_reasons": self.top_reasons,
        }


class RotScorer:
    """Stateful rot scorer with EMA smoothing and state transitions.

    Create one instance per monitored session and call ``update()`` on
    each refresh cycle.
    """

    def __init__(
        self,
        alpha: float = 0.4,
        *,
        # Constraint config — passed through to Module E
        no_new_deps: bool = False,
        forbidden_prefixes: list[str] | None = None,
        must_touch_paths: list[str] | None = None,
        must_touch_after: int = 6,
    ):
        self._alpha = alpha
        self._smoothed: float | None = None
        self._state = RotState.HEALTHY
        self._consecutive_above: dict[str, int] = {
            "warming": 0,   # turns >= 0.35
            "rotting": 0,   # turns >= 0.55
            "critical": 0,  # turns >= 0.75
        }

        # Constraint config
        self._no_new_deps = no_new_deps
        self._forbidden_prefixes = forbidden_prefixes or []
        self._must_touch_paths = must_touch_paths or []
        self._must_touch_after = must_touch_after

    # ------------------------------------------------------------------
    # Core update
    # ------------------------------------------------------------------

    def update(self, buffer: "ActionBuffer") -> RotReport:
        """Compute all modules, aggregate, smooth, and classify."""

        # --- Compute each module ---
        behavioral = compute_behavioral(buffer)
        repetition = compute_repetition(buffer)
        thrash = compute_tool_thrash(buffer)
        progress = compute_progress(buffer)
        constraint = compute_constraints(
            buffer,
            no_new_deps=self._no_new_deps,
            forbidden_prefixes=self._forbidden_prefixes,
            must_touch_paths=self._must_touch_paths,
            must_touch_after=self._must_touch_after,
        )

        modules = {
            "behavioral": behavioral,
            "repetition": repetition,
            "thrash": thrash,
            "progress": progress,
            "constraint": constraint,
        }

        # --- Weighted sum ---
        raw = (
            W_BEHAVIORAL * behavioral.value
            + W_REPETITION * repetition.value
            + W_THRASH * thrash.value
            + W_PROGRESS * progress.value
            + W_CONSTRAINT * constraint.value
        )
        raw = min(raw, 1.0)

        # --- EMA smoothing ---
        if self._smoothed is None:
            self._smoothed = raw
        else:
            self._smoothed = self._alpha * raw + (1.0 - self._alpha) * self._smoothed

        smoothed = self._smoothed

        # --- State machine ---
        self._update_state(smoothed, constraint.value, thrash.value)

        # --- Top 3 contributing reasons ---
        all_evidence: list[tuple[float, str]] = []
        for m in modules.values():
            for ev in m.evidence:
                all_evidence.append((m.value, ev))
        all_evidence.sort(key=lambda x: x[0], reverse=True)
        top_reasons = [ev for _, ev in all_evidence[:3]]

        return RotReport(
            raw_score=round(raw, 4),
            smoothed_score=round(smoothed, 4),
            state=self._state,
            modules=modules,
            top_reasons=top_reasons,
        )

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def _update_state(
        self,
        smoothed: float,
        constraint_val: float,
        thrash_val: float,
    ) -> None:
        # Track consecutive turns above thresholds
        if smoothed >= 0.75:
            self._consecutive_above["critical"] += 1
        else:
            self._consecutive_above["critical"] = 0

        if smoothed >= 0.55:
            self._consecutive_above["rotting"] += 1
        else:
            self._consecutive_above["rotting"] = 0

        if smoothed >= 0.35:
            self._consecutive_above["warming"] += 1
        else:
            self._consecutive_above["warming"] = 0

        # Determine state (highest matching wins)
        # Critical: >=0.75 for 2 turns OR (constraint >=0.7 AND stall >=0.7)
        if (
            self._consecutive_above["critical"] >= 2
            or (constraint_val >= 0.7 and thrash_val >= 0.7)
        ):
            self._state = RotState.CRITICAL
        elif self._consecutive_above["rotting"] >= 3:
            self._state = RotState.ROTTING
        elif self._consecutive_above["warming"] >= 2:
            self._state = RotState.WARMING
        else:
            self._state = RotState.HEALTHY
