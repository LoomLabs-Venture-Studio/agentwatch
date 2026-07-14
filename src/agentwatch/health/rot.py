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
from agentwatch.themes import get_theme

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
    """Rot state levels (best to worst).

    The .value is an internal identifier. Use .label for theme-aware display.
    """
    LEVEL_0 = "level_0"  # Best (productive/healthy)
    LEVEL_1 = "level_1"  # Degraded (struggling)
    LEVEL_2 = "level_2"  # Warning (spinning)
    LEVEL_3 = "level_3"  # Critical (stuck)

    # Aliases for backward compatibility
    HEALTHY = "level_0"
    DEGRADED = "level_1"
    WARNING = "level_2"
    CRITICAL = "level_3"

    @property
    def label(self) -> str:
        """Get the theme-aware display label for this state."""
        theme = get_theme()
        mapping = {
            "level_0": theme.level_0,
            "level_1": theme.level_1,
            "level_2": theme.level_2,
            "level_3": theme.level_3,
        }
        return mapping.get(self.value, self.value)


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
            "state": self.state.label,  # Use theme-aware label
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
        self._state = RotState.LEVEL_0
        self._consecutive_above: dict[str, int] = {
            "level_1": 0,  # turns >= 0.20 (degraded)
            "level_2": 0,  # turns >= 0.40 (warning)
            "level_3": 0,  # turns >= 0.60 (critical)
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
        # Track consecutive turns above thresholds.
        # Thresholds on 0-1 smoothed_score (0=level_0, 1=level_3) are
        # derived from unified display breakpoints 80/60/40:
        #   level_0 (productive) → display>=80 → smoothed<0.20
        #   level_1 (struggling) → display>=60 → smoothed<0.40
        #   level_2 (spinning)   → display>=40 → smoothed<0.60
        #   level_3 (stuck)      → display<40  → smoothed>=0.60
        if smoothed >= 0.60:
            self._consecutive_above["level_3"] += 1
        else:
            self._consecutive_above["level_3"] = 0

        if smoothed >= 0.40:
            self._consecutive_above["level_2"] += 1
        else:
            self._consecutive_above["level_2"] = 0

        if smoothed >= 0.20:
            self._consecutive_above["level_1"] += 1
        else:
            self._consecutive_above["level_1"] = 0

        # Determine state (highest matching wins)
        # level_3: >=0.60 for 2 turns OR (constraint >=0.7 AND stall >=0.7)
        if (
            self._consecutive_above["level_3"] >= 2
            or (constraint_val >= 0.7 and thrash_val >= 0.7)
        ):
            self._state = RotState.LEVEL_3
        elif self._consecutive_above["level_2"] >= 3:
            self._state = RotState.LEVEL_2
        elif self._consecutive_above["level_1"] >= 2:
            self._state = RotState.LEVEL_1
        else:
            self._state = RotState.LEVEL_0
