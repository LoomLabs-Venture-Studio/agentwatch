"""Module A: Behavioral degradation metrics (deterministic)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from agentwatch.parser.models import MetricResult, Turn, turns_from_buffer
from agentwatch.detectors.health._window import scaled_turn_window

if TYPE_CHECKING:
    from agentwatch.parser.models import ActionBuffer

# ---------------------------------------------------------------------------
# Fixed word / phrase lists
# ---------------------------------------------------------------------------

HEDGE_WORDS: frozenset[str] = frozenset({
    "maybe", "perhaps", "possibly", "might", "could", "seem", "seems",
    "seemed", "apparently", "arguably", "conceivably", "likely", "unlikely",
    "roughly", "approximately", "somewhat", "fairly", "quite", "rather",
    "virtually", "practically", "basically", "essentially", "generally",
    "typically", "usually", "probably", "presumably",
})

APOLOGY_PHRASES: tuple[str, ...] = (
    "i apologize",
    "i'm sorry",
    "sorry about",
    "sorry for",
    "my apologies",
    "apologies for",
    "i made a mistake",
    "i was wrong",
    "let me correct",
    "let me fix that",
    "my mistake",
    "that was incorrect",
    "i misspoke",
)

_WORD_RE = re.compile(r"[a-z]+")


def _word_count(text: str) -> int:
    return len(_WORD_RE.findall(text.lower()))


def _hedge_density(text: str) -> float:
    """Fraction of words that are hedge words."""
    words = _WORD_RE.findall(text.lower())
    if not words:
        return 0.0
    return sum(1 for w in words if w in HEDGE_WORDS) / len(words)


def _apology_density(text: str) -> float:
    """Count of apology phrases per 100 words."""
    lower = text.lower()
    words = _WORD_RE.findall(lower)
    if not words:
        return 0.0
    count = sum(1 for phrase in APOLOGY_PHRASES if phrase in lower)
    # Normalize: 1 apology per 100 words → 1.0
    return min(count / max(len(words) / 100.0, 1.0), 1.0)


def _length_inflation_slope(lengths: list[int]) -> float:
    """Simple slope of word counts over N turns, normalized to 0..1.

    Positive slope → inflation.  We clamp negative slopes to 0.
    Normalization: a doubling per turn maps to ~1.0.
    """
    n = len(lengths)
    if n < 2:
        return 0.0

    # Least-squares slope: slope = Σ(xi - x̄)(yi - ȳ) / Σ(xi - x̄)²
    x_mean = (n - 1) / 2.0
    y_mean = sum(lengths) / n

    num = sum((i - x_mean) * (y - y_mean) for i, y in enumerate(lengths))
    denom = sum((i - x_mean) ** 2 for i in range(n))
    if denom == 0:
        return 0.0

    slope = num / denom

    # Clamp: only inflation counts
    if slope <= 0:
        return 0.0

    # Normalize relative to mean length.  A slope equal to the mean length
    # (doubling over the window) maps to 1.0.
    baseline = max(y_mean, 1.0)
    return min(slope / baseline, 1.0)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_behavioral(buffer: ActionBuffer, n_turns: int | None = None) -> MetricResult:
    """Compute the behavioral-degradation metric over the last *n_turns* turns."""

    turns = turns_from_buffer(buffer)
    if len(turns) < 2:
        return MetricResult(name="behavioral", value=0.0)

    if n_turns is None:
        n_turns = scaled_turn_window(len(turns), base=5, fraction=0.15, cap=20)

    recent = turns[-n_turns:]

    # Collect model outputs
    outputs = [t.model_output for t in recent if t.model_output]
    if not outputs:
        return MetricResult(name="behavioral", value=0.0)

    # Sub-metric: length inflation
    lengths = [_word_count(o) for o in outputs]
    inflation = _length_inflation_slope(lengths)
    inflation_result = MetricResult(
        name="length_inflation",
        value=round(inflation, 4),
        evidence=[f"word counts over last {len(lengths)} turns: {lengths}"] if inflation > 0.1 else [],
    )

    # Sub-metric: hedge density (average over recent outputs)
    hedge_vals = [_hedge_density(o) for o in outputs]
    avg_hedge = sum(hedge_vals) / len(hedge_vals)
    # Normalize: 5% hedge words → 1.0
    hedge_score = min(avg_hedge / 0.05, 1.0)
    hedge_result = MetricResult(
        name="hedge_density",
        value=round(hedge_score, 4),
        evidence=[f"avg hedge word ratio: {avg_hedge:.3f}"] if hedge_score > 0.1 else [],
    )

    # Sub-metric: apology density
    apology_vals = [_apology_density(o) for o in outputs]
    avg_apology = sum(apology_vals) / len(apology_vals)
    apology_result = MetricResult(
        name="apology_density",
        value=round(avg_apology, 4),
        evidence=[f"avg apology density: {avg_apology:.3f}"] if avg_apology > 0.1 else [],
    )

    # Combine: simple average
    combined = (inflation + hedge_score + avg_apology) / 3.0
    evidence: list[str] = []
    if inflation > 0.2:
        evidence.append(f"response length inflating (slope={inflation:.2f})")
    if hedge_score > 0.2:
        evidence.append(f"high hedge-word density ({avg_hedge:.1%})")
    if avg_apology > 0.2:
        evidence.append(f"frequent apologies ({avg_apology:.2f})")

    return MetricResult(
        name="behavioral",
        value=round(min(combined, 1.0), 4),
        evidence=evidence,
        contributors=[inflation_result, hedge_result, apology_result],
    )
