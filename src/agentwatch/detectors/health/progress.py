"""Module D: Diff-based progress metrics (deterministic)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentwatch.parser.models import MetricResult, Turn, turns_from_buffer
from agentwatch.detectors.health._window import scaled_turn_window

if TYPE_CHECKING:
    from agentwatch.parser.models import ActionBuffer


def _turns_with_diff_ratio(turns: list[Turn], n: int = 8) -> tuple[float, list[str]]:
    """Fraction of the last *n* turns that contain at least one file edit.

    Returns (deficit score 0..1, evidence).
    A ratio of 1.0 (all turns have diffs) → deficit 0.0.
    A ratio of 0.0 (no turns have diffs) → deficit 1.0.
    """
    recent = turns[-n:] if len(turns) >= n else turns
    if not recent:
        return 0.0, []

    with_diff = sum(1 for t in recent if t.has_edit)
    ratio = with_diff / len(recent)
    deficit = 1.0 - ratio

    evidence: list[str] = []
    if deficit > 0.3:
        evidence.append(f"only {with_diff}/{len(recent)} recent turns produced file changes")

    return round(deficit, 4), evidence


def _file_churn(turns: list[Turn], n: int = 8) -> tuple[float, list[str]]:
    """Detect files touched repeatedly across turns without a subsequent
    successful bash (i.e. edits that never pass).

    Returns (churn score 0..1, evidence).
    """
    recent = turns[-n:] if len(turns) >= n else turns
    if not recent:
        return 0.0, []

    file_edit_counts: dict[str, int] = {}
    file_success: dict[str, bool] = {}

    for turn in recent:
        for f in turn.edited_files:
            file_edit_counts[f] = file_edit_counts.get(f, 0) + 1
            # Reset success tracking on each new edit
            file_success[f] = False
        if turn.has_successful_bash:
            # Mark all previously-edited files as having passed
            for f in file_success:
                file_success[f] = True

    # Files edited 3+ times without success = churn
    churning: list[str] = []
    for f, count in file_edit_counts.items():
        if count >= 3 and not file_success.get(f, False):
            churning.append(f)

    if not churning:
        return 0.0, []

    # Score: 1 churning file = 0.4, 2 = 0.7, 3+ = 1.0
    score = min(len(churning) * 0.35, 1.0)

    evidence = [f"file churning without success: {', '.join(churning[:3])} ({max(file_edit_counts[f] for f in churning)}+ edits)"]

    return round(score, 4), evidence


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_progress(buffer: "ActionBuffer", n_turns: int | None = None) -> MetricResult:
    """Compute the diff-based progress deficit metric."""

    turns = turns_from_buffer(buffer)
    if len(turns) < 2:
        return MetricResult(name="progress", value=0.0)

    if n_turns is None:
        n_turns = scaled_turn_window(len(turns))

    diff_score, diff_ev = _turns_with_diff_ratio(turns, n=n_turns)
    churn_score, churn_ev = _file_churn(turns, n=n_turns)

    diff_result = MetricResult(name="turns_with_diff", value=diff_score, evidence=diff_ev)
    churn_result = MetricResult(name="file_churn", value=churn_score, evidence=churn_ev)

    combined = 0.55 * diff_score + 0.45 * churn_score
    evidence = diff_ev + churn_ev

    return MetricResult(
        name="progress",
        value=round(min(combined, 1.0), 4),
        evidence=evidence,
        contributors=[diff_result, churn_result],
    )
