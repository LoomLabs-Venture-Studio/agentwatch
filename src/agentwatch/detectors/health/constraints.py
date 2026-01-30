"""Module E: Constraint violation metrics (rule-based, deterministic)."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from agentwatch.parser.models import MetricResult, Turn, turns_from_buffer

if TYPE_CHECKING:
    from agentwatch.parser.models import ActionBuffer

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

DEFAULT_DEPENDENCY_MANIFESTS: frozenset[str] = frozenset({
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "requirements-dev.txt",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "build.gradle",
    "pom.xml",
})


def _basename(path: str) -> str:
    return os.path.basename(path)


# ---------------------------------------------------------------------------
# Sub-metrics
# ---------------------------------------------------------------------------

def _no_new_deps(buffer: "ActionBuffer", manifests: frozenset[str]) -> tuple[float, list[str]]:
    """Detect edits to dependency manifest files.

    Returns (score 0..1, evidence).
    Each distinct manifest edited scores 0.5, capped at 1.0.
    """
    actions = list(buffer.actions)
    violated: set[str] = set()

    for action in actions:
        if action.is_file_edit and action.file_path:
            if _basename(action.file_path) in manifests:
                violated.add(action.file_path)

    if not violated:
        return 0.0, []

    score = min(len(violated) * 0.5, 1.0)
    evidence = [f"dependency manifest modified: {p}" for p in sorted(violated)[:3]]
    return round(score, 4), evidence


def _forbidden_paths(buffer: "ActionBuffer", prefixes: list[str]) -> tuple[float, list[str]]:
    """Detect access to files under forbidden path prefixes.

    Returns (score 0..1, evidence).
    """
    if not prefixes:
        return 0.0, []

    actions = list(buffer.actions)
    violated: set[str] = set()

    for action in actions:
        if action.file_path:
            for prefix in prefixes:
                if action.file_path.startswith(prefix):
                    violated.add(action.file_path)
                    break

    if not violated:
        return 0.0, []

    score = min(len(violated) * 0.3, 1.0)
    evidence = [f"forbidden path accessed: {p}" for p in sorted(violated)[:5]]
    return round(score, 4), evidence


def _must_touch(
    buffer: "ActionBuffer",
    required_paths: list[str],
    after_turns: int = 6,
) -> tuple[float, list[str]]:
    """Check that certain paths have been touched after *after_turns* turns.

    Returns (score 0..1, evidence).
    """
    if not required_paths:
        return 0.0, []

    turns = turns_from_buffer(buffer)
    if len(turns) < after_turns:
        return 0.0, []

    # Collect all files touched in the session
    all_touched: set[str] = set()
    for action in buffer.actions:
        if action.file_path:
            all_touched.add(action.file_path)

    missing: list[str] = []
    for req in required_paths:
        # Check both exact match and suffix match
        found = any(t == req or t.endswith("/" + req) for t in all_touched)
        if not found:
            missing.append(req)

    if not missing:
        return 0.0, []

    score = min(len(missing) / max(len(required_paths), 1), 1.0)
    evidence = [f"required path not yet touched after {after_turns} turns: {p}" for p in missing[:3]]
    return round(score, 4), evidence


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_constraints(
    buffer: "ActionBuffer",
    *,
    no_new_deps: bool = False,
    dependency_manifests: frozenset[str] | None = None,
    forbidden_prefixes: list[str] | None = None,
    must_touch_paths: list[str] | None = None,
    must_touch_after: int = 6,
) -> MetricResult:
    """Compute the constraint-violations metric.

    All rules are opt-in via constructor arguments.
    """
    manifests = dependency_manifests or DEFAULT_DEPENDENCY_MANIFESTS
    forbidden = forbidden_prefixes or []
    must = must_touch_paths or []

    sub_results: list[MetricResult] = []
    scores: list[float] = []

    if no_new_deps:
        dep_score, dep_ev = _no_new_deps(buffer, manifests)
        sub_results.append(MetricResult(name="no_new_deps", value=dep_score, evidence=dep_ev))
        scores.append(dep_score)

    if forbidden:
        fp_score, fp_ev = _forbidden_paths(buffer, forbidden)
        sub_results.append(MetricResult(name="forbidden_paths", value=fp_score, evidence=fp_ev))
        scores.append(fp_score)

    if must:
        mt_score, mt_ev = _must_touch(buffer, must, after_turns=must_touch_after)
        sub_results.append(MetricResult(name="must_touch", value=mt_score, evidence=mt_ev))
        scores.append(mt_score)

    if not scores:
        return MetricResult(name="constraint", value=0.0)

    # Take the *max* of active constraint violations (any violation is bad)
    combined = max(scores)
    evidence: list[str] = []
    for r in sub_results:
        evidence.extend(r.evidence)

    return MetricResult(
        name="constraint",
        value=round(min(combined, 1.0), 4),
        evidence=evidence,
        contributors=sub_results,
    )
