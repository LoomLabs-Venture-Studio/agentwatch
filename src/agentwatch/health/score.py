"""Health score calculation from warnings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentwatch.detectors.base import Warning
    from agentwatch.parser.models import ActionBuffer

from agentwatch.detectors.base import Category, Severity


@dataclass
class CategoryScore:
    """Score for a single category."""
    
    category: Category
    score: int  # 0-100
    warnings: list["Warning"] = field(default_factory=list)
    
    @property
    def status(self) -> str:
        if self.score >= 80:
            return "healthy"
        elif self.score >= 50:
            return "warning"
        else:
            return "critical"
    
    @property
    def emoji(self) -> str:
        if self.score >= 80:
            return "✅"
        elif self.score >= 50:
            return "⚠️"
        else:
            return "🔴"


@dataclass
class HealthReport:
    """Complete health report with category breakdown."""
    
    overall_score: int
    category_scores: dict[Category, CategoryScore]
    warnings: list["Warning"]
    
    @property
    def status(self) -> str:
        if self.overall_score >= 80:
            return "healthy"
        elif self.overall_score >= 50:
            return "warning"
        else:
            return "critical"
    
    @property
    def emoji(self) -> str:
        if self.overall_score >= 80:
            return "✅"
        elif self.overall_score >= 50:
            return "⚠️"
        else:
            return "🔴"
    
    @property
    def health_warnings(self) -> list["Warning"]:
        """Get only health-related warnings."""
        return [w for w in self.warnings if w.is_health]
    
    @property
    def security_warnings(self) -> list["Warning"]:
        """Get only security-related warnings."""
        return [w for w in self.warnings if w.is_security]
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "overall_score": self.overall_score,
            "status": self.status,
            "categories": {
                cat.value: {
                    "score": cs.score,
                    "status": cs.status,
                    "warning_count": len(cs.warnings),
                }
                for cat, cs in self.category_scores.items()
            },
            "warnings": [w.to_dict() for w in self.warnings],
            "health_warning_count": len(self.health_warnings),
            "security_warning_count": len(self.security_warnings),
        }


# Category weights for health scoring
HEALTH_CATEGORY_WEIGHTS = {
    Category.PROGRESS: 0.35,
    Category.ERRORS: 0.30,
    Category.CONTEXT: 0.20,
    Category.GOAL: 0.15,
}

# Security categories have equal weight
SECURITY_CATEGORY_WEIGHTS = {
    Category.CREDENTIAL: 0.20,
    Category.INJECTION: 0.25,
    Category.EXFILTRATION: 0.20,
    Category.PRIVILEGE: 0.15,
    Category.NETWORK: 0.10,
    Category.SUPPLY_CHAIN: 0.10,
}


def calculate_health(
    warnings: list["Warning"],
    include_security: bool = False,
    efficiency_score: int | None = None,
    rot_score: float | None = None,
) -> HealthReport:
    """
    Calculate health scores from warnings.

    Args:
        warnings: List of warnings from detectors
        include_security: Whether to include security categories in overall score
        efficiency_score: Optional 0-100 efficiency score to blend into overall
        rot_score: Optional 0.0-1.0 rot score (0 = healthy, 1 = degraded)
            to blend into overall health

    Returns:
        HealthReport with overall and category scores
    """
    # Separate warnings by category
    category_warnings: dict[Category, list["Warning"]] = {}
    for warning in warnings:
        cat = warning.category
        if cat not in category_warnings:
            category_warnings[cat] = []
        category_warnings[cat].append(warning)

    # Calculate per-category scores
    category_scores: dict[Category, CategoryScore] = {}

    # Determine which categories to include
    if include_security:
        all_weights = {**HEALTH_CATEGORY_WEIGHTS, **SECURITY_CATEGORY_WEIGHTS}
    else:
        all_weights = HEALTH_CATEGORY_WEIGHTS

    for cat in Category:
        cat_warnings = category_warnings.get(cat, [])

        # Start at 100, deduct based on severity
        score = 100
        for w in cat_warnings:
            score -= w.severity.score_impact

        score = max(0, score)  # Floor at 0

        category_scores[cat] = CategoryScore(
            category=cat,
            score=score,
            warnings=cat_warnings,
        )

    # Calculate weighted detector-category score
    total_weight = 0
    weighted_score = 0

    for cat, weight in all_weights.items():
        if cat in category_scores:
            weighted_score += category_scores[cat].score * weight
            total_weight += weight

    detector_score = int(weighted_score / total_weight) if total_weight > 0 else 100

    # Blend in efficiency and rot scores when provided.
    # Weight split: detectors 60%, efficiency 20%, rot 20%.
    has_extras = efficiency_score is not None or rot_score is not None
    if has_extras:
        eff = efficiency_score if efficiency_score is not None else 100
        # rot_score is 0..1 (0=healthy).  Invert to 0-100 health scale.
        rot_health = int((1.0 - rot_score) * 100) if rot_score is not None else 100

        overall_score = int(
            detector_score * _DETECTOR_WEIGHT
            + eff * _EFFICIENCY_WEIGHT
            + rot_health * _ROT_WEIGHT
        )
        overall_score = max(0, min(100, overall_score))
    else:
        overall_score = detector_score

    return HealthReport(
        overall_score=overall_score,
        category_scores=category_scores,
        warnings=warnings,
    )


# Blend weights for overall health (must sum to 1.0)
_DETECTOR_WEIGHT = 0.60
_EFFICIENCY_WEIGHT = 0.20
_ROT_WEIGHT = 0.20


@dataclass
class EfficiencyReport:
    """Session efficiency report measuring remaining runway."""

    score: int  # 0-100
    status: str  # "efficient", "degraded", "wasteful"
    context_usage_pct: float
    waste_ratio: float
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "status": self.status,
            "context_usage_pct": self.context_usage_pct,
            "waste_ratio": self.waste_ratio,
            "recommendation": self.recommendation,
        }


# Weights for efficiency scoring (must sum to 1.0)
_CONTEXT_PRESSURE_WEIGHT = 0.45
_CONTEXT_ROT_WEIGHT = 0.20
_REDISCOVERY_WEIGHT = 0.10
_WASTE_RATIO_WEIGHT = 0.25


def calculate_efficiency(
    warnings: list["Warning"],
    buffer: "ActionBuffer",
) -> EfficiencyReport:
    """
    Calculate session efficiency score.

    Measures how much useful runway the session has left before a fresh
    session would be more productive.
    """
    # --- Context pressure (biggest factor) ---
    context_usage_pct = 0.0
    for w in warnings:
        if w.category == Category.CONTEXT and w.signal in ("context_pressure", "context_critical"):
            context_usage_pct = w.details.get("usage_percent", 0) / 100.0
            break

    # Map usage ratio to a penalty: 0% usage = 0 penalty, 100% = full penalty
    pressure_penalty = context_usage_pct  # linear 0-1

    # --- Context rot ---
    rot_count = 0
    for w in warnings:
        if w.category == Category.CONTEXT and w.signal == "context_rot":
            forgotten = w.details.get("forgotten_files", [])
            rot_count = len(forgotten) if isinstance(forgotten, list) else 0
            break

    # Cap rot penalty: 5+ forgotten files = full penalty
    rot_penalty = min(rot_count / 5.0, 1.0)

    # --- Rediscovery ---
    rediscovery_count = 0
    for w in warnings:
        if w.category == Category.CONTEXT and w.signal == "rediscovery":
            rediscovery_count = w.details.get("rediscovery_count", 0)
            break

    # Cap: 4+ rediscoveries = full penalty
    rediscovery_penalty = min(rediscovery_count / 4.0, 1.0)

    # --- Action waste ratio ---
    actions = list(buffer.actions)
    total_actions = len(actions)
    waste_ratio = 0.0

    if total_actions > 0:
        failed_bashes = sum(
            1 for a in actions if a.is_bash and not a.success
        )

        # Duplicate reads: reading a file already read in the last 50 actions
        duplicate_reads = 0
        for i, action in enumerate(actions):
            if action.is_file_read and action.file_path:
                window_start = max(0, i - 50)
                for j in range(window_start, i):
                    prev = actions[j]
                    if prev.is_file_read and prev.file_path == action.file_path:
                        duplicate_reads += 1
                        break

        waste_ratio = (failed_bashes + duplicate_reads) / total_actions

    # Cap waste ratio penalty at 1.0
    waste_penalty = min(waste_ratio / 0.3, 1.0)  # 30%+ waste = full penalty

    # --- Combine into score ---
    total_penalty = (
        pressure_penalty * _CONTEXT_PRESSURE_WEIGHT
        + rot_penalty * _CONTEXT_ROT_WEIGHT
        + rediscovery_penalty * _REDISCOVERY_WEIGHT
        + waste_penalty * _WASTE_RATIO_WEIGHT
    )

    score = max(0, min(100, int(100 * (1.0 - total_penalty))))

    # Status
    if score >= 70:
        status = "efficient"
    elif score >= 40:
        status = "degraded"
    else:
        status = "wasteful"

    # Recommendation
    if score >= 80:
        recommendation = "Session is healthy"
    elif score >= 60:
        recommendation = "Session efficiency declining — consider wrapping up soon"
    elif score >= 40:
        recommendation = "Session is degraded — start planning a fresh session"
    else:
        recommendation = "Consider starting a fresh session"

    return EfficiencyReport(
        score=score,
        status=status,
        context_usage_pct=round(context_usage_pct * 100, 1),
        waste_ratio=round(waste_ratio, 3),
        recommendation=recommendation,
    )


def calculate_security_score(warnings: list["Warning"]) -> int:
    """
    Calculate a security-specific score.
    
    Returns:
        Score from 0-100 (100 = secure, 0 = compromised)
    """
    security_warnings = [w for w in warnings if w.is_security]
    
    if not security_warnings:
        return 100
    
    # Security is more strict - critical = immediate 0
    for w in security_warnings:
        if w.severity == Severity.CRITICAL:
            return 0
    
    # Otherwise deduct based on severity
    score = 100
    for w in security_warnings:
        score -= w.severity.score_impact
    
    return max(0, score)
