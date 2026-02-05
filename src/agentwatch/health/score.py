"""Health score calculation from warnings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentwatch.detectors.base import Warning
    from agentwatch.parser.models import ActionBuffer

from agentwatch.detectors.base import Category, Severity
from agentwatch.themes import (
    get_theme,
    status_from_score as _theme_status_from_score,
    get_status_emojis,
    get_status_labels,
)


# ---------------------------------------------------------------------------
# Unified status thresholds — shared by health, efficiency, and rot display
# ---------------------------------------------------------------------------

STATUS_THRESHOLDS = (80, 60, 40)  # level_0 / level_1 / level_2 / level_3


def STATUS_LABELS() -> tuple[str, str, str, str]:
    """Get status labels from current theme."""
    return get_status_labels()


def _STATUS_EMOJI() -> dict[str, str]:
    """Get status emojis from current theme."""
    return get_status_emojis()


def _score_to_status(score: int) -> str:
    """Map a 0-100 score to a unified status label using current theme."""
    return _theme_status_from_score(float(score))


@dataclass
class CategoryScore:
    """Score for a single category."""
    
    category: Category
    score: int  # 0-100
    warnings: list["Warning"] = field(default_factory=list)
    
    @property
    def status(self) -> str:
        return _score_to_status(self.score)

    @property
    def emoji(self) -> str:
        return _STATUS_EMOJI().get(self.status, "❓")


@dataclass
class HealthReport:
    """Complete health report with category breakdown."""

    overall_score: int
    category_scores: dict[Category, CategoryScore]
    warnings: list["Warning"]

    @property
    def status(self) -> str:
        return _score_to_status(self.overall_score)

    @property
    def emoji(self) -> str:
        return _STATUS_EMOJI().get(self.status, "❓")
    
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
    weights: HealthWeights | None = None,
) -> HealthReport:
    """
    Calculate health scores from warnings.

    Args:
        warnings: List of warnings from detectors
        include_security: Whether to include security categories in overall score
        efficiency_score: Optional 0-100 efficiency score to blend into overall
        rot_score: Optional 0.0-1.0 rot score (0 = healthy, 1 = degraded)
            to blend into overall health
        weights: Optional blend weights for detectors/efficiency/rot

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
    w = weights or HealthWeights()
    has_extras = efficiency_score is not None or rot_score is not None
    if has_extras:
        eff = efficiency_score if efficiency_score is not None else 100
        # rot_score is 0..1 (0=healthy).  Invert to 0-100 health scale.
        rot_health = int((1.0 - rot_score) * 100) if rot_score is not None else 100

        overall_score = int(
            detector_score * w.detectors
            + eff * w.efficiency
            + rot_health * w.rot
        )
        overall_score = max(0, min(100, overall_score))
    else:
        overall_score = detector_score

    return HealthReport(
        overall_score=overall_score,
        category_scores=category_scores,
        warnings=warnings,
    )


@dataclass
class HealthWeights:
    """Configurable blend weights for overall health score.

    Must sum to 1.0.  Passed to ``calculate_health`` to control how
    detector warnings, efficiency, and rot contribute to the overall score.
    """

    detectors: float = 0.40
    efficiency: float = 0.30
    rot: float = 0.30


@dataclass
class EfficiencyReport:
    """Session efficiency report based on pure operational resource metrics."""

    score: int  # 0-100
    status: str  # theme-dependent status label
    recommendation: str
    context_usage_pct: float  # 0-100
    token_burn_rate: float  # tokens/min
    io_ratio: float  # input/output token ratio
    cost_total: float  # cumulative USD
    cost_velocity: float  # USD/min
    cache_hit_rate: float  # 0.0-1.0
    actions_per_turn: float  # avg tool calls per model response
    duration_minutes: float  # wall clock
    # Per-category penalty rollups (0.0 = healthy, 1.0 = full penalty)
    penalty_context: float = 0.0  # max(pressure, burn, io)
    penalty_cache: float = 0.0    # cache miss penalty
    penalty_pacing: float = 0.0   # max(duration, actions_turn)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "status": self.status,
            "recommendation": self.recommendation,
            "context_usage_pct": self.context_usage_pct,
            "token_burn_rate": self.token_burn_rate,
            "io_ratio": self.io_ratio,
            "cost_total": self.cost_total,
            "cost_velocity": self.cost_velocity,
            "cache_hit_rate": self.cache_hit_rate,
            "actions_per_turn": self.actions_per_turn,
            "duration_minutes": self.duration_minutes,
            "penalty_context": self.penalty_context,
            "penalty_cache": self.penalty_cache,
            "penalty_pacing": self.penalty_pacing,
        }


# Sub-metric weights for efficiency scoring (sum to 1.0)
# Cost is excluded — not reported in logs; displayed as informational only.
_W_CONTEXT_PRESSURE = 0.30
_W_BURN_RATE = 0.20
_W_IO_RATIO = 0.10
_W_CACHE_HIT = 0.15
_W_ACTIONS_TURN = 0.10
_W_DURATION = 0.15

# Context window and session budget estimates (tokens).
# The window is the model's context limit.  The budget is the total
# throughput (input+cache+output summed across all turns) at which we
# consider the session fully pressured — roughly 10× the window to
# account for cache-heavy workloads where the same ~200k window is
# refilled on every turn.
_CONTEXT_WINDOW = 200_000
_SESSION_BUDGET = 2_000_000


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def calculate_efficiency(
    warnings: list["Warning"],
    buffer: "ActionBuffer",
) -> EfficiencyReport:
    """Calculate session efficiency from pure operational resource metrics.

    ``warnings`` is accepted for call-site compatibility but ignored — all
    signals are derived from the action buffer and its stats.
    """
    from agentwatch.parser.models import turns_from_buffer

    stats = buffer.stats
    duration = stats.duration_minutes
    action_count = stats.action_count

    # Full input including cache — used for pressure, burn rate, and I/O ratio.
    full_input = stats.total_input_tokens + stats.total_cache_creation + stats.total_cache_read
    full_throughput = full_input + stats.total_output_tokens
    # Fall back to total_tokens when no cache data is available.
    if full_throughput == 0:
        full_throughput = stats.total_tokens
        full_input = stats.total_tokens

    # --- 1. Context pressure (linear 0→1 as usage 0→100%) ---
    # Uses cumulative throughput against a session budget rather than
    # current window fill.  This is monotonically increasing — it never
    # drops after auto-compaction or tool restart, because cumulative
    # totals are replayed from the log.
    context_usage_pct = min(full_throughput / _SESSION_BUDGET * 100, 100.0)
    pressure_penalty = _clamp01(context_usage_pct / 100.0)

    # --- 2. Token burn rate (0 at ≤5k tok/min, 1.0 at ≥30k) ---
    # Skip penalty for very short sessions where rate naturally spikes
    burn_rate = full_throughput / duration if duration > 0 else 0.0
    if duration >= 2.0:
        burn_penalty = _clamp01((burn_rate - 5_000) / (30_000 - 5_000))
    else:
        burn_penalty = 0.0

    # --- 3. I/O ratio (0 at ratio≤8, 1.0 at ratio≥20) ---
    # Skip penalty for very short sessions where ratio hasn't stabilized
    io_ratio = (
        full_input / stats.total_output_tokens
        if stats.total_output_tokens > 0
        else 0.0
    )
    if duration >= 2.0:
        io_penalty = _clamp01((io_ratio - 8.0) / (20.0 - 8.0))
    else:
        io_penalty = 0.0

    # --- 4. Cost velocity (0 at ≤$0.05/min, 1.0 at ≥$0.30/min) ---
    cost_total = stats.estimated_cost
    cost_vel = cost_total / duration if duration > 0 else 0.0
    cost_penalty = _clamp01((cost_vel - 0.05) / (0.30 - 0.05))

    # --- 5. Cache hit rate (penalty = 1 - hit_rate; 0 if no cache data) ---
    total_cache = stats.total_cache_creation + stats.total_cache_read
    cache_hit_rate = (
        stats.total_cache_read / total_cache if total_cache > 0 else 0.0
    )
    cache_penalty = (1.0 - cache_hit_rate) if total_cache > 0 else 0.0

    # --- 6. Actions per turn (ramp below 1.5; skip if <5 actions) ---
    turns = turns_from_buffer(buffer)
    if turns:
        apt = action_count / len(turns)
    else:
        apt = 0.0
    if action_count >= 5:
        actions_turn_penalty = _clamp01((1.5 - apt) / 1.5)
    else:
        actions_turn_penalty = 0.0

    # --- 7. Duration (0 at ≤30min, 1.0 at ≥90min) ---
    duration_penalty = _clamp01((duration - 30.0) / (90.0 - 30.0))

    # --- Weighted penalty sum (cost excluded — informational only) ---
    total_penalty = (
        pressure_penalty * _W_CONTEXT_PRESSURE
        + burn_penalty * _W_BURN_RATE
        + io_penalty * _W_IO_RATIO
        + cache_penalty * _W_CACHE_HIT
        + actions_turn_penalty * _W_ACTIONS_TURN
        + duration_penalty * _W_DURATION
    )

    score = max(0, min(100, int(100 * (1.0 - total_penalty))))

    status = _score_to_status(score)

    # Recommendation using theme labels
    theme = get_theme()
    if score >= 80:
        recommendation = f"Session is {theme.level_0}"
    elif score >= 60:
        recommendation = "Session efficiency declining — consider wrapping up soon"
    elif score >= 40:
        recommendation = f"Session is {theme.level_1} — start planning a fresh session"
    else:
        recommendation = "Consider starting a fresh session"

    return EfficiencyReport(
        score=score,
        status=status,
        recommendation=recommendation,
        context_usage_pct=round(context_usage_pct, 1),
        token_burn_rate=round(burn_rate, 1),
        io_ratio=round(io_ratio, 2),
        cost_total=round(cost_total, 4),
        cost_velocity=round(cost_vel, 4),
        cache_hit_rate=round(cache_hit_rate, 3),
        actions_per_turn=round(apt, 2),
        duration_minutes=round(duration, 1),
        penalty_context=round(max(pressure_penalty, burn_penalty, io_penalty), 4),
        penalty_cache=round(cache_penalty, 4),
        penalty_pacing=round(max(duration_penalty, actions_turn_penalty), 4),
    )


@dataclass
class TeamHealthReport:
    """Aggregate health report for a team of agents."""

    team_id: int
    team_name: str
    overall_score: int  # 0-100 weighted average of members
    member_scores: dict[int, int]  # pid -> score
    member_count: int
    subagent_count: int
    cross_agent_warnings: list["Warning"]  # team-level patterns

    @property
    def status(self) -> str:
        return _score_to_status(self.overall_score)

    def to_dict(self) -> dict:
        return {
            "team_id": self.team_id,
            "team_name": self.team_name,
            "overall_score": self.overall_score,
            "status": self.status,
            "member_scores": self.member_scores,
            "member_count": self.member_count,
            "subagent_count": self.subagent_count,
            "cross_agent_warnings": [w.to_dict() for w in self.cross_agent_warnings],
        }


def calculate_team_health(
    member_reports: dict[int, HealthReport],
    root_pid: int,
    team_name: str = "",
) -> TeamHealthReport:
    """Calculate aggregate health for a team of agents.

    The root agent's score is weighted more heavily (50%), while
    sub-agents split the remaining 50% equally.  If multiple sub-agents
    are struggling, a cross-agent warning is emitted.
    """
    from agentwatch.detectors.base import Warning as Warn, Category, Severity

    if not member_reports:
        return TeamHealthReport(
            team_id=root_pid,
            team_name=team_name,
            overall_score=100,
            member_scores={},
            member_count=0,
            subagent_count=0,
            cross_agent_warnings=[],
        )

    member_scores: dict[int, int] = {
        pid: r.overall_score for pid, r in member_reports.items()
    }
    subagent_pids = [pid for pid in member_reports if pid != root_pid]

    # Weighted average: root gets 50%, subagents split 50%
    root_score = member_scores.get(root_pid, 100)
    if subagent_pids:
        sub_avg = sum(member_scores[p] for p in subagent_pids) / len(subagent_pids)
        overall = int(root_score * 0.5 + sub_avg * 0.5)
    else:
        overall = root_score

    overall = max(0, min(100, overall))

    # Cross-agent pattern detection
    cross_warnings: list[Warn] = []

    # Pattern: majority of sub-agents struggling
    if len(subagent_pids) >= 2:
        struggling = sum(1 for p in subagent_pids if member_scores[p] < 60)
        if struggling >= len(subagent_pids) * 0.5:
            cross_warnings.append(
                Warn(
                    category=Category.PROGRESS,
                    severity=Severity.HIGH,
                    signal="team_cascade_failure",
                    message=f"{struggling}/{len(subagent_pids)} sub-agents are struggling",
                    suggestion="Root agent may be issuing unclear instructions or an impossible task",
                    details={"struggling_count": struggling, "total_subagents": len(subagent_pids)},
                )
            )

    # Pattern: root healthy but sub-agents failing
    if root_score >= 80 and subagent_pids:
        sub_critical = sum(1 for p in subagent_pids if member_scores[p] < 40)
        if sub_critical > 0:
            cross_warnings.append(
                Warn(
                    category=Category.PROGRESS,
                    severity=Severity.MEDIUM,
                    signal="subagent_distress",
                    message=f"{sub_critical} sub-agent(s) in critical state while root is healthy",
                    suggestion="Review sub-agent task assignments for feasibility",
                    details={"critical_subagents": sub_critical},
                )
            )

    # Apply cross-agent penalty
    if cross_warnings:
        penalty = sum(w.severity.score_impact for w in cross_warnings)
        overall = max(0, overall - penalty)

    return TeamHealthReport(
        team_id=root_pid,
        team_name=team_name,
        overall_score=overall,
        member_scores=member_scores,
        member_count=len(member_reports),
        subagent_count=len(subagent_pids),
        cross_agent_warnings=cross_warnings,
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
