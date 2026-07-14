"""Tests for session efficiency scoring (pure operational metrics)."""

from datetime import datetime, timedelta

from agentwatch.health.score import EfficiencyReport, calculate_efficiency
from agentwatch.parser.models import Action, ActionBuffer, ToolType
from agentwatch.themes import get_theme


def _make_action(
    tokens_in: int = 100,
    tokens_out: int = 50,
    cost_usd: float = 0.0,
    cache_creation_tokens: int = 0,
    cache_read_tokens: int = 0,
    outgoing_data: str | None = None,
    tool_type: ToolType = ToolType.READ,
    success: bool = True,
    file_path: str | None = None,
    timestamp: datetime | None = None,
) -> Action:
    return Action(
        timestamp=timestamp or datetime.now(),
        tool_name=tool_type.value,
        tool_type=tool_type,
        success=success,
        file_path=file_path,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cost_usd=cost_usd,
        cache_creation_tokens=cache_creation_tokens,
        cache_read_tokens=cache_read_tokens,
        outgoing_data=outgoing_data,
    )


class TestFreshSession:
    """Low tokens, no cost, good cache → score >= 90."""

    def test_empty_buffer(self):
        buffer = ActionBuffer(max_size=2000)
        report = calculate_efficiency([], buffer)
        theme = get_theme()
        assert report.score == 100
        assert report.status == theme.level_0  # Best status (e.g., "productive")
        assert report.recommendation == f"Session is {theme.level_0}"
        assert report.penalty_context == 0.0
        assert report.penalty_cache == 0.0
        assert report.penalty_pacing == 0.0

    def test_few_low_token_actions(self):
        buffer = ActionBuffer(max_size=2000)
        now = datetime.now()
        # Space actions over 5 minutes ending now so duration_minutes > 0
        for i in range(5):
            buffer.add(_make_action(
                tokens_in=200,
                tokens_out=100,
                cache_creation_tokens=50,
                cache_read_tokens=150,
                outgoing_data=f"response {i}" if i % 2 == 0 else None,
                timestamp=now - timedelta(minutes=4 - i),
            ))
        report = calculate_efficiency([], buffer)
        theme = get_theme()
        assert report.score >= 90, f"Expected >=90, got {report.score}"
        assert report.status == theme.level_0  # Best status


class TestHighBurn:
    """High tokens/min → score drops from burn rate penalty."""

    def test_high_burn_rate(self):
        buffer = ActionBuffer(max_size=2000)
        now = datetime.now()
        # 40k tokens in ~1 minute → burn rate well above 30k/min threshold
        for i in range(10):
            buffer.add(_make_action(
                tokens_in=3000,
                tokens_out=1000,
                timestamp=now + timedelta(seconds=i * 6),
            ))
        report = calculate_efficiency([], buffer)
        assert report.token_burn_rate > 5000
        # Burn rate penalty should pull score below 100
        assert report.score < 95, f"Expected <95, got {report.score}"


class TestContextPressure:
    """Many high-token actions → pressure penalty."""

    def test_heavy_context_usage(self):
        buffer = ActionBuffer(max_size=2000)
        now = datetime.now()
        # Simulate cache-heavy session: each action reads ~40k from cache
        # 40 actions × (3k in + 40k cache_read + 1k out) = ~1.76M throughput
        # against 2M budget → ~88% pressure
        for i in range(40):
            buffer.add(_make_action(
                tokens_in=3000,
                tokens_out=1000,
                cache_read_tokens=40000,
                timestamp=now + timedelta(minutes=i),
            ))
        report = calculate_efficiency([], buffer)
        assert report.context_usage_pct >= 70
        assert report.score < 85, f"Expected <85 with heavy context, got {report.score}"


class TestCacheThrash:
    """Cache creation >> reads → cache penalty."""

    def test_all_creation_no_reads(self):
        buffer = ActionBuffer(max_size=2000)
        now = datetime.now()
        for i in range(10):
            buffer.add(_make_action(
                tokens_in=500,
                tokens_out=200,
                cache_creation_tokens=1000,
                cache_read_tokens=0,
                timestamp=now + timedelta(seconds=i * 30),
            ))
        report = calculate_efficiency([], buffer)
        assert report.cache_hit_rate == 0.0
        assert report.penalty_cache == 1.0  # full miss penalty
        # Full cache penalty (15% weight) should reduce score
        assert report.score <= 90, f"Expected <=90, got {report.score}"

    def test_good_cache_reuse(self):
        buffer = ActionBuffer(max_size=2000)
        now = datetime.now()
        for i in range(10):
            buffer.add(_make_action(
                tokens_in=500,
                tokens_out=200,
                cache_creation_tokens=100,
                cache_read_tokens=900,
                timestamp=now + timedelta(seconds=i * 30),
            ))
        report = calculate_efficiency([], buffer)
        assert report.cache_hit_rate >= 0.8


class TestLongSession:
    """start_time far in past → duration penalty."""

    def test_90min_session(self):
        buffer = ActionBuffer(max_size=2000)
        now = datetime.now()
        start = now - timedelta(minutes=90)
        # First action sets start_time
        buffer.add(_make_action(
            tokens_in=200,
            tokens_out=100,
            timestamp=start,
        ))
        # A few more recent actions
        for i in range(5):
            buffer.add(_make_action(
                tokens_in=200,
                tokens_out=100,
                timestamp=now - timedelta(minutes=5 - i),
            ))
        report = calculate_efficiency([], buffer)
        assert report.duration_minutes >= 85
        # Duration penalty (10% weight at full) should pull score down
        assert report.score < 95, f"Expected <95 for 90min session, got {report.score}"


class TestCostVelocity:
    """High costUSD entries → cost penalty."""

    def test_expensive_session(self):
        buffer = ActionBuffer(max_size=2000)
        now = datetime.now()
        # $0.50/min for 5 min = $2.50 total, well above $0.30/min threshold
        for i in range(10):
            buffer.add(_make_action(
                tokens_in=5000,
                tokens_out=2000,
                cost_usd=0.25,
                timestamp=now + timedelta(seconds=i * 30),
            ))
        report = calculate_efficiency([], buffer)
        assert report.cost_total > 2.0
        assert report.cost_velocity > 0.30
        # Cost is informational only — not part of the penalty score


class TestReportFields:
    """Verify to_dict() keys match the new EfficiencyReport."""

    def test_to_dict_keys(self):
        theme = get_theme()
        report = EfficiencyReport(
            score=72,
            status=theme.level_1,  # Degraded equivalent
            recommendation="Session efficiency declining — consider wrapping up soon",
            context_usage_pct=55.0,
            token_burn_rate=12000.0,
            io_ratio=10.5,
            cost_total=1.20,
            cost_velocity=0.15,
            cache_hit_rate=0.65,
            actions_per_turn=2.3,
            duration_minutes=45.0,
        )
        d = report.to_dict()
        expected_keys = {
            "score",
            "status",
            "recommendation",
            "context_usage_pct",
            "token_burn_rate",
            "io_ratio",
            "cost_total",
            "cost_velocity",
            "cache_hit_rate",
            "actions_per_turn",
            "duration_minutes",
            "penalty_context",
            "penalty_cache",
            "penalty_pacing",
        }
        assert set(d.keys()) == expected_keys
        assert d["score"] == 72
        assert d["status"] == theme.level_1  # Degraded equivalent
        assert d["cache_hit_rate"] == 0.65
        assert d["penalty_context"] == 0.0
