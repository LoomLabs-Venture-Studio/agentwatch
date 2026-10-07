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
        # 100k tokens over ~2.4 minutes → ~41.6k tokens/min, well above the
        # 30k/min threshold. Session must exceed the 2-minute "very short
        # session" grace period (score.py) for the burn penalty to apply.
        for i in range(25):
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
        # Pressure is the latest call's context vs. the window (200K here,
        # since no call exceeds 200K). Each call reads ~170K of context
        # (3k fresh + 167k cache_read) -> ~85% of a 200K window.
        for i in range(40):
            buffer.add(_make_action(
                tokens_in=3000,
                tokens_out=1000,
                cache_read_tokens=167000,
                timestamp=now + timedelta(minutes=i),
            ))
        report = calculate_efficiency([], buffer)
        assert report.context_usage_pct >= 70
        assert report.score < 85, f"Expected <85 with heavy context, got {report.score}"

    def test_cached_session_does_not_saturate(self):
        """Regression (#36): a normal 20-minute cached session re-sends ~60K
        of context per call. Summing cache reads across calls used to hit
        100% pressure; window fill of the latest call is ~31%."""
        buffer = ActionBuffer(max_size=2000)
        now = datetime.now()
        for i in range(40):
            buffer.add(_make_action(
                tokens_in=2000,
                tokens_out=500,
                cache_read_tokens=60000,
                timestamp=now + timedelta(seconds=i * 30),
            ))
        report = calculate_efficiency([], buffer)
        assert 25 <= report.context_usage_pct <= 35, report.context_usage_pct

    def test_pressure_drops_after_compaction(self):
        buffer = ActionBuffer(max_size=2000)
        now = datetime.now()
        for i in range(5):
            buffer.add(_make_action(
                tokens_in=2000, cache_read_tokens=178000,
                timestamp=now + timedelta(seconds=i * 30),
            ))
        buffer.add(_make_action(
            tokens_in=2000, cache_read_tokens=28000,
            timestamp=now + timedelta(seconds=300),
        ))
        report = calculate_efficiency([], buffer)
        assert report.context_usage_pct == 15.0  # 30K / 200K

    def test_call_above_200k_promotes_to_1m_window(self):
        buffer = ActionBuffer(max_size=2000)
        buffer.add(_make_action(tokens_in=10000, cache_read_tokens=240000))
        report = calculate_efficiency([], buffer)
        assert report.context_usage_pct == 25.0  # 250K / 1M

    def test_zero_usage_action_keeps_last_context(self):
        buffer = ActionBuffer(max_size=2000)
        now = datetime.now()
        buffer.add(_make_action(tokens_in=2000, cache_read_tokens=98000, timestamp=now))
        buffer.add(_make_action(
            tokens_in=0, tokens_out=0, success=False,
            timestamp=now + timedelta(seconds=5),
        ))
        assert buffer.stats.last_context_tokens == 100000
        report = calculate_efficiency([], buffer)
        assert report.context_usage_pct == 50.0


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
        # Active for 90 minutes: an action every 15 minutes (idle gaps over
        # 30 minutes are capped, #38).
        for i in range(7):
            buffer.add(_make_action(
                tokens_in=200,
                tokens_out=100,
                timestamp=now - timedelta(minutes=90 - 15 * i),
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


class TestCacheReadsExcludedFromBurn:
    """Regression #36: cache reads must not drive burn rate or I/O ratio."""

    def test_cache_heavy_session_not_penalized_for_burn_or_io(self):
        buffer = ActionBuffer(max_size=2000)
        now = datetime.now()
        # ~4 minutes, 50k cache reads per call (99% hit rate), small fresh
        # input, modest output. Each call fills ~51K of a 200K window, so
        # context pressure stays ~25% and the score isolates burn/io.
        # Old code: ~270k tok/min, io ratio ~170.
        for i in range(20):
            buffer.add(_make_action(
                tokens_in=200,
                tokens_out=300,
                cache_creation_tokens=500,
                cache_read_tokens=50_000,
                timestamp=now + timedelta(seconds=i * 12),
            ))
        report = calculate_efficiency([], buffer)
        assert report.duration_minutes >= 2.0
        assert report.token_burn_rate < 30_000, report.token_burn_rate
        assert report.io_ratio < 8.0, report.io_ratio
        assert report.score >= 75, f"Expected >=75, got {report.score}"


def _report(duration_minutes: float) -> EfficiencyReport:
    return EfficiencyReport(
        score=90, status=get_theme().level_0, recommendation="ok",
        context_usage_pct=10.0, token_burn_rate=725_834.0, io_ratio=1.0,
        cost_total=0.50, cost_velocity=12.34, cache_hit_rate=0.5,
        actions_per_turn=1.0, duration_minutes=duration_minutes,
    )


def test_tui_hides_rates_for_short_sessions():
    """#45: under 2 active minutes, tok/min and $/min show "--"."""
    from agentwatch.ui.app import EfficiencyBar

    bar = EfficiencyBar()
    bar._report = _report(0.0)
    short = bar._build_content()
    assert "-- tok/min" in short and "(--/min)" in short
    assert "725.8k" not in short and "12.34" not in short

    bar._report = _report(2.0)
    warm = bar._build_content()
    assert "725.8k tok/min" in warm and "($12.34/min)" in warm
