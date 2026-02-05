"""Tests for team health scoring."""

from agentwatch.detectors.base import Category, Severity, Warning
from agentwatch.health.score import (
    HealthReport,
    CategoryScore,
    TeamHealthReport,
    calculate_team_health,
)


def _make_report(overall_score: int) -> HealthReport:
    """Create a minimal HealthReport with the given score."""
    return HealthReport(
        overall_score=overall_score,
        category_scores={},
        warnings=[],
    )


class TestCalculateTeamHealth:
    def test_empty_members(self):
        """Empty team returns 100 score."""
        report = calculate_team_health({}, root_pid=100)
        assert report.overall_score == 100
        assert report.member_count == 0

    def test_solo_root(self):
        """Single root agent: team score = root score."""
        report = calculate_team_health(
            {100: _make_report(75)},
            root_pid=100,
            team_name="test-team",
        )
        assert report.overall_score == 75
        assert report.member_count == 1
        assert report.subagent_count == 0
        assert report.team_name == "test-team"

    def test_root_and_subagents_weighted(self):
        """Root 50% weight, sub-agents share 50%."""
        report = calculate_team_health(
            {100: _make_report(80), 200: _make_report(70), 300: _make_report(90)},
            root_pid=100,
        )
        # root=80*0.5=40, sub_avg=(70+90)/2=80*0.5=40, total=80
        assert report.overall_score == 80
        assert report.subagent_count == 2

    def test_cascade_failure_warning(self):
        """Triggers when majority of sub-agents are struggling."""
        report = calculate_team_health(
            {100: _make_report(90), 200: _make_report(30), 300: _make_report(25)},
            root_pid=100,
        )
        # Both sub-agents below 60 -> cascade warning
        signals = [w.signal for w in report.cross_agent_warnings]
        assert "team_cascade_failure" in signals

    def test_subagent_distress_warning(self):
        """Root healthy, sub-agent critical."""
        report = calculate_team_health(
            {100: _make_report(90), 200: _make_report(30)},
            root_pid=100,
        )
        signals = [w.signal for w in report.cross_agent_warnings]
        assert "subagent_distress" in signals

    def test_no_warnings_when_all_healthy(self):
        """No cross-agent warnings when everyone is healthy."""
        report = calculate_team_health(
            {100: _make_report(90), 200: _make_report(85), 300: _make_report(95)},
            root_pid=100,
        )
        assert len(report.cross_agent_warnings) == 0

    def test_cross_agent_penalty_applied(self):
        """Cross-agent warnings reduce the overall team score."""
        report = calculate_team_health(
            {100: _make_report(90), 200: _make_report(30), 300: _make_report(25)},
            root_pid=100,
        )
        # Without penalty: root=90*0.5=45, sub_avg=(30+25)/2=27.5*0.5=13.75 -> 58
        # With cascade warning (HIGH=30): 58 - 30 = 28
        # With subagent_distress (MEDIUM=15): 28 - 15 = 13
        assert report.overall_score < 58
        assert len(report.cross_agent_warnings) > 0

    def test_score_clamped_at_zero(self):
        """Team score never goes below 0."""
        report = calculate_team_health(
            {100: _make_report(10), 200: _make_report(5), 300: _make_report(5)},
            root_pid=100,
        )
        assert report.overall_score >= 0

    def test_to_dict(self):
        """TeamHealthReport serializes correctly."""
        report = calculate_team_health(
            {100: _make_report(80), 200: _make_report(60)},
            root_pid=100,
            team_name="test",
        )
        d = report.to_dict()
        assert "team_id" in d
        assert "overall_score" in d
        assert "member_scores" in d
        assert "cross_agent_warnings" in d
        assert d["member_count"] == 2
