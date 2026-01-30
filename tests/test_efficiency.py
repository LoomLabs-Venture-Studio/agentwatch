"""Tests for session efficiency scoring."""

from datetime import datetime

from agentwatch.detectors.base import Category, Severity, Warning
from agentwatch.health.score import EfficiencyReport, calculate_efficiency
from agentwatch.parser.models import Action, ActionBuffer, ToolType


def _make_action(
    tool_type: ToolType = ToolType.READ,
    success: bool = True,
    file_path: str | None = None,
    command: str | None = None,
) -> Action:
    return Action(
        timestamp=datetime.now(),
        tool_name=tool_type.value,
        tool_type=tool_type,
        success=success,
        file_path=file_path,
        command=command,
    )


class TestFreshSession:
    """A fresh session with few actions and no waste should score near 100."""

    def test_empty_buffer_no_warnings(self):
        buffer = ActionBuffer(max_size=2000)
        report = calculate_efficiency([], buffer)
        assert report.score == 100
        assert report.status == "efficient"
        assert report.recommendation == "Session is healthy"

    def test_few_unique_reads(self):
        buffer = ActionBuffer(max_size=2000)
        for i in range(10):
            buffer.add(_make_action(file_path=f"/src/file_{i}.py"))
        report = calculate_efficiency([], buffer)
        assert report.score >= 95
        assert report.status == "efficient"

    def test_successful_bashes(self):
        buffer = ActionBuffer(max_size=2000)
        for _ in range(20):
            buffer.add(_make_action(tool_type=ToolType.BASH, success=True, command="ls"))
        report = calculate_efficiency([], buffer)
        assert report.score >= 95


class TestModerateSession:
    """A session with some re-reads and ~50% context pressure should score 60-80."""

    def test_moderate_context_pressure(self):
        buffer = ActionBuffer(max_size=2000)
        # 30 unique file reads — no duplicates
        for i in range(30):
            buffer.add(_make_action(file_path=f"/src/file_{i}.py"))

        warnings = [
            Warning(
                category=Category.CONTEXT,
                severity=Severity.MEDIUM,
                signal="context_pressure",
                message="Context window ~50% full",
                details={"usage_percent": 50, "estimated_tokens": 90_000},
            ),
        ]
        report = calculate_efficiency(warnings, buffer)
        assert 60 <= report.score <= 80, f"Expected 60-80, got {report.score}"
        assert report.status in ("efficient", "degraded")

    def test_some_rereads_and_rot(self):
        buffer = ActionBuffer(max_size=2000)
        # Mostly unique reads with a few duplicates spread out
        for i in range(40):
            buffer.add(_make_action(file_path=f"/src/file_{i}.py"))
        # Add a handful of re-reads (5 duplicates out of 45 total)
        for i in range(5):
            buffer.add(_make_action(file_path=f"/src/file_{i}.py"))

        warnings = [
            Warning(
                category=Category.CONTEXT,
                severity=Severity.MEDIUM,
                signal="context_pressure",
                message="Context window ~45% full",
                details={"usage_percent": 45},
            ),
            Warning(
                category=Category.CONTEXT,
                severity=Severity.LOW,
                signal="rediscovery",
                message="Re-reading /src/file_0.py after long gaps (2x)",
                details={"file": "/src/file_0.py", "rediscovery_count": 2},
            ),
        ]
        report = calculate_efficiency(warnings, buffer)
        assert 60 <= report.score <= 80, f"Expected 60-80, got {report.score}"


class TestRottedSession:
    """A session with high pressure, many forgotten files, and lots of waste should score below 40."""

    def test_high_pressure_and_rot(self):
        buffer = ActionBuffer(max_size=2000)
        # Lots of actions with failures and duplicate reads
        for i in range(100):
            buffer.add(
                _make_action(
                    tool_type=ToolType.BASH,
                    success=(i % 3 != 0),  # ~33% failure rate
                    command=f"cmd_{i}",
                )
            )

        warnings = [
            Warning(
                category=Category.CONTEXT,
                severity=Severity.HIGH,
                signal="context_critical",
                message="Context window ~90% full",
                details={"usage_percent": 90},
            ),
            Warning(
                category=Category.CONTEXT,
                severity=Severity.MEDIUM,
                signal="context_rot",
                message="5 early files not referenced recently",
                details={
                    "forgotten_files": [
                        "/src/a.py",
                        "/src/b.py",
                        "/src/c.py",
                        "/src/d.py",
                        "/src/e.py",
                    ],
                },
            ),
            Warning(
                category=Category.CONTEXT,
                severity=Severity.LOW,
                signal="rediscovery",
                message="Re-reading /src/a.py after long gaps (4x)",
                details={"file": "/src/a.py", "rediscovery_count": 4},
            ),
        ]
        report = calculate_efficiency(warnings, buffer)
        assert report.score < 40, f"Expected < 40, got {report.score}"
        assert report.status == "wasteful"
        assert "fresh session" in report.recommendation.lower()

    def test_pure_waste_no_warnings(self):
        """Even without context warnings, high waste ratio alone degrades score."""
        buffer = ActionBuffer(max_size=2000)
        # All bash commands fail
        for i in range(50):
            buffer.add(
                _make_action(tool_type=ToolType.BASH, success=False, command=f"bad_{i}")
            )
        report = calculate_efficiency([], buffer)
        assert report.score <= 75, f"Expected <= 75 with 100% bash failure, got {report.score}"


class TestEfficiencyReportFields:
    """Verify all report fields are populated correctly."""

    def test_context_usage_pct_reflects_warning(self):
        buffer = ActionBuffer(max_size=2000)
        warnings = [
            Warning(
                category=Category.CONTEXT,
                severity=Severity.HIGH,
                signal="context_critical",
                message="Context window ~85% full",
                details={"usage_percent": 85},
            ),
        ]
        report = calculate_efficiency(warnings, buffer)
        assert report.context_usage_pct == 85.0

    def test_waste_ratio_computed(self):
        buffer = ActionBuffer(max_size=2000)
        # 5 reads of the same file = 4 duplicate reads out of 5 total
        for _ in range(5):
            buffer.add(_make_action(file_path="/src/same.py"))
        report = calculate_efficiency([], buffer)
        assert report.waste_ratio > 0

    def test_to_dict(self):
        report = EfficiencyReport(
            score=72,
            status="degraded",
            context_usage_pct=55.0,
            waste_ratio=0.12,
            recommendation="Session efficiency declining — consider wrapping up soon",
        )
        d = report.to_dict()
        assert d["score"] == 72
        assert d["status"] == "degraded"
        assert d["context_usage_pct"] == 55.0
        assert d["waste_ratio"] == 0.12
