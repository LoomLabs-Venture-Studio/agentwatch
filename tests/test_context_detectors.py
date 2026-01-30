"""Tests for context rot, pressure, and rediscovery detectors."""

from datetime import datetime, timedelta

from agentwatch.detectors.health.context import (
    ContextPressureDetector,
    ContextRotDetector,
    RediscoveryDetector,
)
from agentwatch.parser.models import Action, ActionBuffer, ToolType


def _make_action(
    tool_type: ToolType = ToolType.READ,
    file_path: str | None = None,
    success: bool = True,
    error_message: str | None = None,
    command: str | None = None,
    tokens_in: int = 0,
    tokens_out: int = 0,
    offset_minutes: float = 0,
) -> Action:
    return Action(
        timestamp=datetime(2026, 1, 29, 12, 0) + timedelta(minutes=offset_minutes),
        tool_name=tool_type.value,
        tool_type=tool_type,
        success=success,
        file_path=file_path,
        command=command,
        error_message=error_message,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
    )


# ---------------------------------------------------------------------------
# ContextRotDetector
# ---------------------------------------------------------------------------

class TestContextRotDetector:
    def test_no_fire_under_min_actions(self):
        """Won't fire if session is too short."""
        det = ContextRotDetector(min_actions=40)
        buf = ActionBuffer()
        for i in range(30):
            buf.add(_make_action(file_path=f"file{i}.py"))
        assert det.check(buf) is None

    def test_fires_when_early_edited_files_forgotten(self):
        """Fires when files edited early are absent from recent window."""
        det = ContextRotDetector(early_fraction=0.25, recent_window=10, min_actions=40)
        buf = ActionBuffer()

        # Early: edit 3 files
        for f in ["src/a.py", "src/b.py", "src/c.py"]:
            buf.add(_make_action(ToolType.EDIT, file_path=f))
            buf.add(_make_action(ToolType.READ, file_path=f))

        # Middle + recent: work on completely different files (fill to 40+)
        for i in range(40):
            buf.add(_make_action(ToolType.READ, file_path=f"other/file{i}.py"))

        w = det.check(buf)
        assert w is not None
        assert w.signal == "context_rot"
        assert "forgotten_files" in w.details

    def test_no_fire_when_early_files_still_referenced(self):
        """Doesn't fire if early files are still being touched."""
        det = ContextRotDetector(early_fraction=0.25, recent_window=15, min_actions=40)
        buf = ActionBuffer()

        for f in ["src/a.py", "src/b.py"]:
            buf.add(_make_action(ToolType.EDIT, file_path=f))

        for i in range(35):
            buf.add(_make_action(ToolType.READ, file_path=f"other{i}.py"))

        # Re-reference the early files in the recent window
        buf.add(_make_action(ToolType.READ, file_path="src/a.py"))
        buf.add(_make_action(ToolType.READ, file_path="src/b.py"))

        assert det.check(buf) is None

    def test_only_edited_files_count(self):
        """Files only read (not edited) early don't trigger rot."""
        det = ContextRotDetector(early_fraction=0.25, recent_window=10, min_actions=40)
        buf = ActionBuffer()

        # Early: only reads, no edits
        for f in ["src/a.py", "src/b.py", "src/c.py"]:
            buf.add(_make_action(ToolType.READ, file_path=f))

        for i in range(40):
            buf.add(_make_action(ToolType.READ, file_path=f"other{i}.py"))

        assert det.check(buf) is None


# ---------------------------------------------------------------------------
# ContextPressureDetector
# ---------------------------------------------------------------------------

class TestContextPressureDetector:
    def test_no_fire_small_session(self):
        det = ContextPressureDetector(warning_threshold=0.7, model="claude")
        buf = ActionBuffer()
        for i in range(20):
            buf.add(_make_action(tokens_in=100, tokens_out=50))
        assert det.check(buf) is None

    def test_fires_warning_at_70_percent(self):
        det = ContextPressureDetector(warning_threshold=0.7, model="claude")
        buf = ActionBuffer()
        # 180k limit * 0.7 = 126k tokens needed
        # 130 actions * 1000 tokens each = 130k
        for i in range(130):
            buf.add(_make_action(tokens_in=700, tokens_out=300))

        w = det.check(buf)
        assert w is not None
        assert w.signal == "context_pressure"

    def test_fires_critical_at_85_percent(self):
        det = ContextPressureDetector(
            warning_threshold=0.7, critical_threshold=0.85, model="claude"
        )
        buf = ActionBuffer()
        # 180k * 0.85 = 153k tokens needed
        for i in range(160):
            buf.add(_make_action(tokens_in=700, tokens_out=300))

        w = det.check(buf)
        assert w is not None
        assert w.signal == "context_critical"
        assert w.severity.name == "HIGH"


# ---------------------------------------------------------------------------
# RediscoveryDetector
# ---------------------------------------------------------------------------

class TestRediscoveryDetector:
    def test_no_fire_under_window(self):
        det = RediscoveryDetector(window=50)
        buf = ActionBuffer()
        for i in range(30):
            buf.add(_make_action(ToolType.READ, file_path="same.py"))
        assert det.check(buf) is None

    def test_fires_on_spaced_rereads(self):
        """Fires when a file is re-read after gap, twice."""
        det = RediscoveryDetector(window=80, rediscovery_gap=30)
        buf = ActionBuffer()

        # Preamble to exceed window minimum
        for i in range(15):
            buf.add(_make_action(ToolType.BASH, command=f"pre{i}"))

        # Read target file
        buf.add(_make_action(ToolType.READ, file_path="src/important.py"))

        # 32 other actions (gap)
        for i in range(32):
            buf.add(_make_action(ToolType.BASH, command=f"cmd{i}"))

        # Re-read after gap (1st rediscovery)
        buf.add(_make_action(ToolType.READ, file_path="src/important.py"))

        # 32 more other actions
        for i in range(32):
            buf.add(_make_action(ToolType.BASH, command=f"cmd2_{i}"))

        # Re-read again (2nd rediscovery)
        buf.add(_make_action(ToolType.READ, file_path="src/important.py"))

        w = det.check(buf)
        assert w is not None
        assert w.signal == "rediscovery"
        assert "important.py" in w.message

    def test_no_fire_without_gap(self):
        """Consecutive re-reads (no gap) don't count as rediscovery."""
        det = RediscoveryDetector(window=80, rediscovery_gap=30)
        buf = ActionBuffer()

        for i in range(50):
            buf.add(_make_action(ToolType.READ, file_path="src/same.py"))

        # All reads are back-to-back, gap is always 1 — below rediscovery_gap
        assert det.check(buf) is None

    def test_no_fire_single_rediscovery(self):
        """A single rediscovery isn't enough — need 2+."""
        det = RediscoveryDetector(window=80, rediscovery_gap=30)
        buf = ActionBuffer()

        buf.add(_make_action(ToolType.READ, file_path="src/target.py"))
        for i in range(25):
            buf.add(_make_action(ToolType.BASH, command=f"cmd{i}"))
        buf.add(_make_action(ToolType.READ, file_path="src/target.py"))

        # Pad to 50
        for i in range(22):
            buf.add(_make_action(ToolType.BASH, command=f"pad{i}"))

        assert det.check(buf) is None
