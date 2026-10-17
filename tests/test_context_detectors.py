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

    def test_forgotten_files_order_is_deterministic(self):
        """#33: the list came from a set, so its order (and check --json)
        changed with PYTHONHASHSEED."""
        det = ContextRotDetector(early_fraction=0.25, recent_window=10, min_actions=40)
        buf = ActionBuffer()
        files = [f"src/{c}.py" for c in "qzambk"]
        for f in files:
            buf.add(_make_action(ToolType.EDIT, file_path=f))
        for i in range(40):
            buf.add(_make_action(ToolType.READ, file_path=f"other/file{i}.py"))

        assert det.check(buf).details["forgotten_files"] == sorted(files)[:5]

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

def _call(context: int, window: int = 0) -> Action:
    """One model call whose request carried *context* tokens (mostly cache reads)."""
    return Action(
        timestamp=datetime(2026, 1, 29, 12, 0),
        tool_name="Bash",
        tool_type=ToolType.BASH,
        success=True,
        tokens_in=2,
        cache_read_tokens=context - 2,
        tokens_out=300,
        context_window=window,
    )


def _pressure(*calls: Action):
    buf = ActionBuffer()
    for a in calls:
        buf.add(a)
    return ContextPressureDetector().check(buf)


class TestContextPressureDetector:
    def test_long_session_is_not_a_sum_of_calls(self):
        """The 231% bug: 500 calls of 50K each are 50K of context, not 25M."""
        assert _pressure(*[_call(50_000, 200_000) for _ in range(500)]) is None

    def test_warning_on_current_context(self):
        w = _pressure(_call(20_000, 200_000), _call(150_000, 200_000))
        assert w.signal == "context_pressure" and w.details["usage_percent"] == 75

    def test_critical_on_current_context(self):
        w = _pressure(_call(180_000, 200_000))
        assert w.signal == "context_critical" and w.severity.name == "HIGH"
        assert w.details == {"estimated_tokens": 180_000, "usage_percent": 90, "limit": 200_000}

    def test_1m_window_inferred_from_a_call_over_200k(self):
        """The 104%/231% sessions: Opus at 330K on a 1M window is 33%."""
        assert _pressure(_call(331_746)) is None
        w = _pressure(_call(900_000))
        assert w.details["limit"] == 1_000_000 and w.details["usage_percent"] == 90

    def test_unknown_window_claims_no_percentage(self):
        assert _pressure(_call(190_000)) is None

    def test_no_reported_usage_claims_no_percentage(self):
        buf = ActionBuffer()
        for _ in range(500):
            buf.add(_make_action(tokens_in=0, tokens_out=0))
        assert ContextPressureDetector().check(buf) is None

    def test_capped_at_100_percent(self):
        assert _pressure(_call(250_000, 200_000)).details["usage_percent"] == 100

    def test_drops_after_compaction(self):
        assert _pressure(_call(190_000, 200_000), _call(30_000, 200_000)) is None


class TestClaudeContextWindow:
    def test_model_ids(self):
        from agentwatch.parser.logs import claude_context_window

        assert claude_context_window("claude-opus-5-5") == 1_000_000
        assert claude_context_window("claude-sonnet-5") == 1_000_000
        assert claude_context_window("us.anthropic.claude-opus-4-6") == 1_000_000
        assert claude_context_window("claude-sonnet-4-5[1m]") == 1_000_000
        assert claude_context_window("claude-haiku-4-5-20251001") == 0
        assert claude_context_window("<synthetic>") == 0
        assert claude_context_window(None) == 0

    def test_claude_code_transcript_reports_the_window(self):
        from pathlib import Path

        from agentwatch.parser.logs import parse_file

        fixture = Path(__file__).parent / "fixtures" / "claude_code_2_1_30x.jsonl"
        assert {a.context_window for a in parse_file(fixture) if a.tool_name != "tool_result"} == {
            1_000_000
        }


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
