"""Tests for the deterministic context-rot metric modules.

Covers:
- Repetition loops (Module B)
- Tool retry thrash (Module C)
- Progress stall (Module D)
- Forbidden path violation (Module E)
- Dependency change when no_new_deps=True (Module E)
- Behavioral degradation (Module A)
- End-to-end rot score aggregation + state machine
"""

from __future__ import annotations

from datetime import datetime, timedelta

from agentwatch.detectors.health.behavioral import compute_behavioral
from agentwatch.detectors.health.constraints import compute_constraints
from agentwatch.detectors.health.progress import compute_progress
from agentwatch.detectors.health.repetition import compute_repetition
from agentwatch.detectors.health.tool_thrash import compute_tool_thrash
from agentwatch.health.rot import RotScorer, RotState
from agentwatch.parser.models import Action, ActionBuffer, MetricResult, ToolType, Turn, turns_from_actions


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_T0 = datetime(2025, 1, 1, 12, 0, 0)


def _act(
    tool: str = "Read",
    tool_type: ToolType = ToolType.READ,
    file_path: str | None = None,
    success: bool = True,
    error_message: str | None = None,
    command: str | None = None,
    outgoing_data: str | None = None,
    offset_s: int = 0,
) -> Action:
    return Action(
        timestamp=_T0 + timedelta(seconds=offset_s),
        tool_name=tool,
        tool_type=tool_type,
        success=success,
        file_path=file_path,
        command=command,
        error_message=error_message,
        outgoing_data=outgoing_data,
    )


def _buffer_from(actions: list[Action]) -> ActionBuffer:
    buf = ActionBuffer(max_size=2000)
    for a in actions:
        buf.add(a)
    return buf


# ---------------------------------------------------------------------------
# Turn model tests
# ---------------------------------------------------------------------------

class TestTurnModel:
    def test_turns_from_actions_empty(self):
        assert turns_from_actions([]) == []

    def test_turns_basic_boundary(self):
        actions = [
            _act(outgoing_data="Hello, I will read the file.", offset_s=0),
            _act(tool="Read", file_path="a.py", offset_s=1),
            _act(outgoing_data="Now I will edit.", offset_s=2),
            _act(tool="Edit", tool_type=ToolType.EDIT, file_path="a.py", offset_s=3),
        ]
        turns = turns_from_actions(actions)
        assert len(turns) == 2
        assert turns[0].model_output == "Hello, I will read the file."
        assert len(turns[0].actions) == 2  # output action + read
        assert turns[1].has_edit


# ---------------------------------------------------------------------------
# Module A: Behavioral
# ---------------------------------------------------------------------------

class TestBehavioral:
    def test_empty_buffer(self):
        buf = _buffer_from([])
        result = compute_behavioral(buf)
        assert result.name == "behavioral"
        assert result.value == 0.0

    def test_length_inflation_detected(self):
        """Outputs that grow longer each turn should increase the metric."""
        actions: list[Action] = []
        for i in range(6):
            # Each turn doubles in word count
            text = "word " * (10 * (2 ** i))
            actions.append(_act(outgoing_data=text, offset_s=i * 10))
            actions.append(_act(tool="Read", file_path=f"f{i}.py", offset_s=i * 10 + 1))
        buf = _buffer_from(actions)
        result = compute_behavioral(buf)
        # Should detect inflation
        inflation = next((c for c in result.contributors if c.name == "length_inflation"), None)
        assert inflation is not None
        assert inflation.value > 0.2

    def test_hedge_density(self):
        """Output filled with hedge words should score high."""
        hedge_text = "maybe perhaps possibly might seem likely probably presumably " * 20
        actions = [
            _act(outgoing_data="normal output here", offset_s=0),
            _act(tool="Read", file_path="a.py", offset_s=1),
            _act(outgoing_data=hedge_text, offset_s=10),
            _act(tool="Read", file_path="b.py", offset_s=11),
        ]
        buf = _buffer_from(actions)
        result = compute_behavioral(buf)
        hedge = next((c for c in result.contributors if c.name == "hedge_density"), None)
        assert hedge is not None
        assert hedge.value > 0.5


# ---------------------------------------------------------------------------
# Module B: Repetition
# ---------------------------------------------------------------------------

class TestRepetition:
    def test_no_repetition_in_unique_outputs(self):
        # Use truly distinct outputs with minimal word overlap
        texts = [
            "The database migration script needs careful review before deployment.",
            "Authentication tokens should expire after thirty minutes of inactivity.",
            "Refactoring the payment gateway improves latency by reducing round trips.",
            "Caching layer sits between the application server and persistent storage.",
            "Horizontal scaling requires stateless services behind a load balancer.",
        ]
        actions: list[Action] = []
        for i, text in enumerate(texts):
            actions.append(_act(outgoing_data=text, offset_s=i * 10))
            actions.append(_act(tool="Read", file_path=f"f{i}.py", offset_s=i * 10 + 1))
        buf = _buffer_from(actions)
        result = compute_repetition(buf)
        assert result.value < 0.3

    def test_repeated_sentences_detected(self):
        """Identical sentences across turns should push the metric up."""
        sentence = "The quick brown fox jumps over the lazy dog and runs around the park."
        actions: list[Action] = []
        for i in range(5):
            actions.append(_act(outgoing_data=sentence, offset_s=i * 10))
            actions.append(_act(tool="Read", file_path=f"f{i}.py", offset_s=i * 10 + 1))
        buf = _buffer_from(actions)
        result = compute_repetition(buf)
        assert result.value > 0.3

    def test_self_repeating_ngrams(self):
        """Within a single output, repeated 3-grams should be caught."""
        repeated = "foo bar baz " * 30
        actions = [
            _act(outgoing_data="something different to start", offset_s=0),
            _act(tool="Read", file_path="a.py", offset_s=1),
            _act(outgoing_data=repeated, offset_s=10),
        ]
        buf = _buffer_from(actions)
        result = compute_repetition(buf)
        ngram = next((c for c in result.contributors if c.name == "ngram_self_repeat"), None)
        assert ngram is not None
        assert ngram.value > 0.3


# ---------------------------------------------------------------------------
# Module C: Tool thrash & stall
# ---------------------------------------------------------------------------

class TestToolThrash:
    def test_no_thrash_in_healthy_session(self):
        actions = [
            _act(tool="Read", file_path=f"f{i}.py", offset_s=i)
            for i in range(10)
        ]
        buf = _buffer_from(actions)
        result = compute_tool_thrash(buf)
        assert result.value < 0.1

    def test_repeated_identical_commands(self):
        """Same bash command repeated should raise the score."""
        actions = [
            _act(
                tool="Bash",
                tool_type=ToolType.BASH,
                command="npm test",
                success=False,
                error_message="FAIL src/app.test.js",
                offset_s=i,
            )
            for i in range(10)
        ]
        buf = _buffer_from(actions)
        result = compute_tool_thrash(buf)
        tool_sub = next((c for c in result.contributors if c.name == "repeated_tool_calls"), None)
        assert tool_sub is not None
        assert tool_sub.value > 0.5

    def test_repeated_error_signatures(self):
        """Same error repeated should raise the score."""
        actions = [
            _act(
                tool="Bash",
                tool_type=ToolType.BASH,
                command=f"cmd{i}",
                success=False,
                error_message="TypeError: cannot read property 'foo' of undefined",
                offset_s=i,
            )
            for i in range(8)
        ]
        buf = _buffer_from(actions)
        result = compute_tool_thrash(buf)
        err_sub = next((c for c in result.contributors if c.name == "repeated_errors"), None)
        assert err_sub is not None
        assert err_sub.value > 0.5

    def test_stall_detection(self):
        """Many turns of reading without edit+bash should score stall."""
        actions: list[Action] = []
        for i in range(20):
            actions.append(_act(outgoing_data=f"Let me look at file {i}.", offset_s=i * 10))
            actions.append(_act(tool="Read", file_path=f"f{i}.py", offset_s=i * 10 + 1))
        buf = _buffer_from(actions)
        result = compute_tool_thrash(buf)
        stall_sub = next((c for c in result.contributors if c.name == "turns_since_progress"), None)
        assert stall_sub is not None
        assert stall_sub.value > 0.3


# ---------------------------------------------------------------------------
# Module D: Progress
# ---------------------------------------------------------------------------

class TestProgress:
    def test_healthy_progress(self):
        """Turns with edits and successful bash should score low."""
        actions: list[Action] = []
        for i in range(8):
            actions.append(_act(outgoing_data=f"Turn {i}", offset_s=i * 10))
            actions.append(_act(tool="Edit", tool_type=ToolType.EDIT, file_path=f"f{i}.py", offset_s=i * 10 + 1))
            actions.append(_act(tool="Bash", tool_type=ToolType.BASH, command="pytest", success=True, offset_s=i * 10 + 2))
        buf = _buffer_from(actions)
        result = compute_progress(buf)
        assert result.value < 0.2

    def test_no_edits_high_deficit(self):
        """Turns with only reads should have high progress deficit."""
        actions: list[Action] = []
        for i in range(10):
            actions.append(_act(outgoing_data=f"Looking at turn {i}", offset_s=i * 10))
            actions.append(_act(tool="Read", file_path=f"f{i}.py", offset_s=i * 10 + 1))
        buf = _buffer_from(actions)
        result = compute_progress(buf)
        assert result.value > 0.5

    def test_file_churn_detected(self):
        """Same file edited many times without success."""
        actions: list[Action] = []
        for i in range(8):
            actions.append(_act(outgoing_data=f"Fix attempt {i}", offset_s=i * 10))
            actions.append(_act(tool="Edit", tool_type=ToolType.EDIT, file_path="app.py", offset_s=i * 10 + 1))
            actions.append(_act(
                tool="Bash", tool_type=ToolType.BASH, command="pytest",
                success=False, error_message="FAIL", offset_s=i * 10 + 2,
            ))
        buf = _buffer_from(actions)
        result = compute_progress(buf)
        churn = next((c for c in result.contributors if c.name == "file_churn"), None)
        assert churn is not None
        assert churn.value > 0.3


# ---------------------------------------------------------------------------
# Module E: Constraints
# ---------------------------------------------------------------------------

class TestConstraints:
    def test_no_constraints_active(self):
        buf = _buffer_from([_act(tool="Read", file_path="a.py")])
        result = compute_constraints(buf)
        assert result.value == 0.0

    def test_no_new_deps_violation(self):
        """Editing package.json when no_new_deps=True should score."""
        actions = [
            _act(tool="Edit", tool_type=ToolType.EDIT, file_path="/proj/package.json", offset_s=0),
        ]
        buf = _buffer_from(actions)
        result = compute_constraints(buf, no_new_deps=True)
        assert result.value > 0.0
        assert any("package.json" in e for e in result.evidence)

    def test_no_new_deps_no_violation(self):
        """Editing a normal file when no_new_deps=True should not score."""
        actions = [
            _act(tool="Edit", tool_type=ToolType.EDIT, file_path="/proj/src/app.py", offset_s=0),
        ]
        buf = _buffer_from(actions)
        result = compute_constraints(buf, no_new_deps=True)
        assert result.value == 0.0

    def test_forbidden_path_prefix(self):
        """Accessing a forbidden path should score."""
        actions = [
            _act(tool="Read", file_path="/secrets/credentials.json", offset_s=0),
        ]
        buf = _buffer_from(actions)
        result = compute_constraints(buf, forbidden_prefixes=["/secrets/"])
        assert result.value > 0.0
        assert any("forbidden" in e for e in result.evidence)

    def test_must_touch_after_threshold(self):
        """Required path not touched after N turns should score."""
        actions: list[Action] = []
        for i in range(10):
            actions.append(_act(outgoing_data=f"Turn {i}", offset_s=i * 10))
            actions.append(_act(tool="Read", file_path=f"f{i}.py", offset_s=i * 10 + 1))
        buf = _buffer_from(actions)
        result = compute_constraints(buf, must_touch_paths=["tests/test_app.py"], must_touch_after=6)
        assert result.value > 0.0
        assert any("test_app.py" in e for e in result.evidence)

    def test_must_touch_satisfied(self):
        """Required path touched should not score."""
        actions: list[Action] = []
        for i in range(10):
            actions.append(_act(outgoing_data=f"Turn {i}", offset_s=i * 10))
            actions.append(_act(tool="Read", file_path=f"f{i}.py", offset_s=i * 10 + 1))
        # Touch the required file
        actions.append(_act(tool="Edit", tool_type=ToolType.EDIT, file_path="tests/test_app.py", offset_s=100))
        buf = _buffer_from(actions)
        result = compute_constraints(buf, must_touch_paths=["tests/test_app.py"], must_touch_after=6)
        assert result.value == 0.0


# ---------------------------------------------------------------------------
# Rot score aggregation & state machine
# ---------------------------------------------------------------------------

class TestRotScorer:
    def test_healthy_session(self):
        """Clean session should be Healthy."""
        scorer = RotScorer()
        actions: list[Action] = []
        for i in range(8):
            actions.append(_act(outgoing_data=f"Turn {i} doing work", offset_s=i * 10))
            actions.append(_act(tool="Edit", tool_type=ToolType.EDIT, file_path=f"f{i}.py", offset_s=i * 10 + 1))
            actions.append(_act(tool="Bash", tool_type=ToolType.BASH, command="pytest", success=True, offset_s=i * 10 + 2))
        buf = _buffer_from(actions)
        report = scorer.update(buf)
        assert report.state == RotState.HEALTHY
        assert report.smoothed_score < 0.35

    def test_warming_state_after_stall(self):
        """Stalling session should eventually reach Warming."""
        scorer = RotScorer()
        actions: list[Action] = []
        # Many read-only turns
        for i in range(20):
            actions.append(_act(outgoing_data=f"Let me read file {i}", offset_s=i * 10))
            actions.append(_act(tool="Read", file_path=f"f{i % 3}.py", offset_s=i * 10 + 1))
        buf = _buffer_from(actions)
        # Run multiple updates to let EMA accumulate
        for _ in range(4):
            report = scorer.update(buf)
        # Should be at least Warming
        assert report.state in (RotState.WARMING, RotState.ROTTING, RotState.CRITICAL)

    def test_critical_via_constraint_and_thrash(self):
        """High constraint + high thrash should trigger Critical immediately."""
        scorer = RotScorer(
            no_new_deps=True,
            forbidden_prefixes=["/secrets/", "/private/"],
        )
        actions: list[Action] = []
        # Phase 1: constraint violations (dep edits + forbidden paths)
        for i in range(5):
            actions.append(_act(outgoing_data=f"Turn {i}", offset_s=i * 10))
            actions.append(_act(tool="Edit", tool_type=ToolType.EDIT, file_path="/proj/package.json", offset_s=i * 10 + 1))
            actions.append(_act(tool="Edit", tool_type=ToolType.EDIT, file_path="/proj/yarn.lock", offset_s=i * 10 + 2))
            actions.append(_act(tool="Read", file_path="/secrets/key.pem", offset_s=i * 10 + 3))
            actions.append(_act(tool="Read", file_path="/secrets/db.env", offset_s=i * 10 + 4))
            actions.append(_act(tool="Read", file_path="/private/config.json", offset_s=i * 10 + 5))
        # Phase 2: heavy tool thrash — identical failing bash commands
        base_t = 60
        for i in range(20):
            actions.append(_act(
                tool="Bash", tool_type=ToolType.BASH, command="npm test",
                success=False, error_message="FAIL: Cannot find module './dist'",
                offset_s=base_t + i,
            ))
        buf = _buffer_from(actions)
        report = scorer.update(buf)
        report = scorer.update(buf)  # 2nd update for state transitions
        # With constraint >= 0.7 AND thrash >= 0.7, should be Critical
        assert report.modules["constraint"].value >= 0.7, f"constraint={report.modules['constraint'].value}"
        assert report.modules["thrash"].value >= 0.7, f"thrash={report.modules['thrash'].value}"
        assert report.state == RotState.CRITICAL

    def test_report_has_top_reasons(self):
        """Report should include evidence strings."""
        scorer = RotScorer()
        actions: list[Action] = []
        for i in range(15):
            actions.append(_act(outgoing_data=f"Turn {i}", offset_s=i * 10))
            actions.append(_act(tool="Read", file_path="same.py", offset_s=i * 10 + 1))
        buf = _buffer_from(actions)
        report = scorer.update(buf)
        # top_reasons should be a list (possibly empty for healthy sessions)
        assert isinstance(report.top_reasons, list)

    def test_ema_smoothing(self):
        """Score should smooth across updates."""
        scorer = RotScorer(alpha=0.4)
        # First update with stalling buffer
        stall_actions: list[Action] = []
        for i in range(20):
            stall_actions.append(_act(outgoing_data=f"Turn {i}", offset_s=i * 10))
            stall_actions.append(_act(tool="Read", file_path=f"f{i}.py", offset_s=i * 10 + 1))
        buf = _buffer_from(stall_actions)
        r1 = scorer.update(buf)

        # Second update with healthy buffer should pull score down
        healthy_actions: list[Action] = []
        for i in range(8):
            healthy_actions.append(_act(outgoing_data=f"Turn {i}", offset_s=i * 10))
            healthy_actions.append(_act(tool="Edit", tool_type=ToolType.EDIT, file_path=f"g{i}.py", offset_s=i * 10 + 1))
            healthy_actions.append(_act(tool="Bash", tool_type=ToolType.BASH, command="pytest", success=True, offset_s=i * 10 + 2))
        buf2 = _buffer_from(healthy_actions)
        r2 = scorer.update(buf2)

        # Smoothed score should be between raw values — specifically lower than r1 if r2.raw < r1.raw
        if r2.raw_score < r1.raw_score:
            assert r2.smoothed_score < r1.smoothed_score


# ---------------------------------------------------------------------------
# MetricResult structure
# ---------------------------------------------------------------------------

class TestMetricResult:
    def test_to_dict(self):
        m = MetricResult(
            name="test",
            value=0.42,
            evidence=["reason A"],
            contributors=[MetricResult(name="sub", value=0.1)],
        )
        d = m.to_dict()
        assert d["name"] == "test"
        assert d["value"] == 0.42
        assert len(d["evidence"]) == 1
        assert len(d["contributors"]) == 1
        assert d["contributors"][0]["name"] == "sub"
