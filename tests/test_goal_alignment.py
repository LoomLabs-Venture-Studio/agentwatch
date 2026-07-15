"""Tests for `agentwatch.llm`'s Tier-2 goal-alignment advisory
(`OllamaAnalyzer.assess_goal_alignment`, Sprint 15) and its `cli.py` wiring.

Mirrors `test_llm.py`'s conventions: drives `OllamaAnalyzer` against a fake
Ollama `Client` double (no live Ollama daemon required), and drives CLI
wiring via `click.testing.CliRunner` with `agentwatch.llm._import_ollama_client`
monkeypatched the same way `test_llm.py::_make_analyzer` does.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from types import SimpleNamespace

from agentwatch.llm import (
    GOAL_ALIGNMENT_ACTION_WINDOW,
    MAX_FOLLOWUP_MESSAGES,
    GoalAlignmentAssessment,
    OllamaAnalyzer,
)
from agentwatch.parser.models import Action, ActionBuffer, ToolType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_action(
    tool_type: ToolType = ToolType.READ,
    file_path: str | None = None,
    command: str | None = None,
    incoming_message: str | None = None,
    offset_minutes: float = 0,
) -> Action:
    return Action(
        timestamp=datetime(2026, 3, 1, 12, 0) + timedelta(minutes=offset_minutes),
        tool_name=tool_type.value,
        tool_type=tool_type,
        success=True,
        file_path=file_path,
        command=command,
        incoming_message=incoming_message,
    )


class _FakeOllamaClient:
    """Records every chat() call and returns a configurable response.

    Distinguishes a goal-alignment prompt from a per-warning-triage prompt
    by content (the goal-alignment prompt always mentions "Stated task"),
    so a single fake can serve both `assess_warning` and
    `assess_goal_alignment` calls in the same test/CLI invocation without
    the caller having to track call order.
    """

    def __init__(
        self,
        pulled_models=("llama3.2:latest",),
        goal_alignment_content='{"aligned": true, "confidence": "high", '
        '"drift_summary": "Still on task."}',
        warning_content='{"likely_true_positive": true, "confidence": "high", '
        '"rationale": "Looks real."}',
        list_raises=None,
    ):
        self._pulled_models = pulled_models
        self._goal_alignment_content = goal_alignment_content
        self._warning_content = warning_content
        self._list_raises = list_raises
        self.chat_calls: list[dict] = []

    def __call__(self, host=None):
        self.host = host
        return self

    def list(self):
        if self._list_raises is not None:
            raise self._list_raises
        return SimpleNamespace(models=[SimpleNamespace(model=m) for m in self._pulled_models])

    def chat(self, **kwargs):
        self.chat_calls.append(kwargs)
        prompt = kwargs["messages"][0]["content"]
        content = self._goal_alignment_content if "Stated task" in prompt else self._warning_content
        return SimpleNamespace(message=SimpleNamespace(content=content))


def _make_analyzer(monkeypatch, **fake_client_kwargs) -> tuple[OllamaAnalyzer, _FakeOllamaClient]:
    fake_client_instance = _FakeOllamaClient(**fake_client_kwargs)

    def fake_import():
        return fake_client_instance

    monkeypatch.setattr("agentwatch.llm._import_ollama_client", fake_import)
    analyzer = OllamaAnalyzer(model="llama3.2")
    return analyzer, fake_client_instance


# ---------------------------------------------------------------------------
# Stated-task / follow-up extraction
# ---------------------------------------------------------------------------


class TestStatedTaskExtraction:
    def test_first_incoming_message_is_stated_task(self, monkeypatch):
        analyzer, fake = _make_analyzer(monkeypatch)
        buffer = ActionBuffer()
        buffer.add(_make_action(incoming_message="fix the login bug", offset_minutes=0))
        buffer.add(_make_action(tool_type=ToolType.EDIT, file_path="auth.py", offset_minutes=1))
        buffer.add(_make_action(incoming_message="also add a test for it", offset_minutes=2))

        analyzer.assess_goal_alignment(buffer)

        prompt = fake.chat_calls[0]["messages"][0]["content"]
        assert "fix the login bug" in prompt

    def test_later_incoming_messages_included_as_followups(self, monkeypatch):
        analyzer, fake = _make_analyzer(monkeypatch)
        buffer = ActionBuffer()
        buffer.add(_make_action(incoming_message="fix the login bug", offset_minutes=0))
        buffer.add(_make_action(tool_type=ToolType.EDIT, file_path="auth.py", offset_minutes=1))
        buffer.add(_make_action(incoming_message="also add a test for it", offset_minutes=2))

        analyzer.assess_goal_alignment(buffer)

        prompt = fake.chat_calls[0]["messages"][0]["content"]
        assert "also add a test for it" in prompt

    def test_followups_capped_at_max_followup_messages(self, monkeypatch):
        analyzer, fake = _make_analyzer(monkeypatch)
        buffer = ActionBuffer()
        buffer.add(_make_action(incoming_message="stated task", offset_minutes=0))
        for i in range(MAX_FOLLOWUP_MESSAGES + 3):
            buffer.add(_make_action(incoming_message=f"followup-{i}", offset_minutes=i + 1))

        analyzer.assess_goal_alignment(buffer)

        prompt = fake.chat_calls[0]["messages"][0]["content"]
        included = [f"followup-{i}" in prompt for i in range(MAX_FOLLOWUP_MESSAGES + 3)]
        # Only the first MAX_FOLLOWUP_MESSAGES follow-ups (chronologically)
        # should appear in the prompt.
        assert included[:MAX_FOLLOWUP_MESSAGES] == [True] * MAX_FOLLOWUP_MESSAGES
        assert included[MAX_FOLLOWUP_MESSAGES:] == [False] * 3

    def test_recent_action_synopsis_bounded_to_window(self, monkeypatch):
        analyzer, fake = _make_analyzer(monkeypatch)
        buffer = ActionBuffer()
        buffer.add(_make_action(incoming_message="stated task", offset_minutes=0))
        for i in range(GOAL_ALIGNMENT_ACTION_WINDOW + 5):
            buffer.add(
                _make_action(
                    tool_type=ToolType.BASH,
                    command=f"echo marker-{i}",
                    offset_minutes=i + 1,
                )
            )

        analyzer.assess_goal_alignment(buffer)

        prompt = fake.chat_calls[0]["messages"][0]["content"]
        # Only the most recent GOAL_ALIGNMENT_ACTION_WINDOW actions' markers
        # should appear -- the earliest ones must be excluded.
        assert "marker-0" not in prompt
        last_marker = GOAL_ALIGNMENT_ACTION_WINDOW + 5 - 1
        assert f"marker-{last_marker}" in prompt


# ---------------------------------------------------------------------------
# No-incoming_message short-circuit (the Codex-shaped case)
# ---------------------------------------------------------------------------


class TestNoStatedTaskShortCircuit:
    def test_returns_none_when_no_incoming_message_anywhere(self, monkeypatch):
        analyzer, fake = _make_analyzer(monkeypatch)
        buffer = ActionBuffer()
        buffer.add(_make_action(tool_type=ToolType.READ, file_path="main.py"))
        buffer.add(_make_action(tool_type=ToolType.BASH, command="pytest"))

        result = analyzer.assess_goal_alignment(buffer)

        assert result is None

    def test_no_model_call_made_when_no_stated_task(self, monkeypatch):
        """Zero incoming_message actions must short-circuit before any
        network/model call -- this is the honest "nothing to assess" path,
        not a wasted round trip."""
        analyzer, fake = _make_analyzer(monkeypatch)
        buffer = ActionBuffer()
        buffer.add(_make_action(tool_type=ToolType.READ, file_path="main.py"))

        analyzer.assess_goal_alignment(buffer)

        assert fake.chat_calls == []

    def test_empty_buffer_returns_none(self, monkeypatch):
        analyzer, _ = _make_analyzer(monkeypatch)
        buffer = ActionBuffer()

        assert analyzer.assess_goal_alignment(buffer) is None


# ---------------------------------------------------------------------------
# Response parsing (incl. prose-wrapped-JSON salvage)
# ---------------------------------------------------------------------------


class TestResponseParsing:
    def _buffer_with_stated_task(self) -> ActionBuffer:
        buffer = ActionBuffer()
        buffer.add(_make_action(incoming_message="add a hello endpoint"))
        buffer.add(_make_action(tool_type=ToolType.EDIT, file_path="app.py", offset_minutes=1))
        return buffer

    def test_parses_clean_json_response(self, monkeypatch):
        analyzer, _ = _make_analyzer(
            monkeypatch,
            goal_alignment_content='{"aligned": false, "confidence": "medium", '
            '"drift_summary": "Agent is editing unrelated files."}',
        )
        result = analyzer.assess_goal_alignment(self._buffer_with_stated_task())
        assert result.aligned is False
        assert result.confidence == "medium"
        assert result.drift_summary == "Agent is editing unrelated files."

    def test_salvages_json_embedded_in_prose(self, monkeypatch):
        """Small local models don't always obey format=json perfectly --
        the same salvage path assess_warning relies on must work here too."""
        analyzer, _ = _make_analyzer(
            monkeypatch,
            goal_alignment_content="Sure, here is my answer: "
            '{"aligned": true, "confidence": "low", '
            '"drift_summary": "Looks fine."} Hope that helps!',
        )
        result = analyzer.assess_goal_alignment(self._buffer_with_stated_task())
        assert result.aligned is True
        assert result.confidence == "low"
        assert result.drift_summary == "Looks fine."

    def test_unparseable_response_returns_none_aligned_not_crash(self, monkeypatch):
        analyzer, _ = _make_analyzer(
            monkeypatch, goal_alignment_content="I cannot help with that."
        )
        result = analyzer.assess_goal_alignment(self._buffer_with_stated_task())
        assert result.aligned is None
        assert result.confidence == "low"
        assert result.raw_response == "I cannot help with that."

    def test_invalid_confidence_defaults_to_low(self, monkeypatch):
        analyzer, _ = _make_analyzer(
            monkeypatch,
            goal_alignment_content='{"aligned": true, "confidence": "extremely-sure", '
            '"drift_summary": "x"}',
        )
        result = analyzer.assess_goal_alignment(self._buffer_with_stated_task())
        assert result.confidence == "low"

    def test_non_bool_aligned_becomes_none(self, monkeypatch):
        analyzer, _ = _make_analyzer(
            monkeypatch,
            goal_alignment_content='{"aligned": "yes", "confidence": "high", '
            '"drift_summary": "x"}',
        )
        result = analyzer.assess_goal_alignment(self._buffer_with_stated_task())
        assert result.aligned is None

    def test_to_dict_shape(self, monkeypatch):
        analyzer, _ = _make_analyzer(monkeypatch)
        result = analyzer.assess_goal_alignment(self._buffer_with_stated_task())
        assert isinstance(result, GoalAlignmentAssessment)
        d = result.to_dict()
        assert set(d.keys()) == {"aligned", "confidence", "drift_summary"}

    def test_sends_model_and_temperature_zero(self, monkeypatch):
        analyzer, fake = _make_analyzer(monkeypatch)
        analyzer.assess_goal_alignment(self._buffer_with_stated_task())
        assert fake.chat_calls[0]["model"] == "llama3.2"
        assert fake.chat_calls[0]["options"]["temperature"] == 0.0
        assert fake.chat_calls[0]["format"] == "json"


# ---------------------------------------------------------------------------
# CLI wiring: --llm on `check`
# ---------------------------------------------------------------------------


def _write_moltbot_fixture(path, *, with_stated_task: bool) -> None:
    """Moltbot-format JSONL (role-based entries) -- the format actually
    confirmed (via direct grep of parser/logs.py) to populate
    `incoming_message` for a "user" role entry, unlike Claude Code's own
    JSONL entry parser which does not set it for real content."""
    lines = []
    if with_stated_task:
        lines.append(
            json.dumps(
                {
                    "role": "user",
                    "content": "add a health check endpoint",
                    "ts": "2026-01-01T12:00:00",
                }
            )
        )
    lines.append(
        json.dumps(
            {
                "role": "assistant",
                "tool_call": {"name": "edit", "input": {"path": "app.py"}},
                "ts": "2026-01-01T12:01:00",
            }
        )
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestCliGoalAlignmentWiring:
    def test_prints_advisory_block_when_stated_task_present(self, monkeypatch, tmp_path):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        fake_client_instance = _FakeOllamaClient()

        def fake_import():
            return fake_client_instance

        monkeypatch.setattr("agentwatch.llm._import_ollama_client", fake_import)

        log_path = tmp_path / "session.jsonl"
        _write_moltbot_fixture(log_path, with_stated_task=True)

        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--log", str(log_path), "--llm"])

        assert result.exit_code in (0, 1, 2), result.output
        assert "TIER-2 GOAL ALIGNMENT (advisory, not scored)" in result.output
        assert "[ALIGNED]" in result.output
        assert "Still on task." in result.output

    def test_prints_nothing_when_no_stated_task(self, monkeypatch, tmp_path):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        fake_client_instance = _FakeOllamaClient()

        def fake_import():
            return fake_client_instance

        monkeypatch.setattr("agentwatch.llm._import_ollama_client", fake_import)

        log_path = tmp_path / "session.jsonl"
        _write_moltbot_fixture(log_path, with_stated_task=False)

        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--log", str(log_path), "--llm"])

        assert result.exit_code in (0, 1, 2), result.output
        assert "TIER-2 GOAL ALIGNMENT" not in result.output
        # No stated task anywhere in the buffer -> assess_goal_alignment's
        # own short-circuit -> no chat() call for goal alignment at all
        # (any chat() calls that did happen must have been per-warning
        # triage, not goal alignment).
        for call in fake_client_instance.chat_calls:
            assert "Stated task" not in call["messages"][0]["content"]

    def test_no_llm_flag_means_no_advisory_block(self, tmp_path):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        log_path = tmp_path / "session.jsonl"
        _write_moltbot_fixture(log_path, with_stated_task=True)

        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--log", str(log_path)])

        assert result.exit_code in (0, 1, 2), result.output
        assert "TIER-2 GOAL ALIGNMENT" not in result.output


# ---------------------------------------------------------------------------
# CLI wiring: --json --llm surfaces goal_alignment in JSON output
#
# CTO-review gap fix: --llm always ran the goal-alignment model call
# regardless of --json (matching per-warning Tier-2 triage's own
# always-run-under-a--llm behavior), but the result was only ever printed
# in the non-JSON branch -- under --json the call was paid for and then
# silently dropped. `goal_alignment` must now be a top-level key in both
# `check --json` and `security-scan --json` output, present (as `null`)
# even when there's no stated task to assess.
# ---------------------------------------------------------------------------


class TestCliGoalAlignmentJsonOutput:
    def test_check_json_llm_includes_goal_alignment_when_stated_task_present(
        self, monkeypatch, tmp_path
    ):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        fake_client_instance = _FakeOllamaClient()

        def fake_import():
            return fake_client_instance

        monkeypatch.setattr("agentwatch.llm._import_ollama_client", fake_import)

        log_path = tmp_path / "session.jsonl"
        _write_moltbot_fixture(log_path, with_stated_task=True)

        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--log", str(log_path), "--llm", "--json"])

        assert result.exit_code in (0, 1, 2), result.output
        payload = json.loads(result.output)
        assert "goal_alignment" in payload
        assert payload["goal_alignment"] == {
            "aligned": True,
            "confidence": "high",
            "drift_summary": "Still on task.",
        }

    def test_check_json_llm_goal_alignment_null_when_no_stated_task(self, monkeypatch, tmp_path):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        fake_client_instance = _FakeOllamaClient()

        def fake_import():
            return fake_client_instance

        monkeypatch.setattr("agentwatch.llm._import_ollama_client", fake_import)

        log_path = tmp_path / "session.jsonl"
        _write_moltbot_fixture(log_path, with_stated_task=False)

        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--log", str(log_path), "--llm", "--json"])

        assert result.exit_code in (0, 1, 2), result.output
        payload = json.loads(result.output)
        assert "goal_alignment" in payload
        assert payload["goal_alignment"] is None

    def test_security_scan_json_llm_includes_goal_alignment_when_stated_task_present(
        self, monkeypatch, tmp_path
    ):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        fake_client_instance = _FakeOllamaClient()

        def fake_import():
            return fake_client_instance

        monkeypatch.setattr("agentwatch.llm._import_ollama_client", fake_import)

        log_path = tmp_path / "session.jsonl"
        _write_moltbot_fixture(log_path, with_stated_task=True)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["security-scan", "--log", str(log_path), "--llm", "--json"]
        )

        assert result.exit_code in (0, 1, 2), result.output
        payload = json.loads(result.output)
        assert "goal_alignment" in payload
        assert payload["goal_alignment"] == {
            "aligned": True,
            "confidence": "high",
            "drift_summary": "Still on task.",
        }

    def test_security_scan_json_llm_goal_alignment_null_when_no_stated_task(
        self, monkeypatch, tmp_path
    ):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        fake_client_instance = _FakeOllamaClient()

        def fake_import():
            return fake_client_instance

        monkeypatch.setattr("agentwatch.llm._import_ollama_client", fake_import)

        log_path = tmp_path / "session.jsonl"
        _write_moltbot_fixture(log_path, with_stated_task=False)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["security-scan", "--log", str(log_path), "--llm", "--json"]
        )

        assert result.exit_code in (0, 1, 2), result.output
        payload = json.loads(result.output)
        assert "goal_alignment" in payload
        assert payload["goal_alignment"] is None
