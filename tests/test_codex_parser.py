"""Tests for the OpenAI Codex CLI rollout (JSONL) parser.

Covers `agentwatch.parser.codex` (`CodexParser`, `classify_codex_tool`,
`_detect_codex_era`, `_era_for_version`) plus the two wiring points that
route into it: `parser/logs.py`'s `detect_log_format`/`parse_file`, and
`parser/watcher.py`'s `LogWatcher`.

Everything here is built against a **hand-authored fixture**, shaped from
`codex-cli-support-prd.md`'s researched (not live-captured) `RolloutLine`
envelope -- see that PRD's "Open Questions / Requires Live Install to
Confirm" section, especially #1 (the `payload` nesting assumption). This
suite validates internal consistency of the parser against its own
documented assumption, not correctness against real Codex output.
"""

from __future__ import annotations

import json

from agentwatch.parser.codex import (
    CodexParser,
    _detect_codex_era,
    _era_for_version,
    classify_codex_tool,
)
from agentwatch.parser.logs import detect_log_format, parse_file
from agentwatch.parser.models import ToolType
from agentwatch.parser.watcher import LogWatcher

# ---------------------------------------------------------------------------
# Hand-authored fixture: one full rollout stream.
#
# Shape: session_meta (new era, cli_version present) -> turn_context
# (ignored) -> function_call (call_1, "shell") -> narration event_msg
# (ignored, non-adjacent to its output on purpose) -> function_call_output
# (call_1, success) -> function_call (call_2, "apply_patch") ->
# function_call_output (call_2, error) -> function_call (call_3, "shell",
# output NEVER arrives -- tests flush() vs no-flush) -> token_count event_msg.
# ---------------------------------------------------------------------------

CODEX_FIXTURE_LINES: list[dict] = [
    {
        "timestamp": "2026-07-12T10:00:00Z",
        "type": "session_meta",
        "payload": {
            "id": "sess-abc123",
            "cwd": "/home/user/project",
            "cli_version": "0.45.2",
        },
    },
    {
        "timestamp": "2026-07-12T10:00:01Z",
        "type": "turn_context",
        "payload": {"turn_id": 1},
    },
    {
        "timestamp": "2026-07-12T10:00:02Z",
        "type": "response_item",
        "payload": {
            "type": "function_call",
            "call_id": "call_1",
            "name": "shell",
            "arguments": json.dumps({"command": ["ls", "-la"]}),
        },
    },
    {
        "timestamp": "2026-07-12T10:00:03Z",
        "type": "event_msg",
        "payload": {"type": "agent_message", "message": "Let me check the files."},
    },
    {
        "timestamp": "2026-07-12T10:00:04Z",
        "type": "response_item",
        "payload": {
            "type": "function_call_output",
            "call_id": "call_1",
            "output": json.dumps({"content": "file1\nfile2", "success": True}),
        },
    },
    {
        "timestamp": "2026-07-12T10:00:05Z",
        "type": "response_item",
        "payload": {
            "type": "function_call",
            "call_id": "call_2",
            "name": "apply_patch",
            "arguments": json.dumps({"path": "foo.py"}),
        },
    },
    {
        "timestamp": "2026-07-12T10:00:06Z",
        "type": "response_item",
        "payload": {
            "type": "function_call_output",
            "call_id": "call_2",
            "output": json.dumps({"content": "patch failed", "success": False}),
        },
    },
    {
        "timestamp": "2026-07-12T10:00:07Z",
        "type": "response_item",
        "payload": {
            "type": "function_call",
            "call_id": "call_3",
            "name": "shell",
            "arguments": json.dumps({"command": ["pytest"]}),
        },
    },
    {
        "timestamp": "2026-07-12T10:00:08Z",
        "type": "event_msg",
        "payload": {"type": "token_count", "input_tokens": 120, "output_tokens": 45},
    },
]


def _write_jsonl(path, entries: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# _era_for_version / _detect_codex_era
# ---------------------------------------------------------------------------


class TestEraDetection:
    def test_version_at_boundary_is_new(self):
        assert _era_for_version("0.44.0") == "new"

    def test_version_above_boundary_is_new(self):
        assert _era_for_version("0.45.2") == "new"
        assert _era_for_version("1.0.0") == "new"

    def test_version_below_boundary_is_mid(self):
        assert _era_for_version("0.43.9") == "mid"
        assert _era_for_version("0.1.0") == "mid"

    def test_malformed_version_falls_back_to_mid(self):
        assert _era_for_version("not-a-version") == "mid"

    def test_detect_era_new_from_session_meta_cli_version(self):
        entry = {
            "type": "session_meta",
            "payload": {"id": "s1", "cwd": "/x", "cli_version": "0.45.0"},
        }
        assert _detect_codex_era(entry) == "new"

    def test_detect_era_mid_when_payload_wrapper_present_no_version(self):
        entry = {"type": "response_item", "payload": {"type": "function_call"}}
        assert _detect_codex_era(entry) == "mid"

    def test_detect_era_oldest_when_flat_no_payload_wrapper(self):
        entry = {"type": "function_call", "call_id": "call_1", "name": "shell"}
        assert _detect_codex_era(entry) == "oldest"


# ---------------------------------------------------------------------------
# classify_codex_tool
# ---------------------------------------------------------------------------


class TestClassifyCodexTool:
    def test_apply_patch_underscore_is_edit(self):
        assert classify_codex_tool("apply_patch") == ToolType.EDIT

    def test_apply_patch_hyphen_is_edit(self):
        assert classify_codex_tool("apply-patch") == ToolType.EDIT

    def test_falls_through_to_classify_tool_for_shell(self):
        assert classify_codex_tool("shell") == ToolType.BASH

    def test_falls_through_to_classify_tool_for_read(self):
        assert classify_codex_tool("read_file") == ToolType.READ

    def test_unrecognized_name_is_unknown(self):
        assert classify_codex_tool("totally_unrecognized_tool_xyz") == ToolType.UNKNOWN


# ---------------------------------------------------------------------------
# CodexParser
# ---------------------------------------------------------------------------


class TestCodexParser:
    def test_session_meta_sets_session_id_and_yields_nothing(self):
        parser = CodexParser()
        result = parser.parse_line(CODEX_FIXTURE_LINES[0])
        assert result == []
        assert parser.session_id == "sess-abc123"

    def test_turn_context_is_ignored(self):
        parser = CodexParser()
        parser.parse_line(CODEX_FIXTURE_LINES[0])
        result = parser.parse_line(CODEX_FIXTURE_LINES[1])
        assert result == []

    def test_function_call_is_buffered_not_yielded(self):
        parser = CodexParser()
        parser.parse_line(CODEX_FIXTURE_LINES[0])
        result = parser.parse_line(CODEX_FIXTURE_LINES[2])  # function_call call_1
        assert result == []
        assert "call_1" in parser._pending

    def test_non_adjacent_call_and_output_correlate_via_call_id(self):
        """Narration (event_msg) sits between the call and its output --
        proves correlation is call_id-based, not line-adjacency-based."""
        parser = CodexParser()
        for line in CODEX_FIXTURE_LINES[0:5]:  # meta, turn_context, call, narration, output
            actions = parser.parse_line(line)

        assert len(actions) == 1
        action = actions[0]
        assert action.tool_name == "shell"
        assert action.tool_type == ToolType.BASH
        assert action.command == "ls -la"
        assert action.success is True
        assert action.session_id == "sess-abc123"
        assert "call_1" not in parser._pending

    def test_error_output_marks_action_failed_with_error_message(self):
        parser = CodexParser()
        for line in CODEX_FIXTURE_LINES[0:7]:  # through call_2's error output
            actions = parser.parse_line(line)

        assert len(actions) == 1
        action = actions[0]
        assert action.tool_name == "apply_patch"
        assert action.tool_type == ToolType.EDIT
        assert action.success is False
        assert action.error_message == "patch failed"

    def test_output_with_no_matching_pending_call_still_surfaces(self):
        parser = CodexParser()
        parser.parse_line(CODEX_FIXTURE_LINES[0])  # session_meta only
        orphan_output = {
            "timestamp": "2026-07-12T10:00:09Z",
            "type": "response_item",
            "payload": {
                "type": "function_call_output",
                "call_id": "call_never_seen",
                "output": json.dumps({"content": "ok", "success": True}),
            },
        }
        result = parser.parse_line(orphan_output)
        assert len(result) == 1
        assert result[0].tool_name == "unknown_call"
        assert result[0].tool_type == ToolType.UNKNOWN
        assert result[0].success is True

    def test_token_count_event_msg_yields_action(self):
        parser = CodexParser()
        parser.parse_line(CODEX_FIXTURE_LINES[0])
        result = parser.parse_line(CODEX_FIXTURE_LINES[8])  # token_count
        assert len(result) == 1
        assert result[0].tool_name == "token_count"
        assert result[0].tokens_in == 120
        assert result[0].tokens_out == 45

    def test_flush_emits_call_with_no_output_before_eos(self):
        parser = CodexParser()
        for line in CODEX_FIXTURE_LINES:
            parser.parse_line(line)

        # call_3's output never arrives in the fixture -- still pending.
        assert "call_3" in parser._pending
        flushed = parser.flush()
        assert len(flushed) == 1
        assert flushed[0].tool_name == "shell"
        assert flushed[0].command == "pytest"
        # provisional success=True carried through, since no output ever arrived
        assert flushed[0].success is True
        assert parser._pending == {}

    def test_flush_on_empty_pending_returns_empty_list(self):
        parser = CodexParser()
        parser.parse_line(CODEX_FIXTURE_LINES[0])
        assert parser.flush() == []


# ---------------------------------------------------------------------------
# detect_log_format: Codex detection + regression on existing formats
# ---------------------------------------------------------------------------


class TestDetectLogFormatCodex:
    def test_session_meta_line_detected_as_codex(self):
        assert detect_log_format(CODEX_FIXTURE_LINES[0]) == "codex"

    def test_response_item_line_detected_as_codex(self):
        assert detect_log_format(CODEX_FIXTURE_LINES[2]) == "codex"

    def test_event_msg_line_detected_as_codex(self):
        assert detect_log_format(CODEX_FIXTURE_LINES[8]) == "codex"

    def test_turn_context_line_detected_as_codex(self):
        assert detect_log_format(CODEX_FIXTURE_LINES[1]) == "codex"


class TestDetectLogFormatRegression:
    """Existing Claude Code / Moltbot fixtures must still classify
    correctly -- no cross-contamination from the new Codex branch."""

    def test_claude_code_session_id_key(self):
        entry = {"sessionId": "abc", "type": "assistant", "message": {"role": "assistant"}}
        assert detect_log_format(entry) == "claude_code"

    def test_claude_code_message_role_shape(self):
        entry = {"type": "assistant", "message": {"role": "assistant", "content": []}}
        assert detect_log_format(entry) == "claude_code"

    def test_moltbot_skill_key(self):
        entry = {"skill": "python-linter", "type": "assistant"}
        assert detect_log_format(entry) == "moltbot"

    def test_moltbot_tool_call_key(self):
        entry = {"tool_call": {"name": "shell"}, "role": "assistant"}
        assert detect_log_format(entry) == "moltbot"

    def test_metadata_only_entry_returns_skip(self):
        entry = {"type": "file-history-snapshot"}
        assert detect_log_format(entry) == "skip"

    def test_unknown_shape_returns_unknown(self):
        entry = {"some_random_key": 1}
        assert detect_log_format(entry) == "unknown"


# ---------------------------------------------------------------------------
# parse_file: batch read + flush-at-EOF
# ---------------------------------------------------------------------------


class TestParseFileCodex:
    def test_yields_correct_action_stream_with_flush(self, tmp_path):
        log_path = tmp_path / "rollout-2026-07-12-abc.jsonl"
        _write_jsonl(log_path, CODEX_FIXTURE_LINES)

        actions = list(parse_file(log_path))

        tool_names = [a.tool_name for a in actions]
        # call_1 (shell, resolved), call_2 (apply_patch, resolved+error),
        # token_count, and call_3 (shell, flushed at EOF with no output).
        assert tool_names.count("shell") == 2  # call_1 resolved + call_3 flushed
        assert "apply_patch" in tool_names
        assert "token_count" in tool_names

        call_1_action = next(a for a in actions if a.tool_name == "shell" and a.success is True)
        assert call_1_action.command == "ls -la"

        apply_patch_action = next(a for a in actions if a.tool_name == "apply_patch")
        assert apply_patch_action.success is False
        assert apply_patch_action.error_message == "patch failed"

        # call_3 must be present (proves flush() ran at EOF) even though its
        # output line never appears in the fixture.
        flushed_action = next(a for a in actions if a.command == "pytest")
        assert flushed_action.tool_name == "shell"
        assert flushed_action.success is True  # provisional, never corrected

    def test_session_id_filter_applies_to_codex_actions(self, tmp_path):
        log_path = tmp_path / "rollout-2026-07-12-abc.jsonl"
        _write_jsonl(log_path, CODEX_FIXTURE_LINES)

        actions = list(parse_file(log_path, session_id="sess-abc123"))
        assert len(actions) > 0
        assert all(a.session_id == "sess-abc123" for a in actions)

        no_match = list(parse_file(log_path, session_id="some-other-session"))
        assert no_match == []


# ---------------------------------------------------------------------------
# LogWatcher: live-tail read, NO flush on tail path
# ---------------------------------------------------------------------------


class TestLogWatcherCodex:
    def test_reads_resolved_pair_across_non_adjacent_lines(self, tmp_path):
        log_path = tmp_path / "rollout-live.jsonl"
        # Only write through call_1's resolved output (lines 0-4).
        _write_jsonl(log_path, CODEX_FIXTURE_LINES[0:5])

        watcher = LogWatcher(log_path)
        actions = watcher._read_new_lines()

        assert len(actions) == 1
        assert actions[0].tool_name == "shell"
        assert actions[0].command == "ls -la"
        assert actions[0].success is True

    def test_pending_call_not_flushed_at_end_of_available_lines(self, tmp_path):
        """A call whose output hasn't arrived yet must NOT be emitted by
        LogWatcher just because the currently-available lines ran out --
        unlike parse_file(), which flushes at true EOF. This is the
        asymmetry documented in watcher.py's _parse_entry."""
        log_path = tmp_path / "rollout-live.jsonl"
        # Write through call_3's function_call line (no output, ever, in
        # this slice) -- lines 0 through 7 inclusive.
        _write_jsonl(log_path, CODEX_FIXTURE_LINES[0:8])

        watcher = LogWatcher(log_path)
        actions = watcher._read_new_lines()

        # call_1 (resolved) and call_2 (resolved, error) should appear;
        # call_3 must NOT appear -- it's still pending, and LogWatcher
        # never calls .flush().
        tool_names = [a.tool_name for a in actions]
        assert "shell" in tool_names  # call_1's resolved action
        assert "apply_patch" in tool_names  # call_2's resolved action
        pytest_pending = [a for a in actions if a.command == "pytest"]
        assert pytest_pending == []
        assert "call_3" in watcher._codex_parser._pending

    def test_watcher_picks_up_output_on_subsequent_poll(self, tmp_path):
        """Simulates two poll cycles: first read leaves call_3 pending
        (output not yet written), second read (after output is appended)
        resolves it -- proving pending state survives across polls."""
        log_path = tmp_path / "rollout-live.jsonl"
        _write_jsonl(log_path, CODEX_FIXTURE_LINES[0:8])

        watcher = LogWatcher(log_path)
        first_actions = watcher._read_new_lines()
        assert all(a.command != "pytest" for a in first_actions)
        assert "call_3" in watcher._codex_parser._pending

        # Append call_3's output as a later, non-adjacent poll would see it.
        call_3_output = {
            "timestamp": "2026-07-12T10:00:10Z",
            "type": "response_item",
            "payload": {
                "type": "function_call_output",
                "call_id": "call_3",
                "output": json.dumps({"content": "5 passed", "success": True}),
            },
        }
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(call_3_output) + "\n")

        second_actions = watcher._read_new_lines()
        assert len(second_actions) == 1
        assert second_actions[0].command == "pytest"
        assert second_actions[0].success is True
        assert "call_3" not in watcher._codex_parser._pending
