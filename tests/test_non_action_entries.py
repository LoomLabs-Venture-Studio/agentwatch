"""#46: timestamped Claude Code bookkeeping entries are not actions."""

import json

import pytest

from agentwatch.parser.logs import parse_claude_code_entry, parse_file

TS = "2026-01-01T12:00:00Z"
SKIPPED = [
    {"type": "attachment", "attachment": {"type": "hook_additional_context"}},
    {"type": "pr-link", "prNumber": 1, "prUrl": "https://example.com/pr/1"},
    {"type": "file-history-delta", "trackingPath": "a.py"},
    {"type": "continued-in", "continuedInSessionId": "s2"},
    {"type": "user", "message": {"role": "user", "content": "fix the bug"}},
]
# Kept: detectors scan their top-level "content" (a real secret_leak came
# from one on the dev machine's logs).
KEPT = [
    {"type": "system", "subtype": "stop_hook_summary", "content": "hook output"},
    {"type": "queue-operation", "operation": "enqueue", "content": "queued prompt"},
]


@pytest.mark.parametrize("entry", SKIPPED, ids=lambda e: e["type"])
def test_skipped(entry):
    assert parse_claude_code_entry({**entry, "sessionId": "s1", "timestamp": TS}) is None


@pytest.mark.parametrize("entry", KEPT, ids=lambda e: e["type"])
def test_kept_for_scanning(entry):
    action = parse_claude_code_entry({**entry, "sessionId": "s1", "timestamp": TS})
    assert action is not None and action.raw["content"] == entry["content"]


def test_tool_calls_still_parse(tmp_path):
    tool_use = {
        "type": "assistant", "sessionId": "s1", "timestamp": TS,
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "a.py"}}]},
    }
    log = tmp_path / "s1.jsonl"
    lines = [{**e, "sessionId": "s1", "timestamp": TS} for e in SKIPPED] + [tool_use]
    log.write_text("\n".join(json.dumps(e) for e in lines) + "\n", encoding="utf-8")
    actions = list(parse_file(log))
    assert [a.tool_name for a in actions] == ["Read"]
