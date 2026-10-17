"""Claude Code 2.1.300+ transcripts and the loop detector.

The fixture holds real, scrubbed lines: api-request / api-request-shape
(logged on every model turn since 2.1.300), a failing Bash call and its
is_error tool_result (2.1.302), a Read (2.1.300) and an MCP call (2.1.288 --
no 2.1.30x MCP call exists locally; the tool_use block shape is unchanged).
Scenarios are built by cloning those lines.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

from agentwatch.detectors.base import Severity
from agentwatch.detectors.health.loops import LoopDetector
from agentwatch.parser.logs import parse_file
from agentwatch.parser.models import ActionBuffer

FIXTURE = Path(__file__).parent / "fixtures" / "claude_code_2_1_30x.jsonl"
LINES = [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()]


def _line(pred):
    return next(e for e in LINES if pred(e))


def _block(e):
    return e["message"]["content"][0]


API_REQUEST = _line(lambda e: e["type"] == "api-request")
TEXT = _line(lambda e: e["type"] == "assistant" and _block(e)["type"] == "text")
BASH = _line(lambda e: e["type"] == "assistant" and _block(e).get("name") == "Bash")
READ = _line(lambda e: e["type"] == "assistant" and _block(e).get("name") == "Read")
MCP = _line(lambda e: e["type"] == "assistant" and _block(e).get("name", "").startswith("mcp__"))
FAILED = _line(lambda e: e["type"] == "user" and _block(e).get("is_error"))


class _Session:
    def __init__(self):
        self.lines: list[dict] = []

    def add(self, template: dict, **input_changes) -> dict:
        e = copy.deepcopy(template)
        n = len(self.lines)
        e["timestamp"] = f"2026-10-17T17:{n // 60:02d}:{n % 60:02d}.000Z"
        if e["type"] == "assistant" and _block(e)["type"] == "tool_use":
            _block(e)["id"] = f"toolu_{n}"
            _block(e)["input"].update(input_changes)
        self.lines.append(e)
        return e

    def call(self, template: dict, fail: bool = False, **input_changes) -> None:
        """One model turn: the api-request line, the call, its failure."""
        self.add(API_REQUEST)
        use = self.add(template, **input_changes)
        if fail:
            _block(self.add(FAILED))["tool_use_id"] = _block(use)["id"]

    def loop_warnings(self, tmp_path: Path) -> list:
        """LoopDetector after every action, like the live TUI."""
        log = tmp_path / "session.jsonl"
        log.write_text("\n".join(json.dumps(e) for e in self.lines) + "\n", encoding="utf-8")
        buffer, detector, warnings = ActionBuffer(), LoopDetector(), []
        for action in parse_file(log):
            buffer.add(action)
            warnings.append(detector.check(buffer))
        return [w for w in warnings if w]


def test_api_request_lines_are_not_actions():
    names = [a.tool_name for a in parse_file(FIXTURE)]
    assert names == ["text_output", "Bash", "tool_result", "Read", _block(MCP)["name"]]


def test_text_only_turns_are_not_a_loop(tmp_path):
    s = _Session()
    for _ in range(12):
        s.add(API_REQUEST)
        s.add(TEXT)
    assert s.loop_warnings(tmp_path) == []


def test_repeated_read_reaches_high(tmp_path):
    s = _Session()
    for _ in range(12):
        s.call(READ)
    w = s.loop_warnings(tmp_path)[-1]
    assert w.severity == Severity.HIGH
    assert w.details["tool"] == "Read" and w.details["count"] == 10
