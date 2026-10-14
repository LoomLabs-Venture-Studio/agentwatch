"""Core redaction helpers used by `agentwatch scrub` and `audit --pii`."""

from __future__ import annotations

import json
import re

from agentwatch.detectors.security.secret_scanner import (
    _find_spans,
    _redact_line,
    _redact_text,
)

# Matches only after JSON-escape decoding: in the raw line the value follows
# the "n" of a "\n" escape, which the lookbehind rejects.
_CUSTOM = [(re.compile(r"(?<![A-Za-z])ZEBRA\d{6}"), "zebra")]


def test_custom_patterns_reach_decoded_escape_pass():
    line = json.dumps({"cmd": "echo hi\nZEBRA123456"})
    new_line, count = _redact_line(line, patterns=_CUSTOM)
    assert count == 1
    assert "ZEBRA123456" not in new_line
    assert json.loads(new_line) == {"cmd": "echo hi\n[REDACTED]"}


def test_default_patterns_ignore_custom_value():
    line = json.dumps({"cmd": "echo hi\nZEBRA123456"})
    assert _redact_line(line) == (line, 0)


def test_find_spans_merges_and_labels():
    text = "a ZEBRA123456 b"
    assert _find_spans(text, _CUSTOM) == [(2, 13, "zebra")]
    assert _redact_text(text, _CUSTOM) == ("a [REDACTED] b", 1)
