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


# A fake key body: random-looking base64 lines (not a real key).
_PEM_BODY = [
    "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun",
    "VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK",
    "LxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo",
]
_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    + "\n".join(_PEM_BODY)
    + "\n-----END RSA PRIVATE KEY-----"
)


def test_pem_block_body_redacted_in_text():
    new, count = _redact_text(f"key:\n{_PEM}\ndone\n")
    assert count == 1
    for body_line in _PEM_BODY:
        assert body_line not in new
    assert new.endswith("-----END RSA PRIVATE KEY-----\ndone\n")


def test_pem_block_body_redacted_in_jsonl_line():
    line = json.dumps({"type": "tool_result", "content": f"cat id_rsa\n{_PEM}\n"})
    new_line, count = _redact_line(line)
    assert count >= 1
    for body_line in _PEM_BODY:
        assert body_line not in new_line
    assert json.loads(new_line).keys() == {"type", "content"}


def test_unterminated_pem_header_redacted_and_fast():
    import time

    text = "-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 1_000_000
    t0 = time.perf_counter()
    new, count = _redact_text(text)
    assert time.perf_counter() - t0 < 2.0
    assert count == 1
    assert "BEGIN RSA PRIVATE KEY" not in new
