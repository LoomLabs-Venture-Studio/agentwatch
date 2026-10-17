"""Personal-info patterns (detectors/security/pii.py), AC1/AC10/AC11."""

from __future__ import annotations

from datetime import datetime

import pytest

from agentwatch.detectors.security.pii import _PII_PATTERNS, PII_LABELS, _luhn
from agentwatch.detectors.security.secret_scanner import (
    _SECRET_PATTERNS,
    SecretLeakScanner,
    _find_spans,
    _redact_text,
)
from agentwatch.parser.models import Action, ActionBuffer, ToolType

_ALL = _SECRET_PATTERNS + _PII_PATTERNS

REAL = [
    ("email", "jane.doe@gmail.com"),
    ("email", "Bob_Smith+tag@corp.co.uk"),
    ("phone", "+14155552671"),
    ("phone", "+44 20 7946 0958"),
    ("phone", "(415) 555-2671"),
    ("phone", "415-555-2671"),
    ("phone", "415.555.2671"),
    ("phone", "(212) 200-3000"),
    ("us_ssn", "123-45-6789"),
    ("us_ssn", "219-09-9999"),
    ("credit_card", "4111 1111 1111 1111"),
    ("credit_card", "5500-0000-0000-0004"),
    ("credit_card", "378282246310005"),
    ("credit_card", "4111111111111111"),
    ("credit_card", "3782 822463 10005"),
    ("credit_card", "3782-822463-10005"),
    ("street_address", "123 Main St"),
    ("street_address", "4500 Old Mill Road, Apt 4B"),
]

LOOKALIKES = [
    "user@example.com",
    "git@github.com:org/repo.git",
    "icon@2x.png",
    "logo@3x.svg",
    "noreply@github.com",
    "123+bob@users.noreply.github.com",
    "call 4155552671 now",
    "id x415-555-2671",
    "1415-555-26710",
    "000-12-3456",
    "666-12-3456",
    "912-34-5678",
    "123-00-4567",
    "123-45-0000",
    "4111 1111 1111 1112",  # Luhn-invalid 16 digits
    "ts=1760486400003",  # Luhn-valid 13-digit ms timestamp, no issuer prefix
    "sha deadbeef4111111111111111",
    "run 4111 1111 1111 1112 123 ok",  # Luhn-invalid card + CVV
    "order 41111111111111112",  # Luhn-invalid 17-digit run
    "4111 1111-1111 1111",  # mixed separators
    "100-200-3000",  # NANP area code starts 0/1
    "212-100-3000",  # NANP exchange starts 0/1
    "(100) 200-3000",
    "(212) 100-3000",
    "fixed 3 bugs this way",
    "see line 42 of the main street",
]


@pytest.mark.parametrize("label,value", REAL)
def test_real_pii_is_redacted(label, value):
    text = f"contact: {value} thanks"
    new, count = _redact_text(text, _ALL)
    assert count == 1
    assert value not in new
    assert [s[2] for s in _find_spans(text, _ALL)] == [label]


@pytest.mark.parametrize("text", LOOKALIKES)
def test_lookalikes_are_ignored(text):
    assert _redact_text(text, _ALL) == (text, 0)


@pytest.mark.parametrize("card,tail", [
    ("4111 1111 1111 1111", " 123"),
    ("4111-1111-1111-1111", " 12/26"),
    ("5500-0000-0000-0004", " 12 26"),
    ("4111111111111111", " 123"),
    ("3782 822463 10005", " 1234"),
])
def test_card_followed_by_cvv_or_expiry(card, tail):
    text = f"pay with {card}{tail} ok"
    new, count = _redact_text(text, _ALL)
    assert count == 1
    assert card not in new
    assert tail in new


def test_labels_and_luhn():
    assert {label for _, label in _PII_PATTERNS} == PII_LABELS
    assert _luhn("4111111111111111")
    assert not _luhn("4111111111111112")


def test_pii_patterns_are_case_sensitive():
    import re

    assert all(not p.flags & re.IGNORECASE for p, _ in _PII_PATTERNS)


def test_default_patterns_leave_pii_alone():
    text = " ".join(v for _, v in REAL)
    assert _redact_text(text) == (text, 0)


def test_live_scanner_ignores_pii():
    text = "jane.doe@gmail.com +14155552671 123-45-6789 4111 1111 1111 1111 123 Main St"
    buf = ActionBuffer()
    buf.add(Action(
        timestamp=datetime(2026, 10, 15, 12, 0),
        tool_name="Bash",
        tool_type=ToolType.BASH,
        success=True,
        command=f"echo '{text}'",
        outgoing_data=text,
        raw={"content": text},
    ))
    assert SecretLeakScanner().check(buf) is None
