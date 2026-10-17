"""Personal-info patterns for on-request redaction (`scrub`, `audit --pii`).

Same shape as ``_SECRET_PATTERNS``. Compiled case-sensitively: the street
address rule relies on Title Case. Never added to the live scanner (emails
are in every git commit). Checks a regex cannot express live in
``_PII_VALIDATORS`` (True = real), run by ``secret_scanner._is_placeholder``.
"""

from __future__ import annotations

import re
from collections.abc import Callable

# Not inside a longer word/number run (ids, hashes, timestamps, versions).
_START = r"(?<![\w+.-])"
_END = r"(?![\w-])(?!\.\d)"

_SUFFIXES = (
    "St|Ave|Rd|Blvd|Dr|Ln|Ct|Way|Pl|Ter|Pkwy|Hwy|Street|Avenue|Road|"
    "Boulevard|Drive|Lane|Court|Place|Terrace|Parkway|Highway"
)

_PII_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?<![\w.+%-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w-])"),
     "email"),
    (re.compile(
        # NANP: area code and exchange start 2-9.
        _START + r"(?:\+\d(?:[ -]?\d){9,14}|\([2-9]\d\d\) ?[2-9]\d\d-\d{4}"
        r"|[2-9]\d\d([-.])[2-9]\d\d\1\d{4})" + _END
    ), "phone"),
    (re.compile(_START + r"(?!000|666|9)\d{3}-(?!00)\d{2}-(?!0000)\d{4}" + _END), "us_ssn"),
    # Fixed brand groupings, so a trailing CVV/expiry is not swallowed into
    # the digit run: unseparated 13-19, 4-4-4-4, Amex 4-6-5. Each gap is an
    # optional space/dash on its own, so mixed separators still match.
    # ponytail: separated 19-digit (4-4-4-4-3) cards are missed; add the
    # grouping if they show up.
    (re.compile(
        _START + r"(?:\d{13,19}|\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}|\d{4}[ -]?\d{6}[ -]?\d{5})"
        + _END
    ), "credit_card"),
    (re.compile(
        r"(?<![\w.-])\d{1,5} (?:[A-Z][a-z]*\.? ){1,4}(?:" + _SUFFIXES + r")\b"
        r"(?:,? (?:Apt|Suite|Unit)\.? #?\w+)?"
    ), "street_address"),
]

PII_LABELS = frozenset(label for _, label in _PII_PATTERNS)

_FILE_EXTS = frozenset(
    "png jpg jpeg gif svg webp js ts py json md txt css html".split()
)


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _real_card(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return bool(re.match(r"4|5[1-5]|2[2-7]|3[47]|6011|65", digits)) and _luhn(digits)


def _real_email(value: str) -> bool:
    local, _, domain = value.rpartition("@")
    domain = domain.lower()
    return not (
        local.lower() in {"git", "noreply", "no-reply"}
        or "noreply" in domain
        or re.match(r"\d+x\.", domain)
        or domain.rsplit(".", 1)[-1] in _FILE_EXTS
    )


_PII_VALIDATORS: dict[str, Callable[[str], bool]] = {
    "email": _real_email,
    "credit_card": _real_card,
}
