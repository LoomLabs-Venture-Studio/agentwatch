"""Shared path-encoding logic for mapping filesystem paths to Claude Code's
project directory naming scheme.

Claude Code stores per-project session logs under ``~/.claude/projects/``,
keyed by an encoded form of the project's absolute working directory: every
character outside ``[A-Za-z0-9]`` becomes ``-``, e.g.
``C:\\Users\\Zaid\\Desktop\\claude work\\...`` ->
``C--Users-Zaid-Desktop-claude-work-...``. Names over 200 characters are cut
to 200 and suffixed with ``-`` plus a base-36 string hash of the path (#75;
read from the Claude Code 2.x CLI binary, where it is
``s.replace(/[^a-zA-Z0-9]/g, "-")`` and a Java-style ``(h << 5) - h + c``
hash).
"""

from __future__ import annotations

import re
from pathlib import Path

_ENCODE_CHARS = re.compile(r"[^A-Za-z0-9]")
_MAX_LEN = 200


def _js_string_hash(s: str) -> int:
    """JS ``(h << 5) - h + charCodeAt(i) | 0`` over UTF-16 code units."""
    units = s.encode("utf-16-le")
    h = 0
    for i in range(0, len(units), 2):
        h = (h * 31 + int.from_bytes(units[i:i + 2], "little")) & 0xFFFFFFFF
    return h - (1 << 32) if h >= 1 << 31 else h


def _base36(n: int) -> str:
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = ""
    while True:
        n, r = divmod(n, 36)
        out = digits[r] + out
        if not n:
            return out


def encode_path_for_claude(path: Path) -> str:
    """Encode a filesystem path to Claude Code's project directory format.

    e.g., /Users/zaid/my_project -> -Users-zaid-my-project
    e.g., C:\\Users\\Zaid\\my project -> C--Users-Zaid-my-project
    """
    # ponytail: one "-" per code point; JS emits two for chars outside the
    # BMP (emoji). Count UTF-16 units if such paths ever show up.
    raw = str(path)
    encoded = _ENCODE_CHARS.sub("-", raw)
    if len(encoded) <= _MAX_LEN:
        return encoded
    return f"{encoded[:_MAX_LEN]}-{_base36(abs(_js_string_hash(raw)))}"
