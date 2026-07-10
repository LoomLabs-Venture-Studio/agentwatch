"""Shared path-encoding logic for mapping filesystem paths to Claude Code's
project directory naming scheme.

Claude Code stores per-project session logs under ``~/.claude/projects/``,
keyed by an encoded form of the project's absolute working directory. On
POSIX this is a simple ``/`` -> ``-`` substitution. On Windows, Claude Code's
actual encoding also replaces ``\\``, ``:``, and space with ``-`` (verified
empirically against a real ``~/.claude/projects/`` entry on Windows, e.g.
``C:\\Users\\Zaid\\Desktop\\claude work\\...`` ->
``C--Users-Zaid-Desktop-claude-work-...``).

The replacement is applied unconditionally (no platform detection) because
POSIX paths never contain ``\\`` or ``:``, so running the full character set
through the substitution produces identical output to a platform-conditional
rule on both operating systems.
"""

from __future__ import annotations

import re
from pathlib import Path

_ENCODE_CHARS = re.compile(r"[/\\: ]")


def encode_path_for_claude(path: Path) -> str:
    """Encode a filesystem path to Claude Code's project directory format.

    Replaces `/`, `\\`, `:`, and space with `-`.
    e.g., /Users/zaid/Projects/agentwatch -> -Users-zaid-Projects-agentwatch
    e.g., C:\\Users\\Zaid\\my project -> C--Users-Zaid-my-project
    """
    return _ENCODE_CHARS.sub("-", str(path))
