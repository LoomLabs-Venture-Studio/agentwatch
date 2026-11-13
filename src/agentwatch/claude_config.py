"""Where Claude Code keeps its config dir (transcripts, live-session records).

Claude Code reads ``CLAUDE_CONFIG_DIR`` and falls back to ``~/.claude``. A
running process's own value is read by ``discovery`` (from the process
environment); this module answers for agentwatch's own environment and for
whole-history scans. Only that one variable is ever read. Stdlib only: the
status line imports it.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

ENV = "CLAUDE_CONFIG_DIR"


def config_dir_from(value: str | None) -> Path | None:
    """A ``CLAUDE_CONFIG_DIR`` value as a path: ``~`` expanded, empty -> None."""
    if not isinstance(value, str) or not value.strip():
        return None
    return Path(os.path.expanduser(value.strip()))


def env_config_dir(environ: Mapping[str, str] | None = None) -> Path | None:
    """``CLAUDE_CONFIG_DIR`` from *environ* (default: agentwatch's own)."""
    return config_dir_from((os.environ if environ is None else environ).get(ENV))


def default_config_dir() -> Path:
    """$CLAUDE_CONFIG_DIR if set, else ``~/.claude``."""
    return env_config_dir() or Path.home() / ".claude"


def config_dirs() -> list[Path]:
    """Every known config dir, for whole-history scans: $CLAUDE_CONFIG_DIR if
    set, then ``~/.claude``. Only existing dirs, each once (by resolved path).
    No guessing at other ``~/.claude-*`` dirs."""
    candidates = [env_config_dir()]
    try:
        candidates.append(Path.home() / ".claude")
    except RuntimeError:
        pass  # no home dir
    dirs: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        if path is None or not path.is_dir():
            continue
        try:
            key = path.resolve()
        except OSError:
            key = path
        if key not in seen:
            seen.add(key)
            dirs.append(path)
    return dirs
