"""Where Claude Code keeps its config dir (transcripts, live-session records).

Claude Code reads ``CLAUDE_CONFIG_DIR`` and falls back to ``~/.claude``. A
running process's own value is read by ``discovery`` (from the process
environment); this module answers for agentwatch's own environment and for
whole-history scans. Only that one variable is ever read. Stdlib only: the
status line imports it.

Paths come back resolved (symlinks and ``..`` followed, relative values made
absolute against agentwatch's cwd), so one dir always has one spelling:
history keys sessions by a hash of the log path.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

ENV = "CLAUDE_CONFIG_DIR"


def resolved(path: Path) -> Path:
    """*path* resolved, or as given when that fails (a loop, no permission)."""
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return path


def config_dir_from(value: str | None) -> Path | None:
    """A ``CLAUDE_CONFIG_DIR`` value as a path: surrounding whitespace dropped,
    ``~`` expanded, empty -> None. Not resolved (the caller knows against what)."""
    if not isinstance(value, str) or not value.strip():
        return None
    return Path(os.path.expanduser(value.strip()))


def env_config_dir(environ: Mapping[str, str] | None = None) -> Path | None:
    """``CLAUDE_CONFIG_DIR`` from *environ* (default: agentwatch's own)."""
    return config_dir_from((os.environ if environ is None else environ).get(ENV))


def default_config_dir() -> Path:
    """$CLAUDE_CONFIG_DIR if set, else ``~/.claude``; resolved."""
    return resolved(env_config_dir() or Path.home() / ".claude")


def config_dirs(home: Path | None = None) -> list[Path]:
    """Every known config dir, for whole-history scans: $CLAUDE_CONFIG_DIR if
    set, then ``<home>/.claude`` (*home* defaults to the user's). Only
    existing dirs, resolved, each once. No guessing at other ``~/.claude-*``
    dirs."""
    candidates = [env_config_dir()]
    try:
        candidates.append((home or Path.home()) / ".claude")
    except RuntimeError:
        pass  # no home dir
    dirs: list[Path] = []
    for path in candidates:
        if path is None or not path.is_dir():
            continue
        path = resolved(path)
        if path not in dirs:
            dirs.append(path)
    return dirs
