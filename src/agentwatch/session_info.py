"""Context window fill and git branch of a session, for `ps`, `visual` and
`watch-all`.

Context: the latest usage-bearing call's context size
(parser.models.context_tokens) over the model's window as the log proves it
(SessionStats.known_context_window); unknown window -> None, never a guess.
`ps` reads only a bounded tail of the log (CONTEXT_TAIL_BYTES), for agents
whose parser can start mid-file (TAIL_PARSERS); others -> None.

Branch: Claude Code's own `gitBranch` (the latest in the log), else
`.git/HEAD` read directly from the working directory up (never `git`).
Results are cached per (log, size, mtime_ns).
"""

from __future__ import annotations

import json
import os
import re
import stat
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agentwatch.parser.models import SessionStats, context_tokens

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess

CONTEXT_TAIL_BYTES = 1_000_000  # per log, for ps (coach reads 4 MB)
BRANCH_TAIL_BYTES = 64_000  # Claude Code repeats gitBranch on every line
GIT_MAX_DEPTH = 32  # directories walked up looking for .git
GIT_READ_BYTES = 4096  # .git file / HEAD read limit
BRANCH_LIMIT = 100  # one_line cap for JSON; tables cut further
CONTEXT_WARN = 80  # percent: theme warn colour
CONTEXT_BAD = 95  # percent: theme bad colour

# Agents whose log a tail can be parsed from, and the line marker that can
# carry usage (other lines are skipped without decoding).
_CLAUDE = ("claude-code", "claude-desktop")
TAIL_PARSERS = {**dict.fromkeys(_CLAUDE, b'"usage"'), "codex": b"token_count"}

_HEX_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_LOCK = threading.Lock()  # visual's server threads call these concurrently
_CACHE: dict[tuple[str, str], tuple[tuple[int, int], Any]] = {}
_CACHE_MAX = 256


def context_usage(stats: SessionStats) -> dict | None:
    """{"used_tokens", "window", "percent"} of the latest call, or None when
    no call reported usage or the window is unknown. The one formula for
    ps, visual and watch-all's CTX."""
    window = stats.known_context_window
    used = stats.last_context_tokens
    if not (used and window):
        return None
    return {"used_tokens": used, "window": window, "percent": min(100, int(used / window * 100))}


def context_text(usage: dict | None, over: str = ">100%") -> str:
    """'42%'; *over* when the call was bigger than the window (percent is
    clamped at 100; watch-all's 4-wide CTX passes '100+'); '-' unknown."""
    if not usage:
        return "-"
    return over if usage["used_tokens"] > usage["window"] else f"{usage['percent']}%"


def context_tone(percent: int | None) -> str | None:
    """'bad' at >= CONTEXT_BAD, 'warn' at >= CONTEXT_WARN, else None."""
    if percent is None:
        return None
    return "bad" if percent >= CONTEXT_BAD else "warn" if percent >= CONTEXT_WARN else None


def _cached(kind: str, log: Path, compute):
    """compute(size) cached per (log, size, mtime_ns). Fails closed: a
    missing or non-regular log (a FIFO would block), or any error while
    reading one log -> None, so one bad log never stops ps or watch-all."""
    try:
        st = os.stat(log)
    except (OSError, ValueError):
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    key, stamp = (kind, str(log)), (st.st_size, st.st_mtime_ns)
    with _LOCK:
        hit = _CACHE.get(key)
        if hit is not None and hit[0] == stamp:
            return hit[1]
    try:
        value = compute(st.st_size)
    except Exception:  # noqa: BLE001 -- any bad log: no value, never a crash
        value = None
    with _LOCK:
        if len(_CACHE) >= _CACHE_MAX:
            _CACHE.clear()
        _CACHE[key] = (stamp, value)
    return value


def _tail_lines(log: Path, size: int, limit: int) -> list[bytes]:
    with open(log, "rb") as f:
        start = max(0, size - limit)
        f.seek(start)
        lines = f.read(limit).splitlines()
    return lines[1:] if start else lines  # the first line is cut mid-record


def _entries(lines: list[bytes], marker: bytes):
    for line in lines:
        if marker not in line:
            continue
        try:
            entry = json.loads(line)
        except (ValueError, RecursionError):  # deep nesting raises RecursionError
            continue
        if isinstance(entry, dict):
            yield entry


def _tail_stats(log: Path, agent_type: str, size: int) -> dict | None:
    marker = TAIL_PARSERS[agent_type]
    if agent_type in _CLAUDE:
        from agentwatch.parser.logs import ClaudeCodeParser

        parse = ClaudeCodeParser().parse_entry
    else:
        from agentwatch.parser.codex import CodexParser

        parse = CodexParser().parse_line
    stats = SessionStats()
    for entry in _entries(_tail_lines(log, size, CONTEXT_TAIL_BYTES), marker):
        result = parse(entry)
        for action in result if isinstance(result, list) else [result] if result else []:
            if action.context_window:
                stats.context_window = action.context_window
            used = context_tokens(action)
            stats.peak_context_tokens = max(stats.peak_context_tokens, used)
            if used:
                stats.last_context_tokens = used
    return context_usage(stats)


def log_context(log: Path | None, agent_type: str | None) -> dict | None:
    """context_usage() of the tail of *log*; None for agents not in
    TAIL_PARSERS, an unreadable log or no usage in the tail. A window proven
    only by an earlier call over 200K (outside the tail) is not seen."""
    if log is None or agent_type not in TAIL_PARSERS:
        return None
    return _cached("context:" + agent_type, log,
                   lambda size: _tail_stats(log, agent_type, size))


def _log_branch(log: Path, size: int) -> str | None:
    for line in reversed(_tail_lines(log, size, BRANCH_TAIL_BYTES)):
        if b'"gitBranch"' not in line:
            continue
        try:
            entry = json.loads(line)
        except (ValueError, RecursionError):
            continue
        branch = entry.get("gitBranch") if isinstance(entry, dict) else None
        if isinstance(branch, str) and branch:
            return branch
    return None


def log_git_branch(log: Path | None) -> str | None:
    """The latest `gitBranch` in a Claude Code transcript's tail, or None."""
    if log is None:
        return None
    return _cached("branch", log, lambda size: _log_branch(log, size))


def _read(path: Path) -> str:
    """At most GIT_READ_BYTES of a regular file. Opened non-blocking and
    checked with fstat, so a FIFO (or a link to /dev/stdin) is refused, not
    waited on: OSError."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"not a regular file: {path}")
        return os.read(fd, GIT_READ_BYTES).decode("utf-8", "replace").strip()
    finally:
        os.close(fd)


def git_branch(cwd: Path | str | None) -> str | None:
    """The branch checked out at *cwd*, from the first `.git` at or above it
    (a directory, or a worktree/submodule `gitdir:` file): `ref:
    refs/heads/x` -> 'x', a detached HEAD -> '(detached abc1234)'. None when
    there is no repo within GIT_MAX_DEPTH dirs or anything is unreadable."""
    if cwd is None:
        return None
    start = Path(cwd)
    for d in [start, *start.parents][:GIT_MAX_DEPTH]:
        dotgit = d / ".git"
        try:
            if dotgit.is_dir():
                gitdir = dotgit
            elif dotgit.exists():  # a gitdir: file; _read refuses non-regular
                text = _read(dotgit)
                if not text.startswith("gitdir:"):
                    return None
                gitdir = d / text[len("gitdir:"):].strip()  # absolute stays absolute
            else:
                continue
            head = _read(gitdir / "HEAD")
        except (OSError, ValueError):
            return None
        if head.startswith("ref:"):
            ref = head[len("ref:"):].strip()
            return ref.removeprefix("refs/heads/") or None
        if _HEX_SHA.fullmatch(head):
            return f"(detached {head[:7]})"
        return None
    return None


def branch_of(agent: AgentProcess) -> str | None:
    """Claude Code's recorded gitBranch, else the working directory's
    .git/HEAD; one safe line of at most BRANCH_LIMIT chars, None when
    unknown."""
    from agentwatch.detectors.security.secret_scanner import one_line

    try:
        branch = None
        if agent.agent_type in _CLAUDE:
            branch = log_git_branch(agent.log_file)
            if branch == "HEAD":  # Claude Code's word for a detached HEAD
                branch = None
        branch = branch or git_branch(agent.working_directory)
        return (one_line(branch, BRANCH_LIMIT) or None) if branch else None
    except Exception:  # noqa: BLE001 -- fail closed per agent
        return None


def context_of(agent: AgentProcess) -> dict | None:
    """log_context() of a discovered agent; None on any error."""
    try:
        return log_context(agent.log_file, agent.agent_type)
    except Exception:  # noqa: BLE001 -- fail closed per agent
        return None
