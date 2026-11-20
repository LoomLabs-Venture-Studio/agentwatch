"""Per-agent live status for `agentwatch visual`: what each running agent is
doing now (last tool call), its own health and its own cost.

Each agent's log is scored like `check` (health mode). Scores are cached per
(log path, size, mtime_ns), so a 5 s poll re-parses only logs that changed.
A call's target is a file's base name, or only the program a command runs
(never its arguments); results and error text are never read here. Agents with
no readable log still get a row, with the log-derived fields null.
"""

from __future__ import annotations

import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentwatch.cli import json_project
from agentwatch.detectors import create_registry
from agentwatch.detectors.security.secret_scanner import one_line
from agentwatch.discovery import AgentProcess
from agentwatch.health.score import calculate_efficiency, calculate_health
from agentwatch.history import _base
from agentwatch.parser import parse_file
from agentwatch.parser.models import ActionBuffer, is_tool_call

SCHEMA = 1
ACTIVE_S = 120  # written to in the last 2 minutes = active
TARGET_LIMIT = 40
# Agents whose sessions live in one database, not in a log file per session.
NO_SESSION_LOG = {"cursor", "opencode", "kilo-code"}
# log -> ((size, mtime_ns), scored fields); pruned to the logs still running.
_LOCK = threading.Lock()  # visual's server threads call build() concurrently
_CACHE: dict[Path, tuple[tuple[int, int], dict[str, Any]]] = {}


_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=[^\s;&|<>()$`'\"]*")
_STOP = re.compile(r"[;&|<>()$`'\"]")
_NAME = re.compile(r"[A-Za-z0-9._+-]{1,40}")
_OTHER = "a command"


def _program(command: str) -> str:
    """The program a shell command runs, by allow-list: skip leading VAR=value
    words, cut the next word at the first shell operator or quote, keep its
    base name (after / or \\) only if it is a plain name. Anything else is
    "a command", so no argument text can come out."""
    words = command.split()
    while words and _ASSIGN.fullmatch(words[0]):
        words.pop(0)
    if not words:
        return ""
    word = _STOP.split(words[0], maxsplit=1)[0]
    name = re.split(r"[/\\]", word)[-1]
    # a name the secret scanner would redact (token-shaped) is not shown
    return name if _NAME.fullmatch(name) and one_line(name, 40) == name else _OTHER


def _target(action) -> str:
    text = _base(action.file_path) if action.file_path else _program(action.command or "")
    return one_line(text, TARGET_LIMIT)


def _score(log: Path) -> dict[str, Any]:
    out: dict[str, Any] = {"last": None, "health": None, "cost_usd": None}
    buffer = ActionBuffer()
    try:
        warnings = create_registry(mode="health").scan(parse_file(log), buffer)
    except Exception:  # noqa: BLE001 - one unreadable log never hides the rest
        return out
    if not len(buffer):
        return out
    report = calculate_health(warnings, include_security=False)
    out["health"] = {"score": report.overall_score, "label": report.status}
    out["cost_usd"] = calculate_efficiency(warnings, buffer).cost_total
    call = next((a for a in reversed(buffer.actions) if is_tool_call(a)), None)
    if call is not None:
        out["last"] = {"tool": one_line(call.tool_name, TARGET_LIMIT), "target": _target(call),
                       "ok": call.success, "at": call.timestamp}
    return out


def _scored(log: Path, key: tuple[int, int]) -> dict[str, Any]:
    with _LOCK:
        cached = _CACHE.get(log)
    if cached is None or cached[0] != key:
        cached = (key, _score(log))  # parsed outside the lock; a race just parses twice
        with _LOCK:
            _CACHE[log] = cached
    return cached[1]


def _age(at: datetime | None, now: float) -> int | None:
    if at is None:
        return None
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return max(0, round(now - at.timestamp()))


def build(agents: list[AgentProcess]) -> dict[str, Any]:
    now = time.time()
    rows, live = [], set()
    for a in agents:
        row: dict[str, Any] = {
            "pid": a.pid, "agent_type": a.agent_type, "project": json_project(a),
            "last_action": None, "health": None, "cost_usd": None, "active": None,
            "log_expected": a.agent_type not in NO_SESSION_LOG,
        }
        try:
            st = a.log_file.stat() if a.log_file else None
        except OSError:
            st = None
        if st is not None and a.log_file is not None:
            live.add(a.log_file)
            s = _scored(a.log_file, (st.st_size, st.st_mtime_ns))
            last = s["last"]
            row.update(
                health=s["health"], cost_usd=s["cost_usd"], active=now - st.st_mtime < ACTIVE_S,
                last_action=None if last is None else {
                    "tool": last["tool"], "target": last["target"],
                    "age_s": _age(last["at"], now), "ok": last["ok"]})
        rows.append(row)
    with _LOCK:
        for log in [k for k in _CACHE if k not in live]:
            _CACHE.pop(log, None)
    return {"schema": SCHEMA, "agents": rows}
