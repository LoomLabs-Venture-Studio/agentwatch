"""`agentwatch tools`: the tools one session called and how each went.

Counts every action ``is_tool_call`` accepts (no role labels, no usage
records). A failed call shows its ``history.error_kind``, never its text;
a call's target is the file name or the command, one line, redacted, <= 80.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from statistics import median
from typing import Any

from agentwatch.detectors.security.secret_scanner import one_line
from agentwatch.history import _base, error_kind
from agentwatch.parser.models import Action, is_tool_call

SCHEMA = 1
TARGET_LIMIT = 80


def _ms(a: Action) -> int | None:
    """Logged duration, else call to result (Claude Code); None if neither."""
    if a.duration_ms:
        return a.duration_ms
    if a.timestamp and a.completed_at and a.completed_at >= a.timestamp:
        return round((a.completed_at - a.timestamp).total_seconds() * 1000)
    return None


def _target(a: Action) -> str:
    text = _base(a.file_path) if a.file_path else a.command or ""
    return one_line(text, TARGET_LIMIT)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def build(actions: list[Action], log_name: str, with_calls: bool = False) -> dict[str, Any]:
    """*actions*: a whole parsed log (results already merged)."""
    times = [t for a in actions for t in (a.timestamp, a.completed_at) if t]
    calls = [a for a in actions if is_tool_call(a)]
    kinds = {id(a): error_kind(a) for a in calls if not a.success}
    by_tool: dict[str, list[Action]] = {}
    for a in calls:
        by_tool.setdefault(one_line(a.tool_name, TARGET_LIMIT), []).append(a)
    tools = []
    for name, group in by_tool.items():
        failed = [kinds[id(a)] for a in group if not a.success]
        ms = [m for m in map(_ms, group) if m is not None]
        tools.append({
            "tool": name,
            "calls": len(group),
            "failed": len(failed),
            "failure_pct": round(100 * len(failed) / len(group), 1),
            "top_error_kind": Counter(failed).most_common(1)[0][0] if failed else None,
            "total_ms": sum(ms) if ms else None,
            "median_ms": round(median(ms)) if ms else None,
        })
    tools.sort(key=lambda t: -t["calls"])  # stable: first-used first on ties
    sid = next((a.session_id for a in actions if a.session_id), None)
    data: dict[str, Any] = {"schema": SCHEMA, "session": {
        "log": one_line(log_name, 200),
        "session_id": one_line(sid, 80) if sid else None,
        "start": _iso(min(times, default=None)),
        "end": _iso(max(times, default=None)),
        "calls": len(calls),
        "failed": len(kinds),
    }, "tools": tools}
    if with_calls:
        data["calls"] = [{
            "time": _iso(a.timestamp),
            "tool": one_line(a.tool_name, TARGET_LIMIT),
            "target": _target(a),
            "ok": a.success,
            "error_kind": kinds.get(id(a)),
        } for a in calls]
    return data


def _dur(ms: int | None) -> str:
    if ms is None:
        return "-"
    s = ms / 1000
    return f"{s:.1f}s" if s < 60 else f"{s / 60:.1f}m" if s < 3600 else f"{s / 3600:.1f}h"


def _span(start: str | None, end: str | None) -> str:
    if not start or not end:
        return "unknown"
    a, b = datetime.fromisoformat(start), datetime.fromisoformat(end)
    end = f"{b:%H:%M:%S}" if a.date() == b.date() else f"{b:%Y-%m-%d %H:%M:%S}"
    return f"{a:%Y-%m-%d %H:%M:%S} to {end} ({_dur(round((b - a).total_seconds() * 1000))})"


def render(data: dict[str, Any]) -> list[str]:
    s = data["session"]
    head = f"Tools in {s['log']}" + (f" (session {s['session_id']})" if s["session_id"] else "")
    lines = [head, "",
             f"  {'tool':<28} {'calls':>6} {'failed':>6} {'fail %':>6}  {'top error':<17} "
             f"{'total':>7} {'median':>7}"]
    for t in data["tools"]:
        lines.append(
            f"  {t['tool'][:28]:<28} {t['calls']:>6} {t['failed']:>6} "
            f"{t['failure_pct']:>5.0f}%  {t['top_error_kind'] or '-':<17} "
            f"{_dur(t['total_ms']):>7} {_dur(t['median_ms']):>7}")
    lines += ["", f"  Total: {s['calls']} calls, {s['failed']} failed. "
                  f"Span: {_span(s['start'], s['end'])}"]
    if "calls" in data:
        lines += ["", "  Calls:"]
        for c in data["calls"]:
            when = datetime.fromisoformat(c["time"]).strftime("%H:%M:%S") if c["time"] else "-"
            status = "ok" if c["ok"] else f"FAIL {c['error_kind']}"
            lines.append(f"  {when:>8}  {c['tool'][:20]:<20} {c['target']:<80}  {status}")
    return lines
