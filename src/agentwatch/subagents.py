"""`agentwatch subagents`: the health of each subagent of a Claude Code session.

Claude Code writes every subagent's transcript, at any depth, to
``<session>/subagents/agent-<id>.jsonl``, next to ``agent-<id>.meta.json``
(agentType, description, spawnDepth). Each log is scored like `check`.
Meta text goes through one_line; warnings keep only signal, severity and a
one-line message.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentwatch.detectors import create_registry
from agentwatch.detectors.security.secret_scanner import one_line
from agentwatch.health.score import calculate_efficiency, calculate_health
from agentwatch.parser import parse_file
from agentwatch.parser.models import ActionBuffer

SCHEMA = 1
ACTIVE_S = 600  # written to in the last 10 minutes = active
RECENT = 10  # shown without --all
# path -> ((size, mtime_ns), scored fields): `visual` reloads every 5 s and
# only the logs still being written change.
_SCORED: dict[Path, tuple[tuple[int, int], dict[str, Any]]] = {}


def session_of(log: Path) -> Path:
    """The main session log for *log*, which may itself be a subagent log."""
    if log.parent.name == "subagents":
        return log.parent.parent.with_suffix(".jsonl")
    return log


def logs(session: Path) -> list[Path]:
    """Subagent logs of *session*, newest first."""
    paths = (session.with_suffix("") / "subagents").glob("agent-*.jsonl")
    return sorted(paths, key=lambda p: p.stat().st_mtime, reverse=True)


def _meta(log: Path) -> dict[str, Any]:
    try:
        meta = json.loads(log.with_suffix(".meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return meta if isinstance(meta, dict) else {}


def _row(log: Path, now: float) -> dict[str, Any]:
    meta = _meta(log)
    st = log.stat()
    mtime = st.st_mtime
    row: dict[str, Any] = {
        "id": log.stem.removeprefix("agent-"),
        "type": one_line(meta.get("agentType") or "subagent", 40),
        "description": one_line(meta.get("description") or "", 80),
        "depth": meta.get("spawnDepth") if isinstance(meta.get("spawnDepth"), int) else None,
        "active": now - mtime < ACTIVE_S,
        "last_activity": datetime.fromtimestamp(mtime, timezone.utc).isoformat(),
    }
    key = (st.st_size, st.st_mtime_ns)
    cached = _SCORED.get(log)
    if cached is None or cached[0] != key:
        cached = _SCORED[log] = (key, _score(log))
    row.update(cached[1])
    return row


def _score(log: Path) -> dict[str, Any]:
    row: dict[str, Any] = {"actions": 0, "health_score": None, "status": None,
                           "cost_usd": None, "warnings": []}
    buffer = ActionBuffer()
    try:
        warnings = create_registry(mode="health").scan(parse_file(log), buffer)
    except Exception:  # noqa: BLE001 - one unreadable log never hides the rest
        return row
    if not len(buffer):
        return row
    report = calculate_health(warnings, include_security=False)
    row.update(
        actions=len(buffer),
        health_score=report.overall_score,
        status=report.status,
        cost_usd=calculate_efficiency(warnings, buffer).cost_total,
        warnings=[{"signal": w.signal, "severity": w.severity.value,
                   "message": one_line(w.message, 120)}
                  for w in report.health_warnings if w.severity.value in ("high", "critical")],
    )
    return row


def build(session: Path, show_all: bool = False, active_only: bool = False) -> dict[str, Any]:
    """Rows for the newest RECENT subagents (*show_all*: every one;
    *active_only*: only those active), newest first."""
    now = time.time()
    found = logs(session)
    picked = found if show_all else found[:RECENT]
    if active_only:
        picked = [p for p in picked if now - p.stat().st_mtime < ACTIVE_S]
    rows = [_row(p, now) for p in picked]
    return {"schema": SCHEMA, "session": one_line(session.stem, 80), "total": len(found),
            "active": sum(now - p.stat().st_mtime < ACTIVE_S for p in found),
            "subagents": rows}


def _ago(iso: str) -> str:
    s = int(time.time() - datetime.fromisoformat(iso).timestamp())
    return "active" if s < ACTIVE_S else f"{s // 60}m ago" if s < 3600 else (
        f"{s // 3600}h ago" if s < 86400 else f"{s // 86400}d ago")


def render(data: dict[str, Any]) -> list[str]:
    head = (f"Subagents of session {data['session']}: {data['active']} active, "
            f"{data['total']} in all")
    if not data["subagents"]:
        return [head, "", "  No subagents."]
    lines = [head, "", f"  {'type':<18} {'health':>6}  {'status':<12} {'cost':>7} "
                       f"{'actions':>7}  {'last':<8}  description"]
    for r in data["subagents"]:
        score = "-" if r["health_score"] is None else f"{r['health_score']:.0f}"
        cost = "-" if r["cost_usd"] is None else f"${r['cost_usd']:.2f}"
        kind = "  " * max((r["depth"] or 1) - 1, 0) + r["type"]  # depth 2 = spawned by a subagent
        lines.append(f"  {kind[:18]:<18} {score:>6}  {(r['status'] or '-')[:12]:<12} "
                     f"{cost:>7} {r['actions']:>7}  {_ago(r['last_activity']):<8}  "
                     f"{r['description']}")
        lines += [f"      {w['severity'].upper()} {w['signal']}: {w['message']}"
                  for w in r["warnings"]]
    if data["total"] > len(data["subagents"]):
        lines += ["", f"  Showing the newest {len(data['subagents'])}; --all for every one."]
    return lines
