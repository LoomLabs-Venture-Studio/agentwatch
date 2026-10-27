"""`agentwatch report`: what your agents cost you, from the history store.

Sessions are counted in the period their last action falls in. A session
with no price (no token data, or a model with no listed price) is counted
but left out of spend and of the waste %, never guessed. Waste is each
session's `check` waste figure (calls behind health findings, each call once)
summed over sessions.
"""

from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timezone
from typing import Any

from agentwatch.themes import ascii_safe

JSON_SCHEMA = 1
TOP_FINDINGS = 3
# Security finding categories as the report groups them. Counts are findings,
# not secrets: one secret can raise several (secret_leak + secret_in_command),
# and the detectors share no secret identity to merge them by.
SECURITY_GROUPS = {
    "credential": "leaks",
    "network": "egress",
    "exfiltration": "egress",
    "injection": "injection",
    "privilege": "other",
    "supply_chain": "other",
}


def _r(x: float | None) -> float | None:
    return None if x is None else round(x, 4)


def _totals(rows: list[sqlite3.Row]) -> dict[str, Any]:
    priced = [r for r in rows if r["cost_usd"] is not None]
    wasted = [r for r in priced if r["waste_usd"] is not None]
    spend = sum(r["cost_usd"] for r in priced)
    waste = sum(r["waste_usd"] for r in wasted)
    base = sum(r["cost_usd"] for r in wasted)
    return {
        "sessions": len(rows),
        "unpriced_sessions": len(rows) - len(priced),
        "cost_usd": _r(spend) if priced else None,
        "tokens": sum(r["tokens"] or 0 for r in rows),
        "waste_usd": _r(waste) if wasted else None,
        "waste_pct": round(waste / base * 100, 1) if base else None,
        "waste_findings": sum(r["waste_findings"] for r in rows),
    }


def _grouped(rows: list[sqlite3.Row], key: str) -> list[dict[str, Any]]:
    groups: dict[Any, list[sqlite3.Row]] = {}
    for r in rows:
        groups.setdefault(r[key], []).append(r)
    out = [{key: k, **_totals(v)} for k, v in groups.items()]
    out.sort(key=lambda g: (-(g["cost_usd"] or 0), -g["tokens"], str(g[key])))
    return out


def _delta(cur: float | None, prev: float | None) -> float | None:
    return None if cur is None or prev is None else _r(cur - prev)


def build(
    conn: sqlite3.Connection,
    days: int = 7,
    agent: str | None = None,
    project: str | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """The report as plain data; also the --json output (schema JSON_SCHEMA)."""
    conn.row_factory = sqlite3.Row
    end = time.time() if now is None else now
    start = end - days * 86400
    where, args = "", []
    if agent:
        where, args = where + " AND s.agent = ?", [*args, agent]
    if project:
        where, args = where + " AND s.project = ?", [*args, project]

    def sessions(lo: float, hi: float) -> list[sqlite3.Row]:
        return conn.execute(
            "SELECT * FROM sessions s WHERE s.actions > 0 AND s.ended >= ? AND s.ended < ?"
            + where, (lo, hi, *args),
        ).fetchall()

    rows = sessions(start, end)
    prev = _totals(sessions(start - days * 86400, start))
    totals = _totals(rows)
    in_period = (
        "FROM findings f JOIN sessions s USING (log_hash)"
        " WHERE s.actions > 0 AND s.ended >= ? AND s.ended < ?" + where
    )
    top = conn.execute(
        "SELECT f.signal, f.severity, s.agent, s.project, f.cost_usd, f.tokens,"
        " f.first_seen, f.message " + in_period + " AND f.tokens IS NOT NULL"
        " ORDER BY f.cost_usd IS NULL, f.cost_usd DESC, f.tokens DESC LIMIT ?",
        (start, end, *args, TOP_FINDINGS),
    ).fetchall()
    security = {"total": 0, "leaks": 0, "egress": 0, "injection": 0, "other": 0}
    for (category,) in conn.execute(
        "SELECT f.category " + in_period, (start, end, *args)
    ):
        group = SECURITY_GROUPS.get(category)
        if group:
            security[group] += 1
            security["total"] += 1

    return {
        "schema": JSON_SCHEMA,
        "period": {
            "days": days,
            "start": datetime.fromtimestamp(start, timezone.utc).isoformat(),
            "end": datetime.fromtimestamp(end, timezone.utc).isoformat(),
        },
        "filters": {"agent": agent, "project": project},
        "totals": totals,
        "top_findings": [
            {
                "signal": f["signal"], "severity": f["severity"], "agent": f["agent"],
                "project": f["project"], "cost_usd": _r(f["cost_usd"]), "tokens": f["tokens"],
                "date": datetime.fromtimestamp(f["first_seen"], timezone.utc).date().isoformat(),
                "message": f["message"],
            }
            for f in top
        ],
        "by_agent": _grouped(rows, "agent"),
        "by_project": _grouped(rows, "project"),
        "security": security,
        "previous": prev,
        "trend": {
            "cost_usd": _delta(totals["cost_usd"], prev["cost_usd"]),
            "waste_usd": _delta(totals["waste_usd"], prev["waste_usd"]),
        },
    }


def _usd(x: float | None) -> str:
    from agentwatch.detectors.base import format_usd

    return "n/a" if x is None else format_usd(x)


def _signed(x: float | None) -> str:
    return "n/a" if x is None else f"{'+' if x >= 0 else '-'}${abs(x):,.2f}"


def _tok(n: int) -> str:
    from agentwatch.detectors.base import format_tokens

    return format_tokens(n)


def _n(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _cell(x: Any) -> str:
    """A name column: 22 wide, longer names cut with an ellipsis (columns stay aligned)."""
    s, dots = str(x or "-"), ascii_safe("…", "...")
    return f"{s if len(s) <= 22 else s[:22 - len(dots)] + dots:<22}"


def render(rep: dict[str, Any], limit: int = 10) -> list[str]:
    """The report as text lines."""
    t, days = rep["totals"], rep["period"]["days"]
    start = rep["period"]["start"][:10]
    end = rep["period"]["end"][:10]
    scope = "".join(f"  {k}={v}" for k, v in rep["filters"].items() if v)
    lines = [f"agentwatch report: last {days} days ({start} to {end}){scope}", ""]
    if not t["sessions"]:
        return lines + ["  No sessions in this period. Run `agentwatch history sync`."]
    lines.append(f"  Sessions {t['sessions']}   Spend {_usd(t['cost_usd'])}   "
                 f"Tokens {_tok(t['tokens'])}")
    pct = "" if t["waste_pct"] is None else (
        " (<1%)" if t["waste_pct"] < 0.5 else f" ({t['waste_pct']:.0f}%)")
    lines.append(f"  Waste: {_usd(t['waste_usd'])}{pct} "
                 "on stalls, loops, rereads and repeated errors")
    p, tr = rep["previous"], rep["trend"]
    lines.append(f"  vs previous {days} days: spend {_signed(tr['cost_usd'])}, "
                 f"waste {_signed(tr['waste_usd'])}  ({_n(p['sessions'], 'session')}, "
                 f"{_usd(p['cost_usd'])})")
    if t["unpriced_sessions"]:
        n = t["unpriced_sessions"]
        lines.append(f"  Note: {_n(n, 'session')} without a price (no token data or an "
                     "unlisted model): n/a, left out of spend and %.")

    if rep["top_findings"]:
        lines += ["", "  Costliest findings"]
        for f in rep["top_findings"]:
            cost = _usd(f["cost_usd"]) if f["cost_usd"] is not None else f"{_tok(f['tokens'])} tok"
            lines.append(f"    {_cell(f['signal'])} {_cell(f['project'])} {cost:>10}  {f['date']}")

    for title, key in (("By agent", "agent"), ("By project", "project")):
        groups = rep[f"by_{key}"]
        lines += ["", f"  {title}"]
        for g in groups[:limit]:
            lines.append(f"    {_cell(g[key])} {_n(g['sessions'], 'session'):<12} "
                         f"{_usd(g['cost_usd']):>10}   waste {_usd(g['waste_usd'])}")
        if len(groups) > limit:
            lines.append(f"    ... and {len(groups) - limit} more")

    s = rep["security"]
    lines += ["", f"  Security: {_n(s['total'], 'finding')} ({s['leaks']} leak findings, "
              f"{s['egress']} egress, {s['injection']} injection, {s['other']} other)"]
    return lines
