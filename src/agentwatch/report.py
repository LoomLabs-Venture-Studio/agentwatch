"""`agentwatch report`: what your agents cost you, from the history store.

Sessions are counted in the period their last action falls in. A session
with no price (no token data, or a model with no listed price) is counted
but left out of spend and of the waste %, never guessed. Waste is each
session's `check` waste figure (calls behind health findings, each call once)
summed over sessions.

Cost by model and cache use come from each session's API calls (each call
once, as spend counts them); errors by type from its failed calls, by kind
and tool name (``history.ERROR_KINDS``). `--format csv` is the JSON report as
one long table: ``table,rank,name,metric,value``.
"""

from __future__ import annotations

import csv
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


def _pct(part: float, whole: float) -> float | None:
    return round(part / whole * 100, 1) if whole else None


def _models(rows: list[sqlite3.Row]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Per (model, agent): calls, tokens, USD, cache hit % and USD saved; and the
    cache totals. USD is null when any call of the row had no price."""
    models, cache = [], dict.fromkeys(
        ("input_tokens", "cache_write_tokens", "cache_write_1h_tokens", "cache_read_tokens"), 0)
    saved: float | None = None
    for r in rows:
        m = {"model": r["model"] or None, "agent": r["agent"], "calls": r["calls"],
             "input_tokens": r["input_tokens"], "output_tokens": r["output_tokens"]}
        for k in cache:
            m[k] = r[k]
            cache[k] += r[k]
        prompt = m["input_tokens"] + m["cache_write_tokens"] + m["cache_read_tokens"]
        m["tokens"] = prompt + r["output_tokens"]
        m["cost_usd"] = _r(r["cost_usd"])
        m["cache_hit_pct"] = _pct(m["cache_read_tokens"], prompt)
        m["cache_saved_usd"] = _r(r["cache_saved_usd"])
        if r["cache_saved_usd"] is not None:
            saved = (saved or 0.0) + r["cache_saved_usd"]
        models.append(m)
    models.sort(key=lambda m: (-(m["cost_usd"] or 0), -m["tokens"], m["model"] or ""))
    prompt = cache["input_tokens"] + cache["cache_write_tokens"] + cache["cache_read_tokens"]
    return models, {**cache, "hit_pct": _pct(cache["cache_read_tokens"], prompt),
                    "saved_usd": _r(saved)}


def _errors(cur: list[sqlite3.Row], prev: list[sqlite3.Row], sessions: int) -> dict[str, Any]:
    """Failed calls by kind (with the previous period's count) and by tool."""
    def tally(rows: list[sqlite3.Row], key: str) -> dict[str, tuple[int, set[str]]]:
        out: dict[str, tuple[int, set[str]]] = {}
        for r in rows:
            n, hashes = out.get(r[key], (0, set()))
            hashes.add(r["log_hash"])
            out[r[key]] = (n + r["count"], hashes)
        return out

    def ranked(groups: dict[str, tuple[int, set[str]]]) -> list[tuple[str, int, set[str]]]:
        return sorted(((k, n, h) for k, (n, h) in groups.items()), key=lambda g: (-g[1], g[0]))

    before = tally(prev, "kind")
    return {
        "failed_calls": sum(r["count"] for r in cur),
        "sessions": len({r["log_hash"] for r in cur}),
        "sessions_pct": _pct(len({r["log_hash"] for r in cur}), sessions),
        "by_kind": [
            {"kind": k, "count": n, "sessions": len(h), "sessions_pct": _pct(len(h), sessions),
             "previous": before.get(k, (0,))[0], "delta": n - before.get(k, (0,))[0]}
            for k, n, h in ranked(tally(cur, "kind"))
        ],
        "by_tool": [{"tool": k, "count": n, "sessions": len(h)}
                    for k, n, h in ranked(tally(cur, "tool"))],
    }


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
    models, cache = _models(conn.execute(
        "SELECT m.model, s.agent, sum(m.calls) calls, sum(m.input_tokens) input_tokens,"
        " sum(m.output_tokens) output_tokens, sum(m.cache_write_tokens) cache_write_tokens,"
        " sum(m.cache_write_1h_tokens) cache_write_1h_tokens,"
        " sum(m.cache_read_tokens) cache_read_tokens,"
        # NULL when any session's USD for this model is unknown: no partial sum
        " CASE WHEN count(m.cost_usd) = count(*) THEN sum(m.cost_usd) END cost_usd,"
        " CASE WHEN count(m.cache_saved_usd) = count(*) THEN sum(m.cache_saved_usd) END"
        " cache_saved_usd FROM session_models m JOIN sessions s USING (log_hash)"
        " WHERE s.actions > 0 AND s.ended >= ? AND s.ended < ?" + where
        + " GROUP BY m.model, s.agent", (start, end, *args),
    ).fetchall())

    def failed(lo: float, hi: float) -> list[sqlite3.Row]:
        return conn.execute(
            "SELECT e.log_hash, e.kind, e.tool, e.count FROM session_errors e"
            " JOIN sessions s USING (log_hash)"
            " WHERE s.actions > 0 AND s.ended >= ? AND s.ended < ?" + where, (lo, hi, *args),
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
        "models": models,
        "cache": cache,
        "errors": _errors(failed(start, end), failed(start - days * 86400, start),
                          totals["sessions"]),
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

    if rep["models"]:
        lines += ["", "  Cost by model"]
        for m in rep["models"][:limit]:
            hit = "" if m["cache_hit_pct"] is None else f"   cache {m['cache_hit_pct']:.0f}%"
            lines.append(f"    {_cell(m['model'] or '(not logged)')} {m['agent']:<12} "
                         f"{_tok(m['tokens']):>7} tok {_usd(m['cost_usd']):>10}{hit}")
        if len(rep["models"]) > limit:
            lines.append(f"    ... and {len(rep['models']) - limit} more")
        c = rep["cache"]
        if c["hit_pct"] is not None:
            write = c["cache_write_tokens"]
            lines.append(
                f"  Cache: {c['hit_pct']:.0f}% of input read from cache "
                f"({_tok(c['cache_read_tokens'])} read, {_tok(write)} written "
                f"[{_tok(write - c['cache_write_1h_tokens'])} 5m, "
                f"{_tok(c['cache_write_1h_tokens'])} 1h], "
                f"{_tok(c['input_tokens'])} uncached)")
            if c["saved_usd"] is not None:
                lines.append(f"  Cache saved {_usd(c['saved_usd'])} against the input rate "
                             "(priced models)")

    e = rep["errors"]
    if e["failed_calls"]:
        lines += ["", f"  Errors by type: {_n(e['failed_calls'], 'failed call')} in "
                  f"{_n(e['sessions'], 'session')} ({e['sessions_pct']:.0f}%)"]
        for k in e["by_kind"][:limit]:
            share = f"{_n(k['sessions'], 'session')} ({k['sessions_pct']:.0f}%)"
            lines.append(f"    {_cell(k['kind'])} {k['count']:>6}   {share:<20} "
                         f"{k['delta']:+d} vs previous")
        tools = ", ".join(f"{t['tool']} {t['count']}" for t in e["by_tool"][:limit])
        lines.append(f"    by tool: {tools}")

    s = rep["security"]
    lines += ["", f"  Security: {_n(s['total'], 'finding')} ({s['leaks']} leak findings, "
              f"{s['egress']} egress, {s['injection']} injection, {s['other']} other)"]
    return lines


CSV_HEADER = ("table", "rank", "name", "metric", "value")


def _flat(table: str, v: Any, rank: Any = "", name: Any = ""):
    if isinstance(v, list):  # ranked rows: the first field names the row
        for i, item in enumerate(v, 1):
            rest = dict(item)
            yield from _flat(table, rest, i, rest.pop(next(iter(item))))
    elif v and all(isinstance(x, dict) for x in v.values()) and not name:
        for n, x in v.items():  # {name: {metric: value}}, as `stats --json` has
            yield from _flat(table, x, "", n)
    else:
        for k, x in v.items():
            if isinstance(x, (dict, list)):
                yield from _flat(f"{table}.{k}", x, rank, name)
            else:
                yield table, rank, name, k, x


def write_csv(data: dict[str, Any], out: Any, root: str = "report") -> None:
    """*data* (the --json output) as one long CSV table, header CSV_HEADER:
    one row per value. Top-level values are table *root*; nested ones are
    named by their key path (``errors.by_kind``); list rows carry their rank
    and their first field as the name. Empty value = null."""
    w = csv.writer(out, lineterminator="\n")
    w.writerow(CSV_HEADER)
    for key, v in data.items():
        rows = _flat(key, v) if isinstance(v, (dict, list)) else [(root, "", "", key, v)]
        w.writerows(map(_csv_cell, row) for row in rows)


def _csv_cell(x: Any) -> Any:
    """None as empty; text a spreadsheet would run as a formula gets a leading '."""
    if x is None:
        return ""
    return "'" + x if isinstance(x, str) and x[:1] in ("=", "+", "-", "@", "\t", "\r") else x
