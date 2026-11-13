"""Spend caps for Claude Code sessions: `agentwatch budget`, enforced by the
coach hook on PreToolUse (after the command guard and the loop breaker).

Claude Code's own `--max-budget-usd` works only with `claude -p`. With a cap
set, the hook asks the user (or, with `--action deny`, blocks the call) once
the estimated spend reaches it:

- session: this session's spend (its transcript plus its subagents'). The
  PostToolUse pass adds the new transcript bytes to a running total in the
  coach's state file (`cost_usd`, `cost_scan`); PreToolUse only reads it.
- block: the current 5-hour usage block, all sessions; day: today (local
  time), all sessions. Both come from the `statusline --cost` cache
  (block.json). PreToolUse never computes them: with no cache, or one older
  than CACHE_FRESH_S, those caps are skipped.

Every number is an estimate at list price (cc_stats.usage_cost_usd); a
model with no listed price adds nothing. Subscription users pay no list
price, so the block cap (which tracks the 5-hour usage window) suits them
best.

At ADVISE_AT of a cap the agent is told once (additionalContext). Over a
cap the hook asks with a fixed reason; when that call then runs (its
PostToolUse arrives) the ask counts as approved and the hook stays quiet
until the spend crosses the next STEP over the cap. A block or day cap's
approval ends with its block or day; a changed cap starts over.

Settings: user_state_dir()/budget, JSON {"session"|"block"|"day": USD,
"action": "ask"|"deny"}, 0600 via mkstemp. No file (the default): one
failed open per PreToolUse, nothing else. Any error: no decision.
"""

from __future__ import annotations

import json
import math
import time
from pathlib import Path

from agentwatch.coach import (
    BUDGET,
    _atomic_write,
    _private_dir,
    _writable_state_dir,
    state_path,
    user_state_dir,
)

CAPS = ("session", "block", "day")
ACTIONS = ("ask", "deny")
MAX_USD = 1_000_000.0
ADVISE_AT = 0.8
STEP = 0.25  # re-ask at 125%, 150%, ... of a cap
# The status line refreshes block.json at most every 60 s, and only after an
# assistant message; allow one missed refresh before calling it stale.
CACHE_FRESH_S = 120
# Transcript bytes the PostToolUse pass reads per call: a long session's
# first scan finishes over a few calls instead of tripping the watchdog.
SCAN_CHUNK = 16_000_000
STATE_SUFFIX = "..budget.json"  # never a coach state name: agent ids have no "."
_PENDING_MAX = 20
_WHAT = {
    "session": "this session has spent about {spent}",
    "block": "this 5-hour usage block is at about {spent} across all Claude Code sessions",
    "day": "Claude Code spend today is about {spent} across all sessions",
}


def budget_path() -> Path:
    return user_state_dir() / BUDGET


def _usd_value(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) and 0 <= value < MAX_USD else None


def parse_settings(data: object) -> dict | None:
    """The valid caps (> 0) and action from settings JSON; None when no cap is set."""
    if not isinstance(data, dict):
        return None
    caps = {name: v for name in CAPS
            if (v := _usd_value(data.get(name))) is not None and v > 0}
    if not caps:
        return None
    action = data.get("action")
    return {**caps, "action": action if action in ACTIONS else "ask"}


def load_budget() -> dict | None:
    try:
        return parse_settings(json.loads(budget_path().read_text(encoding="utf-8")))
    except Exception:  # OSError, ValueError, RecursionError on deep nesting
        return None


def save_budget(settings: dict | None) -> Path:
    """Write *settings* (None or no cap: delete the file), 0600 in the 0700 dir."""
    path = budget_path()
    settings = parse_settings(settings)
    if settings is None:
        path.unlink(missing_ok=True)
        return path
    if not _private_dir(path.parent):
        raise OSError(f"{path.parent} is not owned by this user")
    _atomic_write(path, json.dumps(settings))
    return path


def money(value: float) -> str:
    return f"${value:,.2f}"


# --- session spend (PostToolUse writes, PreToolUse reads) ---------------------

def scan_cost(transcript: Path, old: object) -> dict:
    """Add the transcript bytes after the last scan to its running total.

    Claude Code writes one line per content block of an assistant message,
    each with that message's usage, one after another; a repeated message id
    adds only its growth (ActionBuffer's largest-copy rule)."""
    from agentwatch.cc_stats import usage_cost_usd

    scan = old if isinstance(old, dict) else {}
    offset, usd = scan.get("offset"), scan.get("usd")
    last_id, last_cost = scan.get("last_id"), scan.get("last_cost")
    if (type(offset) is not int or offset < 0 or _usd_value(usd) is None
            or _usd_value(last_cost) is None):
        offset, usd, last_id, last_cost = 0, 0.0, None, 0.0
    with open(transcript, "rb") as f:
        size = f.seek(0, 2)
        if size < offset:  # rewritten: start over
            offset, usd, last_id, last_cost = 0, 0.0, None, 0.0
        f.seek(offset)
        data = f.read(SCAN_CHUNK)
    end = data.rfind(b"\n") + 1  # a line still being written waits for the next call
    if end == 0 and len(data) == SCAN_CHUNK:
        end = len(data)  # one line over SCAN_CHUNK: skip past it
    for line in data[:end].splitlines():
        if b'"usage"' not in line or b'"assistant"' not in line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        msg = entry.get("message") if isinstance(entry, dict) else None
        if entry.get("type") != "assistant" or not isinstance(msg, dict):
            continue
        u, msg_id = msg.get("usage"), msg.get("id")
        if not isinstance(u, dict) or not isinstance(msg_id, str) or not msg_id:
            continue
        split = u.get("cache_creation")

        def n(value: object) -> int:
            return value if type(value) is int and value >= 0 else 0
        cost = usage_cost_usd(
            msg.get("model") if isinstance(msg.get("model"), str) else None,
            n(u.get("input_tokens")), n(u.get("output_tokens")),
            n(u.get("cache_creation_input_tokens")), n(u.get("cache_read_input_tokens")),
            n(split.get("ephemeral_1h_input_tokens")) if isinstance(split, dict) else 0)
        if cost is None:
            continue  # unpriced model: no guess
        if msg_id == last_id:
            usd += max(0.0, cost - last_cost)
            last_cost = max(last_cost, cost)
        else:
            usd += cost
            last_id, last_cost = msg_id, cost
    return {"offset": offset + end, "usd": usd, "last_id": last_id, "last_cost": last_cost}


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def session_spend(directory: Path, session_id: str) -> float | None:
    """The session's cost_usd plus its subagents', from the coach's state files."""
    main = state_path(directory, session_id)
    total, found = 0.0, False
    for path in [main, *directory.glob(f"{main.stem}.*.json")]:
        if path.name.endswith(STATE_SUFFIX):
            continue
        cost = _usd_value(_read_json(path).get("cost_usd"))
        if cost is not None:
            total, found = total + cost, True
    return total if found else None


def budget_state_path(directory: Path, session_id: str) -> Path:
    main = state_path(directory, session_id)
    return main.with_name(main.stem + STATE_SUFFIX)


def post_tool_use(payload: dict, transcript: Path, old_state: dict, session_id: str,
                  directory: Path) -> dict:
    """PostToolUse with a budget set: the session state's new cost fields, and
    an ask for this very call (if any) marked approved: the call ran."""
    tool_id = payload.get("tool_use_id")
    path = budget_state_path(directory, session_id)
    state = _read_json(path)
    pending = state.get("pending")
    if isinstance(tool_id, str) and isinstance(pending, list):
        hit = [p for p in pending if isinstance(p, dict) and p.get("id") == tool_id]
        if hit:
            acked = state.get("acked") if isinstance(state.get("acked"), dict) else {}
            for p in hit:
                acked[p.get("name")] = [p.get("scope"), p.get("step")]
            state["acked"] = acked
            state["pending"] = [p for p in pending if p not in hit]
            _atomic_write(path, json.dumps(state))
    scan = scan_cost(transcript, old_state.get("cost_scan"))
    return {"cost_usd": round(scan["usd"], 6), "cost_scan": scan}


# --- PreToolUse -----------------------------------------------------------------

def _usage_cache(now: float) -> dict | None:
    from agentwatch.statusline import BLOCK_CACHE

    path = user_state_dir() / BLOCK_CACHE
    try:
        if not 0 <= now - path.stat().st_mtime < CACHE_FRESH_S:
            return None  # stale: skip, never recompute here
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def spends(settings: dict, directory: Path | None, session_id: str | None,
           now: float) -> list[tuple[str, float, float, str]]:
    """(cap name, spent, cap, scope) for each cap whose spend is known. The
    scope names what an approval is for: the cap value, plus the block's end
    or the day's start."""
    out = []
    if "session" in settings and directory is not None and session_id is not None:
        spent = session_spend(directory, session_id)
        if spent is not None:
            out.append(("session", spent, settings["session"], f"{settings['session']}"))
    if "block" in settings or "day" in settings:
        cache = _usage_cache(now) or {}
        block, day = cache.get("block"), cache.get("day")
        if "block" in settings and isinstance(block, dict):
            end, spent = block.get("end"), _usd_value(block.get("cost_usd"))
            if (spent is not None and isinstance(end, (int, float)) and not isinstance(end, bool)
                    and 0 < end - now <= 5 * 3600):
                out.append(("block", spent, settings["block"], f"{settings['block']}@{end}"))
        if "day" in settings and isinstance(day, dict):
            from agentwatch.statusline import day_start

            start, spent = day.get("start"), _usd_value(day.get("cost_usd"))
            if spent is not None and start == day_start(now):
                out.append(("day", spent, settings["day"], f"{settings['day']}@{start}"))
    return out


def _decision(decision: str, reason: str) -> str:
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }})


def pre_tool_use(settings_text: str, payload: dict, session_id: str) -> str | None:
    """Ask/deny over a cap, an advisory at ADVISE_AT, else None."""
    settings = parse_settings(json.loads(settings_text))
    if settings is None:
        return None
    directory = _writable_state_dir()
    if directory is None:
        return None
    found = spends(settings, directory, session_id, time.time())
    if not found:
        return None
    path = budget_state_path(directory, session_id)
    state = _read_json(path)
    acked = state.get("acked") if isinstance(state.get("acked"), dict) else {}
    warned = state.get("warned") if isinstance(state.get("warned"), dict) else {}

    for name, spent, cap, scope in found:
        if spent < cap:
            continue
        what = _WHAT[name].format(spent=money(spent))
        if settings["action"] == "deny":
            return _decision("deny", (
                f"agentwatch blocked this call: {what} (cap {money(cap)}, an estimate at "
                "list price). Stop and tell the user; they can raise the cap with "
                "`agentwatch budget set` or remove it with `agentwatch budget off`."))
        step = int((spent / cap - 1) / STEP)
        old = acked.get(name)
        if (isinstance(old, list) and len(old) == 2 and old[0] == scope
                and isinstance(old[1], int) and old[1] >= step):
            continue  # approved at this step already
        tool_id = payload.get("tool_use_id")
        if isinstance(tool_id, str) and tool_id:
            pending = state.get("pending") if isinstance(state.get("pending"), list) else []
            pending.append({"id": tool_id, "name": name, "scope": scope, "step": step})
            state["pending"] = pending[-_PENDING_MAX:]
        else:  # no id to confirm the approval by: count the ask as approved
            acked[name] = [scope, step]
            state["acked"] = acked
        _atomic_write(path, json.dumps(state))
        return _decision("ask", f"agentwatch: {what} (cap {money(cap)}). Continue?")

    notes = []
    for name, spent, cap, scope in found:
        if ADVISE_AT * cap <= spent < cap and warned.get(name) != scope:
            warned[name] = scope
            then = ("the user will be asked before more tool calls"
                    if settings["action"] == "ask" else "further tool calls will be blocked")
            notes.append(
                f"agentwatch budget: {_WHAT[name].format(spent=money(spent))}, "
                f"{min(99, round(spent / cap * 100))}% of the {money(cap)} {name} cap (an estimate "
                f"at list price). Finish efficiently; past the cap {then}.")
    if not notes:
        return None
    state["warned"] = warned
    _atomic_write(path, json.dumps(state))
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "additionalContext": "\n".join(notes),
    }})
