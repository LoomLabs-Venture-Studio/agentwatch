"""`agentwatch statusline`: one short word in Claude Code's status line.

Claude Code runs the `statusLine` command after each assistant message (300 ms
debounce) with session JSON on stdin (`session_id`, `transcript_path`, ...)
and shows what it prints; a run still going when the next update fires is
cancelled (https://code.claude.com/docs/en/statusline). So this reads only the
coach's state file for the session (the hook already ran the detectors), never
the transcript, and imports nothing heavy (`_entry` skips cli.py).

Prints the most severe current HIGH/CRITICAL coached warning as `⚠ loop
~$1.40`, or nothing when healthy (`--ok`: a dim `✓ agentwatch`). No state,
state older than STALE_S, or any error: nothing, exit 0.

`--cost` adds the current 5-hour usage block (`stats --blocks`) as `5h $4.12
→ ~$9.80 · resets 2h13m`: spend so far, projected spend at reset, time left.
Computing it reads transcripts, so the summary is cached in the per-user
state dir for BLOCK_TTL_S and cc_stats is imported only on a miss.
"""

from __future__ import annotations

import json
import math
import os
import sys
import time
from pathlib import Path

from agentwatch.coach import (
    POINTER,
    _atomic_write,
    _private_dir,
    state_dir,
    state_path,
    user_state_dir,
)

STALE_S = 600
BLOCK_CACHE = "block.json"
BLOCK_TTL_S = 60
# A straight-line projection from a block's first minutes is mostly noise.
PROJECT_AFTER_S = 15 * 60
# Only transcripts written in the last day are read on a cache miss.
# ponytail: a block's start is chained from older messages; with more than
# ~24 h of back-to-back blocks the chain is cut and the active block can start
# at a different hour than `stats --blocks` shows. Anchor from the previous
# block's end if that matters.
LOOKBACK_S = 24 * 3600
_now = time.time
_LABELS = {
    "loop": "loop", "reread": "loop",
    "thrash": "thrash", "file_churn": "thrash", "syntax_loop": "thrash",
    "error_spiral": "errors", "error_blindness": "errors", "high_error_rate": "errors",
    "error_class_persistence": "errors",
    "stall": "stuck", "same_outcome": "stuck", "exploration_stall": "stuck",
}
_RANK = {"high": 1, "critical": 2}
_COLOR = {"high": "\x1b[33m", "critical": "\x1b[31m"}
_DIM, _RESET = "\x1b[2m", "\x1b[0m"


def state_dirs() -> list[Path]:
    """Every dir the coach may have written to. The status line runs from
    settings.json without CLAUDE_PLUGIN_DATA, so it follows the hook's pointer
    file in the per-user dir; before the hook has written one, it looks in the
    plugin's data dirs, <config>/plugins/data/agentwatch-<marketplace>/coach."""
    user = user_state_dir()
    try:
        plugin = [Path((user / POINTER).read_text(encoding="utf-8").strip())]
    except OSError:
        plugin = []
    if not plugin or not plugin[0].is_absolute():
        config = os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude"
        plugin = sorted((Path(config) / "plugins" / "data").glob("agentwatch-*/coach"))
    return list(dict.fromkeys([state_dir(), *plugin, user]))


def _load(session_id: str) -> dict | None:
    """The newest state file for the session, or None if none is fresh."""
    newest, mtime = None, 0.0
    for directory in state_dirs():
        path = state_path(directory, session_id)
        try:
            m = path.stat().st_mtime
        except OSError:
            continue
        if m > mtime:
            newest, mtime = path, m
    if newest is None or time.time() - mtime > STALE_S:
        return None
    return json.loads(newest.read_text(encoding="utf-8"))


def _usd(value: object, limit: float = 10_000) -> str | None:
    # Bounded: a corrupt or hostile state file must not print "$1e+300" or "nan".
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not (math.isfinite(value) and 0 <= value < limit):
        return None
    return "<$0.01" if value < 0.01 else f"${value:,.2f}"


def _cost(value: object) -> str:
    text = _usd(value)
    return "" if text is None else f" {text}" if text.startswith("<") else f" ~{text}"


def _active_block(now: float) -> dict | None:
    """The active block's summary {end, cost_usd, projected_cost_usd}, or None.
    Cached in the per-user state dir; recomputed when older than BLOCK_TTL_S."""
    path = user_state_dir() / BLOCK_CACHE
    try:
        if 0 <= now - path.stat().st_mtime < BLOCK_TTL_S:
            cached = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(cached, dict) and "block" in cached:
                return cached["block"]
    except (OSError, ValueError):
        pass  # missing or corrupt: recompute
    from datetime import UTC, datetime

    from agentwatch import cc_stats

    at = datetime.fromtimestamp(now, UTC)
    blocks = cc_stats.compute_blocks(since=now - LOOKBACK_S)
    burn = blocks[-1].burn(at) if blocks else None
    block = None if burn is None else {
        "end": blocks[-1].end.timestamp(),
        "cost_usd": blocks[-1].usage.cost_usd,
        "projected_cost_usd": burn["projected_cost_usd"],
    }
    try:
        if _private_dir(path.parent):
            _atomic_write(path, json.dumps({"block": block}))
    except OSError:
        pass  # uncached: the next refresh scans again
    return block


def _block_text() -> str:
    """`5h $4.12 → ~$9.80 · resets 2h13m`; "" with no active block or on any error."""
    try:
        now = _now()
        block = _active_block(now)
        if not isinstance(block, dict):
            return ""
        left = block["end"] - now
        if not (isinstance(left, (int, float)) and 0 < left <= 5 * 3600):
            return ""  # the cached block has ended (or the cache is nonsense)
        minutes = int(left // 60)
        text = f"resets {minutes // 60}h{minutes % 60:02d}m"
        spent = _usd(block.get("cost_usd"), 1_000_000)
        if spent:  # unpriced model: no dollars, never a guess
            projected = _usd(block.get("projected_cost_usd"), 1_000_000)
            if 5 * 3600 - left < PROJECT_AFTER_S or not (
                block["projected_cost_usd"] >= block["cost_usd"]
            ):
                projected = None
            text = f"{spent}{f' → ~{projected}' if projected else ''} · {text}"
        text = f"5h {text}"
        return f"{_DIM}{text}{_RESET}" if not os.environ.get("NO_COLOR") else text
    except Exception:
        return ""


def render(stdin_text: str, ok: bool = False, cost: bool = False) -> str:
    """The status line text, or "" to print nothing."""
    parts = [_health(stdin_text, ok), _block_text() if cost else ""]
    return " · ".join(p for p in parts if p)


def _health(stdin_text: str, ok: bool) -> str:
    try:
        session_id = json.loads(stdin_text)["session_id"]
        if not isinstance(session_id, str):
            return ""
        state = _load(session_id)
        if state is None:
            return ""
        severe = [
            w for w in state["warnings"]
            if isinstance(w, dict) and w.get("severity") in _RANK and w.get("signal") in _LABELS
        ]
        color = not os.environ.get("NO_COLOR")
        if not severe:
            if not ok:
                return ""
            return f"{_DIM}✓ agentwatch{_RESET}" if color else "✓ agentwatch"
        worst = max(severe, key=lambda w: _RANK[w["severity"]])  # first of the worst
        text = f"⚠ {_LABELS[worst['signal']]}{_cost(worst.get('cost_usd'))}"
        return f"{_COLOR[worst['severity']]}{text}{_RESET}" if color else text
    except Exception:
        return ""


def main(ok: bool = False, cost: bool = False) -> None:
    """Entry for `agentwatch statusline [--ok] [--cost]`: always exits 0."""
    try:
        stdin = getattr(sys.stdin, "buffer", None)
        # utf-8-sig: a PowerShell pipe (`$json | agentwatch statusline`) adds a BOM.
        text = stdin.read().decode("utf-8-sig", "replace") if stdin else sys.stdin.read()
        out = render(text, ok, cost)
        if out:
            # UTF-8 bytes: a piped stdout on Windows is cp1252, which has no ⚠/✓.
            sys.stdout.buffer.write((out + "\n").encode("utf-8"))
            sys.stdout.flush()
    except Exception:
        pass
    sys.exit(0)
