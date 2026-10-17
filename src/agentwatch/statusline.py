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
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from agentwatch.coach import state_dir, state_path, user_state_dir

STALE_S = 600
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
    settings.json without CLAUDE_PLUGIN_DATA, so look in the plugin's data dir
    (<config>/plugins/data/agentwatch*/coach) as well as the per-user dir."""
    config = os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude"
    plugin = sorted((Path(config) / "plugins" / "data").glob("agentwatch*/coach"))
    return list(dict.fromkeys([state_dir(), *plugin, user_state_dir()]))


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


def _cost(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return ""
    return " <$0.01" if value < 0.005 else f" ~${value:,.2f}"


def render(stdin_text: str, ok: bool = False) -> str:
    """The status line text, or "" to print nothing."""
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


def main(ok: bool = False) -> None:
    """Entry for `agentwatch statusline [--ok]`: always exits 0."""
    try:
        stdin = getattr(sys.stdin, "buffer", None)
        # utf-8-sig: a PowerShell pipe (`$json | agentwatch statusline`) adds a BOM.
        text = stdin.read().decode("utf-8-sig", "replace") if stdin else sys.stdin.read()
        out = render(text, ok)
        if out:
            # UTF-8 bytes: a piped stdout on Windows is cp1252, which has no ⚠/✓.
            sys.stdout.buffer.write((out + "\n").encode("utf-8"))
            sys.stdout.flush()
    except Exception:
        pass
    sys.exit(0)
