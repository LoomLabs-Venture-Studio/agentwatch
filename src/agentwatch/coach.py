"""Coach: a Claude Code hook that tells the agent when it is going wrong.

`agentwatch hook` runs on PostToolUse / PostToolUseFailure. It reads the hook
JSON from stdin, parses the tail of the session transcript with the Claude
Code parser, runs the health detectors, and when a new HIGH/CRITICAL warning
appears it prints a short note that Claude Code adds to Claude's context.

Hook contract (https://code.claude.com/docs/en/hooks): stdin carries
`session_id`, `transcript_path`, `hook_event_name`, `tool_name`, ...; exit 0
with `{"hookSpecificOutput": {"hookEventName": <event>, "additionalContext":
<text>}}` on stdout adds the text next to the tool result without blocking.
Stderr on exit 0 is never shown, and any other exit code shows a "hook error"
notice, so every failure here is silent: exit 0, nothing on stdout.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

EVENTS = ("PostToolUse", "PostToolUseFailure")
# Seconds before the watchdog exits 0 silently. hooks.json allows 10.
BUDGET_S = 5.0
# ponytail: fixed byte tail of the transcript. ActionBuffer keeps only the last
# 500 actions anyway; widen if a detector ever needs older history.
TAIL_BYTES = 4_000_000
_MAX_LINE = 200
# Context estimates (context_pressure) are not something the agent can act on
# mid-task, and they fire on most long sessions; coach only loops, thrashing,
# error spirals and stuck patterns (PROGRESS / ERRORS detectors).
_COACHED = ("progress", "errors")
_SEVERE = ("high", "critical")
_EVIDENCE_KEYS = ("last_error", "error_pattern", "recent_errors", "sample_errors",
                  "last_command", "path", "file_path")


def state_dir() -> Path:
    return Path(tempfile.gettempdir()) / "agentwatch-coach"


def _state_path(session_id: str) -> Path:
    return state_dir() / (re.sub(r"[^A-Za-z0-9_-]", "_", session_id)[:100] + ".json")


def _load_reported(path: Path) -> set[str]:
    try:
        return set(json.loads(path.read_text(encoding="utf-8"))["reported"])
    except Exception:
        return set()


def _save(path: Path, reported: set[str], warnings: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps({
        "updated": datetime.now(timezone.utc).isoformat(),
        "reported": sorted(reported),
        # Latest health snapshot, for a future `agentwatch statusline`.
        "warnings": [
            {"severity": w.severity.value, "signal": w.signal, "message": w.message}
            for w in warnings
        ],
    }), encoding="utf-8")
    os.replace(tmp, path)


def _tail_actions(transcript: Path):
    from agentwatch.parser.logs import parse_claude_code_entry

    with open(transcript, "rb") as f:
        size = f.seek(0, os.SEEK_END)
        start = max(0, size - TAIL_BYTES)
        f.seek(start)
        lines = f.read().splitlines()
    if start:
        lines = lines[1:]  # first line is cut mid-record
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        result = parse_claude_code_entry(entry)
        if isinstance(result, list):
            yield from result
        elif result:
            yield result


def _one_line(text: object) -> str:
    from agentwatch.detectors.security.secret_scanner import redact_truncate

    return " ".join(redact_truncate(str(text), _MAX_LINE * 2).split())[:_MAX_LINE]


def format_message(warning) -> str:
    """At most 3 lines: what is wrong, evidence, what to try."""
    lines = [_one_line(f"agentwatch coach [{warning.severity.value}]: {warning.message}")]
    for key in _EVIDENCE_KEYS:
        value = warning.details.get(key)
        if isinstance(value, list):
            value = value[0] if value else None
        if value:
            lines.append(_one_line(f"Evidence ({key}): {value}"))
            break
    lines.append(_one_line(
        f"Try: {warning.suggestion or 'Stop, re-read the goal, and change approach.'}"
    ))
    return "\n".join(lines)


def run(stdin_text: str) -> str | None:
    """Return the hook's stdout JSON, or None to print nothing."""
    try:
        payload = json.loads(stdin_text)
        event = payload["hook_event_name"]
        session_id = payload["session_id"]
        transcript = Path(payload["transcript_path"])
        if event not in EVENTS or not isinstance(session_id, str):
            return None
        if not transcript.is_file():
            return None

        from agentwatch.detectors.base import warning_dedup_key
        from agentwatch.detectors.registry import create_registry
        from agentwatch.parser.models import ActionBuffer

        buffer = ActionBuffer()
        for action in _tail_actions(transcript):
            buffer.add(action)
        warnings = create_registry("health").check_health(buffer)
        severe = {
            warning_dedup_key(w): w for w in warnings
            if w.severity.value in _SEVERE and w.category.value in _COACHED
        }

        state = _state_path(session_id)
        # Forget warnings that cleared, so a recurrence is reported again.
        reported = _load_reported(state) & severe.keys()
        new = [k for k in severe if k not in reported]
        if new:
            reported.add(new[0])  # one note per call; the rest come next call
        _save(state, reported, warnings)
        if not new:
            return None
        return json.dumps({"hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": format_message(severe[new[0]]),
        }})
    except Exception:
        return None


def main() -> None:
    """Entry for `agentwatch hook`: always exits 0, prints JSON or nothing."""
    watchdog = threading.Timer(BUDGET_S, os._exit, args=(0,))
    watchdog.daemon = True
    watchdog.start()
    try:
        stdin = getattr(sys.stdin, "buffer", None)
        out = run(stdin.read().decode("utf-8", "replace") if stdin else sys.stdin.read())
        if out:
            sys.stdout.write(out + "\n")
            sys.stdout.flush()
    except Exception:
        pass
    finally:
        watchdog.cancel()
    sys.exit(0)
