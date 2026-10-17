"""Coach: a Claude Code hook that tells the agent when it is going wrong.

`agentwatch hook` runs on PostToolUse / PostToolUseFailure. It reads the hook
JSON from stdin, parses the tail of the session transcript with the Claude
Code parser, runs the health detectors, and when a new HIGH/CRITICAL warning
appears it prints a short note that Claude Code adds to Claude's context.

Hook contract (https://code.claude.com/docs/en/hooks): stdin carries
`session_id`, `transcript_path`, `hook_event_name`, `tool_name`,
`tool_use_id`, `agent_id` (in a subagent), `error` (PostToolUseFailure), ...;
exit 0 with `{"hookSpecificOutput": {"hookEventName": <event>,
"additionalContext": <text>}}` on stdout adds the text next to the tool
result without blocking. Stderr on exit 0 is never shown, and any other exit
code shows a "hook error" notice, so every failure here is silent: exit 0,
nothing on stdout.

The note is shown to Claude as a system reminder, so transcript text in it
is labelled as quoted tool output, stripped of `<`/`>`, and kept out of the
"Try" line, which is fixed text per signal.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

EVENTS = ("PostToolUse", "PostToolUseFailure")
# Seconds before the watchdog exits 0 silently. hooks.json allows 10.
BUDGET_S = 5.0
# ponytail: fixed byte tail of the transcript. ActionBuffer keeps only the last
# 500 actions anyway; widen if a detector ever needs older history.
TAIL_BYTES = 4_000_000
STATE_MAX_AGE_S = 7 * 24 * 3600
_MAX_LINE = 200
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
# Context estimates (context_pressure) are not something the agent can act on
# mid-task, and they fire on most long sessions; coach only loops, thrashing,
# error spirals and stuck patterns (PROGRESS / ERRORS detectors).
_COACHED = ("progress", "errors")
_SEVERE = ("high", "critical")
_ERROR_KEYS = ("last_error", "error_pattern", "recent_errors", "sample_errors")
_OTHER_KEYS = ("last_command", "path", "file_path")
_TIPS = {
    "loop": "The same action keeps repeating. Stop and try a different approach.",
    "thrash": "Edits keep failing the same check. Stop editing, re-read the failure, "
              "rethink the fix.",
    "error_spiral": "Nothing has succeeded recently. Go back to the last working state "
                    "or change approach.",
    "error_blindness": "The same error keeps coming back. Read it and fix its cause "
                       "before retrying.",
    "high_error_rate": "Most recent tool calls failed. Check paths, environment and "
                       "commands before retrying.",
    "same_outcome": "Different attempts end the same way. Find the root cause first.",
    "file_churn": "The same file keeps being rewritten. Settle the design before "
                  "editing again.",
    "exploration_stall": "Lots of reading and failing without progress. Pick one "
                         "hypothesis and test it.",
    "error_class_persistence": "The same kind of error persists. Fix its cause instead "
                               "of retrying variants.",
}
_DEFAULT_TIP = "Stop, re-read the goal, and change approach."


def state_dir() -> Path:
    """$CLAUDE_PLUGIN_DATA/coach, else the per-user cache dir (never shared /tmp)."""
    plugin_data = os.environ.get("CLAUDE_PLUGIN_DATA")
    if plugin_data:
        return Path(plugin_data) / "coach"
    return user_state_dir()


def user_state_dir() -> Path:
    """%LOCALAPPDATA% or ~/.cache + agentwatch/coach."""
    if sys.platform == "win32":
        root = os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local"
    else:
        root = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(root) / "agentwatch" / "coach"


def _private_dir(path: Path) -> bool:
    """Create *path* 0o700; on POSIX refuse a dir (or symlink) we do not own."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "posix":
        return True  # per-user %LOCALAPPDATA% / plugin data; ACLs, not modes
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        return False
    if st.st_mode & 0o077:
        os.chmod(path, 0o700)
    return True


def _writable_state_dir() -> Path | None:
    """state_dir(), or the per-user dir when that one cannot be written."""
    for directory in dict.fromkeys((state_dir(), user_state_dir())):
        try:
            if not _private_dir(directory):
                return None  # not ours (POSIX): stay silent, do not fall back
            with tempfile.TemporaryFile(dir=directory):
                return directory
        except OSError:
            continue
    return None


def _prune(directory: Path) -> None:
    cutoff = time.time() - STATE_MAX_AGE_S
    for p in directory.iterdir():
        try:
            if p.suffix in (".json", ".tmp") and p.stat().st_mtime < cutoff:
                p.unlink()
        except OSError:
            pass


def _load_reported(path: Path) -> set[str]:
    try:
        return set(json.loads(path.read_text(encoding="utf-8"))["reported"])
    except Exception:
        return set()


def _save(path: Path, reported: set[str], warnings: list) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({
                "updated": datetime.now(timezone.utc).isoformat(),
                "reported": sorted(reported),
                # Latest health snapshot, for a future `agentwatch statusline`.
                "warnings": [
                    {"severity": w.severity.value, "signal": w.signal, "message": w.message}
                    for w in warnings
                ],
            }, f)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def _parse(entries):
    from agentwatch.parser.logs import parse_claude_code_entry

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        result = parse_claude_code_entry(entry)
        if isinstance(result, list):
            yield from result
        elif result:
            yield result


def _tail_entries(transcript: Path):
    with open(transcript, "rb") as f:
        size = f.seek(0, os.SEEK_END)
        start = max(0, size - TAIL_BYTES)
        f.seek(start)
        lines = f.read().splitlines()
    if start:
        lines = lines[1:]  # first line is cut mid-record
    for line in lines:
        try:
            yield json.loads(line)
        except ValueError:
            continue


def _current_call(payload: dict, actions: list) -> list:
    """The hook's own tool call, when the (async) transcript lacks it yet."""
    tool_id, name = payload.get("tool_use_id"), payload.get("tool_name")
    if not isinstance(tool_id, str) or not isinstance(name, str):
        return []
    recent = [a.raw for a in actions[-50:] if isinstance(a.raw, dict)]
    ts = next((a.timestamp.isoformat() for a in reversed(actions) if a.timestamp), None)
    entries = []
    if not any(r.get("id") == tool_id for r in recent):
        tool_input = payload.get("tool_input")
        entries.append({"type": "assistant", "timestamp": ts, "message": {
            "role": "assistant", "content": [{
                "type": "tool_use", "id": tool_id, "name": name,
                "input": tool_input if isinstance(tool_input, dict) else {},
            }]}})
    if payload["hook_event_name"] == "PostToolUseFailure" and not any(
        r.get("tool_use_id") == tool_id for r in recent
    ):
        entries.append({"type": "user", "timestamp": ts, "message": {
            "role": "user", "content": [{
                "type": "tool_result", "tool_use_id": tool_id, "is_error": True,
                "content": str(payload.get("error") or "Tool error"),
            }]}})
    return list(_parse(entries))


def _last_line(text: object) -> str:
    lines = [line.strip() for line in str(text).splitlines() if line.strip()]
    return lines[-1] if lines else ""


def _clean(text: object) -> str:
    from agentwatch.detectors.security.secret_scanner import redact_truncate

    collapsed = " ".join(str(text).split())
    return redact_truncate(collapsed, _MAX_LINE).replace("<", "").replace(">", "")


def _evidence(warning, actions: list) -> str | None:
    for key in _ERROR_KEYS + _OTHER_KEYS:
        value = warning.details.get(key)
        if isinstance(value, list):
            value = value[0] if value else None
        if not value:
            continue
        if key not in _ERROR_KEYS:
            return str(value)
        # The detail is often cut at 100 chars, before the line that names the
        # error (ModuleNotFoundError: ...). Find the full error it came from.
        needle = _last_line(value)
        full = next((
            a.error_message for a in reversed(actions[-50:])
            if not a.success and a.error_message and needle and needle in a.error_message
        ), value)
        return _last_line(full)
    return None


def format_message(warning, actions: list = ()) -> str:
    """At most 3 lines: what is wrong, quoted evidence, fixed advice."""
    lines = [f"agentwatch coach [{warning.severity.value}]: {_clean(warning.message)}"]
    evidence = _evidence(warning, list(actions))
    if evidence:
        quoted = _clean(evidence).replace('"', "'")  # tool output cannot close the quote
        lines.append(f'Evidence (tool output, quoted): "{quoted}"')
    lines.append(f"Try: {_TIPS.get(warning.signal, _DEFAULT_TIP)}")
    return "\n".join(lines)


def run(stdin_text: str) -> str | None:
    """Return the hook's stdout JSON, or None to print nothing."""
    try:
        payload = json.loads(stdin_text)
        event = payload["hook_event_name"]
        session_id = payload["session_id"]
        transcript = Path(payload["transcript_path"])
        agent_id = payload.get("agent_id")
        if event not in EVENTS or not isinstance(session_id, str):
            return None
        key = session_id
        if agent_id is not None:
            # Subagent hooks carry the parent's transcript_path; the subagent's
            # own log is <transcript>/subagents/agent-<agent_id>.jsonl.
            if not isinstance(agent_id, str) or not _ID.fullmatch(agent_id):
                return None
            transcript = transcript.with_suffix("") / "subagents" / f"agent-{agent_id}.jsonl"
            key = f"{session_id}.{agent_id}"
        if not transcript.is_file():
            return None

        from agentwatch.detectors.base import warning_dedup_key
        from agentwatch.detectors.registry import create_registry
        from agentwatch.parser.models import ActionBuffer

        actions = list(_parse(_tail_entries(transcript)))
        actions += _current_call(payload, actions)
        buffer = ActionBuffer()
        for action in actions:
            buffer.add(action)
        warnings = create_registry("health").check_health(buffer)
        severe = {
            warning_dedup_key(w): w for w in warnings
            if w.severity.value in _SEVERE and w.category.value in _COACHED
        }

        directory = _writable_state_dir()
        if directory is None:
            return None
        _prune(directory)
        state = directory / (re.sub(r"[^A-Za-z0-9_.-]", "_", key)[:150] + ".json")
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
            "additionalContext": format_message(severe[new[0]], actions),
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
