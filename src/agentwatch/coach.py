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

Loop breaker: when a `loop` warning is HIGH, the PostToolUse pass "arms" it in
the session state (loop_id hash, count, cost; never command text). On
PreToolUse the hook reads only that state, keys the incoming call the way
LoopDetector does, and if it is the armed loop's next call denies it once with
`{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision":
"deny", "permissionDecisionReason": <fixed text>}}` (the reason is shown to
Claude). The retry is allowed; the entry is dropped when the loop is no longer
HIGH, so a new loop blocks again. AGENTWATCH_LOOP_BREAKER=off disables it.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import time
from pathlib import Path

# tempfile, threading and datetime are imported where used: `agentwatch statusline`
# imports this module for its state helpers on every status line update.

EVENTS = ("PostToolUse", "PostToolUseFailure")
# Seconds before the watchdog exits 0 silently. hooks.json allows 10.
BUDGET_S = 5.0
# ponytail: fixed byte tail of the transcript. ActionBuffer keeps only the last
# 500 actions anyway; widen if a detector ever needs older history.
TAIL_BYTES = 4_000_000
STATE_MAX_AGE_S = 7 * 24 * 3600
# File in user_state_dir() naming the dir the hook writes state to (no .json,
# so never pruned).
POINTER = "state-dir"
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
# Bash commands that repeat on purpose (polling, test runs): warned, never blocked.
LOOP_ALLOW = ("sleep", "gh run watch", "gh pr checks", "git status", "git log",
              "git diff", "pytest", "python -m pytest", "npm test", "pnpm test",
              "yarn test", "cargo test", "go test", "make test")


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
    import tempfile

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


def _load_armed(path: Path) -> dict:
    try:
        armed = json.loads(path.read_text(encoding="utf-8"))["armed"]
        return armed if isinstance(armed, dict) else {}
    except Exception:
        return {}


def _armed(warnings: list, old: dict) -> dict | None:
    """The HIGH loop to block on the next PreToolUse, keeping its blocked flag."""
    loop = next((w for w in warnings
                 if w.signal == "loop" and w.severity.value == "high"), None)
    if loop is None:
        return None
    loop_id = loop.details["loop_id"]
    armed = {"loop_id": loop_id, "count": loop.details["count"],
             "blocked": old.get("loop_id") == loop_id and bool(old.get("blocked"))}
    if loop.cost_usd is not None:
        armed["cost_usd"] = round(loop.cost_usd, 4)
    return armed


def state_path(directory: Path, key: str) -> Path:
    """The state file for a session (or session.agent) key, always inside *directory*."""
    return directory / (re.sub(r"[^A-Za-z0-9_.-]", "_", key)[:150] + ".json")


def _snapshot(warning) -> dict:
    snap = {"severity": warning.severity.value, "signal": warning.signal,
            "message": warning.message}
    if warning.cost_usd is not None:
        snap["cost_usd"] = round(warning.cost_usd, 4)
    return snap


def _atomic_write(path: Path, text: str) -> None:
    import tempfile

    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def _save(path: Path, reported: set[str], warnings: list, armed: dict | None = None) -> None:
    from datetime import datetime, timezone

    data = {
        "updated": datetime.now(timezone.utc).isoformat(),
        "reported": sorted(reported),
        # Latest health snapshot, read by `agentwatch statusline`.
        "warnings": [_snapshot(w) for w in warnings],
    }
    if armed:
        data["armed"] = armed  # read by the PreToolUse loop breaker
    _atomic_write(path, json.dumps(data))


def _write_pointer(directory: Path) -> None:
    """Record *directory* in the per-user dir for `agentwatch statusline`, which
    runs without CLAUDE_PLUGIN_DATA. Written only when it changes."""
    pointer = user_state_dir() / POINTER
    try:
        if pointer.read_text(encoding="utf-8") == str(directory):
            return
    except OSError:
        pass
    try:
        if _private_dir(pointer.parent):
            _atomic_write(pointer, str(directory))
    except OSError:
        pass


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
    from agentwatch.detectors.security.secret_scanner import one_line

    return one_line(text, _MAX_LINE).replace("<", "").replace(">", "")


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


def call_loop_id(tool_name: str, tool_input: object) -> str:
    """LoopDetector's details["loop_id"] for one call: built through the same
    Claude Code parser and `_loop_key`, so the two always agree."""
    import hashlib

    from agentwatch.detectors.health.loops import _loop_key

    block = {"type": "tool_use", "name": tool_name,
             "input": tool_input if isinstance(tool_input, dict) else {}}
    action = next(_parse([{"type": "assistant",
                           "message": {"role": "assistant", "content": [block]}}]))
    return hashlib.sha1(_loop_key(action).encode()).hexdigest()[:12]


def _breaker(payload: dict, key: str) -> str | None:
    """PreToolUse: deny the armed loop's next call, once. Reads only state."""
    if os.environ.get("AGENTWATCH_LOOP_BREAKER", "").strip().lower() == "off":
        return None
    name, tool_input = payload["tool_name"], payload.get("tool_input")
    if not isinstance(name, str):
        return None
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if name == "Bash" and isinstance(command, str) and command.lstrip().startswith(LOOP_ALLOW):
        return None
    directory = _writable_state_dir()
    if directory is None:
        return None
    path = state_path(directory, key)
    state = json.loads(path.read_text(encoding="utf-8"))
    armed = state["armed"]
    if armed.get("blocked") or armed.get("loop_id") != call_loop_id(name, tool_input):
        return None
    armed["blocked"] = True
    _atomic_write(path, json.dumps(state))

    from agentwatch.detectors.base import format_usd

    cost = armed.get("cost_usd")
    known = isinstance(cost, (int, float)) and cost >= 0.005  # format_usd: no "<$0.01"
    spent = f" ({format_usd(cost)} so far)" if known else ""
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": (
            f"agentwatch blocked this call: the same action ran {int(armed['count'])} "
            f"times in the last 10 calls{spent}. Change approach: read the last error "
            "and fix its cause, or ask the user."),
    }})


def run(stdin_text: str) -> str | None:
    """Return the hook's stdout JSON, or None to print nothing."""
    try:
        payload = json.loads(stdin_text)
        event = payload["hook_event_name"]
        session_id = payload["session_id"]
        agent_id = payload.get("agent_id")
        if not isinstance(session_id, str):
            return None
        key = session_id if agent_id is None else f"{session_id}.{agent_id}"
        if agent_id is not None and (not isinstance(agent_id, str) or not _ID.fullmatch(agent_id)):
            return None
        if event == "PreToolUse":
            return _breaker(payload, key)
        transcript = Path(payload["transcript_path"])
        if event not in EVENTS:
            return None
        if agent_id is not None:
            # Subagent hooks carry the parent's transcript_path; the subagent's
            # own log is <transcript>/subagents/agent-<agent_id>.jsonl.
            transcript = transcript.with_suffix("") / "subagents" / f"agent-{agent_id}.jsonl"
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
        state = state_path(directory, key)
        # Forget warnings that cleared, so a recurrence is reported again.
        reported = _load_reported(state) & severe.keys()
        new = [k for k in severe if k not in reported]
        if new:
            reported.add(new[0])  # one note per call; the rest come next call
        _save(state, reported, warnings, _armed(warnings, _load_armed(state)))
        if directory != user_state_dir():
            _write_pointer(directory)
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
    import threading

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
