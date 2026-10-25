"""opencode session parsing from its SQLite store (read-only).

opencode keeps every session in one SQLite file, ``$XDG_DATA_HOME/opencode/
opencode.db`` (``~/.local/share/opencode/opencode.db``; ``OPENCODE_DB``
overrides it, and non-release channels use ``opencode-<channel>.db``, per
``packages/core/src/database/database.ts::path()`` and
``packages/core/src/global.ts`` at tag v1.18.34). Verified against a live
opencode 1.18.34 session (2026-10-01). Rows used:

- ``session``: ``id``, ``directory`` (the cwd), ``parent_id`` (set on task
  subagent sessions), ``time_updated`` (ms epoch)
- ``message``: ``data`` JSON with ``role``; assistant messages carry
  ``tokens {input, output, reasoning, cache {read, write}}``, ``cost`` and
  ``time.completed`` once the step is over. One assistant message per step.
- ``part``: ``data`` JSON, ``type`` text/tool/patch/step-start/step-finish.
  Tool parts: ``tool``, ``callID``, ``state {status, input, output, error,
  metadata, time {start, end}}``; ``status`` is pending/running/completed/
  error (``session/message-v2.ts``). bash's exit code is
  ``state.metadata.exit``.

Rows are rewritten in place as a step progresses, so a message is only
turned into actions once it is done: its ``time.completed`` is set, or a
later message exists (a user prompt's parts are written before the reply
message is created).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .logs import LogUnreadableError, _redact_truncate, classify_tool, url_hostname
from .models import Action, ToolType

# Tool names from packages/opencode/src/tool/*.ts (v1.18.34). Only read,
# write and bash were seen live. classify_tool() already gets the others
# right by name (edit, apply_patch, glob, grep, webfetch, execute from
# code-mode.ts) except these two:
_TOOL_TYPES = {
    "websearch": ToolType.BROWSER,  # websearch.ts; "search" would say SEARCH
    "todowrite": ToolType.UNKNOWN,  # todo.ts; a todo list, not a file write
}
# Text a tool writes to disk: write.ts content, edit.ts newString,
# apply_patch.ts patchText.
_WRITE_ARGS = ("content", "newString", "patchText")


def open_readonly(db_path: Path) -> sqlite3.Connection:
    """Read-only connection. Still sees rows committed to opencode's WAL.

    Waits up to 1s on a writer's lock before "database is locked".
    """
    return sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=1.0)


def _ms(value: Any) -> datetime | None:
    """ms epoch -> naive UTC; None when missing or bad, never ``datetime.now()`` (#44)."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value / 1000, tz=timezone.utc).replace(tzinfo=None)
        except (OverflowError, OSError, ValueError):
            return None
    return None


def latest_session(
    conn: sqlite3.Connection, directory: Path | None = None, since_ms: int = 0
) -> str | None:
    """Most recently updated top-level session, optionally only for *directory*
    and only if updated at or after *since_ms*."""
    rows = conn.execute(
        "SELECT id, directory FROM session WHERE parent_id IS NULL AND time_updated >= ? "
        "ORDER BY time_updated DESC",
        (since_ms,),
    ).fetchall()
    if directory is None:
        return rows[0][0] if rows else None
    want = directory.resolve()
    for sid, session_dir in rows:
        try:
            if Path(session_dir).resolve() == want:
                return sid
        except (OSError, TypeError):
            continue
    return None


def _tool_action(part: dict, session_id: str, interrupted: bool = False) -> Action | None:
    state = part.get("state")
    if not isinstance(state, dict):
        return None
    if state.get("status") in ("pending", "running"):
        if not interrupted:
            return None  # the row will be rewritten
        # Orphaned by a killed opencode (only a graceful abort marks parts
        # interrupted, processor.ts): report it as a failed call.
        state = {**state, "status": "error", "error": "interrupted"}
    elif state.get("status") not in ("completed", "error"):
        return None
    name = part.get("tool") or "unknown"
    args = state.get("input") if isinstance(state.get("input"), dict) else {}
    times = state.get("time") if isinstance(state.get("time"), dict) else {}
    raw = dict(part)
    written = [args[k] for k in _WRITE_ARGS if isinstance(args.get(k), str)]
    if written:
        # Where the secret scanner reads Claude Code's Write/Edit input.
        raw["input"] = {"content": "\n".join(written)}
    if isinstance(state.get("output"), str):
        raw["content"] = state["output"]  # the scanner's tool_output channel

    action = Action(
        timestamp=_ms(times.get("start")),
        tool_name=name,
        tool_type=_TOOL_TYPES.get(name) or classify_tool(name),
        success=state["status"] == "completed",
        file_path=args.get("filePath") or args.get("path"),
        command=args.get("command") if isinstance(args.get("command"), str) else None,
        network_host=url_hostname(args.get("url")),
        session_id=session_id,
        raw=raw,
    )
    if isinstance(times.get("start"), int) and isinstance(times.get("end"), int):
        action.duration_ms = max(times["end"] - times["start"], 0)
    if not action.success:
        action.error_message = _redact_truncate(str(state.get("error") or "Tool error"), 500)
    else:
        exit_code = (state.get("metadata") or {}).get("exit")
        if isinstance(exit_code, int) and exit_code != 0:
            action.success = False
            action.error_message = f"exit code {exit_code}"
    return action


def message_actions(
    message: dict, parts: list[dict], session_id: str, interrupted: bool = False
) -> list[Action]:
    """Actions for one done message: a user prompt, or one assistant step.

    *interrupted*: the step was cut off, so still-running tool parts are
    emitted as failed calls.
    """
    texts = [
        p["text"] for p in parts
        if p.get("type") == "text" and isinstance(p.get("text"), str)
        and p["text"] and not p.get("synthetic")
    ]
    created = _ms((message.get("time") or {}).get("created"))
    if message.get("role") == "user":
        if not texts:
            return []
        return [Action(
            timestamp=created,
            tool_name="user_message",  # a NON_TOOL_ROLE_LABELS sentinel, like Cursor
            tool_type=ToolType.UNKNOWN,
            success=True,
            incoming_message="\n".join(texts),
            session_id=session_id,
            raw=message,
        )]

    actions = [
        a for p in parts
        if p.get("type") == "tool" and (a := _tool_action(p, session_id, interrupted))
    ]
    if not actions and texts:
        actions = [Action(
            timestamp=created,
            tool_name="text_output",  # as Claude Code does for a text-only reply
            tool_type=ToolType.UNKNOWN,
            success=True,
            session_id=session_id,
            raw={"type": "text"},
        )]
    if actions:
        # The step's usage goes on its first action, like Claude Code's outgoing_data.
        first = actions[0]
        tokens = message.get("tokens") if isinstance(message.get("tokens"), dict) else {}
        cache = tokens.get("cache") if isinstance(tokens.get("cache"), dict) else {}
        first.tokens_in = int(tokens.get("input") or 0)
        first.tokens_out = int(tokens.get("output") or 0) + int(tokens.get("reasoning") or 0)
        first.cache_read_tokens = int(cache.get("read") or 0)
        first.cache_creation_tokens = int(cache.get("write") or 0)
        first.cost_usd = float(message.get("cost") or 0.0)
        first.outgoing_data = "\n".join(texts) or None
    return actions


def read_session(
    conn: sqlite3.Connection, session_id: str, skip: set[str], include_unfinished: bool = False
) -> list[tuple[str, list[Action]]]:
    """(message_id, actions) for each done message not in *skip*, in order.

    *include_unfinished* also takes the newest message while it is still
    running (one-shot reads: its finished tool calls are all there is).
    """
    messages = conn.execute(
        "SELECT id, data FROM message WHERE session_id = ? ORDER BY time_created, id",
        (session_id,),
    ).fetchall()
    out: list[tuple[str, list[Action]]] = []
    decoded: list[dict | None] = []
    for _, data in messages:
        try:
            msg = json.loads(data)
        except (TypeError, json.JSONDecodeError):
            msg = None
        decoded.append(msg if isinstance(msg, dict) else None)
    for i, (mid, _) in enumerate(messages):
        message = decoded[i]
        if mid in skip or message is None:
            continue
        parts = []
        for (pdata,) in conn.execute(
            "SELECT data FROM part WHERE message_id = ? ORDER BY time_created, id", (mid,)
        ):
            try:
                part = json.loads(pdata)
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(part, dict):
                parts.append(part)
        running = any(
            p.get("type") == "tool"
            and isinstance(p.get("state"), dict)
            and p["state"].get("status") in ("pending", "running")
            for p in parts
        )
        # A running tool holds its step even when a later user message exists
        # (prompt.ts writes a queued prompt's row before the step ends). Only a
        # later assistant message releases it: opencode starts the next step
        # after this one ends, so a part still "running" then was orphaned by
        # a killed process (e.g. resumed with `opencode run -s`).
        interrupted = running and any(
            m is not None and m.get("role") == "assistant" for m in decoded[i + 1:]
        )
        if running:
            done = interrupted or include_unfinished
        else:
            done = (
                include_unfinished
                or i + 1 < len(messages)
                or (isinstance(t := message.get("time"), dict) and bool(t.get("completed")))
            )
        if not done:
            break  # keep message order: later messages wait for this one
        try:
            actions = message_actions(message, parts, session_id, interrupted)
        except (AttributeError, TypeError, ValueError):
            # A malformed row (wrong JSON types, #70): skip it, don't end the scan.
            actions = []
        out.append((mid, actions))
    return out


def parse_opencode_session(db_path: Path, session_id: str | None = None) -> list[Action]:
    """One-shot parse of one session (default: the most recently updated)."""
    conn = open_readonly(db_path)
    try:
        sid = session_id or latest_session(conn)
        if sid is None:
            return []
        return [a for _, acts in read_session(conn, sid, set(), True) for a in acts]
    except sqlite3.OperationalError as e:
        # e.g. "database is locked" after open_readonly's busy wait (#70)
        raise LogUnreadableError(db_path, str(e)) from e
    finally:
        conn.close()
