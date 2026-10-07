"""Gemini CLI session (JSONL) log parsing.

Gemini CLI writes one ``session-<ts>-<id8>.jsonl`` per session under
``~/.gemini/tmp/<project-short-id>/chats/`` (subagents: ``chats/<parent-id>/
<id>.jsonl``). Shape per ``packages/core/src/services/chatRecording{Service,
Types}.ts`` (google-gemini/gemini-cli v0.62.0) and the live 0.62.0 run in
docs/research/agent-live-test-2026-10-05.md:

- line 1, header: ``{"sessionId", "projectHash", "startTime", "lastUpdated", "kind"}``
- messages: ``{"id", "timestamp", "type": "user"|"gemini"|"info"|"error"|"warning",
  "content", ...}``; a ``gemini`` message also has ``toolCalls`` (``id``,
  ``name``, ``args``, ``result``, ``status``, ``timestamp``), ``tokens``
  (``input``/``output``/``cached``/``thoughts``/``tool``/``total``) and ``model``
- ``{"$set": {...}}`` metadata patches (``$set.messages`` is a full checkpoint)
  and ``{"$rewindTo": "<message id>"}``

The whole message is re-appended under the same ``id`` every time it changes
(tool status, result, tokens), so actions are emitted once per id: a tool call
when its status is final, a model turn's tokens when they first appear.
"""

from __future__ import annotations

import re
from typing import Any

from .logs import _parse_timestamp, classify_tool
from .models import Action, ToolType

# CoreToolCallStatus (packages/core/src/scheduler/types.ts); the rest
# (validating/scheduled/executing/awaiting_approval) are still in flight.
_FINAL_STATUSES = frozenset({"success", "error", "cancelled"})
# run_shell_command reports a non-zero exit as status "success" with an
# "Exit Code: N" line in its output (packages/core/src/tools/shell.ts).
_EXIT_CODE = re.compile(r"^Exit Code: (-?\d+)$", re.MULTILINE)


def _text(content: Any) -> str:
    """Text of a PartListUnion: a string, or parts with ``text``."""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        content = [content]
    if not isinstance(content, list):
        return ""
    return "".join(
        p if isinstance(p, str) else p.get("text", "") if isinstance(p, dict) else ""
        for p in content
    )


def _response(result: Any) -> dict:
    """``functionResponse.response`` (``{"output": ...}`` or ``{"error": ...}``)."""
    for part in result if isinstance(result, list) else [result]:
        if isinstance(part, dict) and isinstance(part.get("functionResponse"), dict):
            response = part["functionResponse"].get("response")
            if isinstance(response, dict):
                return response
    return {}


class GeminiParser:
    """Stateful parser for one Gemini CLI ``session-*.jsonl`` stream."""

    def __init__(self, session_id: str | None = None):
        self.session_id = session_id
        self._emitted: set[str] = set()  # user message ids, tool call ids, token-turn ids
        self._pending: dict[str, Action] = {}  # tool calls not final yet

    def parse_line(self, entry: dict) -> list[Action]:
        if "projectHash" in entry and "sessionId" in entry:
            self.session_id = entry.get("sessionId") or self.session_id
            return []
        patch = entry.get("$set")
        if isinstance(patch, dict):
            messages = patch.get("messages")
            if isinstance(messages, list):  # checkpoint: already-emitted ids are skipped
                return [a for m in messages if isinstance(m, dict) for a in self._message(m)]
            return []
        # ponytail: $rewindTo is ignored; already-emitted actions are not retracted.
        return self._message(entry)

    def _message(self, msg: dict) -> list[Action]:
        msg_id = msg.get("id")
        if not isinstance(msg_id, str):
            return []
        timestamp = _parse_timestamp(msg)

        if msg.get("type") == "user":
            text = _text(msg.get("content"))
            if not text or msg_id in self._emitted:
                return []
            self._emitted.add(msg_id)
            return [Action(
                timestamp=timestamp,
                tool_name="user_message",  # a NON_TOOL_ROLE_LABELS sentinel, like Cursor
                tool_type=ToolType.UNKNOWN,
                success=True,
                incoming_message=text,
                session_id=self.session_id,
                raw=msg,
            )]

        if msg.get("type") != "gemini":
            return []  # info/error/warning: UI notices, not agent actions

        actions = []
        tokens = msg.get("tokens")
        turn_key = f"turn:{msg_id}"
        if isinstance(tokens, dict) and turn_key not in self._emitted:
            self._emitted.add(turn_key)
            cached = tokens.get("cached") or 0
            actions.append(Action(
                timestamp=timestamp,
                tool_name="assistant_message",  # NON_TOOL_ROLE_LABELS sentinel
                tool_type=ToolType.UNKNOWN,
                success=True,
                tokens_in=max((tokens.get("input") or 0) - cached, 0),
                tokens_out=(tokens.get("output") or 0) + (tokens.get("thoughts") or 0),
                cache_read_tokens=cached,
                outgoing_data=_text(msg.get("content")) or None,
                session_id=self.session_id,
                raw={k: v for k, v in msg.items() if k != "toolCalls"},
            ))

        calls = msg.get("toolCalls")
        for call in calls if isinstance(calls, list) else []:
            if not isinstance(call, dict) or not isinstance(call.get("id"), str):
                continue
            call_id = call["id"]
            if call_id in self._emitted:
                continue
            action = self._tool_action(call, timestamp)
            if call.get("status") in _FINAL_STATUSES:
                self._emitted.add(call_id)
                self._pending.pop(call_id, None)
                actions.append(action)
            else:
                self._pending[call_id] = action
        return actions

    def _tool_action(self, call: dict, msg_timestamp: Any) -> Action:
        name = call.get("name") or "unknown"
        args = call.get("args") if isinstance(call.get("args"), dict) else {}
        raw = {k: v for k, v in call.items() if k not in ("result", "resultDisplay")}
        written = [args[k] for k in ("content", "new_string") if isinstance(args.get(k), str)]
        if written:
            # Where the secret scanner reads Claude Code's Write/Edit input.
            raw["input"] = {"content": "\n".join(written)}

        response = _response(call.get("result"))
        output = response.get("output")
        error = response.get("error")
        if isinstance(output, str):
            raw["content"] = output  # Claude Code tool_result channel (scanner, injection)

        status = call.get("status")
        success = status not in ("error", "cancelled")
        error_message = error if isinstance(error, str) else None
        if status == "cancelled" and error_message is None:
            error_message = "cancelled"
        exit_codes = _EXIT_CODE.findall(output) if isinstance(output, str) else []
        if success and name == "run_shell_command" and exit_codes and exit_codes[-1] != "0":
            success = False
            error_message = f"exit code {exit_codes[-1]}"

        path = args.get("file_path") or args.get("dir_path")
        command = args.get("command")
        return Action(
            timestamp=_parse_timestamp(call) or msg_timestamp,
            tool_name=name,
            tool_type=classify_tool(name),
            success=success,
            file_path=path if isinstance(path, str) else None,
            command=command if isinstance(command, str) else None,
            error_message=error_message,
            session_id=self.session_id,
            raw=raw,
        )

    def flush(self) -> list[Action]:
        """Emit calls that never reached a final status. Batch reads only."""
        remaining = list(self._pending.values())
        self._emitted.update(self._pending)
        self._pending.clear()
        return remaining
