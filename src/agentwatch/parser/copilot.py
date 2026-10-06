"""GitHub Copilot CLI session (JSONL) log parsing.

Copilot CLI writes one ``events.jsonl`` per session under
``$COPILOT_HOME/session-state/<session-id>/`` (``COPILOT_HOME`` defaults to
``~/.copilot``, per ``copilot help environment``). Each line is
``{"type": ..., "data": {...}, "id": ..., "parentId": ..., "timestamp": ...}``.

Verified against a live capture from Copilot CLI 1.0.90 (2026-10-01). A tool
call is split across two events correlated by ``data.toolCallId``:

- ``tool.execution_start``: ``toolName``, ``arguments`` (a dict, e.g.
  ``{"path": ...}`` for ``view``/``edit``, ``{"command": ...}`` for ``bash``)
- ``tool.execution_complete``: ``success`` (bool), ``error.message`` on
  failure, ``result.content`` on success

So, like ``CodexParser``, calls are buffered by id until their completion
arrives. Token usage is only written as session totals in
``session.shutdown``, not per call, so actions carry no token counts.
"""

from __future__ import annotations

from .logs import _parse_timestamp, classify_tool, url_hostname
from .models import Action, ToolType


class CopilotParser:
    """Stateful parser for one Copilot CLI ``events.jsonl`` stream."""

    def __init__(self, session_id: str | None = None):
        self.session_id = session_id
        self._pending: dict[str, Action] = {}

    def parse_line(self, entry: dict) -> list[Action]:
        event_type = entry.get("type")
        data = entry.get("data")
        if not isinstance(data, dict):
            return []

        if event_type == "session.start":
            self.session_id = data.get("sessionId") or self.session_id
            return []

        if event_type == "user.message":
            content = data.get("content")
            if not isinstance(content, str) or not content:
                return []
            return [Action(
                timestamp=_parse_timestamp(entry),
                tool_name="user_message",  # a NON_TOOL_ROLE_LABELS sentinel, like Cursor
                tool_type=ToolType.UNKNOWN,
                success=True,
                incoming_message=content,
                session_id=self.session_id,
                raw=entry,
            )]

        call_id = data.get("toolCallId")
        if event_type == "tool.execution_start" and call_id:
            name = data.get("toolName") or "unknown"
            args = data.get("arguments")
            args = args if isinstance(args, dict) else {}
            action = Action(
                timestamp=_parse_timestamp(entry),
                tool_name=name,
                tool_type=classify_tool(name),
                success=True,  # provisional; set by tool.execution_complete
                file_path=args.get("path"),
                command=args.get("command"),
                network_host=url_hostname(args.get("url")),  # web_fetch
                session_id=self.session_id,
                raw=entry,
            )
            # Written text (edit: new_str, create: file_text) goes where the secret
            # scanner reads Claude Code's Write/Edit input: raw["input"]["content"].
            written = [args[k] for k in ("new_str", "file_text") if isinstance(args.get(k), str)]
            if written:
                action.raw["input"] = {"content": "\n".join(written)}
            self._pending[call_id] = action
            return []

        if event_type == "tool.execution_complete" and call_id in self._pending:
            action = self._pending.pop(call_id)
            action.success = data.get("success") is not False
            error = data.get("error")
            if isinstance(error, dict):
                action.error_message = error.get("message")
            result = data.get("result")
            if isinstance(result, dict) and isinstance(result.get("content"), str):
                # Tool output goes where Claude Code's tool_result keeps it
                # (raw["content"]): the secret scanner's tool_output channel and
                # the indirect/hidden-injection detectors read it there.
                action.raw["content"] = result["content"]
            done = _parse_timestamp(entry)
            if done is not None and action.timestamp is not None:
                elapsed = done - action.timestamp
                action.duration_ms = max(int(elapsed.total_seconds() * 1000), 0)
            return [action]

        return []

    def flush(self) -> list[Action]:
        """Emit calls that never completed. Batch reads only, like CodexParser.flush()."""
        remaining = list(self._pending.values())
        self._pending.clear()
        return remaining
