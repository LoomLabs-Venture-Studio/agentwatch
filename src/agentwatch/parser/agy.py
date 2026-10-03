"""Antigravity CLI (``agy``) transcript (JSONL) parsing.

agy appends one JSON object per conversation step to
``~/.gemini/antigravity-cli/brain/<conversation-id>/.system_generated/logs/transcript.jsonl``.
Verified against live agy 1.2.14 sessions (2026-10-01)::

    {"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "status": "DONE",
     "created_at": "...Z", "tool_calls": [{"name": "view_file",
                                           "args": {"AbsolutePath": "\\"/abs/path\\""}}]}
    {"step_index": 2, "source": "MODEL", "type": "GENERIC", "status": "DONE",
     "created_at": "...Z", "content": "<tool output>"}

Tool calls carry no call id: each call's result is the next GENERIC step, in
order. Any other step while calls are pending ends the pairing (the calls are
emitted without a result) rather than risk shifting results onto the wrong
calls. Live transcripts only show one call per plan, with its result at the
next ``step_index``, so step_index offsets are not used for pairing.

A failed call is ``status: "ERROR"`` with an ``error`` string. A shell
command's exit code is only in ``run_command``'s result text, whose first line
after the timestamp header is "The command exited with code N.". A background
command's step stays ``RUNNING`` and is never updated, so it counts as a
success. Every ``args`` value is JSON-encoded. The file has no session id (it
is the directory name), so the parser is given one.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .logs import _parse_timestamp, classify_tool, url_hostname
from .models import Action, ToolType

_PATH_ARGS = ("AbsolutePath", "TargetFile", "DirectoryPath", "SearchPath")
# Text written to disk: replace_file_content's ReplacementContent (seen live) and
# write_to_file's CodeContent (agy 1.2.14 binary's tool example).
_WRITE_ARGS = ("ReplacementContent", "CodeContent")
# run_command's result opens with "Created At:"/"Completed At:" header lines
# (seen live), then "The command exited with code N." -- only that line counts.
_EXIT_CODE = re.compile(
    r"\A(?:(?:Created|Completed) At:[^\n]*\n|[ \t\r]*\n)*The command exited with code (-?\d+)\."
)
_USER_REQUEST = re.compile(r"<USER_REQUEST>\n?(.*?)\n?(?:</USER_REQUEST>|\Z)", re.DOTALL)


def _decode(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


class AgyParser:
    """Stateful parser for one agy ``transcript.jsonl`` stream."""

    def __init__(self, session_id: str | None = None):
        self.session_id = session_id
        self._pending: list[Action] = []

    def parse_line(self, entry: dict) -> list[Action]:
        tool_calls = entry.get("tool_calls")
        content = entry.get("content") if isinstance(entry.get("content"), str) else None
        # raw minus the step's own text: the scanner reads raw["content"] as tool output.
        raw = {k: v for k, v in entry.items() if k != "content"}

        if entry.get("type") == "USER_INPUT":
            # Seen live: "<USER_REQUEST>\n...\n</USER_REQUEST>\n<ADDITIONAL_METADATA>...".
            m = _USER_REQUEST.search(content or "")
            message = m.group(1) if m else content
            emitted = self.flush()
            if message:
                emitted.append(Action(
                    timestamp=_parse_timestamp({"timestamp": entry.get("created_at")}),
                    tool_name="user_message",  # a NON_TOOL_ROLE_LABELS sentinel, like Cursor
                    tool_type=ToolType.UNKNOWN,
                    success=True,
                    incoming_message=message,
                    session_id=self.session_id,
                    raw=raw,
                ))
            return emitted

        if entry.get("type") == "PLANNER_RESPONSE":
            # A new plan means any still-unanswered calls got no result step.
            emitted = self.flush()
            timestamp = _parse_timestamp({"timestamp": entry.get("created_at")})
            for call in tool_calls if isinstance(tool_calls, list) else []:
                if not isinstance(call, dict):
                    continue
                name = call.get("name") or "unknown"
                args = call.get("args") if isinstance(call.get("args"), dict) else {}
                args = {k: _decode(v) for k, v in args.items()}
                path = next((args[k] for k in _PATH_ARGS if isinstance(args.get(k), str)), None)
                command = args.get("CommandLine")
                call_raw = dict(raw)  # per call: the result is stored into it
                written = [args[k] for k in _WRITE_ARGS if isinstance(args.get(k), str)]
                if written:
                    # Where the secret scanner reads Claude Code's Write/Edit input.
                    call_raw["input"] = {"content": "\n".join(written)}
                self._pending.append(Action(
                    timestamp=timestamp,
                    tool_name=name,
                    tool_type=classify_tool(name),
                    success=True,
                    file_path=path,
                    command=command if isinstance(command, str) else None,
                    network_host=url_hostname(args.get("Url")),  # read_url_content
                    session_id=self.session_id,
                    raw=call_raw,
                ))
            return emitted

        if entry.get("type") != "GENERIC":
            # Not a result step while calls wait (e.g. a SYSTEM_MESSAGE): with no
            # call ids, pairing later results would shift them onto the wrong
            # calls, so emit the pending calls without a result instead.
            return self.flush()
        if not self._pending:
            return []  # a result with no call to pair it with

        action = self._pending.pop(0)
        if content is not None:
            # Where Claude Code's tool_result keeps output (scanner tool_output channel).
            action.raw["content"] = content
        if entry.get("status") == "ERROR":
            action.success = False
            action.error_message = entry.get("error") or content
        elif (
            action.tool_name == "run_command"
            and (m := _EXIT_CODE.match(content or ""))
            and m.group(1) != "0"
        ):
            action.success = False
            action.error_message = f"exit code {m.group(1)}"
        done = _parse_timestamp({"timestamp": entry.get("created_at")})
        if entry.get("created_at") and action.raw.get("created_at"):
            action.duration_ms = max(int((done - action.timestamp).total_seconds() * 1000), 0)
        return [action]

    def flush(self) -> list[Action]:
        """Emit calls with no result step yet. Batch reads only, like CodexParser.flush()."""
        remaining, self._pending = self._pending, []
        return remaining
