"""GitHub Copilot in VS Code: chat-session mutation log parsing.

VS Code (1.109+) writes each chat to ``workspaceStorage/<hash>/chatSessions/
<session-id>.jsonl`` as a mutation log, not an event log (``objectMutationLog.
ts``, microsoft/vscode): kind 0 = full snapshot (resets state), 1 = set the
value at key path ``k``, 2 = push ``v`` onto the array at ``k`` (truncated to
``i`` first when present), 3 = delete ``k``. Replaying the lines in order
gives the session state. Built from a real VS Code 1.140 session (fixture
``tests/fixtures/copilot_vscode/session.jsonl``); see the design spec
``docs/superpowers/specs/2026-10-09-copilot-vscode-design.md`` for the shapes.

Serialized tool parts always say ``isComplete: true`` (``ChatToolInvocation.
toJSON()`` hard-codes it), so a call is only taken as final when it has
``isConfirmed`` and a result, a later model part, or its request finished. A
call still unconfirmed when its request finishes is reported as failed.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .logs import _redact_truncate
from .models import Action, ToolType
from .opencode import _ms

# Only toolIds seen in a real session; add more when a real session shows them.
_FILE_TOOLS = {
    "copilot_readFile": ToolType.READ,
    "copilot_applyPatch": ToolType.EDIT,
    "copilot_createFile": ToolType.WRITE,
    "copilot_listDirectory": ToolType.LIST,
    "copilot_replaceString": ToolType.EDIT,
    "copilot_findTextInFiles": ToolType.SEARCH,  # uris usually {}: no file_path
}
_FINISHED = (1, 2, 3)  # ResponseModelState Complete, Cancelled, Failed


def _apply(state: Any, entry: dict) -> None:
    """Apply one kind 1/2/3 mutation in place; a path that doesn't resolve is skipped."""
    k = entry.get("k")
    if not isinstance(k, list) or not k:
        return
    try:
        parent = state
        for key in k[:-1]:
            parent = parent[key]
        key = k[-1]
        kind = entry.get("kind")
        if kind == 1:
            parent[key] = entry.get("v")
        elif kind == 2:
            target = parent.get(key) if isinstance(parent, dict) else parent[key]
            if target is None:  # VS Code's _applyPush: current[key] || []
                target = parent[key] = []
            if not isinstance(target, list):
                return
            if isinstance(entry.get("i"), int):
                del target[entry["i"]:]
            if isinstance(entry.get("v"), list):
                target.extend(entry["v"])
        elif kind == 3:
            # VS Code's Delete sets undefined: a list slot is cleared, not removed.
            if isinstance(parent, list):
                parent[key] = None
            else:
                del parent[key]
    except (KeyError, IndexError, TypeError):
        pass


def replay(path: Path) -> dict | None:
    """Session state from replaying *path*; None without a kind 0 snapshot.

    Malformed or partial lines (file mid-write) are skipped, never raised.
    """
    state: dict | None = None
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(entry, dict):
                    continue
                if entry.get("kind") == 0:
                    state = entry.get("v") if isinstance(entry.get("v"), dict) else None
                elif state is not None:
                    _apply(state, entry)
    except OSError:
        return None
    return state


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _refusal(confirmed: Any) -> str | None:
    """"denied" / "skipped" for a ToolConfirmKind 0 / 5 (or pre-1.104 ``false``);
    "not confirmed" when absent (only asked once the request is finished)."""
    if confirmed is None:
        return "not confirmed"  # VS Code's loader treats it as denied
    if confirmed is False:
        return "denied"
    if isinstance(confirmed, dict):
        return {0: "denied", 5: "skipped"}.get(confirmed.get("type"))
    return None


def _exit_code(part: dict) -> Any:
    tsd = part.get("toolSpecificData")
    state = tsd.get("terminalCommandState") if isinstance(tsd, dict) else None
    return state.get("exitCode") if isinstance(state, dict) else None


def _is_final(part: dict, later: list[dict], finished: bool) -> bool:
    if part.get("isConfirmed") is None:
        return finished  # waiting for the user, unless the request already ended
    if _refusal(part["isConfirmed"]):
        return True
    if _exit_code(part) is not None or part.get("resultError") or (
        part.get("resultDetails") is not None
    ):
        return True
    # The model only writes again once the round's tool results are back.
    if any(p.get("kind") in (None, "thinking", "markdownContent") for p in later):
        return True
    return finished


def _uri_path(message: Any) -> str | None:
    """First ``invocationMessage.uris`` key as a filesystem path."""
    from agentwatch.cursor_discovery import _file_uri_to_path  # cursor_discovery imports parser

    uris = message.get("uris") if isinstance(message, dict) else None
    if not isinstance(uris, dict):
        return None
    for uri in uris:
        path = _file_uri_to_path(uri) if isinstance(uri, str) else None
        if path is not None:
            return str(path)
    return None


def _tool_action(part: dict, request: dict, session_id: str | None) -> Action:
    tool_id = part.get("toolId") if isinstance(part.get("toolId"), str) else "unknown"
    tsd = part.get("toolSpecificData") if isinstance(part.get("toolSpecificData"), dict) else {}
    action = Action(
        timestamp=_ms(request.get("timestamp")),
        tool_name=tool_id,
        tool_type=ToolType.UNKNOWN,
        success=True,
        unpriced=True,
        session_id=session_id,
        raw=part,
    )
    if tool_id == "run_in_terminal":
        action.tool_type = ToolType.BASH
        cmd = tsd.get("commandLine")
        if isinstance(cmd, dict) and isinstance(cmd.get("original"), str):
            action.command = cmd["original"]
        term = tsd.get("terminalCommandState")
        if isinstance(term, dict):
            action.duration_ms = _int(term.get("duration"))
    elif tool_id in _FILE_TOOLS:
        action.tool_type = _FILE_TOOLS[tool_id]
        action.file_path = _uri_path(part.get("invocationMessage"))

    refusal = _refusal(part.get("isConfirmed"))
    exit_code = _exit_code(part)
    details = part.get("resultDetails")
    if refusal:
        action.success, action.error_message = False, refusal
    elif exit_code is not None:
        action.success = exit_code == 0
        if not action.success:
            action.error_message = f"exit code {exit_code}"
    elif part.get("resultError") or (isinstance(details, dict) and details.get("isError") is True):
        action.success = False
        if isinstance(part.get("resultError"), str):
            action.error_message = _redact_truncate(part["resultError"], 500)
    return action


def actions(state: dict, session_id: str | None = None) -> list[tuple[str, Action]]:
    """(key, action) for every final tool call (key ``toolCallId``) and every
    finished request's ``assistant_message`` (key ``requestId``), in order."""
    return [(key, action) for key, action, _ in request_actions(state, session_id)]


def request_actions(
    state: dict, session_id: str | None = None
) -> list[tuple[str, Action, str | None]]:
    """``actions()`` plus, per action, its request's id when that request is
    finished (None while it runs), so a live watcher can let it settle (#91)."""
    sid = session_id or state.get("sessionId")
    out: list[tuple[str, Action, str | None]] = []
    requests = state.get("requests")
    for index, request in enumerate(requests if isinstance(requests, list) else []):
        if not isinstance(request, dict):
            continue
        model_state = request.get("modelState")
        finished = isinstance(model_state, dict) and model_state.get("value") in _FINISHED
        rid = request.get("requestId")
        sealed = (rid if isinstance(rid, str) else f"#{index}") if finished else None
        response = request.get("response")
        parts = [p for p in response if isinstance(p, dict)] if isinstance(response, list) else []
        for n, part in enumerate(parts):
            call_id = part.get("toolCallId")
            if part.get("kind") != "toolInvocationSerialized" or not isinstance(call_id, str):
                continue
            if _is_final(part, parts[n + 1:], finished):
                out.append((call_id, _tool_action(part, request, sid), sealed))
        if finished and isinstance(request.get("requestId"), str):
            # Tokens are overwritten mid-turn, so only read once the request is done.
            out.append((request["requestId"], Action(
                timestamp=_ms(request.get("timestamp")),
                tool_name="assistant_message",  # a NON_TOOL_ROLE_LABELS sentinel
                tool_type=ToolType.UNKNOWN,
                success=True,
                tokens_in=_int(request.get("promptTokens")),
                tokens_out=_int(request.get("completionTokens")),
                unpriced=True,
                session_id=sid,
                raw={"requestId": request["requestId"], "modelId": request.get("modelId")},
            ), sealed))
    return out


def parse_copilot_vscode(path: Path, session_id: str | None = None) -> Iterator[Action]:
    """One-shot parse of one session file."""
    state = replay(path)
    if state is not None:
        for _, action in actions(state, session_id):
            yield action
