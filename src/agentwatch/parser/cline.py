"""Cline task parsing: the legacy extension's and the SDK's message files.

Both stores hold Anthropic-style messages (``tool_use.id`` <->
``tool_result.tool_use_id``), rewritten whole on every save; see
``docs/superpowers/specs/2026-10-12-cline-adapter-design.md`` for the
citations (cline/cline ``legacy-extension`` @ 7761370 = L, ``main`` @
a484089 = N).

- Legacy ``tasks/<id>/api_conversation_history.json``: a JSON array of
  messages; assistant ``metrics {tokens {prompt, completion, cached}, cost}``
  (L ``shared/messages/content.ts:99-123``, ``metrics.ts:9-18``). Written by
  temp file + rename (L ``core/storage/disk.ts:34-46``).
- SDK ``sessions/<id>/<id>.messages.json``: ``{version: 1, sessionId,
  messages: [...]}``; assistant ``metrics {inputTokens, outputTokens,
  cacheReadTokens, cacheWriteTokens, cost}`` (N ``core/src/services/
  session-data.ts:334-358``, ``shared/src/llms/messages.ts:140-165``).
  Written with a plain ``writeFileSync`` (N ``session-manifest-store.ts:
  236-238``), so a read can be torn: ``load()`` then returns None.

Fixture-verified only (no live Cline install; board decision, #104).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .logs import _redact_truncate, url_hostname
from .models import Action, ToolType
from .opencode import _ms

# L shared/tools.ts:8-36 (ClineDefaultTool).
_LEGACY_TOOLS = {
    "execute_command": ToolType.BASH,
    "read_file": ToolType.READ,
    "write_to_file": ToolType.WRITE,
    "replace_in_file": ToolType.EDIT,
    "apply_patch": ToolType.EDIT,
    "search_files": ToolType.SEARCH,
    "list_files": ToolType.LIST,
    "list_code_definition_names": ToolType.LIST,
    "browser_action": ToolType.BROWSER,
    "use_mcp_tool": ToolType.MCP,
    "access_mcp_resource": ToolType.MCP,
    "load_mcp_documentation": ToolType.MCP,
}
# N sdk/packages/core/src/extensions/tools/constants.ts:12-22 (DefaultToolNames).
_SDK_TOOLS = {
    "run_commands": ToolType.BASH,
    "read_files": ToolType.READ,
    "editor": ToolType.EDIT,
    "apply_patch": ToolType.EDIT,
    "search_codebase": ToolType.SEARCH,
}
# Legacy results carry no is_error; failure is only in the text, after the
# "<description> Result:\n" prefix (L ToolResultUtils.ts:46-49):
# L core/prompts/responses.ts:23-25, integrations/terminal/CommandOrchestrator.ts:639-642.
_LEGACY_FAILURES = (
    "The user denied this operation.",
    "The tool execution failed with the following error:",
    "Command failed with exit code ",
)


def load(path: Path) -> tuple[list, bool] | None:
    """``(messages, is_sdk)``, or None when the file is missing, torn
    mid-write, or neither shape. Never raises."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if isinstance(data, list):
        return data, False
    if (
        isinstance(data, dict)
        and data.get("version") == 1
        and isinstance(data.get("sessionId"), str)
        and isinstance(data.get("messages"), list)
    ):
        return data["messages"], True
    return None


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            b["text"] for b in content
            if isinstance(b, dict) and isinstance(b.get("text"), str)
        )
    return ""


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _cmd(entry: Any) -> str | None:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict) and isinstance(entry.get("command"), str):
        args = entry.get("args")
        extra = [a for a in args if isinstance(a, str)] if isinstance(args, list) else []
        return " ".join([entry["command"], *extra])
    return None


def _commands(inp: Any) -> str | None:
    """run_commands' input in any form RunCommandsInputUnionSchema accepts
    (N extensions/tools/schemas.ts:162-171)."""
    if isinstance(inp, dict) and "commands" in inp:
        inp = inp["commands"]
    elif isinstance(inp, dict) and "cmd" in inp:
        inp = inp["cmd"]
    items = inp if isinstance(inp, list) else [inp]
    return "\n".join(c for c in map(_cmd, items) if c) or None


def _first_path(files: Any) -> str | None:
    """read_files' first path (N schemas.ts:57-99: path / file_path / filePath)."""
    first = files[0] if isinstance(files, list) and files else files
    if isinstance(first, str):
        return first
    if isinstance(first, dict):
        for key in ("path", "file_path", "filePath"):
            if isinstance(first.get(key), str):
                return first[key]
    return None


def _tool_action(block: dict, sdk: bool, ts: Any, sid: str | None) -> Action:
    name = block.get("name") if isinstance(block.get("name"), str) else "unknown"
    inp = block.get("input")
    d = inp if isinstance(inp, dict) else {}
    action = Action(
        timestamp=ts,
        tool_name=name,
        tool_type=(_SDK_TOOLS if sdk else _LEGACY_TOOLS).get(name, ToolType.UNKNOWN),
        success=True,
        session_id=sid,
        raw=block,
    )
    if sdk:
        if name == "run_commands":
            action.command = _commands(inp)
        elif name == "read_files":
            action.file_path = _first_path(d.get("files", inp))
        elif name == "editor" and isinstance(d.get("path"), str):
            action.file_path = d["path"]
        elif name == "fetch_web_content":
            reqs = d.get("requests")
            first = reqs[0] if isinstance(reqs, list) and reqs else None
            url = first.get("url") if isinstance(first, dict) else None
            action.network_host = url_hostname(url)
    else:
        # L handlers read block.params.path || absolutePath (WriteToFileToolHandler.ts:32-36).
        path = d.get("path") or d.get("absolutePath")
        if isinstance(path, str):
            action.file_path = path
        if isinstance(d.get("command"), str):
            action.command = d["command"]
        action.network_host = url_hostname(d.get("url"))
    return action


def _apply_result(action: Action, block: dict, sdk: bool) -> None:
    text = _text(block.get("content"))
    action.incoming_message = text or None
    if sdk:
        failed = block.get("is_error") is True
        detail = text
    else:
        detail = text.split(" Result:\n", 1)[-1]
        failed = detail.startswith(_LEGACY_FAILURES)
        detail = detail.split("\n", 1)[0]
    if failed:
        action.success = False
        action.error_message = _redact_truncate(detail, 500) if detail else "tool error"


def _assistant_text(content: Any) -> str:
    """Text blocks only: tool inputs and thinking stay out of outgoing_data."""
    if isinstance(content, list):
        content = [b for b in content if isinstance(b, dict) and b.get("type") == "text"]
    return _text(content)


def _usage_action(msg: dict, sdk: bool, ts: Any, sid: str | None) -> Action | None:
    metrics = msg.get("metrics")
    if not isinstance(metrics, dict):
        return None
    if sdk:
        cache_read = _int(metrics.get("cacheReadTokens"))
        cache_write = _int(metrics.get("cacheWriteTokens"))
        tokens_in = _int(metrics.get("inputTokens")) + cache_read + cache_write
        tokens_out = _int(metrics.get("outputTokens"))
    else:
        tokens = metrics.get("tokens") if isinstance(metrics.get("tokens"), dict) else {}
        cache_read = cache_write = 0  # legacy only reports a combined "cached" count
        tokens_in, tokens_out = _int(tokens.get("prompt")), _int(tokens.get("completion"))
    cost = metrics.get("cost")
    priced = isinstance(cost, (int, float)) and not isinstance(cost, bool)
    return Action(
        timestamp=ts,
        tool_name="assistant_message",  # a NON_TOOL_ROLE_LABELS sentinel
        tool_type=ToolType.UNKNOWN,
        success=True,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cache_read_tokens=cache_read,
        cache_creation_tokens=cache_write,
        cost_usd=float(cost) if priced else 0.0,
        unpriced=not priced,
        outgoing_data=_assistant_text(msg.get("content")) or None,
        session_id=sid,
        raw={"id": msg.get("id"), "modelInfo": msg.get("modelInfo")},
    )


def actions(messages: list, sdk: bool, session_id: str | None = None) -> list[tuple[str, Action]]:
    """(key, action) per assistant message with metrics (key ``m:<id or #i>``)
    and per tool call once its result exists (key = tool id), in order.

    A ``tool_use`` without a result yet is held back, not emitted.
    """
    # ponytail: legacy tasks on models without native tool calling put tool
    # calls as XML in assistant text and results in plain text blocks (L
    # utils/model-utils.ts:246-255, ToolResultUtils.ts:66-73), so they show
    # token actions only, no tool actions. Upgrade path: parse the XML tool
    # tags out of assistant text, pairing each with the next "[tool ...]
    # Result:" text block (board decision 5, #104).
    pending: dict[str, Action] = {}
    out: list[tuple[str, Action]] = []
    for i, msg in enumerate(messages):
        if not isinstance(msg, dict):
            continue
        ts = _ms(msg.get("ts"))
        content = msg.get("content")
        blocks = [b for b in content if isinstance(b, dict)] if isinstance(content, list) else []
        if msg.get("role") == "assistant":
            mid = msg.get("id")
            usage = _usage_action(msg, sdk, ts, session_id)
            if usage is not None:
                out.append((f"m:{mid}" if isinstance(mid, str) else f"m:#{i}", usage))
            for b in blocks:
                if b.get("type") == "tool_use" and isinstance(b.get("id"), str):
                    pending[b["id"]] = _tool_action(b, sdk, ts, session_id)
        elif msg.get("role") == "user":
            for b in blocks:
                if b.get("type") != "tool_result":
                    continue
                action = pending.pop(b.get("tool_use_id"), None)
                if action is not None:
                    _apply_result(action, b, sdk)
                    out.append((b["tool_use_id"], action))
    return out


def parse_cline(path: Path, session_id: str | None = None) -> Iterator[Action]:
    """One-shot parse of one task/session file."""
    loaded = load(path)
    if loaded is not None:
        for _, action in actions(*loaded, session_id=session_id):
            yield action
