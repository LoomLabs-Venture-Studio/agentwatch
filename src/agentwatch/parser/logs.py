"""JSONL log parsing for various AI agents."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from .models import Action, ToolType


# Sensitive path patterns for security detection
SENSITIVE_PATHS = [
    r"\.moltbot/credentials",
    r"\.moltbot/agents/.*/auth-profiles\.json",
    r"\.clawdbot/",
    r"\.aws/credentials",
    r"\.ssh/",
    r"\.gnupg/",
    r"\.env$",
    r"secrets\.json",
    r"\.netrc",
    r"\.npmrc",
    r"\.pypirc",
    r"id_rsa",
    r"id_ed25519",
    r"\.pem$",
    r"\.key$",
]

SENSITIVE_PATH_REGEX = re.compile("|".join(SENSITIVE_PATHS), re.IGNORECASE)


# Common agent log locations
DEFAULT_SEARCH_PATHS = [
    Path.home() / ".claude" / "projects",
    Path.home() / ".claude" / "logs",
    Path.home() / ".moltbot" / "agents",
    Path.home() / ".clawdbot" / "agents",
    Path.cwd() / ".logs",
    Path.cwd() / "logs",
]


def is_sensitive_path(path: str | None) -> bool:
    """Check if a path matches known sensitive patterns."""
    if not path:
        return False
    return bool(SENSITIVE_PATH_REGEX.search(path))


def classify_tool(tool_name: str) -> ToolType:
    """Classify a tool name into a ToolType."""
    name_lower = tool_name.lower()
    
    if any(x in name_lower for x in ["read", "view", "cat", "get_file"]):
        return ToolType.READ
    if any(x in name_lower for x in ["write", "create", "save"]):
        return ToolType.WRITE
    if any(x in name_lower for x in ["edit", "patch", "replace", "str_replace"]):
        return ToolType.EDIT
    if any(x in name_lower for x in ["bash", "shell", "exec", "run", "command"]):
        return ToolType.BASH
    if any(x in name_lower for x in ["search", "grep", "find", "glob"]):
        return ToolType.SEARCH
    if any(x in name_lower for x in ["list", "ls", "dir"]):
        return ToolType.LIST
    if any(x in name_lower for x in ["browser", "web", "navigate", "click"]):
        return ToolType.BROWSER
    if "mcp" in name_lower:
        return ToolType.MCP
    
    return ToolType.UNKNOWN


def parse_claude_code_entry(entry: dict) -> Action | list[Action] | None:
    """Parse a Claude Code JSONL log entry.

    Claude Code logs store one JSON object per line with structure:
        {type: "assistant"|"user", message: {role, content: [...]}, ...}

    Assistant messages contain tool_use blocks (the action).
    User messages contain tool_result blocks (the outcome).

    We extract actions from tool_use blocks and later merge results.
    """
    try:
        msg = entry.get("message")
        if not isinstance(msg, dict):
            return _parse_claude_code_flat(entry)

        content = msg.get("content")
        if not isinstance(content, list):
            return _parse_claude_code_flat(entry)

        entry_type = entry.get("type") or msg.get("role")

        # Parse timestamp
        timestamp = _parse_timestamp(entry)

        # Token counts (usually on assistant entries)
        tokens_in = entry.get("inputTokens") or entry.get("input_tokens") or 0
        tokens_out = entry.get("outputTokens") or entry.get("output_tokens") or 0

        actions: list[Action] = []

        for block in content:
            if not isinstance(block, dict):
                continue

            block_type = block.get("type")

            if block_type == "tool_use" and entry_type == "assistant":
                tool_name = block.get("name", "unknown")
                tool_input = block.get("input") or {}

                file_path = None
                command = None

                if isinstance(tool_input, dict):
                    file_path = (
                        tool_input.get("file_path")
                        or tool_input.get("path")
                        or tool_input.get("file")
                    )
                    command = tool_input.get("command") or tool_input.get("cmd")

                actions.append(Action(
                    timestamp=timestamp,
                    tool_name=tool_name,
                    tool_type=classify_tool(tool_name),
                    success=True,  # Default; updated when tool_result arrives
                    file_path=file_path,
                    command=command,
                    tokens_in=tokens_in,
                    tokens_out=tokens_out,
                    raw=block,
                ))

            elif block_type == "tool_result" and entry_type == "user":
                is_error = block.get("is_error", False)
                result_content = block.get("content", "")
                if isinstance(result_content, list):
                    result_content = " ".join(
                        b.get("text", "") for b in result_content if isinstance(b, dict)
                    )

                if is_error:
                    # Create an action representing the failed result
                    error_msg = str(result_content)[:500] if result_content else "Tool error"
                    actions.append(Action(
                        timestamp=timestamp,
                        tool_name="tool_result",
                        tool_type=ToolType.BASH,  # Best guess; refined below
                        success=False,
                        error_message=error_msg,
                        raw=block,
                    ))

        if len(actions) == 1:
            return actions[0]
        if actions:
            return actions
        return None

    except Exception:
        return None


def _parse_timestamp(entry: dict) -> datetime:
    """Extract timestamp from a log entry."""
    timestamp_str = entry.get("timestamp") or entry.get("ts") or entry.get("time")
    if timestamp_str:
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            pass
    return datetime.now()


def _parse_claude_code_flat(entry: dict) -> Action | None:
    """Fallback parser for flat Claude Code entries (older format)."""
    try:
        timestamp = _parse_timestamp(entry)

        tool_name = (
            entry.get("tool")
            or entry.get("tool_name")
            or entry.get("type")
            or "unknown"
        )

        file_path = None
        for key in ["file", "path", "file_path", "filename"]:
            if entry.get(key):
                file_path = entry.get(key)
                break
        if not file_path and isinstance(entry.get("input"), dict):
            for key in ["path", "file", "file_path"]:
                if entry["input"].get(key):
                    file_path = entry["input"].get(key)
                    break

        command = None
        for key in ["command", "cmd", "shell_command"]:
            if entry.get(key):
                command = entry.get(key)
                break
        if not command and isinstance(entry.get("input"), dict):
            for key in ["command", "cmd"]:
                if entry["input"].get(key):
                    command = entry["input"].get(key)
                    break

        success = entry.get("success", True)
        if "error" in entry or "err" in entry:
            success = False

        error_message = entry.get("error") or entry.get("err") or entry.get("error_message")

        tokens_in = entry.get("tokens_in") or entry.get("input_tokens") or 0
        tokens_out = entry.get("tokens_out") or entry.get("output_tokens") or 0

        return Action(
            timestamp=timestamp,
            tool_name=tool_name,
            tool_type=classify_tool(tool_name),
            success=success,
            file_path=file_path,
            command=command,
            error_message=error_message,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            raw=entry,
        )
    except Exception:
        return None


def parse_moltbot_entry(entry: dict) -> Action | None:
    """Parse a Moltbot/Clawdbot JSONL session log entry."""
    try:
        # Moltbot stores sessions in ~/.moltbot/agents/<id>/sessions/*.jsonl
        timestamp_str = entry.get("ts") or entry.get("timestamp")
        if timestamp_str:
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                timestamp = datetime.now()
        else:
            timestamp = datetime.now()
        
        # Message type detection
        msg_type = entry.get("type") or entry.get("role")
        
        # Skill information - at top level in Moltbot
        skill_name = entry.get("skill")
        
        # Tool calls in Moltbot - can be dict or nested
        tool_call = entry.get("tool_call") or {}
        if isinstance(tool_call, dict):
            tool_name = tool_call.get("name") or entry.get("tool_name") or msg_type or "message"
            tool_input = tool_call.get("input") or {}
        else:
            tool_name = msg_type or "message"
            tool_input = {}
        
        # Extract file paths from tool inputs
        file_path = None
        if isinstance(tool_input, dict):
            file_path = tool_input.get("path") or tool_input.get("file")
        
        # Command extraction
        command = None
        if isinstance(tool_input, dict):
            command = tool_input.get("command") or tool_input.get("cmd")
        
        # Network information for security
        network_host = None
        network_port = None
        if isinstance(tool_input, dict):
            network_host = tool_input.get("host") or tool_input.get("url")
            network_port = tool_input.get("port")
        
        # Incoming messages (for prompt injection detection)
        incoming_message = None
        if msg_type in ("user", "incoming", "message"):
            incoming_message = entry.get("content") or entry.get("text") or entry.get("message")
        
        # Outgoing data (for exfiltration detection)
        outgoing_data = None
        if msg_type in ("assistant", "outgoing", "response"):
            outgoing_data = entry.get("content") or entry.get("text")
        
        # Success/error
        success = entry.get("success", True)
        error_message = entry.get("error")
        if error_message:
            success = False
        
        return Action(
            timestamp=timestamp,
            tool_name=tool_name,
            tool_type=classify_tool(tool_name),
            success=success,
            file_path=file_path,
            command=command,
            error_message=error_message,
            incoming_message=incoming_message,
            outgoing_data=outgoing_data,
            network_host=network_host,
            network_port=network_port,
            skill_name=skill_name,
            raw=entry,
        )
    except Exception:
        return None


def detect_log_format(first_entry: dict) -> str:
    """Detect whether log is from Claude Code or Moltbot.

    Returns "skip" for metadata-only entries (e.g. file-history-snapshot)
    that should not lock the format decision.
    """
    # Claude Code metadata entries — don't lock format, wait for a real message
    entry_type = first_entry.get("type", "")
    if entry_type in ("file-history-snapshot", "summary", "config"):
        return "skip"

    # Claude Code indicators — check first since its logs also have "type" keys
    # Claude Code entries have top-level sessionId/cwd/version or message.content with tool_use blocks
    if any(key in first_entry for key in ["sessionId", "cwd", "costUSD", "cacheCreationInputTokens"]):
        return "claude_code"
    if entry_type in ("user", "assistant") and "message" in first_entry:
        msg = first_entry.get("message", {})
        if isinstance(msg, dict) and "role" in msg:
            return "claude_code"

    # Moltbot indicators
    if "skill" in first_entry:
        return "moltbot"
    if "tool_call" in first_entry and isinstance(first_entry.get("tool_call"), dict):
        return "moltbot"
    if "role" in first_entry and "skill" not in first_entry:
        return "moltbot"

    return "unknown"


def parse_file(path: Path) -> Iterator[Action]:
    """Parse a JSONL log file, auto-detecting format."""
    log_format = None
    
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            # Detect format on first valid entry (skip metadata-only entries)
            if log_format is None or log_format == "skip":
                log_format = detect_log_format(entry)
                if log_format == "skip":
                    continue
            
            # Parse based on format
            if log_format == "moltbot":
                result = parse_moltbot_entry(entry)
            else:
                result = parse_claude_code_entry(entry)

            if isinstance(result, list):
                yield from result
            elif result:
                yield result


def find_log_files(base_path: Path | None = None) -> list[Path]:
    """Find all relevant log files for known agents."""
    log_files = []
    
    search_paths = DEFAULT_SEARCH_PATHS
    if base_path:
        search_paths = [base_path]
    
    for search_path in search_paths:
        if search_path.exists():
            log_files.extend(search_path.rglob("*.jsonl"))
    
    # Sort by modification time, newest first
    log_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    
    return log_files


def find_latest_session(base_path: Path | None = None) -> Path | None:
    """Find the most recently modified log file."""
    log_files = find_log_files(base_path)
    return log_files[0] if log_files else None
