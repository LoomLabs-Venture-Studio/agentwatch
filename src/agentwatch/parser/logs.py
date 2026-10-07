"""JSONL log parsing for various AI agents."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

from .models import Action, ToolType

# Sensitive path patterns for security detection -- moved to
# `security_patterns.py` (Sprint 14) so `parser.models.ActionBuffer.add()`'s
# raw credential-access counter and `detectors/security/credentials.py` can
# share the same definitions without an import cycle. Re-exported here for
# backward compatibility with existing `from agentwatch.parser.logs import
# is_sensitive_path` call sites.
from .security_patterns import (
    SENSITIVE_PATH_REGEX,  # noqa: F401 -- re-exported, see comment above
    SENSITIVE_PATHS,  # noqa: F401 -- re-exported, see comment above
    is_sensitive_path,  # noqa: F401 -- re-exported, see comment above
)

# Common agent log locations
DEFAULT_SEARCH_PATHS = [
    Path.home() / ".claude" / "projects",
    Path.home() / ".claude" / "logs",
    Path.home() / ".moltbot" / "agents",
    Path.home() / ".clawdbot" / "agents",
    Path.cwd() / ".logs",
    Path.cwd() / "logs",
]


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

        # Token counts — check top-level keys first (older format), then
        # fall back to message.usage (current Claude Code format).
        usage = {}
        if isinstance(msg, dict):
            usage = msg.get("usage") or {}
        tokens_in = (
            entry.get("inputTokens")
            or entry.get("input_tokens")
            or usage.get("input_tokens")
            or 0
        )
        tokens_out = (
            entry.get("outputTokens")
            or entry.get("output_tokens")
            or usage.get("output_tokens")
            or 0
        )
        cost_usd = entry.get("costUSD") or 0.0
        cache_creation_tokens = (
            entry.get("cacheCreationInputTokens")
            or usage.get("cache_creation_input_tokens")
            or 0
        )
        cache_read_tokens = (
            entry.get("cacheReadInputTokens")
            or usage.get("cache_read_input_tokens")
            or 0
        )

        session_id = entry.get("sessionId")

        actions: list[Action] = []

        # Collect assistant text blocks as outgoing_data for turn detection
        # and behavioral/repetition metrics.
        assistant_text_parts: list[str] = []
        if entry_type == "assistant":
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = block.get("text", "")
                    if text:
                        assistant_text_parts.append(text)
                elif isinstance(block, str):
                    assistant_text_parts.append(block)
        outgoing_data = "\n".join(assistant_text_parts) if assistant_text_parts else None

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
                    cost_usd=cost_usd,
                    cache_creation_tokens=cache_creation_tokens,
                    cache_read_tokens=cache_read_tokens,
                    outgoing_data=outgoing_data,
                    session_id=session_id,
                    raw=block,
                ))
                # Only attach text to the first tool_use in this entry
                outgoing_data = None

            elif block_type == "tool_result" and entry_type == "user":
                is_error = block.get("is_error", False)
                result_content = block.get("content", "")
                if isinstance(result_content, list):
                    result_content = " ".join(
                        b.get("text", "") for b in result_content if isinstance(b, dict)
                    )

                if is_error:
                    # Create an action representing the failed result
                    error_msg = (
                        _redact_truncate(str(result_content), 500)
                        if result_content else "Tool error"
                    )
                    actions.append(Action(
                        timestamp=timestamp,
                        tool_name="tool_result",
                        tool_type=ToolType.BASH,  # Best guess; refined below
                        success=False,
                        error_message=error_msg,
                        cost_usd=cost_usd,
                        cache_creation_tokens=cache_creation_tokens,
                        cache_read_tokens=cache_read_tokens,
                        session_id=session_id,
                        raw=block,
                    ))

        # If assistant entry had text but no tool_use blocks, emit a
        # synthetic action so the text is visible to turn/metric logic.
        if assistant_text_parts and not actions and entry_type == "assistant":
            joined = "\n".join(assistant_text_parts)
            actions.append(Action(
                timestamp=timestamp,
                tool_name="text_output",
                tool_type=ToolType.UNKNOWN,
                success=True,
                outgoing_data=joined,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                cost_usd=cost_usd,
                cache_creation_tokens=cache_creation_tokens,
                cache_read_tokens=cache_read_tokens,
                session_id=session_id,
                raw={"type": "text", "text": joined[:500]},
            ))

        if len(actions) == 1:
            return actions[0]
        if actions:
            return actions
        return None

    except Exception:
        return None


def _redact_truncate(text: str, limit: int) -> str:
    """Mask secrets, then cut to *limit* (cutting first leaves part of a
    token straddling the cut unmasked). Imported lazily: the detectors
    package imports the parser package, so a module-level import cycles.
    """
    from agentwatch.detectors.security.secret_scanner import redact_truncate

    return redact_truncate(text, limit)


def url_hostname(url: Any) -> str | None:
    """The hostname of *url*, for ``Action.network_host``.

    Never the full URL: query strings carry tokens, and network_host is
    displayed and exported verbatim (issue #24).
    """
    if not isinstance(url, str):
        return None
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _parse_timestamp(entry: dict) -> datetime | None:
    """Extract timestamp from a log entry.

    Returns a naive datetime (tzinfo stripped) so all parsed timestamps
    compare cleanly, or None when it is missing or unparseable. Never
    ``datetime.now()``: a stray "now" distorts session duration (#44).
    """
    timestamp_str = entry.get("timestamp") or entry.get("ts") or entry.get("time")
    if timestamp_str:
        try:
            parsed = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=None)
        except (ValueError, AttributeError):
            pass
    return None


_NON_ACTION_TYPES = frozenset(
    {"attachment", "pr-link", "file-history-delta", "continued-in"}
)


def _parse_claude_code_flat(entry: dict) -> Action | None:
    """Fallback parser for flat Claude Code entries (older format)."""
    # Current Claude Code logs interleave untimed metadata lines (last-prompt,
    # mode, ai-title, ...). They are not actions, and stamping them
    # datetime.now() wrecks session duration (#38).
    if not (entry.get("timestamp") or entry.get("ts") or entry.get("time")):
        return None
    # Timestamped bookkeeping entries and plain user prompts are not agent
    # actions either, and no detector reads them (#46).
    if entry.get("type") in _NON_ACTION_TYPES or (
        entry.get("type") == "user" and isinstance(entry.get("message"), dict)
    ):
        return None
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
        cost_usd = entry.get("costUSD") or 0.0
        cache_creation_tokens = entry.get("cacheCreationInputTokens") or 0
        cache_read_tokens = entry.get("cacheReadInputTokens") or 0

        session_id = entry.get("sessionId")

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
            cost_usd=cost_usd,
            cache_creation_tokens=cache_creation_tokens,
            cache_read_tokens=cache_read_tokens,
            session_id=session_id,
            raw=entry,
        )
    except Exception:
        return None


def parse_moltbot_entry(entry: dict) -> Action | None:
    """Parse a Moltbot/Clawdbot JSONL session log entry."""
    try:
        # Moltbot stores sessions in ~/.moltbot/agents/<id>/sessions/*.jsonl
        timestamp = _parse_timestamp(entry)

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
            network_host = tool_input.get("host") or url_hostname(tool_input.get("url"))
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

        session_id = entry.get("session_id") or entry.get("sessionId")

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
            session_id=session_id,
            raw=entry,
        )
    except Exception:
        return None


#  Known Codex rollout-line event-type strings (RolloutLine envelope's
#  top-level "type" field). Used by detect_log_format to sniff Codex logs
#  without a distinctive top-level key the way Claude Code (sessionId/cwd)
#  or Moltbot (skill/tool_call) have.
#
#  PLAYBOOK Sprint 8 (2026-07-14): the original 4 values were confirmed by
#  research against issue trackers/community tools, not the primary source.
#  Fetched the real, current codex-rs/protocol/src/protocol.rs from
#  github.com/openai/codex @ main directly: `RolloutItem`
#  (`#[serde(tag = "type", content = "payload")]`, flattened into
#  `RolloutLine`) has 8 real variants, not 4 -- the original set is missing
#  "compacted", "world_state", "inter_agent_communication", and
#  "inter_agent_communication_metadata" (the latter two are a multi-agent
#  feature not previously documented anywhere in this investigation).
#  Practical impact is low (detect_log_format only needs the FIRST entry,
#  and "session_meta" is always first in a real rollout file), but this is
#  now complete against the real enum rather than a partial guess.
_CODEX_EVENT_TYPES = frozenset(
    {
        "session_meta",
        "response_item",
        "event_msg",
        "turn_context",
        "compacted",
        "world_state",
        "inter_agent_communication",
        "inter_agent_communication_metadata",
    }
)


class UnsupportedLogFormatError(ValueError):
    """A log file that is not a recognised agent log (binary, or unknown JSONL)."""

    def __init__(self, path: Path, reason: str):
        self.path = path
        self.reason = reason
        super().__init__(f"unsupported log format: {path} ({reason})")


# How many decoded dict entries may be unrecognised ("unknown") before a log
# counts as an unsupported format. "skip" entries, undecodable lines and
# non-dict JSON don't count. Shared by sniff_jsonl_format, _parse_jsonl and
# LogWatcher via FormatSniffer, so claims() and the parsers always agree.
FORMAT_SNIFF_LINES = 50


# Claude Code bookkeeping lines with no session id of their own.
_CLAUDE_METADATA_TYPES = frozenset(
    {"file-history-snapshot", "file-history-delta", "summary", "config"}
)


def is_binary_file(path: Path) -> bool:
    """True if the file's head has a NUL byte. JSONL and Markdown never do."""
    try:
        with open(path, "rb") as f:
            return b"\0" in f.read(8192)
    except OSError:
        return False


def ensure_supported_log(path: Path) -> None:
    """Raise UnsupportedLogFormatError if no adapter claims *path* and its content
    is binary or unrecognised JSONL. Empty/undecidable files pass (they may
    still be filling up)."""
    from agentwatch.agents import adapter_for
    from agentwatch.agents.base import sniff_jsonl_format

    if adapter_for(path) is not None:
        return
    if is_binary_file(path):
        raise UnsupportedLogFormatError(path, "binary file, not a JSONL agent log")
    if sniff_jsonl_format(path) == "unknown":
        raise UnsupportedLogFormatError(path, "no recognised agent log records")


def detect_log_format(first_entry: dict) -> str:
    """Detect which agent wrote a log from one decoded JSONL entry.

    Returns "skip" for metadata-only entries that should not lock the format
    decision, and "unknown" when nothing matches (including non-dict JSON).
    """
    if not isinstance(first_entry, dict):
        return "unknown"
    entry_type = first_entry.get("type", "")
    if not isinstance(entry_type, str):
        entry_type = ""

    # Claude Code message: {type: user|assistant, message: {role/content, ...}}
    if entry_type in ("user", "assistant") and "message" in first_entry:
        msg = first_entry.get("message", {})
        if isinstance(msg, dict) and ("role" in msg or "content" in msg):
            return "claude_code"

    # Older flat Claude Code entries: Claude-specific field names, or a
    # sessionId alongside a tool name. A bare sessionId is not enough --
    # other agents (e.g. Gemini CLI) use that key too (#39).
    if "costUSD" in first_entry or "cacheCreationInputTokens" in first_entry:
        return "claude_code"
    if "sessionId" in first_entry and ("tool" in first_entry or "tool_name" in first_entry):
        return "claude_code"

    # Claude Code metadata lines (mode, last-prompt, attachment, system, ...)
    # -- don't lock the format, wait for a real message.
    if entry_type in _CLAUDE_METADATA_TYPES or (entry_type and "sessionId" in first_entry):
        return "skip"

    # Moltbot indicators
    if "skill" in first_entry:
        return "moltbot"
    if "tool_call" in first_entry and isinstance(first_entry.get("tool_call"), dict):
        return "moltbot"
    if "role" in first_entry and "skill" not in first_entry:
        return "moltbot"

    # Codex indicators — a "type" value from the known RolloutLine event
    # set, with none of Claude Code's/Moltbot's distinguishing keys above
    # (already ruled out by this point).
    if entry_type in _CODEX_EVENT_TYPES:
        return "codex"

    # Copilot CLI events.jsonl: dotted "type" with the body under "data".
    # Only the first entry is sniffed, and that is always session.start. A
    # live 1.0.90 capture also has model.* events, which this list leaves out.
    if isinstance(first_entry.get("data"), dict) and entry_type.startswith(
        ("session.", "user.", "system.", "assistant.", "tool.")
    ):
        return "copilot"

    # agy (Antigravity CLI) transcript.jsonl: numbered steps.
    if "step_index" in first_entry and "source" in first_entry:
        return "agy"

    return "unknown"


class FormatSniffer:
    """Incremental log-format decision over a stream of decoded entries.

    The first recognised entry locks the format. "skip" entries are ignored,
    and so are up to FORMAT_SNIFF_LINES "unknown" ones -- a stray first line
    must not make a real agent log unreadable (#39). Only once that many
    unknown entries arrive with nothing recognised does the format lock to
    "unknown". Feed it entries one at a time; state persists across calls, so
    a live tail can feed it across reads.
    """

    def __init__(self) -> None:
        self.format: str | None = None
        self.unknown_seen = 0
        # "skip" entries are Claude Code metadata. Some carry content the
        # detectors scan (system, queue-operation), so callers replay them
        # once the format locks to claude_code instead of dropping them.
        self.skipped: list[dict] = []

    def feed(self, entry: object) -> str | None:
        """Return the locked format ("unknown" included), or None if undecided."""
        if self.format is not None:
            return self.format
        fmt = detect_log_format(entry)
        if fmt == "skip":
            self.skipped.append(entry)
            return None
        if fmt == "unknown":
            self.unknown_seen += 1
            if self.unknown_seen >= FORMAT_SNIFF_LINES:
                self.format = "unknown"
            return self.format
        self.format = fmt
        return fmt

    def finish(self) -> str | None:
        """Decision at end of input: undecided input that held any unknown
        entry (and nothing recognised) is "unknown"; skip-only stays None."""
        if self.format is None and self.unknown_seen:
            return "unknown"
        return self.format

    def take_skipped(self) -> list[dict]:
        """Hand back the skipped Claude Code metadata entries, once."""
        skipped, self.skipped = self.skipped, []
        return skipped

    def take_metadata_only(self) -> list[dict]:
        """End-of-input rule shared by parse_file and LogWatcher: undecided
        input holding only Claude Code metadata (no unknown entry) is parsed
        as Claude Code. Returns those entries once, else []."""
        return self.take_skipped() if self.finish() is None else []


def _parse_jsonl(path: Path, session_id: str | None = None) -> Iterator[Action]:
    """JSONL body of parse_file (Claude Code / Moltbot / Codex / Copilot / agy, auto-detected)."""
    # Imported lazily (not at module level) to avoid a logs.py <-> codex.py
    # circular import — codex.py imports classify_tool from this module at
    # its own module level.
    from .agy import AgyParser
    from .codex import CodexParser
    from .copilot import CopilotParser

    if is_binary_file(path):
        raise UnsupportedLogFormatError(path, "binary file, not a JSONL agent log")

    sniffer = FormatSniffer()
    log_format = None
    codex_parser: CodexParser | CopilotParser | AgyParser | None = None

    def parse(entry: dict) -> list[Action]:
        if log_format == "moltbot":
            result = parse_moltbot_entry(entry)
        elif log_format in ("codex", "copilot", "agy"):
            result = codex_parser.parse_line(entry)
        else:
            result = parse_claude_code_entry(entry)
        if not isinstance(result, list):
            result = [result] if result else []
        return [a for a in result if session_id is None or a.session_id == session_id]

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue

            # Detect format on the first recognised entry; metadata-only and
            # (within the sniff window) unrecognised entries are skipped.
            if log_format is None:
                log_format = sniffer.feed(entry)
                if log_format is None:
                    continue
                if log_format == "unknown":
                    raise UnsupportedLogFormatError(path, "no recognised agent log records")
                if log_format == "codex":
                    codex_parser = CodexParser()
                elif log_format == "copilot":
                    codex_parser = CopilotParser()
                elif log_format == "agy":
                    # agy transcripts carry no session id; tag with the requested one.
                    codex_parser = AgyParser(session_id)
                elif log_format == "claude_code":
                    for skipped in sniffer.take_skipped():
                        yield from parse(skipped)

            yield from parse(entry)

        if log_format is None:
            # File ended inside the sniff window with only unrecognised entries.
            if sniffer.finish() == "unknown":
                raise UnsupportedLogFormatError(path, "no recognised agent log records")
            # Only Claude Code metadata (no message yet): parse it as Claude
            # Code, as before #39.
            log_format = "claude_code"
            for skipped in sniffer.take_metadata_only():
                yield from parse(skipped)

        # One-shot batch read: end-of-file legitimately means "this is
        # everything", so flush any function_call left waiting for output
        # that will now never arrive in this file. (LogWatcher's live-tail
        # equivalent deliberately does NOT do this — see watcher.py.)
        if codex_parser is not None:
            for action in codex_parser.flush():
                if session_id is None or action.session_id == session_id:
                    yield action


def parse_file(
    path: Path, session_id: str | None = None, analytics_log: Path | None = None
) -> Iterator[Action]:
    """Parse an agent log file, auto-detecting format.

    Args:
        path: Path to the log file. JSONL (Claude Code / Moltbot / Codex) is
            auto-detected by content; a ``.md`` extension is dispatched to
            the Aider Markdown chat-history parser, and a ``.vscdb``
            extension to Cursor's ``state.vscdb`` SQLite store, instead.
        session_id: Optional session ID to filter by. When provided, only actions
            from this exact session are yielded (prevents log bleeding between
            sessions). For a ``.vscdb`` path this is the Cursor composer_id to
            parse; when omitted the most-recently-active agent-mode composer
            is auto-picked (see ``cursor_source.select_latest_agent_composer``).
        analytics_log: Optional path to an Aider ``--analytics-log`` JSONL
            sidecar. Only used when ``path`` is a ``.md`` Aider transcript;
            ignored for JSONL logs.
    """
    from agentwatch.agents import adapter_for

    adapter = adapter_for(path)
    if adapter is None:
        yield from _parse_jsonl(path, session_id)
        return
    yield from adapter.parse_file(path, session_id, analytics_log=analytics_log)


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
