"""Detectors for prompt injection attempts."""

from __future__ import annotations

import re
from collections import OrderedDict
from collections.abc import Callable

from agentwatch.parser.models import (
    NON_TOOL_ROLE_LABELS,
    Action,
    ActionBuffer,
    is_usage_record,
)
from agentwatch.parser.security_patterns import (
    INJECTION_PATTERNS as _SHARED_INJECTION_PATTERNS,
)
from agentwatch.parser.security_patterns import INJECTION_REGEX

from ..base import Category, SecurityDetector, Severity, Warning


class _ActionMemo:
    """Findings of one detector per action, remembered by action identity and
    ``result_revision`` (bounded). A check re-reads the last 10 actions on every
    new action; without this each result's text is searched ten times. A tool
    result merged into an action later bumps its revision, so it is searched
    again. The action is held so its id cannot be reused while cached."""

    SIZE = 64

    def __init__(self) -> None:
        self._memo: OrderedDict[int, tuple[Action, int, Warning | None]] = OrderedDict()

    def get(self, action: Action, scan: Callable[[Action], Warning | None]) -> Warning | None:
        revision = action.result_revision
        hit = self._memo.get(id(action))
        if hit is not None and hit[0] is action and hit[1] == revision:
            self._memo.move_to_end(id(action))
            return hit[2]
        found = scan(action)
        self._memo[id(action)] = (action, revision, found)
        while len(self._memo) > self.SIZE:
            self._memo.popitem(last=False)
        return found


# --- Where an action's result text came from --------------------------------
#
# Since 0.2.1 a Claude Code tool result reaches the injection detectors. Reading
# a local file that only talks about injection (docs, tests, agent notes) then
# looked like an attack. `local_doc_source()` names that case so the detectors
# can downgrade it; text from the web, an MCP tool, a shell command, a source
# file or a user prompt keeps its severity.
#
# Fail safe, precision over recall: only an agent's own built-in structured
# read tools qualify, by exact name, and only for one plain local path. Shell
# commands never qualify (parsing them is an attack surface: redirections,
# sed/awk scripts, --pre hooks, cd, glued `&`). Anything unknown keeps its
# severity.

# Built-in read/search/list tools, by the exact tool_name each parser emits.
# By name, not ToolType: classify_tool() calls MCP tools such as OpenCode's
# github_get_file_contents READ.
_LOCAL_READ_TOOLS = frozenset({
    # Claude Code tool_use names (parser/logs.py ClaudeCodeParser; MCP tools
    # there are always mcp__<server>__<tool>).
    "Read", "Grep", "Glob", "LS", "NotebookRead",
    # Copilot CLI (parser/copilot.py, toolName "view" seen live in 1.0.90).
    "view",
    # Copilot in VS Code (parser/copilot_vscode.py _FILE_TOOLS, seen live).
    "copilot_readFile", "copilot_listDirectory", "copilot_findTextInFiles",
    # Antigravity CLI (parser/agy.py, view_file seen live in 1.2.14).
    "view_file",
    # Gemini CLI (parser/gemini.py; tests/test_gemini.py: read_file,
    # list_directory). Cline legacy store also names its read tool read_file.
    "read_file", "list_directory",
    # OpenCode / Kilo (parser/opencode.py: packages/opencode/src/tool/*.ts
    # v1.18.34; "read" seen live, glob and grep named there).
    "read", "glob", "grep",
    # Cline legacy (parser/cline.py _LEGACY_TOOLS, shared/tools.ts) and SDK
    # (_SDK_TOOLS, DefaultToolNames). read_files must name exactly one file.
    "search_files", "list_files", "list_code_definition_names",
    "read_files", "search_codebase",
})
# Codex has no structured text read tool (view_image is an image; reads go
# through exec_command), Cursor and Aider log no tool names: none qualify.

_DOC_SUFFIXES = (".md", ".mdx", ".markdown", ".rst", ".txt", ".adoc")
_DOC_DIRS = frozenset({"docs", "doc"})
_TEST_DIRS = frozenset({"tests", "test", "__tests__", "spec", "specs"})
_DOC_NAMES = frozenset({"readme", "changelog", "license", "contributing"})
# Third-party, downloaded, cached or fetched content stays untrusted even when
# it looks like a doc: installed packages and environments, temp and download
# folders, caches, plugins, and Claude Code's saved large tool results (which
# may hold a web fetch). Compared lower-case, per path segment.
_UNTRUSTED_DIRS = frozenset({
    "node_modules", "bower_components", "site-packages", "dist-packages", "vendor",
    ".venv", "venv", "venvs", "pipx", ".cargo", ".m2", ".npm", "_cacache",
    "tmp", "temp", "shm", "downloads", ".cache", "cache",
    "plugins", "tool-results",
})
# Untrusted folders named by two segments in a row (macOS temp, Go modules,
# Claude Code's own session folders).
_UNTRUSTED_PAIRS = frozenset({("var", "folders"), ("pkg", "mod"), (".claude", "projects")})
# System pseudo-files (/dev/tcp, /proc/self/fd/0) are never docs.
_UNTRUSTED_ROOTS = ("/dev/", "/proc/", "/sys/")
# A path that is not one plain local file: an unexpanded variable ($HOME,
# %TEMP%, ~), a glob, a URL or stream (":" past a drive letter), a NUL.
_UNPLAIN_CHARS = frozenset("$%~*?:\x00")
_DRIVE_RE = re.compile(r"^[a-z]:/")
_TEST_NAME_RE = re.compile(
    r"^(?:test_.+\.py|conftest\.py|.+_test\.[a-z0-9]+|.+\.(?:spec|test)\.[a-z0-9]+)$"
)


def _path_parts(path: object) -> list[str] | None:
    """Lower-case segments of a plain local *path*, or None when it is a UNC
    or // path, holds a variable, glob, URL or ``..`` segment, or is a
    system pseudo-file."""
    if not isinstance(path, str) or not path:
        return None
    norm = path.replace("\\", "/").lower()
    if norm.startswith("//"):
        return None  # UNC share (\\host\share) or //host
    rest = norm[2:] if _DRIVE_RE.match(norm) else norm
    if any(c in _UNPLAIN_CHARS for c in rest):
        return None
    if norm.startswith(_UNTRUSTED_ROOTS):
        return None
    parts = [p for p in norm.split("/") if p and p != "."]
    if not parts or ".." in parts:
        return None
    if _DRIVE_RE.match(norm):
        parts = parts[1:]  # "c:"
    if any(p in _UNTRUSTED_DIRS for p in parts):
        return None
    if any(pair in _UNTRUSTED_PAIRS for pair in zip(parts, parts[1:])):
        return None
    return parts or None


def _doc_path_reason(path: object) -> str | None:
    """Why *path* is a local doc or test file (or a docs/tests folder), or None."""
    parts = _path_parts(path)
    if parts is None:
        return None
    name = parts[-1]
    if name.endswith(_DOC_SUFFIXES):
        return f"doc file ({name[name.rfind('.'):]})"
    if _TEST_NAME_RE.match(name):
        return "test file"
    if name.split(".", 1)[0] in _DOC_NAMES:
        return "doc file"
    if any(p in _DOC_DIRS for p in parts):
        return "file under docs/"
    if any(p in _TEST_DIRS for p in parts):
        return "file under tests/"
    return None


def _single_read_file(action: Action) -> bool:
    """Cline SDK read_files lists files but the parser keeps only the first:
    only a one-file call is checked whole."""
    if action.tool_name != "read_files":
        return True
    inp = action.raw.get("input") if isinstance(action.raw, dict) else None
    files = inp
    if isinstance(inp, dict):
        files = next((inp[k] for k in ("files", "file_paths", "paths") if k in inp), None)
    return not isinstance(files, list) or len(files) == 1


def local_doc_source(action: Action) -> str | None:
    """Why *action*'s result text came from reading a local doc or test file
    (e.g. "doc file (.md)"), or None if it may be untrusted.

    Only a built-in structured read tool (``_LOCAL_READ_TOOLS``, by exact
    name) with no network host qualifies, and its one path must be a plain
    local doc or test file outside third-party, temp and cache folders. A
    shell command, user prompt, web fetch, MCP result or source file read
    returns None. Whether the file was written earlier in the session is
    checked by the detectors (``_RecentActions``), not here.
    """
    if action.tool_name not in _LOCAL_READ_TOOLS:
        return None
    if action.network_host is not None or action.network_port is not None:
        return None
    if not _single_read_file(action):
        return None
    return _doc_path_reason(action.file_path)


# How many recent actions can launder a doc read. 50 is the widest window any
# security detector reads (exfiltration, undeclared egress), so a write that
# still counts as context for them also blocks a downgrade here.
_LAUNDER_WINDOW = 50
_LAUNDER_TEXT_LIMIT = 20_000  # of a non-read action's input text, searched


class _RecentActions:
    """The last ``_LAUNDER_WINDOW`` actions this detector has seen, kept across
    checks. A check gets the live buffer, but a late tool result is rescanned
    in a one-action buffer (SessionScan._scan_results); the actions kept here
    still give that rescan its context."""

    def __init__(self) -> None:
        self._seen: OrderedDict[int, Action] = OrderedDict()

    def see(self, buffer: ActionBuffer) -> None:
        for action in buffer.last(_LAUNDER_WINDOW):
            if id(action) not in self._seen:  # held, so the id is not reused
                self._seen[id(action)] = action
        while len(self._seen) > _LAUNDER_WINDOW:
            self._seen.popitem(last=False)

    def launders(self, read: Action) -> bool:
        """True if another recent action may have put the read file's text
        there: a write or edit to it (or into it, for a folder), or any other
        non-read tool call (shell, network, MCP, unknown) that names it.
        Fail safe: a later action counts as well as an earlier one."""
        parts = _path_parts(read.file_path)
        if parts is None:
            return True
        name = parts[-1]
        for other in self._seen.values():
            if other is read or other.tool_name in NON_TOOL_ROLE_LABELS:
                continue
            if is_usage_record(other):
                continue
            if other.is_file_edit:
                written = (other.file_path or "").replace("\\", "/").lower().split("/")
                if name in written:
                    return True
                continue
            if other.tool_name in _LOCAL_READ_TOOLS and not other.is_network:
                continue
            if name in _action_text(other):
                return True
        return False


def _action_text(action: Action) -> str:
    """Lower-case text naming what a non-read action touched: its command,
    path, host and tool input (bounded)."""
    raw = action.raw if isinstance(action.raw, dict) else {}
    inp = raw.get("input") or raw.get("args") or raw.get("arguments") or ""
    parts = [action.command or "", action.file_path or "", action.network_host or "", str(inp)]
    return " ".join(p[:_LAUNDER_TEXT_LIMIT] for p in parts).lower()


def _local_doc_reason(action: Action, recent: _RecentActions) -> str | None:
    """`local_doc_source`, unless a recent action may have written the file."""
    reason = local_doc_source(action)
    if reason is None or recent.launders(action):
        return None
    return reason


def _worst(warnings: list[Warning | None]) -> Warning | None:
    """The most severe warning (the first among equals), or None."""
    found = [w for w in warnings if w is not None]
    return max(found, key=lambda w: w.severity.score_impact) if found else None


class PromptInjectionDetector(SecurityDetector):
    """Heuristic detection of injection attempts in incoming messages."""

    category = Category.INJECTION
    name = "prompt_injection"
    description = "Potential prompt injection attempt detected"

    # Known injection patterns. Sourced from
    # `agentwatch.parser.security_patterns` (Sprint 14) so this detector and
    # `SessionStats.injection_attempts`'s raw counter (`parser/models.py`)
    # share one definition instead of two that could drift apart.
    INJECTION_PATTERNS = _SHARED_INJECTION_PATTERNS

    # Weighted patterns (more likely to be actual attacks) -- a confidence
    # tier on top of INJECTION_PATTERNS, not a distinct raw signal, so this
    # one stays local to the detector rather than moving to the shared module.
    HIGH_CONFIDENCE_PATTERNS = [
        r"ignore (?:all )?(?:previous |prior )?instructions",
        r"disregard .{0,20}(?:rules|guidelines|instructions)",
        r"<\|im_start\|>",
        r"jailbreak",
        r"DAN mode",
    ]

    def __init__(self):
        self._pattern = INJECTION_REGEX
        self._high_confidence = re.compile(
            "|".join(self.HIGH_CONFIDENCE_PATTERNS),
            re.IGNORECASE
        )
        self._memo = _ActionMemo()
        self._recent = _RecentActions()

    def check(self, buffer: ActionBuffer) -> Warning | None:
        self._recent.see(buffer)
        # The worst in the window: a downgraded doc read must not hide a
        # critical finding that came after it.
        return _worst([self._memo.get(a, self._scan) for a in buffer.last(10)])

    def _scan(self, action: Action) -> Warning | None:
        if not action.incoming_message:
            return None

        message = action.incoming_message

        # Check for high-confidence patterns first
        if self._high_confidence.search(message):
            warning = Warning(
                category=self.category,
                severity=Severity.CRITICAL,
                signal="prompt_injection",
                message="High-confidence prompt injection attempt detected",
                details={
                    "source": "incoming_message",
                    "confidence": "high",
                },
            )
            return self._downgrade_doc(action, warning, Severity.MEDIUM)

        # Check for general patterns
        matches = self._pattern.findall(message)
        if matches:
            # Multiple pattern matches = higher confidence
            severity = Severity.HIGH if len(matches) > 1 else Severity.MEDIUM

            warning = Warning(
                category=self.category,
                severity=severity,
                signal="prompt_injection",
                message=f"Possible prompt injection attempt ({len(matches)} pattern match)",
                details={
                    "source": "incoming_message",
                    "match_count": len(matches),
                    "confidence": "medium",
                },
            )
            return self._downgrade_doc(action, warning, Severity.LOW)

        return None

    def _downgrade_doc(self, action: Action, warning: Warning, to: Severity) -> Warning:
        """Injection text read from a local doc or test file is most likely
        writing about injection: keep the finding at *to*, with the reason.
        ``origin`` is part of the finding's identity, so a later real finding
        is a new one (SIEM export, alerts) rather than a repeat of this one."""
        reason = _local_doc_reason(action, self._recent)
        if reason is None:
            return warning
        warning.details["origin"] = "local_doc"
        warning.details["downgraded_from"] = warning.severity.value
        warning.details["reason"] = f"read from a local {reason}"
        warning.severity = to
        warning.message = f"Injection-like text in a local {reason} (likely documentation)"
        return warning


# Whole-word instruction keywords inside an HTML comment body: not part of a
# hyphenated token (prettier-ignore, re-run) and not a word fragment (runtime).
_COMMENT_KEYWORD_RE = re.compile(
    r"(?<![\w-])(?:ignore|execute|run|instructions?)(?![\w-])", re.IGNORECASE
)


class HiddenInstructionDetector(SecurityDetector):
    """Detects hidden instructions in various encodings."""

    category = Category.INJECTION
    name = "hidden_instruction"
    description = "Hidden or encoded instructions detected"

    # Patterns for hidden content
    HIDDEN_PATTERNS = [
        # Unicode tricks
        r"[\u200b-\u200f\u2060-\u206f]",  # Zero-width characters
        r"[\u2800-\u28ff]{10,}",  # Braille patterns (sometimes used to hide text)

        # Base64 that might contain instructions
        r"(?:aWdub3Jl|ZXhlY3V0ZQ|cnVuIHRoZQ)",  # base64 for ignore, execute, run the

        # Markdown hidden content
        r"\[//\]:\s*#",  # Markdown comment
        r"\[hidden\]",

        # CSS/Style hiding
        r"display:\s*none",
        r"visibility:\s*hidden",
        r"font-size:\s*0",
        r"color:\s*(?:white|#fff|transparent)",
    ]

    def __init__(self):
        self._pattern = re.compile(
            "|".join(self.HIDDEN_PATTERNS),
            re.IGNORECASE
        )
        self._memo = _ActionMemo()
        self._recent = _RecentActions()

    @staticmethod
    def _has_instruction_comment(text: str) -> bool:
        """True if an HTML comment whose body names an instruction keyword.

        Linear scan, not a regex: an HTML comment closes at the first ``-->``,
        and an unterminated comment runs to the end of the text (it still
        hides what follows). Bodies never overlap, so total work is O(n) and
        there is no length cap for an attacker to pad past.
        """
        pos = 0
        while True:
            start = text.find("<!--", pos)
            if start < 0:
                return False
            body_start = start + 4
            close = text.find("-->", body_start)
            body_end = len(text) if close < 0 else close
            # Slice so the body is its own string: the "-" of "<!--" must not
            # block a keyword that opens the body.
            if _COMMENT_KEYWORD_RE.search(text[body_start:body_end]):
                return True
            if close < 0:
                return False  # no later comment can close either
            pos = close + 3

    def check(self, buffer: ActionBuffer) -> Warning | None:
        self._recent.see(buffer)
        return _worst([self._memo.get(a, self._scan) for a in buffer.last(10)])

    def _scan(self, action: Action) -> Warning | None:
        content = action.incoming_message or ""

        # Also check raw data for web content
        if action.raw.get("content"):
            content += str(action.raw.get("content", ""))

        if self._pattern.search(content) or self._has_instruction_comment(content):
            details = {"source": action.tool_name}
            # Markdown and HTML comments are ordinary in docs.
            reason = _local_doc_reason(action, self._recent)
            if reason is not None:
                details["origin"] = "local_doc"
                details["downgraded_from"] = Severity.HIGH.value
                details["reason"] = f"read from a local {reason}"
            return Warning(
                category=self.category,
                severity=Severity.HIGH if reason is None else Severity.MEDIUM,
                signal="hidden_instruction",
                message="Hidden or encoded content detected",
                details=details,
            )
        return None


class IndirectInjectionDetector(SecurityDetector):
    """Detects potential indirect prompt injection from external sources."""

    category = Category.INJECTION
    name = "indirect_injection"
    description = "Potential injection from external content"

    # Commands that might appear in fetched content
    INSTRUCTION_PATTERNS = [
        r"(?:please |now )?(?:run|execute|perform|do) (?:the following|this)",
        r"(?:you must|you should|you need to) (?:now )?",
        r"important(?:\s+instructions?)?:",
        r"(?:follow these|execute these|perform these) (?:steps|instructions|commands)",
        r"as (?:your|the) (?:next|first) (?:step|action|task)",
    ]

    def __init__(self):
        self._pattern = re.compile(
            "|".join(self.INSTRUCTION_PATTERNS),
            re.IGNORECASE
        )
        self._memo = _ActionMemo()

    def check(self, buffer: ActionBuffer) -> Warning | None:
        for action in buffer.last(10):
            warning = self._memo.get(action, self._scan)
            if warning is not None:
                return warning
        return None

    def _scan(self, action: Action) -> Warning | None:
        # Check content from external sources (web, files, etc.)
        if action.tool_type.value not in ("read", "browser", "mcp"):
            return None
        content = action.raw.get("content") or action.raw.get("output") or ""

        if isinstance(content, str) and self._pattern.search(content):
            return Warning(
                category=self.category,
                severity=Severity.MEDIUM,
                signal="indirect_injection",
                message=f"Instruction-like content in external source ({action.tool_name})",
                details={
                    "source_type": action.tool_type.value,
                    "tool": action.tool_name,
                },
            )
        return None
