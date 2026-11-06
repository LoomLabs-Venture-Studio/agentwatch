"""Detectors for prompt injection attempts."""

from __future__ import annotations

import re
import shlex
from collections import OrderedDict
from collections.abc import Callable

from agentwatch.parser.models import (
    NON_TOOL_ROLE_LABELS,
    Action,
    ActionBuffer,
    ToolType,
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
# can downgrade it; text from the web, an MCP tool, a source file or a user
# prompt keeps its severity. Generic over parsers: only Action fields are read.

_DOC_SUFFIXES = (".md", ".mdx", ".markdown", ".rst", ".txt", ".adoc")
_DOC_DIRS = frozenset({"docs", "doc"})
_TEST_DIRS = frozenset({"tests", "test", "__tests__", "spec", "specs"})
_DOC_NAMES = frozenset({"readme", "changelog", "license", "contributing"})
# Third-party or fetched content stays untrusted even when it looks like a doc:
# installed packages, temp files, and Claude Code's saved large tool results
# (which may hold a web fetch).
_UNTRUSTED_DIRS = frozenset({
    "node_modules", "site-packages", "dist-packages", "vendor",
    "tmp", "temp", "tool-results",
})
_TEST_NAME_RE = re.compile(
    r"^(?:test_.+\.py|conftest\.py|.+_test\.[a-z0-9]+|.+\.(?:spec|test)\.[a-z0-9]+)$"
)
# Shell commands that only print files. The first positional argument of the
# pattern-taking ones is the pattern, not a file.
_PRINT_COMMANDS = frozenset({
    "cat", "head", "tail", "less", "more", "nl", "wc", "bat", "type",
    "get-content", "gc", "cut", "sort", "uniq", "column", "fold", "tac", "rev",
})
_PATTERN_COMMANDS = frozenset({"grep", "egrep", "fgrep", "rg", "sed", "awk", "findstr"})
# Arguments are text, not files (tr's character sets, echo's words).
_TEXT_COMMANDS = frozenset({"tr", "echo"})
_SHELL_SPLIT_RE = re.compile(r"\|\||&&|[|;\n]")


def _doc_path_reason(path: str) -> str | None:
    """Why *path* is a local doc or test file (or a docs/tests folder), or None."""
    parts = [p for p in path.replace("\\", "/").lower().split("/") if p and p != "."]
    if not parts or any(p in _UNTRUSTED_DIRS for p in parts):
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


def _command_read_paths(command: str) -> list[str] | None:
    """Files a print-only shell command reads, or None when the command does
    anything else (or cannot be parsed). ``cd`` steps are allowed."""
    if "$(" in command or "`" in command:
        return None
    paths: list[str] = []
    for segment in _SHELL_SPLIT_RE.split(command):
        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError:
            return None
        if not tokens:
            continue
        program = tokens[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
        if program == "cd" or program in _TEXT_COMMANDS:
            continue
        if program not in _PRINT_COMMANDS and program not in _PATTERN_COMMANDS:
            return None
        positional: list[str] = []
        has_e = False
        skip = False
        for tok in tokens[1:]:
            if skip:
                skip = False
                continue
            if tok in (">", ">>", "<", "2>", "&>"):
                skip = True
                continue
            if ">" in tok or "<" in tok:
                continue
            if tok in ("-e", "-f", "--regexp", "--file"):
                has_e = skip = True  # the next token is the pattern or its file
                continue
            if tok.startswith("-"):
                has_e = has_e or tok.startswith(("--regexp=", "--file="))
                continue
            if tok.isdigit():
                continue  # head -n 50, grep -A 3
            positional.append(tok)
        if program in _PATTERN_COMMANDS and not has_e and positional:
            positional = positional[1:]  # the pattern / sed or awk script
        paths.extend(positional)
    return paths or None


def local_doc_source(action: Action) -> str | None:
    """Why *action*'s result text came from reading a local doc or test file
    (e.g. "doc file (.md)"), or None if it may be untrusted.

    Only read, search, list and print-only shell actions qualify, with no
    network host and not an MCP tool; every file they name must be a doc or
    test file. A user prompt, a web fetch, an MCP result or a source file
    read returns None.
    """
    if action.network_host is not None or action.network_port is not None:
        return None
    if action.tool_name in NON_TOOL_ROLE_LABELS or is_usage_record(action):
        return None
    if "mcp" in action.tool_name.lower():
        return None
    if action.tool_type in (ToolType.READ, ToolType.SEARCH, ToolType.LIST):
        paths = [action.file_path] if action.file_path else None
    elif action.tool_type == ToolType.BASH and action.command:
        paths = _command_read_paths(action.command)
    else:
        return None
    if not paths:
        return None
    reasons = [_doc_path_reason(p) for p in paths]
    if any(r is None for r in reasons):
        return None
    return reasons[0]


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

    def check(self, buffer: ActionBuffer) -> Warning | None:
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

    @staticmethod
    def _downgrade_doc(action: Action, warning: Warning, to: Severity) -> Warning:
        """Injection text read from a local doc or test file is most likely
        writing about injection: keep the finding at *to*, with the reason."""
        reason = local_doc_source(action)
        if reason is None:
            return warning
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
        return _worst([self._memo.get(a, self._scan) for a in buffer.last(10)])

    def _scan(self, action: Action) -> Warning | None:
        content = action.incoming_message or ""

        # Also check raw data for web content
        if action.raw.get("content"):
            content += str(action.raw.get("content", ""))

        if self._pattern.search(content) or self._has_instruction_comment(content):
            details = {"source": action.tool_name}
            # Markdown and HTML comments are ordinary in docs.
            reason = local_doc_source(action)
            if reason is not None:
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
