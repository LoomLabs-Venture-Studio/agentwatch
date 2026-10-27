"""Detectors for prompt injection attempts."""

from __future__ import annotations

import re
from collections import OrderedDict
from collections.abc import Callable

from agentwatch.parser.models import Action, ActionBuffer
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
        for action in buffer.last(10):
            warning = self._memo.get(action, self._scan)
            if warning is not None:
                return warning
        return None

    def _scan(self, action: Action) -> Warning | None:
        if not action.incoming_message:
            return None

        message = action.incoming_message

        # Check for high-confidence patterns first
        if self._high_confidence.search(message):
            return Warning(
                category=self.category,
                severity=Severity.CRITICAL,
                signal="prompt_injection",
                message="High-confidence prompt injection attempt detected",
                details={
                    "source": "incoming_message",
                    "confidence": "high",
                },
            )

        # Check for general patterns
        matches = self._pattern.findall(message)
        if matches:
            # Multiple pattern matches = higher confidence
            severity = Severity.HIGH if len(matches) > 1 else Severity.MEDIUM

            return Warning(
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

        return None


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
        for action in buffer.last(10):
            warning = self._memo.get(action, self._scan)
            if warning is not None:
                return warning
        return None

    def _scan(self, action: Action) -> Warning | None:
        content = action.incoming_message or ""

        # Also check raw data for web content
        if action.raw.get("content"):
            content += str(action.raw.get("content", ""))

        if self._pattern.search(content) or self._has_instruction_comment(content):
            return Warning(
                category=self.category,
                severity=Severity.HIGH,
                signal="hidden_instruction",
                message="Hidden or encoded content detected",
                details={"source": action.tool_name},
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
