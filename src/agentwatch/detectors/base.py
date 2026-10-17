"""Base classes for all detectors."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agentwatch.parser.models import ActionBuffer
from agentwatch.themes import get_current_theme_name


class Category(Enum):
    """Categories of issues detected."""
    # Health categories
    PROGRESS = "progress"
    ERRORS = "errors"
    CONTEXT = "context"
    GOAL = "goal"

    # Security categories
    CREDENTIAL = "credential"
    INJECTION = "injection"
    EXFILTRATION = "exfiltration"
    PRIVILEGE = "privilege"
    NETWORK = "network"
    SUPPLY_CHAIN = "supply_chain"


_SEVERITY_EMOJI: dict["Severity", str] = {}
_SEVERITY_EMOJI_ASCII: dict["Severity", str] = {}


class Severity(Enum):
    """Severity levels for warnings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def emoji(self) -> str:
        """Severity glyph -- theme-aware ONLY for ASCII-safety, not vocabulary.

        DESIGN DECISION (Task #9, flagged for CTO review rather than picked
        silently): ``Severity`` is a categorical enum (LOW/MEDIUM/HIGH/
        CRITICAL) that is architecturally independent of ``StatusTheme``'s
        four SCORE-DERIVED levels (``level_0``..``level_3``) -- no severity
        means "all good" the way ``level_0`` does, since every ``Warning``
        that reaches this property already represents an actual problem.

        Considered mapping LOW/MEDIUM/HIGH/CRITICAL onto
        ``emoji_1``/``emoji_1-or-2``/``emoji_2``/``emoji_3`` (skipping
        ``emoji_0``) as suggested, but rejected it: it would make every
        non-ascii theme's *wording* leak into severity display too (e.g.
        the `agent` theme's "struggling"/"spinning" vocabulary standing in
        for MEDIUM/HIGH), doubles up two severities onto one theme level
        for every theme, and is a strictly bigger behavior change than this
        bug (a tofu'd emoji under `--theme ascii`) calls for.

        Instead: keep the existing fixed emoji per severity for every theme
        except `ascii` -- so all 11 non-ascii themes are provably unchanged
        (see test_severity_emoji_unchanged_for_non_ascii_themes) -- and only
        swap in bracketed ASCII markers when the `ascii` theme is active,
        matching that theme's own [OK]/[WARN]/[ALERT]/[FAIL] convention.
        """
        if get_current_theme_name() == "ascii":
            return _SEVERITY_EMOJI_ASCII[self]
        return _SEVERITY_EMOJI[self]

    @property
    def score_impact(self) -> int:
        """How much this severity impacts the health score."""
        return {
            Severity.LOW: 5,
            Severity.MEDIUM: 15,
            Severity.HIGH: 30,
            Severity.CRITICAL: 50,
        }[self]


# Populated post-class-definition since the dicts key on `Severity` members.
# Non-ascii themes: unchanged from pre-Task-#9 hardcoded values (see the
# design-decision docstring on `Severity.emoji` above).
_SEVERITY_EMOJI.update({
    Severity.LOW: "💡",
    Severity.MEDIUM: "⚠️",
    Severity.HIGH: "🔴",
    Severity.CRITICAL: "🚨",
})
_SEVERITY_EMOJI_ASCII.update({
    Severity.LOW: "[LOW]",
    Severity.MEDIUM: "[MED]",
    Severity.HIGH: "[HIGH]",
    Severity.CRITICAL: "[CRIT]",
})


@dataclass
class Warning:
    """A warning produced by a detector."""

    category: Category
    severity: Severity
    signal: str  # e.g., "loop", "credential_access", "injection"
    message: str
    suggestion: str | None = None  # Actionable recommendation
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str | None = None

    @property
    def emoji(self) -> str:
        return self.severity.emoji

    @property
    def is_security(self) -> bool:
        """Check if this is a security-related warning."""
        return self.category in (
            Category.CREDENTIAL,
            Category.INJECTION,
            Category.EXFILTRATION,
            Category.PRIVILEGE,
            Category.NETWORK,
            Category.SUPPLY_CHAIN,
        )

    @property
    def is_health(self) -> bool:
        """Check if this is a health-related warning."""
        return self.category in (
            Category.PROGRESS,
            Category.ERRORS,
            Category.CONTEXT,
            Category.GOAL,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        d = {
            "category": self.category.value,
            "severity": self.severity.value,
            "signal": self.signal,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp,
            "is_security": self.is_security,
        }
        if self.suggestion:
            d["suggestion"] = self.suggestion
        return d


# "Identity-ish" detail keys, checked in this order, used to disambiguate
# two simultaneously-open warnings that share the same `signal` but concern
# different targets (e.g. two different files each independently tripping
# the same re-read-loop detector). Deliberately excludes any key known to
# carry a live occurrence counter (those change every tick and would defeat
# dedup if included here).
_IDENTITY_DETAIL_KEYS = (
    "secret_type",
    "channel",
    "file_path",
    "file",
    "path",
    "error_class",
    "error_pattern",
    "last_command",
    "last_error",
    "endpoint",
    "loop_id",
)

# Error text in a key is normalized first: its durations, pids, temp paths
# and timestamps change on every run of the same failure.
_ERROR_DETAIL_KEYS = frozenset({"error_pattern", "last_error"})

# Volatile parts of an error message: line numbers, durations, hex ids and
# hashes, Windows and POSIX paths (temp dirs), and any 2+ digit number
# (pids, ports, timestamps). Single digits stay: "exit code 1" != "exit code 2".
_VOLATILE_ERROR_RE = re.compile(
    r"line \d+"
    r"|\d+(?:\.\d+)?\s*(?:ms|s|secs?|seconds?)\b"
    r"|0x[0-9a-f]+|\b[0-9a-f]{8,}\b"
    r"|[a-z]:\\[^\s'\"]+"
    r"|/[\w./\-]+"
    r"|\d{2,}"
)


def normalize_error(msg: str) -> str:
    """Stable signature of an error message: volatile parts become ``<X>``,
    whitespace collapsed."""
    return " ".join(_VOLATILE_ERROR_RE.sub("<X>", msg.lower()).split())


def warning_dedup_key(warning: Warning) -> str:
    """Stable content-based identity for *warning*, used to recognize
    "already seen, still open" across `check_all()` calls that construct
    an entirely new `Warning` object each time."""
    parts = [warning.signal]
    for key in _IDENTITY_DETAIL_KEYS:
        if key == "last_error" and "loop_id" in warning.details:
            continue  # a loop is its call (loop_id); the error text varies per run
        value = warning.details.get(key)
        if value:
            if key in _ERROR_DETAIL_KEYS:
                value = normalize_error(str(value))
            parts.append(f"{key}={value}")
    return "|".join(parts)


class Detector(ABC):
    """Abstract base class for all detectors."""

    category: Category
    name: str
    description: str

    # Whether this detector is security-focused
    is_security_detector: bool = False

    @abstractmethod
    def check(self, buffer: ActionBuffer) -> Warning | None:
        """
        Check the action buffer for issues.

        Returns a Warning if an issue is detected, None otherwise.
        """
        pass

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.category.value}/{self.name})>"


class SecurityDetector(Detector):
    """Base class for security-focused detectors."""

    is_security_detector: bool = True

    # Audit logging for security detectors
    def check_with_audit(self, buffer: ActionBuffer) -> tuple[Warning | None, dict[str, Any]]:
        """
        Check and return audit information.

        Returns (warning, audit_log) tuple.
        """
        warning = self.check(buffer)

        audit_log = {
            "detector": self.name,
            "category": self.category.value,
            "triggered": warning is not None,
            "action_count": len(buffer),
        }

        if warning:
            audit_log["warning"] = warning.to_dict()

        return warning, audit_log
