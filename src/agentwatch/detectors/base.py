"""Base classes for all detectors."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from agentwatch.parser.models import ActionBuffer, calls_of, calls_usage
from agentwatch.themes import ascii_safe, get_current_theme_name

if TYPE_CHECKING:
    from collections.abc import Iterable

    from agentwatch.parser.models import Action


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
    # Spend on the API calls behind the actions this finding covers (see
    # with_cost). None = no token data / no price: absent, never 0 or a guess.
    tokens: int | None = None
    cost_usd: float | None = None
    # Those calls, so a session total can count a call shared by two findings once.
    calls: dict[Any, Any] = field(default_factory=dict, repr=False, compare=False)

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
        if self.tokens is not None:
            d["tokens"] = self.tokens
        if self.cost_usd is not None:
            d["cost_usd"] = round(self.cost_usd, 4)
        return d

    def with_cost(self, actions: "Iterable[Action]", buffer: ActionBuffer) -> "Warning":
        """Set tokens/cost_usd from the calls behind *actions*; returns self."""
        self.calls = calls_of(actions, buffer)
        self.tokens, self.cost_usd = calls_usage(self.calls.values())
        return self

    @property
    def cost_label(self) -> str | None:
        """'~$1.40 · 210k tok', '210k tok' without a price, None without tokens."""
        return format_cost(self.cost_usd, self.tokens)


def format_tokens(tokens: int) -> str:
    """210000 -> '210k', 1_234_567 -> '1.2M'."""
    if tokens >= 1_000_000:
        return f"{tokens / 1_000_000:.1f}M"
    if tokens >= 1_000:
        return f"{tokens / 1_000:.0f}k"
    return str(tokens)


def format_usd(cost: float) -> str:
    return "<$0.01" if cost < 0.005 else f"~${cost:,.2f}"


def findings_spend(warnings: "Iterable[Warning]") -> tuple[int, int | None, float | None]:
    """(findings with token data, tokens, usd) over the union of their calls:
    a call two findings share (a loop that is also an error spiral) counts once."""
    spent = [w for w in warnings if w.tokens is not None]
    calls: dict[Any, Any] = {}
    for w in spent:
        calls.update(w.calls)
    tokens, cost = calls_usage(calls.values())
    return len(spent), tokens, cost


def waste_summary(warnings: "Iterable[Warning]", stats: Any) -> dict[str, Any] | None:
    """Spend on the calls behind the findings vs the session's (*stats*, a
    SessionStats), or None when no finding has token data. A call shared by
    two findings counts once. `check`'s waste line and `agentwatch history`."""
    findings, tokens, cost = findings_spend(warnings)
    if not findings:
        return None
    return {
        "findings": findings,
        "tokens": tokens,
        "cost_usd": None if cost is None else round(cost, 4),
        "session_tokens": stats.billed_tokens,
        "session_cost_usd": None if stats.billed_cost is None else round(stats.billed_cost, 4),
    }


def format_cost(cost: float | None, tokens: int | None) -> str | None:
    """Shared cost text for check, the TUIs and the waste line."""
    if tokens is None:
        return None
    tok = f"{format_tokens(tokens)} tok"
    if cost is None:
        return tok
    return f"{format_usd(cost)} {ascii_safe('·', '|')} {tok}"


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


def normalize_error(msg: object) -> str:
    """Stable signature of an error message: volatile parts become ``<X>``,
    whitespace collapsed. Non-strings are stringified, not trusted."""
    if not isinstance(msg, str):
        msg = "" if msg is None else str(msg)
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
