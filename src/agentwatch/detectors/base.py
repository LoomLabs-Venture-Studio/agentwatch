"""Base classes for all detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agentwatch.parser.models import ActionBuffer


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


class Severity(Enum):
    """Severity levels for warnings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @property
    def emoji(self) -> str:
        return {
            Severity.LOW: "💡",
            Severity.MEDIUM: "⚠️",
            Severity.HIGH: "🔴",
            Severity.CRITICAL: "🚨",
        }[self]
    
    @property
    def score_impact(self) -> int:
        """How much this severity impacts the health score."""
        return {
            Severity.LOW: 5,
            Severity.MEDIUM: 15,
            Severity.HIGH: 30,
            Severity.CRITICAL: 50,
        }[self]


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
