"""Detectors for error patterns and failure modes."""

from __future__ import annotations

import re
from collections import Counter

from agentwatch.parser.models import ActionBuffer

from ..base import Category, Detector, Severity, Warning


class ErrorSpiralDetector(Detector):
    """Detects consecutive failures without recovery."""
    
    category = Category.ERRORS
    name = "error_spiral"
    description = "Multiple consecutive failures"
    
    def __init__(self, threshold: int = 3):
        self.threshold = threshold
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.threshold:
            return None
        
        recent = buffer.last(self.threshold + 2)
        
        # Count consecutive failures from the end
        consecutive_failures = 0
        for action in reversed(recent):
            if not action.success:
                consecutive_failures += 1
            else:
                break
        
        if consecutive_failures >= self.threshold:
            # Collect the actual errors
            recent_errs = [
                a.error_message[:100] for a in reversed(recent)
                if not a.success and a.error_message
            ][:3]

            return Warning(
                category=self.category,
                severity=Severity.HIGH,
                signal="error_spiral",
                message=f"Error spiral: {consecutive_failures} consecutive failures",
                suggestion="Nothing has succeeded recently. Consider reverting recent changes or trying a completely different approach.",
                details={
                    "consecutive_failures": consecutive_failures,
                    "recent_errors": recent_errs,
                },
            )
        
        return None


class ErrorBlindnessDetector(Detector):
    """Detects when the same error keeps occurring without being fixed."""
    
    category = Category.ERRORS
    name = "error_blindness"
    description = "Same error repeated without fix"
    
    def __init__(self, threshold: int = 3, window: int = 15):
        self.threshold = threshold
        self.window = window
    
    def _normalize_error(self, error: str) -> str:
        """Normalize error message for comparison."""
        # Remove line numbers, file paths, etc.
        error = re.sub(r'line \d+', 'line N', error)
        error = re.sub(r':\d+:\d+', ':N:N', error)
        error = re.sub(r'/[\w/.-]+\.py', 'FILE.py', error)
        return error.strip()[:200]  # Truncate for comparison
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.window:
            return None
        
        recent = buffer.last(self.window)
        
        # Collect and normalize errors
        errors = []
        for action in recent:
            if not action.success and action.error_message:
                errors.append(self._normalize_error(action.error_message))
        
        if not errors:
            return None
        
        # Count repeated errors
        error_counts = Counter(errors)
        most_common, count = error_counts.most_common(1)[0]
        
        if count >= self.threshold:
            return Warning(
                category=self.category,
                severity=Severity.HIGH,
                signal="error_blindness",
                message=f"Same error repeated {count}x without fix",
                suggestion=f"The error \"{most_common[:80]}\" keeps appearing unchanged. The agent isn't reading or addressing the error message.",
                details={
                    "error_pattern": most_common[:100],
                    "count": count,
                },
            )
        
        return None


class SyntaxLoopDetector(Detector):
    """Detects repeated syntax or import errors."""
    
    category = Category.ERRORS
    name = "syntax_loop"
    description = "Repeated syntax/import errors"
    
    SYNTAX_PATTERNS = [
        r"SyntaxError",
        r"IndentationError",
        r"ImportError",
        r"ModuleNotFoundError",
        r"NameError",
        r"cannot find module",
        r"unexpected token",
        r"parsing error",
    ]
    
    def __init__(self, threshold: int = 3, window: int = 15):
        self.threshold = threshold
        self.window = window
        self._pattern = re.compile("|".join(self.SYNTAX_PATTERNS), re.IGNORECASE)
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.window:
            return None
        
        recent = buffer.last(self.window)
        
        # Count syntax-like errors
        syntax_errors = 0
        for action in recent:
            if action.error_message and self._pattern.search(action.error_message):
                syntax_errors += 1
        
        if syntax_errors >= self.threshold:
            # Collect sample error messages
            samples = [
                a.error_message[:100] for a in recent
                if a.error_message and self._pattern.search(a.error_message)
            ][:3]

            return Warning(
                category=self.category,
                severity=Severity.MEDIUM,
                signal="syntax_loop",
                message=f"Repeated syntax/import errors ({syntax_errors}x)",
                suggestion=f"Recurring syntax/import errors suggest a structural issue. Errors seen: {'; '.join(samples[:2])}",
                details={"count": syntax_errors, "sample_errors": samples},
            )
        
        return None


class HighErrorRateDetector(Detector):
    """Detects when error rate is unusually high."""
    
    category = Category.ERRORS
    name = "high_error_rate"
    description = "Unusually high failure rate"
    
    def __init__(self, threshold: float = 0.6, window: int = 20, min_actions: int = 10):
        self.threshold = threshold
        self.window = window
        self.min_actions = min_actions
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.min_actions:
            return None
        
        recent = buffer.last(self.window)
        
        failures = sum(1 for a in recent if not a.success)
        error_rate = failures / len(recent)
        
        if error_rate >= self.threshold:
            return Warning(
                category=self.category,
                severity=Severity.HIGH if error_rate > 0.75 else Severity.MEDIUM,
                signal="high_error_rate",
                message=f"High error rate: {int(error_rate * 100)}% of actions failing ({failures}/{len(recent)})",
                suggestion=f"{failures} out of {len(recent)} recent actions failed. The agent may be in an unrecoverable state for this approach.",
                details={
                    "error_rate": round(error_rate, 2),
                    "failures": failures,
                    "total": len(recent),
                },
            )
        
        return None
