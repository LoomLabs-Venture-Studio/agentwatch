"""Detectors for context window and memory issues."""

from __future__ import annotations

from agentwatch.parser.models import ActionBuffer

from ..base import Category, Detector, Severity, Warning


class ContextRotDetector(Detector):
    """Detects when important early-session files are forgotten."""

    category = Category.CONTEXT
    name = "context_rot"
    description = "Important early files no longer being referenced"

    def __init__(
        self,
        early_fraction: float = 0.25,
        recent_window: int = 50,
        min_actions: int = 40,
    ):
        self.early_fraction = early_fraction
        self.recent_window = recent_window
        self.min_actions = min_actions

    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.min_actions:
            return None

        # Use the first 25% of the session as "early"
        early_count = max(15, int(len(buffer) * self.early_fraction))

        # Get files from early in session
        early_actions = buffer.first(early_count)
        early_files = {a.file_path for a in early_actions if a.file_path}

        if not early_files:
            return None

        # Get files referenced recently
        recent_files = buffer.files_in_window(self.recent_window)

        # Find forgotten files
        forgotten = early_files - recent_files

        # Filter to likely important files (edited, not just read)
        edited_early = {
            a.file_path for a in early_actions if a.is_file_edit and a.file_path
        }
        # Sorted: set order depends on PYTHONHASHSEED, and check --json must
        # give the same output on every run (#33).
        important_forgotten = sorted(f for f in forgotten if f in edited_early)

        if len(important_forgotten) >= 2:
            return Warning(
                category=self.category,
                severity=Severity.MEDIUM,
                signal="context_rot",
                message=f"{len(important_forgotten)} early files not referenced recently",
                details={
                    "forgotten_files": important_forgotten[:5],
                    "total_early": len(early_files),
                    "total_recent": len(recent_files),
                },
            )

        return None


class ContextPressureDetector(Detector):
    """Warns when the current context fills the model's window.

    Current context is the latest call's input + cache tokens
    (``SessionStats.last_context_tokens``), not a sum over the session:
    every call re-sends the conversation, so a sum passes 100% on any long
    session. It drops after compaction. No usage reported, or no known
    window (``SessionStats.known_context_window``): no percentage claimed.
    """

    category = Category.CONTEXT
    name = "context_pressure"
    description = "Context window filling up"

    def __init__(self, warning_threshold: float = 0.7, critical_threshold: float = 0.85):
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold

    def check(self, buffer: ActionBuffer) -> Warning | None:
        stats = buffer.stats
        tokens, window = stats.last_context_tokens, stats.known_context_window
        if not (tokens and window):
            return None
        usage_ratio = min(tokens / window, 1.0)
        if usage_ratio < self.warning_threshold:
            return None
        critical = usage_ratio >= self.critical_threshold
        return Warning(
            category=self.category,
            severity=Severity.HIGH if critical else Severity.MEDIUM,
            signal="context_critical" if critical else "context_pressure",
            message=f"Context window ~{int(usage_ratio * 100)}% full",
            details={
                "estimated_tokens": tokens,
                "usage_percent": int(usage_ratio * 100),
                "limit": window,
            },
        )


class RediscoveryDetector(Detector):
    """Detects when agent is re-discovering things it should already know."""

    category = Category.CONTEXT
    name = "rediscovery"
    description = "Agent re-discovering previously learned information"

    def __init__(self, window: int = 200, rediscovery_gap: int = 30):
        self.window = window
        self.rediscovery_gap = rediscovery_gap

    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.window:
            return None

        actions = buffer.last(self.window)

        # Track file read positions
        file_first_read: dict[str, int] = {}
        file_reread_gaps: dict[str, list[int]] = {}

        for i, action in enumerate(actions):
            if action.is_file_read and action.file_path:
                path = action.file_path
                if path in file_first_read:
                    gap = i - file_first_read[path]
                    if gap >= self.rediscovery_gap:
                        if path not in file_reread_gaps:
                            file_reread_gaps[path] = []
                        file_reread_gaps[path].append(gap)
                    # Always update to measure next gap from this read
                    file_first_read[path] = i
                else:
                    file_first_read[path] = i

        # Find files with significant rediscovery
        worst_file = None
        worst_count = 0
        for path, gaps in file_reread_gaps.items():
            if len(gaps) > worst_count:
                worst_file = path
                worst_count = len(gaps)

        if worst_count >= 2:
            return Warning(
                category=self.category,
                severity=Severity.LOW,
                signal="rediscovery",
                message=f"Re-reading {worst_file} after long gaps ({worst_count}x)",
                details={
                    "file": worst_file,
                    "rediscovery_count": worst_count,
                },
            )

        return None
