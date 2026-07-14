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
        important_forgotten = []
        for f in forgotten:
            for action in early_actions:
                if action.file_path == f and action.is_file_edit:
                    important_forgotten.append(f)
                    break
        
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
    """Estimates context window usage and warns when filling up."""
    
    category = Category.CONTEXT
    name = "context_pressure"
    description = "Context window filling up"
    
    # Rough estimate: average tokens per action type
    TOKENS_PER_ACTION = {
        "read": 500,
        "edit": 200,
        "bash": 300,
        "write": 150,
        "default": 150,
    }
    
    # Approximate context limits by model
    CONTEXT_LIMITS = {
        "claude": 180_000,
        "gpt4": 128_000,
        "default": 128_000,
    }
    
    def __init__(
        self, 
        warning_threshold: float = 0.7, 
        critical_threshold: float = 0.85,
        model: str = "claude",
    ):
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold
        self.context_limit = self.CONTEXT_LIMITS.get(model, self.CONTEXT_LIMITS["default"])
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < 10:
            return None
        
        # Estimate tokens used
        estimated_tokens = 0
        for action in buffer.actions:  # All buffered actions represent cumulative context
            action_type = action.tool_type.value
            tokens = self.TOKENS_PER_ACTION.get(
                action_type, 
                self.TOKENS_PER_ACTION["default"]
            )
            
            # Use actual tokens if available
            if action.tokens_in or action.tokens_out:
                tokens = action.tokens_in + action.tokens_out
            
            estimated_tokens += tokens
        
        usage_ratio = estimated_tokens / self.context_limit
        
        if usage_ratio >= self.critical_threshold:
            return Warning(
                category=self.category,
                severity=Severity.HIGH,
                signal="context_critical",
                message=f"Context window ~{int(usage_ratio * 100)}% full",
                details={
                    "estimated_tokens": estimated_tokens,
                    "usage_percent": int(usage_ratio * 100),
                    "limit": self.context_limit,
                },
            )
        elif usage_ratio >= self.warning_threshold:
            return Warning(
                category=self.category,
                severity=Severity.MEDIUM,
                signal="context_pressure",
                message=f"Context window ~{int(usage_ratio * 100)}% full",
                details={
                    "estimated_tokens": estimated_tokens,
                    "usage_percent": int(usage_ratio * 100),
                    "limit": self.context_limit,
                },
            )
        
        return None


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
