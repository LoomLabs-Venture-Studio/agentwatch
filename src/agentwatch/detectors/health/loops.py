"""Detectors for loops, thrashing, and repetitive behavior."""

from __future__ import annotations

from collections import Counter

from agentwatch.parser.models import ActionBuffer

from ..base import Category, Detector, Severity, Warning


class LoopDetector(Detector):
    """Detects when agent is stuck in a loop."""
    
    category = Category.PROGRESS
    name = "loop"
    description = "Agent performing same action repeatedly"
    
    def __init__(self, threshold: int = 4, window: int = 10):
        self.threshold = threshold
        self.window = window
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.window:
            return None
        
        recent = buffer.last(self.window)
        
        # Check for repeated identical tool calls
        tool_sequence = [f"{a.tool_name}:{a.file_path or ''}" for a in recent]
        counts = Counter(tool_sequence)
        
        most_common, count = counts.most_common(1)[0]
        
        if count >= self.threshold:
            tool, path = most_common.split(":", 1) if ":" in most_common else (most_common, "")

            # Gather the actual commands/errors for context
            matching = [a for a in recent if f"{a.tool_name}:{a.file_path or ''}" == most_common]
            last_cmd = next((a.command for a in reversed(matching) if a.command), None)
            last_err = next((a.error_message for a in reversed(matching) if a.error_message), None)

            detail_line = ""
            if last_cmd:
                detail_line = f"Command: {last_cmd[:100]}"
            if last_err:
                detail_line += f" → {last_err[:100]}" if detail_line else f"Error: {last_err[:100]}"

            return Warning(
                category=self.category,
                severity=Severity.MEDIUM if count < 6 else Severity.HIGH,
                signal="loop",
                message=f"Repeated action: {tool}" + (f" on {path}" if path else "") + f" ({count}x)",
                suggestion=f"The exact same action is being repeated. "
                + (f"The command \"{last_cmd[:80]}\" keeps failing — try a fundamentally different approach." if last_cmd and last_err else "Consider whether a different strategy is needed."),
                details={
                    "tool": tool,
                    "path": path or None,
                    "count": count,
                    "last_command": last_cmd,
                    "last_error": last_err,
                },
            )
        
        return None


class RereadDetector(Detector):
    """Detects when agent keeps re-reading the same file."""
    
    category = Category.PROGRESS
    name = "reread"
    description = "Agent re-reading same file multiple times"
    
    def __init__(self, threshold: int = 3, window: int = 15):
        self.threshold = threshold
        self.window = window
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.window:
            return None
        
        recent = buffer.last(self.window)
        
        # Count reads per file
        read_counts: dict[str, int] = {}
        for action in recent:
            if action.is_file_read and action.file_path:
                read_counts[action.file_path] = read_counts.get(action.file_path, 0) + 1
        
        # Find worst offender
        for path, count in read_counts.items():
            if count >= self.threshold:
                return Warning(
                    category=self.category,
                    severity=Severity.LOW if count < 5 else Severity.MEDIUM,
                    signal="reread",
                    message=f"Re-reading file: {path} ({count}x)",
                    suggestion=f"Reading the same file {count} times suggests the agent isn't retaining what it reads. The file content may be too long, or the agent is losing context.",
                    details={"path": path, "count": count},
                )
        
        return None


class ThrashDetector(Detector):
    """Detects edit→test→fail cycles on the same file."""
    
    category = Category.PROGRESS
    name = "thrash"
    description = "Repeated edit→test→fail cycle"
    
    def __init__(self, threshold: int = 3, window: int = 20):
        self.threshold = threshold
        self.window = window
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.window:
            return None
        
        recent = buffer.last(self.window)
        
        # Track edit→bash→fail patterns per file
        file_thrash_counts: dict[str, int] = {}
        
        i = 0
        while i < len(recent) - 2:
            action = recent[i]
            
            # Look for: edit file → bash command → failure
            if action.is_file_edit and action.file_path:
                # Check next few actions for bash + failure
                for j in range(i + 1, min(i + 4, len(recent))):
                    if recent[j].is_bash and not recent[j].success:
                        path = action.file_path
                        file_thrash_counts[path] = file_thrash_counts.get(path, 0) + 1
                        break
            
            i += 1
        
        # Check for threshold
        for path, count in file_thrash_counts.items():
            if count >= self.threshold:
                # Get the last error from a bash failure near this file
                last_err = None
                for a in reversed(recent):
                    if a.is_bash and not a.success and a.error_message:
                        last_err = a.error_message[:120]
                        break

                return Warning(
                    category=self.category,
                    severity=Severity.HIGH,
                    signal="thrash",
                    message=f"Edit→test→fail cycle on {path} ({count}x)",
                    suggestion=f"Edits to {path} keep failing tests. "
                    + (f"Last error: \"{last_err}\". " if last_err else "")
                    + "Stop editing and re-examine the approach.",
                    details={"path": path, "count": count, "last_error": last_err},
                )
        
        return None


class StallDetector(Detector):
    """Detects when agent has stopped making progress."""
    
    category = Category.PROGRESS
    name = "stall"
    description = "No meaningful progress detected"
    
    def __init__(self, window: int = 15, min_edits: int = 1):
        self.window = window
        self.min_edits = min_edits
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.window:
            return None
        
        recent = buffer.last(self.window)
        
        # Count productive actions
        edits = sum(1 for a in recent if a.is_file_edit)
        reads = sum(1 for a in recent if a.is_file_read)
        successful_bash = sum(1 for a in recent if a.is_bash and a.success)
        
        # If lots of reads but no edits, might be stuck
        if reads > 8 and edits < self.min_edits and successful_bash < 2:
            stalled_files = sorted({a.file_path for a in recent if a.is_file_read and a.file_path})[:5]
            return Warning(
                category=self.category,
                severity=Severity.MEDIUM,
                signal="stall",
                message=f"Lots of reading ({reads}), minimal writing ({edits})",
                suggestion=f"The agent is reading but not acting. Files being read: {', '.join(stalled_files)}. It may be stuck deciding what to do.",
                details={
                    "reads": reads,
                    "edits": edits,
                    "successful_bash": successful_bash,
                    "files_being_read": stalled_files,
                },
            )
        
        return None
