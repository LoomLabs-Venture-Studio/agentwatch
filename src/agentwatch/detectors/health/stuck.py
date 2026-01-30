"""Detectors for non-trivial stuck patterns.

These detect cases where the agent is trying different approaches but making
no real progress — the actions look different but the macro outcome is the same.
"""

from __future__ import annotations

import re
from collections import Counter

from agentwatch.parser.models import ActionBuffer

from ..base import Category, Detector, Severity, Warning


# Maps raw error strings to a normalized error class
_ERROR_CLASS_PATTERNS = [
    (re.compile(r"SyntaxError", re.IGNORECASE), "SyntaxError"),
    (re.compile(r"IndentationError", re.IGNORECASE), "IndentationError"),
    (re.compile(r"TypeError", re.IGNORECASE), "TypeError"),
    (re.compile(r"ValueError", re.IGNORECASE), "ValueError"),
    (re.compile(r"AttributeError", re.IGNORECASE), "AttributeError"),
    (re.compile(r"KeyError", re.IGNORECASE), "KeyError"),
    (re.compile(r"IndexError", re.IGNORECASE), "IndexError"),
    (re.compile(r"NameError", re.IGNORECASE), "NameError"),
    (re.compile(r"ImportError|ModuleNotFoundError", re.IGNORECASE), "ImportError"),
    (re.compile(r"FileNotFoundError|No such file", re.IGNORECASE), "FileNotFoundError"),
    (re.compile(r"PermissionError|Permission denied", re.IGNORECASE), "PermissionError"),
    (re.compile(r"ConnectionError|ConnectionRefused|ECONNREFUSED", re.IGNORECASE), "ConnectionError"),
    (re.compile(r"TimeoutError|timed?\s*out", re.IGNORECASE), "TimeoutError"),
    (re.compile(r"AssertionError|AssertError", re.IGNORECASE), "AssertionError"),
    (re.compile(r"exit code \d+|exited with|returned? \d+", re.IGNORECASE), "NonZeroExit"),
    (re.compile(r"FAIL|FAILED|failing", re.IGNORECASE), "TestFailure"),
    (re.compile(r"cannot find module|Module not found", re.IGNORECASE), "ModuleNotFound"),
    (re.compile(r"command not found", re.IGNORECASE), "CommandNotFound"),
]


def _classify_error(error_msg: str) -> str:
    """Classify an error message into a broad error class."""
    for pattern, error_class in _ERROR_CLASS_PATTERNS:
        if pattern.search(error_msg):
            return error_class
    return "UnknownError"


class SameOutcomeDetector(Detector):
    """Detects when edits are attempted but the error outcome stays the same.

    The agent edits code, runs a command, gets an error. Edits again differently,
    runs the command, gets the same category of error. The fixes aren't working.
    """

    category = Category.PROGRESS
    name = "same_outcome"
    description = "Different fixes producing the same error"

    def __init__(self, threshold: int = 3, window: int = 25):
        self.threshold = threshold
        self.window = window

    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.window:
            return None

        recent = buffer.last(self.window)

        # Find edit→bash(fail) pairs and classify the errors
        error_classes_after_edits: list[tuple[str, str]] = []  # (error_class, error_msg)
        edits_seen = 0

        for i, action in enumerate(recent):
            if action.is_file_edit:
                edits_seen += 1
                # Look ahead for the next bash failure
                for j in range(i + 1, min(i + 5, len(recent))):
                    if recent[j].is_bash and not recent[j].success and recent[j].error_message:
                        ec = _classify_error(recent[j].error_message)
                        error_classes_after_edits.append((ec, recent[j].error_message))
                        break

        if len(error_classes_after_edits) < self.threshold:
            return None

        # Count error classes
        class_counts = Counter(ec for ec, _ in error_classes_after_edits)
        most_common_class, count = class_counts.most_common(1)[0]

        if count < self.threshold:
            return None

        # Gather example error messages for this class
        examples = [msg for ec, msg in error_classes_after_edits if ec == most_common_class]
        example_msg = examples[-1][:120] if examples else ""

        return Warning(
            category=self.category,
            severity=Severity.HIGH if count >= 5 else Severity.MEDIUM,
            signal="same_outcome",
            message=f"Tried {edits_seen} different edits but keep hitting {most_common_class} ({count}x)",
            suggestion=f"The edits aren't resolving the root cause. Consider stepping back and re-reading the error: \"{example_msg}\"",
            details={
                "error_class": most_common_class,
                "occurrences": count,
                "total_edits": edits_seen,
                "last_error": example_msg,
            },
        )


class FileChurnDetector(Detector):
    """Detects when a single file keeps getting edited without tests passing.

    The agent keeps modifying the same file over and over, but never achieves
    a successful test run in between. The file is being churned.
    """

    category = Category.PROGRESS
    name = "file_churn"
    description = "File edited repeatedly without successful test"

    def __init__(self, threshold: int = 4, window: int = 30):
        self.threshold = threshold
        self.window = window

    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.window:
            return None

        recent = buffer.last(self.window)

        # Track per-file: edits since last successful bash
        file_edit_runs: dict[str, int] = {}  # file -> consecutive edits without success
        last_success_seen = False

        for action in recent:
            if action.is_bash and action.success:
                # Reset all counters — a successful run clears churn
                file_edit_runs.clear()
                last_success_seen = True
            elif action.is_file_edit and action.file_path:
                file_edit_runs[action.file_path] = file_edit_runs.get(action.file_path, 0) + 1

        if not file_edit_runs:
            return None

        # Find the worst offender
        worst_file = max(file_edit_runs, key=file_edit_runs.get)
        worst_count = file_edit_runs[worst_file]

        if worst_count < self.threshold:
            return None

        # Collect the recent errors to show context
        recent_errors = [
            a.error_message for a in recent
            if a.is_bash and not a.success and a.error_message
        ]
        last_error = recent_errors[-1][:120] if recent_errors else None

        return Warning(
            category=self.category,
            severity=Severity.HIGH if worst_count >= 6 else Severity.MEDIUM,
            signal="file_churn",
            message=f"Edited {worst_file} {worst_count}x with no successful test in between",
            suggestion=f"Stop editing and re-read the file from scratch. The repeated edits suggest a misunderstanding of the code."
            + (f" Last error: \"{last_error}\"" if last_error else ""),
            details={
                "file": worst_file,
                "edit_count": worst_count,
                "last_error": last_error,
                "other_churned_files": {
                    f: c for f, c in file_edit_runs.items()
                    if c >= self.threshold and f != worst_file
                },
            },
        )


class ExplorationStallDetector(Detector):
    """Detects when the agent stops exploring new files.

    A healthy agent expands its working set — reads new files, touches new
    modules. A stuck agent narrows: it keeps operating on the same 2-3 files
    while actions accumulate.
    """

    category = Category.PROGRESS
    name = "exploration_stall"
    description = "No new files explored despite continued activity"

    def __init__(self, stale_window: int = 20, min_actions: int = 25):
        self.stale_window = stale_window
        self.min_actions = min_actions

    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.min_actions:
            return None

        all_actions = list(buffer.actions)

        # Split into "earlier" and "recent" halves
        split = len(all_actions) - self.stale_window
        if split < 5:
            return None

        earlier = all_actions[:split]
        recent = all_actions[split:]

        # Files touched in each period
        earlier_files = {a.file_path for a in earlier if a.file_path}
        recent_files = {a.file_path for a in recent if a.file_path}

        if not recent_files:
            return None

        # New files = files in recent that weren't in earlier
        new_files = recent_files - earlier_files

        # If the agent is still exploring, no problem
        if new_files:
            return None

        # No new files in the recent window — check if there's actual activity
        recent_action_count = len(recent)
        recent_edits = sum(1 for a in recent if a.is_file_edit)
        recent_errors = sum(1 for a in recent if not a.success)

        if recent_action_count < 10:
            return None

        stuck_files = sorted(recent_files)[:5]  # Show up to 5

        return Warning(
            category=self.category,
            severity=Severity.MEDIUM if recent_errors < 5 else Severity.HIGH,
            signal="exploration_stall",
            message=f"Last {recent_action_count} actions only touched {len(recent_files)} known file(s), no new files explored",
            suggestion=f"The agent is circling the same files: {', '.join(stuck_files)}. Consider reading related files or taking a different approach entirely.",
            details={
                "recent_action_count": recent_action_count,
                "unique_recent_files": len(recent_files),
                "files": stuck_files,
                "recent_edits": recent_edits,
                "recent_errors": recent_errors,
                "total_known_files": len(earlier_files),
            },
        )


class ErrorClassPersistenceDetector(Detector):
    """Detects when the same class of error persists across many attempts.

    Even though the exact error text changes, the error *type* stays the same.
    e.g., keeps getting TypeError with different messages, or keeps getting
    test failures from the same test suite.
    """

    category = Category.ERRORS
    name = "error_class_persistence"
    description = "Same type of error persisting despite different fixes"

    def __init__(self, threshold: int = 4, window: int = 20, min_edits_between: int = 2):
        self.threshold = threshold
        self.window = window
        self.min_edits_between = min_edits_between

    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.window:
            return None

        recent = buffer.last(self.window)

        # Collect all bash failures with their error classes
        failures: list[tuple[str, str]] = []  # (error_class, raw_message)
        edits_since_last_failure = 0

        for action in recent:
            if action.is_file_edit:
                edits_since_last_failure += 1
            elif action.is_bash and not action.success and action.error_message:
                ec = _classify_error(action.error_message)
                failures.append((ec, action.error_message))
                edits_since_last_failure = 0

        if len(failures) < self.threshold:
            return None

        # Count error classes
        class_counts = Counter(ec for ec, _ in failures)
        most_common_class, count = class_counts.most_common(1)[0]

        if count < self.threshold:
            return None

        # Check that there were edits in between (not just repeated runs)
        total_edits = sum(1 for a in recent if a.is_file_edit)

        if total_edits < self.min_edits_between:
            # This is the trivial "same command repeated" case — let LoopDetector handle it
            return None

        # Collect the different error messages for this class
        error_samples = [msg for ec, msg in failures if ec == most_common_class]
        unique_messages = list(dict.fromkeys(error_samples))[:3]  # Dedupe, keep order, max 3

        return Warning(
            category=self.category,
            severity=Severity.HIGH if count >= 6 else Severity.MEDIUM,
            signal="error_class_persistence",
            message=f"{most_common_class} persisting across {total_edits} edits ({count} failures)",
            suggestion=f"The root cause isn't being addressed. The error type is consistently {most_common_class} — focus on why that specific error class keeps occurring rather than patching symptoms.",
            details={
                "error_class": most_common_class,
                "failure_count": count,
                "total_edits": total_edits,
                "sample_errors": unique_messages,
                "all_error_classes": dict(class_counts),
            },
        )
