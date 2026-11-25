"""Detectors for privilege escalation and dangerous commands."""

from __future__ import annotations

import re

from agentwatch.guard import DESTRUCTIVE_PATTERNS
from agentwatch.parser.models import ActionBuffer
from agentwatch.parser.security_patterns import (
    PRIVILEGE_COMMAND_PATTERNS,
    PRIVILEGE_COMMAND_REGEX,
)

from ..base import Category, SecurityDetector, Severity, Warning
from . import safe_shapes as shapes
from .secret_scanner import redact_truncate


def _worst_command(recent, pattern, severity_of):
    """(severity, action) of the worst matching command in *recent*, the
    earliest one on a tie. Every match is judged: a lowered first match
    must not hide a later one that keeps its severity (all of a detector's
    findings share one dedup key)."""
    best = None
    for action in recent:
        if action.command and pattern.search(action.command):
            severity = severity_of(action.command)
            if best is None or shapes.rank(severity) > shapes.rank(best[0]):
                best = (severity, action)
    return best


class PrivilegeEscalationDetector(SecurityDetector):
    """Detects commands that attempt privilege escalation."""

    category = Category.PRIVILEGE
    name = "privilege_escalation"
    description = "Privilege escalation attempt detected"

    # Sourced from `agentwatch.parser.security_patterns` (Sprint 14) so this
    # detector and `SessionStats.privilege_commands`'s raw counter
    # (`parser/models.py`) share one definition instead of two that could
    # drift apart.
    PRIVILEGE_PATTERNS = PRIVILEGE_COMMAND_PATTERNS

    # Sprint 50: severity lowered only for these shapes, never the match.
    # sudo and every other rule: only text inside a file-writing heredoc
    # with a quoted delimiter (data). chmod: also a plain 3-digit mode.
    _CHMOD_RULE = r"chmod\s+[0-7]*[4567][0-7]*"

    def __init__(self):
        self._pattern = PRIVILEGE_COMMAND_REGEX
        heredoc = shapes.data_judge(heredoc_only=True)
        self._rules = [
            shapes.Rule(
                re.compile(p, re.IGNORECASE),
                shapes.first_of(shapes.chmod_judge, heredoc) if p == self._CHMOD_RULE
                else heredoc,
            )
            for p in self.PRIVILEGE_PATTERNS
        ]
        self._memo = shapes.Memo()

    def severity_of(self, command: str) -> Severity:
        return self._memo.get(command, self._judge)

    def _judge(self, command: str) -> Severity:
        return shapes.evaluate(command, self._rules, Severity.CRITICAL)

    def check(self, buffer: ActionBuffer) -> Warning | None:
        best = _worst_command(buffer.last(10), self._pattern, self.severity_of)
        if best is None:
            return None
        severity, action = best
        return Warning(
            category=self.category,
            severity=severity,
            signal="privilege_escalation",
            message="Privilege escalation command detected",
            details={
                "command": redact_truncate(action.command, 100),  # Truncate for safety
                "tool": action.tool_name,
            },
        )


class DangerousCommandDetector(SecurityDetector):
    """Detects dangerous or destructive commands."""

    category = Category.PRIVILEGE
    name = "dangerous_command"
    description = "Potentially dangerous command detected"

    DANGEROUS_PATTERNS = [
        # Destructive operations, shared with the coach hook's command guard
        *DESTRUCTIVE_PATTERNS,

        # Fork bombs and resource exhaustion
        r":\(\)\{:\|:&\};:",  # Classic fork bomb
        r"while\s+true.*fork",

        # Network dangerous
        r"nc\s+-[el]",  # Netcat listener
        r"ncat\s+-[el]",
        r"socat\s+.*EXEC",

        # Reverse shells
        r"bash\s+-i\s+>&\s*/dev/tcp",
        r"python.*socket.*connect",
        r"/bin/sh\s+-i",

        # History/log manipulation
        r"history\s+-c",
        r">\s*~/.bash_history",
        r"shred.*\.bash_history",
        r"rm.*\.bash_history",

        # Disable security
        r"setenforce\s+0",
        r"iptables\s+-F",
        r"ufw\s+disable",
    ]

    # Sprint 50: severity lowered only for these shapes, never the match.
    # Any rule: text inside a file-writing heredoc (quoted delimiter) or one
    # argument of a data-only command (git commit -m, echo > notes.md): low.
    # rm -rf of /tmp, $TMPDIR or cache dot-dir paths: medium. python ...
    # socket ... connect with no shell segment holding both words: medium.
    _RM_RULES = (r"rm\s+-rf\s+[/~]", r"rm\s+-rf\s+\.")
    _SOCKET_RULE = r"python.*socket.*connect"

    def __init__(self):
        self._pattern = re.compile(
            "|".join(self.DANGEROUS_PATTERNS),
            re.IGNORECASE
        )
        data = shapes.data_judge()
        judges = {
            **{p: shapes.first_of(shapes.rm_judge, data) for p in self._RM_RULES},
            self._SOCKET_RULE: shapes.first_of(shapes.socket_judge, data),
        }
        self._rules = [
            shapes.Rule(re.compile(p, re.IGNORECASE), judges.get(p, data))
            for p in self.DANGEROUS_PATTERNS
        ]
        self._memo = shapes.Memo()

    def severity_of(self, command: str) -> Severity:
        return self._memo.get(command, self._judge)

    def _judge(self, command: str) -> Severity:
        return shapes.evaluate(command, self._rules, Severity.CRITICAL)

    def check(self, buffer: ActionBuffer) -> Warning | None:
        best = _worst_command(buffer.last(10), self._pattern, self.severity_of)
        if best is None:
            return None
        severity, action = best
        return Warning(
            category=self.category,
            severity=severity,
            signal="dangerous_command",
            message="Dangerous command detected",
            details={
                "command": redact_truncate(action.command, 100),
                "tool": action.tool_name,
            },
        )


class MassFileOperationDetector(SecurityDetector):
    """Detects mass file operations that could be destructive."""

    category = Category.PRIVILEGE
    name = "mass_file_operation"
    description = "Mass file operation detected"

    def __init__(self, threshold: int = 10, window: int = 20):
        self.threshold = threshold
        self.window = window
        self._memo = shapes.Memo()

    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.window:
            return None

        recent = buffer.last(self.window)

        # Count file operations
        deletes = 0
        overwrites = 0
        # Sprint 50: medium, not high, when every counted deletion is an rm
        # of temp, cache or build-output paths, or text in data.
        shaped = True

        for action in recent:
            cmd = action.command or ""

            # Count delete operations
            if "rm " in cmd or "unlink" in cmd or "shred" in cmd:
                deletes += 1
                shaped = shaped and self._memo.get(cmd, shapes.safe_delete)

            # Count overwrite operations (> file)
            if action.is_file_edit:
                overwrites += 1

        if deletes >= self.threshold:
            return Warning(
                category=self.category,
                severity=Severity.MEDIUM if shaped else Severity.HIGH,
                signal="mass_delete",
                message=f"Mass file deletion detected ({deletes} operations)",
                details={"delete_count": deletes},
            )

        if overwrites >= self.threshold * 2:  # Higher threshold for edits
            return Warning(
                category=self.category,
                severity=Severity.MEDIUM,
                signal="mass_overwrite",
                message=f"Unusual volume of file modifications ({overwrites})",
                details={"overwrite_count": overwrites},
            )

        return None


class SensitiveDirectoryAccessDetector(SecurityDetector):
    """Detects access to sensitive system directories."""

    category = Category.PRIVILEGE
    name = "sensitive_directory"
    description = "Access to sensitive system directory"

    SENSITIVE_DIRS = [
        r"^/etc/",
        r"^/var/log/",
        r"^/root/",
        r"^/boot/",
        r"^/sys/",
        r"^/proc/",
        r"/\.ssh/",
        r"/\.gnupg/",
        r"/\.config/",
        r"^/usr/local/bin/",
        r"^/usr/bin/",
    ]

    def __init__(self):
        self._pattern = re.compile("|".join(self.SENSITIVE_DIRS))

    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(10)

        for action in recent:
            path = action.file_path or action.command or ""

            if self._pattern.search(path):
                # The fallback is a whole command: mask secrets before any cut.
                path = redact_truncate(path, 200)
                # Write operations are more severe
                severity = Severity.HIGH if action.is_file_edit else Severity.MEDIUM

                return Warning(
                    category=self.category,
                    severity=severity,
                    signal="sensitive_directory",
                    message=f"Access to sensitive directory: {path[:50]}",
                    details={
                        "path": path,
                        "operation": "write" if action.is_file_edit else "read",
                    },
                )

        return None
