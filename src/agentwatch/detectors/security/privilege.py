"""Detectors for privilege escalation and dangerous commands."""

from __future__ import annotations

import re

from agentwatch.parser.models import ActionBuffer

from ..base import Category, SecurityDetector, Severity, Warning


class PrivilegeEscalationDetector(SecurityDetector):
    """Detects commands that attempt privilege escalation."""
    
    category = Category.PRIVILEGE
    name = "privilege_escalation"
    description = "Privilege escalation attempt detected"
    
    PRIVILEGE_PATTERNS = [
        # Direct privilege escalation
        r"\bsudo\b",
        r"\bsu\s+-",
        r"\bdoas\b",
        r"\bpkexec\b",
        
        # Permission changes
        r"chmod\s+[0-7]*[4567][0-7]*",  # Setuid/setgid bits
        r"chmod\s+\+s",
        r"chown\s+root",
        r"chgrp\s+(?:root|wheel|admin)",
        
        # Capability manipulation
        r"setcap\b",
        r"getcap\b",
        
        # User/group manipulation
        r"useradd\b",
        r"usermod\b",
        r"groupadd\b",
        r"visudo\b",
        
        # System service manipulation
        r"systemctl\s+(?:enable|start|restart)",
        r"service\s+\w+\s+(?:start|restart)",
    ]
    
    def __init__(self):
        self._pattern = re.compile(
            "|".join(self.PRIVILEGE_PATTERNS),
            re.IGNORECASE
        )
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(10)
        
        for action in recent:
            if action.command and self._pattern.search(action.command):
                return Warning(
                    category=self.category,
                    severity=Severity.CRITICAL,
                    signal="privilege_escalation",
                    message=f"Privilege escalation command detected",
                    details={
                        "command": action.command[:100],  # Truncate for safety
                        "tool": action.tool_name,
                    },
                )
        
        return None


class DangerousCommandDetector(SecurityDetector):
    """Detects dangerous or destructive commands."""
    
    category = Category.PRIVILEGE
    name = "dangerous_command"
    description = "Potentially dangerous command detected"
    
    DANGEROUS_PATTERNS = [
        # Destructive operations
        r"rm\s+-rf\s+[/~]",
        r"rm\s+-rf\s+\*",
        r"rm\s+-rf\s+\.",
        r">\s*/dev/sd[a-z]",  # Overwrite disk
        r"mkfs\.",
        r"dd\s+if=.+of=/dev",
        
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
    
    def __init__(self):
        self._pattern = re.compile(
            "|".join(self.DANGEROUS_PATTERNS),
            re.IGNORECASE
        )
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(10)
        
        for action in recent:
            if action.command and self._pattern.search(action.command):
                return Warning(
                    category=self.category,
                    severity=Severity.CRITICAL,
                    signal="dangerous_command",
                    message="Dangerous command detected",
                    details={
                        "command": action.command[:100],
                        "tool": action.tool_name,
                    },
                )
        
        return None


class MassFileOperationDetector(SecurityDetector):
    """Detects mass file operations that could be destructive."""
    
    category = Category.PRIVILEGE
    name = "mass_file_operation"
    description = "Mass file operation detected"
    
    def __init__(self, threshold: int = 10, window: int = 20):
        self.threshold = threshold
        self.window = window
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.window:
            return None
        
        recent = buffer.last(self.window)
        
        # Count file operations
        deletes = 0
        overwrites = 0
        
        for action in recent:
            cmd = action.command or ""
            
            # Count delete operations
            if "rm " in cmd or "unlink" in cmd or "shred" in cmd:
                deletes += 1
            
            # Count overwrite operations (> file)
            if action.is_file_edit:
                overwrites += 1
        
        if deletes >= self.threshold:
            return Warning(
                category=self.category,
                severity=Severity.HIGH,
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
