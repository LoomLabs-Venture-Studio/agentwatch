"""Detectors for credential and secret access patterns."""

from __future__ import annotations

import re

from agentwatch.parser.models import ActionBuffer
from agentwatch.parser.logs import is_sensitive_path

from ..base import Category, SecurityDetector, Severity, Warning


class CredentialAccessDetector(SecurityDetector):
    """Flags any access to known credential paths."""
    
    category = Category.CREDENTIAL
    name = "credential_access"
    description = "Agent accessing credential or secret files"
    
    # Additional patterns beyond the parser's SENSITIVE_PATHS
    EXTRA_SENSITIVE_PATTERNS = [
        r"password",
        r"secret",
        r"token",
        r"api[_-]?key",
        r"credentials?\.json",
        r"auth.*\.json",
        r"\.vault",
        r"keychain",
        r"\.kdbx?$",  # KeePass
    ]
    
    def __init__(self):
        self._extra_pattern = re.compile(
            "|".join(self.EXTRA_SENSITIVE_PATTERNS), 
            re.IGNORECASE
        )
    
    def _is_sensitive(self, path: str) -> bool:
        """Check if path is sensitive."""
        if is_sensitive_path(path):
            return True
        if self._extra_pattern.search(path):
            return True
        return False
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(10)
        
        for action in recent:
            if action.file_path and self._is_sensitive(action.file_path):
                severity = Severity.HIGH
                
                # Critical if it's a write operation
                if action.is_file_edit:
                    severity = Severity.CRITICAL
                
                return Warning(
                    category=self.category,
                    severity=severity,
                    signal="credential_access",
                    message=f"Agent accessed sensitive path: {action.file_path}",
                    details={
                        "path": action.file_path,
                        "operation": "write" if action.is_file_edit else "read",
                        "tool": action.tool_name,
                    },
                )
        
        return None


class SecretInOutputDetector(SecurityDetector):
    """Detects potential secrets being output or transmitted."""
    
    category = Category.CREDENTIAL
    name = "secret_in_output"
    description = "Potential secret/credential in agent output"
    
    SECRET_PATTERNS = [
        # API keys (various formats)
        r"(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?[\w-]{20,}",
        r"sk-[a-zA-Z0-9]{20,}",  # OpenAI
        r"sk-ant-[a-zA-Z0-9-]{20,}",  # Anthropic
        r"ghp_[a-zA-Z0-9]{36}",  # GitHub
        r"gho_[a-zA-Z0-9]{36}",  # GitHub OAuth
        r"glpat-[a-zA-Z0-9-]{20,}",  # GitLab
        
        # AWS
        r"AKIA[0-9A-Z]{16}",
        r"aws[_-]?secret[_-]?access[_-]?key",
        
        # Private keys
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        
        # Passwords
        r"(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        
        # Tokens
        r"(?:bearer|token)['\"]?\s*[:=]\s*['\"]?[\w-]{20,}",
        r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",  # JWT
    ]
    
    def __init__(self):
        self._pattern = re.compile("|".join(self.SECRET_PATTERNS), re.IGNORECASE)
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(5)
        
        for action in recent:
            # Check outgoing data
            if action.outgoing_data and self._pattern.search(action.outgoing_data):
                return Warning(
                    category=self.category,
                    severity=Severity.CRITICAL,
                    signal="secret_in_output",
                    message="Potential secret detected in agent output",
                    details={
                        "tool": action.tool_name,
                        "has_network": action.is_network,
                    },
                )
            
            # Check bash commands for secrets
            if action.command and self._pattern.search(action.command):
                return Warning(
                    category=self.category,
                    severity=Severity.HIGH,
                    signal="secret_in_command",
                    message="Potential secret in bash command",
                    details={"tool": action.tool_name},
                )
        
        return None


class CredentialExfiltrationDetector(SecurityDetector):
    """Detects credential access followed by network activity."""
    
    category = Category.CREDENTIAL
    name = "credential_exfil"
    description = "Credential access followed by network activity"
    
    def __init__(self, window: int = 10):
        self.window = window
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < 3:
            return None
        
        recent = buffer.last(self.window)
        
        # Look for pattern: credential access → network activity
        credential_accessed = False
        credential_path = None
        
        for i, action in enumerate(recent):
            if action.file_path and is_sensitive_path(action.file_path):
                credential_accessed = True
                credential_path = action.file_path
            
            # If we've seen credential access and now see network
            if credential_accessed and action.is_network:
                return Warning(
                    category=self.category,
                    severity=Severity.CRITICAL,
                    signal="credential_exfil",
                    message=f"Network activity after credential access: {credential_path}",
                    details={
                        "credential_path": credential_path,
                        "network_host": action.network_host,
                        "network_port": action.network_port,
                    },
                )
        
        return None
