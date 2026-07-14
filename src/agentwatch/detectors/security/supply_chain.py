"""Detectors for supply chain attacks via skills/plugins."""

from __future__ import annotations

import re

from agentwatch.parser.models import ActionBuffer

from ..base import Category, SecurityDetector, Severity, Warning


class MaliciousSkillDetector(SecurityDetector):
    """Detects potentially malicious skill behavior."""
    
    category = Category.SUPPLY_CHAIN
    name = "malicious_skill"
    description = "Skill exhibiting suspicious behavior"
    
    # Suspicious patterns in skill execution
    SUSPICIOUS_SKILL_PATTERNS = [
        # Network exfiltration
        r"curl.*-d.*\$",
        r"wget.*--post",
        r"nc\s+-",
        
        # Credential access
        r"cat.*\.env",
        r"cat.*credentials",
        r"cat.*secret",
        r"cat.*/etc/passwd",
        
        # Persistence
        r"crontab",
        r"\.bashrc",
        r"\.profile",
        r"\.zshrc",
        r"systemctl.*enable",
        
        # Download and execute
        r"curl.*\|\s*(?:bash|sh)",
        r"wget.*-O.*\|\s*(?:bash|sh)",
        r"eval.*\$\(",
    ]
    
    def __init__(self):
        self._pattern = re.compile(
            "|".join(self.SUSPICIOUS_SKILL_PATTERNS),
            re.IGNORECASE
        )
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(15)
        
        for action in recent:
            # Check if action is from a skill
            if not action.skill_name:
                continue
            
            # Check command for suspicious patterns
            if action.command and self._pattern.search(action.command):
                return Warning(
                    category=self.category,
                    severity=Severity.CRITICAL,
                    signal="malicious_skill",
                    message=f"Skill '{action.skill_name}' executing suspicious command",
                    details={
                        "skill": action.skill_name,
                        "command": action.command[:80],
                    },
                )
            
            # Check for skill accessing sensitive files
            if action.file_path:
                sensitive_patterns = [
                    r"\.env",
                    r"credential",
                    r"secret",
                    r"\.ssh",
                    r"\.aws",
                    r"token",
                    r"password",
                ]
                for pattern in sensitive_patterns:
                    if re.search(pattern, action.file_path, re.IGNORECASE):
                        return Warning(
                            category=self.category,
                            severity=Severity.HIGH,
                            signal="skill_credential_access",
                            message=f"Skill '{action.skill_name}' accessing sensitive file",
                            details={
                                "skill": action.skill_name,
                                "path": action.file_path,
                            },
                        )
        
        return None


class SkillNetworkActivityDetector(SecurityDetector):
    """Detects skills making network requests."""
    
    category = Category.SUPPLY_CHAIN
    name = "skill_network"
    description = "Skill making network requests"
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(20)
        
        for action in recent:
            if action.skill_name and action.is_network:
                return Warning(
                    category=self.category,
                    severity=Severity.MEDIUM,
                    signal="skill_network",
                    message=f"Skill '{action.skill_name}' making network request",
                    details={
                        "skill": action.skill_name,
                        "host": action.network_host,
                        "port": action.network_port,
                    },
                )
        
        return None


class NewSkillExecutionDetector(SecurityDetector):
    """Alerts when a new/unknown skill starts executing."""
    
    category = Category.SUPPLY_CHAIN
    name = "new_skill"
    description = "New skill started executing"
    
    def __init__(self):
        self._known_skills: set[str] = set()
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(10)
        
        for action in recent:
            if action.skill_name and action.skill_name not in self._known_skills:
                # First time seeing this skill
                self._known_skills.add(action.skill_name)
                
                return Warning(
                    category=self.category,
                    severity=Severity.LOW,
                    signal="new_skill",
                    message=f"New skill started: {action.skill_name}",
                    details={"skill": action.skill_name},
                )
        
        return None


class SkillChainDetector(SecurityDetector):
    """Detects suspicious skill chaining (one skill invoking another)."""
    
    category = Category.SUPPLY_CHAIN
    name = "skill_chain"
    description = "Suspicious skill chaining detected"
    
    def __init__(self, window: int = 20):
        self.window = window
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < 5:
            return None
        
        recent = buffer.last(self.window)
        
        # Track skill transitions
        prev_skill = None
        skill_transitions = []
        
        for action in recent:
            if action.skill_name:
                if prev_skill and prev_skill != action.skill_name:
                    skill_transitions.append((prev_skill, action.skill_name))
                prev_skill = action.skill_name
        
        # Alert if many skill transitions (could indicate injection propagation)
        if len(skill_transitions) >= 3:
            return Warning(
                category=self.category,
                severity=Severity.MEDIUM,
                signal="skill_chain",
                message=f"Multiple skill transitions detected ({len(skill_transitions)})",
                details={
                    "transitions": skill_transitions[:5],
                    "count": len(skill_transitions),
                },
            )
        
        return None


class SkillInstallDetector(SecurityDetector):
    """Detects new skill installations."""
    
    category = Category.SUPPLY_CHAIN
    name = "skill_install"
    description = "New skill being installed"
    
    INSTALL_PATTERNS = [
        r"skill.*install",
        r"molthub.*install",
        r"clawdhub.*install",
        r"moltbot.*add.*skill",
        r"clawdbot.*add.*skill",
    ]
    
    def __init__(self):
        self._pattern = re.compile(
            "|".join(self.INSTALL_PATTERNS),
            re.IGNORECASE
        )
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(10)
        
        for action in recent:
            if action.command and self._pattern.search(action.command):
                return Warning(
                    category=self.category,
                    severity=Severity.HIGH,
                    signal="skill_install",
                    message="New skill being installed",
                    details={"command": action.command[:80]},
                )
        
        return None
