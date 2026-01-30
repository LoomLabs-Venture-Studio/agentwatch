"""Detectors for prompt injection attempts."""

from __future__ import annotations

import re

from agentwatch.parser.models import ActionBuffer

from ..base import Category, SecurityDetector, Severity, Warning


class PromptInjectionDetector(SecurityDetector):
    """Heuristic detection of injection attempts in incoming messages."""
    
    category = Category.INJECTION
    name = "prompt_injection"
    description = "Potential prompt injection attempt detected"
    
    # Known injection patterns
    INJECTION_PATTERNS = [
        # Direct instruction override
        r"ignore (?:previous|all|prior|above|your) (?:instructions?|rules?|guidelines?)",
        r"disregard (?:previous|all|prior|your) (?:instructions?|rules?)",
        r"forget (?:everything|all|your) (?:previous|prior)?",
        
        # Role/persona manipulation
        r"you are now",
        r"act as (?:if you were|a)",
        r"pretend (?:you are|to be)",
        r"roleplay as",
        r"new persona",
        r"your new (role|identity|name) is",
        
        # Jailbreak attempts
        r"jailbreak",
        r"DAN mode",
        r"developer mode",
        r"unrestricted mode",
        r"no (?:rules|restrictions|limits)",
        
        # System prompt manipulation
        r"system:\s*",
        r"<\|im_start\|>",  # ChatML injection
        r"<\|system\|>",
        r"\[INST\]",  # Llama format
        r"<<SYS>>",
        r"\[system\]",
        
        # Authority claims
        r"(?:I am|this is) (?:the|your|an?) (?:admin|developer|owner|creator)",
        r"(?:admin|root|sudo) (?:access|mode|privileges?)",
        r"override (?:safety|security|restrictions?)",
        
        # Encoded instructions
        r"base64[:\s]",
        r"decode (?:this|the following)",
        r"execute (?:the following|this) (?:code|command)",
    ]
    
    # Weighted patterns (more likely to be actual attacks)
    HIGH_CONFIDENCE_PATTERNS = [
        r"ignore (?:all )?(?:previous |prior )?instructions",
        r"disregard .{0,20}(?:rules|guidelines|instructions)",
        r"<\|im_start\|>",
        r"jailbreak",
        r"DAN mode",
    ]
    
    def __init__(self):
        self._pattern = re.compile(
            "|".join(self.INJECTION_PATTERNS), 
            re.IGNORECASE | re.MULTILINE
        )
        self._high_confidence = re.compile(
            "|".join(self.HIGH_CONFIDENCE_PATTERNS),
            re.IGNORECASE
        )
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(10)
        
        for action in recent:
            if not action.incoming_message:
                continue
            
            message = action.incoming_message
            
            # Check for high-confidence patterns first
            if self._high_confidence.search(message):
                return Warning(
                    category=self.category,
                    severity=Severity.CRITICAL,
                    signal="prompt_injection",
                    message="High-confidence prompt injection attempt detected",
                    details={
                        "source": "incoming_message",
                        "confidence": "high",
                    },
                )
            
            # Check for general patterns
            matches = self._pattern.findall(message)
            if matches:
                # Multiple pattern matches = higher confidence
                severity = Severity.HIGH if len(matches) > 1 else Severity.MEDIUM
                
                return Warning(
                    category=self.category,
                    severity=severity,
                    signal="prompt_injection",
                    message=f"Possible prompt injection attempt ({len(matches)} pattern match)",
                    details={
                        "source": "incoming_message",
                        "match_count": len(matches),
                        "confidence": "medium",
                    },
                )
        
        return None


class HiddenInstructionDetector(SecurityDetector):
    """Detects hidden instructions in various encodings."""
    
    category = Category.INJECTION
    name = "hidden_instruction"
    description = "Hidden or encoded instructions detected"
    
    # Patterns for hidden content
    HIDDEN_PATTERNS = [
        # Unicode tricks
        r"[\u200b-\u200f\u2060-\u206f]",  # Zero-width characters
        r"[\u2800-\u28ff]{10,}",  # Braille patterns (sometimes used to hide text)
        
        # HTML/XML comments with instructions
        r"<!--.*(?:ignore|execute|run|instruction).*-->",
        
        # Base64 that might contain instructions
        r"(?:aWdub3Jl|ZXhlY3V0ZQ|cnVuIHRoZQ)",  # base64 for ignore, execute, run the
        
        # Markdown hidden content
        r"\[//\]:\s*#",  # Markdown comment
        r"\[hidden\]",
        
        # CSS/Style hiding
        r"display:\s*none",
        r"visibility:\s*hidden",
        r"font-size:\s*0",
        r"color:\s*(?:white|#fff|transparent)",
    ]
    
    def __init__(self):
        self._pattern = re.compile(
            "|".join(self.HIDDEN_PATTERNS),
            re.IGNORECASE
        )
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(10)
        
        for action in recent:
            content = action.incoming_message or ""
            
            # Also check raw data for web content
            if action.raw.get("content"):
                content += str(action.raw.get("content", ""))
            
            if self._pattern.search(content):
                return Warning(
                    category=self.category,
                    severity=Severity.HIGH,
                    signal="hidden_instruction",
                    message="Hidden or encoded content detected",
                    details={"source": action.tool_name},
                )
        
        return None


class IndirectInjectionDetector(SecurityDetector):
    """Detects potential indirect prompt injection from external sources."""
    
    category = Category.INJECTION
    name = "indirect_injection"
    description = "Potential injection from external content"
    
    # Commands that might appear in fetched content
    INSTRUCTION_PATTERNS = [
        r"(?:please |now )?(?:run|execute|perform|do) (?:the following|this)",
        r"(?:you must|you should|you need to) (?:now )?",
        r"important(?:\s+instructions?)?:",
        r"(?:follow these|execute these|perform these) (?:steps|instructions|commands)",
        r"as (?:your|the) (?:next|first) (?:step|action|task)",
    ]
    
    def __init__(self):
        self._pattern = re.compile(
            "|".join(self.INSTRUCTION_PATTERNS),
            re.IGNORECASE
        )
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(10)
        
        for action in recent:
            # Check content from external sources (web, files, etc.)
            if action.tool_type.value in ("read", "browser", "mcp"):
                content = action.raw.get("content") or action.raw.get("output") or ""
                
                if isinstance(content, str) and self._pattern.search(content):
                    return Warning(
                        category=self.category,
                        severity=Severity.MEDIUM,
                        signal="indirect_injection",
                        message=f"Instruction-like content in external source ({action.tool_name})",
                        details={
                            "source_type": action.tool_type.value,
                            "tool": action.tool_name,
                        },
                    )
        
        return None
