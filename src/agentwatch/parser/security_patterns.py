"""Shared raw pattern-matching primitives for security-relevant `Action` fields.

Single source of truth reused by two independent layers that must never
drift apart:

  1. `parser.models.ActionBuffer.add()` -- raw per-action running counters
     (`SessionStats.credential_accesses` / `.privilege_commands` /
     `.network_connections` / `.injection_attempts`; see the design-decision
     comment on `ActionBuffer.add()` for why these are raw-match counts,
     not detector-fired counts).
  2. `detectors.security.{credentials,privilege,injection}` -- the
     threshold-based `Warning`-firing detectors, which apply additional
     windowing/severity logic on top of the same raw signal.

This module is intentionally dependency-free (stdlib `re` only, no imports
from `agentwatch.parser.models` or `agentwatch.detectors`) so it can be
imported from *both* `parser` and `detectors` without an import cycle --
`detectors.security.*` already imports `agentwatch.parser.models`, so
`parser.models` must never import back from `detectors`. Sitting one level
below both, this module lets them share the actual regex definitions
instead of each keeping its own copy that could silently drift apart.

Network activity has no pattern list here -- `Action.is_network` (a plain
property on the dataclass itself, `network_host is not None or
network_port is not None`) is already the single raw signal both
`ActionBuffer.add()` and `detectors/security/network.py` build on, so
there is nothing to centralize.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Credential / secret paths
# ---------------------------------------------------------------------------
# `SENSITIVE_PATHS` / `SENSITIVE_PATH_REGEX` / `is_sensitive_path` moved
# here from `parser/logs.py`, which now imports and re-exports them for
# backward compatibility (existing `from agentwatch.parser.logs import
# is_sensitive_path` call sites keep working unchanged).

SENSITIVE_PATHS = [
    r"\.moltbot/credentials",
    r"\.moltbot/agents/.*/auth-profiles\.json",
    r"\.clawdbot/",
    r"\.aws/credentials",
    r"\.ssh/",
    r"\.gnupg/",
    r"\.env$",
    r"secrets\.json",
    r"\.netrc",
    r"\.npmrc",
    r"\.pypirc",
    r"id_rsa",
    r"id_ed25519",
    r"\.pem$",
    r"\.key$",
]

SENSITIVE_PATH_REGEX = re.compile("|".join(SENSITIVE_PATHS), re.IGNORECASE)


def is_sensitive_path(path: str | None) -> bool:
    """Check if a path matches known sensitive patterns."""
    if not path:
        return False
    return bool(SENSITIVE_PATH_REGEX.search(path))


# Additional credential-like path patterns, from
# `detectors.security.credentials.CredentialAccessDetector` (which now
# imports `CREDENTIAL_EXTRA_PATTERN` from here instead of compiling its own).
CREDENTIAL_EXTRA_PATTERNS = [
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

CREDENTIAL_EXTRA_PATTERN = re.compile("|".join(CREDENTIAL_EXTRA_PATTERNS), re.IGNORECASE)


def is_credential_like_path(path: str | None) -> bool:
    """Raw match: `is_sensitive_path` OR the extra credential-like patterns.

    Mirrors `CredentialAccessDetector._is_sensitive` exactly (same two
    checks, same order) so the raw counter and the detector never disagree.
    """
    if not path:
        return False
    return bool(SENSITIVE_PATH_REGEX.search(path)) or bool(CREDENTIAL_EXTRA_PATTERN.search(path))


# ---------------------------------------------------------------------------
# Privilege escalation / dangerous commands
# ---------------------------------------------------------------------------
# From `detectors.security.privilege.PrivilegeEscalationDetector`, which now
# imports `PRIVILEGE_COMMAND_REGEX` from here instead of compiling its own.

PRIVILEGE_COMMAND_PATTERNS = [
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

PRIVILEGE_COMMAND_REGEX = re.compile("|".join(PRIVILEGE_COMMAND_PATTERNS), re.IGNORECASE)


def is_privilege_command(command: str | None) -> bool:
    """Raw match: does *command* look like a privilege-escalation attempt?"""
    if not command:
        return False
    return bool(PRIVILEGE_COMMAND_REGEX.search(command))


# ---------------------------------------------------------------------------
# Prompt injection
# ---------------------------------------------------------------------------
# From `detectors.security.injection.PromptInjectionDetector`, which now
# imports `INJECTION_REGEX` from here instead of compiling its own. The
# detector's separate `HIGH_CONFIDENCE_PATTERNS` (a subset used only to pick
# CRITICAL vs HIGH/MEDIUM severity) stays local to that detector -- it isn't
# a distinct raw signal, just a confidence tier on top of this one.

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

INJECTION_REGEX = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE | re.MULTILINE)


def is_injection_like(message: str | None) -> bool:
    """Raw match: does *message* contain an injection-pattern phrase?"""
    if not message:
        return False
    return bool(INJECTION_REGEX.search(message))
