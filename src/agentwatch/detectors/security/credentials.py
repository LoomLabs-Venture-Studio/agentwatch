"""Detectors for credential and secret access patterns."""

from __future__ import annotations

import re

from agentwatch.parser.models import ActionBuffer
from agentwatch.parser.security_patterns import (
    CREDENTIAL_EXTRA_PATTERN,
    CREDENTIAL_EXTRA_PATTERNS,
    is_sensitive_path,
)

from ..base import Category, SecurityDetector, Severity, Warning
from . import safe_shapes as shapes

# Sprint 50: a source or docs file whose NAME holds "secret" or "token"
# (secret_scanner.py, token_refresh.py, secrets-management.md) is not a
# credential store. Low only when those two words are the only credential
# patterns that match the whole path, both only in the file name, and no
# real sensitive-path pattern (.env, ~/.ssh, ~/.aws, *.pem ...) matches.
_WORD_ONLY_PATTERNS = ("secret", "token")
_EXTRA_EACH = [(p, re.compile(p, re.IGNORECASE)) for p in CREDENTIAL_EXTRA_PATTERNS]
_SOURCE_DOC_EXTS = frozenset({
    "py", "pyi", "md", "rst", "ts", "tsx", "js", "jsx", "mjs", "cjs", "go", "rs",
    "java", "kt", "rb", "c", "h", "cc", "cpp", "hpp", "cs", "swift", "vue", "svelte",
})


def _word_only_source_path(path: str) -> bool:
    if is_sensitive_path(path):
        return False
    cut = max(path.rfind("/"), path.rfind("\\"))
    folder, name = path[: cut + 1], path[cut + 1 :]
    dot = name.rfind(".")
    if dot <= 0 or name[dot + 1 :].lower() not in _SOURCE_DOC_EXTS:
        return False
    hits = {p for p, rx in _EXTRA_EACH if rx.search(path)}
    if not hits or not hits <= set(_WORD_ONLY_PATTERNS):
        return False
    return not any(rx.search(folder) for _, rx in _EXTRA_EACH)


class CredentialAccessDetector(SecurityDetector):
    """Flags any access to known credential paths."""

    category = Category.CREDENTIAL
    name = "credential_access"
    description = "Agent accessing credential or secret files"

    # Additional patterns beyond the parser's SENSITIVE_PATHS. Sourced from
    # `agentwatch.parser.security_patterns` (Sprint 14) so this detector and
    # `SessionStats.credential_accesses`'s raw counter (`parser/models.py`)
    # share one definition instead of two that could drift apart.
    EXTRA_SENSITIVE_PATTERNS = CREDENTIAL_EXTRA_PATTERNS

    def _is_sensitive(self, path: str) -> bool:
        """Check if path is sensitive."""
        if is_sensitive_path(path):
            return True
        if CREDENTIAL_EXTRA_PATTERN.search(path):
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
                if _word_only_source_path(action.file_path):
                    severity = Severity.LOW

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

    # Sprint 50: lowered (never dropped) when every match in the text is a
    # documented example credential or an obvious dummy (low), or a key
    # BEGIN line with no key body after it (medium). See _match_cap.
    _NAME_ONLY = r"aws[_-]?secret[_-]?access[_-]?key"
    _KEY_HEADERS = (
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    )
    # The value after a bare variable name: AWS_SECRET_ACCESS_KEY=value.
    _NAME_VALUE = re.compile(r"['\"]?[ \t]*[:=][ \t]*['\"]?([A-Za-z0-9/+=]{16,})")
    _ASSIGNED = re.compile(r"[:=]")

    def __init__(self):
        self._pattern = re.compile("|".join(self.SECRET_PATTERNS), re.IGNORECASE)
        self._each = [(p, re.compile(p, re.IGNORECASE)) for p in self.SECRET_PATTERNS]
        self._memo = shapes.Memo()

    def _match_cap(self, rule: str, m: re.Match) -> Severity | None:
        text = m.string
        if rule in self._KEY_HEADERS:
            return Severity.MEDIUM if shapes.key_header_without_body(text, m.end()) else None
        if rule == self._NAME_ONLY:
            named = self._NAME_VALUE.match(text, m.end())
            value = named.group(1) if named else None  # a bare name keeps
        else:
            value = m.group(0)
            sep = self._ASSIGNED.search(value)
            if sep:
                value = value[sep.end():].strip().strip("'\"").strip()
        return Severity.LOW if value and shapes.dummy_secret(value) else None

    def _cap(self, text: str) -> Severity | None:
        """The cap for *text*: the worst over every match of every pattern,
        None (keep) if any one match keeps its severity."""
        if not shapes.analysable(text):
            return None
        caps = []
        for rule, rx in self._each:
            for count, m in enumerate(rx.finditer(text)):
                cap = self._match_cap(rule, m) if count < shapes.MAX_MATCHES else None
                if cap is None:
                    return None
                caps.append(cap)
        return shapes.worst(caps)

    def _finding(self, action) -> tuple[str, Severity] | None:
        """(signal, severity) this action raises on its own, as before:
        output first, else the command."""
        if action.outgoing_data and self._pattern.search(action.outgoing_data):
            return "secret_in_output", shapes.capped(
                Severity.CRITICAL, self._memo.get(action.outgoing_data, self._cap))
        if action.command and self._pattern.search(action.command):
            return "secret_in_command", shapes.capped(
                Severity.HIGH, self._memo.get(action.command, self._cap))
        return None

    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(5)
        found = [(a, f) for a in recent if (f := self._finding(a)) is not None]
        if not found:
            return None
        # The signal is the first match's, as before; its severity is the
        # worst of that signal in the window, so a lowered first match never
        # hides a later real secret (both share the signal's dedup key).
        signal = found[0][1][0]
        action, (_, severity) = found[0]
        for a, (sig, sev) in found[1:]:
            if sig == signal and shapes.rank(sev) > shapes.rank(severity):
                action, severity = a, sev
        if signal == "secret_in_output":
            return Warning(
                category=self.category,
                severity=severity,
                signal="secret_in_output",
                message="Potential secret detected in agent output",
                details={
                    "tool": action.tool_name,
                    "has_network": action.is_network,
                },
            )
        return Warning(
            category=self.category,
            severity=severity,
            signal="secret_in_command",
            message="Potential secret in bash command",
            details={"tool": action.tool_name},
        )


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
