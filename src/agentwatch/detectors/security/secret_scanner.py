"""Real-time secret/credential leak scanner across all action channels."""

from __future__ import annotations

import math
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentwatch.parser.models import ActionBuffer

from ..base import Category, SecurityDetector, Severity, Warning

# ---------------------------------------------------------------------------
# Pattern registry — each entry: (compiled regex, secret_type label)
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[re.Pattern, str]] = []


def _p(pattern: str, label: str) -> None:
    _SECRET_PATTERNS.append((re.compile(pattern, re.IGNORECASE), label))


# Anthropic (Claude) — full API key format (must be before generic anthropic)
_p(r"sk-ant-api03-[a-zA-Z0-9\-_]{90,}", "claude_api_key")

# OpenRouter (must be before generic sk- patterns)
_p(r"sk-or-v1-[a-zA-Z0-9]{48,}", "openrouter_api_key")

# OpenAI
_p(r"sk-proj-[a-zA-Z0-9]{20,}", "openai_project_key")
_p(r"sk-[a-zA-Z0-9]{20,}", "openai_api_key")

# Anthropic (generic)
_p(r"sk-ant-[a-zA-Z0-9\-]{20,}", "anthropic_api_key")

# GitHub
_p(r"ghp_[a-zA-Z0-9]{36}", "github_pat")
_p(r"gho_[a-zA-Z0-9]{36}", "github_oauth")
_p(r"ghs_[a-zA-Z0-9]{36}", "github_app_token")
_p(r"github_pat_[a-zA-Z0-9_]{22,}", "github_fine_grained_pat")

# GitLab
_p(r"glpat-[a-zA-Z0-9\-]{20,}", "gitlab_pat")

# AWS
_p(r"AKIA[0-9A-Z]{16}", "aws_access_key")
_p(
    r"(?:aws_secret_access_key|aws_secret)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}",
    "aws_secret_key",
)

# Google Cloud
_p(r"AIza[0-9A-Za-z\-_]{35}", "google_api_key")

# Slack
_p(r"xox[bpors]-[0-9a-zA-Z\-]{10,}", "slack_token")

# Stripe
_p(r"sk_live_[0-9a-zA-Z]{24,}", "stripe_secret_key")
_p(r"pk_live_[0-9a-zA-Z]{24,}", "stripe_publishable_key")

# Neon DB connection string — must be before generic database pattern
_p(r"postgres://[^:\s]+:[^@\s]+@[^\s]*neon\.tech", "neondb_connection_string")

# Database connection strings with embedded passwords (generic)
_p(
    r"(?:postgres|mysql|mongodb|redis|amqp)(?:ql)?://[^:\s]+:[^@\s]+@[^\s]+",
    "database_connection_string",
)

# Private keys
_p(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "private_key")
_p(r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "pgp_private_key")

# Supabase (anon/JWT) — must be before generic JWT
_p(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJpc3[a-zA-Z0-9_\-\.]+", "supabase_jwt_key")

# JWT tokens (generic)
_p(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", "jwt_token")

# Generic password assignments
_p(r"(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]", "password_assignment")

# Bearer / token assignments
_p(r"(?:bearer|token)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}", "bearer_token")

# Generic API key assignments
_p(r"(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}", "generic_api_key")

# High-entropy hex/base64 assigned to key-like variable names
_p(
    r"(?:secret|key|token|credential|auth)[_-]?\w*['\"]?\s*[:=]\s*['\"]?"
    r"[A-Za-z0-9+/=_\-]{32,}",
    "high_entropy_secret",
)

# Firecrawl
_p(r"fc-[a-zA-Z0-9]{32,}", "firecrawl_api_key")

# Railway
_p(r"railway_[a-zA-Z0-9]{32,}", "railway_token")

# Supabase (service key)
_p(r"sbp_[a-zA-Z0-9]{40,}", "supabase_service_key")

# Neon DB (API key)
_p(r"neondb_[a-zA-Z0-9\-_]{20,}", "neondb_api_key")

# Vercel
_p(r"vercel_[a-zA-Z0-9_]{20,}", "vercel_token")

# Netlify
_p(r"nfp_[a-zA-Z0-9]{40,}", "netlify_pat")

# Twilio
_p(r"SK[0-9a-fA-F]{32}", "twilio_api_key")

# SendGrid
_p(r"SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{22,}", "sendgrid_api_key")

# Mailgun
_p(r"key-[a-zA-Z0-9]{32}", "mailgun_api_key")

# Datadog
_p(r"dd[ap][a-zA-Z0-9]{30,}", "datadog_api_key")

# HuggingFace
_p(r"hf_[a-zA-Z0-9]{34,}", "huggingface_token")

# Replicate
_p(r"r8_[a-zA-Z0-9]{36,}", "replicate_api_key")

# Pinecone
_p(r"pc-[a-zA-Z0-9]{32,}", "pinecone_api_key")

# Discord Bot
_p(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}", "discord_bot_token")

# Doppler
_p(r"dp\.st\.[a-zA-Z0-9_\-]{40,}", "doppler_service_token")

# Linear
_p(r"lin_api_[a-zA-Z0-9]{40,}", "linear_api_key")

# npm
_p(r"npm_[a-zA-Z0-9]{36,}", "npm_token")

# PyPI
_p(r"pypi-[a-zA-Z0-9\-_]{16,}", "pypi_token")

# Cloudflare
_p(r"v1\.0-[a-f0-9]{24}-[a-f0-9]{146,}", "cloudflare_api_token")


# ---------------------------------------------------------------------------
# Placeholder / false-positive filters
# ---------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(
    r"your[_-]?(?:key|token|secret|api|password)|"
    r"example|xxx{3,}|<REPLACE>|TODO|CHANGEME|"
    r"insert[_-]?(?:key|token|here)|"
    r"placeholder|dummy|test[_-]?(?:key|token|secret)",
    re.IGNORECASE,
)

_TEST_PATH_RE = re.compile(r"(?:^|/)(?:test_|tests/|fixture|mock|conftest)", re.IGNORECASE)


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_false_positive(match_text: str, file_path: str | None = None) -> bool:
    """Return True if the match is likely a placeholder or test fixture."""
    if _PLACEHOLDER_RE.search(match_text):
        return True
    if file_path and _TEST_PATH_RE.search(file_path):
        return True
    # Low Shannon entropy suggests a pattern like "aaaaaaa..." rather than a real key
    # Extract the value portion (after = or :) for entropy check
    for sep in ("=", ":"):
        idx = match_text.find(sep)
        if idx != -1:
            value = match_text[idx + 1 :].strip().strip("'\"").strip()
            if len(value) >= 16 and _shannon_entropy(value) < 3.0:
                return True
            break
    return False


# ---------------------------------------------------------------------------
# Channel extraction
# ---------------------------------------------------------------------------

def extract_scannable_content(action: Any) -> list[tuple[str, str, str | None]]:
    """Extract (text, channel, file_path) tuples from all channels of an action.

    Returns a list of tuples: (content_text, channel_label, optional_file_path).
    """
    results: list[tuple[str, str, str | None]] = []

    # 1. Model output
    if getattr(action, "outgoing_data", None):
        results.append((action.outgoing_data, "model_output", None))

    # 2. Bash commands
    if getattr(action, "command", None):
        results.append((action.command, "bash_command", None))

    # 3. User / incoming messages
    if getattr(action, "incoming_message", None):
        results.append((action.incoming_message, "user_message", None))

    # 4. Dig into action.raw for Write/Edit tool inputs
    raw = getattr(action, "raw", None) or {}

    # Claude Code logs tool inputs in raw["input"]
    raw_input = raw.get("input", {})
    if isinstance(raw_input, dict):
        # Write tool: content field
        if "content" in raw_input and isinstance(raw_input["content"], str):
            fp = raw_input.get("file_path") or getattr(action, "file_path", None)
            results.append((raw_input["content"], "file_write", fp))
        # Edit tool: new_string / new_str
        for key in ("new_string", "new_str"):
            if key in raw_input and isinstance(raw_input[key], str):
                fp = raw_input.get("file_path") or getattr(action, "file_path", None)
                results.append((raw_input[key], "file_write", fp))

    # 5. Tool result content (bash output, file reads)
    raw_content = raw.get("content")
    if isinstance(raw_content, str) and raw_content:
        results.append((raw_content, "tool_output", getattr(action, "file_path", None)))
    # Also handle list-of-blocks style content
    if isinstance(raw_content, list):
        for block in raw_content:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                results.append((block["text"], "tool_output", getattr(action, "file_path", None)))

    return results


# ---------------------------------------------------------------------------
# Severity mapping per channel
# ---------------------------------------------------------------------------

_CHANNEL_SEVERITY: dict[str, Severity] = {
    "file_write": Severity.CRITICAL,
    "model_output": Severity.CRITICAL,
    "bash_command": Severity.HIGH,
    "tool_output": Severity.MEDIUM,
    "user_message": Severity.MEDIUM,
}

# ---------------------------------------------------------------------------
# Remediation guidance per secret type
# ---------------------------------------------------------------------------

_REMEDIATION: dict[str, str] = {
    "openai_api_key": (
        "Remove from file, use env var OPENAI_API_KEY, rotate key at platform.openai.com"
    ),
    "openai_project_key": "Remove from file, use env var, rotate at platform.openai.com",
    "anthropic_api_key": (
        "Remove from file, use env var ANTHROPIC_API_KEY, rotate at console.anthropic.com"
    ),
    "github_pat": "Remove immediately, rotate at github.com/settings/tokens",
    "github_oauth": "Remove and rotate at GitHub OAuth app settings",
    "github_app_token": "Remove and rotate at GitHub app settings",
    "github_fine_grained_pat": "Remove and rotate at github.com/settings/tokens",
    "gitlab_pat": "Remove and rotate at GitLab access tokens settings",
    "aws_access_key": "Remove from file, use env var or IAM role, rotate in AWS console",
    "aws_secret_key": "Remove from file, use env var or IAM role, rotate in AWS console",
    "google_api_key": "Remove from file, restrict key in Google Cloud Console, rotate",
    "slack_token": "Remove from file, use env var, rotate in Slack app settings",
    "stripe_secret_key": "Remove immediately, rotate at dashboard.stripe.com/apikeys",
    "stripe_publishable_key": "Review exposure scope, rotate at dashboard.stripe.com/apikeys",
    "database_connection_string": (
        "Remove from file, use env var or secret manager for DB credentials"
    ),
    "private_key": "Remove from file, regenerate key pair, never commit private keys",
    "pgp_private_key": "Remove from file, regenerate PGP key pair",
    "jwt_token": "Remove from file, tokens may need regeneration if leaked",
    "password_assignment": "Remove hardcoded password, use env var or secret manager",
    "bearer_token": "Remove from file, rotate token, use env var",
    "generic_api_key": "Remove from file, use env var, rotate if committed to git",
    "high_entropy_secret": "Review value—if a real secret, remove from file and rotate",
    "claude_api_key": (
        "Remove from file, use env var ANTHROPIC_API_KEY, rotate at console.anthropic.com"
    ),
    "openrouter_api_key": "Remove from file, use env var, rotate at openrouter.ai/keys",
    "firecrawl_api_key": "Remove from file, use env var, rotate at firecrawl.dev dashboard",
    "railway_token": "Remove from file, use env var, rotate at railway.app account settings",
    "supabase_service_key": "Remove from file, use env var, rotate in Supabase dashboard",
    "supabase_jwt_key": (
        "Remove from file, use env var, rotate JWT secret in Supabase dashboard"
    ),
    "neondb_api_key": "Remove from file, use env var, rotate at console.neon.tech",
    "neondb_connection_string": "Remove from file, use env var, rotate password in Neon console",
    "vercel_token": "Remove from file, use env var, rotate at vercel.com/account/tokens",
    "netlify_pat": "Remove from file, use env var, rotate at app.netlify.com/user/applications",
    "twilio_api_key": "Remove from file, use env var, rotate at twilio.com/console",
    "sendgrid_api_key": (
        "Remove from file, use env var, rotate at app.sendgrid.com/settings/api_keys"
    ),
    "mailgun_api_key": (
        "Remove from file, use env var, rotate at app.mailgun.com/settings/api_security"
    ),
    "datadog_api_key": (
        "Remove from file, use env var, rotate at "
        "app.datadoghq.com/organization-settings/api-keys"
    ),
    "huggingface_token": (
        "Remove from file, use env var, rotate at huggingface.co/settings/tokens"
    ),
    "replicate_api_key": (
        "Remove from file, use env var, rotate at replicate.com/account/api-tokens"
    ),
    "pinecone_api_key": "Remove from file, use env var, rotate at app.pinecone.io",
    "discord_bot_token": (
        "Remove from file, use env var, regenerate at discord.com/developers/applications"
    ),
    "doppler_service_token": "Remove from file, use env var, rotate at dashboard.doppler.com",
    "linear_api_key": "Remove from file, use env var, rotate at linear.app/settings/api",
    "npm_token": "Remove from file, use env var, rotate at npmjs.com/settings/tokens",
    "pypi_token": "Remove from file, use env var, rotate at pypi.org/manage/account",
    "cloudflare_api_token": (
        "Remove from file, use env var, rotate at dash.cloudflare.com/profile/api-tokens"
    ),
}


def _safe_prefix(match_text: str, max_len: int = 12) -> str:
    """Return a safe partial display of a matched secret."""
    # Find the likely secret value (after = or : or just the match start)
    for sep in ("=", ":"):
        idx = match_text.find(sep)
        if idx != -1:
            value = match_text[idx + 1 :].strip().strip("'\"").strip()
            if len(value) > max_len:
                return value[:max_len] + "..."
            return value
    # Fallback: prefix of the whole match
    if len(match_text) > max_len:
        return match_text[:max_len] + "..."
    return match_text


# ---------------------------------------------------------------------------
# SecretLeakScanner
# ---------------------------------------------------------------------------

class SecretLeakScanner(SecurityDetector):
    """Scans all action channels for leaked secrets/credentials in real time."""

    category = Category.CREDENTIAL
    name = "secret_leak_scanner"
    description = "Real-time scanning for secrets leaked through any channel"

    DEDUP_TTL = 300.0  # 5 minutes

    def __init__(self) -> None:
        # Dedup cache: fingerprint -> timestamp of first alert
        self._seen: dict[str, float] = {}

    def _dedup_key(self, secret_type: str, channel: str, file_path: str | None) -> str:
        return f"{secret_type}:{channel}:{file_path or ''}"

    def _is_seen(self, key: str, now: float) -> bool:
        ts = self._seen.get(key)
        if ts is None:
            return False
        if now - ts > self.DEDUP_TTL:
            del self._seen[key]
            return False
        return True

    def _mark_seen(self, key: str, now: float) -> None:
        self._seen[key] = now

    def _expire_old(self, now: float) -> None:
        """Remove entries older than TTL."""
        expired = [k for k, ts in self._seen.items() if now - ts > self.DEDUP_TTL]
        for k in expired:
            del self._seen[k]

    def check(self, buffer: ActionBuffer) -> Warning | None:
        """Scan recent actions for secret leaks. Returns the highest-severity finding."""
        recent = buffer.last(5)
        if not recent:
            return None

        now = time.time()
        self._expire_old(now)

        best_warning: Warning | None = None
        best_severity_impact = -1

        for action in recent:
            contents = extract_scannable_content(action)
            for text, channel, file_path in contents:
                for pattern, secret_type in _SECRET_PATTERNS:
                    m = pattern.search(text)
                    if m is None:
                        continue

                    match_text = m.group(0)

                    if _is_false_positive(match_text, file_path):
                        continue

                    dedup = self._dedup_key(secret_type, channel, file_path)
                    if self._is_seen(dedup, now):
                        continue

                    self._mark_seen(dedup, now)

                    severity = _CHANNEL_SEVERITY.get(channel, Severity.MEDIUM)
                    tool_name = getattr(action, "tool_name", None) or ""

                    warning = Warning(
                        category=self.category,
                        severity=severity,
                        signal="secret_leak",
                        message=f"Secret detected ({secret_type}) in {channel}",
                        suggestion=_REMEDIATION.get(
                            secret_type,
                            "Remove from file, use env var, rotate if committed to git",
                        ),
                        details={
                            "secret_type": secret_type,
                            "channel": channel,
                            "file_path": file_path,
                            "tool": tool_name,
                            "matched_prefix": _safe_prefix(match_text),
                            "remediation": _REMEDIATION.get(
                                secret_type,
                                "Remove from file, use env var, rotate if committed to git",
                            ),
                        },
                    )

                    if severity.score_impact > best_severity_impact:
                        best_severity_impact = severity.score_impact
                        best_warning = warning

        return best_warning


# ---------------------------------------------------------------------------
# Passive audit — scan existing log files
# ---------------------------------------------------------------------------

_SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
}


@dataclass
class ImpactAssessment:
    """Impact context for a secret finding — populated by assess_impact()."""

    is_active_session: bool = False
    active_pid: int | None = None
    still_in_source: bool = False
    source_line: int | None = None
    env_var_matches: list[str] = field(default_factory=list)


@dataclass
class AuditFinding:
    """A single secret leak found during a passive log audit."""

    secret_type: str
    channel: str
    file_path: str | None
    log_file: str
    session_id: str | None
    project_name: str
    matched_prefix: str
    severity: str
    remediation: str
    timestamp: str | None
    impact: ImpactAssessment | None = None


def audit_log_file(
    log_path: Path,
    *,
    project_name: str = "",
) -> list[AuditFinding]:
    """Scan a single JSONL log file for secret leaks. Returns all findings."""
    from agentwatch.parser import parse_file

    session_id = log_path.stem
    findings: list[AuditFinding] = []
    seen: set[str] = set()  # dedup: (secret_type, channel, file_path) per session

    for action in parse_file(log_path):
        ts = getattr(action, "timestamp", None)
        ts_str = ts.isoformat() if ts else None

        for text, channel, file_path in extract_scannable_content(action):
            for pattern, secret_type in _SECRET_PATTERNS:
                m = pattern.search(text)
                if m is None:
                    continue

                match_text = m.group(0)
                if _is_false_positive(match_text, file_path):
                    continue

                dedup_key = f"{secret_type}:{channel}:{file_path or ''}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                severity = _CHANNEL_SEVERITY.get(channel, Severity.MEDIUM)

                findings.append(
                    AuditFinding(
                        secret_type=secret_type,
                        channel=channel,
                        file_path=file_path,
                        log_file=log_path.name,
                        session_id=session_id,
                        project_name=project_name,
                        matched_prefix=_safe_prefix(match_text),
                        severity=_SEVERITY_LABEL.get(severity, "medium"),
                        remediation=_REMEDIATION.get(
                            secret_type,
                            "Remove from file, use env var, rotate if committed to git",
                        ),
                        timestamp=ts_str,
                    )
                )

    return findings


def redact_log_file(log_path: Path) -> int:
    """Replace all detected secrets in a JSONL log file with [REDACTED].

    Operates line-by-line on the raw text so the JSONL structure is preserved.
    Returns the number of replacements made.
    """
    lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True)
    total_replacements = 0
    new_lines: list[str] = []

    for line in lines:
        new_line = line
        for pattern, _label in _SECRET_PATTERNS:
            # Replace all occurrences of each pattern in this line. Track the
            # actual redaction count ourselves rather than relying on
            # re.subn()'s return value, which counts every regex match --
            # including ones where _redact() recognized a false positive and
            # returned the text unchanged.
            actual_count = 0

            def _redact(m: re.Match) -> str:
                nonlocal actual_count
                matched = m.group(0)
                if _is_false_positive(matched):
                    return matched  # leave placeholders/test data alone
                actual_count += 1
                return "[REDACTED]"

            new_line = pattern.sub(_redact, new_line)
            total_replacements += actual_count
        new_lines.append(new_line)

    if total_replacements > 0:
        log_path.write_text("".join(new_lines), encoding="utf-8")

    return total_replacements


# ---------------------------------------------------------------------------
# Impact assessment helpers
# ---------------------------------------------------------------------------


def _pattern_for_secret_type(secret_type: str) -> re.Pattern | None:
    """Look up compiled regex by label from _SECRET_PATTERNS."""
    for pattern, label in _SECRET_PATTERNS:
        if label == secret_type:
            return pattern
    return None


def _build_active_session_map() -> dict[str, int]:
    """Return {log_filename: pid} for currently running agents."""
    from agentwatch.discovery import find_running_agents

    mapping: dict[str, int] = {}
    for agent in find_running_agents():
        if agent.log_file is not None:
            mapping[agent.log_file.name] = agent.pid
    return mapping


def _check_source_file(
    file_path: str, secret_type: str
) -> tuple[bool, int | None]:
    """Check if the secret pattern still matches in the source file.

    Returns (found, line_number) — line_number is 1-indexed if found.
    """
    pattern = _pattern_for_secret_type(secret_type)
    if pattern is None:
        return False, None

    try:
        source = Path(file_path)
        if not source.is_file():
            return False, None
        text = source.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False, None

    for lineno, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            return True, lineno
    return False, None


def _check_env_vars(secret_type: str) -> list[str]:
    """Return names of env vars whose values match the secret pattern."""
    pattern = _pattern_for_secret_type(secret_type)
    if pattern is None:
        return []

    matches: list[str] = []
    for var_name, var_value in os.environ.items():
        if pattern.search(var_value):
            matches.append(var_name)
    return matches


def assess_impact(
    findings: list[AuditFinding],
    *,
    active_session_map: dict[str, int] | None = None,
) -> None:
    """Populate finding.impact in-place for all findings.

    Pass active_session_map to avoid calling find_running_agents() (useful in tests).
    """
    if active_session_map is None:
        active_session_map = _build_active_session_map()

    for finding in findings:
        impact = ImpactAssessment()

        # Active session check
        pid = active_session_map.get(finding.log_file)
        if pid is not None:
            impact.is_active_session = True
            impact.active_pid = pid

        # Source file check
        if finding.file_path:
            found, lineno = _check_source_file(finding.file_path, finding.secret_type)
            impact.still_in_source = found
            impact.source_line = lineno

        # Environment variable check
        impact.env_var_matches = _check_env_vars(finding.secret_type)

        finding.impact = impact
