"""Real-time secret/credential leak scanner across all action channels."""

from __future__ import annotations

import contextlib
import json
import math
import os
import re
import stat
import tempfile
import time
from collections.abc import Iterator
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

# Connection strings: user and password are bounded and possessive, since
# unbounded each "postgres://" start scans to the end of the text (quadratic
# on long tool output); 256 chars is far beyond any real user/password. The
# host tail stops at "@" and "\" (a raw-JSON escape such as "\n"), so it
# never overlaps the next URL's tail.
_URL_USERINFO = r"[^:\s]{1,256}+:[^@\s]{1,256}+@"
_URL_TAIL = r"[^\s@\\]"

# Neon DB connection string — must be before generic database pattern
_p(r"postgres://" + _URL_USERINFO + _URL_TAIL + r"*neon\.tech", "neondb_connection_string")

# Database connection strings with embedded passwords (generic)
_p(
    r"(?:postgres|mysql|mongodb|redis|amqp)(?:ql)?://" + _URL_USERINFO + _URL_TAIL + "++",
    "database_connection_string",
)

# Private keys
_p(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "private_key")
_p(r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "pgp_private_key")

# Supabase (anon/JWT) — must be before generic JWT
_p(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJpc3[a-zA-Z0-9_\-\.]+", "supabase_jwt_key")

# JWT tokens (generic). Starts only at the beginning of a token-char run: from
# every eyJ inside a long run the scan went to its end (quadratic, #32).
_p(r"(?<![\w-])eyJ[a-zA-Z0-9_-]*+\.eyJ[a-zA-Z0-9_-]*+\.[a-zA-Z0-9_-]*", "jwt_token")

# Generic password assignments
_p(r"(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]", "password_assignment")

# Bearer / token assignments
_p(r"(?:bearer|token)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}", "bearer_token")

# Generic API key assignments
_p(r"(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}", "generic_api_key")

# High-entropy hex/base64 assigned to key-like variable names. The name tail
# stops at the next key word, so each char is scanned from one start only:
# otherwise every key word in a long identifier scanned to its end
# (quadratic, #32). The match starts at the name's last key word.
_KEY_WORD = r"(?:secret|key|token|credential|auth)"
_p(
    _KEY_WORD + rf"[_-]?(?:(?!{_KEY_WORD})\w)*+['\"]?\s*[:=]\s*['\"]?"
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

# Discord Bot. Starts only at the beginning of an alphanumeric run: from every
# M/N inside a long run the scan went to its end (quadratic, #32).
_p(r"(?<![A-Za-z\d])[MN][A-Za-z\d]{23,}+\.[\w-]{6}\.[\w-]{27,}", "discord_bot_token")

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

# Unprefixed secrets recognisable only by their command/header context. The
# named group ``secret`` marks the value: only it is masked/redacted, since
# the match also holds the context (``mysql -u root -p...``) that mask_secret
# would otherwise mistake for the value. A value never starts with ``$``
# (a variable reference) or ``…``/``[`` (an already-masked value).
_SECRET_VALUE = r"(?P<secret>[^\s'\"$…\[][^\s'\"]*)"
_p(r"\b(?:PGPASSWORD|MYSQL_PWD)\s*=\s*['\"]?" + _SECRET_VALUE, "db_password_env")
# curl/mysql as a program word anywhere on a line (error text quotes
# commands mid-line, behind prompts, bash -c, ssh, docker exec, xargs ...),
# but not inside a path, variable or identifier -- except a bin/ directory.
_CMD = r"(?:(?<=/bin/)|(?<![\w/.$-]))"


def _flag_gap(word: str) -> str:
    """1 to 40 whitespace-separated tokens between *word* and its flag.

    At least one: "-p" glued to the word ("mysql-python") is not a flag.

    Stops at shell separators and newlines, and never runs past another
    *word*, not even one glued inside a token ("mysql:mysql:..."): each char
    is then scanned from at most one start, which keeps these patterns
    linear on long tool output (an unbounded or overlapping gap goes
    quadratic). Each token is possessive: otherwise a run of spaces can be
    split between tokens in exponentially many ways.
    """
    token = rf"(?:(?!{_CMD}(?:{word})\b)[^\s;&|(`])*+"
    return rf"\b(?:{token}[^\S\n]++(?!['\"]?(?:{word})\b)){{1,40}}?['\"]?"


_MYSQL = r"mysql(?:dump|admin|import|show|check|sh|binlog)?|mariadb(?:-\w+)?"
# -p is case-sensitive: mysql's -P is the port. find's -perm/-print/-prune/
# -path are not passwords (find / -name mysql -print).
_p(
    _CMD + rf"(?:{_MYSQL})" + _flag_gap(_MYSQL)
    + r"(?-i:-p)(?!(?:erm|rint\w*|rune|ath)\b)['\"]?" + _SECRET_VALUE,
    "cli_password_flag",
)
_p(r"--password=['\"]?" + _SECRET_VALUE, "cli_password_flag")
_p(
    _CMD + r"curl" + _flag_gap("curl")
    + r"(?:-u[\s'\",]*+|--user[\s=,'\"]++)[^\s:'\"]+:" + _SECRET_VALUE,
    "curl_basic_auth",
)
# The scheme is bounded and dot-free for the same reason (dotted schemes
# are rare; "a.a.a..." would otherwise restart a scheme scan at every "a").
# Any scheme except the database ones database_connection_string handles.
_p(
    r"\b(?!(?:postgres|mysql|mongodb|redis|amqp)(?:ql)?://)[a-z][a-z0-9+-]{0,30}://"
    r"[^\s:/@]+:(?P<secret>[^\s@/$…\[][^\s@/]*)@",
    "url_credentials",
)
_p(r"\bbearer\s+(?P<secret>[a-z0-9_\-.=~+/]{20,})", "bearer_header")


# ---------------------------------------------------------------------------
# Placeholder / false-positive filters
# ---------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(
    r"your[_-]?(?:key|token|secret|api|password)|"
    r"example|xxx{3,}|<[\w-]+>|TODO|CHANGEME|"
    r"insert[_-]?(?:key|token|here)|"
    r"placeholder|dummy|test[_-]?(?:key|token|secret)",
    re.IGNORECASE,
)

# Stock/default credentials: a value that is exactly one of these is a
# placeholder or a well-known default, not a leaked secret.
_DEFAULT_CREDENTIALS = frozenset({
    "admin", "pass", "passwd", "password", "postgres", "root", "secret", "mysql",
})

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
    value = match_text
    for sep in ("=", ":"):
        idx = match_text.find(sep)
        if idx != -1:
            value = match_text[idx + 1 :].strip().strip("'\"").strip()
            if len(value) >= 16 and _shannon_entropy(value) < 3.0:
                return True
            break
    return value.lower() in _DEFAULT_CREDENTIALS


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


# A value this long is assumed to be a random token, where the last 4 chars
# are the standard hint for identifying which credential to rotate. Anything
# shorter (typically a human-chosen password) reveals no characters at all.
_MASK_TAIL_MIN_LEN = 20
_MASK_TAIL_CHARS = 4


def mask_secret(match_text: str) -> str:
    """Return a display-safe form of a matched secret.

    Reveals at most the last 4 chars of the secret value, and only when the
    value is >= 20 chars; shorter values reveal nothing but their length.
    The value is the text after ``=``/``:`` (quotes stripped) when present,
    otherwise the whole match -- never the scheme prefix (``ghp_``, ``AKIA``
    ...), which ``secret_type`` already identifies. For a connection-string
    URL the value is its password, never the host tail.
    """
    value = match_text
    url = _URL_PASSWORD_RE.match(match_text)
    if url:
        value = url.group(1)
    else:
        for sep in ("=", ":"):
            idx = match_text.find(sep)
            if idx != -1:
                value = match_text[idx + 1 :].strip().strip("'\"").strip()
                break
    if len(value) >= _MASK_TAIL_MIN_LEN:
        return "…" + value[-_MASK_TAIL_CHARS:]
    return f"[hidden, {len(value)} chars]"


def _match_value(m: re.Match) -> str:
    """The secret part of a match: its ``secret`` group if it has one."""
    return m.group("secret") if "secret" in m.re.groupindex else m.group(0)


def _mask_match(m: re.Match, label: str) -> str:
    """*m*'s text with only its secret value masked.

    Keeps the key name and quotes of an assignment match, so
    ``MYSQL_PWD="..."`` reads ``MYSQL_PWD="[hidden, N chars]"`` rather than
    ``MYSQL_[hidden, N chars]``.
    """
    if "secret" not in m.re.groupindex and label not in _ASSIGNMENT_LABELS:
        return mask_secret(m.group(0))
    start, end = _value_span(m, label)
    return m.string[m.start() : start] + mask_secret(_match_value(m)) + m.string[end : m.end()]


def redact_secrets(text: str) -> str:
    """Replace every ``_SECRET_PATTERNS`` match in *text* with its masked form.

    For free text (e.g. a shell command) that is about to be placed in a
    ``Warning``. Deliberately skips the placeholder/false-positive filter:
    masking a harmless placeholder costs nothing, leaking a real secret the
    heuristic misjudged does. Callers that truncate must redact *first* --
    truncating first can cut a token so the pattern no longer matches.
    """
    for pattern, label in _SECRET_PATTERNS:
        text = pattern.sub(lambda m: _mask_match(m, label), text)
    return text


# Extra chars scanned past the display cut-off so a secret that starts before
# the cut-off still has its full minimum-length match inside the window. The
# longest minimum match in _SECRET_PATTERNS is cloudflare_api_token (176:
# "v1.0-" + 24 hex + "-" + 146 hex); claude_api_key is next at 103.
_REDACT_WINDOW_MARGIN = 256


def redact_truncate(text: str, limit: int) -> str:
    """Return ``redact_secrets(text)[:limit]`` without scanning all of *text*.

    Commands can be megabytes (heredocs), but callers only keep the first
    *limit* chars; redacting a bounded window keeps detectors cheap. A secret
    straddling *limit* is still masked because the window extends
    ``_REDACT_WINDOW_MARGIN`` chars past it.
    """
    return redact_secrets(text[: limit + _REDACT_WINDOW_MARGIN])[:limit]


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
                    m = _first_live_match(pattern, secret_type, text, file_path)
                    if m is None:
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
                            "matched_prefix": mask_secret(_match_value(m)),
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
                m = _first_live_match(pattern, secret_type, text, file_path)
                if m is None:
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
                        matched_prefix=mask_secret(_match_value(m)),
                        severity=_SEVERITY_LABEL.get(severity, "medium"),
                        remediation=_REMEDIATION.get(
                            secret_type,
                            "Remove from file, use env var, rotate if committed to git",
                        ),
                        timestamp=ts_str,
                    )
                )

    return findings


_REDACTED = "[REDACTED]"

# Patterns whose match includes a key name + separator (``password": "...``).
# Only the value after the separator is redacted.
_ASSIGNMENT_LABELS = frozenset({
    "aws_secret_key",
    "password_assignment",
    "bearer_token",
    "generic_api_key",
    "high_entropy_secret",
})
_ASSIGNMENT_PREFIX_RE = re.compile(r"[^:=]*[:=]\s*['\"]?")

# Connection-string patterns: only the password between ``user:`` and ``@``.
_URL_LABELS = frozenset({"neondb_connection_string", "database_connection_string"})
_URL_PASSWORD_RE = re.compile(r"[a-z]+://[^:\s]+:([^@\s]+)@", re.IGNORECASE)


def _value_span(m: re.Match, label: str) -> tuple[int, int]:
    """Return the (start, end) span of the secret value inside a pattern match.

    Detection patterns may include the key name, separator, quotes or a URL
    host. Redacting the whole match would destroy JSON structure, so only the
    value itself is replaced.
    """
    if "secret" in m.re.groupindex:
        return m.span("secret")
    start, end = m.span()
    text = m.group(0)
    if label in _ASSIGNMENT_LABELS:
        prefix = _ASSIGNMENT_PREFIX_RE.match(text)
        if prefix:
            start += prefix.end()
            value = text[prefix.end():]
            end -= len(value) - len(value.rstrip("'\""))
    elif label in _URL_LABELS:
        pw = _URL_PASSWORD_RE.match(text)
        if pw:
            return m.start() + pw.start(1), m.start() + pw.end(1)
    return start, end


def _is_redacted_value(m: re.Match, label: str) -> bool:
    """True if the secret VALUE of this match already holds [REDACTED].

    Only the value span is checked, never the whole match: greedy tails (e.g.
    a DB URL's host part) can swallow an unrelated placeholder while the real
    password in the same match is still there.
    """
    vstart, vend = _value_span(m, label)
    return _REDACTED in m.string[vstart:vend]


def _iter_matches(pattern: re.Pattern, label: str, text: str) -> Iterator[re.Match]:
    """Like ``pattern.finditer(text)``, but resume after a DB URL's password.

    A DB URL's host tail stops only at whitespace, so it can run over the
    next URL: in raw JSON a newline is the two chars ``\\n``, and URLs may be
    glued with ``;``. Resuming after the whole match would skip that URL.
    """
    pos = 0
    while (m := pattern.search(text, pos)) is not None:
        yield m
        pos = _value_span(m, label)[1] if label in _URL_LABELS else m.end()


def _is_placeholder(m: re.Match, label: str, file_path: str | None = None) -> bool:
    """``_is_false_positive`` for a match, judged on the right text.

    For a DB URL that is only its password: a host like ``db.example.com``
    or a ``?application_name=test_key`` tail says nothing about it.
    """
    if label in _URL_LABELS:
        start, end = _value_span(m, label)
        return _is_false_positive(m.string[start:end], file_path)
    return _is_false_positive(_match_value(m), file_path)


def _first_live_match(
    pattern: re.Pattern, label: str, text: str, file_path: str | None = None
) -> re.Match | None:
    """First match of *pattern* in *text* that is neither redacted nor a placeholder.

    Both are skipped here, not by the caller: a placeholder or redacted
    match must not hide a live one later in the same text.
    """
    for m in _iter_matches(pattern, label, text):
        if not _is_redacted_value(m, label) and not _is_placeholder(m, label, file_path):
            return m
    return None


def _redact_text(text: str) -> tuple[str, int]:
    """Redact secret values in *text*. Returns (new_text, real_redaction_count).

    Every pattern is matched against the original text and overlapping value
    spans are merged before anything is replaced: replacing pattern by
    pattern let one replacement hide another value ("sk-proj-...api_key=V"
    became "[REDACTED]_key=V", which no pattern matches).
    """
    spans: list[tuple[int, int]] = []
    for pattern, label in _SECRET_PATTERNS:
        for m in _iter_matches(pattern, label, text):
            # Leave placeholders/test data alone; they are not real redactions.
            if _is_placeholder(m, label):
                continue
            vstart, vend = _value_span(m, label)
            # Skip only values that are exactly the placeholder (idempotent
            # re-runs). A value that merely contains it ("hunter-[REDACTED]!")
            # still gets fully redacted so no fragment of it is left behind.
            if vstart < vend and text[vstart:vend] != _REDACTED:
                spans.append((vstart, vend))
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    pieces: list[str] = []
    pos = 0
    for start, end in merged:
        pieces += [text[pos:start], _REDACTED]
        pos = end
    return "".join(pieces) + text[pos:], len(merged)


def _redact_json_value(obj: Any) -> tuple[Any, int]:
    """Redact secrets inside every string value of a parsed JSON document."""
    if isinstance(obj, str):
        return _redact_text(obj)
    if isinstance(obj, list):
        total = 0
        out_list = []
        for item in obj:
            new_item, n = _redact_json_value(item)
            out_list.append(new_item)
            total += n
        return out_list, total
    if isinstance(obj, dict):
        total = 0
        out_dict = {}
        for k, v in obj.items():
            new_v, n = _redact_json_value(v)
            out_dict[k] = new_v
            total += n
        return out_dict, total
    return obj, 0


_NOT_JSON = object()


def _json_skeleton(text: str) -> Any:
    """Parse *text* and blank out string values, keeping keys and structure.

    Returns ``_NOT_JSON`` if *text* is not valid JSON.
    """
    def _shape(obj: Any) -> Any:
        if isinstance(obj, str):
            return str
        if isinstance(obj, list):
            return [_shape(v) for v in obj]
        if isinstance(obj, dict):
            return {k: _shape(v) for k, v in obj.items()}
        return obj

    try:
        return _shape(json.loads(text))
    except ValueError:
        return _NOT_JSON


def _redact_line(line: str) -> tuple[str, int]:
    """Redact one JSONL line (without its newline).

    Invariant: a line that was valid JSON stays valid JSON with the same keys
    and structure. Redaction is done on the raw text so every other byte is
    preserved; if that would change the JSON structure (e.g. a match spanning
    two string values), fall back to redacting the parsed string values and
    re-serializing that one line.
    """
    new_line, count = _redact_text(line)
    before = _json_skeleton(line)
    if before is _NOT_JSON:
        return (new_line, count) if count else (line, 0)
    if count and _json_skeleton(new_line) != before:
        obj, count = _redact_json_value(json.loads(line))
        return (_dump_json_line(obj, line), count) if count else (line, 0)
    # Some secrets only show once JSON escapes are decoded (a command after
    # "\n" reads "...nmysql -p..." in the raw text). Re-check the decoded
    # values so nothing a finding was reported for is left behind.
    obj, extra = _redact_json_value(json.loads(new_line))
    if extra:
        return _dump_json_line(obj, line), count + extra
    return (new_line, count) if count else (line, 0)


def _dump_json_line(obj: Any, original: str) -> str:
    # ensure_ascii=True keeps lone surrogates (e.g. a JS-truncated emoji
    # "\ud83d") as \u escapes, so the line always encodes as valid UTF-8.
    out = json.dumps(obj, ensure_ascii=True, separators=(",", ":"))
    if original.endswith("\r"):
        out += "\r"  # keep CRLF line endings
    return out


def _atomic_write_bytes(path: Path, data: bytes, mode: int) -> None:
    """Write *data* to *path* via a same-directory temp file + os.replace()."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def redact_log_file(log_path: Path, backups: list[Path] | None = None) -> int:
    """Replace the values of detected secrets in a JSONL log file with [REDACTED].

    Works line-by-line on the raw bytes (decoded with ``surrogateescape`` so
    invalid UTF-8 round-trips exactly). Only the secret value is replaced; key
    names, quotes and every other byte are kept, and valid JSON lines stay
    valid JSON. When anything is redacted, a one-time ``<name>.bak`` copy of the
    original bytes is kept (owner-only permissions, it still holds the secrets)
    and the file is replaced atomically with its original permission mode.

    If *backups* is given and anything was redacted, the ``.bak`` path (new or
    pre-existing) is appended to it so callers can tell the user where the
    unredacted copy lives.

    Returns the number of real (non-false-positive) redactions.
    """
    original = log_path.read_bytes()
    total_replacements = 0
    new_lines: list[str] = []

    for line in original.decode("utf-8", errors="surrogateescape").split("\n"):
        new_line, count = _redact_line(line)
        new_lines.append(new_line)
        total_replacements += count

    if total_replacements > 0:
        mode = stat.S_IMODE(log_path.stat().st_mode)
        backup = log_path.with_name(log_path.name + ".bak")
        if not backup.exists():
            _atomic_write_bytes(backup, original, 0o600)
        data = "\n".join(new_lines).encode("utf-8", errors="surrogateescape")
        _atomic_write_bytes(log_path, data, mode)
        if backups is not None:
            backups.append(backup)

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
