"""Tests for the SecretLeakScanner detector."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from agentwatch.detectors.security.secret_scanner import (
    AuditFinding,
    SecretLeakScanner,
    _is_false_positive,
    _shannon_entropy,
    audit_log_file,
    extract_scannable_content,
    redact_log_file,
)
from agentwatch.parser.models import Action, ActionBuffer, ToolType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_action(
    tool_type: ToolType = ToolType.READ,
    file_path: str | None = None,
    success: bool = True,
    command: str | None = None,
    outgoing_data: str | None = None,
    incoming_message: str | None = None,
    raw: dict | None = None,
    offset_minutes: float = 0,
) -> Action:
    return Action(
        timestamp=datetime(2026, 3, 1, 12, 0) + timedelta(minutes=offset_minutes),
        tool_name=tool_type.value,
        tool_type=tool_type,
        success=success,
        file_path=file_path,
        command=command,
        outgoing_data=outgoing_data,
        incoming_message=incoming_message,
        raw=raw or {},
    )


# ---------------------------------------------------------------------------
# TestExtractScannableContent
# ---------------------------------------------------------------------------

class TestExtractScannableContent:
    """Tests for the content extraction helper across all channels."""

    def test_extracts_outgoing_data(self):
        action = _make_action(outgoing_data="Here is an API key: sk-abc123")
        results = extract_scannable_content(action)
        channels = [ch for _, ch, _ in results]
        assert "model_output" in channels
        text = next(t for t, ch, _ in results if ch == "model_output")
        assert "sk-abc123" in text

    def test_extracts_command(self):
        action = _make_action(
            tool_type=ToolType.BASH,
            command="curl -H 'Authorization: Bearer sk-ant-secret123456789012345'",
        )
        results = extract_scannable_content(action)
        channels = [ch for _, ch, _ in results]
        assert "bash_command" in channels

    def test_extracts_incoming_message(self):
        action = _make_action(incoming_message="Use this key: AKIAI44QH8DHBFNRK3GQ")
        results = extract_scannable_content(action)
        channels = [ch for _, ch, _ in results]
        assert "user_message" in channels

    def test_extracts_write_tool_content(self):
        action = _make_action(
            tool_type=ToolType.WRITE,
            file_path="/app/config.py",
            raw={"input": {"file_path": "/app/config.py", "content": 'API_KEY = "sk-test12345678901234567890"'}},
        )
        results = extract_scannable_content(action)
        channels = [ch for _, ch, _ in results]
        assert "file_write" in channels
        match = next((t, fp) for t, ch, fp in results if ch == "file_write")
        assert match[1] == "/app/config.py"

    def test_extracts_edit_tool_new_string(self):
        action = _make_action(
            tool_type=ToolType.EDIT,
            file_path="/app/config.py",
            raw={"input": {"file_path": "/app/config.py", "new_string": 'password = "hunter2secret"'}},
        )
        results = extract_scannable_content(action)
        channels = [ch for _, ch, _ in results]
        assert "file_write" in channels

    def test_extracts_tool_output_string(self):
        action = _make_action(
            raw={"content": "AKIA1234567890ABCDEF some output"},
        )
        results = extract_scannable_content(action)
        channels = [ch for _, ch, _ in results]
        assert "tool_output" in channels

    def test_extracts_tool_output_blocks(self):
        action = _make_action(
            raw={"content": [{"type": "text", "text": "ghp_abcdefghij1234567890abcdefghijklmn"}]},
        )
        results = extract_scannable_content(action)
        channels = [ch for _, ch, _ in results]
        assert "tool_output" in channels

    def test_empty_action(self):
        action = _make_action()
        results = extract_scannable_content(action)
        assert results == []


# ---------------------------------------------------------------------------
# TestSecretLeakScanner — detection per secret type
# ---------------------------------------------------------------------------

class TestSecretLeakScanner:
    """Core detection tests for the scanner."""

    def _buf_with(self, **kwargs) -> ActionBuffer:
        buf = ActionBuffer()
        buf.add(_make_action(**kwargs))
        return buf

    def test_detects_openai_key(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(outgoing_data="key is sk-abcdefghij1234567890ab")
        w = scanner.check(buf)
        assert w is not None
        assert w.signal == "secret_leak"
        assert w.details["secret_type"] == "openai_api_key"

    def test_detects_anthropic_key(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(outgoing_data="key sk-ant-abcdefghijklmnopqrstuvwx")
        w = scanner.check(buf)
        assert w is not None
        assert w.details["secret_type"] == "anthropic_api_key"

    def test_detects_github_pat(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(outgoing_data="token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        w = scanner.check(buf)
        assert w is not None
        assert w.details["secret_type"] == "github_pat"

    def test_detects_aws_access_key(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(outgoing_data="AKIAI44QH8DHBFNRK3GQ")
        w = scanner.check(buf)
        assert w is not None
        assert w.details["secret_type"] == "aws_access_key"

    def test_detects_google_api_key(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(outgoing_data="AIzaSyA-abcdefghijklmnopqrstuvwxyz12345")
        w = scanner.check(buf)
        assert w is not None
        assert w.details["secret_type"] == "google_api_key"

    def test_detects_slack_token(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(outgoing_data="token xoxb-1234567890-abcdefg")
        w = scanner.check(buf)
        assert w is not None
        assert w.details["secret_type"] == "slack_token"

    def test_detects_stripe_secret(self):
        scanner = SecretLeakScanner()
        # Build at runtime to avoid GitHub push protection
        key = "sk_live_" + "abcdefghij" * 3
        buf = self._buf_with(outgoing_data=key)
        w = scanner.check(buf)
        assert w is not None
        assert w.details["secret_type"] == "stripe_secret_key"

    def test_detects_jwt(self):
        scanner = SecretLeakScanner()
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        buf = self._buf_with(outgoing_data=jwt)
        w = scanner.check(buf)
        assert w is not None
        assert w.details["secret_type"] == "jwt_token"

    def test_detects_private_key(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(
            raw={"input": {"file_path": "/app/id_rsa", "content": "-----BEGIN RSA PRIVATE KEY-----\nMII..."}}
        )
        w = scanner.check(buf)
        assert w is not None
        assert w.details["secret_type"] == "private_key"

    def test_detects_db_connection_string(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(
            raw={"input": {"file_path": "/app/config.py", "content": 'DB = "postgres://admin:s3cret@db.host:5432/mydb"'}}
        )
        w = scanner.check(buf)
        assert w is not None
        assert w.details["secret_type"] == "database_connection_string"

    # -----------------------------------------------------------------------
    # Severity per channel
    # -----------------------------------------------------------------------

    def test_file_write_severity_critical(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(
            tool_type=ToolType.WRITE,
            file_path="/app/config.py",
            raw={"input": {"file_path": "/app/config.py", "content": "sk-abcdefghij1234567890ab"}},
        )
        w = scanner.check(buf)
        assert w is not None
        assert w.severity.value == "critical"
        assert w.details["channel"] == "file_write"

    def test_model_output_severity_critical(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(outgoing_data="sk-abcdefghij1234567890ab")
        w = scanner.check(buf)
        assert w is not None
        assert w.severity.value == "critical"
        assert w.details["channel"] == "model_output"

    def test_bash_command_severity_high(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(
            tool_type=ToolType.BASH,
            command="export KEY=sk-abcdefghij1234567890ab",
        )
        w = scanner.check(buf)
        assert w is not None
        assert w.severity.value == "high"
        assert w.details["channel"] == "bash_command"

    def test_tool_output_severity_medium(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(raw={"content": "AKIAI44QH8DHBFNRK3GQ in output"})
        w = scanner.check(buf)
        assert w is not None
        assert w.severity.value == "medium"
        assert w.details["channel"] == "tool_output"

    def test_user_message_severity_medium(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(incoming_message="Use AKIAI44QH8DHBFNRK3GQ please")
        w = scanner.check(buf)
        assert w is not None
        assert w.severity.value == "medium"
        assert w.details["channel"] == "user_message"

    # -----------------------------------------------------------------------
    # Deduplication
    # -----------------------------------------------------------------------

    def test_dedup_suppresses_repeat(self):
        scanner = SecretLeakScanner()
        action = _make_action(outgoing_data="sk-abcdefghij1234567890ab")
        buf = ActionBuffer()
        buf.add(action)

        w1 = scanner.check(buf)
        assert w1 is not None

        # Same buffer, same content — should be suppressed
        w2 = scanner.check(buf)
        assert w2 is None

    def test_dedup_expires_after_ttl(self):
        scanner = SecretLeakScanner()
        scanner.DEDUP_TTL = 0.1  # Very short TTL for testing
        action = _make_action(outgoing_data="sk-abcdefghij1234567890ab")
        buf = ActionBuffer()
        buf.add(action)

        w1 = scanner.check(buf)
        assert w1 is not None

        # Wait for TTL to expire
        time.sleep(0.15)

        w2 = scanner.check(buf)
        assert w2 is not None

    # -----------------------------------------------------------------------
    # False positive rejection
    # -----------------------------------------------------------------------

    def test_rejects_placeholder(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(outgoing_data="api_key = 'your_key_here_placeholder_12345678901234567890'")
        w = scanner.check(buf)
        assert w is None

    def test_rejects_test_file_path(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(
            raw={
                "input": {
                    "file_path": "tests/test_config.py",
                    "content": 'KEY = "sk-abcdefghij1234567890ab"',
                }
            }
        )
        w = scanner.check(buf)
        assert w is None

    def test_rejects_low_entropy(self):
        # A repeated character string looks like a key pattern but has low entropy
        scanner = SecretLeakScanner()
        buf = self._buf_with(outgoing_data="secret_key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'")
        w = scanner.check(buf)
        assert w is None

    # -----------------------------------------------------------------------
    # Warning details
    # -----------------------------------------------------------------------

    def test_warning_has_remediation(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(outgoing_data="AKIAI44QH8DHBFNRK3GQ")
        w = scanner.check(buf)
        assert w is not None
        assert "remediation" in w.details
        assert "rotate" in w.details["remediation"].lower() or "remove" in w.details["remediation"].lower()

    def test_warning_has_matched_prefix(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(outgoing_data="sk-abcdefghij1234567890abcdefgh")
        w = scanner.check(buf)
        assert w is not None
        assert "matched_prefix" in w.details
        # Should be a truncated prefix, not the full key
        assert w.details["matched_prefix"].endswith("...")

    def test_warning_has_suggestion(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(outgoing_data="AKIAI44QH8DHBFNRK3GQ")
        w = scanner.check(buf)
        assert w is not None
        assert w.suggestion is not None
        assert len(w.suggestion) > 0

    # -----------------------------------------------------------------------
    # Registry integration
    # -----------------------------------------------------------------------

    def test_registered_in_security_detectors(self):
        from agentwatch.detectors.security import get_all_security_detectors
        detectors = get_all_security_detectors()
        names = [d.name for d in detectors]
        assert "secret_leak_scanner" in names

    def test_works_via_registry(self):
        from agentwatch.detectors import create_registry
        registry = create_registry(mode="security")
        buf = ActionBuffer()
        buf.add(_make_action(outgoing_data="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"))
        warnings = registry.check_all(buf)
        secret_warnings = [w for w in warnings if w.signal == "secret_leak"]
        assert len(secret_warnings) > 0

    # -----------------------------------------------------------------------
    # Empty / edge cases
    # -----------------------------------------------------------------------

    def test_empty_buffer(self):
        scanner = SecretLeakScanner()
        buf = ActionBuffer()
        assert scanner.check(buf) is None

    def test_no_secrets_in_clean_content(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(outgoing_data="This is a normal response with no secrets.")
        assert scanner.check(buf) is None


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_zero_for_empty(self):
        assert _shannon_entropy("") == 0.0

    def test_low_for_repeated(self):
        assert _shannon_entropy("aaaaaaaaaa") == 0.0

    def test_high_for_random(self):
        # A string with many distinct characters has high entropy
        assert _shannon_entropy("aB3$xZ9!qW2@") > 3.0


# ---------------------------------------------------------------------------
# False positive helper
# ---------------------------------------------------------------------------

class TestIsFalsePositive:
    def test_placeholder_detected(self):
        assert _is_false_positive("api_key = your_key_here_abcdef1234567890")

    def test_test_path_detected(self):
        assert _is_false_positive("sk-realkey1234567890abcdef", file_path="tests/test_auth.py")

    def test_real_key_not_rejected(self):
        assert not _is_false_positive("sk-proj-aB3xZ9qW2kL5mN8pR1tU4vY7")

    def test_low_entropy_rejected(self):
        assert _is_false_positive("secret = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")


# ---------------------------------------------------------------------------
# WarningsList formatting
# ---------------------------------------------------------------------------

class TestWarningsListFormatting:
    def test_secret_leak_format(self):
        from agentwatch.detectors.base import Category, Severity, Warning
        from agentwatch.ui.app import WarningsList

        w = Warning(
            category=Category.CREDENTIAL,
            severity=Severity.CRITICAL,
            signal="secret_leak",
            message="Secret detected (openai_api_key) in file_write",
            details={
                "secret_type": "openai_api_key",
                "channel": "file_write",
                "file_path": "/app/config.py",
                "matched_prefix": "sk-proj-abc...",
            },
        )
        detail = WarningsList._format_details(w)
        assert "openai_api_key" in detail
        assert "file_write" in detail
        assert "/app/config.py" in detail
        assert "sk-proj-abc..." in detail


# ---------------------------------------------------------------------------
# Helpers for audit tests
# ---------------------------------------------------------------------------

def _write_jsonl(tmp_path: Path, filename: str, lines: list[dict]) -> Path:
    """Write a list of dicts as a JSONL file and return the path."""
    p = tmp_path / filename
    with open(p, "w") as f:
        for obj in lines:
            f.write(json.dumps(obj) + "\n")
    return p


def _make_assistant_line(content_blocks: list[dict], tool_inputs: list[dict] | None = None) -> dict:
    """Create a minimal assistant JSONL line for testing."""
    blocks = list(content_blocks)
    if tool_inputs:
        for ti in tool_inputs:
            blocks.append({
                "type": "tool_use",
                "id": f"tool_{id(ti)}",
                "name": ti.get("name", "Write"),
                "input": ti.get("input", {}),
            })
    return {
        "type": "assistant",
        "message": {
            "id": f"msg_{id(blocks)}",
            "model": "claude-sonnet-4-5-20250929",
            "content": blocks,
            "usage": {"input_tokens": 100, "output_tokens": 50},
        },
    }


def _make_tool_result_line(content: str) -> dict:
    """Create a minimal tool_result JSONL line."""
    return {
        "type": "tool_result",
        "content": content,
    }


# ---------------------------------------------------------------------------
# TestAuditLogFile
# ---------------------------------------------------------------------------

class TestAuditLogFile:
    """Tests for the audit_log_file() function."""

    def test_finds_secret_in_write_tool(self, tmp_path):
        lines = [
            _make_assistant_line([], tool_inputs=[{
                "name": "Write",
                "input": {
                    "file_path": "/app/config.py",
                    "content": 'OPENAI_KEY = "sk-proj-abc123def456ghi789jklmno"',
                },
            }]),
        ]
        p = _write_jsonl(tmp_path, "session1.jsonl", lines)
        findings = audit_log_file(p, project_name="test")
        assert len(findings) >= 1
        types = [f.secret_type for f in findings]
        assert any("openai" in t for t in types)
        assert findings[0].project_name == "test"
        assert findings[0].session_id == "session1"

    def test_finds_secret_in_bash_command(self, tmp_path):
        lines = [
            _make_assistant_line([], tool_inputs=[{
                "name": "Bash",
                "input": {"command": "curl -H 'Authorization: Bearer sk-ant-secret12345678901234567890'"},
            }]),
        ]
        p = _write_jsonl(tmp_path, "session2.jsonl", lines)
        findings = audit_log_file(p, project_name="test")
        assert len(findings) >= 1

    def test_skips_false_positives(self, tmp_path):
        lines = [
            _make_assistant_line([], tool_inputs=[{
                "name": "Write",
                "input": {
                    "file_path": "/app/example.py",
                    "content": 'api_key = "your_key_here_placeholder_12345678901234567890"',
                },
            }]),
        ]
        p = _write_jsonl(tmp_path, "session3.jsonl", lines)
        findings = audit_log_file(p, project_name="test")
        assert len(findings) == 0

    def test_returns_empty_for_clean_log(self, tmp_path):
        lines = [
            _make_assistant_line([{
                "type": "text",
                "text": "Hello, I can help you with that.",
            }]),
        ]
        p = _write_jsonl(tmp_path, "session4.jsonl", lines)
        findings = audit_log_file(p, project_name="test")
        assert findings == []

    def test_deduplicates_same_secret_in_session(self, tmp_path):
        # Same secret type and channel appearing twice in one session
        lines = [
            _make_assistant_line([], tool_inputs=[{
                "name": "Write",
                "input": {
                    "file_path": "/app/config.py",
                    "content": 'KEY = "sk-proj-abc123def456ghi789jklmno"',
                },
            }]),
            _make_assistant_line([], tool_inputs=[{
                "name": "Write",
                "input": {
                    "file_path": "/app/config.py",
                    "content": 'KEY = "sk-proj-abc123def456ghi789jklmno"',
                },
            }]),
        ]
        p = _write_jsonl(tmp_path, "session5.jsonl", lines)
        findings = audit_log_file(p, project_name="test")
        # Should be deduplicated to 1 finding for the same secret_type+channel+file_path
        openai_file_write = [
            f for f in findings
            if "openai" in f.secret_type and f.channel == "file_write"
        ]
        assert len(openai_file_write) == 1

    def test_finding_has_all_fields(self, tmp_path):
        lines = [
            _make_assistant_line([], tool_inputs=[{
                "name": "Write",
                "input": {
                    "file_path": "/app/secrets.py",
                    "content": "AKIAI44QH8DHBFNRK3GQ",
                },
            }]),
        ]
        p = _write_jsonl(tmp_path, "sess.jsonl", lines)
        findings = audit_log_file(p, project_name="myproj")
        assert len(findings) >= 1
        f = findings[0]
        assert f.secret_type == "aws_access_key"
        assert f.channel == "file_write"
        assert f.file_path == "/app/secrets.py"
        assert f.log_file == "sess.jsonl"
        assert f.session_id == "sess"
        assert f.project_name == "myproj"
        assert f.matched_prefix  # non-empty
        assert f.severity in ("critical", "high", "medium")
        assert f.remediation  # non-empty


# ---------------------------------------------------------------------------
# TestNewPatterns — test each newly added provider pattern
# ---------------------------------------------------------------------------

class TestNewPatterns:
    """Tests for the expanded secret pattern set."""

    def _scan(self, text: str) -> str | None:
        """Scan text and return the detected secret_type, or None."""
        scanner = SecretLeakScanner()
        buf = ActionBuffer()
        buf.add(_make_action(outgoing_data=text))
        w = scanner.check(buf)
        return w.details["secret_type"] if w else None

    def test_claude_api_key(self):
        key = "sk-ant-api03-" + "a" * 50 + "B" * 25 + "c1d2e3" + "-" * 5 + "f" * 10
        assert self._scan(key) == "claude_api_key"

    def test_openrouter_api_key(self):
        key = "sk-or-v1-" + "a1b2c3d4e5f6" * 5
        assert self._scan(key) == "openrouter_api_key"

    def test_firecrawl_api_key(self):
        key = "fc-" + "a1b2c3d4" * 5
        assert self._scan(key) == "firecrawl_api_key"

    def test_railway_token(self):
        key = "railway_" + "a1b2c3d4" * 5
        assert self._scan(key) == "railway_token"

    def test_supabase_service_key(self):
        key = "sbp_" + "a1b2c3d4e5" * 5
        assert self._scan(key) == "supabase_service_key"

    def test_supabase_jwt_key(self):
        key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSJ9.abc123"
        assert self._scan(key) == "supabase_jwt_key"

    def test_neondb_api_key(self):
        key = "neondb_" + "a1b2c3d4e5f6g7h8i9j0" + "extra12345"
        assert self._scan(key) == "neondb_api_key"

    def test_neondb_connection_string(self):
        key = "postgres://user:password@ep-cool-name-123456.us-east-2.aws.neon.tech"
        assert self._scan(key) == "neondb_connection_string"

    def test_vercel_token(self):
        key = "vercel_" + "a1b2c3d4e5f6g7h8i9j0" + "extra_chars"
        assert self._scan(key) == "vercel_token"

    def test_netlify_pat(self):
        key = "nfp_" + "a1b2c3d4e5" * 5
        assert self._scan(key) == "netlify_pat"

    def test_twilio_api_key(self):
        key = "SK" + "0a1b2c3d" * 4
        assert self._scan(key) == "twilio_api_key"

    def test_sendgrid_api_key(self):
        key = "SG.abc123def456ghi789jklm.nopqrstuvwxyz012345abcde"
        assert self._scan(key) == "sendgrid_api_key"

    def test_mailgun_api_key(self):
        key = "key-" + "a1b2c3d4" * 4
        assert self._scan(key) == "mailgun_api_key"

    def test_datadog_api_key(self):
        key = "dda" + "a1b2c3d4e5f6g7h8i9j0" + "extra678901"
        assert self._scan(key) == "datadog_api_key"

    def test_huggingface_token(self):
        key = "hf_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7"
        assert self._scan(key) == "huggingface_token"

    def test_replicate_api_key(self):
        key = "r8_" + "a1b2c3d4e5f6g7h8i9j0" * 2
        assert self._scan(key) == "replicate_api_key"

    def test_pinecone_api_key(self):
        key = "pc-" + "a1b2c3d4" * 5
        assert self._scan(key) == "pinecone_api_key"

    def test_discord_bot_token(self):
        # Build at runtime to avoid GitHub push protection
        key = "MTk2MDg0NzY5MzU2MjEx" + "MjU3.G2sPaQ.r7hK9mDpVfA2cE8bN3gJ1qW5tY0uI4oL6"
        assert self._scan(key) == "discord_bot_token"

    def test_doppler_service_token(self):
        key = "dp.st." + "a1b2c3d4e5" * 5
        assert self._scan(key) == "doppler_service_token"

    def test_linear_api_key(self):
        key = "lin_api_" + "a1b2c3d4e5" * 5
        assert self._scan(key) == "linear_api_key"

    def test_npm_token(self):
        key = "npm_" + "a1b2c3d4e5f6" * 4
        assert self._scan(key) == "npm_token"

    def test_pypi_token(self):
        key = "pypi-" + "a1b2c3d4e5f6g7h8"
        assert self._scan(key) == "pypi_token"

    def test_cloudflare_api_token(self):
        key = "v1.0-" + "a" * 24 + "-" + "b" * 150
        assert self._scan(key) == "cloudflare_api_token"


# ---------------------------------------------------------------------------
# TestRedactLogFile
# ---------------------------------------------------------------------------

class TestRedactLogFile:
    """Tests for the redact_log_file() function."""

    def test_redacts_secret_in_file(self, tmp_path):
        secret = "sk-proj-abc123def456ghi789jklmno"
        line = json.dumps({"type": "assistant", "message": {"content": f"Use {secret}"}})
        p = tmp_path / "session.jsonl"
        p.write_text(line + "\n")

        count = redact_log_file(p)
        assert count >= 1

        content = p.read_text()
        assert secret not in content
        assert "[REDACTED]" in content

    def test_redacts_multiple_secrets(self, tmp_path):
        line1 = json.dumps({"data": "key is sk-abcdefghij1234567890ab"})
        line2 = json.dumps({"data": "aws AKIAI44QH8DHBFNRK3GQ here"})
        p = tmp_path / "multi.jsonl"
        p.write_text(line1 + "\n" + line2 + "\n")

        count = redact_log_file(p)
        assert count >= 2

        content = p.read_text()
        assert "sk-abcdefghij1234567890ab" not in content
        assert "AKIAI44QH8DHBFNRK3GQ" not in content

    def test_leaves_clean_file_unchanged(self, tmp_path):
        line = json.dumps({"data": "no secrets here"})
        p = tmp_path / "clean.jsonl"
        p.write_text(line + "\n")

        count = redact_log_file(p)
        assert count == 0

        content = p.read_text()
        assert "[REDACTED]" not in content
        assert "no secrets here" in content

    def test_preserves_jsonl_structure(self, tmp_path):
        secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        obj = {"type": "tool_result", "content": f"token: {secret}"}
        p = tmp_path / "struct.jsonl"
        p.write_text(json.dumps(obj) + "\n")

        redact_log_file(p)

        content = p.read_text().strip()
        parsed = json.loads(content)
        assert parsed["type"] == "tool_result"
        assert "[REDACTED]" in parsed["content"]
        assert secret not in parsed["content"]

    def test_skips_false_positives(self, tmp_path):
        placeholder = "api_key = your_key_here_placeholder_12345678901234567890"
        p = tmp_path / "fp.jsonl"
        p.write_text(json.dumps({"data": placeholder}) + "\n")

        count = redact_log_file(p)
        # The placeholder should survive (false positive not redacted)
        content = p.read_text()
        assert "placeholder" in content

    def test_returns_zero_for_no_secrets(self, tmp_path):
        p = tmp_path / "empty.jsonl"
        p.write_text("{}\n{}\n")
        assert redact_log_file(p) == 0
