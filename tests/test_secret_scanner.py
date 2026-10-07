"""Tests for the SecretLeakScanner detector."""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from agentwatch.detectors.security.secret_scanner import (
    AuditFinding,
    SecretLeakScanner,
    _is_false_positive,
    _pattern_for_secret_type,
    _shannon_entropy,
    assess_impact,
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
            raw={
                "input": {
                    "file_path": "/app/config.py",
                    "content": 'API_KEY = "sk-test12345678901234567890"',
                }
            },
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
            raw={
                "input": {
                    "file_path": "/app/config.py",
                    "new_string": 'password = "hunter2secret"',
                }
            },
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
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        buf = self._buf_with(outgoing_data=jwt)
        w = scanner.check(buf)
        assert w is not None
        assert w.details["secret_type"] == "jwt_token"

    def test_detects_private_key(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(
            raw={
                "input": {
                    "file_path": "/app/id_rsa",
                    "content": "-----BEGIN RSA PRIVATE KEY-----\nMII...",
                }
            }
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
        buf = self._buf_with(
            outgoing_data="api_key = 'your_key_here_placeholder_12345678901234567890'"
        )
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
        buf = self._buf_with(
            outgoing_data="secret_key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
        )
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
        remediation = w.details["remediation"].lower()
        assert "rotate" in remediation or "remove" in remediation

    def test_warning_has_matched_prefix(self):
        scanner = SecretLeakScanner()
        buf = self._buf_with(outgoing_data="sk-abcdefghij1234567890abcdefgh")
        w = scanner.check(buf)
        assert w is not None
        assert "matched_prefix" in w.details
        # Only the last 4 chars of a long token, never the key's prefix
        assert w.details["matched_prefix"] == "…efgh"

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
                "input": {
                    "command": "curl -H 'Authorization: Bearer sk-ant-secret12345678901234567890'"
                },
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
        key = "postgres://user:N3onPw7xQ@ep-cool-name-123456.us-east-2.aws.neon.tech"
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
        # False-positive matches must not be counted as replacements.
        assert count == 0
        # The placeholder should survive (false positive not redacted)
        content = p.read_text()
        assert "placeholder" in content

    def test_returns_zero_for_no_secrets(self, tmp_path):
        p = tmp_path / "empty.jsonl"
        p.write_text("{}\n{}\n")
        assert redact_log_file(p) == 0

    # -- Regression: redaction must not corrupt the log [BUG] ---------------

    def test_password_key_value_stays_valid_json(self, tmp_path):
        p = tmp_path / "pw.jsonl"
        row = {"type": "tool_use", "input": {"password": "Hunter2Pass!x"}}
        p.write_text(json.dumps(row) + "\n")

        assert redact_log_file(p) == 1

        assert p.read_text() == '{"type": "tool_use", "input": {"password": "[REDACTED]"}}\n'

    def test_api_key_key_value_stays_valid_json(self, tmp_path):
        p = tmp_path / "apikey.jsonl"
        p.write_text(json.dumps({"input": {"api_key": "abcdefghij0123456789XYZ"}}) + "\n")

        assert redact_log_file(p) == 1

        assert p.read_text() == '{"input": {"api_key": "[REDACTED]"}}\n'

    def test_token_inside_text_string(self, tmp_path):
        token = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        p = tmp_path / "ghp.jsonl"
        p.write_text(json.dumps({"type": "text", "text": f"export TOKEN={token}"}) + "\n")

        assert redact_log_file(p) == 1

        parsed = json.loads(p.read_text())
        assert parsed == {"type": "text", "text": "export TOKEN=[REDACTED]"}

    def test_db_url_inside_json_string_stays_valid_json(self, tmp_path):
        rows = [
            {"type": "text", "text": "connect postgres://user:s3cretPassw0rd@db.internal/app now"},
            # URL at the very end of a string: greedy host tail must not eat the quote
            {"text": "postgres://admin:Sup3rS3cretPw@db.host/app", "next": "x"},
        ]
        p = tmp_path / "db.jsonl"
        p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

        assert redact_log_file(p) == 2

        lines = p.read_text().splitlines()
        assert json.loads(lines[0]) == {
            "type": "text",
            "text": "connect postgres://user:[REDACTED]@db.internal/app now",
        }
        assert json.loads(lines[1]) == {
            "text": "postgres://admin:[REDACTED]@db.host/app",
            "next": "x",
        }

    def test_match_spanning_json_strings_never_breaks_json(self, tmp_path):
        # The db-URL regex matches across the two string values here. A raw
        # redaction would break the line, so the parsed-JSON fallback is used:
        # the cross-string "match" is not a real secret, the ghp_ token is.
        token = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        line = '{"a":"postgres://u:p1","b":"x@y","c":"' + token + '"}'
        p = tmp_path / "span.jsonl"
        p.write_text(line + "\n")

        assert redact_log_file(p) == 1

        out = p.read_text()
        assert json.loads(out) == {"a": "postgres://u:p1", "b": "x@y", "c": "[REDACTED]"}
        assert token not in out

    def test_preserves_non_utf8_bytes(self, tmp_path):
        clean = b'{"type":"text","text":"caf\xe9 bytes"}\n'
        dirty = b'{"text":"na\xefve sk-abcdefghij1234567890ab \xff"}\n'
        p = tmp_path / "latin1.jsonl"
        p.write_bytes(clean + dirty)

        assert redact_log_file(p) == 1

        assert p.read_bytes() == clean + b'{"text":"na\xefve [REDACTED] \xff"}\n'

    def test_no_secret_file_not_rewritten(self, tmp_path):
        original = b'{"data": "no secrets here"}\n{"x": "caf\xe9"}\n'
        p = tmp_path / "clean.jsonl"
        p.write_bytes(original)
        os.utime(p, (1_000_000_000, 1_000_000_000))

        assert redact_log_file(p) == 0

        assert p.read_bytes() == original
        assert p.stat().st_mtime == 1_000_000_000
        assert not (tmp_path / "clean.jsonl.bak").exists()

    def test_creates_backup_with_original_bytes(self, tmp_path):
        original = (
            json.dumps({"input": {"password": "Hunter2Pass!x"}}).encode()
            + b'\n{"x":"caf\xe9"}\n'
        )
        p = tmp_path / "bak.jsonl"
        p.write_bytes(original)

        redact_log_file(p)

        assert (tmp_path / "bak.jsonl.bak").read_bytes() == original

    def test_does_not_overwrite_existing_backup(self, tmp_path):
        p = tmp_path / "bak2.jsonl"
        p.write_text(json.dumps({"password": "Hunter2Pass!x"}) + "\n")
        bak = tmp_path / "bak2.jsonl.bak"
        bak.write_bytes(b"older backup\n")

        assert redact_log_file(p) == 1

        assert bak.read_bytes() == b"older backup\n"

    @pytest.mark.skipif(
        sys.platform == "win32", reason="POSIX file mode bits are not supported on Windows"
    )
    def test_preserves_file_mode(self, tmp_path):
        p = tmp_path / "mode.jsonl"
        p.write_text(json.dumps({"password": "Hunter2Pass!x"}) + "\n")
        p.chmod(0o640)

        redact_log_file(p)

        assert stat.S_IMODE(p.stat().st_mode) == 0o640

    def test_leaves_no_temp_files(self, tmp_path):
        p = tmp_path / "mode.jsonl"
        p.write_text(json.dumps({"password": "Hunter2Pass!x"}) + "\n")

        redact_log_file(p)

        assert sorted(x.name for x in tmp_path.iterdir()) == ["mode.jsonl", "mode.jsonl.bak"]

    def test_false_positive_not_counted_or_changed(self, tmp_path):
        original = json.dumps({"api_key": "your_key_here_placeholder_12345678901234567890"}) + "\n"
        p = tmp_path / "fp2.jsonl"
        p.write_text(original)

        assert redact_log_file(p) == 0

        assert p.read_text() == original
        assert not (tmp_path / "fp2.jsonl.bak").exists()

    def test_second_run_is_noop(self, tmp_path):
        p = tmp_path / "twice.jsonl"
        p.write_text(json.dumps({"input": {"password": "Hunter2Pass!x"}}) + "\n")

        assert redact_log_file(p) == 1
        after_first = p.read_bytes()

        assert redact_log_file(p) == 0
        assert p.read_bytes() == after_first

    # The db-URL match spans two JSON strings in these lines, forcing the
    # parsed-JSON fallback. Lone surrogate escapes (a JS-truncated emoji) must
    # stay escaped so the output is still valid UTF-8 and valid JSON.
    _GHP = "ghp_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"

    def _fallback_line(self, surrogate: str) -> bytes:
        return (
            '{"input":{"command":"psql postgres://u:p1","description":"ops@corp.io '
            + surrogate + " " + self._GHP + '"}}'
        ).encode()

    def _assert_fallback_ok(self, tmp_path, surrogate: str) -> None:
        p = tmp_path / "sur.jsonl"
        p.write_bytes(self._fallback_line(surrogate) + b"\n")

        assert redact_log_file(p) == 1

        out = p.read_bytes().decode("utf-8")  # strict: must be valid UTF-8
        parsed = json.loads(out)
        assert self._GHP not in out
        assert parsed["input"]["command"] == "psql postgres://u:p1"
        assert parsed["input"]["description"].endswith(" [REDACTED]")

    def test_fallback_keeps_lone_high_surrogate_escaped(self, tmp_path):
        self._assert_fallback_ok(tmp_path, "\\ud83d")

    def test_fallback_keeps_lone_low_surrogate_escaped(self, tmp_path):
        self._assert_fallback_ok(tmp_path, "\\udc80")

    def test_fallback_preserves_crlf(self, tmp_path):
        p = tmp_path / "crlf.jsonl"
        p.write_bytes(self._fallback_line("x") + b"\r\n" + b'{"ok":1}\r\n')

        assert redact_log_file(p) == 1

        lines = p.read_bytes().split(b"\n")
        assert lines[0].endswith(b"\r") and self._GHP.encode() not in lines[0]
        assert lines[1:] == [b'{"ok":1}\r', b""]

    # "Already redacted" must be judged on the secret VALUE only. A DB URL's
    # greedy host tail can swallow an unrelated [REDACTED] (e.g. a ghp_ token
    # redacted by an earlier pattern) while the real password is still there.
    _LIVE_URL = "postgres://admin:RealPw9xQ@db.host/app"

    def _audit_command(self, tmp_path, command: str) -> list:
        p = _write_jsonl(tmp_path, "det.jsonl", [
            _make_assistant_line([], tool_inputs=[{"name": "Bash", "input": {"command": command}}]),
        ])
        return audit_log_file(p)

    def test_already_redacted_values_are_not_detected(self, tmp_path):
        command = "psql postgres://admin:[REDACTED]@db.host/app; password = '[REDACTED]'"
        assert self._audit_command(tmp_path, command) == []

    def test_placeholder_in_url_tail_does_not_hide_password(self, tmp_path):
        findings = self._audit_command(tmp_path, f"psql {self._LIVE_URL}?token=[REDACTED]")
        assert [f.secret_type for f in findings] == ["database_connection_string"]

    def test_live_scanner_ignores_placeholder_only_in_url_tail(self):
        buf = ActionBuffer()
        buf.add(_make_action(
            tool_type=ToolType.BASH, command=f"psql {self._LIVE_URL}?token=[REDACTED]",
        ))
        w = SecretLeakScanner().check(buf)
        assert w is not None
        assert w.details["secret_type"] == "database_connection_string"

    def test_earlier_redacted_url_does_not_hide_later_live_one(self, tmp_path):
        command = f"psql postgres://old:[REDACTED]@h1/x && psql {self._LIVE_URL}"
        assert [f.secret_type for f in self._audit_command(tmp_path, command)] == [
            "database_connection_string"
        ]

        p = tmp_path / "mixed.jsonl"
        p.write_text(json.dumps({"text": command}) + "\n")
        assert redact_log_file(p) == 1
        assert json.loads(p.read_text()) == {
            "text": "psql postgres://old:[REDACTED]@h1/x && psql postgres://admin:[REDACTED]@db.host/app"
        }

    def test_reports_backup_path_to_caller(self, tmp_path):
        p = tmp_path / "out.jsonl"
        p.write_text(json.dumps({"password": "Hunter2Pass!x"}) + "\n")
        clean = tmp_path / "clean2.jsonl"
        clean.write_text('{"data": "nothing"}\n')
        backups: list[Path] = []

        redact_log_file(p, backups=backups)
        redact_log_file(clean, backups=backups)

        assert backups == [tmp_path / "out.jsonl.bak"]


class TestAuditRedactCli:
    """`audit --redact` must tell the user where unredacted .bak backups are."""

    def _setup(
        self,
        tmp_path,
        monkeypatch,
        command: str = "echo sk-proj-abc123def456ghi789jklmno",
        name: str = "sess1",
    ) -> Path:
        project = tmp_path / "projects" / "-tmp-proj"
        project.mkdir(parents=True, exist_ok=True)
        _write_jsonl(project, f"{name}.jsonl", [
            _make_assistant_line([], tool_inputs=[{
                "name": "Bash",
                "input": {"command": command},
            }]),
        ])
        monkeypatch.setattr("agentwatch.cc_stats.CLAUDE_PROJECTS_DIR", tmp_path / "projects")
        return project / f"{name}.jsonl.bak"

    def test_rerun_after_redact_reports_no_findings(self, tmp_path, monkeypatch):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        # Redaction keeps the key / URL around [REDACTED], so these would still
        # match the detection patterns unless treated as already redacted.
        self._setup(
            tmp_path,
            monkeypatch,
            command="psql postgres://admin:S3cr3tPassw0rd@db.host/app; password = 'Hunter2Pass!x'",
        )
        runner = CliRunner()
        first = runner.invoke(cli, ["audit", "--all", "--redact", "--json"])
        assert json.loads(first.stdout)["redacted"] == 2

        second = runner.invoke(cli, ["audit", "--all", "--redact", "--json"])

        assert json.loads(second.stdout)["total_findings"] == 0
        assert second.exit_code == 0

    _GHP = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

    def _redact_then_reaudit(self, log: Path) -> str:
        from click.testing import CliRunner

        from agentwatch.cli import cli

        runner = CliRunner()
        runner.invoke(cli, ["audit", "--all", "--redact", "--json"])
        out = log.read_text()
        assert "RealPw9xQ" not in out
        assert self._GHP not in out

        again = runner.invoke(cli, ["audit", "--all", "--json"])
        assert json.loads(again.stdout)["total_findings"] == 0
        assert again.exit_code == 0
        return out

    def test_url_with_token_in_tail_redacts_password_and_token(self, tmp_path, monkeypatch):
        self._setup(
            tmp_path,
            monkeypatch,
            command=f"psql postgres://admin:RealPw9xQ@db.host/app?token={self._GHP}",
        )
        out = self._redact_then_reaudit(tmp_path / "projects" / "-tmp-proj" / "sess1.jsonl")
        assert "postgres://admin:[REDACTED]@db.host/app?token=[REDACTED]" in out

    def test_url_next_to_token_in_sibling_field_compact(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch)  # creates the project dir + patches
        log = tmp_path / "projects" / "-tmp-proj" / "sess1.jsonl"
        line = _make_assistant_line([], tool_inputs=[{
            "name": "Bash",
            "input": {"command": "psql postgres://admin:RealPw9xQ@db.host/app", "env": self._GHP},
        }])
        log.write_text(json.dumps(line, separators=(",", ":")) + "\n")

        out = self._redact_then_reaudit(log)
        cmd = json.loads(out)["message"]["content"][0]["input"]
        assert cmd == {
            "command": "psql postgres://admin:[REDACTED]@db.host/app",
            "env": "[REDACTED]",
        }

    def test_one_failing_file_does_not_abort_run(self, tmp_path, monkeypatch):
        from click.testing import CliRunner

        from agentwatch.cli import cli
        from agentwatch.detectors.security import secret_scanner

        self._setup(tmp_path, monkeypatch, name="a_bad")
        good_bak = self._setup(tmp_path, monkeypatch, name="b_good")
        real = secret_scanner.redact_log_file

        def flaky(path, backups=None):
            if path.name == "a_bad.jsonl":
                raise UnicodeEncodeError("utf-8", "\ud83d", 0, 1, "surrogates not allowed")
            return real(path, backups=backups)

        monkeypatch.setattr(secret_scanner, "redact_log_file", flaky)
        result = CliRunner().invoke(cli, ["audit", "--all", "--redact", "--json"])

        data = json.loads(result.stdout)
        assert data["redacted"] == 1
        assert data["backups"] == [str(good_bak)]
        assert [e["log_file"] for e in data["redact_errors"]] == [
            str(tmp_path / "projects" / "-tmp-proj" / "a_bad.jsonl")
        ]

    def test_human_output_names_backup(self, tmp_path, monkeypatch):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        bak = self._setup(tmp_path, monkeypatch)
        result = CliRunner().invoke(cli, ["audit", "--all", "--redact"])

        assert bak.exists()
        assert "ORIGINAL (unredacted) secrets" in result.output
        assert str(bak) in result.output

    def test_json_output_lists_backups(self, tmp_path, monkeypatch):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        bak = self._setup(tmp_path, monkeypatch)
        result = CliRunner().invoke(cli, ["audit", "--all", "--redact", "--json"])

        data = json.loads(result.stdout)
        assert data["redacted"] >= 1
        assert data["backups"] == [str(bak)]


# ---------------------------------------------------------------------------
# TestImpactAssessment
# ---------------------------------------------------------------------------

class TestImpactAssessment:
    """Tests for impact assessment helpers and assess_impact()."""

    def _make_finding(
        self,
        secret_type: str = "openai_api_key",
        log_file: str = "session1.jsonl",
        file_path: str | None = "/app/config.py",
    ) -> AuditFinding:
        return AuditFinding(
            secret_type=secret_type,
            channel="file_write",
            file_path=file_path,
            log_file=log_file,
            session_id="session1",
            project_name="test",
            matched_prefix="sk-proj-abc...",
            severity="critical",
            remediation="Remove from file",
            timestamp=None,
        )

    # -- Active session detection --

    def test_active_session_detected(self):
        finding = self._make_finding(log_file="active.jsonl")
        active_map = {"active.jsonl": 54321}
        assess_impact([finding], active_session_map=active_map)
        assert finding.impact is not None
        assert finding.impact.is_active_session is True
        assert finding.impact.active_pid == 54321

    def test_inactive_session(self):
        finding = self._make_finding(log_file="old.jsonl")
        active_map = {"active.jsonl": 54321}
        assess_impact([finding], active_session_map=active_map)
        assert finding.impact is not None
        assert finding.impact.is_active_session is False
        assert finding.impact.active_pid is None

    # -- Source file checks --

    def test_still_in_source(self, tmp_path):
        source = tmp_path / "config.py"
        source.write_text('OPENAI_KEY = "sk-abcdefghij1234567890ab"\n')
        finding = self._make_finding(file_path=str(source))
        assess_impact([finding], active_session_map={})
        assert finding.impact is not None
        assert finding.impact.still_in_source is True
        assert finding.impact.source_line == 1

    def test_not_in_source_when_removed(self, tmp_path):
        source = tmp_path / "config.py"
        source.write_text('OPENAI_KEY = "use-env-var"\n')
        finding = self._make_finding(file_path=str(source))
        assess_impact([finding], active_session_map={})
        assert finding.impact is not None
        assert finding.impact.still_in_source is False

    def test_source_file_missing(self):
        finding = self._make_finding(file_path="/nonexistent/path/config.py")
        assess_impact([finding], active_session_map={})
        assert finding.impact is not None
        assert finding.impact.still_in_source is False

    def test_no_file_path_skips_source_check(self):
        finding = self._make_finding(file_path=None)
        assess_impact([finding], active_session_map={})
        assert finding.impact is not None
        assert finding.impact.still_in_source is False
        assert finding.impact.source_line is None

    # -- Environment variable checks --

    def test_env_var_match(self, monkeypatch):
        monkeypatch.setenv("MY_OPENAI_KEY", "sk-proj-abc123def456ghi789jklmno")
        finding = self._make_finding(secret_type="openai_project_key")
        assess_impact([finding], active_session_map={})
        assert finding.impact is not None
        assert "MY_OPENAI_KEY" in finding.impact.env_var_matches

    def test_env_var_no_match(self, monkeypatch):
        monkeypatch.setenv("SAFE_VAR", "nothing-secret-here")
        finding = self._make_finding()
        assess_impact([finding], active_session_map={})
        assert finding.impact is not None
        assert "SAFE_VAR" not in finding.impact.env_var_matches

    # -- Pattern lookup --

    def test_pattern_lookup_known(self):
        pat = _pattern_for_secret_type("openai_api_key")
        assert pat is not None
        assert pat.search("sk-abcdefghij1234567890ab")

    def test_pattern_lookup_unknown(self):
        assert _pattern_for_secret_type("nonexistent_type") is None


# ---------------------------------------------------------------------------
# matched_prefix masking -- no displayed form may reveal the secret
# ---------------------------------------------------------------------------

_GHP_TOKEN = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
_SHORT_PASSWORD = "Hunter2Pass!"


def _leaks(secret: str, text: str, window: int = 5) -> bool:
    """True if any *window*-char run of *secret* appears in *text*.

    A 5-char window allows the permitted last-4 hint but catches any
    longer fragment, including the scheme prefix (e.g. ``ghp_A``).
    """
    return any(secret[i : i + window] in text for i in range(len(secret) - window + 1))


class TestMatchedPrefixMasking:
    """Regression tests for the matched_prefix plaintext leak [BUG]."""

    def _warning_for(self, outgoing_data: str):
        buf = ActionBuffer()
        buf.add(_make_action(outgoing_data=outgoing_data))
        w = SecretLeakScanner().check(buf)
        assert w is not None
        return w

    def test_short_password_reveals_nothing(self):
        w = self._warning_for(f'password="{_SHORT_PASSWORD}"')
        assert w.details["secret_type"] == "password_assignment"
        assert w.details["matched_prefix"] == "[hidden, 12 chars]"

    def test_short_pwd_reveals_nothing(self):
        w = self._warning_for('pwd = "s3cretpw"')
        assert w.details["matched_prefix"] == "[hidden, 8 chars]"

    def test_long_token_shows_only_last_four(self):
        w = self._warning_for(f"here is my token {_GHP_TOKEN} ok")
        assert w.details["secret_type"] == "github_pat"
        assert w.details["matched_prefix"] == "…Q7r8"

    def test_private_key_header_is_masked(self):
        w = self._warning_for("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        assert w.details["secret_type"] == "private_key"
        assert "BEGIN" not in w.details["matched_prefix"]

    def test_audit_finding_matched_prefix_is_masked(self, tmp_path):
        log = tmp_path / "session.jsonl"
        entry = {
            "type": "assistant",
            "timestamp": "2026-03-01T12:00:00Z",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": f"here: {_GHP_TOKEN}"}],
            },
        }
        log.write_text(json.dumps(entry) + "\n", encoding="utf-8")
        findings = audit_log_file(log)
        assert findings, "fixture should produce at least one finding"
        for f in findings:
            assert not _leaks(_GHP_TOKEN, f.matched_prefix)

    def test_siem_round_trip_contains_no_raw_secret(self, tmp_path):
        from agentwatch.siem import SiemLogger

        path = tmp_path / "siem.jsonl"
        warnings = [
            self._warning_for(f'password="{_SHORT_PASSWORD}"'),
            self._warning_for(f"export GH={_GHP_TOKEN}"),
        ]
        with SiemLogger(path) as siem:
            for w in warnings:
                siem.log_warning(w)

        raw_text = path.read_text(encoding="utf-8")
        lines = [json.loads(line) for line in raw_text.splitlines() if line]
        assert len(lines) == 2
        # Key name is unchanged for downstream consumers.
        assert all("matched_prefix" in line["details"] for line in lines)
        assert _SHORT_PASSWORD not in raw_text
        assert _GHP_TOKEN not in raw_text
        # Fragment check on the decoded form: the raw file escapes the
        # ellipsis as "…", whose trailing "6" would spuriously complete
        # the token's own 5-char tail "6Q7r8".
        decoded = "\n".join(json.dumps(line, ensure_ascii=False) for line in lines)
        assert not _leaks(_SHORT_PASSWORD, decoded)
        assert not _leaks(_GHP_TOKEN, decoded)


# ---------------------------------------------------------------------------
# Issue #26: DB-URL matches must not run on past the password
# ---------------------------------------------------------------------------

class TestDbUrlRunOn:
    def test_newline_escaped_env_redacts_both_passwords_in_raw_line(self, tmp_path):
        # In raw JSONL the .env newline is the two chars "\n", not whitespace,
        # so the first URL's host tail used to swallow the second URL.
        env = (
            "DATABASE_URL=postgres://app:Pr1maryPw9x@db1.internal:5432/app\n"
            "REPLICA_URL=postgres://app:R3plicaPw7q@db2.internal:5432/app\n"
        )
        line = json.dumps({"input": {"file_path": "/app/.env", "content": env}})
        p = tmp_path / "env.jsonl"
        p.write_text(line + "\n")

        assert redact_log_file(p) == 2
        # Redacted in the raw text: every other byte kept, no re-serialization.
        assert p.read_text() == (
            line.replace("Pr1maryPw9x", "[REDACTED]").replace("R3plicaPw7q", "[REDACTED]")
            + "\n"
        )
        assert redact_log_file(p) == 0

    _GLUED = "x=postgres://x:[REDACTED]@h;y=postgres://admin:LivePw5Zk@db2.host/app"

    def test_placeholder_glued_to_live_url_is_detected(self, tmp_path):
        bash = {"name": "Bash", "input": {"command": self._GLUED}}
        p = _write_jsonl(tmp_path, "glued.jsonl", [_make_assistant_line([], tool_inputs=[bash])])
        assert [f.secret_type for f in audit_log_file(p)] == ["database_connection_string"]

        buf = ActionBuffer()
        buf.add(_make_action(tool_type=ToolType.BASH, command=self._GLUED))
        w = SecretLeakScanner().check(buf)
        assert w is not None and w.details["secret_type"] == "database_connection_string"

    def test_placeholder_glued_to_live_url_is_redacted(self, tmp_path):
        p = tmp_path / "glued.jsonl"
        p.write_text(json.dumps({"command": self._GLUED}) + "\n")

        assert redact_log_file(p) == 1
        assert json.loads(p.read_text()) == {
            "command": "x=postgres://x:[REDACTED]@h;y=postgres://admin:[REDACTED]@db2.host/app"
        }
        assert redact_log_file(p) == 0


def test_glued_secrets_all_redacted():
    # Issue #26 part 3: the token pattern swallows "api"; redacting it first
    # left "[REDACTED]_key=VALUE", which no pattern matches any more.
    from agentwatch.detectors.security.secret_scanner import _redact_text

    value = "Zq8Wm3Xr7Tn2Lp5Vb9Kc4Hd6"  # 24 chars: only generic_api_key matches
    text = f"echo sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8t6api_key={value}"
    assert _redact_text(text) == ("echo [REDACTED]_key=[REDACTED]", 2)


@pytest.mark.parametrize(
    "url,expected",
    [
        # A 1-char host used to make "last 4" of "//u:Pw12345678@x" read "…78@x".
        ("postgres://u:Pw12345678@x", "[hidden, 10 chars]"),
        ("mysql://root:S3cretPw@db.internal:3306/app", "[hidden, 8 chars]"),
        ("postgres://u:Ab3dEf6hIj9kLm2nOp5qRs8t@h/db", "…Rs8t"),  # 24-char password
    ],
)
def test_db_url_mask_reveals_only_from_password(url, expected):
    # Issue #24 part 4a: the reveal comes from the password, not the URL tail.
    from agentwatch.detectors.security.secret_scanner import mask_secret

    assert mask_secret(url) == expected
    buf = ActionBuffer()
    buf.add(_make_action(tool_type=ToolType.BASH, command=f"psql {url}"))
    w = SecretLeakScanner().check(buf)
    assert w is not None and w.details["matched_prefix"] == expected


# ---------------------------------------------------------------------------
# Issue #26 oracle: every value the scanner flags is gone after one redaction
# ---------------------------------------------------------------------------

_ORACLE_GHP = "ghp_Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8"
_ORACLE_CORPUS = [
    # (tool input, as written by the agent)
    {"file_path": "/app/.env", "content": (
        "DATABASE_URL=postgres://app:Pr1maryPw9x@db1.internal:5432/app\n"
        "REPLICA_URL=postgres://app:R3plicaPw7q@db2.internal:5432/app\n")},
    {"command": "x=postgres://x:[REDACTED]@h;y=postgres://admin:LivePw5Zk@db2.host/app"},
    {"command": "echo sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8t6api_key=Zq8Wm3Xr7Tn2Lp5Vb9Kc4Hd6"},
    {"command": f"psql postgres://admin:TailPw9xQ@db.host/app?token={_ORACLE_GHP}"},
    {"command": "psql postgres://old:[REDACTED]@h1/x && psql postgres://admin:LaterPw3c@h2/app"},
    {"command": "mysql://root:MyPw7Zk2q@db1/app;mysql://root:MyPw8Zk3r@db2/app"},
    {"file_path": "/app/.env", "content": (
        "A=postgres://u:NeonPw4Xy7@ep-x.us-east-2.aws.neon.tech/db\n"
        "B=postgres://u:NeonPw5Zq8@ep-y.neon.tech/db\n")},
    # A literal backslash-n inside the decoded command (JSON in a shell string).
    {"command": "echo '{\"a\":\"postgres://u:EscPw1Aa9@h1/x\\nB=postgres://u:EscPw2Bb8@h2/y\"}'"},
    {"command": "PGPASSWORD=PgEnvPw7Hq psql -h db -U app"},
    {"command": 'MYSQL_PWD="MyEnvPw3Lz" mysql -u root'},
    {"command": "mysql -uroot -p'QuotedPw5t' db"},
    {"command": "cd /srv\nmysql -u root -pNewlinePw4 db"},
    {"command": "mysql --host=mysql-primary -u root -pHostGlu9e db"},
    {"command": "curl -s -u admin:CurlPw8Rk https://api.internal/v1"},
    {"command": "git clone https://deploy:a8F3kQ9zL2mX7wP4tR6vB1nY5cH0@github.com/org/repo.git"},
    {"command": "curl -H 'Authorization: Bearer b9G4lR0aM3nY8xQ5uS7wC2oZ6dI1' https://x"},
    {"command": "export GH=" + _ORACLE_GHP + "; password = 'Hunter2Pass!x'"},
    # A placeholder URL before a live one (QA round 2 of #26).
    {"file_path": "/app/.env", "content": (
        "TEST_URL=postgres://<user>:<password>@localhost/app\n"
        "DATABASE_URL=postgres://admin:AfterPh7Lq@prod.db/app\n")},
    # Placeholder-looking text outside the password (QA round 2 of #26).
    {"command": "psql postgres://admin:ExHostPw8m@db.example.com/app"},
    {"command": "psql postgres://admin:TailKeyPw6@db.host/app?application_name=test_key"},
    # Tokens that start with the program word (QA round 2 of #26).
    {"command": "mysql -u root -h mysql01 -pGapPw1Aq7"},
    {"command": "mysql -u root -h mysqldb.prod -pGapPw2Bw6"},
    {"command": "mysql -u mysqluser -pGapPw3Ce5 app"},
    {"command": "mysql --host=mysql_primary -u app -pGapPw4Dr4"},
    {"command": "curl -H 'X: curlbot' -u admin:GapPw5Et3 https://x"},
    {"command": "curl --url curlhost -u admin:GapPw6Fy2"},
]
# Every secret planted above, so the oracle can't pass just because the
# scanner never saw one (a run-on URL hid its neighbour from detection too).
_ORACLE_PLANTED = [
    "Pr1maryPw9x", "R3plicaPw7q", "LivePw5Zk", "Zq8Wm3Xr7Tn2Lp5Vb9Kc4Hd6", _ORACLE_GHP,
    "TailPw9xQ", "LaterPw3c", "MyPw7Zk2q", "MyPw8Zk3r", "NeonPw4Xy7", "NeonPw5Zq8",
    "EscPw1Aa9", "EscPw2Bb8", "PgEnvPw7Hq", "MyEnvPw3Lz", "QuotedPw5t", "NewlinePw4",
    "HostGlu9e", "CurlPw8Rk", "a8F3kQ9zL2mX7wP4tR6vB1nY5cH0", "b9G4lR0aM3nY8xQ5uS7wC2oZ6dI1",
    "Hunter2Pass!x", "GapPw1Aq7", "GapPw2Bw6", "GapPw3Ce5", "GapPw4Dr4", "GapPw5Et3",
    "GapPw6Fy2", "AfterPh7Lq", "ExHostPw8m", "TailKeyPw6",
]


def _flagged_values(log: Path) -> set[str]:
    """Every live, non-placeholder value any pattern flags in *log*.

    Uses only scanner names that exist before #26 too (falling back to plain
    finditer), so on old code the oracle fails on assertions, not imports.
    """
    from agentwatch.detectors.security import secret_scanner as sc
    from agentwatch.parser import parse_file

    iter_matches = getattr(sc, "_iter_matches", lambda p, _label, t: p.finditer(t))
    is_placeholder = getattr(
        sc, "_is_placeholder", lambda m, _label, fp: _is_false_positive(sc._match_value(m), fp)
    )
    values = set()
    for action in parse_file(log):
        for text, _, file_path in extract_scannable_content(action):
            for pattern, label in sc._SECRET_PATTERNS:
                for m in iter_matches(pattern, label, text):
                    if sc._is_redacted_value(m, label):
                        continue
                    if is_placeholder(m, label, file_path):
                        continue
                    start, end = sc._value_span(m, label)
                    values.add(text[start:end])
    return values


@pytest.mark.parametrize("tool_input", _ORACLE_CORPUS)
def test_redaction_oracle(tmp_path, tool_input):
    name = "Write" if "content" in tool_input else "Bash"
    log = _write_jsonl(tmp_path, "oracle.jsonl", [
        _make_assistant_line([], tool_inputs=[{"name": name, "input": tool_input}]),
    ])
    flagged = _flagged_values(log)
    assert flagged, "corpus entry should be flagged"

    assert redact_log_file(log) > 0

    from agentwatch.parser import parse_file

    raw = log.read_text()
    assert all(json.loads(line) for line in raw.splitlines())  # still valid JSON
    texts = [raw] + [t for a in parse_file(log) for t, _, _ in extract_scannable_content(a)]
    assert [v for v in flagged if any(v in t for t in texts)] == []
    assert [v for v in _ORACLE_PLANTED if any(v in t for t in texts)] == []
    assert _flagged_values(log) == set()
    assert audit_log_file(log) == []
    assert redact_log_file(log) == 0


def test_placeholder_url_does_not_hide_live_url_after_it(tmp_path):
    # QA round 2 of #26: the first unredacted match was a placeholder, and the
    # callers then dropped the whole pattern instead of looking further.
    env = (
        "TEST_URL=postgres://<user>:<password>@localhost/app\n"
        "DATABASE_URL=postgres://admin:LivePw5Zk@prod.db/app\n"
    )
    write = {"name": "Write", "input": {"file_path": "/app/.env", "content": env}}
    log = _write_jsonl(tmp_path, "ph.jsonl", [_make_assistant_line([], tool_inputs=[write])])
    assert [f.secret_type for f in audit_log_file(log)] == ["database_connection_string"]

    buf = ActionBuffer()
    buf.add(_make_action(tool_type=ToolType.WRITE, raw={"input": write["input"]}))
    w = SecretLeakScanner().check(buf)
    assert w is not None and w.details["secret_type"] == "database_connection_string"


@pytest.mark.parametrize(
    "url",
    [
        "postgres://admin:LivePw5Zk@db.example.com/app",
        "postgres://admin:LivePw5Zk@db.host/app?application_name=test_key",
    ],
)
def test_db_url_placeholder_check_uses_password_only(tmp_path, url):
    # QA round 2 of #26: the placeholder check ran on the whole URL, so a
    # host or query that looks like a placeholder hid a live password.
    bash = {"name": "Bash", "input": {"command": f"psql {url}"}}
    log = _write_jsonl(tmp_path, "fp.jsonl", [_make_assistant_line([], tool_inputs=[bash])])
    assert [f.secret_type for f in audit_log_file(log)] == ["database_connection_string"]
    assert redact_log_file(log) == 1
    assert "LivePw5Zk" not in log.read_text()


@pytest.mark.parametrize(
    "url",
    [
        "postgres://<user>:<password>@localhost/app",
        "postgres://user:password@db.host/app",
        "postgres://app:CHANGEME@db.host/app",
    ],
)
def test_db_url_placeholder_password_still_ignored(url):
    buf = ActionBuffer()
    buf.add(_make_action(tool_type=ToolType.BASH, command=f"psql {url}"))
    assert SecretLeakScanner().check(buf) is None


@pytest.mark.parametrize("text,shown,redacted", [
    # Missed forms
    ("mysql_secure_installation -pHx7q2Lm9Zr",
     "mysql_secure_installation -p[hidden, 10 chars]",
     "mysql_secure_installation -p[REDACTED]"),
    ("/opt/x/curl -u a:Hx7q2Lm9Zr https://h",
     "/opt/x/curl -u a:[hidden, 10 chars] https://h",
     "/opt/x/curl -u a:[REDACTED] https://h"),
    # A trailing colon is punctuation: count right, colon kept
    ("mysql -u root -pHx7q2Lm9Zr: Access denied",
     "mysql -u root -p[hidden, 10 chars]: Access denied",
     "mysql -u root -p[REDACTED]: Access denied"),
])
def test_scanner_followups_31(text, shown, redacted):
    from agentwatch.detectors.security.secret_scanner import _redact_text, redact_secrets

    assert redact_secrets(text) == shown
    assert _redact_text(text) == (redacted, 1)


def test_curl_path_prefix_stays_linear():
    """#31: "/x/curl" starts must not each rescan a 40-token gap."""
    from agentwatch.detectors.security.secret_scanner import redact_secrets

    start = time.perf_counter()
    redact_secrets("/x/curl " * 60_000)
    assert time.perf_counter() - start < 2.0


@pytest.mark.parametrize("url,password", [
    ("redis://:S3cretRedisPw9@cache:6379/0", "S3cretRedisPw9"),  # empty user
    ("postgres://admin:Live@Pw5Zk@db.host/app", "Live@Pw5Zk"),  # raw "@" in password
])
def test_db_url_gaps_33(url, password):
    from agentwatch.detectors.security.secret_scanner import _redact_text, redact_secrets

    assert password not in redact_secrets(f"psql {url}")
    redacted, count = _redact_text(f"psql {url}")
    assert count == 1 and redacted == f"psql {url.replace(password, '[REDACTED]')}"


def test_redact_truncate_caches_repeat_windows(monkeypatch):
    """#25: re-redacting the same command on every tick hits the cache."""
    from agentwatch.detectors.security import secret_scanner

    secret_scanner._redact_window.cache_clear()
    calls = []
    real = secret_scanner.redact_secrets
    monkeypatch.setattr(secret_scanner, "redact_secrets", lambda t: calls.append(t) or real(t))
    token = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
    for _ in range(5):
        out = secret_scanner.redact_truncate(f"git push https://{token}@github.com/o/r", 80)
    assert len(calls) == 1
    assert token not in out


# --- #64: reported length counts the whole value, colons and = included ----------

@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ("export PGPASSWORD=Ab:cd:ef", "PGPASSWORD=[hidden, 8 chars]"),
        ("PGPASSWORD=a=b=c", "PGPASSWORD=[hidden, 5 chars]"),
    ],
)
def test_masked_length_counts_whole_value(text, shown):
    from agentwatch.detectors.security.secret_scanner import (
        SecretLeakScanner,
        redact_secrets,
    )

    assert shown in redact_secrets(text)
    buf = ActionBuffer()
    buf.add(Action(timestamp=datetime(2026, 3, 1, 12, 0), tool_name="Bash",
                   tool_type=ToolType.BASH, success=True, command=text))
    warning = SecretLeakScanner().check(buf)
    assert warning is not None
    assert warning.details["matched_prefix"] == shown.split("=", 1)[1]
