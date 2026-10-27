"""`agentwatch check --security` exit codes (Sprint 38, fix A).

A CRITICAL security finding must fail `check --security` even when the
averaged health score is high. Uses a synthetic Claude Code JSONL fixture
(`tests/fixtures/check_security_critical.jsonl`: one `sudo rm -rf` Bash
call, flagged CRITICAL by privilege_escalation and dangerous_command).
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from agentwatch.cli import cli

FIXTURE = Path(__file__).parent / "fixtures" / "check_security_critical.jsonl"


def test_check_security_fails_on_critical_finding():
    res = CliRunner().invoke(cli, ["check", "--log", str(FIXTURE), "--security"])
    assert res.exit_code == 2, res.output


def test_check_without_security_keeps_old_exit_code():
    res = CliRunner().invoke(cli, ["check", "--log", str(FIXTURE)])
    assert res.exit_code == 0, res.output


def test_security_scan_agrees_with_check_security():
    res = CliRunner().invoke(cli, ["security-scan", "--log", str(FIXTURE)])
    assert res.exit_code == 2, res.output


def test_check_help_documents_exit_codes():
    res = CliRunner().invoke(cli, ["check", "--help"])
    assert res.exit_code == 0
    assert "Exit codes" in res.output
    assert "2 = critical" in res.output
    assert "1 = at risk (score 50-99)" in res.output
    assert "2 = compromised (score below 50)" in res.output
