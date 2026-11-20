"""`agentwatch check --security` exit codes (Sprint 38, fix A).

A CRITICAL security finding must fail `check --security` even when the
averaged health score is high. Uses a synthetic Claude Code JSONL fixture
(`tests/fixtures/check_security_critical.jsonl`: one `sudo rm -rf` Bash
call, flagged CRITICAL by privilege_escalation and dangerous_command).
"""

from __future__ import annotations

from pathlib import Path

import pytest
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


MEDIUM_FIXTURE = Path(__file__).parent / "fixtures" / "check_security_medium.jsonl"
CLEAN_FIXTURE = Path(__file__).parent / "fixtures" / "check_security_clean.jsonl"


def test_check_security_at_risk_exits_1_for_medium_finding():
    # A MEDIUM-only finding (data_upload) gives a security score of 85: at risk.
    res = CliRunner().invoke(cli, ["check", "--log", str(MEDIUM_FIXTURE), "--security"])
    assert res.exit_code == 1, res.output


def test_check_without_security_ignores_medium_finding():
    res = CliRunner().invoke(cli, ["check", "--log", str(MEDIUM_FIXTURE)])
    assert res.exit_code == 0, res.output


def test_check_security_clean_log_matches_plain_check():
    plain = CliRunner().invoke(cli, ["check", "--log", str(CLEAN_FIXTURE)])
    secure = CliRunner().invoke(cli, ["check", "--log", str(CLEAN_FIXTURE), "--security"])
    assert plain.exit_code == 0, plain.output
    assert secure.exit_code == plain.exit_code, secure.output


def test_check_security_headline_is_the_security_verdict():
    """QA sweep: the headline said PRODUCTIVE (82%) while exiting 2. In
    security mode it is the security verdict, the health status below it."""
    res = CliRunner().invoke(cli, ["check", "--log", str(FIXTURE), "--security"])
    assert res.exit_code == 2, res.output
    lines = [line.strip() for line in res.output.splitlines()]
    sec = next(i for i, line in enumerate(lines) if line.startswith("Security:"))
    assert "COMPROMISED (0%)" in lines[sec]
    assert lines[sec + 1].startswith("Health:")
    assert not any(line.startswith("Overall:") for line in lines)


@pytest.mark.parametrize("fixture, verdict", [(MEDIUM_FIXTURE, "AT RISK (85%)"),
                                              (CLEAN_FIXTURE, "SECURE (100%)")])
def test_check_security_headline_tiers(fixture, verdict):
    res = CliRunner().invoke(cli, ["check", "--log", str(fixture), "--security"])
    assert f"{verdict}" in res.output


def test_plain_check_keeps_overall_headline():
    res = CliRunner().invoke(cli, ["check", "--log", str(CLEAN_FIXTURE)])
    assert "Overall:" in res.output and "Security:" not in res.output
