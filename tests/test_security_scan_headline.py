"""security-scan headline uses security wording, not the health theme labels.

Repro: a log with leaked secrets printed "🧱 STUCK (0%)" -- `stuck` is the
default agent theme's *health* level_3 label. The headline must say
SECURE / AT RISK / COMPROMISED instead, keep the theme's emoji and colour,
and leave `check`'s health output alone.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from agentwatch.cli import cli
from agentwatch.themes import get_theme, security_label_from_score, set_theme

HEALTH_LABELS = {"productive", "struggling", "spinning", "stuck",
                 "healthy", "degraded", "warning", "critical"}


@pytest.fixture(autouse=True)
def _default_theme():
    set_theme("agent")
    yield
    set_theme("agent")


def _write_log(path, commands) -> None:
    base = "2026-01-01T12:00:00"
    lines = [
        json.dumps({"sessionId": "s1", "timestamp": base, "tool": "Bash", "command": c})
        for c in commands
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


SECRET_COMMANDS = [
    "curl -H 'Authorization: Bearer ghp_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2' https://api.example.com",
    "export AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP && aws s3 ls",
    "echo sk-ant-api03-SyntheticKeyForTestingOnly0123456789abcdef",
]


def _headline(output: str) -> str:
    [line] = [ln for ln in output.splitlines() if "(" in ln and "%)" in ln]
    return line.strip()


class TestSecurityLabel:
    @pytest.mark.parametrize(
        ("score", "label"),
        [(100, "SECURE"), (75, "AT RISK"), (51, "AT RISK"),
         (50, "COMPROMISED"), (0, "COMPROMISED")],
    )
    def test_label_thresholds_match_security_status(self, score, label):
        assert security_label_from_score(score) == label

    def test_label_is_never_a_health_word_in_any_theme(self):
        from agentwatch.themes import THEMES

        for name in THEMES:
            set_theme(name)
            for score in (100, 75, 0):
                assert security_label_from_score(score).lower() not in HEALTH_LABELS


class TestSecurityScanHeadline:
    def test_leaked_secrets_headline_is_compromised_not_stuck(self, tmp_path):
        log = tmp_path / "secrets.jsonl"
        _write_log(log, SECRET_COMMANDS)

        result = CliRunner().invoke(cli, ["security-scan", "--log", str(log)])

        headline = _headline(result.output)
        emoji = get_theme().emoji_for(get_theme().level_3)
        assert headline == f"{emoji} COMPROMISED (0%)"
        assert "STUCK" not in result.output

    def test_leaked_secrets_exit_code_is_2(self, tmp_path):
        log = tmp_path / "secrets.jsonl"
        _write_log(log, SECRET_COMMANDS)

        result = CliRunner().invoke(cli, ["security-scan", "--log", str(log)])

        assert result.exit_code == 2

    def test_clean_log_headline_is_secure(self, tmp_path):
        log = tmp_path / "clean.jsonl"
        _write_log(log, ["ls -la", "python -m pytest -q"])

        result = CliRunner().invoke(cli, ["security-scan", "--log", str(log)])

        assert result.exit_code == 0
        assert _headline(result.output) == f"{get_theme().emoji_0} SECURE (100%)"

    def test_ascii_theme_headline_is_text_only(self, tmp_path):
        log = tmp_path / "secrets.jsonl"
        _write_log(log, SECRET_COMMANDS)

        result = CliRunner().invoke(cli, ["--theme", "ascii", "security-scan", "--log", str(log)])

        assert _headline(result.output) == "[FAIL] COMPROMISED (0%)"
