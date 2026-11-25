"""Snapshot of today's security severities on a benign synthetic session
(Sprint 50, Wave 1).

tests/fixtures/security_benign.jsonl is a synthetic Claude Code session made
only of ordinary dev work: every false-alarm class seen in a local
measurement (scripts/fp_corpus.py), rebuilt from normal commands and fake or
documented example keys. Each line carries an ``fpClass`` field (ignored by
the parser) naming the class it reproduces; ``baseline`` lines are the
warm-up every class is scanned after (the >= 10/20-action windows some
detectors need).

These dicts RECORD what the detectors do today; they are not the goal.
Wave 2 lowers severities under strict safe shapes and updates them here
on purpose: the target there is no critical and no high anywhere below,
with every finding still present (a lower severity, never a dropped
detection). A key that disappears from a dict is a lost detection.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agentwatch.cli import cli
from agentwatch.detectors.registry import create_registry
from agentwatch.parser.logs import parse_file
from agentwatch.parser.models import ActionBuffer

FIXTURE = Path(__file__).parent / "fixtures" / "security_benign.jsonl"

# Whole session: finding key -> severity, as `agentwatch security-scan` reports it.
SESSION_BASELINE: dict[str, str] = {
    "privilege_escalation": "critical",
    "dangerous_command": "critical",
    "c2_beacon": "critical",
    "secret_leak:aws_access_key@file_write": "critical",
    "secret_leak:aws_access_key@model_output": "critical",
    "secret_in_output": "critical",
    "prompt_injection": "critical",
    "credential_access:token_refresh.py": "critical",
    "dns_exfil": "high",
    "skill_install": "high",
    "secret_in_command": "high",
    "secret_leak:aws_access_key@bash_command": "high",
    "secret_leak:aws_secret_key@bash_command": "high",
    "secret_leak:github_pat@bash_command": "high",
    "credential_access:secrets-management.md": "high",
    "hidden_instruction": "high",
    "mass_delete": "high",
}
SESSION_EXIT_CODE = 2  # security-scan: score below 50 -> compromised

# Each class scanned on its own (after the baseline warm-up): what it raises.
CLASS_BASELINE: dict[str, dict[str, str]] = {
    "baseline": {},
    "chmod_mode": {"privilege_escalation": "critical"},
    "rm_rf_tmp": {"dangerous_command": "critical"},
    "rm_rf_dotdir": {"dangerous_command": "critical"},
    "python_socket_words": {"dangerous_command": "critical"},
    "attack_strings_as_data": {"dangerous_command": "critical"},
    "sleep_then_local_curl": {"c2_beacon": "critical"},
    "cron_curl_in_text": {"c2_beacon": "critical"},
    "dig_lookup": {"dns_exfil": "high"},
    "host_word_in_text": {"dns_exfil": "high"},
    "skill_install_words": {"skill_install": "high"},
    "aws_example_key_cmd": {
        "secret_in_command": "high",
        "secret_leak:aws_access_key@bash_command": "high",
        "secret_leak:aws_secret_key@bash_command": "high",
    },
    "fixture_key_cmd": {
        "secret_in_command": "high",
        "secret_leak:github_pat@bash_command": "high",
    },
    "aws_example_key_write": {"secret_leak:aws_access_key@file_write": "critical"},
    "aws_example_key_reply": {
        "secret_in_output": "critical",
        "secret_leak:aws_access_key@model_output": "critical",
    },
    "credential_word_in_path_read": {"credential_access:secrets-management.md": "high"},
    "credential_word_in_path_edit": {"credential_access:token_refresh.py": "critical"},
    "injection_text_in_test_file": {"prompt_injection": "critical"},
    "injection_words_in_source": {"prompt_injection": "high"},
    "css_display_none": {"hidden_instruction": "high"},
    "cleanup_rm": {"mass_delete": "high"},
}


def _key(w) -> str:
    d = w.details or {}
    if w.signal == "secret_leak":
        return f"secret_leak:{d.get('secret_type')}@{d.get('channel')}"
    if w.signal == "credential_access":
        return f"credential_access:{Path(d.get('path') or '').name}"
    return w.signal


def _scan(path: Path) -> dict[str, str]:
    """`security-scan`'s own scan, as finding key -> severity."""
    warnings = create_registry(mode="security").scan(parse_file(path), ActionBuffer())
    found: dict[str, str] = {}
    for w in warnings:
        key = _key(w)
        assert key not in found, f"two findings share the key {key}: refine _key"
        found[key] = w.severity.value
    return found


def _lines() -> list[dict]:
    return [json.loads(x) for x in FIXTURE.read_text(encoding="utf-8").splitlines() if x]


def test_fixture_classes_match_baseline():
    classes = {line["fpClass"] for line in _lines()}
    assert classes == set(CLASS_BASELINE)


def test_session_severities():
    assert _scan(FIXTURE) == SESSION_BASELINE


def test_session_exit_code():
    result = CliRunner().invoke(cli, ["security-scan", "--log", str(FIXTURE), "--json"])
    assert result.exit_code == SESSION_EXIT_CODE


@pytest.mark.parametrize("fp_class", sorted(CLASS_BASELINE))
def test_class_severities(fp_class, tmp_path):
    lines = [x for x in _lines() if x["fpClass"] in ("baseline", fp_class)]
    log = tmp_path / f"{fp_class}.jsonl"
    log.write_text("".join(json.dumps(x) + "\n" for x in lines), encoding="utf-8")
    assert _scan(log) == CLASS_BASELINE[fp_class]
