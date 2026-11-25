"""Security severities on a benign synthetic session (Sprint 50).

tests/fixtures/security_benign.jsonl is a synthetic Claude Code session made
only of ordinary dev work: every false-alarm class seen in a local
measurement (scripts/fp_corpus.py), rebuilt from normal commands and fake or
documented example keys. Each line carries an ``fpClass`` field (ignored by
the parser) naming the class it reproduces; ``baseline`` lines are the
warm-up every class is scanned after (the >= 10/20-action windows some
detectors need).

Wave 1 recorded what the detectors did (every class critical or high).
Wave 2 lowered severities under strict safe shapes
(detectors/security/safe_shapes.py): no critical and no high anywhere below,
and every finding key is still present. A key that disappears from a dict
is a lost detection, never an improvement.
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
    "dangerous_command": "medium",  # rm -rf /tmp/..., .pytest_cache, socket words
    "c2_beacon": "medium",  # sleep 2; curl http://127.0.0.1:...
    "prompt_injection": "medium",  # attack string in a test literal; base64 + system:
    "mass_delete": "medium",  # rm -f build/obj/*.o one by one
    "privilege_escalation": "low",  # chmod 700 ~, 644, 755
    "dns_exfil": "low",  # dig +short github.com; 'Host 1.2.3.4' in curl -w
    "skill_install": "low",  # ls skills && pip install
    "secret_in_command": "low",  # AWS example key, ghp_ sequence
    "secret_leak:aws_access_key@bash_command": "low",
    "secret_leak:aws_secret_key@bash_command": "low",
    "secret_leak:github_pat@bash_command": "low",
    "secret_leak:aws_access_key@file_write": "low",
    "secret_leak:aws_access_key@model_output": "low",
    "credential_access:secrets-management.md": "low",
    "secret_in_output": "low",
    "hidden_instruction": "low",  # display: none; in a .css Read
    "credential_access:token_refresh.py": "low",
}
# Still 2: the fixture packs every false-alarm class into one session, and
# 4 medium + 13 low findings take 125 points off the security score. The
# scoring is unchanged (out of Sprint 50's scope); no finding is critical.
SESSION_EXIT_CODE = 2  # security-scan: score below 50 -> compromised

# Each class scanned on its own (after the baseline warm-up): what it raises.
CLASS_BASELINE: dict[str, dict[str, str]] = {
    "baseline": {},
    "chmod_mode": {"privilege_escalation": "low"},
    "rm_rf_tmp": {"dangerous_command": "medium"},
    "rm_rf_dotdir": {"dangerous_command": "medium"},
    "python_socket_words": {"dangerous_command": "medium"},
    "attack_strings_as_data": {"dangerous_command": "low"},
    "sleep_then_local_curl": {"c2_beacon": "medium"},
    "cron_curl_in_text": {"c2_beacon": "low"},
    "dig_lookup": {"dns_exfil": "low"},
    "host_word_in_text": {"dns_exfil": "low"},
    "skill_install_words": {"skill_install": "low"},
    "aws_example_key_cmd": {
        "secret_in_command": "low",
        "secret_leak:aws_access_key@bash_command": "low",
        "secret_leak:aws_secret_key@bash_command": "low",
    },
    "fixture_key_cmd": {
        "secret_in_command": "low",
        "secret_leak:github_pat@bash_command": "low",
    },
    "aws_example_key_write": {"secret_leak:aws_access_key@file_write": "low"},
    "aws_example_key_reply": {
        "secret_in_output": "low",
        "secret_leak:aws_access_key@model_output": "low",
    },
    "credential_word_in_path_read": {"credential_access:secrets-management.md": "low"},
    "credential_word_in_path_edit": {"credential_access:token_refresh.py": "low"},
    "injection_text_in_test_file": {"prompt_injection": "medium"},
    "injection_words_in_source": {"prompt_injection": "medium"},
    "css_display_none": {"hidden_instruction": "low"},
    "cleanup_rm": {"mass_delete": "medium"},
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


def test_no_critical_or_high_on_benign_work():
    """The Sprint 50 gate: the benign corpus raises nothing critical or high."""
    found = _scan(FIXTURE)
    assert not {k: v for k, v in found.items() if v in ("critical", "high")}
    for fp_class, expected in CLASS_BASELINE.items():
        assert not {k for k, v in expected.items() if v in ("critical", "high")}, fp_class
