"""`agentwatch scrub <path>` (spec ACs 2-8, 11)."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from agentwatch.cli import cli

_PEM_BODY = [
    "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun",
    "VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK",
]
SECRETS = [
    "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
    "AKIAQ7R3T5V7X9Z2B4D6",
    "Tr0ub4dor&3xK",
]
PII = [
    "jane.doe@gmail.com",
    "(415) 555-2671",
    "123-45-6789",
    "4111 1111 1111 1111",
    "123 Main St",
]
RAW = SECRETS + PII + _PEM_BODY
N = len(SECRETS) + len(PII) + 1  # the PEM key is one value

TEXT = (
    f"github: {SECRETS[0]}\n"
    f"aws: {SECRETS[1]}\n"
    f'db_password = "{SECRETS[2]}"\n'
    + "".join(f"pii: {v}\n" for v in PII)
    + "-----BEGIN RSA PRIVATE KEY-----\n"
    + "\n".join(_PEM_BODY)
    + "\n-----END RSA PRIVATE KEY-----\n"
)


def _run(*args: str):
    return CliRunner().invoke(cli, ["scrub", *args])


def _seed(tmp_path: Path, name: str = "file.txt", text: str = TEXT) -> Path:
    p = tmp_path / name
    p.write_bytes(text.encode())
    return p


def test_copy_redacts_all_and_keeps_original(tmp_path):  # AC2
    src = _seed(tmp_path)
    before = src.read_bytes()
    res = _run(str(src), "--json")
    assert res.exit_code == 0, res.output
    out = json.loads(res.stdout)
    assert out["redacted"] == N
    assert out["output"] == str(tmp_path / "file.scrubbed.txt")
    assert out["backup"] is None
    cleaned = (tmp_path / "file.scrubbed.txt").read_text()
    for raw in RAW:
        assert raw not in cleaned
    assert src.read_bytes() == before


def test_jsonl_lines_stay_valid(tmp_path):  # AC3
    lines = [
        json.dumps({"type": "user", "message": {"content": "mail jane.doe@gmail.com"}}),
        "not json: card 4111 1111 1111 1111",
        json.dumps({"type": "tool_result", "content": "ok\n(415) 555-2671"}),
    ]
    src = _seed(tmp_path, "run.jsonl", "\n".join(lines) + "\n")
    res = _run(str(src))
    assert res.exit_code == 0, res.output
    out = (tmp_path / "run.scrubbed.jsonl").read_text().split("\n")
    assert json.loads(out[0]).keys() == json.loads(lines[0]).keys()
    assert json.loads(out[2]).keys() == json.loads(lines[2]).keys()
    assert out[1] == "not json: card [REDACTED]"
    joined = "\n".join(out)
    for raw in ("jane.doe@gmail.com", "4111 1111 1111 1111", "(415) 555-2671"):
        assert raw not in joined


def test_dry_run_writes_nothing_and_matches_real_count(tmp_path):  # AC4
    src = _seed(tmp_path)
    dry = _run(str(src), "--dry-run", "--json")
    assert dry.exit_code == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == ["file.txt"]
    d = json.loads(dry.stdout)
    assert d["dry_run"] is True and d["output"] is None and d["backup"] is None
    assert {f["type"] for f in d["findings"]} >= {"email", "phone", "us_ssn", "credit_card"}
    human = _run(str(src), "--dry-run")
    real = _run(str(src), "--json")
    assert json.loads(real.stdout)["redacted"] == d["redacted"] == N
    for output in (dry.output, human.output, real.output):
        for raw in RAW:
            assert raw not in output


def test_in_place_keeps_bak_and_refuses_second_run(tmp_path):  # AC5
    src = _seed(tmp_path)
    before = src.read_bytes()
    res = _run(str(src), "--in-place", "--json")
    assert res.exit_code == 0, res.output
    bak = tmp_path / "file.txt.bak"
    assert json.loads(res.stdout)["backup"] == str(bak)
    assert bak.read_bytes() == before
    for raw in RAW:
        assert raw not in src.read_text()
    if sys.platform != "win32":
        assert stat.S_IMODE(bak.stat().st_mode) == 0o600
    after = src.read_bytes()
    again = _run(str(src), "--in-place")
    assert again.exit_code == 2
    assert src.read_bytes() == after and bak.read_bytes() == before


def test_idempotent(tmp_path):  # AC6
    src = _seed(tmp_path)
    _run(str(src))
    res = _run(str(tmp_path / "file.scrubbed.txt"), "--dry-run", "--json")
    assert res.exit_code == 0
    assert json.loads(res.stdout)["redacted"] == 0


def test_exit_codes(tmp_path):  # AC7
    assert _run(str(_seed(tmp_path))).exit_code == 0
    clean = _seed(tmp_path, "clean.txt", "nothing to see\n")
    assert _run(str(clean), "--dry-run").exit_code == 0
    assert _run(str(tmp_path / "missing.txt")).exit_code == 2
    assert _run(str(tmp_path)).exit_code == 2
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"abc\x00def jane.doe@gmail.com")
    assert _run(str(binary)).exit_code == 2
    assert not (tmp_path / "blob.scrubbed.bin").exists()


@pytest.mark.parametrize("name,expected", [
    (".env", ".env.scrubbed"),
    ("notes.txt", "notes.scrubbed.txt"),
])
def test_output_naming_and_overwrite(tmp_path, name, expected):  # AC8
    src = _seed(tmp_path, name, "API_KEY=ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\n")
    (tmp_path / expected).write_text("stale")
    assert _run(str(src)).exit_code == 0
    assert "[REDACTED]" in (tmp_path / expected).read_text()


def test_secrets_only_leaves_pii(tmp_path):  # AC11
    src = _seed(tmp_path)
    res = _run(str(src), "--secrets-only", "--json")
    assert json.loads(res.stdout)["redacted"] == len(SECRETS) + 1
    cleaned = (tmp_path / "file.scrubbed.txt").read_text()
    for raw in PII:
        assert raw in cleaned


def test_claude_code_log_prompt_pii_redacted_in_copy(tmp_path):
    # audit skips user prompts; the skill relies on scrub catching them.
    lines = [
        json.dumps({"type": "user", "message": {"content": "my ssn is 123-45-6789"}}),
        json.dumps({"type": "assistant", "message": {"content": "noted"}}),
    ]
    src = _seed(tmp_path, "session.jsonl", "\n".join(lines) + "\n")
    res = _run(str(src), "--json")
    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)["redacted"] >= 1
    out = (tmp_path / "session.scrubbed.jsonl").read_text()
    assert "123-45-6789" not in out
    for line in out.splitlines():
        json.loads(line)
