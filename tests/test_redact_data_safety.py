"""Data-safety fixes for `audit --redact` and `scrub` (Sprint 37 F3).

All secrets here are synthetic.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentwatch.detectors.security.secret_scanner import (
    _redact_text,
    redact_secrets,
)

PW = "Zq7wertyuiopasdfghjkl9XyZ"  # 25 chars, tail "9XyZ"
SK = "sk-proj-abc123def456ghi789jklmno"


def _log(tmp_path: Path, name: str = "s.jsonl", secret: str = "Hunter2Pass!x") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps({"password": secret}) + "\n")
    return p


def _baks(p: Path) -> list[Path]:
    return sorted(p.parent.glob(p.name + ".bak*"))


def _cc_line(command: str) -> str:
    return json.dumps({
        "type": "assistant",
        "message": {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": "t1", "name": "Bash",
                         "input": {"command": command}}],
        },
    }) + "\n"


def _cc_project(tmp_path: Path, monkeypatch, command: str = f"echo {SK}") -> Path:
    project = tmp_path / "projects" / "-tmp-proj"
    project.mkdir(parents=True)
    log = project / "sess.jsonl"
    log.write_text(_cc_line(command))
    monkeypatch.setattr("agentwatch.cc_stats.CLAUDE_PROJECTS_DIR", tmp_path / "projects")
    return log


# --------------------------------------------------------------------------
# P3: masked previews never show the tail of a password
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        f'password = "{PW}"',
        f"PGPASSWORD={PW}",
        f"mysql -u root -p{PW}",
        f"curl -u admin:{PW} https://api.internal/x",
        f"git clone https://admin:{PW}@git.internal/r.git",
        f"psql postgres://admin:{PW}@db.prod.internal/app",
        f"PASSWORD={PW}",
    ],
)
def test_password_previews_never_show_the_tail(text):
    assert "9XyZ" not in redact_secrets(text)
    found: list[dict] = []
    _redact_text(text, found=found)
    assert found, text
    assert all("9XyZ" not in f["preview"] for f in found)
    assert all(f["preview"].startswith("[hidden") for f in found)


def test_token_previews_still_show_tail():
    found: list[dict] = []
    _redact_text("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", found=found)
    assert found[0]["preview"] == "…Q7r8"
