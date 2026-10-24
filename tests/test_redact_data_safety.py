"""Data-safety fixes for `audit --redact` and `scrub` (Sprint 37 F3).

All secrets here are synthetic.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from agentwatch.cli import cli
from agentwatch.detectors.security import secret_scanner as sc
from agentwatch.detectors.security.secret_scanner import (
    _is_false_positive,
    _redact_text,
    redact_log_file,
    redact_secrets,
    scrub_file,
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


# --------------------------------------------------------------------------
# P2: placeholder words inside a secret must not stop redaction
# --------------------------------------------------------------------------

_REAL_SECRETS = [
    'password="MyExample#Pass1"',
    "DB_PASSWORD=Dummy-Pr0d-9x!",
    "STRIPE=sk_live_TODO" + "aB3xZ9qW2kL5mN8pR1tU4vY7",
    "api_key=sk-proj-Test_key" + "aB3xZ9qW2kL5mN8pR1tU4vY7",
    "psql postgres://postgres:postgres@prod.internal/app",
    "psql postgres://admin:admin@db.prod.internal/app",
    "git clone https://root:root@git.corp.internal/r.git",
]


@pytest.mark.parametrize("text", _REAL_SECRETS)
def test_real_secret_with_placeholder_word_is_redacted(text):
    redacted, count = _redact_text(text)
    assert count >= 1, text
    assert redacted != text


@pytest.mark.parametrize(
    "text",
    [
        "token: ***",
        "password=gho_****",
        "password=<your-password>",
        "password=${DB_PASSWORD}",
        "password={{ db_password }}",
        "password=%(db_password)s",
        "password=changeme",
        "api_key = your_key_here_abcdef1234567890",
        "api_key = your_key_here_placeholder_12345678901234567890",
        'password = "example_password"',
        'password = "xxxxxxxxxxxx"',
        'password = "TODO_replace_me"',
        'password = "placeholder_value"',
        "psql postgres://postgres:postgres@localhost/app",
        "psql postgres://root:root@127.0.0.1:5432/app",
        "psql postgres://root:root@[::1]:5432/app",
        "psql postgres://app:CHANGEME@db.host/app",
        "psql postgres://<user>:<password>@db.host/app",
    ],
)
def test_real_placeholders_stay_untouched(text):
    assert _redact_text(text) == (text, 0)


@pytest.mark.parametrize(
    "value",
    ["your_key_here", "YOUR_API_KEY", "example", "changeme", "xxxxxxxx", "TODO"],
)
def test_whole_value_placeholders_are_false_positives(value):
    assert _is_false_positive(f"api_key = {value}")


@pytest.mark.parametrize(
    "value",
    ["MyExample#Pass1", "Dummy-Pr0d-9x!", "sk_live_TODO" + "aB3xZ9qW2kL5mN8pR1tU4vY7"],
)
def test_values_merely_containing_a_placeholder_word_are_not(value):
    assert not _is_false_positive(f"password = {value}")


# --------------------------------------------------------------------------
# P2: symlinks are refused
# --------------------------------------------------------------------------


def test_scrub_in_place_refuses_symlink(tmp_path):
    target = _log(tmp_path, "real.jsonl")
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    before = target.read_bytes()

    with pytest.raises(ValueError, match="symlink"):
        scrub_file(link, in_place=True)

    assert link.is_symlink()
    assert target.read_bytes() == before
    assert not list(tmp_path.glob("*.bak*"))


def test_scrub_cli_in_place_symlink_errors_exit_2(tmp_path):
    target = _log(tmp_path, "real.jsonl")
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    res = CliRunner().invoke(cli, ["scrub", str(link), "--in-place"])
    assert res.exit_code == 2
    assert "symlink" in res.output
    assert "Hid" not in res.output


def test_scrub_copy_of_symlink_still_works(tmp_path):
    target = _log(tmp_path, "real.jsonl")
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    r = scrub_file(link)
    assert r.redacted == 1 and r.output is not None
    assert "Hunter2Pass!x" not in r.output.read_text()


def test_redact_log_file_refuses_symlink(tmp_path):
    target = _log(tmp_path, "real.jsonl")
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    before = target.read_bytes()

    with pytest.raises(ValueError, match="symlink"):
        redact_log_file(link)

    assert link.is_symlink() and target.read_bytes() == before
    assert not list(tmp_path.glob("*.bak*"))


# --------------------------------------------------------------------------
# P2: every run gets its own backup
# --------------------------------------------------------------------------


def test_second_run_writes_a_fresh_backup_with_its_own_original(tmp_path):
    p = _log(tmp_path)
    b1: list[Path] = []
    assert redact_log_file(p, backups=b1) == 1
    first_backup_bytes = b1[0].read_bytes()

    # A secret appended after the first run.
    with p.open("a") as fh:
        fh.write(json.dumps({"password": "Second9Secret!y"}) + "\n")
    before_second = p.read_bytes()
    b2: list[Path] = []
    assert redact_log_file(p, backups=b2) == 1

    assert b1[0] != b2[0]
    assert b1[0].read_bytes() == first_backup_bytes  # earlier backup untouched
    assert b2[0].read_bytes() == before_second  # holds THIS run's original
    assert b"Second9Secret!y" in b2[0].read_bytes()
    assert b"Second9Secret!y" not in p.read_bytes()
    assert len(_baks(p)) == 2


def test_backup_name_is_timestamped_and_private(tmp_path):
    p = _log(tmp_path)
    p.chmod(0o640)
    backups: list[Path] = []
    redact_log_file(p, backups=backups)
    assert backups[0].name.startswith("s.jsonl.bak.")
    assert backups[0].name != "s.jsonl.bak."
    if os.name == "posix":
        assert (backups[0].stat().st_mode & 0o777) == 0o600
        assert (p.stat().st_mode & 0o777) == 0o640


def test_backup_names_do_not_collide_within_one_second(tmp_path):
    p = _log(tmp_path)
    redact_log_file(p)
    for i in range(3):
        with p.open("a") as fh:
            fh.write(json.dumps({"password": f"Again{i}Secret!y"}) + "\n")
        redact_log_file(p)
    assert len(_baks(p)) == 4


def test_cli_lists_exact_backup_paths_for_repeated_runs(tmp_path, monkeypatch):
    log = _cc_project(tmp_path, monkeypatch)
    runner = CliRunner()
    first = json.loads(runner.invoke(cli, ["audit", "--all", "--redact", "--json"]).stdout)
    late = "sk-proj-zzz123def456ghi789jklmno"
    with log.open("a") as fh:
        fh.write(_cc_line(f"echo {late}"))
    second = json.loads(runner.invoke(cli, ["audit", "--all", "--redact", "--json"]).stdout)

    assert len(first["backups"]) == 1 and len(second["backups"]) == 1
    assert first["backups"] != second["backups"]
    assert late in Path(second["backups"][0]).read_text()
    assert late not in log.read_text()
    for b in first["backups"] + second["backups"]:
        assert Path(b).exists()


# --------------------------------------------------------------------------
# P1: a live log must not lose appended lines
# --------------------------------------------------------------------------


@pytest.fixture
def quiet_window(monkeypatch):
    """Turn the recent-write guard back on (conftest switches it off)."""
    monkeypatch.setattr(sc, "_RECENT_WRITE_SECONDS", 5.0)


def _append_during_redact(monkeypatch, p: Path, line: bytes, times: int = 1):
    """Append *line* to *p* from inside the redaction pass (after the read)."""
    real = sc._redact_line
    calls = {"n": 0}

    def hooked(text, *a, **kw):
        if calls["n"] < times:
            calls["n"] += 1
            with p.open("ab") as fh:
                fh.write(line)
        return real(text, *a, **kw)

    monkeypatch.setattr(sc, "_redact_line", hooked)


def test_append_during_redact_is_not_lost(tmp_path, monkeypatch):
    p = _log(tmp_path)
    appended = json.dumps({"note": "written while redacting"}).encode() + b"\n"
    _append_during_redact(monkeypatch, p, appended)

    assert redact_log_file(p) == 1

    data = p.read_bytes()
    assert data.endswith(appended)
    assert b"Hunter2Pass!x" not in data
    assert len(data.splitlines()) == 2
    assert not [x for x in tmp_path.iterdir() if x.name.endswith(".tmp")]
    # The retry's backup is the file as it was when that pass read it.
    assert len(_baks(p)) == 1
    assert appended in _baks(p)[0].read_bytes()


def test_append_with_a_secret_during_redact_is_redacted_and_kept(tmp_path, monkeypatch):
    p = _log(tmp_path)
    late = json.dumps({"password": "LateSecret9!zz"}).encode() + b"\n"
    _append_during_redact(monkeypatch, p, late)

    assert redact_log_file(p) == 2
    assert b"LateSecret9!zz" not in p.read_bytes()
    assert len(p.read_bytes().splitlines()) == 2


def test_persistent_change_aborts_and_leaves_file_and_dir_intact(tmp_path, monkeypatch):
    p = _log(tmp_path)
    _append_during_redact(monkeypatch, p, b'{"n": 1}\n', times=1000)

    with pytest.raises(sc.LogChangedError, match="changed while"):
        redact_log_file(p)

    # Nothing replaced, no temp file, no backup of a run that did not happen.
    assert b"Hunter2Pass!x" in p.read_bytes()
    assert sorted(x.name for x in tmp_path.iterdir()) == ["s.jsonl"]


def test_replaced_inode_is_detected_and_retried(tmp_path, monkeypatch):
    p = _log(tmp_path)
    real = sc._redact_line
    state = {"done": False}

    def hooked(text, *a, **kw):
        if not state["done"]:
            state["done"] = True
            other = tmp_path / "other"
            other.write_bytes(p.read_bytes() + b'{"n": 2}\n')
            os.replace(other, p)  # a writer rotated the file: new inode
        return real(text, *a, **kw)

    monkeypatch.setattr(sc, "_redact_line", hooked)
    assert redact_log_file(p) == 1
    assert b'{"n": 2}' in p.read_bytes()


def test_audit_reports_changing_file_as_error_not_crash(tmp_path, monkeypatch):
    log = _cc_project(tmp_path, monkeypatch)
    _append_during_redact(monkeypatch, log, b'{"n": 1}\n', times=1000)

    res = CliRunner().invoke(cli, ["audit", "--all", "--redact", "--json"])

    out = json.loads(res.stdout)
    assert out["redacted"] == 0
    assert out["redact_errors"] and "changed while" in out["redact_errors"][0]["error"]
    assert out["backups"] == []


def test_recently_modified_file_is_refused_without_force(tmp_path, quiet_window):
    p = _log(tmp_path)  # just written: mtime is now
    before = p.read_bytes()

    with pytest.raises(sc.LogBusyError, match="--force"):
        redact_log_file(p)

    assert p.read_bytes() == before and _baks(p) == []


def test_recently_modified_file_is_redacted_with_force(tmp_path, quiet_window):
    p = _log(tmp_path)
    assert redact_log_file(p, force=True) == 1
    assert b"Hunter2Pass!x" not in p.read_bytes()


def test_old_file_is_redacted_without_force(tmp_path, quiet_window):
    p = _log(tmp_path)
    old = time.time() - 3600
    os.utime(p, (old, old))
    assert redact_log_file(p) == 1


def test_clean_recent_file_is_not_refused(tmp_path, quiet_window):
    p = tmp_path / "clean.jsonl"
    p.write_text('{"x": "nothing here"}\n')
    assert redact_log_file(p) == 0


def test_cli_recent_file_needs_force_and_force_warns(tmp_path, monkeypatch, quiet_window):
    log = _cc_project(tmp_path, monkeypatch)
    runner = CliRunner()

    plain = runner.invoke(cli, ["audit", "--all", "--redact"])
    assert SK in log.read_text()
    assert "--force" in plain.output

    forced = runner.invoke(cli, ["audit", "--all", "--redact", "--force"])
    assert SK not in log.read_text()
    assert "WARNING" in forced.output
