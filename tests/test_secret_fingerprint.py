"""Secret fingerprints: two different secrets of one type, channel and file
are two findings; the same secret seen twice is one. The fingerprint is a
keyed hash; the value never reaches a warning, its key or an output."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from agentwatch import history
from agentwatch.agents import ClaudeCodeAdapter
from agentwatch.cli import cli
from agentwatch.detectors import create_registry
from agentwatch.detectors.base import warning_dedup_key
from agentwatch.detectors.registry import SessionScan
from agentwatch.detectors.security import secret_scanner as sc
from agentwatch.detectors.security.secret_scanner import (
    SecretLeakScanner,
    audit_log_file,
    secret_fingerprint,
)
from agentwatch.parser import ActionBuffer
from agentwatch.parser.models import Action, ToolType

KEY_A = "ghp_" + "a1B2" * 9
KEY_B = "ghp_" + "c3D4" * 9
T0 = datetime(2026, 3, 1, 12, 0)


@pytest.fixture(autouse=True)
def _fresh_key(monkeypatch):
    """Each test loads (or creates) the key in its own tmp data dir."""
    monkeypatch.setattr(sc, "_fingerprint_key", None)


def _cmd(command: str, i: int = 0) -> Action:
    return Action(timestamp=T0 + timedelta(seconds=i), tool_name="Bash",
                  tool_type=ToolType.BASH, success=True, command=command)


def _secret_findings(actions: list[Action]) -> list:
    buf = ActionBuffer()
    found: dict = {}
    scanner = SecretLeakScanner()
    for a in actions:
        buf.add(a)
        for w in scanner.check_many(buf):
            found[warning_dedup_key(w)] = w
    return list(found.values())


def _assert_no_value(obj, *values):
    text = json.dumps(obj, default=str)
    for v in values:
        assert v not in text
        assert v[4:] not in text  # nor the value without its scheme prefix


# --- fingerprint -------------------------------------------------------------

def test_fingerprint_is_short_keyed_and_stable():
    fp = secret_fingerprint(KEY_A)
    assert len(fp) == 12 and int(fp, 16) >= 0
    assert secret_fingerprint(KEY_A) == fp
    assert secret_fingerprint(KEY_B) != fp
    import hashlib
    assert fp != hashlib.sha256(KEY_A.encode()).hexdigest()[:12]  # not a plain hash


def test_key_file_is_private_and_reused_across_processes():
    secret_fingerprint(KEY_A)
    path = history.data_dir() / sc._FINGERPRINT_KEY_FILE
    assert len(path.read_bytes()) == 32
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
    fp = secret_fingerprint(KEY_A)
    sc._fingerprint_key = None  # as a new process would
    assert secret_fingerprint(KEY_A) == fp


def test_another_users_key_gives_other_fingerprints(tmp_path, monkeypatch):
    fp = secret_fingerprint(KEY_A)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "other"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "other"))
    sc._fingerprint_key = None
    assert secret_fingerprint(KEY_A) != fp


def test_unwritable_key_falls_back_to_a_process_key(monkeypatch):
    monkeypatch.setattr(sc, "_load_fingerprint_key", lambda: None)
    fp = secret_fingerprint(KEY_A)
    assert len(fp) == 12 and secret_fingerprint(KEY_A) == fp


# --- live scanner -------------------------------------------------------------

def test_two_secrets_same_type_and_channel_are_two_findings():
    found = _secret_findings([_cmd(f"push --token {KEY_A}", 0),
                              _cmd(f"push --token {KEY_B}", 1)])
    assert [(w.details["secret_type"], w.details["channel"]) for w in found] == [
        ("github_pat", "bash_command")] * 2
    assert len({w.details["fingerprint"] for w in found}) == 2


def test_two_secrets_in_one_text_are_two_findings():
    found = _secret_findings([_cmd(f"a {KEY_A} b {KEY_B}")])
    assert len(found) == 2


def test_same_secret_twice_is_one_finding():
    found = _secret_findings([_cmd(f"push --token {KEY_A}", 0),
                              _cmd(f"retry --token {KEY_A} {KEY_A}", 1)])
    assert len(found) == 1


def test_session_scan_keeps_both_secrets():
    """The ledger keeps both, also after they leave the 5-action window."""
    registry = create_registry("security")
    actions = [_cmd(f"push --token {KEY_A}", 0), _cmd(f"push --token {KEY_B}", 1)]
    actions += [_cmd("ls", 2 + i) for i in range(10)]
    leaks = [w for w in registry.scan(iter(actions), ActionBuffer())
             if w.signal == "secret_leak"]
    assert len(leaks) == 2
    session = SessionScan(registry)
    buf = ActionBuffer()
    for a in actions:
        session.add(buf, a)
    assert len([k for k in session.findings if k.startswith("secret_leak|")]) == 2


def test_value_absent_from_warning_details_and_dedup_key():
    [w] = _secret_findings([_cmd(f"push --token {KEY_A}")])
    fp = w.details["fingerprint"]
    assert fp == secret_fingerprint(KEY_A)
    key = warning_dedup_key(w)
    assert f"fingerprint={fp}" in key
    _assert_no_value({"m": w.message, "s": w.suggestion, "d": w.details, "k": key,
                      "dict": w.to_dict()}, KEY_A)


def test_tool_result_channel_and_fingerprint():
    a = _cmd("cat .env")
    a.incoming_message = f"GITHUB_TOKEN={KEY_A}\n"
    [w] = _secret_findings([a])
    assert w.details["channel"] == "tool_result"
    assert w.severity.value == "medium"
    assert w.details["fingerprint"] == secret_fingerprint(KEY_A)


def test_db_url_fingerprint_is_its_password_only():
    pw = "Zq7wertyuiopasdfghjkl9XyZ"
    found = _secret_findings([
        _cmd(f"psql postgres://admin:{pw}@db.prod.internal/app", 0),
        _cmd(f"psql postgres://admin:{pw}@db2.prod.internal/app", 1),
    ])
    assert len(found) == 1
    assert found[0].details["fingerprint"] == secret_fingerprint(pw)


# --- audit, JSON outputs, history -----------------------------------------------

def _cc_log(path: Path, commands: list[str]) -> Path:
    lines = []
    for i, c in enumerate(commands):
        lines.append({"type": "assistant", "sessionId": "s1",
                      "timestamp": (T0 + timedelta(seconds=i)).isoformat() + "Z",
                      "message": {"id": f"m{i}", "role": "assistant", "content": [
                          {"type": "tool_use", "id": f"t{i}", "name": "Bash",
                           "input": {"command": c}}]}})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(e) + "\n" for e in lines))
    old = time.time() - 3600
    os.utime(path, (old, old))
    return path


def test_audit_two_secrets_two_findings_same_twice_one(tmp_path):
    log = _cc_log(tmp_path / "s.jsonl", [f"x {KEY_A}", f"y {KEY_A}", f"z {KEY_B}"])
    found = [f for f in audit_log_file(log) if f.secret_type == "github_pat"]
    assert sorted(f.fingerprint for f in found) == sorted(
        [secret_fingerprint(KEY_A), secret_fingerprint(KEY_B)])


def test_audit_tool_result_block_is_tool_result(tmp_path):
    log = tmp_path / "s.jsonl"
    log.write_text(json.dumps({"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "x", "content": f"out {KEY_A}"}]}}) + "\n")
    assert [(f.channel, f.fingerprint) for f in audit_log_file(log)] == [
        ("tool_result", secret_fingerprint(KEY_A))]


@pytest.fixture
def cc_env(tmp_path, monkeypatch):
    projects = tmp_path / "projects"
    monkeypatch.setattr("agentwatch.cc_stats.CLAUDE_PROJECTS_DIR", projects)
    monkeypatch.setattr("agentwatch.agents.ADAPTERS", [ClaudeCodeAdapter()])
    return projects / "-tmp-proj"


def test_json_outputs_carry_fingerprint_not_value(cc_env):
    log = _cc_log(cc_env / "s.jsonl", [f"x {KEY_A}", f"z {KEY_B}"])
    runner = CliRunner()
    audit = runner.invoke(cli, ["audit", "--all", "--json"])
    fps = {f["fingerprint"] for f in json.loads(audit.stdout)["findings"]
           if f["secret_type"] == "github_pat"}
    assert fps == {secret_fingerprint(KEY_A), secret_fingerprint(KEY_B)}
    scan = runner.invoke(cli, ["security-scan", "--log", str(log), "--json"])
    leaks = [w for w in json.loads(scan.stdout)["warnings"] if w["signal"] == "secret_leak"]
    assert {w["details"]["fingerprint"] for w in leaks} == fps
    _assert_no_value([audit.stdout, scan.stdout], KEY_A, KEY_B)


def test_history_stores_one_row_per_secret_and_resync_replaces(cc_env):
    log = _cc_log(cc_env / "s.jsonl", [f"x {KEY_A}", f"z {KEY_B}"])
    conn = history.connect()
    history.sync(conn)
    rows = conn.execute("SELECT key_hash FROM findings WHERE signal='secret_leak'").fetchall()
    assert len(rows) == 2
    # A changed log is re-scanned and its findings replaced, not added to.
    _cc_log(log, [f"x {KEY_A}", f"z {KEY_B}", f"again {KEY_A}"])
    os.utime(log, (time.time() - 3000, time.time() - 3000))
    history.sync(conn)
    again = conn.execute("SELECT key_hash FROM findings WHERE signal='secret_leak'").fetchall()
    assert sorted(again) == sorted(rows)
    dump = "\n".join(conn.iterdump())
    assert KEY_A not in dump and KEY_B not in dump
    assert secret_fingerprint(KEY_A) not in dump  # only a hash of the dedup key


# --- audit: one finding per value (QA #220 B) ----------------------------------

def _user_log(path: Path, texts: list[str]) -> Path:
    path.write_text("".join(json.dumps({
        "type": "user", "timestamp": "2026-03-01T12:00:00Z",
        "message": {"role": "user", "content": t}}) + "\n" for t in texts))
    return path


def _tokens(n: int) -> list[str]:
    import random
    import string
    rnd = random.Random(7)
    return ["ghp_" + "".join(rnd.choice(string.ascii_letters + string.digits)
                             for _ in range(36)) for _ in range(n)]


def test_audit_reports_each_value_once_under_the_live_scanners_pattern(tmp_path):
    # Each token is also a bearer token, a bearer header, a key=value secret
    # and a high-entropy string; it is one github_pat finding, as live.
    tokens = _tokens(200)
    log = _user_log(tmp_path / "s.jsonl",
                    [f"export GITHUB_TOKEN={t}\nAuthorization: Bearer {t}" for t in tokens])
    found = audit_log_file(log)
    assert len(found) == 200
    assert {f.secret_type for f in found} == {"github_pat"}
    assert {f.fingerprint for f in found} == {secret_fingerprint(t) for t in tokens}


def test_audit_same_value_repeated_is_one_finding(tmp_path):
    (token,) = _tokens(1)
    log = _user_log(tmp_path / "s.jsonl",
                    [f"export GITHUB_TOKEN={token}\nAuthorization: Bearer {token}"] * 50)
    assert [f.secret_type for f in audit_log_file(log)] == ["github_pat"]


def test_audit_and_live_scanner_pick_the_same_types(tmp_path):
    (token,) = _tokens(1)
    text = (f"GITHUB_TOKEN={token}\nAuthorization: Bearer {token}\n"
            "DATABASE_URL=postgres://admin:Zq7wErTy9uIoPaSdFgHjKl2@db.example.net/app\n")
    log = tmp_path / "s.jsonl"
    log.write_text(json.dumps({"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "x", "content": text}]}}) + "\n")
    audit = sorted(f.secret_type for f in audit_log_file(log))
    live = sorted(w.details["secret_type"] for w in SecretLeakScanner()._scan_action(
        Action(timestamp=T0, tool_name="Bash", tool_type=ToolType.BASH, success=True,
               incoming_message=text)))
    assert audit == live and "github_pat" in audit and "bearer_token" not in audit


# --- key file self-repair (QA #220 A) -------------------------------------------

def _key_path() -> Path:
    directory = history.data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    return directory / sc._FINGERPRINT_KEY_FILE


@pytest.mark.parametrize("content", [b"", b"\x01" * 7], ids=["empty", "truncated"])
def test_old_broken_key_file_is_replaced_and_then_reused(monkeypatch, content):
    monkeypatch.setattr(sc, "_KEY_READ_TRIES", 1)
    path = _key_path()
    path.write_bytes(content)
    old = time.time() - 60
    os.utime(path, (old, old))
    key = sc._load_fingerprint_key()
    assert key is not None and len(key) == 32 and path.read_bytes() == key
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
    assert sc._load_fingerprint_key() == key  # stable from now on
    assert not [p for p in path.parent.iterdir() if p.suffix == ".tmp"]


def test_fresh_broken_key_file_is_left_to_its_writer(monkeypatch):
    monkeypatch.setattr(sc, "_KEY_READ_TRIES", 1)
    path = _key_path()
    path.write_bytes(b"\x01" * 7)  # just written: maybe another process mid-write
    assert sc._load_fingerprint_key() is None
    assert path.read_bytes() == b"\x01" * 7


@pytest.mark.skipif(os.name != "posix", reason="symlinks need privileges on Windows")
def test_symlinked_key_file_is_refused_not_replaced(tmp_path, monkeypatch):
    monkeypatch.setattr(sc, "_KEY_READ_TRIES", 1)
    target = tmp_path / "elsewhere"
    target.write_bytes(b"")
    path = _key_path()
    path.symlink_to(target)
    old = time.time() - 60
    os.utime(path, (old, old), follow_symlinks=False)
    assert sc._load_fingerprint_key() is None
    assert path.is_symlink() and target.read_bytes() == b""


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership")
def test_key_file_owned_by_someone_else_is_refused(monkeypatch):
    monkeypatch.setattr(sc, "_KEY_READ_TRIES", 1)
    path = _key_path()
    path.write_bytes(b"")
    old = time.time() - 60
    os.utime(path, (old, old))
    uid = os.getuid()
    monkeypatch.setattr("agentwatch.coach._private_dir", lambda d: True)  # the dir is ours
    monkeypatch.setattr(sc.os, "getuid", lambda: uid + 1)  # the file is not
    assert sc._load_fingerprint_key() is None
    assert path.read_bytes() == b""


# --- channel labels of raw tool output (pinned; merging labels is separate) -----

def test_copilot_agy_opencode_raw_tool_output_keeps_tool_output_channel(tmp_path):
    from agentwatch.parser import parse_file
    from agentwatch.parser.opencode import _tool_action

    (token,) = _tokens(1)
    out = f"GITHUB_TOKEN={token}\n"
    copilot = tmp_path / "events.jsonl"
    copilot.write_text("".join(json.dumps(e) + "\n" for e in [
        {"type": "session.start", "timestamp": "2026-10-01T12:21:50Z",
         "data": {"sessionId": "s", "producer": "copilot-agent", "copilotVersion": "1.0.90",
                  "context": {"cwd": "/tmp/aw-test"}}},
        {"type": "tool.execution_start", "timestamp": "2026-10-01T12:21:56Z",
         "data": {"toolCallId": "c1", "toolName": "view", "arguments": {"path": "/tmp/.env"}}},
        {"type": "tool.execution_complete", "timestamp": "2026-10-01T12:21:57Z",
         "data": {"toolCallId": "c1", "success": True, "result": {"content": out}}},
    ]))
    agy = tmp_path / "transcript.jsonl"
    agy.write_text("".join(json.dumps(e) + "\n" for e in [
        {"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "status": "DONE",
         "created_at": "2026-10-01T12:38:27Z", "content": "<USER_REQUEST>\nread .env"},
        {"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "status": "DONE",
         "created_at": "2026-10-01T12:38:28Z", "tool_calls": [
             {"name": "view_file", "args": {"AbsolutePath": json.dumps("/tmp/.env")}}]},
        {"step_index": 2, "source": "MODEL", "type": "GENERIC", "status": "DONE",
         "created_at": "2026-10-01T12:38:29Z", "content": out},
    ]))
    opencode = _tool_action({"tool": "read", "state": {
        "status": "completed", "input": {"filePath": "/tmp/.env"}, "output": out,
        "time": {"start": 1, "end": 2}}}, "ses_x")

    for actions in (list(parse_file(copilot)), list(parse_file(agy)), [opencode]):
        channels = {ch for a in actions for text, ch, _ in sc.extract_scannable_content(a)
                    if token in text}
        assert channels == {"tool_output"}
        buf = ActionBuffer()
        for a in actions:
            buf.add(a)
        assert {w.details["channel"] for w in SecretLeakScanner().check_many(buf)} == {
            "tool_output"}
