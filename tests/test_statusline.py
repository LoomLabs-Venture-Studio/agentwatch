"""`agentwatch statusline`: one short word in Claude Code's status line."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from agentwatch import coach, statusline
from agentwatch.cli import cli
from agentwatch.detectors.base import Category, Severity, Warning

SID = "sess-1"
ENTRY = [sys.executable, "-c", "from agentwatch._entry import main; main()", "statusline"]


@pytest.fixture(autouse=True)
def _dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(statusline, "state_dirs", lambda: [tmp_path / "state"])
    monkeypatch.delenv("NO_COLOR", raising=False)


def _state(tmp_path: Path, warnings: list[dict], session: str = SID, age_s: float = 0) -> Path:
    directory = tmp_path / "state"
    directory.mkdir(exist_ok=True)
    path = coach.state_path(directory, session)
    path.write_text(json.dumps({"updated": "x", "reported": [], "warnings": warnings}),
                    encoding="utf-8")
    if age_s:
        then = time.time() - age_s
        os.utime(path, (then, then))
    return path


def _w(signal: str, severity: str = "high", cost: float | None = None) -> dict:
    w = {"severity": severity, "signal": signal, "message": "m"}
    if cost is not None:
        w["cost_usd"] = cost
    return w


def _stdin(session: str = SID) -> str:
    return json.dumps({"session_id": session, "transcript_path": "/x.jsonl",
                       "model": {"display_name": "Opus"}, "cost": {"total_cost_usd": 3.2}})


def _plain(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


@pytest.mark.parametrize(("signal", "label"), [
    ("loop", "loop"), ("reread", "loop"),
    ("thrash", "thrash"), ("file_churn", "thrash"), ("syntax_loop", "thrash"),
    ("error_spiral", "errors"), ("error_blindness", "errors"),
    ("high_error_rate", "errors"), ("error_class_persistence", "errors"),
    ("stall", "stuck"), ("same_outcome", "stuck"), ("exploration_stall", "stuck"),
])
def test_label_mapping(tmp_path, signal, label):
    _state(tmp_path, [_w(signal)])
    assert _plain(statusline.render(_stdin())) == f"⚠ {label}"


@pytest.mark.parametrize("warning", [
    _w("context_critical"), _w("context_pressure", "critical"), _w("rediscovery"),
    _w("credential_access", "critical"), _w("loop", "medium"), _w("loop", "low"),
])
def test_context_security_and_minor_warnings_are_not_shown(tmp_path, warning):
    _state(tmp_path, [warning])
    assert statusline.render(_stdin()) == ""


def test_most_severe_warning_wins(tmp_path):
    _state(tmp_path, [_w("loop", cost=0.5), _w("error_spiral", "critical", cost=2.0),
                      _w("thrash", "critical")])
    assert _plain(statusline.render(_stdin())) == "⚠ errors ~$2.00"


@pytest.mark.parametrize(("cost", "text"), [
    (1.4, " ~$1.40"), (1234.5, " ~$1,234.50"), (0.001, " <$0.01"), (None, ""),
    ("1.4", ""), (True, ""), (0, " <$0.01"), (0.005, " <$0.01"), (0.0099, " <$0.01"),
    (0.01, " ~$0.01"), (9999.99, " ~$9,999.99"), (10_000, ""), (1e300, ""), (-0.5, ""),
    (float("nan"), ""), (float("inf"), ""), (float("-inf"), ""),
])
def test_cost_formatting(tmp_path, cost, text):
    _state(tmp_path, [_w("loop", cost=cost)])
    assert _plain(statusline.render(_stdin())) == f"⚠ loop{text}"


def test_colors_by_severity_and_no_color(tmp_path, monkeypatch):
    _state(tmp_path, [_w("loop")])
    assert statusline.render(_stdin()).startswith("\x1b[33m")  # HIGH: yellow
    _state(tmp_path, [_w("loop", "critical")])
    assert statusline.render(_stdin()).startswith("\x1b[31m")  # CRITICAL: red
    monkeypatch.setenv("NO_COLOR", "1")
    assert statusline.render(_stdin()) == "⚠ loop"


def test_healthy_prints_nothing_unless_ok(tmp_path, monkeypatch):
    _state(tmp_path, [_w("context_critical")])
    assert statusline.render(_stdin()) == ""
    assert statusline.render(_stdin(), ok=True) == "\x1b[2m✓ agentwatch\x1b[0m"
    monkeypatch.setenv("NO_COLOR", "1")
    assert statusline.render(_stdin(), ok=True) == "✓ agentwatch"


def test_no_state_prints_nothing_even_with_ok(tmp_path):
    # No coach run for this session yet (or no coach): no check to report as ok.
    assert statusline.render(_stdin(), ok=True) == ""
    _state(tmp_path, [_w("loop")], session="other")
    assert statusline.render(_stdin(), ok=True) == ""


def test_stale_state_prints_nothing(tmp_path):
    _state(tmp_path, [_w("loop")], age_s=statusline.STALE_S + 30)
    assert statusline.render(_stdin()) == ""
    assert statusline.render(_stdin(), ok=True) == ""
    _state(tmp_path, [_w("loop")], age_s=statusline.STALE_S - 30)
    assert _plain(statusline.render(_stdin())) == "⚠ loop"


def test_newest_state_across_dirs_wins(tmp_path, monkeypatch):
    old, new = tmp_path / "a", tmp_path / "b"
    for directory, signal, age in ((old, "loop", 60), (new, "thrash", 0)):
        directory.mkdir()
        path = coach.state_path(directory, SID)
        path.write_text(json.dumps({"warnings": [_w(signal)]}), encoding="utf-8")
        os.utime(path, (time.time() - age,) * 2)
    monkeypatch.setattr(statusline, "state_dirs", lambda: [old, new])
    assert _plain(statusline.render(_stdin())) == "⚠ thrash"


def test_state_dirs_cover_plugin_data_and_user_dir(tmp_path, monkeypatch):
    # The statusline runs from settings.json, without CLAUDE_PLUGIN_DATA, so it
    # finds the plugin's coach dir under the Claude config dir itself.
    _real_dirs(tmp_path, monkeypatch)
    data = tmp_path / "plugins" / "data"
    plugin = data / "agentwatch-agentwatch" / "coach"  # <name>-<marketplace>
    inline = data / "agentwatch-inline" / "coach"  # --plugin-dir
    for d in (plugin, inline, data / "other-plugin" / "coach", data / "agentwatchx" / "coach"):
        d.mkdir(parents=True)
    dirs = statusline.state_dirs()
    assert plugin in dirs and inline in dirs
    assert coach.user_state_dir() in dirs
    assert not any("other-plugin" in str(d) or "agentwatchx" in str(d) for d in dirs)


def _real_dirs(tmp_path, monkeypatch):
    monkeypatch.undo()
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "local"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))  # undone above too


def test_pointer_from_the_hook_beats_a_planted_plugin_dir(tmp_path, monkeypatch):
    # A planted plugins/data/agentwatch-evil/coach/<sid>.json must not hide or
    # override the real warning once the hook has recorded where it writes.
    _real_dirs(tmp_path, monkeypatch)
    data = tmp_path / "plugins" / "data"
    real, evil = data / "agentwatch-agentwatch" / "coach", data / "agentwatch-evil" / "coach"
    for directory, warnings, age in ((real, [_w("loop", cost=1.4)], 60), (evil, [], 0)):
        directory.mkdir(parents=True)
        path = coach.state_path(directory, SID)
        path.write_text(json.dumps({"warnings": warnings}), encoding="utf-8")
        os.utime(path, (time.time() - age,) * 2)
    coach._write_pointer(real)
    assert evil not in statusline.state_dirs()
    assert _plain(statusline.render(_stdin())) == "⚠ loop ~$1.40"


@pytest.mark.parametrize("stdin", [
    "", "not json", "[1, 2]", "{}", '{"session_id": 5}', '{"session_id": null}',
])
def test_fail_open_on_garbage_stdin(tmp_path, stdin):
    _state(tmp_path, [_w("loop")])
    assert statusline.render(stdin, ok=True) == ""


@pytest.mark.parametrize("content", [
    "garbage", "[]", '{"warnings": 5}', '{"warnings": [5, "x", null]}',
    '{"warnings": [{"severity": "high"}]}', '{"warnings": [{"signal": ["loop"]}]}',
])
def test_fail_open_on_garbage_state(tmp_path, content):
    _state(tmp_path, [])
    coach.state_path(tmp_path / "state", SID).write_text(content, encoding="utf-8")
    assert _plain(statusline.render(_stdin())) == ""


def test_session_id_cannot_escape_state_dir(tmp_path):
    (tmp_path / "evil.json").write_text(json.dumps({"warnings": [_w("loop")]}))
    assert statusline.render(_stdin("../evil")) == ""


def test_coach_snapshot_stores_cost(tmp_path):
    path = tmp_path / "s.json"
    warnings = [
        Warning(Category.PROGRESS, Severity.HIGH, "loop", "m", cost_usd=1.23456),
        Warning(Category.ERRORS, Severity.HIGH, "error_spiral", "m"),
    ]
    coach._save(path, set(), warnings)
    saved = json.loads(path.read_text(encoding="utf-8"))["warnings"]
    assert saved[0]["cost_usd"] == 1.2346
    assert "cost_usd" not in saved[1]


def test_coach_state_feeds_statusline(tmp_path, monkeypatch):
    monkeypatch.setattr(coach, "state_dir", lambda: tmp_path / "state")
    entries = []
    for i in range(8):  # the same failing command 8 times: a HIGH loop
        ts = f"2026-10-17T10:00:{i:02d}Z"
        entries += [
            {"type": "assistant", "timestamp": ts, "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": f"t{i}", "name": "Bash",
                 "input": {"command": "pytest"}}]}},
            {"type": "user", "timestamp": ts, "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": f"t{i}", "is_error": True,
                 "content": "AssertionError: boom"}]}},
        ]
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")
    coach.run(json.dumps({"session_id": SID, "transcript_path": str(transcript),
                          "hook_event_name": "PostToolUse"}))
    assert _plain(statusline.render(_stdin())) in {"⚠ loop", "⚠ errors"}


def test_cli_command(tmp_path):
    _state(tmp_path, [_w("loop", cost=1.4)])
    result = CliRunner().invoke(cli, ["statusline"], input=_stdin(), env={"NO_COLOR": "1"})
    assert result.exit_code == 0
    assert result.output == "⚠ loop ~$1.40\n"


def _env(tmp_path: Path) -> dict:
    env = dict(os.environ, CLAUDE_PLUGIN_DATA=str(tmp_path), NO_COLOR="1")
    env["CLAUDE_CONFIG_DIR"] = str(tmp_path / "no-config")
    return env


def test_entry_fast_path_prints_utf8_and_fails_open(tmp_path):
    directory = tmp_path / "coach"
    directory.mkdir()
    coach.state_path(directory, SID).write_text(
        json.dumps({"warnings": [_w("loop", cost=1.4)]}), encoding="utf-8")
    bom = b"\xef\xbb\xbf"  # a PowerShell pipe adds one
    proc = subprocess.run(ENTRY, input=bom + _stdin().encode(), capture_output=True,
                          env=_env(tmp_path), timeout=60)
    assert (proc.returncode, proc.stdout.decode("utf-8")) == (0, "⚠ loop ~$1.40\n")
    proc = subprocess.run(ENTRY, input=b"\xff garbage", capture_output=True,
                          env=_env(tmp_path), timeout=60)
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")


def test_entry_imports_nothing_heavy():
    code = ("import sys\nfrom agentwatch._entry import main\nfrom agentwatch import statusline\n"
            "print(' '.join(sorted(sys.modules)))")
    mods = set(subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                              timeout=60, check=True).stdout.split())
    heavy = {"click", "textual", "pydantic", "psutil", "watchfiles", "agentwatch.cli",
             "agentwatch.parser", "agentwatch.detectors", "agentwatch.cc_stats"}
    assert not mods & heavy


def test_latency_smoke(tmp_path):
    # Generous bound for CI; the target is < 150 ms wall on Windows (see PR).
    directory = tmp_path / "coach"
    directory.mkdir()
    coach.state_path(directory, SID).write_text(json.dumps({"warnings": [_w("loop")]}))
    times = []
    for _ in range(3):
        start = time.perf_counter()
        subprocess.run(ENTRY, input=_stdin().encode(), capture_output=True,
                       env=_env(tmp_path), timeout=60, check=True)
        times.append(time.perf_counter() - start)
    assert min(times) < 2.0


def test_empty_or_relative_pointer_falls_back_to_plugin_glob(tmp_path, monkeypatch):
    _real_dirs(tmp_path, monkeypatch)
    plugin = tmp_path / "plugins" / "data" / "agentwatch-inline" / "coach"
    plugin.mkdir(parents=True)
    pointer = coach.user_state_dir() / coach.POINTER
    pointer.parent.mkdir(parents=True)
    for text in ("", "relative/dir"):
        pointer.write_text(text, encoding="utf-8")
        dirs = statusline.state_dirs()
        assert plugin in dirs and Path(".") not in dirs and Path("relative/dir") not in dirs
