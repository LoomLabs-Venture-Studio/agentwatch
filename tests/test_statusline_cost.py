"""`agentwatch statusline --cost`: the current 5-hour block from a tmp HOME."""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import time
from datetime import UTC, datetime

import pytest

from agentwatch import cc_stats, coach, statusline

SID = "sess-1"
STDIN = json.dumps({"session_id": SID, "transcript_path": "/x.jsonl", "model": {}})
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC).timestamp()  # block 10:30 -> 10:00-15:00
SONNET = "claude-sonnet-4-5-20250929"


def _line(msg_id, ts, model=SONNET, inp=2_000_000, out=1_000_000):
    return json.dumps({
        "type": "assistant", "timestamp": ts,
        "message": {"id": msg_id, "model": model, "content": [],
                    "usage": {"input_tokens": inp, "output_tokens": out}},
    })


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Path.home() on Windows
    for var in ("XDG_CACHE_HOME", "CLAUDE_PLUGIN_DATA", "CLAUDE_CONFIG_DIR", "NO_COLOR"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(statusline, "_now", lambda: NOW)
    pdir = tmp_path / ".claude" / "projects" / "-p"
    pdir.mkdir(parents=True)
    # Other tests' monkeypatch.setattr of the lazy CLAUDE_PROJECTS_DIR leaves a
    # global behind on undo (often the real ~/.claude/projects); setitem
    # removes the key on undo instead.
    monkeypatch.setitem(vars(cc_stats), "CLAUDE_PROJECTS_DIR", pdir.parent)
    return pdir


def _log(pdir, *lines):
    path = pdir / "s.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.utime(path, (NOW, NOW))


def _plain(text):
    return text.replace(statusline._DIM, "").replace(statusline._RESET, "")


def test_active_block_spend_projection_and_reset(home):
    _log(home, _line("m1", "2026-10-30T10:30:00Z"))
    # $21 over 2 h -> $52.50 at 15:00 UTC, 3 h from now
    assert statusline.render(STDIN, cost=True) == (
        f"{statusline._DIM}5h $21.00 → ~$52.50 · resets 3h00m{statusline._RESET}")


def test_cache_hit_skips_scan_stale_cache_rescans(home, monkeypatch):
    _log(home, _line("m1", "2026-10-30T10:30:00Z"))
    assert "$21.00" in statusline.render(STDIN, cost=True)
    cache = coach.user_state_dir() / statusline.BLOCK_CACHE
    assert json.loads(cache.read_text())["block"]["cost_usd"] == 21.0

    def boom(**_):
        raise AssertionError("rescanned")
    monkeypatch.setattr(cc_stats, "compute_blocks", boom)
    monkeypatch.setattr(statusline, "_now", lambda: NOW + 600)  # 10 min later, warm cache
    os.utime(cache, (NOW + 590, NOW + 590))
    assert _plain(statusline.render(STDIN, cost=True)) == "5h $21.00 → ~$52.50 · resets 2h50m"

    os.utime(cache, (NOW + 500, NOW + 500))  # 100 s old: stale -> scan
    assert statusline.render(STDIN, cost=True) == ""  # the scan failed: fail open


def test_corrupt_cache_recomputes_or_shows_nothing(home):
    _log(home, _line("m1", "2026-10-30T10:30:00Z"))
    cache = coach.user_state_dir() / statusline.BLOCK_CACHE
    cache.parent.mkdir(parents=True)
    for junk, expect in (("{not json", "$21.00"), ("[1, 2]", "$21.00"),
                         ('{"block": {"end": "x"}}', ""), ('{"block": 7}', "")):
        cache.write_text(junk)
        os.utime(cache, (NOW, NOW))
        out = _plain(statusline.render(STDIN, cost=True))
        assert (expect in out) if expect else out == "", junk


def test_unpriced_model_shows_reset_only(home, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    _log(home, _line("m1", "2026-10-30T10:30:00Z", model="claude-opus-4-9"))
    assert statusline.render(STDIN, cost=True) == "5h resets 3h00m"


def test_no_active_block_no_segment(home):
    _log(home, _line("m1", "2026-10-30T04:00:00Z"))  # block ended 09:00
    assert statusline.render(STDIN, cost=True) == ""
    assert statusline.render(STDIN, ok=True, cost=True) == ""  # no coach state either


def test_old_transcripts_not_read(home):
    _log(home, _line("m1", "2026-10-30T10:30:00Z"))
    then = NOW - statusline.LOOKBACK_S - 1
    os.utime(home / "s.jsonl", (then, then))
    assert statusline.render(STDIN, cost=True) == ""


def test_joins_with_warning_and_ok(home, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    _log(home, _line("m1", "2026-10-30T10:30:00Z"))
    state = coach.state_dir()
    state.mkdir(parents=True, exist_ok=True)
    path = coach.state_path(state, SID)
    path.write_text(json.dumps({"warnings": []}))
    assert statusline.render(STDIN, ok=True, cost=True) == (
        "✓ agentwatch · 5h $21.00 → ~$52.50 · resets 3h00m")
    path.write_text(json.dumps({"warnings": [
        {"severity": "high", "signal": "loop", "cost_usd": 1.4}]}))
    assert statusline.render(STDIN, cost=True) == (
        "⚠ loop ~$1.40 · 5h $21.00 → ~$52.50 · resets 3h00m")


def test_cost_off_never_scans(home, monkeypatch):
    def boom(**_):
        raise AssertionError("scanned")
    monkeypatch.setattr(cc_stats, "compute_blocks", boom)
    _log(home, _line("m1", "2026-10-30T10:30:00Z"))
    assert statusline.render(STDIN) == ""
    assert statusline.render(STDIN, ok=False, cost=False) == statusline._health(STDIN, False)
    assert not (coach.user_state_dir() / statusline.BLOCK_CACHE).exists()


def test_projection_hidden_early_in_block_or_below_spend(home, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    _log(home, _line("m1", "2026-10-30T12:01:00Z"))  # block 12:00-17:00
    monkeypatch.setattr(statusline, "_now", lambda: NOW + 14 * 60)
    assert statusline.render(STDIN, cost=True) == "5h $21.00 · resets 4h46m"
    (coach.user_state_dir() / statusline.BLOCK_CACHE).unlink()
    monkeypatch.setattr(statusline, "_now", lambda: NOW + 15 * 60)
    assert "→ ~$" in statusline.render(STDIN, cost=True)

    cache = coach.user_state_dir() / statusline.BLOCK_CACHE
    cache.write_text(json.dumps({"block": {
        "end": NOW + 3 * 3600, "cost_usd": 21.0, "projected_cost_usd": 20.0}}))
    os.utime(cache, (NOW + 15 * 60, NOW + 15 * 60))
    assert statusline.render(STDIN, cost=True) == "5h $21.00 · resets 2h45m"


def test_cost_off_never_imports_cc_stats(home):
    code = ("import sys\nfrom agentwatch import statusline\n"
            f"statusline.render({STDIN!r}, ok=True, cost=sys.argv[1] == '1')\n"
            "print('agentwatch.cc_stats' in sys.modules)")
    for cost, imported in (("0", "False"), ("1", "True")):
        proc = subprocess.run([sys.executable, "-c", code, cost], capture_output=True,
                              text=True, timeout=60, check=True)
        assert proc.stdout.strip() == imported


def test_entry_fast_path_cost(home, tmp_path):
    now = time.time()
    ts = datetime.fromtimestamp(now - 1800, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    (home / "s.jsonl").write_text(_line("m1", ts) + "\n", encoding="utf-8")
    # Reports on stderr whether the full CLI was imported, after main()'s sys.exit(0).
    code = ("import atexit, sys\nfrom agentwatch._entry import main\n"
            "atexit.register(lambda: sys.stderr.write(str('agentwatch.cli' in sys.modules)))\n"
            "main()")
    env = dict(os.environ, NO_COLOR="1", CLAUDE_PLUGIN_DATA=str(tmp_path / "plugin"),
               CLAUDE_CONFIG_DIR=str(tmp_path / "no-config"))
    proc = subprocess.run([sys.executable, "-c", code, "statusline", "--cost"],
                          input=STDIN.encode(), capture_output=True, env=env, timeout=60)
    assert (proc.returncode, proc.stderr) == (0, b"False")
    assert re.fullmatch(r"5h \$21\.00 .*resets \dh\d\dm\n", proc.stdout.decode("utf-8"))


def test_main_exits_0_on_errors(home, monkeypatch, capsys):
    def boom(**_):
        raise RuntimeError("scan failed")
    monkeypatch.setattr(cc_stats, "compute_blocks", boom)
    for stdin in (STDIN.encode(), b"\xff garbage"):
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(stdin)))
        with pytest.raises(SystemExit) as exc:
            statusline.main(ok=True, cost=True)
        assert exc.value.code == 0
        assert capsys.readouterr() == ("", "")


def test_cache_written_private_and_replaced(home):
    _log(home, _line("m1", "2026-10-30T10:30:00Z"))
    statusline.render(STDIN, cost=True)
    directory = coach.user_state_dir()
    cache = directory / statusline.BLOCK_CACHE
    end = datetime(2026, 10, 30, 15, 0, tzinfo=UTC).timestamp()
    assert json.loads(cache.read_text()) == {
        "block": {"end": end, "cost_usd": 21.0, "projected_cost_usd": 52.5}}
    if os.name == "posix":
        assert directory.stat().st_mode & 0o777 == 0o700
    _log(home, _line("m1", "2026-10-30T10:30:00Z"), _line("m2", "2026-10-30T11:00:00Z"))
    os.utime(cache, (NOW - 100, NOW - 100))  # stale: the next render rescans
    statusline.render(STDIN, cost=True)
    assert json.loads(cache.read_text())["block"]["cost_usd"] == 42.0
    assert [p.name for p in directory.iterdir()] == [statusline.BLOCK_CACHE]  # no *.tmp
