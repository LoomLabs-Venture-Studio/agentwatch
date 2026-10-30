"""`agentwatch statusline --cost`: the current 5-hour block from a tmp HOME."""

from __future__ import annotations

import json
import os
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
    for var in ("XDG_CACHE_HOME", "CLAUDE_PLUGIN_DATA", "CLAUDE_CONFIG_DIR", "NO_COLOR"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(statusline, "_now", lambda: NOW)
    pdir = tmp_path / ".claude" / "projects" / "-p"
    pdir.mkdir(parents=True)
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
