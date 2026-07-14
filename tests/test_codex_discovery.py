"""Tests for Codex CLI session-log resolution in `agentwatch.discovery`.

Covers `_resolve_codex_log()` (cwd-match path and mtime-fallback path) and
its `_read_codex_session_meta()` helper, against hand-authored fixture
`session_meta` lines -- no live Codex CLI install is available (see
`codex-cli-support-prd.md`'s Open Questions), so these fixtures encode the
PRD's researched-but-unconfirmed envelope shape
(`{"type": "session_meta", "payload": {"cwd": ..., "id": ...}}`).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

from agentwatch.discovery import _read_codex_session_meta, _resolve_codex_log


def _session_meta_line(session_id: str, cwd: str, cli_version: str = "0.45.0") -> dict:
    return {
        "timestamp": "2026-07-12T10:00:00Z",
        "type": "session_meta",
        "payload": {"id": session_id, "cwd": cwd, "cli_version": cli_version},
    }


def _write_jsonl(path: Path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


def _day_bucket(codex_home: Path, days_back: int = 0) -> Path:
    day = datetime.now() - timedelta(days=days_back)
    return codex_home / "sessions" / f"{day:%Y}" / f"{day:%m}" / f"{day:%d}"


# ---------------------------------------------------------------------------
# _read_codex_session_meta
# ---------------------------------------------------------------------------


class TestReadCodexSessionMeta:
    def test_finds_session_meta_as_first_line(self, tmp_path):
        rollout = tmp_path / "rollout-1.jsonl"
        _write_jsonl(
            rollout,
            [
                _session_meta_line("sess-1", "/home/user/proj"),
                {"timestamp": "t", "type": "turn_context", "payload": {}},
            ],
        )
        meta = _read_codex_session_meta(rollout)
        assert meta is not None
        assert meta["cwd"] == "/home/user/proj"
        assert meta["id"] == "sess-1"

    def test_finds_session_meta_within_bounded_window(self, tmp_path):
        rollout = tmp_path / "rollout-2.jsonl"
        _write_jsonl(
            rollout,
            [
                {"timestamp": "t", "type": "turn_context", "payload": {}},
                {"timestamp": "t", "type": "event_msg", "payload": {"type": "agent_message"}},
                _session_meta_line("sess-2", "/home/user/proj2"),
            ],
        )
        meta = _read_codex_session_meta(rollout, max_lines=5)
        assert meta is not None
        assert meta["cwd"] == "/home/user/proj2"

    def test_returns_none_when_session_meta_outside_bounded_window(self, tmp_path):
        rollout = tmp_path / "rollout-3.jsonl"
        filler = [{"timestamp": "t", "type": "turn_context", "payload": {}} for _ in range(5)]
        _write_jsonl(rollout, filler + [_session_meta_line("sess-3", "/x")])
        meta = _read_codex_session_meta(rollout, max_lines=3)
        assert meta is None

    def test_returns_none_for_nonexistent_file(self, tmp_path):
        assert _read_codex_session_meta(tmp_path / "does-not-exist.jsonl") is None

    def test_returns_none_for_malformed_json_lines(self, tmp_path):
        rollout = tmp_path / "rollout-4.jsonl"
        rollout.write_text("{not valid json\n{also not valid\n", encoding="utf-8")
        assert _read_codex_session_meta(rollout) is None

    def test_skips_blank_lines(self, tmp_path):
        rollout = tmp_path / "rollout-5.jsonl"
        with open(rollout, "w", encoding="utf-8") as f:
            f.write("\n")
            f.write(json.dumps(_session_meta_line("sess-5", "/y")) + "\n")
        meta = _read_codex_session_meta(rollout)
        assert meta is not None
        assert meta["cwd"] == "/y"


# ---------------------------------------------------------------------------
# _resolve_codex_log
# ---------------------------------------------------------------------------


class TestResolveCodexLog:
    def test_no_codex_home_returns_none(self, tmp_path, monkeypatch):
        missing = tmp_path / "no-such-codex-home"
        monkeypatch.setenv("CODEX_HOME", str(missing))
        log_file, session_id = _resolve_codex_log(cwd=tmp_path)
        assert log_file is None
        assert session_id is None

    def test_no_sessions_for_today_or_yesterday_returns_none(self, tmp_path, monkeypatch):
        codex_home = tmp_path / ".codex"
        (codex_home / "sessions").mkdir(parents=True)
        monkeypatch.setenv("CODEX_HOME", str(codex_home))
        log_file, session_id = _resolve_codex_log(cwd=tmp_path)
        assert log_file is None
        assert session_id is None

    def test_cwd_match_path_returns_matching_file(self, tmp_path, monkeypatch):
        codex_home = tmp_path / ".codex"
        target_cwd = tmp_path / "myproject"
        target_cwd.mkdir()
        other_cwd = tmp_path / "otherproject"
        other_cwd.mkdir()

        bucket = _day_bucket(codex_home)
        matching = bucket / "rollout-2026-07-12-aaa.jsonl"
        non_matching = bucket / "rollout-2026-07-12-bbb.jsonl"
        _write_jsonl(matching, [_session_meta_line("sess-match", str(target_cwd))])
        _write_jsonl(non_matching, [_session_meta_line("sess-other", str(other_cwd))])

        monkeypatch.setenv("CODEX_HOME", str(codex_home))
        log_file, session_id = _resolve_codex_log(cwd=target_cwd)

        assert log_file == matching
        assert session_id == "sess-match"

    def test_mtime_fallback_when_no_cwd_matches(self, tmp_path, monkeypatch):
        codex_home = tmp_path / ".codex"
        target_cwd = tmp_path / "myproject"
        target_cwd.mkdir()
        unrelated_cwd = tmp_path / "unrelated"
        unrelated_cwd.mkdir()

        bucket = _day_bucket(codex_home)
        older = bucket / "rollout-2026-07-12-older.jsonl"
        newer = bucket / "rollout-2026-07-12-newer.jsonl"
        _write_jsonl(older, [_session_meta_line("sess-older", str(unrelated_cwd))])
        _write_jsonl(newer, [_session_meta_line("sess-newer", str(unrelated_cwd))])

        # Force a clear mtime ordering (filesystem mtime resolution can be
        # coarse) so "newer" is unambiguously the most recently modified.
        import os
        import time

        now = time.time()
        os.utime(older, (now - 100, now - 100))
        os.utime(newer, (now, now))

        monkeypatch.setenv("CODEX_HOME", str(codex_home))
        log_file, session_id = _resolve_codex_log(cwd=target_cwd)

        assert log_file == newer
        assert session_id == "sess-newer"

    def test_mtime_fallback_when_session_meta_unreadable(self, tmp_path, monkeypatch):
        codex_home = tmp_path / ".codex"
        target_cwd = tmp_path / "myproject"
        target_cwd.mkdir()

        bucket = _day_bucket(codex_home)
        broken = bucket / "rollout-2026-07-12-broken.jsonl"
        bucket.mkdir(parents=True)
        broken.write_text("not json at all\n", encoding="utf-8")

        monkeypatch.setenv("CODEX_HOME", str(codex_home))
        log_file, session_id = _resolve_codex_log(cwd=target_cwd)

        assert log_file == broken
        assert session_id is None

    def test_honors_codex_home_env_var_single_root(self, tmp_path, monkeypatch):
        custom_root = tmp_path / "custom-codex-root"
        target_cwd = tmp_path / "myproject"
        target_cwd.mkdir()

        bucket = _day_bucket(custom_root)
        rollout = bucket / "rollout-2026-07-12-custom.jsonl"
        _write_jsonl(rollout, [_session_meta_line("sess-custom", str(target_cwd))])

        monkeypatch.setenv("CODEX_HOME", str(custom_root))
        log_file, session_id = _resolve_codex_log(cwd=target_cwd)

        assert log_file == rollout
        assert session_id == "sess-custom"

    def test_checks_yesterdays_bucket_too(self, tmp_path, monkeypatch):
        codex_home = tmp_path / ".codex"
        target_cwd = tmp_path / "myproject"
        target_cwd.mkdir()

        yesterday_bucket = _day_bucket(codex_home, days_back=1)
        rollout = yesterday_bucket / "rollout-yesterday.jsonl"
        _write_jsonl(rollout, [_session_meta_line("sess-yesterday", str(target_cwd))])

        monkeypatch.setenv("CODEX_HOME", str(codex_home))
        log_file, session_id = _resolve_codex_log(cwd=target_cwd)

        assert log_file == rollout
        assert session_id == "sess-yesterday"
