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

import agentwatch.discovery as discovery
from agentwatch.discovery import (
    _find_open_codex_rollout,
    _read_codex_session_meta,
    _resolve_codex_log,
)


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


# ---------------------------------------------------------------------------
# _find_open_codex_rollout (PRD Open Question #5, PID-based resolution)
# ---------------------------------------------------------------------------


class _FakeOpenFile:
    def __init__(self, path):
        self.path = path


class TestFindOpenCodexRollout:
    """Mirrors ``TestFindOpenJsonl`` (discovery.py's Claude Code case) --
    uses psutil.Process.open_files() (cross-platform) instead of lsof."""

    def test_finds_matching_rollout_under_sessions_root(self, tmp_path, monkeypatch):
        sessions_root = tmp_path / "sessions"
        bucket = sessions_root / "2026" / "07" / "15"
        bucket.mkdir(parents=True)
        target = bucket / "rollout-2026-07-15-abc.jsonl"
        target.write_text("")

        class _FakeProcess:
            def __init__(self, pid):
                pass

            def open_files(self):
                return [_FakeOpenFile(str(target))]

        monkeypatch.setattr(discovery.psutil, "Process", _FakeProcess)

        assert _find_open_codex_rollout(pid=123, sessions_root=sessions_root) == target

    def test_ignores_files_outside_sessions_root(self, tmp_path, monkeypatch):
        sessions_root = tmp_path / "sessions"
        sessions_root.mkdir()
        outside = tmp_path / "other" / "rollout-x.jsonl"
        outside.parent.mkdir()
        outside.write_text("")

        class _FakeProcess:
            def __init__(self, pid):
                pass

            def open_files(self):
                return [_FakeOpenFile(str(outside))]

        monkeypatch.setattr(discovery.psutil, "Process", _FakeProcess)

        assert _find_open_codex_rollout(pid=123, sessions_root=sessions_root) is None

    def test_ignores_non_rollout_jsonl_files(self, tmp_path, monkeypatch):
        sessions_root = tmp_path / "sessions"
        bucket = sessions_root / "2026" / "07" / "15"
        bucket.mkdir(parents=True)
        other = bucket / "notes.jsonl"  # .jsonl suffix but not rollout- prefixed
        other.write_text("")

        class _FakeProcess:
            def __init__(self, pid):
                pass

            def open_files(self):
                return [_FakeOpenFile(str(other))]

        monkeypatch.setattr(discovery.psutil, "Process", _FakeProcess)

        assert _find_open_codex_rollout(pid=123, sessions_root=sessions_root) is None

    def test_ignores_non_jsonl_files(self, tmp_path, monkeypatch):
        sessions_root = tmp_path / "sessions"
        bucket = sessions_root / "2026" / "07" / "15"
        bucket.mkdir(parents=True)
        notes = bucket / "rollout-notes.txt"
        notes.write_text("")

        class _FakeProcess:
            def __init__(self, pid):
                pass

            def open_files(self):
                return [_FakeOpenFile(str(notes))]

        monkeypatch.setattr(discovery.psutil, "Process", _FakeProcess)

        assert _find_open_codex_rollout(pid=123, sessions_root=sessions_root) is None

    def test_returns_none_on_access_denied(self, tmp_path, monkeypatch):
        sessions_root = tmp_path / "sessions"
        sessions_root.mkdir()

        class _FakeProcess:
            def __init__(self, pid):
                raise discovery.psutil.AccessDenied(pid)

        monkeypatch.setattr(discovery.psutil, "Process", _FakeProcess)

        assert _find_open_codex_rollout(pid=123, sessions_root=sessions_root) is None

    def test_returns_none_on_no_such_process(self, tmp_path, monkeypatch):
        sessions_root = tmp_path / "sessions"
        sessions_root.mkdir()

        class _FakeProcess:
            def __init__(self, pid):
                raise discovery.psutil.NoSuchProcess(pid)

        monkeypatch.setattr(discovery.psutil, "Process", _FakeProcess)

        assert _find_open_codex_rollout(pid=123, sessions_root=sessions_root) is None

    def test_returns_none_when_file_no_longer_exists(self, tmp_path, monkeypatch):
        sessions_root = tmp_path / "sessions"
        bucket = sessions_root / "2026" / "07" / "15"
        bucket.mkdir(parents=True)
        gone = bucket / "rollout-gone.jsonl"  # never created on disk

        class _FakeProcess:
            def __init__(self, pid):
                pass

            def open_files(self):
                return [_FakeOpenFile(str(gone))]

        monkeypatch.setattr(discovery.psutil, "Process", _FakeProcess)

        assert _find_open_codex_rollout(pid=123, sessions_root=sessions_root) is None


# ---------------------------------------------------------------------------
# _resolve_codex_log -- PID-based resolution preferred over cwd heuristic
# ---------------------------------------------------------------------------


class TestResolveCodexLogPidResolution:
    def test_pid_match_found_is_preferred_over_cwd_heuristic(self, tmp_path, monkeypatch):
        """A PID-based open-file match should win even when a *different*
        file would otherwise match on cwd via the session_meta heuristic --
        it's authoritative, so it bypasses that heuristic entirely."""
        codex_home = tmp_path / ".codex"
        target_cwd = tmp_path / "myproject"
        target_cwd.mkdir()

        bucket = _day_bucket(codex_home)
        cwd_matching = bucket / "rollout-2026-07-15-cwdmatch.jsonl"
        pid_matching = bucket / "rollout-2026-07-15-pidmatch.jsonl"
        _write_jsonl(cwd_matching, [_session_meta_line("sess-cwd", str(target_cwd))])
        _write_jsonl(pid_matching, [_session_meta_line("sess-pid", str(target_cwd))])

        monkeypatch.setenv("CODEX_HOME", str(codex_home))

        class _FakeProcess:
            def __init__(self, pid):
                pass

            def open_files(self):
                return [_FakeOpenFile(str(pid_matching))]

        monkeypatch.setattr(discovery.psutil, "Process", _FakeProcess)

        log_file, session_id = _resolve_codex_log(cwd=target_cwd, pid=123)

        assert log_file == pid_matching
        assert session_id == "sess-pid"

    def test_pid_match_not_found_falls_through_to_existing_heuristic(self, tmp_path, monkeypatch):
        """When the PID has no matching open rollout file, behavior is
        unchanged from the pre-existing cwd-match/mtime-fallback path."""
        codex_home = tmp_path / ".codex"
        target_cwd = tmp_path / "myproject"
        target_cwd.mkdir()

        bucket = _day_bucket(codex_home)
        matching = bucket / "rollout-2026-07-15-cwdmatch.jsonl"
        _write_jsonl(matching, [_session_meta_line("sess-match", str(target_cwd))])

        monkeypatch.setenv("CODEX_HOME", str(codex_home))

        class _FakeProcess:
            def __init__(self, pid):
                pass

            def open_files(self):
                return []  # nothing open matching the rollout pattern

        monkeypatch.setattr(discovery.psutil, "Process", _FakeProcess)

        log_file, session_id = _resolve_codex_log(cwd=target_cwd, pid=123)

        assert log_file == matching
        assert session_id == "sess-match"

    def test_access_denied_on_pid_lookup_falls_through_gracefully(self, tmp_path, monkeypatch):
        """AccessDenied/NoSuchProcess during the PID-based lookup must not
        raise -- it should fall through to the existing heuristic, the same
        graceful handling _get_process_cwd already has."""
        codex_home = tmp_path / ".codex"
        target_cwd = tmp_path / "myproject"
        target_cwd.mkdir()

        bucket = _day_bucket(codex_home)
        matching = bucket / "rollout-2026-07-15-cwdmatch.jsonl"
        _write_jsonl(matching, [_session_meta_line("sess-match", str(target_cwd))])

        monkeypatch.setenv("CODEX_HOME", str(codex_home))

        class _FakeProcess:
            def __init__(self, pid):
                raise discovery.psutil.AccessDenied(pid)

        monkeypatch.setattr(discovery.psutil, "Process", _FakeProcess)

        log_file, session_id = _resolve_codex_log(cwd=target_cwd, pid=123)

        assert log_file == matching
        assert session_id == "sess-match"

    def test_no_pid_given_behaves_exactly_as_before(self, tmp_path, monkeypatch):
        """pid=None (the default) must skip PID-based resolution entirely
        and never touch psutil.Process, matching pre-existing callers."""
        codex_home = tmp_path / ".codex"
        target_cwd = tmp_path / "myproject"
        target_cwd.mkdir()

        bucket = _day_bucket(codex_home)
        matching = bucket / "rollout-2026-07-15-cwdmatch.jsonl"
        _write_jsonl(matching, [_session_meta_line("sess-match", str(target_cwd))])

        monkeypatch.setenv("CODEX_HOME", str(codex_home))

        def _explode(pid):
            raise AssertionError("psutil.Process should not be called when pid is None")

        monkeypatch.setattr(discovery.psutil, "Process", _explode)

        log_file, session_id = _resolve_codex_log(cwd=target_cwd)

        assert log_file == matching
        assert session_id == "sess-match"
