"""Tests for DiscoveryCache memoization in find_running_agents().

Added alongside the fix that made find_running_agents() reuse cached
cwd/log-file resolutions across repeated scans instead of re-resolving cwd
for every already-known PID on every poll tick (the multi-agent UI re-scans
every 5s). These tests fake out ``psutil.process_iter``/``_get_process_cwd``
entirely and assert the expensive per-PID resolution functions are only
invoked once across two scans with the same cache, then re-invoked if the
cached log path goes stale.
"""

from __future__ import annotations

import types

import agentwatch.discovery as discovery
from agentwatch.discovery import DiscoveryCache, find_running_agents


class _FakeProcess:
    """Stand-in for a psutil.Process yielded by process_iter(attrs=[...]).

    Exposes an ``.info`` dict the way psutil does when ``attrs`` is passed
    to ``process_iter`` — real code reads process fields via ``proc.info``,
    never by calling methods on the Process object directly.
    """

    def __init__(self, pid: int, ppid: int = 1, cmdline=None):
        self.info = {
            "pid": pid,
            "ppid": ppid,
            "cmdline": cmdline if cmdline is not None else ["claude", "--resume"],
            "name": "claude",
            "memory_info": types.SimpleNamespace(rss=1024 * 1024),
            "cpu_percent": 0.0,
            "create_time": 1_700_000_000.0,
        }


def _fake_process_iter(pid: int):
    def _iter(attrs=None):
        return iter([_FakeProcess(pid)])

    return _iter


class TestDiscoveryCacheMemoization:
    def test_cached_pid_skips_lsof_on_second_scan(self, tmp_path, monkeypatch):
        pid = 54321

        monkeypatch.setattr(discovery.psutil, "process_iter", _fake_process_iter(pid))

        cwd_calls = {"count": 0}
        log_calls = {"count": 0}

        def fake_get_cwd(p):
            cwd_calls["count"] += 1
            return tmp_path

        # The cache only reuses a log path that still exists on disk, so the
        # fake resolution must point at a real file for the cache-hit path
        # to be exercised (a stale/missing path is covered by the other test).
        session_log = tmp_path / "session.jsonl"
        session_log.write_text("")

        def fake_resolve_claude_code_log(cwd, pid=None):
            log_calls["count"] += 1
            return session_log, "session-id"

        monkeypatch.setattr(discovery, "_get_process_cwd", fake_get_cwd)
        monkeypatch.setattr(discovery, "_resolve_claude_code_log", fake_resolve_claude_code_log)

        cache = DiscoveryCache()

        first = find_running_agents(cache)
        assert len(first) == 1
        assert cwd_calls["count"] == 1
        assert log_calls["count"] == 1

        second = find_running_agents(cache)
        assert len(second) == 1
        # Same PID, same cache -> both cwd/log resolutions are skipped.
        assert cwd_calls["count"] == 1
        assert log_calls["count"] == 1

    def test_cache_reresolves_when_log_file_no_longer_exists(self, tmp_path, monkeypatch):
        pid = 54322

        monkeypatch.setattr(discovery.psutil, "process_iter", _fake_process_iter(pid))
        monkeypatch.setattr(discovery, "_get_process_cwd", lambda p: tmp_path)

        log_calls = {"count": 0}
        stale_log = tmp_path / "gone.jsonl"  # never created on disk -> .exists() is False

        def fake_resolve_claude_code_log(cwd, pid=None):
            log_calls["count"] += 1
            return stale_log, "session-id"

        monkeypatch.setattr(discovery, "_resolve_claude_code_log", fake_resolve_claude_code_log)

        cache = DiscoveryCache()
        find_running_agents(cache)
        find_running_agents(cache)

        # Cached log path doesn't exist on disk, so it must re-resolve every time.
        assert log_calls["count"] == 2

    def test_no_cache_preserves_bare_call_behavior(self, tmp_path, monkeypatch):
        """find_running_agents() with no cache arg behaves exactly as before."""
        pid = 54323

        monkeypatch.setattr(discovery.psutil, "process_iter", _fake_process_iter(pid))

        cwd_calls = {"count": 0}

        def fake_get_cwd(p):
            cwd_calls["count"] += 1
            return tmp_path

        monkeypatch.setattr(discovery, "_get_process_cwd", fake_get_cwd)
        monkeypatch.setattr(
            discovery, "_resolve_claude_code_log", lambda cwd, pid=None: (None, None)
        )

        find_running_agents()
        find_running_agents()

        # No cache provided -> every scan re-resolves from scratch (unchanged
        # behavior for existing CLI callers / tests that call this bare).
        assert cwd_calls["count"] == 2

    def test_prune_drops_entries_for_dead_pids(self):
        cache = DiscoveryCache()
        cache.cwd_by_pid[1] = "cwd-for-1"
        cache.cwd_by_pid[2] = "cwd-for-2"
        cache.log_by_pid[1] = ("log1", "sid1")
        cache.log_by_pid[2] = ("log2", "sid2")

        cache.prune(live_pids={1})

        assert 1 in cache.cwd_by_pid
        assert 2 not in cache.cwd_by_pid
        assert 2 not in cache.log_by_pid
