"""LogWatcher (JSONL) live tailing, incl. macOS FSEvents behaviour.

On macOS an append to a recently created file is reported as Change.added and
the tmp dir may be reported via a symlink, so a modified-only, unresolved-path
filter missed appends. Synthetic data only.
"""

from __future__ import annotations

import asyncio
import json
import os

import pytest

import agentwatch.parser.watcher as w
from agentwatch.parser.watcher import LogWatcher


def _line(n: int) -> str:
    tool_use = {
        "type": "tool_use",
        "id": f"t{n}",
        "name": "Read",
        "input": {"file_path": f"/f{n}.py"},
    }
    entry = {
        "type": "assistant",
        "sessionId": "s1",
        "timestamp": "2026-01-01T00:00:00Z",
        "message": {"role": "assistant", "content": [tool_use]},
    }
    return json.dumps(entry) + "\n"


@pytest.fixture
def log_path(tmp_path):
    return tmp_path / "session.jsonl"


def _append(path, text):
    with open(path, "a", encoding="utf-8") as f:
        f.write(text)


class TestLogWatcherAsync:
    async def test_appends_after_watch_starts_are_emitted(self, log_path):
        log_path.write_text(_line(1), encoding="utf-8")
        gen = LogWatcher(log_path).watch()
        try:
            first = await asyncio.wait_for(gen.__anext__(), timeout=2)
            assert first.tool_name == "Read"
            for n in (2, 3):
                _append(log_path, _line(n))
                got = await asyncio.wait_for(gen.__anext__(), timeout=5)
                assert got.tool_name == "Read"
        finally:
            await gen.aclose()

    async def test_append_before_watch_is_armed(self, log_path):
        log_path.write_text(_line(1), encoding="utf-8")
        gen = LogWatcher(log_path).watch()
        try:
            await asyncio.wait_for(gen.__anext__(), timeout=2)
            _append(log_path, _line(2))  # before the generator re-arms awatch
            got = await asyncio.wait_for(gen.__anext__(), timeout=5)
            assert got.tool_name == "Read"
        finally:
            await gen.aclose()

    async def test_idle_ticks_do_not_read_file(self, log_path, monkeypatch):
        log_path.write_text(_line(1), encoding="utf-8")
        watcher = LogWatcher(log_path)
        watcher._POLL_TICK_MS = 50
        reads = 0
        real = watcher._read_new_lines

        def counting():
            nonlocal reads
            reads += 1
            return real()

        monkeypatch.setattr(watcher, "_read_new_lines", counting)
        gen = watcher.watch()
        try:
            await asyncio.wait_for(gen.__anext__(), timeout=2)
            assert reads == 1
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(gen.__anext__(), timeout=0.5)
            assert reads == 1
        finally:
            await gen.aclose()

    async def test_truncation_is_reanchored(self, log_path):
        log_path.write_text(_line(1) + _line(2) + _line(3), encoding="utf-8")
        gen = LogWatcher(log_path).watch()
        try:
            for _ in range(3):
                await asyncio.wait_for(gen.__anext__(), timeout=2)
            log_path.write_text(_line(4), encoding="utf-8")  # shorter than old offset
            got = await asyncio.wait_for(gen.__anext__(), timeout=5)
            assert got.tool_name == "Read"
        finally:
            await gen.aclose()


class TestLogWatcherSync:
    def test_truncation_resets_offset(self, log_path):
        log_path.write_text(_line(1) + _line(2), encoding="utf-8")
        watcher = LogWatcher(log_path)
        assert len(watcher._read_new_lines()) == 2
        log_path.write_text(_line(3), encoding="utf-8")
        assert len(watcher._read_new_lines()) == 1

    def test_replaced_inode_resets_offset(self, log_path):
        log_path.write_text(_line(1) + _line(2), encoding="utf-8")
        watcher = LogWatcher(log_path)
        assert len(watcher._read_new_lines()) == 2
        new = log_path.with_name("new.jsonl")
        new.write_text(_line(3) + _line(4) + _line(5), encoding="utf-8")
        os.replace(new, log_path)
        assert len(watcher._read_new_lines()) == 3


def test_resolve_helper_follows_symlinks(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    assert w._resolve(link / "x.jsonl") == w._resolve(real / "x.jsonl")
