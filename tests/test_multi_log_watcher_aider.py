"""Tests for `MultiLogWatcher`'s Aider `.md` wiring (PLAYBOOK Sprint 7,
Aider Phase 3 -- the live-tailing item explicitly deferred out of Sprint 6).

Mirrors `test_multi_log_watcher_cursor.py`'s structure: `_find_all_logs()`
must surface `.md` entries despite the historical `.jsonl`-only filter, and
`watch()` must construct an `AiderLogWatcher` (not a `LogWatcher`, which
would silently produce zero actions against Markdown) for them.
"""

from __future__ import annotations

import asyncio

from agentwatch.discovery import AgentProcess
from agentwatch.parser.watcher import AiderLogWatcher, CursorWatcher, LogWatcher, MultiLogWatcher

SESSION_MD = """# aider chat started at 2026-07-14 10:00:00

#### hello from aider

Sure, on it.
"""


def _aider_proc(md_path, pid: int) -> AgentProcess:
    return AgentProcess(
        pid=pid,
        agent_type="aider",
        working_directory=md_path.parent,
        log_file=md_path,
        command="aider",
    )


class TestFindAllLogsIncludesMarkdown:
    def test_md_entry_surfaces_alongside_jsonl(self, tmp_path):
        md_path = tmp_path / ".aider.chat.history.md"
        md_path.write_text(SESSION_MD, encoding="utf-8")
        jsonl_path = tmp_path / "session.jsonl"
        jsonl_path.write_text('{"type": "assistant"}\n', encoding="utf-8")

        aider_proc = _aider_proc(md_path, pid=111)
        claude_proc = AgentProcess(
            pid=222,
            agent_type="claude-code",
            working_directory=tmp_path,
            log_file=jsonl_path,
            command="claude",
        )

        watcher = MultiLogWatcher.from_processes([aider_proc, claude_proc])
        logs = watcher._find_all_logs()

        assert md_path in logs
        assert jsonl_path in logs

    def test_stopped_md_entry_excluded(self, tmp_path):
        md_path = tmp_path / ".aider.chat.history.md"
        md_path.write_text(SESSION_MD, encoding="utf-8")
        proc = _aider_proc(md_path, pid=111)
        proc.command = "(stopped)"

        watcher = MultiLogWatcher(paths=[])
        watcher._process_mode = True
        watcher._process_meta[proc.log_file] = proc

        assert md_path not in watcher._find_all_logs()


class TestWatchConstructsAiderLogWatcher:
    async def test_md_process_gets_an_aider_log_watcher(self, tmp_path):
        md_path = tmp_path / ".aider.chat.history.md"
        md_path.write_text(SESSION_MD, encoding="utf-8")
        proc = _aider_proc(md_path, pid=111)

        watcher = MultiLogWatcher.from_processes([proc], poll_interval=0.01)
        gen = watcher.watch()
        try:
            event_type, log_path = await asyncio.wait_for(gen.__anext__(), timeout=2)
            assert event_type == "agent_added"
            assert log_path == md_path
            assert isinstance(watcher.watchers[md_path], AiderLogWatcher)
            assert not isinstance(watcher.watchers[md_path], LogWatcher)
            assert not isinstance(watcher.watchers[md_path], CursorWatcher)

            event_type, (action, path) = await asyncio.wait_for(gen.__anext__(), timeout=2)
            assert event_type == "action"
            assert path == md_path
            assert action.tool_name == "aider_prompt"
            assert action.incoming_message == "hello from aider"
        finally:
            await gen.aclose()
