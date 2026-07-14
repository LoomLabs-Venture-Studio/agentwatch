"""Tests for `agentwatch.parser.watcher.AiderLogWatcher` (PLAYBOOK Sprint 7,
Aider Phase 3 -- live watch/TUI tailing, the item explicitly deferred out of
Sprint 6's scope).

Drives `_read_new_actions()` directly for the incremental-cursor behavior
(reparse-whole-file-but-only-emit-the-new-tail), mirroring how
`test_cursor_watcher.py` drives `CursorWatcher._poll_once()` directly rather
than the async `watch()` loop for the same reason: the interesting behavior
is synchronous and side-effect-only-via-instance-state. One async test at
the bottom drives the real `watch()` loop against a real growing file on
disk to prove the `watchfiles.awatch` trigger path works end to end.
"""

from __future__ import annotations

import asyncio

import pytest

from agentwatch.parser.watcher import AiderLogWatcher

SESSION_1 = """# aider chat started at 2026-07-14 10:00:00

#### fix the bug

I'll fix it.

foo.py
```python
<<<<<<< SEARCH
old code
=======
new code
>>>>>>> REPLACE
```

Commit abc1234 fix the bug
"""

TURN_2 = """
#### add a test

Adding a test now.
"""

SESSION_2_HEADER = "\n# aider chat started at 2026-07-14 11:00:00\n"

TURN_2B = """
#### resumed session turn

Doing more work.
"""


@pytest.fixture
def md_path(tmp_path):
    return tmp_path / ".aider.chat.history.md"


class TestReadNewActions:
    def test_missing_file_returns_empty(self, md_path):
        watcher = AiderLogWatcher(md_path)
        assert watcher._read_new_actions() == []

    def test_first_read_emits_all_existing_actions(self, md_path):
        md_path.write_text(SESSION_1, encoding="utf-8")
        watcher = AiderLogWatcher(md_path)

        actions = watcher._read_new_actions()

        assert len(actions) == 2  # aider_prompt + aider_edit
        assert actions[0].tool_name == "aider_prompt"
        assert actions[0].incoming_message == "fix the bug"
        assert actions[1].tool_name == "aider_edit"
        assert actions[1].file_path == "foo.py"
        assert actions[1].success is True  # a Commit line follows the edit block

    def test_second_read_after_no_growth_emits_nothing(self, md_path):
        md_path.write_text(SESSION_1, encoding="utf-8")
        watcher = AiderLogWatcher(md_path)
        watcher._read_new_actions()

        assert watcher._read_new_actions() == []

    def test_appended_turn_emits_only_the_new_action(self, md_path):
        md_path.write_text(SESSION_1, encoding="utf-8")
        watcher = AiderLogWatcher(md_path)
        first = watcher._read_new_actions()
        assert len(first) == 2

        with open(md_path, "a", encoding="utf-8") as f:
            f.write(TURN_2)

        second = watcher._read_new_actions()
        assert len(second) == 1
        assert second[0].tool_name == "aider_prompt"
        assert second[0].incoming_message == "add a test"

    def test_already_emitted_actions_never_repeat_across_many_polls(self, md_path):
        md_path.write_text(SESSION_1, encoding="utf-8")
        watcher = AiderLogWatcher(md_path)

        seen = []
        seen.extend(watcher._read_new_actions())
        seen.extend(watcher._read_new_actions())  # no growth
        with open(md_path, "a", encoding="utf-8") as f:
            f.write(TURN_2)
        seen.extend(watcher._read_new_actions())
        seen.extend(watcher._read_new_actions())  # no growth again

        assert len(seen) == 3  # 2 from session 1's first turn + 1 new prompt

    def test_new_resumed_session_gets_its_own_cursor(self, md_path):
        """A second `# aider chat started at` header appended later starts a
        brand-new session_id with its own independent emitted-count cursor --
        must not be confused with, or block, the first session's cursor."""
        md_path.write_text(SESSION_1, encoding="utf-8")
        watcher = AiderLogWatcher(md_path)
        first = watcher._read_new_actions()
        assert len(first) == 2

        with open(md_path, "a", encoding="utf-8") as f:
            f.write(SESSION_2_HEADER)
            f.write(TURN_2B)

        second = watcher._read_new_actions()
        assert len(second) == 1
        assert second[0].incoming_message == "resumed session turn"
        # Session ids must differ (different session_start timestamps).
        assert second[0].session_id != first[0].session_id

    def test_session_id_filter_restricts_to_one_session(self, md_path):
        md_path.write_text(SESSION_1, encoding="utf-8")
        with open(md_path, "a", encoding="utf-8") as f:
            f.write(SESSION_2_HEADER)
            f.write(TURN_2B)

        # First discover the real session ids via an unfiltered watcher.
        probe = AiderLogWatcher(md_path)
        all_actions = probe._read_new_actions()
        session_ids = {a.session_id for a in all_actions}
        assert len(session_ids) == 2
        target = sorted(session_ids)[0]

        filtered = AiderLogWatcher(md_path, session_id=target)
        actions = filtered._read_new_actions()
        assert actions
        assert all(a.session_id == target for a in actions)


class TestAiderLogWatcherAsync:
    async def test_watch_emits_actions_as_file_grows(self, md_path):
        md_path.write_text(SESSION_1, encoding="utf-8")
        watcher = AiderLogWatcher(md_path)

        gen = watcher.watch()
        try:
            first = await asyncio.wait_for(gen.__anext__(), timeout=2)
            second = await asyncio.wait_for(gen.__anext__(), timeout=2)
            assert {first.tool_name, second.tool_name} == {"aider_prompt", "aider_edit"}

            async def append_later():
                await asyncio.sleep(0.2)
                with open(md_path, "a", encoding="utf-8") as f:
                    f.write(TURN_2)

            asyncio.create_task(append_later())
            third = await asyncio.wait_for(gen.__anext__(), timeout=5)
            assert third.tool_name == "aider_prompt"
            assert third.incoming_message == "add a test"
        finally:
            await gen.aclose()
