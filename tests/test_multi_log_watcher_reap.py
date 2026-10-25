"""MultiLogWatcher.reap_stopped() must stop the reaped watcher (Sprint 37 F2).

reap_stopped() used to drop the watcher from ``watchers`` while its task,
held in a local dict inside watch(), kept running. When the same log path
came back (a resumed session, a re-mapped process) a second watcher was
started next to the leaked one and every new action was emitted twice.

The watchers here are fakes fed by hand, so the test is deterministic and
needs no file-system events.
"""

from __future__ import annotations

import asyncio

from agentwatch.discovery import AgentProcess
from agentwatch.parser.watcher import MultiLogWatcher


class _FakeWatcher:
    def __init__(self):
        self.queue: asyncio.Queue = asyncio.Queue()
        self.cancelled = False

    async def watch(self):
        try:
            while True:
                yield await self.queue.get()
        except asyncio.CancelledError:
            self.cancelled = True
            raise


def _proc(log, pid=4242):
    return AgentProcess(
        pid=pid, agent_type="claude-code", working_directory=log.parent,
        log_file=log, command="claude",
    )


async def _next_event(gen, timeout=1.0):
    return await asyncio.wait_for(gen.__anext__(), timeout=timeout)


async def _drain(gen, seconds=0.2):
    """Every event the watcher yields within *seconds*."""
    events = []
    try:
        while True:
            events.append(await _next_event(gen, timeout=seconds))
    except asyncio.TimeoutError:
        return events


async def test_reaped_watcher_is_cancelled_and_readded_log_emits_once(tmp_path, monkeypatch):
    log = tmp_path / "session.jsonl"
    log.write_text("")
    proc = _proc(log)
    made: list[_FakeWatcher] = []

    def make_watcher(self, key):
        made.append(_FakeWatcher())
        return made[-1]

    monkeypatch.setattr(MultiLogWatcher, "_make_watcher", make_watcher)
    mlw = MultiLogWatcher.from_processes([proc], poll_interval=0.01)
    gen = mlw.watch()
    try:
        assert await _next_event(gen) == ("agent_added", log)
        await asyncio.sleep(0.02)  # the watcher task is running

        mlw.refresh_processes([])  # the process stops
        assert mlw.reap_stopped(timeout=0.0) == [log]
        await asyncio.sleep(0.05)
        assert made[0].cancelled

        mlw.refresh_processes([proc])  # the same log comes back
        assert await _next_event(gen) == ("agent_added", log)
        assert len(made) == 2

        # Both watchers would see the same new line if the first had leaked.
        for w in made:
            w.queue.put_nowait("action-1")
        events = await _drain(gen)

        assert events == [("action", ("action-1", log))]
    finally:
        await gen.aclose()


async def test_actions_queued_by_a_reaped_watcher_are_dropped(tmp_path, monkeypatch):
    log = tmp_path / "session.jsonl"
    log.write_text("")
    proc = _proc(log)
    made: list[_FakeWatcher] = []
    monkeypatch.setattr(
        MultiLogWatcher, "_make_watcher", lambda self, key: made.append(_FakeWatcher()) or made[-1]
    )
    mlw = MultiLogWatcher.from_processes([proc], poll_interval=0.05)
    gen = mlw.watch()
    try:
        assert await _next_event(gen) == ("agent_added", log)
        made[0].queue.put_nowait("late")
        await asyncio.sleep(0.02)  # the watcher task moves it to the shared queue

        mlw.refresh_processes([])
        mlw.reap_stopped(timeout=0.0)

        assert await _drain(gen) == []
    finally:
        await gen.aclose()


async def test_closing_watch_cancels_every_task(tmp_path, monkeypatch):
    logs = [tmp_path / f"s{i}.jsonl" for i in range(2)]
    for p in logs:
        p.write_text("")
    made: list[_FakeWatcher] = []
    monkeypatch.setattr(
        MultiLogWatcher, "_make_watcher", lambda self, key: made.append(_FakeWatcher()) or made[-1]
    )
    mlw = MultiLogWatcher.from_processes(
        [_proc(p, pid=i) for i, p in enumerate(logs, 1)], poll_interval=0.01
    )
    gen = mlw.watch()
    await _next_event(gen)
    await _next_event(gen)
    await asyncio.sleep(0.02)  # both watcher tasks are running
    await gen.aclose()
    await asyncio.sleep(0.02)

    assert [w.cancelled for w in made] == [True, True]
