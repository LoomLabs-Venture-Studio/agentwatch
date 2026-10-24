"""#130 Wave 2: NetSampler wired into `watch` and `watch-all`.

Fake sampler, fake watcher and fake discovery: no live sockets, no psutil scans.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agentwatch.discovery import AgentProcess
from agentwatch.parser.models import Action, ToolType
from agentwatch.ui.app import AgentWatchApp, StatsPanel
from agentwatch.ui.multi_app import MultiAgentWatchApp

_REAL_FIND_OWN = AgentWatchApp._find_own_process  # conftest stubs it per test
T0 = datetime(2026, 10, 15, 12, 0, 0)  # naive = UTC
EP = ("1.2.3.4", 443)


def _epoch(ts: datetime) -> float:
    return ts.replace(tzinfo=timezone.utc).timestamp()


def _action(ts: datetime, duration_ms: int = 0) -> Action:
    return Action(
        timestamp=ts, tool_name="Read", tool_type=ToolType.READ, success=True,
        duration_ms=duration_ms,
    )


def _proc(pid: int, log_file: Path, agent_type: str = "claude-code") -> AgentProcess:
    return AgentProcess(
        pid=pid, agent_type=agent_type, working_directory=Path("proj"), log_file=log_file,
        command=agent_type, team_id=pid,
    )


class FakeSampler:
    def __init__(self):
        self.tracked: set[int] = set()
        self.calls: list[tuple[int, float, float]] = []
        self.started = self.stopped = False

    def track(self, pid):
        self.tracked.add(pid)

    def untrack(self, pid):
        self.tracked.discard(pid)

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def endpoints(self, pid, start, end):
        self.calls.append((pid, start, end))
        return [EP] if pid in self.tracked else None


class FakeWatcher:
    def __init__(self, events=(), procs=None, new=(), expired=()):
        self.events, self.procs = list(events), procs or {}
        self.new, self.expired = list(new), list(expired)

    async def watch(self):
        for event in self.events:
            yield event

    def get_process_meta(self, path):
        return self.procs.get(path)

    def refresh_processes(self, processes):
        return self.new

    def reap_stopped(self, timeout=60.0):
        return self.expired


async def _until(pilot, cond):
    for _ in range(100):
        if cond():
            return
        await pilot.pause(0.01)
    raise AssertionError("condition never met")


def _stats_line(app) -> str:
    if isinstance(app, MultiAgentWatchApp):  # the numbers line of the Selected strip
        return str(app.query_one("#selected").render()).splitlines()[1]
    return app.query_one("#stats-display", StatsPanel)._build_content()


class TestWatchAll:
    async def test_actions_get_endpoints_with_prev_end_chaining(self):
        good, cursor = Path("good.jsonl"), Path("cursor.key")
        a1 = _action(T0, duration_ms=2000)
        a2 = _action(T0 + timedelta(seconds=5))  # duration 0: starts at a1's end
        c1 = _action(T0)
        app = MultiAgentWatchApp(agent_processes=[])
        app._net_sampler = sampler = FakeSampler()
        app.watcher = FakeWatcher(
            events=[
                ("agent_added", good), ("agent_added", cursor),
                ("action", (a1, good)), ("action", (a2, good)), ("action", (c1, cursor)),
            ],
            procs={good: _proc(100, good), cursor: _proc(200, cursor, "cursor")},
        )
        async with app.run_test() as pilot:
            await _until(pilot, lambda: cursor in app.agents and len(app.agents[cursor]["buffer"]))
            assert sampler.started
            assert sampler.tracked == {100}  # cursor is editor-hosted: not tracked
            t0 = _epoch(T0)
            assert sampler.calls == [(100, t0 - 2, t0), (100, t0, t0 + 5)]
            assert a1.observed_endpoints == [EP] and a2.observed_endpoints == [EP]
            assert c1.observed_endpoints is None

            app.selected_path = good
            app.refresh_ui()
            assert _stats_line(app).endswith("  Net: 1 endpoints")
            app.selected_path = cursor
            app.refresh_ui()
            assert _stats_line(app).endswith("  Net: n/a (not attributable)")
        assert sampler.stopped

    async def test_all_logs_mode_does_not_sample(self):
        app = MultiAgentWatchApp(watch_paths=[])
        app._net_sampler = sampler = FakeSampler()
        async with app.run_test():
            pass
        assert not sampler.started and sampler.stopped

    async def test_refresh_tracks_new_and_reaping_untracks(self, monkeypatch):
        monkeypatch.setattr("agentwatch.ui.multi_app.find_running_agents", lambda cache: [])
        a, b = Path("a.jsonl"), Path("b.jsonl")
        app = MultiAgentWatchApp(agent_processes=[])
        app._net_sampler = sampler = FakeSampler()
        # two log files of one process (same pid), plus an editor-hosted one
        app.watcher = FakeWatcher(
            new=[_proc(100, a), _proc(100, b), _proc(300, Path("c.key"), "cursor")]
        )
        async with app.run_test() as pilot:
            await app._refresh_processes()
            await pilot.pause()
            assert sampler.tracked == {100}
            assert app.agents[a].get("net_sampled") and not app.agents[Path("c.key")].get(
                "net_sampled")

            app.watcher.new, app.watcher.expired = [], [a]
            await app._refresh_processes()
            assert sampler.tracked == {100}  # b still has pid 100

            app.watcher.expired = [b]
            await app._refresh_processes()
            assert sampler.tracked == set()

    async def test_refresh_retracks_when_log_gets_new_pid(self, monkeypatch):
        monkeypatch.setattr("agentwatch.ui.multi_app.find_running_agents", lambda cache: [])
        a, b = Path("a.jsonl"), Path("b.jsonl")
        app = MultiAgentWatchApp(agent_processes=[])
        app._net_sampler = sampler = FakeSampler()
        app.watcher = FakeWatcher(new=[_proc(100, a), _proc(100, b)])
        async with app.run_test() as pilot:
            await app._refresh_processes()
            await pilot.pause()
            assert sampler.tracked == {100}

            # a's session is resumed by a new process; b still belongs to 100
            app.watcher.new, app.watcher.procs = [], {a: _proc(200, a), b: _proc(100, b)}
            await app._refresh_processes()
            assert app.agents[a]["pid"] == 200 and sampler.tracked == {100, 200}
            assert app._team_by_pid[200] == 200

            app.watcher.procs[b] = _proc(300, b)  # last holder of 100 moves on
            await app._refresh_processes()
            assert sampler.tracked == {200, 300} and 100 not in app._team_by_pid

            action = _action(T0)
            app.watcher.events = [("action", (action, a))]
            app.run_worker(app._watch_loop())
            await _until(pilot, lambda: len(app.agents[a]["buffer"]))
            assert action.observed_endpoints == [EP] and sampler.calls[-1][0] == 200


class TestWatch:
    def _run(self, tmp_path, monkeypatch, procs):
        log = tmp_path / "session.jsonl"
        log.write_text("", encoding="utf-8")
        seen = {}

        def fake_find(cache=None):
            seen["thread"] = threading.get_ident()
            return procs(log)

        monkeypatch.setattr("agentwatch.discovery.find_running_agents", fake_find)
        monkeypatch.setattr(AgentWatchApp, "_find_own_process", _REAL_FIND_OWN)
        app = AgentWatchApp(log_path=log)
        app._net_sampler = sampler = FakeSampler()
        return app, sampler, seen

    async def test_pid_resolved_by_log_path_off_ui_thread(self, tmp_path, monkeypatch):
        app, sampler, seen = self._run(
            tmp_path, monkeypatch,
            lambda log: [_proc(7, tmp_path / "other.jsonl"),
                         _proc(42, tmp_path / "x" / ".." / log.name)],
        )
        async with app.run_test() as pilot:
            await _until(pilot, lambda: app._net_pid is not None)
            assert seen["thread"] != threading.get_ident()
            assert app._net_pid == 42 and sampler.tracked == {42} and sampler.started
            action = _action(T0, duration_ms=1000)
            app._on_action(action)
            assert action.observed_endpoints == [EP]
            assert sampler.calls == [(42, _epoch(T0) - 1, _epoch(T0))]
            app.refresh_display()
            assert _stats_line(app).endswith("  Net: 1 endpoints")
        assert sampler.stopped

    async def test_no_matching_process_leaves_none(self, tmp_path, monkeypatch):
        app, sampler, seen = self._run(
            tmp_path, monkeypatch, lambda log: [_proc(7, tmp_path / "other.jsonl")]
        )
        async with app.run_test() as pilot:
            await _until(pilot, lambda: "thread" in seen)
            await pilot.pause()
            action = _action(T0)
            app._on_action(action)
            assert action.observed_endpoints is None
            assert not sampler.tracked and not sampler.started
            app.refresh_display()
            assert _stats_line(app).endswith("  Net: no live process")
        assert sampler.stopped

    async def test_non_attributable_match_not_tracked(self, tmp_path, monkeypatch):
        app, sampler, seen = self._run(
            tmp_path, monkeypatch, lambda log: [_proc(9, log, "cursor")]
        )
        async with app.run_test() as pilot:
            await _until(pilot, lambda: "thread" in seen)
            await pilot.pause()
            assert not sampler.tracked and app._net_pid is None
            app.refresh_display()
            assert _stats_line(app).endswith("  Net: n/a (not attributable)")

