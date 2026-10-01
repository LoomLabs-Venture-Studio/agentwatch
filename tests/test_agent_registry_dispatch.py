"""Core dispatch sites route through agentwatch.agents (cli-agents sub-project 0)."""

from __future__ import annotations

import types
from pathlib import Path

import agentwatch.discovery as discovery
from agentwatch import agents
from agentwatch.agents.base import BaseAdapter


class _FakeProcess:
    def __init__(self, pid: int, cmdline: list[str]):
        self.info = {
            "pid": pid,
            "ppid": 1,
            "cmdline": cmdline,
            "name": cmdline[0],
            "memory_info": types.SimpleNamespace(rss=1024 * 1024),
            "cpu_percent": 0.0,
            "create_time": 1_700_000_000.0,
        }


def _iter(*procs):
    return lambda attrs=None: iter(list(procs))


class FakeAgentAdapter(BaseAdapter):
    """An agent that exists only in this test file."""

    name = "fakeagent"
    kind = "process"
    process_pattern = r"\bfakeagent\b"

    def __init__(self, log: Path):
        self._log = log

    def resolve_log(self, cwd, pid):
        return self._log, "fake-session"

    def claims(self, path):
        return path.suffix == ".fake"

    def make_watcher(self, source, session_id):
        from agentwatch.parser.watcher import LogWatcher

        path = source if isinstance(source, Path) else source.log_file
        return LogWatcher(path, session_id=session_id)

    def parse_file(self, path, session_id=None, **opts):
        from datetime import datetime

        from agentwatch.parser.models import Action, ToolType

        yield Action(timestamp=datetime(2026, 1, 1), tool_name="Read",
                     tool_type=ToolType.READ, success=True, session_id="fake-session")


def _isolate(monkeypatch, *extra):
    monkeypatch.setattr(agents, "ADAPTERS", [*agents.ADAPTERS, *extra])
    monkeypatch.setattr("agentwatch.cursor_discovery.find_cursor_agents", lambda: [])


class TestDiscoveryViaRegistry:
    def test_agent_patterns_still_exported(self):
        assert set(discovery.AGENT_PATTERNS) == {"claude-code", "aider", "codex"}
        assert discovery.AGENT_PATTERNS["codex"] == {"pattern": r"\bcodex\b", "exclude": None}

    def test_fake_adapter_discovered_without_core_edits(self, tmp_path, monkeypatch):
        log = tmp_path / "s.fake"
        log.write_text("", encoding="utf-8")
        _isolate(monkeypatch, FakeAgentAdapter(log))
        monkeypatch.setattr(discovery.psutil, "process_iter",
                            _iter(_FakeProcess(777, ["fakeagent", "--go"])))
        monkeypatch.setattr(discovery, "_get_process_cwd", lambda pid: tmp_path)

        found = discovery.find_running_agents()

        assert [(a.pid, a.agent_type, a.log_file, a.session_id) for a in found] == [
            (777, "fakeagent", log, "fake-session")
        ]

    def test_first_match_wins_in_registry_order(self, tmp_path, monkeypatch):
        _isolate(monkeypatch)
        monkeypatch.setattr(discovery.psutil, "process_iter",
                            _iter(_FakeProcess(5, ["aider", "--model", "codex"])))
        monkeypatch.setattr(discovery, "_get_process_cwd", lambda pid: tmp_path)
        monkeypatch.setattr(discovery, "_resolve_aider_log", lambda cwd: (None, None))

        found = discovery.find_running_agents()

        assert [a.agent_type for a in found] == ["aider"]

    def test_broken_adapter_does_not_break_others(self, tmp_path, monkeypatch):
        class Boom(BaseAdapter):
            name = "boom"
            kind = "editor"

            def discover(self):
                raise RuntimeError("boom")

        _isolate(monkeypatch, Boom())
        monkeypatch.setattr(discovery.psutil, "process_iter",
                            _iter(_FakeProcess(9, ["claude"])))
        monkeypatch.setattr(discovery, "_get_process_cwd", lambda pid: tmp_path)
        monkeypatch.setattr(discovery, "_resolve_claude_code_log",
                            lambda cwd, pid=None: (None, None))

        assert [a.agent_type for a in discovery.find_running_agents()] == ["claude-code"]


class TestParseFileViaRegistry:
    def test_fake_adapter_parse_file(self, tmp_path, monkeypatch):
        from agentwatch.parser.logs import parse_file

        p = tmp_path / "x.fake"
        p.write_text("anything", encoding="utf-8")
        _isolate(monkeypatch, FakeAgentAdapter(p))

        actions = list(parse_file(p))

        assert [a.session_id for a in actions] == ["fake-session"]

    def test_unclaimed_path_falls_back_to_jsonl(self, tmp_path):
        import json

        from agentwatch.parser.logs import parse_file

        p = tmp_path / "log.txt"  # no adapter claims .txt
        entry = {
            "type": "assistant",
            "sessionId": "fallback-sess",
            "timestamp": "2026-01-01T00:00:00Z",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "t1", "name": "Read",
                     "input": {"file_path": "/tmp/a.py"}}
                ],
            },
        }
        p.write_text(json.dumps(entry) + "\n", encoding="utf-8")

        actions = list(parse_file(p))

        # Parsed as Claude Code JSONL by the fallback, exactly as before the refactor.
        assert [(a.tool_name, a.session_id) for a in actions] == [("Read", "fallback-sess")]


class TestMultiLogWatcherViaRegistry:
    def test_fake_agent_is_live_listed_and_watched(self, tmp_path, monkeypatch):
        from agentwatch.discovery import AgentProcess
        from agentwatch.parser.watcher import LogWatcher, MultiLogWatcher, _has_live_log

        log = tmp_path / "s.fake"
        log.write_text("", encoding="utf-8")
        _isolate(monkeypatch, FakeAgentAdapter(log))
        proc = AgentProcess(pid=777, agent_type="fakeagent", working_directory=tmp_path,
                            log_file=log, session_id="fake-session", command="fakeagent")

        assert _has_live_log(proc)
        mlw = MultiLogWatcher.from_processes([proc])
        assert mlw._find_all_logs() == [log]
        w = mlw._make_watcher(log)
        assert isinstance(w, LogWatcher) and w.session_id == "fake-session"

    def test_builtin_agents_get_their_historical_watcher(self, tmp_path):
        from agentwatch.discovery import AgentProcess
        from agentwatch.parser.watcher import (
            AiderLogWatcher,
            CursorWatcher,
            LogWatcher,
            MultiLogWatcher,
            _has_live_log,
        )

        cc = tmp_path / "cc.jsonl"
        cc.write_text("", encoding="utf-8")
        md = tmp_path / ".aider.chat.history.md"
        md.write_text("", encoding="utf-8")
        db = tmp_path / "state.vscdb"
        db.write_text("", encoding="utf-8")
        synthetic = tmp_path / "cursor-synthetic-key"  # never created

        def mk(pid, agent, log, sid, **kw):
            return AgentProcess(pid=pid, agent_type=agent, working_directory=tmp_path,
                                log_file=log, session_id=sid, command=agent, **kw)

        procs = [
            mk(1, "claude-code", cc, "s-cc"),
            mk(2, "aider", md, "s-aider"),
            mk(3, "cursor", synthetic, "composer-9", cursor_db_path=db),
        ]
        assert all(_has_live_log(p) for p in procs)  # cursor live via db, not synthetic key
        mlw = MultiLogWatcher.from_processes(procs)
        assert mlw._find_all_logs() == [cc, md, synthetic]

        w_cc, w_md, w_cur = (mlw._make_watcher(p.log_file) for p in procs)
        assert type(w_cc) is LogWatcher and w_cc.session_id == "s-cc"
        assert type(w_md) is AiderLogWatcher and w_md.session_id == "s-aider"
        assert type(w_cur) is CursorWatcher
        assert w_cur.composer_id_filter == "composer-9"
        assert w_cur.db_path == db

    def test_unknown_agent_and_stopped_entries(self, tmp_path):
        from agentwatch.discovery import AgentProcess
        from agentwatch.parser.watcher import MultiLogWatcher, _has_live_log

        log = tmp_path / "x.jsonl"
        log.write_text("", encoding="utf-8")
        weird = AgentProcess(pid=5, agent_type="mystery", working_directory=tmp_path,
                             log_file=log, session_id="m", command="mystery")
        assert _has_live_log(weird)  # unknown agent: falls back to log_file.exists()
        assert not _has_live_log(
            AgentProcess(pid=6, agent_type="mystery", working_directory=tmp_path,
                         log_file=tmp_path / "gone.jsonl", session_id="m", command="mystery")
        )
        mlw = MultiLogWatcher.from_processes([weird])
        assert mlw._find_all_logs() == [log]  # .jsonl claimed by an adapter
        weird.command = "(stopped)"
        assert mlw._find_all_logs() == []


class TestSingleAgentAppViaRegistry:
    def test_select_watcher_uses_adapter(self, tmp_path, monkeypatch):
        from agentwatch.parser.watcher import LogWatcher
        from agentwatch.ui.app import select_single_agent_watcher

        log = tmp_path / "s.fake"
        log.write_text("", encoding="utf-8")
        _isolate(monkeypatch, FakeAgentAdapter(log))

        w = select_single_agent_watcher(log, cursor_composer_id=None)

        assert isinstance(w, LogWatcher) and w.path == log

    def test_select_watcher_defaults(self, tmp_path):
        from agentwatch.parser.watcher import AiderLogWatcher, CursorWatcher, LogWatcher
        from agentwatch.ui.app import select_single_agent_watcher

        assert isinstance(select_single_agent_watcher(tmp_path / "a.jsonl", None), LogWatcher)
        assert isinstance(select_single_agent_watcher(tmp_path / "a.md", None), AiderLogWatcher)
        assert isinstance(select_single_agent_watcher(tmp_path / "x.log", None), LogWatcher)
        cw = select_single_agent_watcher(tmp_path / "state.vscdb", "comp-1")
        assert isinstance(cw, CursorWatcher) and cw.composer_id_filter == "comp-1"


class TestAdapterFailureIsolation:
    def test_resolve_log_failure_is_debug_logged_and_agent_still_listed(
        self, tmp_path, monkeypatch, caplog
    ):
        import logging

        class BadResolve(FakeAgentAdapter):
            name = "badresolve"
            process_pattern = r"\bbadresolve\b"

            def resolve_log(self, cwd, pid):
                raise RuntimeError("resolve exploded")

        _isolate(monkeypatch, BadResolve(tmp_path / "x.fake"))
        monkeypatch.setattr(discovery.psutil, "process_iter",
                            _iter(_FakeProcess(321, ["badresolve", "--go"])))
        monkeypatch.setattr(discovery, "_get_process_cwd", lambda pid: tmp_path)

        with caplog.at_level(logging.DEBUG, logger="agentwatch.discovery"):
            found = discovery.find_running_agents()

        assert [(a.pid, a.agent_type, a.log_file) for a in found] == [(321, "badresolve", None)]
        records = [r for r in caplog.records if r.name == "agentwatch.discovery"]
        assert records and records[0].levelno == logging.DEBUG
        assert "badresolve" in records[0].getMessage()
        assert records[0].exc_info is not None

    def test_editor_discover_failure_is_debug_logged(self, tmp_path, monkeypatch, caplog):
        import logging

        class Boom(BaseAdapter):
            name = "boomeditor"
            kind = "editor"

            def discover(self):
                raise RuntimeError("boom")

        _isolate(monkeypatch, Boom())
        monkeypatch.setattr(discovery.psutil, "process_iter", _iter())

        with caplog.at_level(logging.DEBUG, logger="agentwatch.discovery"):
            discovery.find_running_agents()

        assert any(
            r.name == "agentwatch.discovery" and "boomeditor" in r.getMessage()
            for r in caplog.records
        )

    async def test_watch_all_survives_adapter_make_watcher_failure(
        self, tmp_path, monkeypatch, caplog
    ):
        import asyncio
        import logging
        from datetime import datetime

        from agentwatch.discovery import AgentProcess
        from agentwatch.parser.models import Action, ToolType
        from agentwatch.parser.watcher import MultiLogWatcher

        class StubWatcher:
            async def watch(self):
                yield Action(timestamp=datetime(2026, 1, 1), tool_name="Read",
                             tool_type=ToolType.READ, success=True, session_id="good")

        class GoodAdapter(FakeAgentAdapter):
            name = "goodagent"

            def make_watcher(self, source, session_id):
                return StubWatcher()

        class BadAdapter(FakeAgentAdapter):
            name = "badagent"

            def claims(self, path):
                return path.suffix == ".bad"

            def make_watcher(self, source, session_id):
                raise NotImplementedError("no watcher")

        good_log = tmp_path / "g.fake"
        bad_log = tmp_path / "b.bad"
        good_log.write_text("", encoding="utf-8")
        bad_log.write_text("", encoding="utf-8")
        _isolate(monkeypatch, GoodAdapter(good_log), BadAdapter(bad_log))

        def mk(pid, agent, log):
            return AgentProcess(pid=pid, agent_type=agent, working_directory=tmp_path,
                                log_file=log, session_id="s", command=agent)

        # Bad agent first so it is attempted before the good one.
        mlw = MultiLogWatcher.from_processes(
            [mk(1, "badagent", bad_log), mk(2, "goodagent", good_log)], poll_interval=0.01
        )

        events = []

        async def collect():
            async for ev in mlw.watch():
                events.append(ev)
                if ev[0] == "action":
                    return

        with caplog.at_level(logging.DEBUG, logger="agentwatch.parser.watcher"):
            await asyncio.wait_for(collect(), timeout=5)

        kinds = [(k, d if k == "agent_added" else d[1]) for k, d in events]
        assert ("agent_added", good_log) in kinds
        assert ("agent_added", bad_log) not in kinds
        assert ("action", good_log) in kinds
        assert bad_log in mlw._active_files  # not retried every poll tick
        assert bad_log not in mlw.watchers
        assert any(r.levelno == logging.DEBUG and bad_log.name in r.getMessage()
                   for r in caplog.records)
