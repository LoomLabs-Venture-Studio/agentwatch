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
