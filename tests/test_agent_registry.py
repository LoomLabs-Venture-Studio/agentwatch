"""Tests for the agent adapter registry (cli-agents sub-project 0)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentwatch import agents
from agentwatch.agents.base import BaseAdapter, sniff_jsonl_format
from agentwatch.discovery import AgentProcess

# Snapshot of discovery.AGENT_PATTERNS. Was a verbatim copy of develop@45e19ce;
# claude-code/aider/codex were re-anchored to the program path in the PR-29 fix
# wave (args like `--model claude-...` stole other agents' PIDs).
_LEGACY_PATTERNS = {
    "claude-code": {
        "pattern": (
            r"(^|[/\\])claude(\.exe)?$"
            r"|[/\\]claude[/\\]versions[/\\][^/\\]+$"
            r"|[/\\]@anthropic-ai[/\\]claude-code[/\\]cli\.js$"
        ),
        "exclude": r"Claude\.app|Claude Helper",
    },
    "aider": {"pattern": r"(^|[/\\])aider(\.exe)?$", "exclude": None},
    "codex": {"pattern": r"(^|[/\\])codex(\.exe|\.js)?$", "exclude": None},
    "copilot": {"pattern": r"(^|[/\\])copilot(\.exe)?(\s|$)", "exclude": r"^\S*node(\.exe)?\s"},
    "agy": {"pattern": r"(^|[/\\])agy(\.exe)?(\s|$)", "exclude": None},
    "gemini": {"pattern": r"(^|[/\\])gemini(\.exe|\.js)?$", "exclude": None},
}


def _write_jsonl(path: Path, entries: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")
    return path


class TestRegistryShape:
    def test_order(self):
        assert [a.name for a in agents.ADAPTERS] == [
            "claude-code", "aider", "codex", "cursor", "copilot", "agy", "gemini",
        ]

    def test_get(self):
        assert agents.get("codex").name == "codex"
        assert agents.get("nope") is None

    def test_kinds(self):
        assert [a.name for a in agents.process_adapters()] == [
            "claude-code", "aider", "codex", "copilot", "agy", "gemini",
        ]
        assert [a.name for a in agents.editor_adapters()] == ["cursor"]

    def test_process_patterns_match_legacy(self):
        got = {
            a.name: {"pattern": a.process_pattern, "exclude": a.process_exclude}
            for a in agents.process_adapters()
        }
        assert got == _LEGACY_PATTERNS

    def test_all_adapters_subclass_base(self):
        assert all(isinstance(a, BaseAdapter) for a in agents.ADAPTERS)


class TestClaims:
    def test_claude_code_jsonl(self, tmp_path):
        p = _write_jsonl(
            tmp_path / "s.jsonl",
            [{"type": "user", "sessionId": "abc", "message": {"role": "user", "content": "hi"}}],
        )
        assert agents.adapter_for(p).name == "claude-code"

    def test_moltbot_jsonl_goes_to_claude_code(self, tmp_path):
        p = _write_jsonl(tmp_path / "m.jsonl", [{"skill": "x", "role": "assistant"}])
        assert agents.adapter_for(p).name == "claude-code"

    def test_codex_jsonl(self, tmp_path):
        p = _write_jsonl(
            tmp_path / "rollout.jsonl", [{"type": "session_meta", "payload": {"id": "1"}}]
        )
        assert sniff_jsonl_format(p) == "codex"
        assert agents.adapter_for(p).name == "codex"

    def test_skip_entries_do_not_lock_format(self, tmp_path):
        p = _write_jsonl(
            tmp_path / "s.jsonl",
            [{"type": "file-history-snapshot"}, {"type": "session_meta", "payload": {}}],
        )
        assert agents.adapter_for(p).name == "codex"

    def test_missing_jsonl_falls_to_claude_code(self, tmp_path):
        assert agents.adapter_for(tmp_path / "missing.jsonl").name == "claude-code"

    def test_aider_md(self, tmp_path):
        p = tmp_path / ".aider.chat.history.md"
        p.write_text("# aider chat started at 2026-01-01 00:00:00\n", encoding="utf-8")
        assert agents.adapter_for(p).name == "aider"

    def test_cursor_vscdb(self, tmp_path):
        assert agents.adapter_for(tmp_path / "state.vscdb").name == "cursor"

    def test_unclaimed(self, tmp_path):
        assert agents.adapter_for(tmp_path / "notes.txt") is None


class TestIsLive:
    def test_process_agent_uses_log_file(self, tmp_path):
        log = tmp_path / "a.jsonl"
        proc = AgentProcess(pid=1, agent_type="claude-code", working_directory=tmp_path,
                            log_file=log)
        assert agents.get("claude-code").is_live(proc) is False
        log.write_text("", encoding="utf-8")
        assert agents.get("claude-code").is_live(proc) is True

    def test_cursor_uses_db_path_not_synthetic_log(self, tmp_path):
        db = tmp_path / "state.vscdb"
        proc = AgentProcess(pid=1, agent_type="cursor", working_directory=tmp_path,
                            log_file=tmp_path / "never-created", cursor_db_path=db)
        assert agents.get("cursor").is_live(proc) is False
        db.write_bytes(b"")
        assert agents.get("cursor").is_live(proc) is True


class TestMakeWatcher:
    def test_types(self, tmp_path):
        from agentwatch.parser.watcher import AiderLogWatcher, CursorWatcher, LogWatcher

        assert isinstance(agents.get("claude-code").make_watcher(tmp_path / "a.jsonl", "s"),
                          LogWatcher)
        assert isinstance(agents.get("codex").make_watcher(tmp_path / "a.jsonl", None),
                          LogWatcher)
        assert isinstance(agents.get("aider").make_watcher(tmp_path / "a.md", "s"),
                          AiderLogWatcher)
        proc = AgentProcess(pid=1, agent_type="cursor", working_directory=tmp_path,
                            log_file=tmp_path / "k", cursor_db_path=tmp_path / "state.vscdb")
        w = agents.get("cursor").make_watcher(proc, "composer-1")
        assert isinstance(w, CursorWatcher)
        assert w.db_path == tmp_path / "state.vscdb"
        assert w.composer_id_filter == "composer-1"

    def test_session_id_passed_through(self, tmp_path):
        w = agents.get("claude-code").make_watcher(tmp_path / "a.jsonl", "sess-9")
        assert w.session_id == "sess-9"


class TestResolveLogDelegatesAtCallTime:
    """Adapters must look up discovery._resolve_* at call time so existing
    tests' monkeypatches keep working."""

    def test_claude_code(self, tmp_path, monkeypatch):
        import agentwatch.discovery as discovery

        monkeypatch.setattr(discovery, "_resolve_claude_code_log",
                            lambda cwd, pid=None: (tmp_path / "x.jsonl", "sid"))
        assert agents.get("claude-code").resolve_log(tmp_path, 5) == (tmp_path / "x.jsonl", "sid")

    def test_cursor_discover(self, monkeypatch):
        sentinel = [object()]
        monkeypatch.setattr("agentwatch.cursor_discovery.find_cursor_agents", lambda: sentinel)
        assert agents.get("cursor").discover() is sentinel


def test_register_appends(monkeypatch):
    monkeypatch.setattr(agents, "ADAPTERS", list(agents.ADAPTERS))

    class Fake(BaseAdapter):
        name = "fake"
        kind = "process"
        process_pattern = r"\bfakeagent\b"

    agents.register(Fake())
    assert agents.get("fake") is not None
    with pytest.raises(ValueError):
        agents.register(Fake())
