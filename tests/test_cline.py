"""Cline adapter: legacy and SDK task stores (synthetic fixtures, #104)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agentwatch import agents
from agentwatch.agents import cline as cline_agent
from agentwatch.parser import cline
from agentwatch.parser.models import ToolType

FIX = Path(__file__).parent / "fixtures" / "cline"
TASK_ID = "1760000000000"
SID = "1760000000000_abcde"
LEGACY = FIX / "legacy" / "tasks" / TASK_ID / "api_conversation_history.json"
SDK = FIX / "sdk" / "sessions" / SID / f"{SID}.messages.json"


def _tools(path):
    return [a for a in cline.parse_cline(path) if a.tool_name != "assistant_message"]


def _usage(path):
    return [a for a in cline.parse_cline(path) if a.tool_name == "assistant_message"]


class TestLegacy:
    def test_tool_mapping_and_results(self):
        got = _tools(LEGACY)
        assert [(a.tool_name, a.tool_type) for a in got] == [
            ("execute_command", ToolType.BASH),
            ("read_file", ToolType.READ),
            ("replace_in_file", ToolType.EDIT),
            ("execute_command", ToolType.BASH),
        ]
        assert got[0].command == "pytest -q"
        assert (got[0].success, got[0].error_message) == (False, "Command failed with exit code 1.")
        assert got[1].file_path == "src/app.py" and got[1].success
        assert "return a - b" in got[1].incoming_message
        assert (got[2].success, got[2].error_message) == (False, "The user denied this operation.")
        assert got[3].success and got[3].error_message is None

    def test_tool_use_without_result_is_held(self):
        assert "web_fetch" not in [a.tool_name for a in _tools(LEGACY)]

    def test_tokens_and_cost(self):
        usage = _usage(LEGACY)
        assert len(usage) == 5
        assert (usage[0].tokens_in, usage[0].tokens_out, usage[0].cost_usd) == (1200, 80, 0.0048)
        assert not usage[0].unpriced
        assert usage[0].outgoing_data == "I'll run the tests first."
        assert usage[0].timestamp is not None

    def test_failed_tool_execution(self):
        msgs = [
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "t1", "name": "write_to_file",
                 "input": {"absolutePath": "/tmp/x.txt", "content": "x"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content":
                "[write_to_file for '/tmp/x.txt'] Result:\nThe tool execution failed with the "
                "following error:\n<error>\nEACCES\n</error>"}]},
        ]
        (a,) = [a for _, a in cline.actions(msgs, sdk=False)]
        assert (a.tool_type, a.file_path, a.success) == (ToolType.WRITE, "/tmp/x.txt", False)
        assert a.error_message.startswith("The tool execution failed")

    def test_xml_mode_task_yields_tokens_only(self):
        # Non-native-tool models: the call is XML in text, the result plain text.
        msgs = [
            {"role": "user", "content": [{"type": "text", "text": "<task>list</task>"}]},
            {"role": "assistant", "id": "r1",
             "metrics": {"tokens": {"prompt": 500, "completion": 20, "cached": 0}, "cost": 0.001},
             "content": [{"type": "text",
                          "text": "<execute_command>\n<command>ls</command>\n</execute_command>"}]},
            {"role": "user", "content": [
                {"type": "text", "text": "[execute_command for 'ls'] Result:\nCommand executed."}]},
        ]
        got = [a for _, a in cline.actions(msgs, sdk=False)]
        assert [a.tool_name for a in got] == ["assistant_message"]
        assert (got[0].tokens_in, got[0].tokens_out) == (500, 20)


class TestSdk:
    def test_tool_mapping_and_results(self):
        got = _tools(SDK)
        assert [(a.tool_name, a.tool_type) for a in got] == [
            ("run_commands", ToolType.BASH),
            ("read_files", ToolType.READ),
            ("editor", ToolType.EDIT),
            ("fetch_web_content", ToolType.UNKNOWN),
        ]
        assert got[0].command == "npm test\ngit status --short"
        assert (got[0].success, got[0].error_message) == (False, "1 failing")
        assert got[1].file_path == "/home/dev/project/src/index.ts" and got[1].success
        assert got[1].incoming_message == "export const x = 1"
        assert got[2].file_path == "/home/dev/project/src/index.ts"
        assert got[3].network_host == "registry.example.org"  # host only, never the query

    def test_tokens_are_fresh_input_only(self):
        # SDK inputTokens already includes cache reads/writes (900 = 500 + 300 + 100).
        usage = _usage(SDK)
        assert len(usage) == 2  # msg-3 has no metrics
        a = usage[0]
        assert (a.tokens_in, a.tokens_out, a.cost_usd) == (500, 60, 0.0031)
        assert (a.cache_read_tokens, a.cache_creation_tokens) == (300, 100)

    def test_missing_cost_is_unpriced(self):
        msgs = [{"role": "assistant", "metrics": {"inputTokens": 1, "outputTokens": 2},
                 "content": "hi"}]
        (a,) = [a for _, a in cline.actions(msgs, sdk=True)]
        assert a.unpriced and a.cost_usd == 0.0 and a.outgoing_data == "hi"

    @pytest.mark.parametrize("inp,want", [
        ({"commands": ["a", "b"]}, "a\nb"),
        ({"commands": "a"}, "a"),
        ({"commands": {"command": "git", "args": ["log"]}}, "git log"),
        ([{"command": "ls"}], "ls"),
        ({"command": "ls", "args": ["-la"]}, "ls -la"),
        ({"command": "pwd"}, "pwd"),
        ({"cmd": "id"}, "id"),
        (["x", "y"], "x\ny"),
        ("echo hi", "echo hi"),
        ({}, None),
    ])
    def test_run_commands_input_forms(self, inp, want):
        assert cline._commands(inp) == want

    @pytest.mark.parametrize("files,want", [
        ("/a", "/a"), (["/a", "/b"], "/a"), ({"file_path": "/c"}, "/c"),
        ([{"filePath": "/d"}], "/d"), ([], None),
    ])
    def test_read_files_input_forms(self, files, want):
        assert cline._first_path(files) == want

    @pytest.mark.parametrize("inp", [
        {"files": ["/p"]}, {"file_paths": ["/p"]}, {"file_paths": "/p"},
        {"paths": [{"path": "/p"}]}, {"paths": "/p"}, {"path": "/p"}, "/p",
    ])
    def test_read_files_top_level_forms(self, inp):
        msgs = [
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "r", "name": "read_files", "input": inp}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "r", "content": "x"}]},
        ]
        (a,) = [a for _, a in cline.actions(msgs, sdk=True)]
        assert a.file_path == "/p"


class TestLoad:
    def test_shapes(self, tmp_path):
        assert cline.load(LEGACY)[1] is False
        assert cline.load(SDK)[1] is True
        other = tmp_path / "x.messages.json"
        other.write_text('{"messages": []}', encoding="utf-8")
        assert cline.load(other) is None
        assert cline.load(tmp_path / "missing.json") is None

    def test_torn_read_is_skipped(self, tmp_path):
        p = tmp_path / f"{SID}.messages.json"
        text = SDK.read_text(encoding="utf-8")
        p.write_text(text[: len(text) // 2], encoding="utf-8")
        assert cline.load(p) is None
        assert list(cline.parse_cline(p)) == []


class TestWatcher:
    def _write(self, path, msgs):
        path.write_text(json.dumps(msgs), encoding="utf-8")

    def test_emit_once_after_result(self, tmp_path):
        from agentwatch.parser.watcher import ClineWatcher

        msgs = json.loads(LEGACY.read_text(encoding="utf-8"))
        p = tmp_path / "api_conversation_history.json"
        self._write(p, msgs)
        w = ClineWatcher(p)
        first = w._read_new_actions()
        assert len(first) == 9 and "web_fetch" not in [a.tool_name for a in first]
        assert w._read_new_actions() == []
        msgs.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_05",
                     "content": "[web_fetch for 'x'] Result:\nok"}]})
        self._write(p, msgs)
        (fetch,) = w._read_new_actions()
        assert fetch.tool_name == "web_fetch" and fetch.network_host == "docs.example.com"

    def test_rewrite_after_truncation_emits_new_usage(self, tmp_path):
        # Checkpoint restore: history truncated, new messages reuse the indexes.
        from agentwatch.parser.watcher import ClineWatcher

        def asst(n, ts):
            return {"role": "assistant", "ts": ts, "content": [{"type": "text", "text": n}],
                    "metrics": {"tokens": {"prompt": n * 10, "completion": 1}, "cost": 0.1}}

        user = {"role": "user", "content": "go"}
        p = tmp_path / "api_conversation_history.json"
        self._write(p, [user, asst(1, 1), user, asst(2, 2), user, asst(3, 3)])
        w = ClineWatcher(p)
        assert len(w._read_new_actions()) == 3
        self._write(p, [user, asst(1, 1), user, asst(20, 20), user, asst(30, 30)])
        assert [a.tokens_in for a in w._read_new_actions()] == [200, 300]

    def test_torn_read_is_retried_on_tick(self, tmp_path):
        from agentwatch.parser.watcher import ClineWatcher

        p = tmp_path / f"{SID}.messages.json"
        text = SDK.read_text(encoding="utf-8")
        p.write_text(text[:100], encoding="utf-8")
        w = ClineWatcher(p)
        assert w._read_new_actions() == [] and w._held  # parent re-reads while held
        p.write_text(text, encoding="utf-8")
        assert len(w._read_new_actions()) == 6 and not w._held

    async def test_watch_retries_torn_read_without_change(self, tmp_path, monkeypatch):
        import asyncio

        from agentwatch.parser import cline as parser_cline
        from agentwatch.parser.watcher import ClineWatcher

        p = tmp_path / f"{SID}.messages.json"
        p.write_text(SDK.read_text(encoding="utf-8"), encoding="utf-8")
        real, calls = parser_cline.load, []

        def flaky(path):  # first read torn, later reads whole; the file never changes
            calls.append(path)
            return None if len(calls) == 1 else real(path)

        monkeypatch.setattr(parser_cline, "load", flaky)
        w = ClineWatcher(p)

        async def first():
            async for a in w.watch():
                return a

        assert (await asyncio.wait_for(first(), timeout=10)) is not None

    def test_torn_rewrite_keeps_state(self, tmp_path):
        from agentwatch.parser.watcher import ClineWatcher

        p = tmp_path / f"{SID}.messages.json"
        text = SDK.read_text(encoding="utf-8")
        p.write_text(text, encoding="utf-8")
        w = ClineWatcher(p, session_id=SID)
        assert len(w._read_new_actions()) == 6
        p.write_text(text[:100], encoding="utf-8")
        assert w._read_new_actions() == []
        p.write_text(text, encoding="utf-8")
        assert w._read_new_actions() == []  # nothing re-emitted

    def test_adapter_makes_watcher(self):
        from agentwatch.parser.watcher import ClineWatcher

        w = agents.get("cline").make_watcher(SDK, SID)
        assert isinstance(w, ClineWatcher) and w.path == SDK and w.session_id == SID


class TestRouting:
    def test_claims(self, tmp_path):
        adapter = agents.get("cline")
        assert adapter.claims(LEGACY) and adapter.claims(SDK)
        assert not adapter.claims(FIX / "legacy" / "state" / "taskHistory.json")
        assert not adapter.claims(SDK.parent / f"{SID}.json")  # the manifest
        torn = tmp_path / "t.messages.json"
        torn.write_text("{", encoding="utf-8")
        assert not adapter.claims(torn)

    def test_adapter_for_and_parse_file(self):
        from agentwatch.parser.logs import parse_file

        assert agents.adapter_for(LEGACY).name == "cline"
        assert agents.adapter_for(SDK).name == "cline"
        assert not agents.get("claude-code").claims(SDK)
        assert len(list(parse_file(SDK))) == 6

    @pytest.mark.parametrize("ext_id,want", [
        ("saoudrizwan.claude-dev", "cline"),
        ("rooveterinaryinc.roo-cline", None),  # Roo Code (#117)
        ("kilocode.kilo-code", None),  # Kilo Code (#118)
    ])
    def test_legacy_routes_by_extension_id(self, tmp_path, ext_id, want):
        task = tmp_path / "User" / "globalStorage" / ext_id / "tasks" / TASK_ID
        task.mkdir(parents=True)
        log = task / "api_conversation_history.json"
        shutil.copy(LEGACY, log)
        got = agents.adapter_for(log)
        assert (got.name if got else None) == want

    def test_legacy_outside_global_storage_is_cline(self, tmp_path):
        log = tmp_path / "api_conversation_history.json"  # e.g. a copied file
        shutil.copy(LEGACY, log)
        assert agents.adapter_for(log).name == "cline"

    def test_does_not_claim_jsonl(self):
        cp = Path(__file__).parent / "fixtures" / "copilot_vscode"
        for p in cp.glob("*.jsonl"):
            assert not agents.get("cline").claims(p)


def _copy_tree(tmp_path):
    shutil.copytree(FIX, tmp_path / "cline")
    return tmp_path / "cline"


class TestDiscovery:
    @pytest.fixture
    def legacy_user(self, tmp_path):
        root = _copy_tree(tmp_path)
        user = tmp_path / "User"
        (user / "globalStorage").mkdir(parents=True)
        shutil.move(root / "legacy", user / "globalStorage" / "saoudrizwan.claude-dev")
        return user

    def _legacy(self, user, now):
        return cline_agent._legacy_agents(user, now)

    def test_legacy_entry(self, legacy_user):
        log = next(legacy_user.glob("globalStorage/*/tasks/*/api_conversation_history.json"))
        (a,) = self._legacy(legacy_user, log.stat().st_mtime + 10)
        from agentwatch.cursor_discovery import _synthetic_pid

        assert (a.agent_type, a.session_id, a.log_file) == ("cline", TASK_ID, log)
        assert a.working_directory == Path("/home/dev/project")
        assert a.pid == _synthetic_pid(TASK_ID) and a.command == "vscode (cline)"

    def test_legacy_recency_and_unresolved_cwd(self, legacy_user):
        log = next(legacy_user.glob("globalStorage/*/tasks/*/api_conversation_history.json"))
        assert self._legacy(legacy_user, log.stat().st_mtime + 1801) == []
        (legacy_user / "globalStorage/saoudrizwan.claude-dev/state/taskHistory.json").unlink()
        (a,) = self._legacy(legacy_user, log.stat().st_mtime)
        assert a.working_directory is None

    def test_legacy_process_gate(self, legacy_user, tmp_path, monkeypatch):
        monkeypatch.setattr(cline_agent, "_vscode_running", lambda: False)
        empty = tmp_path / "no-sessions"
        assert cline_agent.find_cline_agents(user_dir=legacy_user, sessions_dir=empty) == []
        got = cline_agent.find_cline_agents(
            user_dir=legacy_user, sessions_dir=empty, require_running=False, now=1e12
        )
        assert got == []  # gate bypassed, but everything is outside the window

    @pytest.fixture
    def sessions(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cline_agent.psutil, "pid_exists", lambda pid: pid == 4242)
        return _copy_tree(tmp_path) / "sdk" / "sessions"

    def _now(self, sessions):
        return (sessions / SID / f"{SID}.messages.json").stat().st_mtime + 10

    def _manifest(self, sessions, **changes):
        p = sessions / SID / f"{SID}.json"
        data = json.loads(p.read_text(encoding="utf-8"))
        data.update(changes)
        p.write_text(json.dumps(data), encoding="utf-8")

    def test_sdk_entry(self, sessions):
        from agentwatch.cursor_discovery import _synthetic_pid

        (a,) = cline_agent._sdk_agents(sessions, self._now(sessions))  # subagent file skipped
        assert (a.session_id, a.command) == (SID, "cline (cli)")
        assert a.log_file == sessions / SID / f"{SID}.messages.json"  # not messages_path
        assert a.working_directory == Path("/home/dev/project")
        assert a.pid == _synthetic_pid(SID) and a.uptime

    @pytest.mark.parametrize("change", [
        {"status": "completed"}, {"status": "failed"}, {"pid": 1}, {"pid": "4242"},
    ])
    def test_sdk_finished_or_dead_skipped(self, sessions, change):
        self._manifest(sessions, **change)
        assert cline_agent._sdk_agents(sessions, self._now(sessions)) == []

    def test_sdk_idle_and_vscode_source(self, sessions):
        self._manifest(sessions, status="idle", source="vscode")
        (a,) = cline_agent._sdk_agents(sessions, self._now(sessions))
        assert a.command == "cline (vscode)"

    def test_sdk_recency(self, sessions):
        assert cline_agent._sdk_agents(sessions, self._now(sessions) + 1800) == []

    def test_bad_manifest_never_raises(self, sessions):
        (sessions / SID / f"{SID}.json").write_text("{", encoding="utf-8")
        assert cline_agent.find_cline_agents(
            user_dir=sessions, sessions_dir=sessions, require_running=False
        ) == []

    def test_sessions_dir_env(self, monkeypatch, tmp_path):
        for name in ("CLINE_SESSION_DATA_DIR", "CLINE_DATA_DIR", "CLINE_DIR"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setattr(cline_agent.Path, "home", lambda: tmp_path)
        assert cline_agent.cline_sessions_dir() == tmp_path / ".cline" / "data" / "sessions"
        monkeypatch.setenv("CLINE_DIR", " /c ")
        assert cline_agent.cline_sessions_dir() == Path("/c/data/sessions")
        monkeypatch.setenv("CLINE_DATA_DIR", "/d")
        assert cline_agent.cline_sessions_dir() == Path("/d/sessions")
        monkeypatch.setenv("CLINE_SESSION_DATA_DIR", "/s")
        assert cline_agent.cline_sessions_dir() == Path("/s")
        monkeypatch.setenv("CLINE_SESSION_DATA_DIR", "  ")  # blank: ignored, like Cline
        assert cline_agent.cline_sessions_dir() == Path("/d/sessions")

    def test_discover_delegates(self, monkeypatch):
        monkeypatch.setattr(cline_agent, "find_cline_agents", lambda: ["x"])
        assert agents.get("cline").discover() == ["x"]
