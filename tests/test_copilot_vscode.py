"""GitHub Copilot in VS Code: chat-session mutation log (#87)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from agentwatch.parser.copilot_vscode import actions, parse_copilot_vscode, replay
from agentwatch.parser.models import ToolType

FIXTURE = Path(__file__).parent / "fixtures" / "copilot_vscode" / "session.jsonl"
SESSION_ID = "b4d87730-a8da-47a4-8a80-c39642ea196f"


def _lines() -> list[str]:
    return FIXTURE.read_text(encoding="utf-8").splitlines()


def _prefix(tmp_path: Path, last: int) -> Path:
    """Copy of the fixture's lines 0..last."""
    p = tmp_path / f"{SESSION_ID}.jsonl"
    p.write_text("\n".join(_lines()[: last + 1]) + "\n", encoding="utf-8")
    return p


def _write(path: Path, entries: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")
    return path


def _tool_part(**kw) -> dict:
    return {"kind": "toolInvocationSerialized", "toolCallId": "c1", "toolId": "x",
            "isComplete": True, **kw}


def _state(parts: list[dict], model_state: int = 0) -> dict:
    return {"sessionId": "s", "requests": [{
        "requestId": "r1", "timestamp": 1791566809923,
        "modelState": {"value": model_state}, "response": parts,
    }]}


class TestReplay:
    def test_set_push_delete(self, tmp_path):
        p = _write(tmp_path / "s.jsonl", [
            {"kind": 0, "v": {"sessionId": "s", "requests": [], "a": {"b": 1}, "arr": [1, 2, 3]}},
            {"kind": 1, "k": ["a", "b"], "v": 2},
            {"kind": 2, "k": ["arr"], "v": [4], "i": 1},
            {"kind": 2, "k": ["arr"], "v": [5]},
            {"kind": 1, "k": ["a", "c"], "v": 3},
            {"kind": 3, "k": ["a", "b"]},
        ])
        state = replay(p)
        assert state["a"] == {"c": 3}
        assert state["arr"] == [1, 4, 5]

    def test_push_without_v_truncates(self, tmp_path):
        p = _write(tmp_path / "s.jsonl", [
            {"kind": 0, "v": {"sessionId": "s", "requests": [], "arr": [1, 2, 3]}},
            {"kind": 2, "k": ["arr"], "i": 0},
        ])
        assert replay(p)["arr"] == []

    def test_push_creates_missing_or_null_array(self, tmp_path):
        # VS Code's _applyPush: arr = current[key] || []
        p = _write(tmp_path / "s.jsonl", [
            {"kind": 0, "v": {"sessionId": "s", "requests": [], "nul": None, "n": 1}},
            {"kind": 2, "k": ["missing"], "v": [1]},
            {"kind": 2, "k": ["nul"], "v": [2]},
            {"kind": 2, "k": ["n"], "v": [3]},
        ])
        state = replay(p)
        assert (state["missing"], state["nul"], state["n"]) == ([1], [2], 1)

    def test_later_kind0_resets(self, tmp_path):
        p = _write(tmp_path / "s.jsonl", [
            {"kind": 0, "v": {"sessionId": "s", "requests": [], "old": 1}},
            {"kind": 0, "v": {"sessionId": "s", "requests": [], "new": 2}},
        ])
        assert replay(p) == {"sessionId": "s", "requests": [], "new": 2}

    def test_no_initial_is_none(self, tmp_path):
        p = _write(tmp_path / "s.jsonl", [{"kind": 1, "k": ["a"], "v": 1}])
        assert replay(p) is None
        assert replay(tmp_path / "missing.jsonl") is None

    def test_bad_lines_and_paths_skipped(self, tmp_path):
        p = _write(tmp_path / "s.jsonl", [
            {"kind": 0, "v": {"sessionId": "s", "requests": []}},
            {"kind": 1, "k": ["nope", 0, "x"], "v": 1},
            {"kind": 2, "k": ["requests", 5], "v": [1]},
            {"kind": 3, "k": ["missing"]},
            {"kind": 1, "k": [], "v": 1},
            {"kind": 9},
            [1, 2],
        ])
        with open(p, "a", encoding="utf-8") as f:
            f.write('{"kind":1,"k":["requests"],"v":')  # partial last line
        assert replay(p) == {"sessionId": "s", "requests": []}


class TestFixture:
    def test_scrubbed(self):
        text = FIXTURE.read_text(encoding="utf-8")
        assert "zaid" not in text.lower() and "akroush" not in text.lower()
        assert len(_lines()) == 23

    def test_full_session(self):
        got = actions(replay(FIXTURE))
        tools = [a for _, a in got if a.tool_name != "assistant_message"]
        assert [(a.tool_name, a.tool_type) for a in tools] == [
            ("copilot_readFile", ToolType.READ),
            ("copilot_memory", ToolType.UNKNOWN),
            ("copilot_applyPatch", ToolType.EDIT),
            ("run_in_terminal", ToolType.BASH),
            ("run_in_terminal", ToolType.BASH),
        ]
        read, memory, patch, ok, bad = tools
        assert read.file_path == str(Path("c:/Users/dev/Desktop/aw-vscode-test/hello.py"))
        assert patch.file_path == read.file_path
        assert memory.file_path is None  # invocationMessage is a plain string
        assert all(a.success for a in (read, memory, patch))  # resultError: false
        assert (ok.command, ok.success, ok.duration_ms) == ("python hello.py", True, 823)
        assert (bad.command, bad.success, bad.error_message) == (
            "nonexistent-cmd", False, "exit code 1",
        )
        assert all(a.unpriced and a.cost_usd == 0 for _, a in got)
        assert all(a.session_id == SESSION_ID for _, a in got)
        assert ok.timestamp == datetime(2026, 10, 9, 17, 26, 49, 923000)  # request ms, naive UTC
        assert [k for k, _ in got][-1] == "request_4e1fc19f-564f-43cd-a4da-579253b15efb"

    def test_parse_copilot_vscode(self):
        assert len(list(parse_copilot_vscode(FIXTURE))) == 6

    def test_pending_terminal_call_waits_for_rewrite(self, tmp_path):
        # Line 9: run_in_terminal pushed without isConfirmed (waiting for the user).
        got = actions(replay(_prefix(tmp_path, 9)))
        assert [a.tool_name for _, a in got] == [
            "copilot_readFile", "copilot_memory", "copilot_applyPatch",
        ]
        # Line 12 rewrites it (kind 2, i=20) with isConfirmed and exitCode 0.
        got = actions(replay(_prefix(tmp_path, 12)))
        term = [a for _, a in got if a.tool_name == "run_in_terminal"]
        assert len(term) == 1 and term[0].success

    def test_assistant_message_waits_for_finished_request(self, tmp_path):
        # Lines 4/5 set 431/20275 while modelState is 4; not final yet.
        got = actions(replay(_prefix(tmp_path, 15)))
        assert "assistant_message" not in [a.tool_name for _, a in got]
        msg = [a for _, a in actions(replay(FIXTURE)) if a.tool_name == "assistant_message"]
        assert len(msg) == 1
        assert (msg[0].tokens_in, msg[0].tokens_out) == (20603, 588)


class TestSuccess:
    def _one(self, part, model_state=0):
        got = actions(_state([part], model_state))
        return got[0][1] if got else None

    def test_denied_and_skipped(self):
        for conf, msg in (({"type": 0}, "denied"), (False, "denied"), ({"type": 5}, "skipped")):
            a = self._one(_tool_part(isConfirmed=conf))
            assert (a.success, a.error_message) == (False, msg)

    def test_result_error_string(self):
        a = self._one(_tool_part(isConfirmed={"type": 1}, resultError="boom"))
        assert (a.success, a.error_message) == (False, "boom")

    def test_result_details_is_error(self):
        a = self._one(_tool_part(isConfirmed={"type": 1}, resultDetails={"isError": True}))
        assert a.success is False

    def test_confirmed_without_result_waits(self):
        part = _tool_part(isConfirmed={"type": 1})
        assert self._one(part) is None
        assert self._one(part, model_state=4) is None  # NeedsInput is not finished
        assert self._one(part, model_state=1).success  # request finished
        later = actions(_state([part, {"value": "done"}]))  # later markdown part
        assert [k for k, _ in later] == ["c1"]

    def test_bad_request_shapes_never_raise(self):
        assert actions({"requests": [None, {"response": "x"}, {"response": [None, 1]}]}) == []
        assert actions({"requests": "x"}) == []


class TestAdapter:
    def test_sniff_and_claims(self):
        from agentwatch import agents
        from agentwatch.agents.base import sniff_jsonl_format

        assert sniff_jsonl_format(FIXTURE) == "copilot_vscode"
        assert agents.adapter_for(FIXTURE).name == "copilot-vscode"
        assert not agents.get("claude-code").claims(FIXTURE)

    def test_parse_file(self):
        from agentwatch.parser.logs import parse_file

        got = list(parse_file(FIXTURE))
        assert [a.tool_name for a in got] == [
            "copilot_readFile", "copilot_memory", "copilot_applyPatch",
            "run_in_terminal", "run_in_terminal", "assistant_message",
        ]


class TestWatcher:
    def test_emits_each_key_once(self, tmp_path):
        from agentwatch.parser.watcher import CopilotVscodeWatcher

        lines = _lines()
        p = _prefix(tmp_path, 9)
        w = CopilotVscodeWatcher(p)
        assert [a.tool_name for a in w._read_new_actions()] == [
            "copilot_readFile", "copilot_memory", "copilot_applyPatch",
        ]
        assert w._read_new_actions() == []
        with open(p, "a", encoding="utf-8") as f:
            f.write("\n".join(lines[10:13]) + "\n")
        got = w._read_new_actions()
        assert [(a.tool_name, a.command) for a in got] == [("run_in_terminal", "python hello.py")]
        with open(p, "a", encoding="utf-8") as f:
            f.write("\n".join(lines[13:]) + "\n")
        got = w._read_new_actions()
        assert [a.tool_name for a in got] == ["run_in_terminal", "assistant_message"]
        assert w._read_new_actions() == []

    def test_adapter_makes_watcher(self):
        from agentwatch import agents
        from agentwatch.parser.watcher import CopilotVscodeWatcher

        w = agents.get("copilot-vscode").make_watcher(FIXTURE, SESSION_ID)
        assert isinstance(w, CopilotVscodeWatcher)
        assert w.path == FIXTURE and w.session_id == SESSION_ID


def test_default_user_dir(monkeypatch):
    from agentwatch import vscode_paths

    monkeypatch.setattr(vscode_paths.sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", r"C:\Users\dev\AppData\Roaming")
    assert vscode_paths.default_user_dir("Code") == (
        Path(r"C:\Users\dev\AppData\Roaming") / "Code" / "User"
    )


class TestDiscovery:
    def _user_dir(self, tmp_path: Path, folder: bool = True, session: str | None = None) -> Path:
        user = tmp_path / "User"
        ws = user / "workspaceStorage" / "hash1"
        (ws / "chatSessions").mkdir(parents=True)
        if folder:
            (tmp_path / "proj").mkdir()
            (ws / "workspace.json").write_text(
                json.dumps({"folder": (tmp_path / "proj").as_uri()}), encoding="utf-8"
            )
        log = ws / "chatSessions" / f"{SESSION_ID}.jsonl"
        log.write_text(session or FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
        return user

    def _find(self, user: Path, **kw):
        from agentwatch.agents.copilot_vscode import find_copilot_vscode_agents

        return find_copilot_vscode_agents(user_dir=user, require_running=False, **kw)

    def test_happy_path(self, tmp_path):
        from agentwatch.cursor_discovery import _synthetic_pid

        user = self._user_dir(tmp_path)
        [proc] = self._find(user)
        assert proc.agent_type == "copilot-vscode"
        assert proc.log_file == user / "workspaceStorage/hash1/chatSessions" / f"{SESSION_ID}.jsonl"
        assert proc.session_id == SESSION_ID
        assert proc.pid == _synthetic_pid(SESSION_ID)
        assert proc.working_directory == tmp_path / "proj"
        assert proc.command == "vscode (copilot)"
        assert proc.uptime

    def test_recency_cutoff(self, tmp_path):
        user = self._user_dir(tmp_path)
        log = next(user.glob("workspaceStorage/*/chatSessions/*.jsonl"))
        mtime = log.stat().st_mtime
        assert len(self._find(user, now=mtime + 1799)) == 1
        assert self._find(user, now=mtime + 1801) == []

    def test_unresolved_workspace_skipped(self, tmp_path):
        assert self._find(self._user_dir(tmp_path, folder=False)) == []

    def test_empty_session_skipped(self, tmp_path):
        empty = json.dumps({"kind": 0, "v": {"sessionId": SESSION_ID, "requests": []}})
        assert self._find(self._user_dir(tmp_path, session=empty + "\n")) == []

    def test_missing_dir_and_process_gate(self, tmp_path, monkeypatch):
        from agentwatch import agents
        from agentwatch.agents import copilot_vscode

        assert self._find(tmp_path / "nope") == []
        monkeypatch.setattr(copilot_vscode, "_vscode_running", lambda: False)
        assert copilot_vscode.find_copilot_vscode_agents(user_dir=self._user_dir(tmp_path)) == []
        monkeypatch.setattr(copilot_vscode, "find_copilot_vscode_agents", lambda: ["x"])
        assert agents.get("copilot-vscode").discover() == ["x"]


def test_create_file_and_list_directory_seen_live():
    def part(tool_id, uri, call_id):
        return _tool_part(toolId=tool_id, toolCallId=call_id, isConfirmed={"type": 1},
                          invocationMessage={"value": "x", "uris": {uri: {}}})

    got = actions(_state([
        part("copilot_createFile", "file:///c%3A/proj/new.py", "c1"),
        part("copilot_listDirectory", "file:///c%3A/proj", "c2"),
    ], model_state=1))
    create, listing = [a for _, a in got if a.tool_name != "assistant_message"]
    assert (create.tool_type, create.file_path) == (ToolType.WRITE, str(Path("c:/proj/new.py")))
    assert (listing.tool_type, listing.file_path) == (ToolType.LIST, str(Path("c:/proj")))


def test_ps_columns_fit_editor_agents(capsys, tmp_path):
    from agentwatch.cli import _print_agents_view, _print_teams_view
    from agentwatch.discovery import AgentProcess

    proc = AgentProcess(pid=1809276400, agent_type="copilot-vscode",
                        working_directory=tmp_path / "aw-vscode-test", team_id=1809276400)
    _print_agents_view([proc])
    _print_teams_view([proc])
    rows = [line for line in capsys.readouterr().out.splitlines() if "1809276400" in line]
    assert len(rows) == 2
    assert all("1809276400  copilot-vscode  aw-vscode-test" in r for r in rows)


def test_replace_string_and_find_text_seen_live():
    def part(tool_id, uris, call_id):
        return _tool_part(toolId=tool_id, toolCallId=call_id, isConfirmed={"type": 1},
                          invocationMessage={"value": "x", "uris": uris})

    got = actions(_state([
        part("copilot_replaceString", {"file:///c%3A/proj/a.py": {}}, "c1"),
        part("copilot_findTextInFiles", {}, "c2"),
        part("copilot_fetchWebPage", {}, "c3"),
    ], model_state=1))
    edit, search, fetch = [a for _, a in got if a.tool_name != "assistant_message"]
    assert (edit.tool_type, edit.file_path) == (ToolType.EDIT, str(Path("c:/proj/a.py")))
    assert (search.tool_type, search.file_path) == (ToolType.SEARCH, None)
    assert fetch.tool_type == ToolType.UNKNOWN
