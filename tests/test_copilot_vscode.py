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
        assert "Zaid" not in text and "zaid-akroush" not in text
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
