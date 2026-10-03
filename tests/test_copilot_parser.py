"""Copilot CLI events.jsonl parsing + discovery.

Event shapes are copied from a live Copilot CLI 1.0.90 session (2026-10-01)
that read a file, edited it, ran a shell command and read a missing file.
"""

import json
import re

from agentwatch import agents
from agentwatch.agents.copilot import resolve_copilot_log as _resolve_copilot_log
from agentwatch.parser.logs import detect_log_format, parse_file
from agentwatch.parser.models import ToolType

SID = "a972b7b2-bccd-416f-bbbd-c2f4980ec53a"


def _ev(type_, data, ts):
    return {"type": type_, "data": data, "id": f"id-{ts}", "parentId": None,
            "timestamp": f"2026-10-01T12:21:{ts}Z"}


def _start(call_id, name, args, ts):
    return _ev("tool.execution_start",
               {"toolCallId": call_id, "toolName": name, "arguments": args, "turnId": "0"}, ts)


def _done(call_id, ts, success=True, content="ok", error=None):
    data = {"toolCallId": call_id, "turnId": "0", "success": success}
    if success:
        data["result"] = {"content": content}
    else:
        data["error"] = {"message": error, "code": "failure"}
    return _ev("tool.execution_complete", data, ts)


SESSION = [
    _ev("session.start", {"sessionId": SID, "producer": "copilot-agent",
                          "copilotVersion": "1.0.90",
                          "context": {"cwd": "/tmp/aw-test"}}, "50.257"),
    _ev("user.message", {"content": "Read notes.txt ..."}, "53.301"),
    _start("c1", "view", {"path": "/tmp/aw-test/notes.txt"}, "56.000"),
    _start("c2", "bash", {"command": "python3 --version", "mode": "sync"}, "56.100"),
    _done("c1", "56.500", content="hello\n"),
    _done("c2", "57.000", content="Python 3.14.6\n<shellId: 0 completed with exit code 0>"),
    _start("c3", "edit", {"path": "/tmp/aw-test/notes.txt", "old_str": "hello",
                          "new_str": "hello world"}, "57.300"),
    _done("c3", "58.700", content="File /tmp/aw-test/notes.txt updated with changes."),
    _start("c4", "view", {"path": "/tmp/aw-test/missing.txt"}, "59.000"),
    _done("c4", "59.900", success=False, error="Path does not exist"),
    _ev("session.shutdown", {"shutdownType": "routine"}, "59.950"),
]


def _write(path, entries):
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
    return path


def _tools(path):
    """Tool actions only; user prompts are emitted as separate user_message actions."""
    return [a for a in parse_file(path) if a.tool_name != "user_message"]


def test_detects_copilot_format(tmp_path):
    assert detect_log_format(SESSION[0]) == "copilot"
    # Claimed by the copilot adapter, not claude-code's JSONL catch-all.
    assert agents.adapter_for(_write(tmp_path / "events.jsonl", SESSION)).name == "copilot"


def test_parses_real_session_shape(tmp_path):
    actions = _tools(_write(tmp_path / "events.jsonl", SESSION))

    assert [(a.tool_name, a.tool_type, a.success) for a in actions] == [
        ("view", ToolType.READ, True),
        ("bash", ToolType.BASH, True),
        ("edit", ToolType.EDIT, True),
        ("view", ToolType.READ, False),
    ]
    view, bash, edit, missing = actions
    assert view.file_path == "/tmp/aw-test/notes.txt"
    assert view.raw["content"] == "hello\n"  # tool output, not incoming_message
    assert view.duration_ms == 500
    assert bash.command == "python3 --version"
    assert edit.file_path == "/tmp/aw-test/notes.txt"
    assert missing.error_message == "Path does not exist"
    assert all(a.session_id == SID for a in actions)


def test_uncompleted_call_flushed_at_eof(tmp_path):
    entries = SESSION[:1] + [_start("c9", "bash", {"command": "sleep 999"}, "56.000")]
    actions = list(parse_file(_write(tmp_path / "events.jsonl", entries)))
    assert [(a.command, a.success) for a in actions] == [("sleep 999", True)]


def test_process_pattern_skips_loader_and_vscode_extension():
    adapter = agents.get("copilot")

    def matches(cmd):
        return bool(re.search(adapter.process_pattern, cmd)) and not re.search(
            adapter.process_exclude, cmd
        )

    lib = "/home/u/.nvm/versions/node/v24/lib/node_modules/@github"
    assert matches(f"{lib}/copilot/node_modules/@github/copilot-linux-x64/copilot -p hi")
    assert not matches(f"node {lib}/copilot/npm-loader.js -p hi")
    assert not matches("node /home/u/.nvm/versions/node/v24/bin/copilot")  # seen live
    assert not matches("/usr/share/code/code --type=extensionHost github.copilot-chat-0.30")
    # Found live: VS Code's built-in runtime, and a shell command mentioning the word.
    assert not matches("/usr/share/code/resources/app/node_modules.asar.unpacked/@github/"
                       "copilot-sdk-linux-x64/prebuilds/linux-x64/copilot-runtime --headless")
    assert not matches("/bin/bash -c agentwatch ps | grep -iE 'copilot|TEAM'")
    assert matches(r"C:\Users\u\AppData\copilot-win32-x64\copilot.exe")


def test_resolve_log_prefers_cwd_match(tmp_path, monkeypatch):
    monkeypatch.setenv("COPILOT_HOME", str(tmp_path))
    work = tmp_path / "work"
    work.mkdir()
    for sid, cwd in (("match", work), ("newer-other", tmp_path)):
        d = tmp_path / "session-state" / sid
        d.mkdir(parents=True)
        _write(d / "events.jsonl", [_ev("session.start", {"sessionId": sid,
                                                          "context": {"cwd": str(cwd)}}, "00")])

    log, sid = _resolve_copilot_log(work)
    assert sid == "match"
    assert log == tmp_path / "session-state" / "match" / "events.jsonl"


def test_resolve_log_uses_pid_lock_before_first_message(tmp_path, monkeypatch):
    # A fresh session has inuse.<pid>.lock but no events.jsonl yet; it must
    # not fall back to an older session in the same cwd.
    monkeypatch.setenv("COPILOT_HOME", str(tmp_path))
    old = tmp_path / "session-state" / "old"
    old.mkdir(parents=True)
    _write(old / "events.jsonl", [_ev("session.start", {"sessionId": "old",
                                                        "context": {"cwd": str(tmp_path)}}, "00")])
    new = tmp_path / "session-state" / "new"
    new.mkdir()
    (new / "inuse.4242.lock").write_text("4242")

    assert _resolve_copilot_log(tmp_path, pid=4242) == (None, "new")
    _write(new / "events.jsonl", SESSION[:1])
    assert _resolve_copilot_log(tmp_path, pid=4242) == (new / "events.jsonl", "new")


def test_resolve_log_without_session_state(tmp_path, monkeypatch):
    monkeypatch.setenv("COPILOT_HOME", str(tmp_path))
    assert _resolve_copilot_log(tmp_path) == (None, None)


# Built from pieces so no scanner flags this file itself.
FAKE_GH_TOKEN = "gh" + "p_" + "Zq7Lm2Xc9Vb4Nk8Rt1Yw6Pd3Hs5Jf0Ga2Ue7"


def _scan(actions):
    from agentwatch.detectors.security.secret_scanner import SecretLeakScanner
    from agentwatch.parser.models import ActionBuffer

    buf = ActionBuffer()
    for a in actions:
        buf.add(a)
    return SecretLeakScanner().check(buf)


def test_user_prompt_is_incoming_message_and_tool_output_is_not(tmp_path):
    actions = list(parse_file(_write(tmp_path / "events.jsonl", SESSION)))
    user = actions[0]
    assert (user.tool_name, user.incoming_message) == ("user_message", "Read notes.txt ...")
    assert [a.incoming_message for a in actions[1:]] == [None] * 4
    assert actions[1].raw["content"] == "hello\n"  # tool output, where Claude Code keeps it


def test_secret_in_tool_output_reported_on_tool_output_channel(tmp_path):
    entries = SESSION[:2] + [
        _start("c1", "view", {"path": "/tmp/aw-test/.env"}, "56.000"),
        _done("c1", "56.500", content=f"GITHUB_TOKEN={FAKE_GH_TOKEN}\n"),
    ]
    warning = _scan(parse_file(_write(tmp_path / "events.jsonl", entries)))
    assert warning is not None and warning.details["channel"] == "tool_output"


def test_secret_in_edit_and_create_is_detected(tmp_path):
    # Arg names from @github/copilot 1.0.0's tool schemas (edit: new_str, create: file_text).
    for name, args in (("edit", {"path": "/w/app.py", "old_str": "x", "new_str": None}),
                       ("create", {"path": "/w/app.py", "file_text": None})):
        key = "new_str" if name == "edit" else "file_text"
        args[key] = f'TOKEN = "{FAKE_GH_TOKEN}"\n'
        entries = SESSION[:2] + [_start("c1", name, args, "56.000"), _done("c1", "56.500")]
        warning = _scan(parse_file(_write(tmp_path / "events.jsonl", entries)))
        assert warning is not None and warning.details["channel"] == "file_write", name


def test_web_fetch_sets_hostname_only(tmp_path):
    url = "https://api.example.com:8443/v1/data?token=abc123&x=1"
    entries = SESSION[:2] + [_start("c1", "web_fetch", {"url": url}, "56.000"),
                             _done("c1", "56.500")]
    [fetch] = _tools(_write(tmp_path / "events.jsonl", entries))
    assert fetch.network_host == "api.example.com"
