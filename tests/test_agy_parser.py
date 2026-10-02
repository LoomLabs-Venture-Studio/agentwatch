"""agy (Antigravity CLI) transcript parsing + discovery.

Step shapes are copied from live agy 1.2.14 sessions (2026-10-01): one that
read a file, edited it, ran a shell command and read a missing file, and one
that ran a background command.
"""

import json
import re
from types import SimpleNamespace

from agentwatch import agents
from agentwatch.agents import agy as agy_adapter
from agentwatch.parser.logs import detect_log_format, parse_file
from agentwatch.parser.models import ToolType


def _step(i, type_, ts, status="DONE", **extra):
    return {"step_index": i, "source": "MODEL", "type": type_, "status": status,
            "created_at": f"2026-10-01T12:38:{ts}Z", **extra}


def _call(i, ts, name, **args):
    # agy JSON-encodes every argument value.
    return _step(i, "PLANNER_RESPONSE", ts, tool_calls=[
        {"name": name, "args": {k: json.dumps(v) for k, v in args.items()}}])


SESSION = [
    {"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "status": "DONE",
     "created_at": "2026-10-01T12:38:27Z", "content": "<USER_REQUEST>\nRead notes.txt ..."},
    _call(1, "27", "view_file", AbsolutePath="/tmp/aw-test/notes.txt"),
    _step(2, "GENERIC", "32", content="File Path: `file:///tmp/aw-test/notes.txt`\n1: hello\n"),
    _call(3, "32", "replace_file_content", TargetFile="/tmp/aw-test/notes.txt",
          TargetContent="hello\n", ReplacementContent="hello world\n"),
    _step(4, "GENERIC", "36", content="The following changes were made ..."),
    _call(5, "36", "run_command", CommandLine="python3 --version", Cwd="/tmp/aw-test"),
    _step(6, "GENERIC", "45",
          content="\nThe command exited with code 0.\nOutput:\nPython 3.14.6\r\n"),
    _call(7, "45", "view_file", AbsolutePath="/tmp/aw-test/missing.txt"),
    _step(8, "GENERIC", "51", status="ERROR",
          error="failed to read file: stat /tmp/aw-test/missing.txt: no such file or directory"),
    _step(9, "PLANNER_RESPONSE", "51", content="Here are the results ..."),
]


def _write(path, entries):
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
    return path


def test_detects_agy_format(tmp_path):
    assert detect_log_format(SESSION[0]) == "agy"
    # Claimed by the agy adapter, not claude-code's JSONL catch-all.
    assert agents.adapter_for(_write(tmp_path / "transcript.jsonl", SESSION)).name == "agy"


def test_parses_real_session_shape(tmp_path):
    actions = list(parse_file(_write(tmp_path / "transcript.jsonl", SESSION)))

    assert [(a.tool_name, a.tool_type, a.success) for a in actions] == [
        ("view_file", ToolType.READ, True),
        ("replace_file_content", ToolType.EDIT, True),
        ("run_command", ToolType.BASH, True),
        ("view_file", ToolType.READ, False),
    ]
    view, edit, run, missing = actions
    assert view.file_path == "/tmp/aw-test/notes.txt"  # JSON-decoded, no quotes
    assert view.duration_ms == 5000
    assert edit.file_path == "/tmp/aw-test/notes.txt"
    assert run.command == "python3 --version"
    assert "no such file" in missing.error_message


def test_session_id_comes_from_caller(tmp_path):
    path = _write(tmp_path / "transcript.jsonl", SESSION)
    assert {a.session_id for a in parse_file(path, session_id="cid-1")} == {"cid-1"}


def test_nonzero_exit_code_is_a_failure(tmp_path):
    entries = SESSION[:1] + [
        _call(1, "27", "run_command", CommandLine="false"),
        _step(2, "GENERIC", "28", content="\nThe command exited with code 1.\nOutput:\n"),
    ]
    [action] = parse_file(_write(tmp_path / "transcript.jsonl", entries))
    assert (action.success, action.error_message) == (False, "exit code 1")


def test_background_command_counted_once(tmp_path):
    # Seen live: a background command's step stays RUNNING and is never
    # updated; completion arrives as a SYSTEM_MESSAGE.
    entries = SESSION[:1] + [
        _call(1, "27", "run_command", CommandLine="sleep 25"),
        _step(2, "GENERIC", "28", status="RUNNING", content="Tool is running as a background task"),
        _step(3, "PLANNER_RESPONSE", "29", content="Waiting for it to finish..."),
        _step(4, "SYSTEM_MESSAGE", "53", content="The following is a <SYSTEM_MESSAGE> ..."),
        _step(5, "PLANNER_RESPONSE", "54", content="done"),
    ]
    actions = list(parse_file(_write(tmp_path / "transcript.jsonl", entries)))
    assert [(a.command, a.success) for a in actions] == [("sleep 25", True)]


def test_process_pattern():
    adapter = agents.get("agy")

    def matches(cmd):
        return bool(re.search(adapter.process_pattern, cmd))

    assert matches("agy --dangerously-skip-permissions -p hi")  # seen live
    assert matches("/home/u/.local/bin/agy")
    assert not matches("/bin/bash -c pgrep -af 'agy|antigravity'")
    assert not matches("/usr/bin/agyle")


def test_resolve_log_from_presence_lock(tmp_path, monkeypatch):
    monkeypatch.setattr(agy_adapter, "AGY_HOME", tmp_path)
    lock = tmp_path / "presence" / "cid-1.lock"
    lock.parent.mkdir()
    lock.touch()
    proc = SimpleNamespace(open_files=lambda: [SimpleNamespace(path=str(lock))])
    monkeypatch.setattr(agy_adapter.psutil, "Process", lambda pid: proc)

    # Transcript not written yet -> session known, no log.
    assert agy_adapter.resolve_agy_log(tmp_path, pid=1) == (None, "cid-1")
    log = tmp_path / "brain" / "cid-1" / ".system_generated" / "logs" / "transcript.jsonl"
    log.parent.mkdir(parents=True)
    _write(log, SESSION[:1])
    assert agy_adapter.resolve_agy_log(tmp_path, pid=1) == (log, "cid-1")


def test_resolve_log_without_pid(tmp_path):
    assert agy_adapter.resolve_agy_log(tmp_path) == (None, None)
