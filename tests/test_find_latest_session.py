"""find_latest_session prefers main sessions over subagent logs (#63)."""

import os

from agentwatch.parser import find_latest_session


def _touch(path, mtime):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}\n")
    os.utime(path, (mtime, mtime))


def test_skips_newer_subagent_log(tmp_path):
    main = tmp_path / "proj" / "s1.jsonl"
    _touch(main, 1000)
    _touch(tmp_path / "proj" / "s1" / "subagents" / "agent-a1.jsonl", 2000)
    assert find_latest_session(tmp_path) == main


def test_falls_back_to_subagent_log_when_alone(tmp_path):
    sub = tmp_path / "proj" / "s1" / "subagents" / "agent-a1.jsonl"
    _touch(sub, 2000)
    assert find_latest_session(tmp_path) == sub


def test_none_when_empty(tmp_path):
    assert find_latest_session(tmp_path) is None
