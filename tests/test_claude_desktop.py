"""Claude Desktop (Cowork sessions) adapter + discovery (#73).

Every fixture is synthetic and built in tmp_path: the directory layout
mirrors a real Claude Desktop install (local-agent-mode-sessions/<a>/<b>/
local_<id>.json + local_<id>/.claude/projects/<dir>/<cliSessionId>.jsonl),
but every id, path and message is invented.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentwatch import agents
from agentwatch import claude_desktop_discovery as cdd
from agentwatch.discovery import AgentProcess
from agentwatch.parser.watcher import LogWatcher

NOW = 1_800_000_000.0  # fixed "current time" (epoch seconds)
CWD = r"C:\work\demo"

TRANSCRIPT = [
    {"type": "user", "sessionId": "cli-aaaa", "timestamp": "2026-10-09T10:00:00.000Z",
     "message": {"role": "user", "content": "list files"}},
    {"type": "assistant", "sessionId": "cli-aaaa", "timestamp": "2026-10-09T10:00:01.000Z",
     "message": {"role": "assistant", "content": [
         {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "ls"}},
     ]}},
    {"type": "user", "sessionId": "cli-aaaa", "timestamp": "2026-10-09T10:00:02.000Z",
     "message": {"role": "user", "content": [
         {"type": "tool_result", "tool_use_id": "toolu_1", "content": "a.txt"},
     ]}},
]


def _session(
    root: Path,
    local_id: str = "local_0001",
    cli_id: str = "cli-aaaa",
    *,
    meta: dict | str | None = None,
    age_s: float = 60,
    archived: bool = False,
    transcript: bool = True,
) -> Path:
    """Write one synthetic Cowork session under *root*; return transcript path."""
    group = root / "local-agent-mode-sessions" / "acct-1" / "org-1"
    group.mkdir(parents=True, exist_ok=True)
    if meta is None:
        meta = {
            "sessionId": local_id, "cliSessionId": cli_id, "cwd": CWD,
            "lastActivityAt": int((NOW - age_s) * 1000), "isArchived": archived,
        }
    (group / f"{local_id}.json").write_text(
        meta if isinstance(meta, str) else json.dumps(meta), encoding="utf-8"
    )
    proj = group / local_id / ".claude" / "projects" / "C--work-demo"
    proj.mkdir(parents=True, exist_ok=True)
    path = proj / f"{cli_id}.jsonl"
    if transcript:
        path.write_text("\n".join(json.dumps(e) for e in TRANSCRIPT) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def root(tmp_path, monkeypatch):
    r = tmp_path / "Claude"
    (r / "local-agent-mode-sessions").mkdir(parents=True)
    monkeypatch.setattr(cdd, "claude_desktop_roots", lambda: [r])
    monkeypatch.setattr(cdd, "is_claude_desktop_running", lambda: True)
    return r


def _find():
    return cdd.find_claude_desktop_agents(now=NOW)


class TestRoots:
    def test_windows_order_and_existence_filter(self, tmp_path, monkeypatch):
        local, appdata = tmp_path / "Local", tmp_path / "Roaming"
        msix = local / "Packages" / "Claude_abc123" / "LocalCache" / "Roaming" / "Claude"
        plain = appdata / "Claude"
        for r in (msix, plain):
            (r / "local-agent-mode-sessions").mkdir(parents=True)
        # A Packages entry without sessions is filtered out.
        (local / "Packages" / "Claude_zzz" / "LocalCache" / "Roaming" / "Claude").mkdir(
            parents=True
        )
        monkeypatch.setattr(cdd.sys, "platform", "win32")
        monkeypatch.setenv("LOCALAPPDATA", str(local))
        monkeypatch.setenv("APPDATA", str(appdata))
        assert cdd.claude_desktop_roots() == [msix, plain]

    def test_windows_none_exist(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cdd.sys, "platform", "win32")
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "a"))
        monkeypatch.setenv("APPDATA", str(tmp_path / "b"))
        assert cdd.claude_desktop_roots() == []

    def test_macos(self, tmp_path, monkeypatch):
        mac = tmp_path / "Library" / "Application Support" / "Claude"
        (mac / "local-agent-mode-sessions").mkdir(parents=True)
        monkeypatch.setattr(cdd.sys, "platform", "darwin")
        monkeypatch.setattr(cdd.Path, "home", lambda: tmp_path)
        assert cdd.claude_desktop_roots() == [mac]


class _Proc:
    def __init__(self, name):
        self.info = {"name": name}


class TestRunningGate:
    @pytest.mark.parametrize(
        ("names", "expected"),
        [
            (["Claude.exe"], True),
            (["Claude"], True),
            (["claude.exe"], False),  # Claude Code, not the desktop app
            (["cowork-svc.exe"], False),  # service runs with the app closed
            ([], False),
        ],
    )
    def test_exact_name(self, monkeypatch, names, expected):
        monkeypatch.setattr(
            cdd.psutil, "process_iter", lambda attrs=None: iter(_Proc(n) for n in names)
        )
        assert cdd.is_claude_desktop_running() is expected

    def test_not_running_returns_empty_with_sessions(self, root, monkeypatch):
        _session(root)
        monkeypatch.setattr(cdd, "is_claude_desktop_running", lambda: False)
        assert _find() == []


class TestFindAgents:
    def test_active_session(self, root):
        transcript = _session(root)
        [agent] = _find()
        assert agent.agent_type == "claude-desktop"
        assert agent.log_file == transcript
        assert agent.session_id == "cli-aaaa"
        assert agent.working_directory == Path(CWD)
        assert agent.command == "Claude Desktop (Cowork)"
        assert agent.pid == cdd._synthetic_pid("local_0001")

    def test_stale_and_archived_skipped(self, root):
        _session(root, "local_0001", "cli-aaaa")
        _session(root, "local_0002", "cli-bbbb", age_s=cdd.ACTIVITY_WINDOW_SECONDS + 1)
        _session(root, "local_0003", "cli-cccc", archived=True)
        assert [a.session_id for a in _find()] == ["cli-aaaa"]

    def test_transcript_selected_by_cli_session_id(self, root):
        transcript = _session(root)
        proj = transcript.parent
        decoy = proj.parent / "C--other" / "decoy.jsonl"
        decoy.parent.mkdir()
        decoy.write_text("{}\n", encoding="utf-8")
        sub = proj / "cli-aaaa" / "subagents" / "agent-1.jsonl"
        sub.parent.mkdir(parents=True)
        sub.write_text("{}\n", encoding="utf-8")
        [agent] = _find()
        assert agent.log_file == transcript

    @pytest.mark.parametrize(
        "meta",
        [
            "{not json",
            "[1, 2]",
            {"sessionId": "local_0001", "cwd": CWD, "lastActivityAt": int(NOW * 1000)},
            {"sessionId": "local_0001", "cliSessionId": "cli-aaaa",
             "lastActivityAt": int(NOW * 1000)},
            {"sessionId": "local_0001", "cliSessionId": "cli-aaaa", "cwd": CWD,
             "lastActivityAt": "soon"},
        ],
    )
    def test_bad_metadata_skipped(self, root, meta):
        _session(root, meta=meta)
        assert _find() == []

    def test_missing_transcript_skipped(self, root):
        _session(root, transcript=False)
        assert _find() == []

    def test_unrelated_entries_tolerated(self, root):
        sessions = root / "local-agent-mode-sessions"
        (sessions / "skills-plugin" / "x" / "y").mkdir(parents=True)
        (sessions / "skills-plugin" / "x" / "y" / "local_skill.json").write_text(
            "{}", encoding="utf-8"
        )
        (sessions / "stray.txt").write_text("", encoding="utf-8")
        _session(root)
        assert [a.session_id for a in _find()] == ["cli-aaaa"]


class TestAdapter:
    def test_registered_after_gemini(self):
        names = [a.name for a in agents.ADAPTERS]
        assert names[-2:] == ["gemini", "claude-desktop"]
        assert agents.get("claude-desktop").kind == "editor"

    def test_discover_delegates(self, monkeypatch):
        sentinel = [object()]
        monkeypatch.setattr(cdd, "find_claude_desktop_agents", lambda: sentinel)
        assert agents.get("claude-desktop").discover() is sentinel

    def test_watcher_and_parse(self, tmp_path):
        transcript = _session(tmp_path)
        adapter = agents.get("claude-desktop")
        assert adapter.claims(transcript) is False
        assert agents.adapter_for(transcript).name == "claude-code"

        proc = AgentProcess(pid=1, agent_type="claude-desktop", working_directory=Path(CWD),
                            log_file=transcript, session_id="cli-aaaa")
        assert adapter.is_live(proc) is True
        w = adapter.make_watcher(proc, "cli-aaaa")
        assert isinstance(w, LogWatcher)
        assert w.path == transcript

        actions = list(adapter.parse_file(transcript, "cli-aaaa"))
        assert [a.tool_name for a in actions] == ["Bash"]
        assert actions[0].success is True
