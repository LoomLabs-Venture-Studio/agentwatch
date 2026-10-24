"""Claude Code process -> session log mapping (Sprint 37 F2).

Claude Code does not hold its transcript open, so ``_find_open_jsonl`` finds
nothing for a live session and every process used to fall back to the
newest log in its project dir: several sessions in one directory all got
the same log, and the multi-agent watcher (keyed by log path) dropped all
but one of them.

Claude Code 2.1.x keeps one record per live process at
``~/.claude/sessions/<pid>.json`` (pid, sessionId, cwd, startedAt, procStart
-- ``LC_ALL=C TZ=UTC ps -o lstart=`` of the process) and rewrites
``sessionId`` in place when the conversation changes (/clear, /resume).
These tests build that layout in a tmp dir with fake psutil processes; no
real user paths are read.
"""

from __future__ import annotations

import json
import os
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest

import agentwatch.discovery as discovery
from agentwatch.discovery import DiscoveryCache, find_running_agents
from agentwatch.path_encoding import encode_path_for_claude

T0 = 1_790_000_000.0  # fake process start times are offsets from this


def _lstart(ts: float) -> str:
    # What `LC_ALL=C TZ=UTC ps -o lstart=` prints, e.g. "Sat Oct 24 00:32:05 2026".
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%a %b %d %H:%M:%S %Y")


class _Machine:
    """A fake home dir plus a fake process table for find_running_agents()."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        self.claude_home = tmp_path / "home" / ".claude"
        (self.claude_home / "sessions").mkdir(parents=True)
        self.procs: dict[int, dict] = {}
        self.open_files: dict[int, list[Path]] = {}
        self.open_files_calls = 0
        machine = self

        class _FakeProcess:
            def __init__(self, pid):
                if pid not in machine.procs:
                    raise discovery.psutil.NoSuchProcess(pid)
                self.pid = pid
                self.info = dict(machine.procs[pid])

            def open_files(self):
                machine.open_files_calls += 1
                return [types.SimpleNamespace(path=str(p)) for p in machine.open_files.get(
                    self.pid, []
                )]

            def create_time(self):
                return machine.procs[self.pid]["create_time"]

        def _process_iter(attrs=None):
            return iter([_FakeProcess(pid) for pid in sorted(machine.procs)])

        monkeypatch.setattr(discovery, "_claude_home", lambda: machine.claude_home)
        monkeypatch.setattr(discovery.psutil, "process_iter", _process_iter)
        monkeypatch.setattr(discovery.psutil, "Process", _FakeProcess)
        monkeypatch.setattr(discovery, "_get_process_cwd", lambda pid: machine.procs[pid]["_cwd"])
        monkeypatch.setattr(discovery._agents, "editor_adapters", lambda: [])

    def project(self, name: str) -> Path:
        cwd = self.claude_home.parent / "src" / name
        cwd.mkdir(parents=True, exist_ok=True)
        return cwd

    def project_dir(self, cwd: Path) -> Path:
        d = self.claude_home / "projects" / encode_path_for_claude(cwd)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def transcript(self, cwd: Path, session_id: str, mtime: float) -> Path:
        path = self.project_dir(cwd) / f"{session_id}.jsonl"
        path.write_text(json.dumps({"type": "user", "sessionId": session_id}) + "\n")
        os.utime(path, (mtime, mtime))
        return path

    def spawn(self, pid: int, cwd: Path, started: float, ppid: int = 1) -> None:
        self.procs[pid] = {
            "pid": pid,
            "ppid": ppid,
            "cmdline": ["claude"],
            "name": "claude",
            "memory_info": types.SimpleNamespace(rss=1024 * 1024),
            "cpu_percent": 0.0,
            "create_time": started,
            "_cwd": cwd,
        }

    def register(self, pid: int, session_id: str, *, started: float | None = None,
                 cwd: Path | None = None, **extra) -> Path:
        """Write ~/.claude/sessions/<pid>.json the way Claude Code does."""
        proc = self.procs[pid]
        started = proc["create_time"] if started is None else started
        record = {
            "pid": pid,
            "sessionId": session_id,
            "cwd": str(cwd or proc["_cwd"]),
            "startedAt": int((started + 1.5) * 1000),
            "procStart": _lstart(started),
            "kind": "interactive",
            "status": "idle",
            **extra,
        }
        path = self.claude_home / "sessions" / f"{pid}.json"
        path.write_text(json.dumps(record))
        return path

    def by_pid(self, cache: DiscoveryCache | None = None) -> dict[int, discovery.AgentProcess]:
        return {a.pid: a for a in find_running_agents(cache)}


@pytest.fixture
def machine(tmp_path, monkeypatch) -> _Machine:
    return _Machine(tmp_path, monkeypatch)


SID_A = "aaaaaaaa-0000-4000-8000-000000000001"
SID_B = "bbbbbbbb-0000-4000-8000-000000000002"
SID_C = "cccccccc-0000-4000-8000-000000000003"


class TestTwoSessionsOneProjectDir:
    def test_each_process_gets_its_own_session_log(self, machine):
        cwd = machine.project("app")
        # A is the older session: the old newest-mtime fallback gave B to both.
        log_a = machine.transcript(cwd, SID_A, mtime=T0 + 100)
        log_b = machine.transcript(cwd, SID_B, mtime=T0 + 200)
        machine.spawn(41131, cwd, started=T0)
        machine.spawn(41752, cwd, started=T0 + 50)
        machine.register(41131, SID_A)
        machine.register(41752, SID_B)

        agents = machine.by_pid()

        assert agents[41131].log_file == log_a
        assert agents[41131].session_id == SID_A
        assert agents[41752].log_file == log_b
        assert agents[41752].session_id == SID_B

    def test_multi_log_watcher_tracks_both(self, machine):
        from agentwatch.parser.watcher import MultiLogWatcher

        cwd = machine.project("app")
        machine.transcript(cwd, SID_A, mtime=T0 + 100)
        machine.transcript(cwd, SID_B, mtime=T0 + 200)
        machine.spawn(41131, cwd, started=T0)
        machine.spawn(41752, cwd, started=T0 + 50)
        machine.register(41131, SID_A)
        machine.register(41752, SID_B)

        watcher = MultiLogWatcher.from_processes(find_running_agents())

        assert {p.pid for p in watcher._process_meta.values()} == {41131, 41752}

    def test_open_file_still_wins_where_it_works(self, machine):
        cwd = machine.project("app")
        machine.transcript(cwd, SID_A, mtime=T0 + 100)
        log_b = machine.transcript(cwd, SID_B, mtime=T0 + 50)
        machine.spawn(500, cwd, started=T0)
        machine.register(500, SID_A)
        machine.open_files[500] = [log_b]

        agent = machine.by_pid()[500]

        assert agent.log_file == log_b
        assert agent.session_id == SID_B

    def test_transcript_kept_in_another_project_dir_is_found(self, machine):
        # A resumed session keeps writing where it began, which can be the
        # dir of a different cwd than the process's own.
        cwd = machine.project("app")
        elsewhere = machine.project("app-sub")
        log = machine.transcript(elsewhere, SID_A, mtime=T0 + 100)
        machine.project_dir(cwd)
        machine.spawn(500, cwd, started=T0)
        machine.register(500, SID_A)

        agent = machine.by_pid()[500]

        assert agent.log_file == log
        assert agent.session_id == SID_A

    def test_two_processes_claiming_one_session_never_share_it(self, machine):
        cwd = machine.project("app")
        log = machine.transcript(cwd, SID_A, mtime=T0 + 100)
        machine.spawn(600, cwd, started=T0)
        machine.spawn(601, cwd, started=T0 + 10)
        machine.register(600, SID_A)
        machine.register(601, SID_A)

        agents = machine.by_pid()

        # The newer process is the one that opened the session last.
        assert agents[601].log_file == log
        assert agents[601].session_id == SID_A
        assert agents[600].log_file is None
        assert agents[600].session_id is None


class TestUnmatchedProcessGetsNoLog:
    def test_registered_session_without_transcript_gets_no_other_log(self, machine):
        cwd = machine.project("app")
        machine.transcript(cwd, SID_A, mtime=T0 + 100)  # someone else's session
        machine.spawn(700, cwd, started=T0)
        machine.register(700, SID_B)  # fresh session: nothing written yet

        agent = machine.by_pid()[700]

        assert agent.log_file is None
        assert agent.session_id == SID_B

    def test_ambiguous_unregistered_processes_get_no_log(self, machine):
        cwd = machine.project("app")
        machine.transcript(cwd, SID_A, mtime=T0 + 100)
        machine.transcript(cwd, SID_B, mtime=T0 + 200)
        machine.spawn(800, cwd, started=T0)
        machine.spawn(801, cwd, started=T0 + 10)

        agents = machine.by_pid()

        assert agents[800].log_file is None and agents[800].session_id is None
        assert agents[801].log_file is None and agents[801].session_id is None

    def test_unregistered_process_does_not_take_a_registered_ones_log(self, machine):
        cwd = machine.project("app")
        log_a = machine.transcript(cwd, SID_A, mtime=T0 + 100)
        machine.spawn(900, cwd, started=T0)
        machine.spawn(901, cwd, started=T0 + 10)
        machine.register(900, SID_A)

        agents = machine.by_pid()

        assert agents[900].log_file == log_a
        assert agents[901].log_file is None

    def test_log_last_written_before_the_process_started_is_not_its_own(self, machine):
        cwd = machine.project("app")
        machine.transcript(cwd, SID_A, mtime=T0 - 3600)
        machine.spawn(950, cwd, started=T0)

        assert machine.by_pid()[950].log_file is None

    def test_stale_record_of_a_reused_pid_is_ignored(self, machine):
        cwd = machine.project("app")
        machine.transcript(cwd, SID_A, mtime=T0 + 100)
        machine.spawn(960, cwd, started=T0 + 50)
        # Left behind by a crashed process that had this pid an hour earlier.
        machine.register(960, SID_B, started=T0 - 3600)
        machine.transcript(cwd, SID_B, mtime=T0 - 3000)

        agent = machine.by_pid()[960]

        # Treated as unregistered: its only log written since it started is A.
        assert agent.session_id != SID_B
        assert agent.log_file == machine.project_dir(cwd) / f"{SID_A}.jsonl"

    def test_unreadable_record_does_not_fall_back_to_a_guess(self, machine):
        cwd = machine.project("app")
        machine.transcript(cwd, SID_A, mtime=T0 + 100)
        machine.spawn(970, cwd, started=T0)
        (machine.claude_home / "sessions" / "970.json").write_text('{"pid": 970, "sessi')

        agent = machine.by_pid()[970]

        assert agent.log_file is None


class TestSingleSessionUnchanged:
    def test_registered_single_session(self, machine):
        cwd = machine.project("app")
        log = machine.transcript(cwd, SID_A, mtime=T0 + 100)
        machine.spawn(1100, cwd, started=T0)
        machine.register(1100, SID_A)

        agent = machine.by_pid()[1100]

        assert agent.log_file == log
        assert agent.session_id == SID_A

    def test_unregistered_single_session_still_gets_the_newest_log(self, machine):
        # No session record (older Claude Code, or a mode that does not
        # register): the only process in the dir keeps the old fallback.
        cwd = machine.project("app")
        machine.transcript(cwd, SID_A, mtime=T0 + 100)
        log_b = machine.transcript(cwd, SID_B, mtime=T0 + 200)
        machine.spawn(1101, cwd, started=T0)

        agent = machine.by_pid()[1101]

        assert agent.log_file == log_b
        assert agent.session_id == SID_B

    def test_resolve_without_pid_returns_newest_log(self, machine):
        cwd = machine.project("app")
        machine.transcript(cwd, SID_A, mtime=T0 + 100)
        log_b = machine.transcript(cwd, SID_B, mtime=T0 + 200)

        assert discovery._resolve_claude_code_log(cwd) == (log_b, SID_B)


class TestParseLstart:
    def test_parses_c_locale_utc_lstart(self):
        assert discovery._parse_lstart(_lstart(T0)) == T0

    def test_space_padded_day(self):
        expected = datetime(2026, 10, 4, 0, 32, 5, tzinfo=timezone.utc).timestamp()
        assert discovery._parse_lstart("Sun Oct  4 00:32:05 2026") == expected

    @pytest.mark.parametrize("value", [None, "", "garbage", "Sat Foo 24 00:32:05 2026", 12])
    def test_rejects_anything_else(self, value):
        assert discovery._parse_lstart(value) is None
