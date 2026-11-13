"""CLAUDE_CONFIG_DIR: Claude Code sessions outside ~/.claude.

Claude Code keeps transcripts in $CLAUDE_CONFIG_DIR/projects (default
~/.claude). Discovery asks each running process for its own value first,
then agentwatch's own environment, then ~/.claude; whole-history scans cover
$CLAUDE_CONFIG_DIR and ~/.claude. Everything here runs on tmp dirs, a fake
home and fake psutil processes.
"""

from __future__ import annotations

import json
import os
import types
from pathlib import Path

import pytest

import agentwatch.discovery as discovery
from agentwatch import cc_stats, claude_config
from agentwatch.agents.claude_code import ClaudeCodeAdapter
from agentwatch.path_encoding import encode_path_for_claude

SID = "aaaaaaaa-0000-4000-8000-000000000001"
T0 = 1_790_000_000.0


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    """A fake home dir; no CLAUDE_CONFIG_DIR, no assigned projects dir."""
    home = (tmp_path / "home").resolve()  # config dirs come back resolved
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    # Other tests' monkeypatching can leave the lazy value assigned.
    monkeypatch.delitem(vars(cc_stats), "CLAUDE_PROJECTS_DIR", raising=False)
    return home


def _transcript(config: Path, cwd: Path, session_id: str = SID, mtime: float = T0) -> Path:
    d = config / "projects" / encode_path_for_claude(cwd)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{session_id}.jsonl"
    path.write_text(json.dumps({"type": "user", "sessionId": session_id, "cwd": str(cwd)}) + "\n")
    os.utime(path, (mtime, mtime))
    return path


# --- claude_config -------------------------------------------------------------------


class TestConfigDirFrom:
    def test_empty_and_blank_are_ignored(self):
        assert claude_config.config_dir_from(None) is None
        assert claude_config.config_dir_from("") is None
        assert claude_config.config_dir_from("   ") is None

    def test_tilde_is_expanded(self, home):
        assert claude_config.config_dir_from("~/.claude-alt") == home / ".claude-alt"

    def test_default_without_env_is_home_claude(self, home):
        assert claude_config.default_config_dir() == home / ".claude"

    def test_default_follows_env(self, home, monkeypatch):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", "~/.claude-alt")
        assert claude_config.default_config_dir() == home / ".claude-alt"

    def test_empty_env_falls_back(self, home, monkeypatch):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", "")
        assert claude_config.default_config_dir() == home / ".claude"


class TestConfigDirs:
    def test_home_claude_only(self, home):
        (home / ".claude").mkdir()
        assert claude_config.config_dirs() == [home / ".claude"]

    def test_env_first_then_home_only_existing(self, home, monkeypatch):
        (home / ".claude").mkdir()
        (home / ".claude-alt").mkdir()
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude-alt"))
        assert claude_config.config_dirs() == [home / ".claude-alt", home / ".claude"]
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / "missing"))
        assert claude_config.config_dirs() == [home / ".claude"]

    def test_deduplicated_by_resolved_path(self, home, monkeypatch):
        (home / ".claude").mkdir()
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / "x" / ".." / ".claude"))
        assert len(claude_config.config_dirs()) == 1

    def test_dedup_through_symlink(self, home, monkeypatch):
        (home / ".claude").mkdir()
        try:
            (home / "link").symlink_to(home / ".claude", target_is_directory=True)
        except OSError:
            pytest.skip("no symlinks here")
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / "link"))
        assert claude_config.config_dirs() == [home / ".claude"]  # resolved, once

    def test_relative_value_comes_back_absolute(self, home, monkeypatch):
        (home / ".claude-alt").mkdir()
        monkeypatch.chdir(home)
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", ".claude-alt")
        assert claude_config.config_dirs() == [home / ".claude-alt"]
        assert claude_config.default_config_dir() == home / ".claude-alt"

    def test_no_guessing_other_claude_dirs(self, home):
        (home / ".claude").mkdir()
        (home / ".claude-orca").mkdir()
        assert claude_config.config_dirs() == [home / ".claude"]


# --- whole-history scans -------------------------------------------------------------


class TestHistoryRoots:
    def test_find_all_project_dirs_covers_both_roots(self, home, monkeypatch):
        a = _transcript(home / ".claude", home / "proj-a")
        b = _transcript(home / ".claude-alt", home / "proj-b")
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude-alt"))
        assert set(cc_stats.find_all_project_dirs()) == {a.parent, b.parent}
        logs = set(ClaudeCodeAdapter().history_logs())
        assert logs == {a, b}

    def test_same_root_twice_is_scanned_once(self, home, monkeypatch):
        a = _transcript(home / ".claude", home / "proj-a")
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", "~/.claude")
        assert cc_stats.find_all_project_dirs() == [a.parent]

    def test_home_claude_only_user_unchanged(self, home):
        a = _transcript(home / ".claude", home / "proj-a")
        _transcript(home / ".claude-orca", home / "proj-b")  # not guessed at
        assert cc_stats.find_all_project_dirs() == [a.parent]
        assert cc_stats.CLAUDE_PROJECTS_DIR == home / ".claude" / "projects"

    def test_cwd_to_project_dir_looks_in_every_root(self, home, monkeypatch):
        cwd = home / "proj-b"
        cwd.mkdir()
        (home / ".claude").mkdir()
        b = _transcript(home / ".claude-alt", cwd)
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude-alt"))
        assert cc_stats.cwd_to_project_dir(cwd) == b.parent

    def test_history_meta_in_env_root(self, home, monkeypatch):
        cwd = home / "proj-b"
        b = _transcript(home / ".claude-alt", cwd)
        (home / ".claude").mkdir()
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude-alt"))
        assert ClaudeCodeAdapter().history_meta(b) == (SID, "proj-b")
        assert ClaudeCodeAdapter().history_meta(home / "elsewhere" / "x.jsonl") == ("x", None)

    def test_parser_default_paths_cover_every_root(self, home, monkeypatch):
        from agentwatch.parser import logs

        (home / ".claude").mkdir()
        (home / ".claude-alt").mkdir()
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude-alt"))
        monkeypatch.delitem(vars(logs), "DEFAULT_SEARCH_PATHS", raising=False)
        paths = logs.DEFAULT_SEARCH_PATHS
        for root in (home / ".claude-alt", home / ".claude"):
            assert root / "projects" in paths and root / "logs" in paths

    def test_default_log_finds_session_in_env_root(self, home, monkeypatch):
        from agentwatch import cli
        from agentwatch.parser import logs

        cwd = home / "proj-b"
        cwd.mkdir()
        b = _transcript(home / ".claude-alt", cwd)
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude-alt"))
        monkeypatch.delitem(vars(logs), "DEFAULT_SEARCH_PATHS", raising=False)
        monkeypatch.chdir(cwd)
        assert cli._default_log() == (b, None)


# --- per-process config dir ----------------------------------------------------------


class _FakeProcess:
    """psutil.Process stand-in: environ() returns a dict or raises."""

    environ_calls = 0
    env: object = None  # dict, or an exception instance to raise

    def __init__(self, pid):
        self.pid = pid

    def environ(self):
        type(self).environ_calls += 1
        if isinstance(self.env, BaseException):
            raise self.env
        return self.env

    def create_time(self):
        return T0

    def open_files(self):
        return []


@pytest.fixture
def fake_proc(monkeypatch):
    class Proc(_FakeProcess):
        pass

    monkeypatch.setattr(discovery.psutil, "Process", Proc)
    monkeypatch.setattr(discovery, "_config_dir_by_proc", {})
    return Proc


class TestProcessConfigDir:
    def test_process_env_wins(self, home, fake_proc, monkeypatch):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude-mine"))
        fake_proc.env = {"CLAUDE_CONFIG_DIR": "~/.claude-orca", "OTHER": "x"}
        assert discovery._claude_home(42, T0) == home / ".claude-orca"

    def test_readable_env_without_value_is_home_claude(self, home, fake_proc, monkeypatch):
        # The process really uses ~/.claude, whatever agentwatch's own env says.
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude-mine"))
        fake_proc.env = {"OTHER": "x"}
        assert discovery._claude_home(42, T0) == home / ".claude"

    def test_own_env_when_process_env_unreadable(self, home, fake_proc, monkeypatch):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude-mine"))
        fake_proc.env = discovery.psutil.AccessDenied(42)
        assert discovery._claude_home(42, T0) == home / ".claude-mine"

    def test_empty_process_value_ignored(self, home, fake_proc):
        fake_proc.env = {"CLAUDE_CONFIG_DIR": ""}
        assert discovery._claude_home(42, T0) == home / ".claude"

    @pytest.mark.parametrize("error", [
        ValueError("bad environ"),
        discovery.psutil.AccessDenied(42),
        discovery.psutil.NoSuchProcess(42),
        discovery.psutil.ZombieProcess(42),
        NotImplementedError(),
        AttributeError("environ"),
        OSError(),
    ])
    def test_unreadable_environ_falls_back(self, home, fake_proc, error):
        fake_proc.env = error
        assert discovery._claude_home(42, T0) == home / ".claude"

    def test_relative_value_taken_against_process_cwd(self, home, fake_proc, monkeypatch):
        (home / "work" / "cfg").mkdir(parents=True)
        monkeypatch.setattr(discovery, "_get_process_cwd", lambda pid: home / "work")
        fake_proc.env = {"CLAUDE_CONFIG_DIR": "cfg"}
        assert discovery._claude_home(42, T0) == home / "work" / "cfg"

    def test_relative_value_ignored_without_process_cwd(self, home, fake_proc, monkeypatch):
        monkeypatch.setattr(discovery, "_get_process_cwd", lambda pid: None)
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude-mine"))
        fake_proc.env = {"CLAUDE_CONFIG_DIR": "cfg"}
        assert discovery._claude_home(42, T0) == home / ".claude-mine"

    def test_symlinked_value_is_resolved(self, home, fake_proc):
        (home / ".claude").mkdir()
        try:
            (home / "link").symlink_to(home / ".claude", target_is_directory=True)
        except OSError:
            pytest.skip("no symlinks here")
        fake_proc.env = {"CLAUDE_CONFIG_DIR": str(home / "link")}
        assert discovery._claude_home(42, T0) == home / ".claude"

    def test_cached_per_pid_and_start_time(self, home, fake_proc):
        a, b = str(home / "a"), str(home / "b")
        fake_proc.env = {"CLAUDE_CONFIG_DIR": a}
        assert discovery._claude_home(42, T0) == Path(a)
        fake_proc.env = {"CLAUDE_CONFIG_DIR": b}
        assert discovery._claude_home(42, T0) == Path(a)
        assert fake_proc.environ_calls == 1
        assert discovery._claude_home(42, T0 + 5) == Path(b)  # pid reused
        assert fake_proc.environ_calls == 2

    def test_only_the_one_value_is_cached(self, home, fake_proc):
        fake_proc.env = {"CLAUDE_CONFIG_DIR": str(home / "a"), "SECRET_TOKEN": "s3cret"}
        discovery._claude_home(42, T0)
        assert "s3cret" not in repr(discovery._config_dir_by_proc)


class TestResolveUnderProcessRoot:
    def _record(self, config: Path, pid: int, cwd: Path) -> None:
        sessions = config / "sessions"
        sessions.mkdir(parents=True, exist_ok=True)
        (sessions / f"{pid}.json").write_text(json.dumps({
            "pid": pid, "sessionId": SID, "cwd": str(cwd),
            "startedAt": int((T0 + 1) * 1000),
        }))

    def test_log_resolved_in_process_config_dir(self, home, fake_proc):
        cwd = home / "proj"
        cwd.mkdir()
        log = _transcript(home / ".claude-orca", cwd)
        self._record(home / ".claude-orca", 42, cwd)
        (home / ".claude").mkdir()
        fake_proc.env = {"CLAUDE_CONFIG_DIR": str(home / ".claude-orca")}
        assert discovery._resolve_claude_code_log(cwd, pid=42) == (log, SID)

    def test_without_process_env_home_claude_is_used(self, home, fake_proc):
        cwd = home / "proj"
        cwd.mkdir()
        log = _transcript(home / ".claude", cwd)
        self._record(home / ".claude", 42, cwd)
        _transcript(home / ".claude-orca", cwd)  # not looked at
        fake_proc.env = discovery.psutil.AccessDenied(42)
        assert discovery._resolve_claude_code_log(cwd, pid=42) == (log, SID)

    def test_without_pid_newest_across_roots(self, home, monkeypatch):
        cwd = home / "proj"
        cwd.mkdir()
        _transcript(home / ".claude", cwd, mtime=T0)
        newer = _transcript(home / ".claude-alt", cwd, "bbbbbbbb-0000-4000-8000-0000000000b2",
                            mtime=T0 + 10)
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude-alt"))
        assert discovery._resolve_claude_code_log(cwd)[0] == newer

    def test_find_running_agents_uses_process_root(self, home, fake_proc, monkeypatch):
        cwd = home / "proj"
        cwd.mkdir()
        log = _transcript(home / ".claude-orca", cwd)
        self._record(home / ".claude-orca", 42, cwd)
        fake_proc.env = {"CLAUDE_CONFIG_DIR": str(home / ".claude-orca")}
        proc = {
            "pid": 42, "ppid": 1, "cmdline": ["claude"], "name": "claude",
            "memory_info": types.SimpleNamespace(rss=1), "cpu_percent": 0.0,
            "create_time": T0,
        }
        monkeypatch.setattr(discovery, "snapshot", lambda attrs: [dict(proc)])
        monkeypatch.setattr(discovery, "_get_process_cwd", lambda pid: cwd)
        monkeypatch.setattr(discovery._agents, "editor_adapters", lambda: [])
        agents = {a.pid: a for a in discovery.find_running_agents()}
        assert agents[42].log_file == log
        assert agents[42].session_id == SID


# --- one project in both config dirs (QA #237) ---------------------------------------


def _session(config: Path, cwd: Path, session_id: str, mtime: float, secret: bool = False) -> Path:
    """A Claude Code transcript with one priced assistant message (and, with
    *secret*, a tool call that leaks a token)."""
    d = config / "projects" / encode_path_for_claude(cwd)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{session_id}.jsonl"
    command = "echo ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" if secret else "ls"
    lines = [
        {"type": "user", "sessionId": session_id, "cwd": str(cwd),
         "timestamp": "2026-11-01T00:00:00Z", "message": {"role": "user", "content": "hi"}},
        {"type": "assistant", "sessionId": session_id, "cwd": str(cwd),
         "timestamp": "2026-11-01T00:00:01Z",
         "message": {"id": f"msg_{session_id}", "role": "assistant",
                     "model": "claude-sonnet-4-5",
                     "usage": {"input_tokens": 100, "output_tokens": 10},
                     "content": [{"type": "tool_use", "id": f"tu_{session_id}",
                                  "name": "Bash", "input": {"command": command}}]}},
    ]
    path.write_text("".join(json.dumps(e) + "\n" for e in lines))
    os.utime(path, (mtime, mtime))
    return path


SID_B = "bbbbbbbb-0000-4000-8000-0000000000b2"
SID_C = "cccccccc-0000-4000-8000-0000000000c3"


@pytest.fixture
def both_roots(home, monkeypatch):
    """Project `proj` with one session in ~/.claude and two in ~/.claude-alt."""
    cwd = home / "proj"
    cwd.mkdir()
    old = T0 - 7200
    logs = {
        "home": _session(home / ".claude", cwd, SID, old, secret=True),
        "alt1": _session(home / ".claude-alt", cwd, SID_B, old + 10),
        "alt2": _session(home / ".claude-alt", cwd, SID_C, old + 20),
    }
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude-alt"))
    monkeypatch.chdir(cwd)
    from agentwatch.parser import logs as parser_logs

    monkeypatch.delitem(vars(parser_logs), "DEFAULT_SEARCH_PATHS", raising=False)
    return cwd, logs


class TestProjectInBothRoots:
    def test_cwd_to_project_dirs_returns_both(self, both_roots):
        _, logs = both_roots
        assert set(cc_stats.cwd_to_project_dirs()) == {logs["home"].parent, logs["alt1"].parent}

    def test_stats_counts_sessions_from_both(self, both_roots):
        report = cc_stats.compute_stats()
        assert report.session_count == 3

    def test_stats_all_counts_project_once(self, both_roots):
        report = cc_stats.compute_stats(all_projects=True)
        assert report.session_count == 3
        assert report.project_name == "all (1 projects)"

    def test_audit_scans_both(self, both_roots):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        for args in (["audit", "--json"], ["audit", "--all", "--json"]):
            result = CliRunner().invoke(cli, args)
            data = json.loads(result.output)
            assert data["sessions_scanned"] == 3, args
            assert data["projects"] == ["proj"], args
            assert data["findings"], args  # the leak is in the ~/.claude session
            assert result.exit_code != 0, args

    def test_default_log_is_newest_across_both(self, both_roots, home):
        from agentwatch import cli

        _, logs = both_roots
        assert cli._default_log() == (logs["alt2"], None)
        os.utime(logs["home"], (T0, T0))
        assert cli._default_log() == (logs["home"], None)


class TestHistorySymlinkedConfigDir:
    def test_symlink_to_home_claude_adds_no_sessions(self, home, monkeypatch, tmp_path):
        from agentwatch import history
        from agentwatch.agents.claude_code import ClaudeCodeAdapter

        cwd = home / "proj"
        _session(home / ".claude", cwd, SID, T0 - 7200)
        _session(home / ".claude", cwd, SID_B, T0 - 7100)
        try:
            (home / "cfg-link").symlink_to(home / ".claude", target_is_directory=True)
        except OSError:
            pytest.skip("no symlinks here")
        monkeypatch.setattr("agentwatch.agents.ADAPTERS", [ClaudeCodeAdapter()])
        conn = history.connect()
        assert history.sync(conn)["new"] == 2
        for value in (str(home / "cfg-link"), "~/cfg-link", "~/.claude/"):
            monkeypatch.setenv("CLAUDE_CONFIG_DIR", value)
            assert history.sync(conn)["new"] == 0, value
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 2


class TestConfigScanBothRoots:
    def _run(self, home):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        r = CliRunner().invoke(cli, ["config-scan", "--path", str(home / "proj"), "--json"])
        return json.loads(r.output)

    def _put(self, path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))
        path.chmod(0o600)

    def test_settings_and_claude_json_from_both(self, home, monkeypatch):
        (home / "proj").mkdir()
        bypass = {"permissions": {"defaultMode": "bypassPermissions"}}
        self._put(home / ".claude" / "settings.json", bypass)
        self._put(home / ".claude-alt" / "settings.json", bypass)
        npx = {"mcpServers": {"s": {"command": "npx", "args": ["-y", "some-mcp"]}}}
        self._put(home / ".claude.json", npx)  # ~/.claude's: in home
        self._put(home / ".claude-alt" / ".claude.json", npx)  # $CLAUDE_CONFIG_DIR's: inside
        self._put(home / ".claude-alt" / "x" / ".claude.json", npx)  # never read
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", "~/.claude-alt")
        joined = " ".join(sorted(f["file"] for f in self._run(home)["findings"]))
        assert "~/.claude/settings.json" in joined
        assert "~/.claude-alt/settings.json" in joined
        assert "~/.claude.json" in joined
        assert "~/.claude-alt/.claude.json" in joined
        assert "/x/" not in joined


class TestStatuslineConfigDir:
    def test_tilde_and_whitespace(self, home, monkeypatch, tmp_path):
        from agentwatch import statusline

        coach = home / ".claude-alt" / "plugins" / "data" / "agentwatch-m" / "coach"
        coach.mkdir(parents=True)
        monkeypatch.setattr(statusline, "user_state_dir", lambda: tmp_path / "user")
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", "  ~/.claude-alt  ")
        assert coach in statusline.state_dirs()
