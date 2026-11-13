"""agentwatch.posture: approvals and sandbox of a live agent process, from fake
psutil processes (argv variants, parent chains, access denied, zombies, pid
reuse) and each surface that shows it (ps, ps --json, check, watch-all,
visual)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import psutil
import pytest
from click.testing import CliRunner

from agentwatch import cli, discovery, posture
from agentwatch.discovery import AgentProcess
from agentwatch.posture import Posture

# Far above any real pid, so /proc/<pid> never exists for these fakes.
PID = 4_190_001

linux_only = pytest.mark.skipif(sys.platform == "win32", reason="ancestry is not read on Windows")


class FakeProc:
    def __init__(self, pid, cmdline, name=None, parent=None, create_time=1000.0,
                 status=psutil.STATUS_RUNNING, deny=(), exe="", env=None):
        self.pid = pid
        self._exe = exe
        self._env = env or {}
        self._cmdline = cmdline
        self._name = name or (Path(cmdline[0]).name if cmdline else "")
        self._parent = parent
        self._create_time = create_time
        self._status = status
        self._deny = set(deny)

    def _check(self, what):
        if what in self._deny:
            raise psutil.AccessDenied(self.pid)

    def cmdline(self):
        self._check("cmdline")
        return list(self._cmdline)

    def name(self):
        self._check("name")
        return self._name

    def create_time(self):
        self._check("create_time")
        return self._create_time

    def status(self):
        return self._status

    def exe(self):
        self._check("exe")
        return self._exe

    def environ(self):
        self._check("environ")
        return dict(self._env)

    def parent(self):
        self._check("parent")
        return self._parent


def chain(*cmdlines):
    """Processes from the top ancestor down; returns the last (the agent)."""
    proc = FakeProc(1, ["/sbin/init"], name="systemd")
    for i, cmd in enumerate(cmdlines):
        proc = FakeProc(PID - len(cmdlines) + i + 1, cmd, parent=proc)
    return proc


@pytest.fixture
def procs(monkeypatch, tmp_path):
    """pid -> fake process; Claude Code and Codex config read from tmp_path."""
    table: dict[int, FakeProc] = {}

    def lookup(pid):
        if pid not in table:
            raise psutil.NoSuchProcess(pid)
        return table[pid]

    monkeypatch.setattr(posture, "_process", lookup)
    monkeypatch.setattr(posture, "_proc_root", lambda pid: tmp_path / "noroot")
    claude_home = tmp_path / "claude"
    claude_home.mkdir()
    monkeypatch.setattr(discovery, "_claude_home", lambda pid=None, ct=None: claude_home)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    (tmp_path / "codex").mkdir()
    managed = tmp_path / "managed"
    managed.mkdir()
    monkeypatch.setattr(posture, "_managed_claude_paths",
                        lambda: sorted(managed.glob("*.json")))
    monkeypatch.setattr(posture, "_CODEX_SYSTEM", tmp_path / "etc-codex.toml")
    from agentwatch.agents import gemini as gemini_agent

    (tmp_path / "gemini").mkdir()
    monkeypatch.setattr(gemini_agent, "_gemini_dir", lambda: tmp_path / "gemini")
    (tmp_path / "proj").mkdir()
    CWD[0] = tmp_path / "proj"
    posture.clear_cache()
    yield table
    posture.clear_cache()


CWD: list[Path] = [Path("/w/app")]  # the procs fixture's project dir, set per test


def agent(agent_type="claude-code", pid=PID):
    return AgentProcess(pid=pid, agent_type=agent_type, working_directory=CWD[0])


def run(procs, cmdline, agent_type="claude-code", *ancestors) -> Posture:
    proc = chain(*ancestors, cmdline)
    procs[proc.pid] = proc
    return posture.posture(agent(agent_type, proc.pid))


# -- approvals ----------------------------------------------------------


@linux_only
@pytest.mark.parametrize("argv, approvals, reason", [
    (["claude", "--dangerously-skip-permissions"], "skipped", "--dangerously-skip-permissions"),
    (["claude", "--permission-mode", "bypassPermissions"], "skipped",
     "--permission-mode bypassPermissions"),
    (["claude", "--permission-mode=bypassPermissions"], "skipped",
     "--permission-mode bypassPermissions"),
    (["claude", "--permission-mode", "acceptEdits"], "on", "--permission-mode acceptEdits"),
    (["claude", "--permission-mode", "auto"], "auto", "--permission-mode auto"),
    (["claude", "--permission-mode", "manual"], "on", "--permission-mode manual"),
    (["claude", "--permission-mode", "dontAsk"], "on", "--permission-mode dontAsk"),
    (["node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js",
      "--dangerously-skip-permissions"], "skipped", "--dangerously-skip-permissions"),
])
def test_claude_code_flags(procs, argv, approvals, reason):
    p = run(procs, argv)
    assert p.approvals == approvals
    assert reason in p.reasons
    assert p.sandbox == "none" and p.confidence == "high"


@linux_only
def test_claude_code_allow_flag_is_low_confidence(procs):
    p = run(procs, ["claude", "--permission-mode", "default",
                    "--allow-dangerously-skip-permissions"])
    assert (p.approvals, p.confidence) == ("on", "low")
    assert "bypass allowed" in p.reasons


@linux_only
def test_claude_code_user_settings_bypass(procs, tmp_path):
    (tmp_path / "claude" / "settings.json").write_text(
        json.dumps({"permissions": {"defaultMode": "bypassPermissions"}}))
    p = run(procs, ["claude"])
    assert (p.approvals, p.confidence) == ("skipped", "low")
    assert "settings: bypassPermissions" in p.reasons
    # An explicit --permission-mode wins over the settings file.
    posture.clear_cache()
    assert run(procs, ["claude", "--permission-mode", "plan"]).approvals == "on"


@linux_only
def test_claude_code_sandbox_setting(procs, tmp_path):
    (tmp_path / "claude" / "settings.json").write_text(json.dumps({"sandbox": {"enabled": True}}))
    p = run(procs, ["claude", "--dangerously-skip-permissions"])
    assert (p.approvals, p.sandbox) == ("skipped", "sandboxed")
    assert not p.risky


@linux_only
def test_claude_code_bad_settings_file_is_ignored(procs, tmp_path):
    (tmp_path / "claude" / "settings.json").write_text("{not json")
    assert run(procs, ["claude", "--permission-mode", "plan"]).approvals == "on"


@linux_only
@pytest.mark.parametrize("argv, approvals, sandbox", [
    (["codex"], "on", "sandboxed"),
    (["codex", "--yolo"], "skipped", "none"),
    (["codex", "--dangerously-bypass-approvals-and-sandbox"], "skipped", "none"),
    (["codex", "-s", "danger-full-access"], "on", "none"),
    (["codex", "--sandbox=danger-full-access", "-a", "never"], "skipped", "none"),
    (["codex", "--ask-for-approval", "never"], "skipped", "sandboxed"),
    (["codex", "-s", "workspace-write", "-a", "on-request"], "on", "sandboxed"),
    (["codex", "--full-auto"], "on", "sandboxed"),
    (["codex", "--approve-for-me"], "auto", "sandboxed"),
])
def test_codex_flags(procs, argv, approvals, sandbox):
    p = run(procs, argv, "codex")
    assert (p.approvals, p.sandbox) == (approvals, sandbox)


@linux_only
def test_codex_explicit_flags_are_high_confidence(procs):
    assert run(procs, ["codex", "--yolo"], "codex").confidence == "high"
    posture.clear_cache()
    assert run(procs, ["codex"], "codex").confidence == "low"  # defaults only


@linux_only
def test_codex_config_toml(procs, tmp_path):
    (tmp_path / "codex" / "config.toml").write_text(
        'sandbox_mode = "workspace-write"\napproval_policy = "on-request"\n'
        '[profiles.wild]\nsandbox_mode = "danger-full-access"\n')
    p = run(procs, ["codex"], "codex")
    assert (p.approvals, p.sandbox) == ("on", "sandboxed")
    assert "config: sandbox_mode workspace-write" in p.reasons
    posture.clear_cache()
    # A profile's own sandbox_mode; its approval_policy falls back to the top level.
    p = run(procs, ["codex", "--profile", "wild"], "codex")
    assert (p.approvals, p.sandbox) == ("on", "none")
    posture.clear_cache()
    (tmp_path / "codex" / "config.toml").write_text('approval_policy = "never"\n')
    assert run(procs, ["codex"], "codex").approvals == "skipped"


@linux_only
def test_codex_unknown_values_are_not_echoed(procs):
    p = run(procs, ["codex", "-s", "sk-secret-looking-value"], "codex")
    assert all("secret" not in r for r in p.reasons)
    assert "--sandbox" in p.reasons


@linux_only
@pytest.mark.parametrize("argv, approvals", [
    (["gemini"], "on"),
    (["gemini", "--yolo"], "skipped"),
    (["gemini", "-y"], "skipped"),
    (["gemini", "--approval-mode", "yolo"], "skipped"),
    (["gemini", "--approval-mode=auto_edit"], "on"),
])
def test_gemini_flags(procs, argv, approvals):
    assert run(procs, argv, "gemini").approvals == approvals


@linux_only
@pytest.mark.parametrize("argv, approvals", [
    (["copilot"], "on"),
    (["copilot", "--allow-all-tools"], "skipped"),
    (["copilot", "--allow-all"], "skipped"),
    (["copilot", "--yolo"], "skipped"),
    (["copilot", "--allow-all-paths"], "on"),
])
def test_copilot_flags(procs, argv, approvals):
    assert run(procs, argv, "copilot").approvals == approvals


@linux_only
def test_other_agents_are_unknown_approvals(procs):
    p = run(procs, ["aider"], "aider")
    assert p.approvals == "unknown" and p.confidence == "low"


# -- sandbox ------------------------------------------------------------


@linux_only
@pytest.mark.parametrize("launcher, reason", [
    (["bwrap", "--ro-bind", "/", "/"], "bwrap"),
    (["/usr/bin/firejail"], "firejail"),
    (["nsjail", "--"], "nsjail"),
    (["/usr/bin/sandbox-exec", "-p", "x"], "sandbox-exec"),
    (["srt", "claude"], "srt"),
    (["node", "/usr/lib/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js"], "srt"),
])
def test_sandbox_launcher_ancestor(procs, launcher, reason):
    p = run(procs, ["claude", "--dangerously-skip-permissions"], "claude-code",
            ["bash"], launcher, ["bash", "-c", "x"])
    # bwrap/firejail/nsjail/sandbox-exec argv decides what is confined: low
    expected = "high" if reason == "srt" else "low"
    assert (p.sandbox, p.confidence) == ("sandboxed", expected)
    assert reason in p.reasons and not p.risky


@linux_only
def test_codex_linux_sandbox_ancestor(procs):
    p = run(procs, ["claude"], "claude-code", ["codex"], ["codex-linux-sandbox", "--"])
    assert p.sandbox == "sandboxed" and "codex sandbox" in p.reasons
    posture.clear_cache()
    p = run(procs, ["claude", "--permission-mode", "plan"], "claude-code",
            ["codex-linux-sandbox", "--"])
    assert p.confidence == "high"  # a fixed Codex policy: stays high


@linux_only
@pytest.mark.parametrize("runtime", ["containerd-shim-runc-v2", "conmon", "docker-init"])
def test_container_ancestor_is_low_confidence(procs, runtime):
    p = run(procs, ["claude", "--dangerously-skip-permissions"], "claude-code", [runtime])
    assert (p.sandbox, p.confidence) == ("container", "low")
    assert not p.risky


@linux_only
def test_container_marker_file(procs, monkeypatch, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / ".dockerenv").write_text("")
    monkeypatch.setattr(posture, "_proc_root", lambda pid: root)
    p = run(procs, ["claude"])
    assert (p.sandbox, p.confidence) == ("container", "low")


@linux_only
def test_podman_marker_file(procs, monkeypatch, tmp_path):
    root = tmp_path / "root"
    (root / "run").mkdir(parents=True)
    (root / "run" / ".containerenv").write_text("")
    monkeypatch.setattr(posture, "_proc_root", lambda pid: root)
    assert run(procs, ["claude"]).sandbox == "container"


@linux_only
def test_ancestor_launcher_beats_codex_flags(procs):
    p = run(procs, ["codex", "--yolo"], "codex", ["bwrap"])
    assert (p.approvals, p.sandbox) == ("skipped", "sandboxed")


@linux_only
def test_unreadable_ancestry_is_none_low_confidence(procs):
    parent = FakeProc(PID - 1, ["bash"], deny={"parent"})
    procs[PID] = FakeProc(PID, ["claude", "--dangerously-skip-permissions"], parent=parent)
    p = posture.posture(agent())
    assert (p.sandbox, p.confidence) == ("none", "low")
    assert "ancestry partly unreadable" in p.reasons


@linux_only
def test_unreadable_ancestor_cmdline_still_uses_its_name(procs):
    launcher = FakeProc(PID - 1, ["bwrap"], name="bwrap", deny={"cmdline"},
                        parent=FakeProc(1, ["/sbin/init"]))
    procs[PID] = FakeProc(PID, ["claude"], parent=launcher)
    assert posture.posture(agent()).sandbox == "sandboxed"


@linux_only
def test_ancestry_walk_is_bounded(procs):
    proc = FakeProc(10, ["bash"])
    proc._parent = proc  # a cycle: never ends without the bound
    procs[PID] = FakeProc(PID, ["claude"], parent=proc)
    p = posture.posture(agent())
    assert p.sandbox == "none" and p.confidence == "low"


def test_windows_sandbox_is_unknown(procs, monkeypatch):
    monkeypatch.setattr(posture.sys, "platform", "win32")
    procs[PID] = FakeProc(PID, ["claude.exe", "--dangerously-skip-permissions"],
                          name="claude.exe", parent=FakeProc(1, ["bwrap"]))
    p = posture.posture(agent())
    assert (p.approvals, p.sandbox, p.confidence) == ("skipped", "unknown", "low")
    posture.clear_cache()
    procs[PID] = FakeProc(PID, ["codex.exe", "--yolo"], name="codex.exe")
    assert posture.posture(agent("codex")).sandbox == "none"  # explicit: clearly off


# -- process errors -----------------------------------------------------


def test_gone_process_is_unknown(procs):
    assert posture.posture(agent()) == posture.UNKNOWN


def test_access_denied_is_unknown(procs):
    procs[PID] = FakeProc(PID, ["claude"], deny={"cmdline"})
    assert posture.posture(agent()) == posture.UNKNOWN


def test_create_time_denied_is_unknown(procs):
    procs[PID] = FakeProc(PID, ["claude"], deny={"create_time"})
    assert posture.posture(agent()) == posture.UNKNOWN


def test_zombie_is_unknown(procs):
    procs[PID] = FakeProc(PID, ["claude", "--dangerously-skip-permissions"],
                          status=psutil.STATUS_ZOMBIE)
    assert posture.posture(agent()) == posture.UNKNOWN


def test_pid_not_the_agent_is_unknown(procs):
    """A synthetic pid (Codex app-server thread) or a reused one: the process
    there is not this agent."""
    procs[PID] = FakeProc(PID, ["/usr/bin/python3", "server.py"])
    assert posture.posture(agent()) == posture.UNKNOWN


def test_editor_agents_are_unknown_without_psutil(procs, monkeypatch):
    monkeypatch.setattr(posture, "_process", lambda pid: pytest.fail("psutil read"))
    assert posture.posture(agent("cursor")) == posture.UNKNOWN
    assert posture.posture(agent("copilot-vscode")) == posture.UNKNOWN


@linux_only
def test_cached_per_pid_and_create_time(procs):
    procs[PID] = FakeProc(PID, ["claude", "--dangerously-skip-permissions"],
                          parent=FakeProc(1, ["init"]))
    first = posture.posture(agent())
    procs[PID]._cmdline = ["claude"]  # same process: cached verdict
    assert posture.posture(agent()) is first
    # pid reused by a new process (new start time): read again
    procs[PID] = FakeProc(PID, ["claude", "--permission-mode", "plan"], create_time=2000.0,
                          parent=FakeProc(1, ["init"]))
    assert posture.posture(agent()).approvals == "on"


def test_unexpected_error_is_unknown(procs, monkeypatch):
    procs[PID] = FakeProc(PID, ["claude"])
    monkeypatch.setattr(posture, "_compute", lambda *a: 1 / 0)
    assert posture.posture(agent()) == posture.UNKNOWN


def test_reasons_never_hold_raw_argv(procs):
    procs[PID] = FakeProc(PID, ["claude", "--dangerously-skip-permissions", "-p",
                                "rm -rf /home/someone/secret"], parent=FakeProc(1, ["init"]))
    blob = json.dumps(posture.posture(agent()).to_dict())
    assert "someone" not in blob and "rm -rf" not in blob


# -- labels -------------------------------------------------------------


def test_label_and_tone():
    risky = Posture("skipped", "none", "high", ("--yolo",))
    assert posture.label(risky) == "yolo · no sandbox" and posture.tone(risky) == "bad"
    safe = Posture("on", "sandboxed", "high")
    assert posture.label(safe, " / ") == "approvals / sandboxed" and posture.tone(safe) == "good"
    assert posture.tone(Posture("skipped", "container")) == "warn"
    assert posture.tone(Posture("on", "none")) == "neutral"
    assert posture.label(posture.UNKNOWN) == "approvals ? · sandbox ?"
    assert posture.UNKNOWN.to_dict() == {"approvals": "unknown", "sandbox": "unknown",
                                         "confidence": "low", "reasons": []}


# -- surfaces -----------------------------------------------------------

RISKY = Posture("skipped", "none", "high", ("--dangerously-skip-permissions",))
SAFE = Posture("on", "sandboxed", "high", ("default mode", "bwrap"))


@pytest.fixture
def fixed(monkeypatch):
    """posture() answers from a pid -> Posture map."""
    table: dict[int, Posture] = {}
    monkeypatch.setattr(posture, "posture", lambda a: table.get(a.pid, posture.UNKNOWN))
    return table


def _agents():
    return [AgentProcess(pid=100, agent_type="claude-code", working_directory=Path("/w/a"),
                         team_id=100),
            AgentProcess(pid=200, agent_type="codex", working_directory=Path("/w/b"),
                         team_id=200)]


def test_ps_json_has_posture(monkeypatch, fixed):
    fixed[100] = RISKY
    monkeypatch.setattr(cli, "find_running_agents", _agents)
    rows = json.loads(CliRunner().invoke(cli.cli, ["ps", "--json"]).output)
    assert rows[0]["posture"] == {"approvals": "skipped", "sandbox": "none",
                                  "confidence": "high",
                                  "reasons": ["--dangerously-skip-permissions"]}
    assert rows[1]["posture"]["approvals"] == "unknown"


def test_ps_text_has_posture_column(monkeypatch, fixed):
    fixed[100], fixed[200] = RISKY, SAFE
    monkeypatch.setattr(cli, "find_running_agents", _agents)
    result = CliRunner().invoke(cli.cli, ["ps"], color=True)
    assert "POSTURE" in result.output
    lines = result.output.splitlines()
    risky = next(line for line in lines if line.lstrip().startswith("100"))
    safe = next(line for line in lines if line.lstrip().startswith("200"))
    assert "yolo · no sandbox" in risky and "\x1b[31m" in risky  # red
    assert "approvals · sandboxed" in safe and "\x1b[32m" in safe  # green


def test_ps_text_ascii_theme(monkeypatch, fixed):
    from agentwatch import themes

    fixed[100] = RISKY
    monkeypatch.setattr(cli, "find_running_agents", lambda: _agents()[:1])
    monkeypatch.setattr(themes, "get_current_theme_name", lambda: "ascii")
    out = CliRunner().invoke(cli.cli, ["ps"]).output
    assert "yolo / no sandbox" in out
    assert "·" not in out.split("POSTURE")[1]


def test_ps_teams_view_has_posture(monkeypatch, fixed):
    fixed[100] = RISKY
    sub = AgentProcess(pid=101, agent_type="claude-code", working_directory=Path("/w/a"),
                       parent_agent_pid=100, team_id=100, depth=1)
    monkeypatch.setattr(cli, "find_running_agents", lambda: [_agents()[0], sub])
    out = CliRunner().invoke(cli.cli, ["ps"]).output
    assert "POSTURE" in out and "yolo · no sandbox" in out
    header = next(line for line in out.splitlines() if "POSTURE" in line)
    row = next(line for line in out.splitlines() if line.lstrip().startswith("100"))
    assert header.index("POSTURE") == row.index("yolo")


def test_ps_agents_view_column_aligned(monkeypatch, fixed):
    fixed[100] = RISKY
    monkeypatch.setattr(cli, "find_running_agents", lambda: _agents()[:1])
    out = CliRunner().invoke(cli.cli, ["ps"]).output
    header = next(line for line in out.splitlines() if "POSTURE" in line)
    row = next(line for line in out.splitlines() if line.lstrip().startswith("100"))
    assert header.index("POSTURE") == row.index("yolo")


def _check(monkeypatch, tmp_path, fixed, p: Posture):
    log = tmp_path / "s.jsonl"
    log.write_text(json.dumps({
        "type": "assistant", "timestamp": "2026-11-13T10:00:00Z", "sessionId": "s",
        "message": {"id": "m1", "role": "assistant", "content": [
            {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/a"}}]},
    }) + "\n")
    proc = AgentProcess(pid=100, agent_type="claude-code", working_directory=tmp_path,
                        log_file=log)
    fixed[100] = p
    monkeypatch.setattr(cli, "find_running_agents", lambda: [proc])
    return CliRunner().invoke(cli.cli, ["check", "--log", str(log)])


def test_check_advisory_when_skipped_and_no_sandbox(monkeypatch, tmp_path, fixed):
    healthy = _check(monkeypatch, tmp_path, fixed, SAFE)
    result = _check(monkeypatch, tmp_path, fixed, RISKY)
    assert "Advisory: this session's agent runs with approvals skipped and no sandbox " \
           "(--dangerously-skip-permissions). Not scored." in result.output
    assert "Advisory" not in healthy.output
    assert result.exit_code == healthy.exit_code  # advisory only


def test_check_json_unchanged_by_posture(monkeypatch, tmp_path, fixed):
    log = tmp_path / "s.jsonl"
    _check(monkeypatch, tmp_path, fixed, RISKY)
    out = CliRunner().invoke(cli.cli, ["check", "--json", "--log", str(log)]).output
    assert "Advisory" not in out


def test_check_without_running_process_has_no_advisory(monkeypatch, tmp_path, fixed):
    result = _check(monkeypatch, tmp_path, fixed, RISKY)
    monkeypatch.setattr(cli, "find_running_agents", lambda: [])
    again = CliRunner().invoke(cli.cli, ["check", "--log", str(tmp_path / "s.jsonl")])
    assert "Advisory" in result.output and "Advisory" not in again.output


def test_visual_ps_carries_posture(monkeypatch, fixed):
    from agentwatch import visual

    fixed[100] = RISKY
    monkeypatch.setattr(cli, "find_running_agents", _agents)
    data = visual.redact(visual._ps(False))
    assert data[0]["posture"]["approvals"] == "skipped"
    assert "postureChip" in visual.PAGE


async def test_watch_all_badge_and_selected_title():
    from test_multi_app_table import _screen, _seed

    from agentwatch.ui.multi_app import MultiAgentWatchApp

    for size in ((120, 40), (80, 24)):  # wide, and narrow (no AGENT column)
        app = MultiAgentWatchApp()
        async with app.run_test(size=size) as pilot:
            _seed(app, "risky", pid=100)
            _seed(app, "guarded", pid=200)
            _seed(app, "plain", pid=300)
            app._postures = {100: RISKY, 200: Posture("skipped", "container", "low"),
                             300: SAFE}
            app.selected_path = Path("risky.jsonl")
            app.refresh_ui()
            await pilot.pause()
            table = app.query_one("#sessions")
            risky = table.get_cell("risky.jsonl", "project")
            assert risky.plain == "! risky"
            assert "red" in str(risky.get_style_at_offset(app.console, 0))
            guarded = table.get_cell("guarded.jsonl", "project")
            assert guarded.plain == "! guarded"
            assert "yellow" in str(guarded.get_style_at_offset(app.console, 0))
            assert table.get_cell("plain.jsonl", "project").plain == "plain"
            if size[0] == 120:
                assert "yolo / no sandbox" in _screen(app)  # the Selected strip title


def test_check_old_log_skips_discovery(monkeypatch, tmp_path, fixed):
    """A log not written in the last 10 minutes has no live agent: `check`
    never pays for process discovery (CI over old logs costs nothing extra)."""
    import os

    result = _check(monkeypatch, tmp_path, fixed, RISKY)
    assert "Advisory" in result.output  # fresh log: discovery runs
    log = tmp_path / "s.jsonl"
    old = log.stat().st_mtime - cli.POSTURE_ADVISORY_RECENT_S - 5
    os.utime(log, (old, old))
    monkeypatch.setattr(cli, "find_running_agents", lambda: pytest.fail("discovery ran"))
    result = CliRunner().invoke(cli.cli, ["check", "--log", str(log)])
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Advisory" not in result.output and "discovery ran" not in result.output


def test_check_json_never_runs_discovery(monkeypatch, tmp_path, fixed):
    _check(monkeypatch, tmp_path, fixed, RISKY)  # writes a fresh log
    monkeypatch.setattr(cli, "find_running_agents", lambda: pytest.fail("discovery ran"))
    result = CliRunner().invoke(cli.cli, ["check", "--json", "--log",
                                          str(tmp_path / "s.jsonl")])
    assert "discovery ran" not in result.output
    json.loads(result.output)


# -- QA #241 ------------------------------------------------------------


def _one(procs, cmdline, agent_type="claude-code", **kw) -> Posture:
    procs[PID] = FakeProc(PID, cmdline, parent=FakeProc(1, ["/sbin/init"]), **kw)
    posture.clear_cache()
    return posture.posture(agent(agent_type))


def test_parse_forms():
    cli = posture._CODEX
    for argv in (["-sV"], ["-s", "V"], ["-s=V"], ["--sandbox", "V"], ["--sandbox=V"]):
        assert posture._last(posture._parse(argv, cli), "sandbox") == "V", argv
    # prompts and anything after -- are not flags
    assert posture._parse(["exec", "explain --yolo", "--", "--yolo"], cli) == []
    # a value option swallows its value, even one that looks like a flag
    assert posture._last(posture._parse(["-m", "--yolo"], cli), "yolo") is None


@linux_only
@pytest.mark.parametrize("argv, approvals, sandbox", [  # B1
    (["codex", "-sdanger-full-access", "-anever"], "skipped", "none"),
    (["codex", "-s=danger-full-access", "-a=never"], "skipped", "none"),
    (["codex", "-sread-only", "-anever"], "skipped", "sandboxed"),
    (["codex", "exec", "--yolo", "do it"], "skipped", "none"),
    (["codex", "exec", "explain --yolo"], "skipped", "sandboxed"),  # exec: Never
    (["codex", "--not-so-yolo"], "auto", "sandboxed"),
])
def test_codex_short_flag_forms(procs, argv, approvals, sandbox):
    p = _one(procs, argv, "codex")
    assert (p.approvals, p.sandbox) == (approvals, sandbox)
    assert posture.tone(p) != "good"


@linux_only
@pytest.mark.parametrize("argv", [  # B2
    ["codex", "-c", "approval_policy=never", "-c", 'sandbox_mode="danger-full-access"'],
    ["codex", "-c", 'approval_policy="never"', "-c", "sandbox_mode=danger-full-access"],
    ["codex", "--config", "approval_policy=never", "--config=sandbox_mode=danger-full-access"],
    ["codex", "-capproval_policy=never", "-csandbox_mode=danger-full-access"],
])
def test_codex_config_overrides(procs, tmp_path, argv):
    (tmp_path / "codex" / "config.toml").write_text(
        'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n')
    p = _one(procs, argv, "codex")
    assert (p.approvals, p.sandbox, p.confidence) == ("skipped", "none", "high")


@linux_only
def test_codex_flag_beats_override(procs):
    p = _one(procs, ["codex", "-c", "approval_policy=never", "-a", "on-request"], "codex")
    assert p.approvals == "on"


@linux_only
def test_codex_profile_v2_file(procs, tmp_path):  # B3
    (tmp_path / "codex" / "config.toml").write_text('approval_policy = "on-request"\n')
    (tmp_path / "codex" / "y.config.toml").write_text(
        'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
    p = _one(procs, ["codex", "-p", "y"], "codex")
    assert (p.approvals, p.sandbox) == ("skipped", "none")
    assert _one(procs, ["codex", "--profile=y"], "codex").approvals == "skipped"
    # only overrides in the profile: the rest comes from config.toml
    (tmp_path / "codex" / "y.config.toml").write_text('sandbox_mode = "read-only"\n')
    p = _one(procs, ["codex", "-py"], "codex")
    assert (p.approvals, p.sandbox) == ("on", "sandboxed")


@linux_only
def test_codex_legacy_profiles(procs, tmp_path):
    (tmp_path / "codex" / "config.toml").write_text(
        'profile = "y"\n[profiles.y]\napproval_policy = "never"\n'
        'sandbox_mode = "danger-full-access"\n')
    assert _one(procs, ["codex"], "codex").approvals == "skipped"  # top-level selector
    (tmp_path / "codex" / "config.toml").write_text(
        '[profiles.y]\napproval_policy = "never"\n')
    assert _one(procs, ["codex", "-p", "y"], "codex").approvals == "skipped"
    assert _one(procs, ["codex", "-c", "profile=y"], "codex").approvals == "skipped"


@linux_only
def test_codex_unreadable_profile_is_unknown(procs, tmp_path):
    p = _one(procs, ["codex", "-p", "missing"], "codex")
    assert (p.approvals, p.sandbox) == ("unknown", "unknown")
    (tmp_path / "codex" / "config.toml").write_text('profile = "gone"\n')
    assert _one(procs, ["codex"], "codex").approvals == "unknown"


@linux_only
def test_codex_home_from_process_environment(procs, tmp_path):
    own = tmp_path / "own-codex"
    own.mkdir()
    (own / "config.toml").write_text('approval_policy = "never"\n')
    assert _one(procs, ["codex"], "codex", env={"CODEX_HOME": str(own)}).approvals == "skipped"
    assert _one(procs, ["codex"], "codex").approvals == "on"  # agentwatch's own CODEX_HOME


@linux_only
def test_codex_system_config_and_bad_config(procs, tmp_path):
    (tmp_path / "etc-codex.toml").write_text('approval_policy = "never"\n')
    assert _one(procs, ["codex"], "codex").approvals == "skipped"
    (tmp_path / "codex" / "config.toml").write_text('approval_policy = "on-request"\n')
    assert _one(procs, ["codex"], "codex").approvals == "on"  # user layer beats system
    (tmp_path / "codex" / "config.toml").write_text("not = [toml")
    p = _one(procs, ["codex"], "codex")
    assert p.approvals == "unknown" and p.sandbox == "unknown"


@linux_only
def test_codex_granular_policy_and_reviewer(procs, tmp_path):
    (tmp_path / "codex" / "config.toml").write_text(
        '[approval_policy.granular]\nsandbox_approval = false\n')
    assert _one(procs, ["codex"], "codex").approvals == "unknown"
    (tmp_path / "codex" / "config.toml").write_text('approvals_reviewer = "auto_review"\n')
    p = _one(procs, ["codex", "-s", "workspace-write"], "codex")
    assert p.approvals == "auto" and posture.tone(p) == "neutral"


@linux_only
def test_codex_defaults_are_never_green(procs):
    p = _one(procs, ["codex"], "codex")
    assert (p.approvals, p.sandbox, p.confidence) == ("on", "sandboxed", "low")
    assert posture.tone(p) == "neutral"


@linux_only
@pytest.mark.parametrize("settings, approvals", [  # B4
    ('{"permissions":{"defaultMode":"bypassPermissions"}}', "skipped"),
    ('{"permissions":{"defaultMode":"plan"}}', "on"),
    ("{not json", "unknown"),
])
def test_claude_settings_flag_inline(procs, settings, approvals):
    p = _one(procs, ["claude", "--settings", settings])
    assert p.approvals == approvals
    assert posture.tone(p) != "good"


@linux_only
def test_claude_settings_flag_file(procs, tmp_path):
    f = tmp_path / "s.json"
    f.write_text('{"permissions":{"defaultMode":"bypassPermissions"}}')
    assert _one(procs, ["claude", f"--settings={f}"]).approvals == "skipped"
    rel = tmp_path / "proj" / "rel.json"
    rel.write_text('{"permissions":{"defaultMode":"bypassPermissions"}}')
    assert _one(procs, ["claude", "--settings", "rel.json"]).approvals == "skipped"
    assert _one(procs, ["claude", "--settings", str(tmp_path / "nope.json")]).approvals == \
        "unknown"


@linux_only
def test_claude_managed_settings(procs, tmp_path):
    (tmp_path / "managed" / "managed-settings.json").write_text(
        '{"permissions":{"defaultMode":"bypassPermissions"}}')
    (tmp_path / "claude" / "settings.json").write_text('{"permissions":{"defaultMode":"plan"}}')
    p = _one(procs, ["claude"])
    assert p.approvals == "skipped" and "settings: bypassPermissions" in p.reasons
    # managed disableBypassPermissionsMode refuses the flag
    (tmp_path / "managed" / "managed-settings.json").write_text(
        '{"permissions":{"disableBypassPermissionsMode":"disable"}}')
    p = _one(procs, ["claude", "--dangerously-skip-permissions"])
    assert p.approvals == "on" and "bypass disabled" in p.reasons


@linux_only
def test_claude_managed_paths_per_os(monkeypatch):
    for platform, base in (("linux", "/etc/claude-code"),
                           ("darwin", "/Library/Application Support/ClaudeCode")):
        monkeypatch.setattr(posture.sys, "platform", platform)
        assert posture._managed_claude_paths()[0] == Path(base) / "managed-settings.json"


@linux_only
def test_claude_project_settings(procs, tmp_path):
    claude_dir = tmp_path / "proj" / ".claude"
    claude_dir.mkdir()
    (tmp_path / "claude" / "settings.json").write_text(
        '{"permissions":{"defaultMode":"bypassPermissions"}}')
    (claude_dir / "settings.json").write_text('{"permissions":{"defaultMode":"acceptEdits"}}')
    assert _one(procs, ["claude"]).approvals == "on"  # project beats user
    # bypassPermissions from a project file is not honoured: Manual
    (claude_dir / "settings.local.json").write_text(
        '{"permissions":{"defaultMode":"bypassPermissions"}}')
    assert _one(procs, ["claude"]).approvals == "on"


@linux_only
def test_claude_restricted(procs, tmp_path):
    (tmp_path / "claude" / "settings.json").write_text(
        '{"permissions":{"defaultMode":"bypassPermissions"}}')
    p = _one(procs, ["claude", "--restricted"])
    assert p.approvals != "skipped" and "--restricted" in p.reasons  # user settings ignored
    p = _one(procs, ["claude", "--restricted", "--dangerously-skip-permissions"])
    assert p.approvals == "on"


VERSIONED = "/home/u/.local/share/claude/versions/{}"


@linux_only
@pytest.mark.parametrize("version, argv, approvals, confidence", [
    ("2.1.323", ["claude"], "auto", "high"),
    ("2.1.283", ["claude"], "auto", "high"),
    ("2.1.250", ["claude"], "auto", "low"),  # plan-dependent
    ("2.1.100", ["claude"], "on", "low"),  # Manual (sandbox none: high approvals only)
    (None, ["claude"], "auto", "low"),  # npm install: version unknown
    ("2.1.323", ["claude", "-p", "hi"], "on", "low"),
])
def test_claude_builtin_default(procs, version, argv, approvals, confidence):
    exe = VERSIONED.format(version) if version else "/usr/bin/node"
    p = _one(procs, argv, exe=exe)
    assert p.approvals == approvals
    assert posture.tone(p) != "good"


@linux_only
def test_claude_disable_auto_mode(procs, tmp_path):
    (tmp_path / "claude" / "settings.json").write_text(
        '{"permissions":{"disableAutoMode":"disable"}}')
    assert _one(procs, ["claude"], exe=VERSIONED.format("2.1.323")).approvals == "on"
    p = _one(procs, ["claude", "--permission-mode", "auto"])
    assert p.approvals == "on" and "auto disabled" in p.reasons


@linux_only
def test_claude_partial_allows(procs):
    p = _one(procs, ["claude", "--permission-mode", "default", "--allowedTools",
                     "Bash(git status:*)"])
    assert p.approvals == "on" and "some tools pre-approved" in p.reasons
    p = _one(procs, ["copilot", "--allow-tool", "shell"], "copilot")
    assert p.approvals == "on" and "some tools pre-approved" in p.reasons
    p = _one(procs, ["copilot", "--allow-all-paths"], "copilot")
    assert p.approvals == "on" and "some tools pre-approved" in p.reasons


@linux_only
@pytest.mark.parametrize("argv, approvals", [  # B5
    (["gemini", "-dy"], "skipped"),
    (["gemini", "-yd"], "skipped"),
    (["gemini", "--yolo=true"], "skipped"),
    (["gemini", "--yolo", "true"], "skipped"),
    (["gemini", "--yolo=false"], "on"),
    (["gemini", "--yolo", "--no-yolo"], "on"),
    (["gemini", "--approvalMode", "yolo"], "skipped"),
    (["gemini", "--approvalMode=auto_edit"], "on"),
    (["gemini", "--approval-mode", "bogus"], "unknown"),
    (["gemini", "-p", "explain --yolo"], "on"),
    (["gemini", "-m", "-y"], "skipped"),  # yargs never takes a dash word as a value
])
def test_gemini_yargs_forms(procs, argv, approvals):
    assert _one(procs, argv, "gemini").approvals == approvals


@linux_only
def test_gemini_settings(procs, tmp_path):
    (tmp_path / "gemini" / "settings.json").write_text(
        '{"general":{"defaultApprovalMode":"yolo"},"tools":{"sandbox":"docker"}}')
    p = _one(procs, ["gemini"], "gemini")
    assert p.approvals == "on"  # a yolo default in settings is ignored by Gemini
    assert p.sandbox == "sandboxed" and "settings: tools.sandbox" in p.reasons
    (tmp_path / "gemini" / "settings.json").write_text(
        '{"general":{"defaultApprovalMode":"auto_edit"}}')
    p = _one(procs, ["gemini", "-s"], "gemini")
    assert p.sandbox == "sandboxed" and p.confidence == "low"
    assert _one(procs, ["gemini", "--no-sandbox"], "gemini").sandbox == "none"


@linux_only
def test_container_names_are_exact(procs):  # crunch is not crun
    p = run(procs, ["claude", "--permission-mode", "plan"], "claude-code", ["crunch"])
    assert p.sandbox == "none"
    posture.clear_cache()
    p = run(procs, ["claude", "--permission-mode", "plan"], "claude-code",
            ["/usr/bin/containerd-shim-runc-v2", "-id", "x"])
    assert p.sandbox == "container"


@linux_only
def test_depth_cut_reason(procs):
    proc = FakeProc(10, ["bash"])
    proc._parent = proc
    procs[PID] = FakeProc(PID, ["claude"], parent=proc)
    assert "ancestry too deep" in posture.posture(agent()).reasons


@linux_only
def test_flatpak_bwrap_is_low_confidence(procs, monkeypatch, tmp_path):
    p = run(procs, ["claude", "--permission-mode", "plan"], "claude-code",
            ["flatpak", "run", "x"], ["bwrap", "--args", "40"])
    assert (p.sandbox, p.confidence) == ("sandboxed", "low") and "flatpak" in p.reasons
    posture.clear_cache()
    p = run(procs, ["/app/bin/claude", "--permission-mode", "plan"], "claude-code", ["bwrap"])
    assert (p.sandbox, p.confidence) == ("sandboxed", "low") and "flatpak" in p.reasons
    posture.clear_cache()
    root = tmp_path / "root"
    root.mkdir()
    (root / ".flatpak-info").write_text("")
    monkeypatch.setattr(posture, "_proc_root", lambda pid: root)
    p = run(procs, ["claude", "--permission-mode", "plan"], "claude-code", ["bwrap"])
    assert (p.sandbox, p.confidence) == ("sandboxed", "low")


@linux_only
def test_good_tone_needs_human_and_real_sandbox(procs):
    p = run(procs, ["claude", "--permission-mode", "plan"], "claude-code", ["srt"])
    assert (p.approvals, p.sandbox, p.confidence) == ("on", "sandboxed", "high")
    assert posture.tone(p) == "good"
    posture.clear_cache()
    p = run(procs, ["claude", "--permission-mode", "auto"], "claude-code", ["srt"])
    assert posture.tone(p) == "neutral"  # auto review is not a human
    posture.clear_cache()
    p = run(procs, ["claude", "--permission-mode", "plan"], "claude-code", ["conmon"])
    assert posture.tone(p) == "neutral"  # a container is not a sandbox


def test_auto_labels():
    p = Posture("auto", "none", "high")
    assert posture.label(p) == "auto-review · no sandbox" and posture.tone(p) == "neutral"


# -- QA round 2 (PR #241): project config, exec, permission profiles, yargs,
# configurable launchers, allow-all rules -----------------------------------


def _srt(procs, cmdline, agent_type="codex") -> Posture:
    """The agent under srt (a real sandbox, high confidence), fresh cache."""
    posture.clear_cache()
    return run(procs, cmdline, agent_type, ["srt"])


def _repo(path: Path) -> Path:
    (path / ".git").mkdir(parents=True)
    (path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    return path


def _codex_project(path: Path, text: str) -> None:
    (path / ".codex").mkdir(parents=True, exist_ok=True)
    (path / ".codex" / "config.toml").write_text(text)


GOOD_CODEX = ["codex", "-s", "workspace-write", "-a", "on-request"]


@linux_only
def test_codex_flags_under_srt_are_green(procs):
    """The baseline the next tests break: explicit flags in a real sandbox."""
    assert posture.tone(_srt(procs, GOOD_CODEX)) == "good"


@linux_only
def test_codex_project_reviewer_is_not_green(procs):  # finding 1 (QA repro)
    _codex_project(CWD[0], 'approvals_reviewer = "auto_review"\n')
    p = _srt(procs, GOOD_CODEX)
    assert p.approvals == "auto" and posture.tone(p) != "good"
    assert "project config" in p.reasons


@linux_only
def test_codex_project_layer_precedence(procs, tmp_path):  # finding 1
    repo = _repo(tmp_path / "proj")
    sub = repo / "pkg" / "app"
    sub.mkdir(parents=True)
    (tmp_path / "codex" / "config.toml").write_text('approval_policy = "on-request"\n')
    _codex_project(repo, 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
    CWD[0] = sub
    p = _one(procs, ["codex"], "codex")
    assert (p.approvals, p.sandbox, p.confidence) == ("skipped", "none", "low")  # project > user
    _codex_project(sub, 'approval_policy = "on-request"\n')
    p = _one(procs, ["codex"], "codex")  # the closest directory wins, per key
    assert (p.approvals, p.sandbox) == ("on", "none") and p.confidence == "low"
    p = _one(procs, ["codex", "-c", "approval_policy=never"], "codex")  # -c > project
    assert p.approvals == "skipped"
    p = _one(procs, ["codex", "-a", "on-request", "-s", "read-only"], "codex")  # flags > project
    assert (p.approvals, p.sandbox) == ("on", "sandboxed")


@linux_only
def test_codex_project_walk_stops_at_repo_root(procs, tmp_path):  # finding 1
    outer = tmp_path / "outer"
    repo = _repo(outer / "repo")
    _codex_project(outer, 'approval_policy = "never"\n')
    CWD[0] = repo
    assert _one(procs, ["codex"], "codex").approvals == "on"  # above the root: not read
    # No repo root at all: only the cwd's own .codex counts.
    plain = tmp_path / "plain" / "sub"
    plain.mkdir(parents=True)
    _codex_project(tmp_path / "plain", 'approval_policy = "never"\n')
    CWD[0] = plain
    assert _one(procs, ["codex"], "codex").approvals == "on"
    _codex_project(plain, 'approval_policy = "never"\n')
    assert _one(procs, ["codex"], "codex").approvals == "skipped"


@linux_only
def test_codex_project_unknowns_are_never_green(procs, monkeypatch):  # finding 1
    _codex_project(CWD[0], "not = [toml")
    p = _srt(procs, GOOD_CODEX)
    assert posture.tone(p) != "good" and "project config unknown" in p.reasons
    (CWD[0] / ".codex" / "config.toml").unlink()
    monkeypatch.setattr(posture, "_PROJECT_WALK_MAX", 1)  # walk cut before any root
    p = _srt(procs, GOOD_CODEX)
    assert posture.tone(p) != "good" and "project config unknown" in p.reasons


@linux_only
def test_codex_project_cwd_and_denylist(procs, tmp_path):  # finding 1
    elsewhere = tmp_path / "elsewhere"
    _codex_project(elsewhere, 'approval_policy = "never"\n')

    class CwdProc(FakeProc):
        def cwd(self):
            return str(elsewhere)

    procs[PID] = CwdProc(PID, ["codex"], parent=FakeProc(1, ["/sbin/init"]))
    posture.clear_cache()
    assert posture.posture(agent("codex")).approvals == "skipped"  # the process's own cwd
    # -C/--cd moves the project, relative to the process cwd
    _codex_project(elsewhere / "inner", 'approval_policy = "on-request"\n')
    procs[PID] = CwdProc(PID, ["codex", "-C", "inner"], parent=FakeProc(1, ["/sbin/init"]))
    posture.clear_cache()
    assert posture.posture(agent("codex")).approvals == "on"
    # profile/profiles are not honoured from a project layer
    _codex_project(CWD[0], 'profile = "gone"\n')
    p = _one(procs, ["codex"], "codex")
    assert p.approvals == "on" and "config profile unreadable" not in p.reasons


@linux_only
@pytest.mark.parametrize("argv, approvals", [  # finding 2
    (["codex", "exec", "fix it"], "skipped"),
    (["codex", "e", "fix it"], "skipped"),
    (["codex", "review"], "skipped"),
    (["codex", "exec", "-s", "workspace-write", "fix it"], "skipped"),
    (["codex", "exec", "-c", "approval_policy=on-request", "x"], "unknown"),  # unproven
    (["codex", "-a", "on-request", "exec", "x"], "unknown"),  # -a is not an exec option
    (["codex", "exec", "--approve-for-me", "x"], "auto"),
])
def test_codex_exec_has_no_approvals(procs, argv, approvals):
    p = _one(procs, argv, "codex")
    assert p.approvals == approvals and posture.tone(p) != "good"
    assert "codex exec (no approvals)" in p.reasons
    assert "default approvals" not in p.reasons


@linux_only
def test_codex_exec_with_config_reviewer(procs, tmp_path):  # finding 2
    (tmp_path / "codex" / "config.toml").write_text(
        'approvals_reviewer = "auto_review"\napproval_policy = "on-request"\n')
    assert _one(procs, ["codex", "exec", "x"], "codex").approvals == "auto"


@linux_only
def test_codex_permission_profiles(procs, tmp_path):  # finding 3
    cfg = tmp_path / "codex" / "config.toml"
    cfg.write_text('default_permissions = ":danger-full-access"\n')
    p = _srt(procs, ["codex", "-a", "on-request"])
    assert p.approvals == "on" and "permission profile" in p.reasons
    p = _one(procs, ["codex", "-a", "on-request"], "codex")
    assert p.sandbox == "none"  # QA repro: never "sandboxed"
    cfg.write_text('default_permissions = "mine"\n[permissions.mine]\n')
    assert _one(procs, ["codex"], "codex").sandbox == "unknown"
    cfg.write_text('[permissions.mine]\n')
    assert _one(procs, ["codex"], "codex").sandbox == "unknown"
    cfg.write_text("")
    p = _one(procs, ["codex", "-c", 'default_permissions=":danger-full-access"',
                     "-a", "on-request"], "codex")
    assert p.sandbox == "none" and "-c default_permissions" in p.reasons
    assert _one(procs, ["codex", "-c", "default_permissions=mine"], "codex").sandbox == "unknown"
    _codex_project(CWD[0], 'default_permissions = "mine"\n')
    assert _one(procs, ["codex"], "codex").sandbox == "unknown"  # project layer too


@linux_only
def test_codex_sandbox_flag_with_permission_profile_is_low(procs, tmp_path):  # finding 3
    (tmp_path / "codex" / "config.toml").write_text('default_permissions = "mine"\n')
    p = _one(procs, GOOD_CODEX, "codex")  # -s beats the profile, but low confidence
    assert (p.sandbox, p.confidence) == ("sandboxed", "low")
    p = _one(procs, ["codex", "-c", "sandbox_mode=workspace-write"], "codex")
    assert p.sandbox == "sandboxed" and p.confidence == "low"


@linux_only
@pytest.mark.parametrize("argv, approvals", [  # finding 4
    (["gemini", "-m", "--yolo"], "skipped"),
    (["gemini", "-p", "--yolo", "task"], "skipped"),
    (["gemini", "--model", "--yolo"], "skipped"),
    (["gemini", "-m", "x", "-y"], "skipped"),
    (["gemini", "-my"], "skipped"),
    (["gemini", "-y", "true"], "skipped"),
    (["gemini", "-y", "false"], "on"),  # yargs: true/false after a boolean is its value
    (["gemini", "-y", "task"], "skipped"),  # a boolean never takes another word
    (["gemini", "--yolo=1"], "unknown"),  # odd boolean values: not guessed
    (["gemini", "--yolo=TRUE"], "unknown"),
])
def test_gemini_dash_words_are_not_values(procs, argv, approvals):
    assert _one(procs, argv, "gemini").approvals == approvals


@linux_only
@pytest.mark.parametrize("argv, sandbox", [  # finding 4
    (["gemini", "-s"], "sandboxed"),
    (["gemini", "-s", "false"], "none"),
    (["gemini", "-s", "task"], "sandboxed"),
    (["gemini", "-ms"], "unknown"),  # a value option inside a group: not proof
    (["gemini", "-m", "-s"], "sandboxed"),
    (["gemini", "--sandbox=1"], "unknown"),
])
def test_gemini_short_sandbox_forms(procs, argv, sandbox):
    p = _one(procs, argv, "gemini")
    assert p.sandbox == sandbox and posture.tone(p) != "good"


def test_yargs_short_groups():
    cli, bools = posture._GEMINI, posture._GEMINI_BOOLS

    def parse(argv):
        return posture._parse(argv, cli, bools)

    assert posture._last(parse(["-mgemini-pro"]), "model") is True  # yargs: each letter a flag
    assert posture._last(parse(["-m=x"]), "model") == "x"
    assert posture._last(parse(["-m", "-"]), "model") == "-"
    assert posture._last(parse(["-m", "--"]), "model") == "--"
    assert posture._last(parse(["--model", "-y"]), "yolo") is True
    assert posture._last(parse(["-y=false"]), "yolo") == "false"


@linux_only
@pytest.mark.parametrize("launcher", [  # finding 5
    ["bwrap", "--bind", "/", "/"], ["bwrap", "--ro-bind", "/", "/"], ["firejail", "--noprofile"],
    ["nsjail", "--"], ["/usr/bin/sandbox-exec", "-p", "(allow default)"],
])
def test_configurable_launchers_are_low_confidence(procs, launcher):
    p = run(procs, ["claude", "--permission-mode", "plan"], "claude-code", launcher)
    assert (p.sandbox, p.confidence) == ("sandboxed", "low")
    assert posture.tone(p) != "good" and "launcher options not read" in p.reasons
    assert "/" not in " ".join(p.reasons)  # launcher argv never echoed


@linux_only
@pytest.mark.parametrize("rule", ["Bash", "Bash(*)", "*", "bash"])  # finding 6
def test_claude_allow_all_rule_is_not_green(procs, tmp_path, rule):
    (tmp_path / "claude" / "settings.json").write_text(
        json.dumps({"permissions": {"allow": ["Read", rule]}}))
    p = _srt(procs, ["claude", "--permission-mode", "plan"], "claude-code")
    assert (p.approvals, p.confidence) == ("on", "low") and posture.tone(p) != "good"
    assert "all commands pre-approved" in p.reasons
    assert all(rule not in r for r in p.reasons if r.startswith("Bash"))


@linux_only
@pytest.mark.parametrize("argv", [  # finding 6
    ["--allowedTools", "Bash"],
    ["--allowedTools", "Edit,Bash"],
    ["--allowed-tools", "Edit", "Bash(*)"],
    ["--allowedTools=*"],
])
def test_claude_allowed_tools_flag_allow_all(procs, argv):
    p = _srt(procs, ["claude", "--permission-mode", "plan", *argv], "claude-code")
    assert p.confidence == "low" and "all commands pre-approved" in p.reasons


@linux_only
def test_claude_narrow_allow_rules_stay_green(procs, tmp_path):  # finding 6: narrow
    (tmp_path / "claude" / "settings.json").write_text(
        json.dumps({"permissions": {"allow": ["Bash(git status:*)", "Edit"]}}))
    p = _srt(procs, ["claude", "--permission-mode", "plan", "--allowedTools", "Read"],
             "claude-code")
    assert posture.tone(p) == "good" and "all commands pre-approved" not in p.reasons
    # an allow-all word that is a prompt, not the option's value, is not read
    p = _srt(procs, ["claude", "--permission-mode", "plan", "--allowedTools", "Read", "--",
                     "Bash"], "claude-code")
    assert posture.tone(p) == "good"
