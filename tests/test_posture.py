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
                 status=psutil.STATUS_RUNNING, deny=()):
        self.pid = pid
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
    posture.clear_cache()
    yield table
    posture.clear_cache()


def agent(agent_type="claude-code", pid=PID):
    return AgentProcess(pid=pid, agent_type=agent_type, working_directory=Path("/w/app"))


def run(procs, cmdline, agent_type="claude-code", *ancestors) -> Posture:
    proc = chain(*ancestors, cmdline)
    procs[proc.pid] = proc
    return posture.posture(agent(agent_type, proc.pid))


# -- approvals ----------------------------------------------------------


@linux_only
@pytest.mark.parametrize("argv, approvals, reason", [
    (["claude"], "on", "default mode"),
    (["claude", "--dangerously-skip-permissions"], "skipped", "--dangerously-skip-permissions"),
    (["claude", "--permission-mode", "bypassPermissions"], "skipped",
     "--permission-mode bypassPermissions"),
    (["claude", "--permission-mode=bypassPermissions"], "skipped",
     "--permission-mode bypassPermissions"),
    (["claude", "--permission-mode", "acceptEdits"], "on", "--permission-mode"),
    (["claude", "--", "--dangerously-skip-permissions"], "on", "default mode"),
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
    p = run(procs, ["claude", "--allow-dangerously-skip-permissions"])
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
    assert run(procs, ["claude"]).approvals == "on"


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
    (["codex", "--approve-for-me"], "on", "sandboxed"),
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
    assert (p.sandbox, p.confidence) == ("sandboxed", "high")
    assert reason in p.reasons and not p.risky


@linux_only
def test_codex_linux_sandbox_ancestor(procs):
    p = run(procs, ["claude"], "claude-code", ["codex"], ["codex-linux-sandbox", "--"])
    assert p.sandbox == "sandboxed" and "codex sandbox" in p.reasons


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
    procs[PID] = FakeProc(PID, ["claude"], create_time=2000.0, parent=FakeProc(1, ["init"]))
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
