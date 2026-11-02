"""Per-user off switch for the command guard: `agentwatch guard off|on`
(Sprint 40, board 2026-11-02). The guard is off only for exactly {"on": false}."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from click.testing import CliRunner

from agentwatch import coach, guard
from agentwatch.cli import cli

RM = {"command": "rm -rf ~"}


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    """Real user_state_dir(), pointed at tmp_path so the real user dir is untouched."""
    for var in ("LOCALAPPDATA", "XDG_CACHE_HOME", "HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(tmp_path))
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.delenv("AGENTWATCH_LOOP_BREAKER", raising=False)
    assert tmp_path in coach.user_state_dir().parents


def _payload(tool_input: dict, event: str = "PreToolUse", transcript: str = "/none.jsonl",
             tool_use_id: str = "tnext") -> str:
    return json.dumps({"session_id": "sess-1", "transcript_path": transcript,
                       "hook_event_name": event, "tool_name": "Bash",
                       "tool_input": tool_input, "tool_use_id": tool_use_id})


def _decision(out: str | None) -> str | None:
    return None if out is None else json.loads(out)["hookSpecificOutput"]["permissionDecision"]


def _write(text: str) -> None:
    coach.user_state_dir().mkdir(parents=True, exist_ok=True)
    coach.guard_path().write_text(text, encoding="utf-8")


def test_off_skips_the_guard_without_importing_it(monkeypatch):
    coach.set_guard(False)
    assert json.loads(coach.guard_path().read_text(encoding="utf-8")) == {"on": False}
    assert coach.guard_path() == coach.user_state_dir() / "guard"
    monkeypatch.delitem(sys.modules, "agentwatch.guard", raising=False)
    assert coach.run(_payload(RM)) is None
    assert "agentwatch.guard" not in sys.modules


def test_on_deletes_the_file_and_asks_again():
    coach.set_guard(False)
    coach.set_guard(True)
    assert not coach.guard_path().exists()
    assert _decision(coach.run(_payload(RM))) == "ask"
    coach.set_guard(True)  # already on: no error


@pytest.mark.parametrize("text", [
    None, "", "not json", '{"on": 0}', '{"on": null}', '{"on": "false"}', "[]", "false",
    '{"on": true}', "{}", '[{"on": false}]',
    pytest.param("[" * 100_000 + "]" * 100_000, id="deep-nesting"),
])
def test_anything_but_exactly_on_false_keeps_the_guard_on(text):
    if text is not None:
        _write(text)
    assert coach.guard_enabled() is True
    assert _decision(coach.run(_payload(RM))) == "ask"


def test_unreadable_file_keeps_the_guard_on():
    coach.guard_path().mkdir(parents=True)  # a directory: read_text raises
    assert coach.guard_enabled() is True
    assert _decision(coach.run(_payload(RM))) == "ask"


def _loop_transcript(tmp_path, command: str, n: int = 6):
    lines = []
    for i in range(n):
        ts = f"2026-10-17T10:00:{i:02d}Z"
        lines.append({"type": "assistant", "timestamp": ts, "message": {
            "role": "assistant", "content": [
                {"type": "tool_use", "id": f"t{i}", "name": "Bash",
                 "input": {"command": command}}]}})
        lines.append({"type": "user", "timestamp": ts, "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"t{i}", "content": "boom",
             "is_error": True}]}})
    path = tmp_path / "s.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in lines) + "\n", encoding="utf-8")
    coach.run(_payload({"command": command}, "PostToolUse", str(path), f"t{n - 1}"))
    return str(path)


def test_breaker_still_runs_when_the_guard_is_off(tmp_path):
    command = "git reset --hard HEAD~1"
    t = _loop_transcript(tmp_path, command)
    assert _decision(coach.run(_payload({"command": command}, transcript=t))) == "ask"
    coach.set_guard(False)
    assert _decision(coach.run(_payload({"command": command}, transcript=t))) == "deny"


def test_cli_off_on_status():
    runner = CliRunner()
    result = runner.invoke(cli, ["guard"])
    assert result.exit_code == 0, result.output
    assert "agentwatch guard: on" in result.output
    assert str(coach.guard_path()) in result.output

    result = runner.invoke(cli, ["guard", "off"])
    assert result.exit_code == 0, result.output
    assert "agentwatch guard: off" in result.output
    assert str(coach.guard_path()) in result.output
    assert coach.guard_enabled() is False

    assert "agentwatch guard: off" in runner.invoke(cli, ["guard", "status"]).output

    result = runner.invoke(cli, ["guard", "on"])
    assert result.exit_code == 0, result.output
    assert "agentwatch guard: on" in result.output
    assert not coach.guard_path().exists()


def test_cli_write_failure_exits_1(monkeypatch):
    def fail(on):
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(coach, "set_guard", fail)
    result = CliRunner().invoke(cli, ["guard", "off"])
    assert result.exit_code == 1
    assert "cannot write" in result.output  # CliRunner mixes stderr into output


def test_real_entry_process_with_guard_off_prints_nothing(tmp_path):
    coach.set_guard(False)
    env = {"PATH": "", "HOME": str(tmp_path), "XDG_CACHE_HOME": str(tmp_path),
           "LOCALAPPDATA": str(tmp_path), "USERPROFILE": str(tmp_path),
           "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
    proc = subprocess.run(
        [sys.executable, "-c", "from agentwatch._entry import main; main()", "hook"],
        input=_payload({"command": "bash -c 'rm -rf ~'"}), capture_output=True, text=True,
        timeout=30, env=env, cwd=tmp_path,
    )
    assert proc.returncode == 0
    assert proc.stdout == ""


# The agent must not be able to turn its own guard off silently (CTO review).

def _asks_off(out: str | None) -> bool:
    if _decision(out) != "ask":
        return False
    reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
    return "turns off the agentwatch command guard" in reason


@pytest.mark.parametrize("command", [
    "agentwatch guard off",
    "agentwatch --theme ascii guard off",
    "/usr/local/bin/agentwatch guard off",
    "agentwatch.exe guard off",
    r'"C:\Python313\Scripts\agentwatch.exe" guard off',
    "python -m agentwatch guard off",
    "python3 -m agentwatch.cli guard off",
    "py -3 -m agentwatch guard off",
    "uvx --from agentwatch-monitor agentwatch guard off",
    "uvx agentwatch-monitor guard off",
    "pipx run agentwatch-monitor guard off",
    "pipx run agentwatch-monitor==0.2.1 guard off",
    "bash -c 'agentwatch guard off'",
    "sudo agentwatch guard off",
    "env X=1 agentwatch guard off",
    "cd /tmp && agentwatch guard off",
    "true; agentwatch guard off",
    "echo $(agentwatch guard off)",
    "agentwatch guard off && rm -rf ./build",
    # fix round: the agentguard alias, more launchers and wrappers
    "agentguard guard off",
    "agentguard.exe guard off",
    "python -m agentguard guard off",
    "uvx --from agentwatch-monitor agentguard guard off",
    "xargs agentwatch guard off",
    "npx agentwatch guard off",
    "npx agentwatch-monitor guard off",
    "eval agentguard guard off",
    "cmd /c agentwatch guard off",
    'pwsh -c "agentguard guard off"',
    "wsl agentwatch guard off",
    "agentguard guard off 'oops",
    pytest.param("true;" * 4100 + "agentguard guard off", id="long-agentguard"),
])
def test_turning_the_guard_off_asks(command):
    assert _asks_off(coach.run(_payload({"command": command})))


@pytest.mark.parametrize("path", [
    "~/.cache/agentwatch/coach/guard",
    "$HOME/.cache/agentwatch/coach/guard",
    "/home/u/.cache/agentwatch/coach/../coach/guard",
    "C:/Users/U/AppData/Local/AgentWatch/Coach/GUARD",
])
@pytest.mark.parametrize("template", [
    "echo '{{\"on\": false}}' > {}",
    "echo '{{\"on\": false}}' >> {}",
    "printf x | tee -a {}",
    "cp /tmp/off.json {}",
    "mv /tmp/off.json {}",
    "bash -c 'echo x > {}'",
])
def test_bash_writes_to_the_guard_file_ask(template, path):
    assert _asks_off(coach.run(_payload({"command": template.format(path)})))


def test_bash_write_to_the_real_guard_path_asks():
    path = str(coach.guard_path())
    assert _asks_off(coach.run(_payload({"command": f'echo x > "{path}"'})))


@pytest.mark.parametrize("tool,key", [
    ("Write", "file_path"), ("Edit", "file_path"), ("MultiEdit", "file_path"),
    ("NotebookEdit", "notebook_path"),
])
def test_file_tools_on_the_guard_file_ask(tool, key):
    for path in (str(coach.guard_path()), str(coach.guard_path()).upper()):
        payload = json.loads(_payload({key: path, "content": '{"on": false}'}))
        payload["tool_name"] = tool
        assert _asks_off(coach.run(json.dumps(payload)))


@pytest.mark.parametrize("command", [
    "agentwatch guard",
    "agentwatch guard on",
    "agentwatch guard status",
    'echo "agentwatch guard off"',
    'git commit -m "agentwatch guard off"',
    "echo x > /tmp/project/guard",
    "cp a.json src/guard",
    "cat ~/.cache/agentwatch/coach/guard",
    "echo agentguard guard off",
    "agentguard guard",
    "agentguard guard on",
    "npx prettier --write .",
    "xargs grep -l guard",
])
def test_guard_look_alikes_pass(command):
    assert coach.run(_payload({"command": command})) is None


def test_write_to_an_unrelated_guard_file_passes(tmp_path):
    for path in (str(tmp_path / "guard"), str(tmp_path / "coach" / "guard")):
        payload = json.loads(_payload({"file_path": path, "content": "x"}))
        payload["tool_name"] = "Write"
        assert coach.run(json.dumps(payload)) is None


def test_unparsable_guard_off_still_asks():
    assert _asks_off(coach.run(_payload({"command": "agentwatch guard off 'oops"})))


# Fix round (#193): wrappers that run their arguments as a command.

@pytest.mark.parametrize("command", [
    "eval rm -rf /",
    'eval "rm -rf /"',
    "builtin eval 'rm -rf ~'",
    "builtin command rm -rf /",
    "setsid rm -rf ~",
    "setsid -f -w git reset --hard",
    "cmd /c git reset --hard",
    'cmd /c "git reset --hard"',
    "cmd.exe /C rm -rf /",
    'powershell -Command "git reset --hard"',
    "powershell.exe -command git push --force",
    "pwsh -c git reset --hard",
    "wsl rm -rf ~",
    "wsl -d Ubuntu rm -rf ~",
    "wsl.exe -u root -e git reset --hard",
    "wsl -- rm -rf /",
    'script -q -c "rm -rf /" /dev/null',
    "script --command 'git reset --hard'",
    'cmd /c bash -c "rm -rf /"',
    "bash.exe -c 'rm -rf /'",
])
def test_wrapped_commands_ask(command):
    assert guard.check("Bash", {"command": command}) is not None


@pytest.mark.parametrize("command", [
    "cat eval.txt",
    "echo eval rm -rf /",
    "builtin echo rm -rf /",
    "setsid sleep 1",
    "cmd /c dir",
    "pwsh -c Get-ChildItem",
    "powershell -File build.ps1",
    # -EncodedCommand is base64 and not decoded: a documented gap.
    "powershell -EncodedCommand cgBtACAALQByAGYAIAAvAA==",
    "wsl ls ~",
    "script session.log",
    'script -c "ls -la" /dev/null',
])
def test_wrapper_look_alikes_pass(command):
    assert guard.check("Bash", {"command": command}) is None
