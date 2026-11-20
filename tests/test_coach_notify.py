"""`agentwatch hook` on Notification/Stop (attention alerts) and `agentwatch notify`."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from agentwatch import coach
from agentwatch.cli import cli


@pytest.fixture
def sent(tmp_path, monkeypatch):
    """Settings and state in tmp; desktop delivery and webhook captured."""
    monkeypatch.setattr(coach, "state_dir", lambda: tmp_path / "state")
    monkeypatch.setattr(coach, "user_state_dir", lambda: tmp_path / "user-state")
    out: list[tuple] = []
    monkeypatch.setattr(coach, "_spawn", lambda argv, data: out.append(("desktop", argv[-2:])))
    monkeypatch.setattr("agentwatch.alerts.notify_command",
                        lambda title, body: (["notify-send", title, body], None))
    monkeypatch.setattr("agentwatch.alerts.post_webhook",
                        lambda url, text, timeout: out.append(("webhook", url, text)))
    return out


def _transcript(tmp_path: Path) -> Path:
    entries = [
        {"type": "user", "message": {"role": "user", "content": "fix the test"}},
        {"type": "assistant", "message": {
            "id": "m1", "role": "assistant", "model": "claude-sonnet-4-5",
            "usage": {"input_tokens": 1000, "output_tokens": 100},
            "content": [{"type": "tool_use", "id": "t1", "name": "Bash", "input": {}}]}},
        {"type": "user", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": "ok"}]}},
        {"type": "assistant", "message": {
            "id": "m2", "role": "assistant", "model": "claude-sonnet-4-5",
            "usage": {"input_tokens": 1000, "output_tokens": 100}, "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "Done."}]}},
    ]
    path = tmp_path / "sess.jsonl"
    path.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")
    return path


def _ev(tmp_path, event, **kw) -> str:
    return json.dumps({"session_id": "sess-1", "transcript_path": str(_transcript(tmp_path)),
                       "cwd": "/home/u/myproj", "hook_event_name": event, **kw})


def _notif(tmp_path, kind="idle_prompt", message="Claude is waiting for your input"):
    return _ev(tmp_path, "Notification", notification_type=kind, message=message)


def _on(**settings):
    coach.save_notify({"on": True, **settings})


def test_off_by_default_no_alert_no_output(tmp_path, sent):
    assert coach.run(_notif(tmp_path)) is None
    assert coach.run(_ev(tmp_path, "Stop", stop_hook_active=False)) is None
    assert sent == []
    assert not (tmp_path / "state").exists()  # did not even touch state


def test_permission_prompt_alert_text(tmp_path, sent):
    _on()
    msg = "Claude needs your permission to use Bash"
    out = coach.run(_notif(tmp_path, "permission_prompt", msg))
    assert out is None
    assert sent == [("desktop", ["agentwatch: Claude Code · myproj — waiting for permission",
                                 "Claude needs your permission to use Bash"])]


def test_stop_alerts_finished_with_turn_summary(tmp_path, sent):
    _on()
    assert coach.run(_ev(tmp_path, "Stop", stop_hook_active=False)) is None
    (kind, (title, body)), = sent
    assert title == "agentwatch: Claude Code · myproj — finished"
    assert body.startswith("1 tool call this turn, ~$0.")


def test_turn_summary_prices_1h_cache_writes_at_the_1h_rate(tmp_path):
    usage = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0,
             "cache_creation_input_tokens": 1_000_000,
             "cache_creation": {"ephemeral_5m_input_tokens": 600_000,
                                "ephemeral_1h_input_tokens": 400_000}}
    entries = [
        {"type": "user", "message": {"role": "user", "content": "go"}},
        {"type": "assistant", "message": {
            "id": "m1", "role": "assistant", "model": "claude-sonnet-4-5", "usage": usage,
            "content": [{"type": "text", "text": "Done."}]}},
    ]
    path = tmp_path / "sess.jsonl"
    path.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")
    # Sonnet 4.5: 5m writes $3.75/M, 1h writes $6/M -> 0.6 * 3.75 + 0.4 * 6
    assert coach._turn_summary(path) == "0 tool calls this turn, ~$4.65"


def test_repeat_idle_deduped_then_stop_and_new_wait_alert_again(tmp_path, sent):
    _on()
    coach.run(_notif(tmp_path))
    coach.run(_notif(tmp_path))  # the reminder repeats: no second alert
    assert len(sent) == 1
    coach.run(_ev(tmp_path, "Stop", stop_hook_active=False))
    assert len(sent) == 2
    coach.run(_notif(tmp_path))  # idle after "finished": already said
    assert len(sent) == 2
    coach.run(_notif(tmp_path, "permission_prompt", "needs permission"))
    assert len(sent) == 3


def test_different_permission_prompts_each_alert(tmp_path, sent, monkeypatch):
    _on()
    coach.run(_notif(tmp_path, "permission_prompt", "Claude needs your permission to use Bash"))
    coach.run(_notif(tmp_path, "permission_prompt", "Claude needs your permission to use Write"))
    assert len(sent) == 2
    coach.run(_notif(tmp_path, "permission_prompt", "Claude needs your permission to use Write"))
    assert len(sent) == 2  # the same prompt re-sent within REPEAT_S
    now = coach.time.time()
    monkeypatch.setattr(coach.time, "time", lambda: now + coach.REPEAT_S + 1)
    coach.run(_notif(tmp_path, "permission_prompt", "Claude needs your permission to use Write"))
    assert len(sent) == 3


def test_repeated_idle_alerts_once(tmp_path, sent):
    _on()
    for _ in range(3):
        coach.run(_notif(tmp_path))
    assert len(sent) == 1


def test_malformed_events_mean_none(tmp_path, sent):
    _on(events="done")
    coach.run(_ev(tmp_path, "Stop", stop_hook_active=False))
    coach.run(_notif(tmp_path))
    assert sent == []


def test_post_tool_use_clears_waiting_state(tmp_path, sent):
    _on()
    coach.run(_notif(tmp_path, "permission_prompt", "needs permission"))
    post = json.dumps({"session_id": "sess-1", "transcript_path": str(_transcript(tmp_path)),
                       "hook_event_name": "PostToolUse", "tool_name": "Bash",
                       "tool_use_id": "t1", "tool_input": {}})
    assert coach.run(post) is None
    coach.run(_notif(tmp_path, "permission_prompt", "needs permission"))
    assert len(sent) == 2


def test_stop_hook_active_and_unknown_types_ignored(tmp_path, sent):
    _on()
    coach.run(_ev(tmp_path, "Stop", stop_hook_active=True))
    coach.run(_notif(tmp_path, "auth_success", "ok"))
    assert sent == []


def test_events_filter(tmp_path, sent):
    _on(events=["done"])
    coach.run(_notif(tmp_path))
    assert sent == []
    coach.run(_ev(tmp_path, "Stop", stop_hook_active=False))
    assert len(sent) == 1
    _on(events=["needs-input"])
    coach.run(_ev(tmp_path, "Stop", stop_hook_active=False))  # not sent, clears state
    coach.run(_notif(tmp_path))
    assert [s[1][0].rsplit("— ", 1)[1] for s in sent] == ["finished", "waiting for your input"]


def test_webhook_gets_the_alert(tmp_path, sent):
    _on(webhook="https://hooks.example.com/T/SECRET")
    coach.run(_notif(tmp_path, "permission_prompt", "Claude needs your permission to use <Bash>"))
    hook = [s for s in sent if s[0] == "webhook"]
    assert hook == [("webhook", "https://hooks.example.com/T/SECRET",
                     "agentwatch: Claude Code · myproj — waiting for permission\n"
                     "Claude needs your permission to use Bash")]


def test_secrets_in_message_are_redacted(tmp_path, sent):
    _on()
    coach.run(_notif(tmp_path, "permission_prompt",
                     "run curl -H 'Authorization: Bearer ghp_" + "a" * 36 + "'"))
    assert "ghp_" + "a" * 36 not in sent[0][1][1]


@pytest.mark.parametrize("text", ["{not json", "[]", '{"on": "yes"}', ""])
def test_corrupt_settings_mean_off(tmp_path, sent, text):
    path = tmp_path / "user-state" / coach.NOTIFY
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")
    assert coach.run(_notif(tmp_path)) is None
    assert sent == []


def test_corrupt_state_file_still_alerts(tmp_path, sent):
    _on()
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "sess-1.json").write_text("{oops", encoding="utf-8")
    coach.run(_notif(tmp_path))
    assert len(sent) == 1


def test_plugin_hooks_json():
    root = Path(__file__).resolve().parents[1]
    hooks = json.loads((root / "plugin" / "hooks" / "hooks.json").read_text("utf-8"))["hooks"]
    for event in ("Notification", "Stop"):
        (group,) = hooks[event]
        (h,) = group["hooks"]
        assert h["command"] == "agentwatch hook; exit 0" and h["async"] is True
    assert set(hooks["Notification"][0]["matcher"].split("|")) == set(coach._WAITING)
    # The tool hooks stay synchronous: PreToolUse's deny and PostToolUse's note need it.
    for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
        assert "async" not in hooks[event][0]["hooks"][0]


def test_settings_file_never_pruned():
    assert Path(coach.NOTIFY).suffix not in (".json", ".tmp")


# --- console path -------------------------------------------------------


def _env(tmp_path) -> dict:
    env = {**os.environ, "HOME": str(tmp_path), "XDG_CACHE_HOME": str(tmp_path / "cache"),
           "LOCALAPPDATA": str(tmp_path / "local")}
    env.pop("CLAUDE_PLUGIN_DATA", None)
    return env


def _hook(tmp_path, payload: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", "from agentwatch._entry import main; main()", "hook"],
        input=payload, capture_output=True, text=True, timeout=60, env=env,
    )


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows creationflags path")
def test_real_spawn_returns_at_once_and_feeds_stdin_windows(tmp_path):
    marker = tmp_path / "got.txt"
    script = ("import sys, time; time.sleep(1); "
              f"open({str(marker)!r}, 'wb').write(sys.stdin.buffer.read())")
    start = time.monotonic()
    coach._spawn([sys.executable, "-c", script], b"toast xml")
    assert time.monotonic() - start < 0.5  # did not wait for the 1 s child
    assert not marker.exists()
    deadline = time.monotonic() + 30
    while not (marker.exists() and marker.read_bytes()) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert marker.read_bytes() == b"toast xml"


@pytest.mark.skipif(sys.platform != "linux", reason="fake notify-send is a shell script")
def test_console_hook_off_and_on(tmp_path):
    env = _env(tmp_path)
    # A fake notifier on PATH records its argv: never the real notify-send.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "notified.txt"
    fake = bin_dir / "notify-send"
    fake.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{log}'\n")
    fake.chmod(0o755)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"

    proc = _hook(tmp_path, _notif(tmp_path), env)
    assert (proc.returncode, proc.stdout) == (0, "")
    assert not log.exists()

    res = CliRunner(env=env).invoke(cli, ["notify", "on"])
    assert res.exit_code == 0, res.output
    proc = _hook(tmp_path, _notif(tmp_path), env)
    assert (proc.returncode, proc.stdout) == (0, "")
    for _ in range(50):  # the notifier runs detached
        if log.exists() and "waiting" in log.read_text():
            break
        subprocess.run([sys.executable, "-c", "import time; time.sleep(0.1)"])
    lines = log.read_text().splitlines()
    assert "agentwatch: Claude Code · myproj — waiting for your input" in lines
    assert "Claude is waiting for your input" in lines


# --- `agentwatch notify` --------------------------------------------------


def test_notify_cli_on_status_off(tmp_path, monkeypatch):
    env = _env(tmp_path)
    for k in ("HOME", "XDG_CACHE_HOME", "LOCALAPPDATA"):
        monkeypatch.setenv(k, env[k])
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    runner = CliRunner()
    assert "off" in runner.invoke(cli, ["notify", "status"]).output

    url = "https://hooks.slack.com/services/T0/B0/SECRETTOKEN"
    res = runner.invoke(cli, ["notify", "on", "--webhook", url, "--events", "done"])
    assert res.exit_code == 0, res.output
    status = runner.invoke(cli, ["notify"]).output
    assert "on (done)" in status and "webhook https://hooks.slack.com/***" in status
    assert "SECRETTOKEN" not in res.output + status

    path = coach.notify_path()
    assert json.loads(path.read_text())["webhook"] == url
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700

    assert runner.invoke(cli, ["notify", "off"]).output.strip() == "agentwatch notify: off"
    assert not path.exists()


def test_notify_cli_rejects_bad_input(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    runner = CliRunner()
    assert runner.invoke(cli, ["notify", "on", "--events", "done,lunch"]).exit_code == 2
    res = runner.invoke(cli, ["notify", "on", "--webhook", "ftp://x/SECRET"])
    assert res.exit_code == 2 and "SECRET" not in res.output
    assert runner.invoke(cli, ["notify", "off", "--webhook", "https://x/y"]).exit_code == 2
