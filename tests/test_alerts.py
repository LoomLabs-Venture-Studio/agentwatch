"""Alerts: rate limiting, text, webhook, notifier backends, escaping, headless."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from agentwatch import alerts
from agentwatch.alerts import Alerter, mask_url, notify_command, post_webhook
from agentwatch.cli import cli
from agentwatch.detectors.base import Category, Severity, Warning
from agentwatch.themes import get_theme

NASTY = 'say "hi" \'there\' `whoami` $(rm -rf ~) $env:PATH; & | <b>x</b>\nline 2 · —'


def _w(signal="loop", severity=Severity.CRITICAL, message="Repeated action: Bash (8x)",
       cost=None, **details) -> Warning:
    w = Warning(Category.PROGRESS, severity, signal, message, details=details)
    if cost is not None:
        w.tokens, w.cost_usd = 210_000, cost
    return w


def _report(critical=False, score=None):
    theme = get_theme()
    return SimpleNamespace(
        status=theme.level_3 if critical else theme.level_0,
        overall_score=score if score is not None else (20 if critical else 95),
    )


class _Recorder:
    """Alerter whose sends are captured instead of dispatched."""

    def __init__(self, **kw):
        self.sent: list[tuple[str, str]] = []
        self.alerter = Alerter(notify=True, **kw)
        self.alerter._desktop = lambda title, body: self.sent.append((title, body))

    def observe(self, warnings, report=None, session="s1"):
        self.alerter.observe(session, "claude-code", "myproj", warnings, report or _report())


@pytest.fixture(autouse=True)
def sync_threads(monkeypatch):
    """Run alert sends inline so tests see their effects immediately."""

    class _Inline:
        def __init__(self, target, args=(), daemon=None):
            self._target, self._args = target, args

        def start(self):
            self._target(*self._args)

    monkeypatch.setattr(alerts, "Thread", _Inline)


# --- rate limiting -------------------------------------------------------


def test_one_alert_per_session_and_dedup_key():
    r = _Recorder()
    for _ in range(3):
        r.observe([_w(last_command="pytest")])
    assert len(r.sent) == 1
    r.observe([_w(last_command="pytest")], session="s2")  # another session
    assert len(r.sent) == 2


def test_cleared_warning_realerts_on_recurrence():
    r = _Recorder()
    r.observe([_w()])
    r.observe([])
    r.observe([_w()])
    assert len(r.sent) == 2


def test_volatile_error_text_does_not_realert():
    r = _Recorder()
    r.observe([_w(signal="error_spiral", last_error="timeout after 1532 ms pid 4411")])
    r.observe([_w(signal="error_spiral", last_error="timeout after 2210 ms pid 5120")])
    assert len(r.sent) == 1


def test_notify_min_threshold():
    high = _w(signal="thrash", severity=Severity.HIGH)
    r = _Recorder()  # default: critical
    r.observe([high, _w(severity=Severity.MEDIUM, signal="stall")])
    assert r.sent == []
    r = _Recorder(notify_min="high")
    r.observe([high])
    assert len(r.sent) == 1


def test_escalation_to_threshold_alerts():
    r = _Recorder(notify_min="high")
    r.observe([_w(severity=Severity.MEDIUM)])
    r.observe([_w(severity=Severity.HIGH)])
    assert len(r.sent) == 1


def test_overall_critical_once_per_cooldown(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(alerts, "_monotonic", lambda: now[0])
    medium = [_w(severity=Severity.MEDIUM)]
    r = _Recorder()
    r.observe(medium, _report(critical=True))
    r.observe(medium, _report(critical=True))
    assert [t for t, _ in r.sent] == ["agentwatch: Claude Code · myproj — critical 20%"]

    r.observe(medium, _report())  # clears
    now[0] += 60
    r.observe(medium, _report(critical=True))  # recurs inside the cooldown
    assert len(r.sent) == 1
    now[0] += alerts.CRITICAL_COOLDOWN_S
    r.observe(medium, _report(critical=True))  # still critical, cooldown over
    assert len(r.sent) == 2
    now[0] += alerts.CRITICAL_COOLDOWN_S
    r.observe(medium, _report(critical=True))  # same episode: no repeat
    assert len(r.sent) == 2


def test_overall_critical_folded_into_finding_alert():
    r = _Recorder()
    r.observe([_w()], _report(critical=True))
    assert len(r.sent) == 1
    assert "loop" in r.sent[0][0]


def test_no_sinks_no_sends():
    a = Alerter()
    a._desktop = a._post = lambda *_: pytest.fail("sent without a sink")
    a.observe("s", "claude-code", "p", [_w()], _report(critical=True))


# --- text ----------------------------------------------------------------


def test_text_format_with_cost():
    r = _Recorder()
    r.observe([_w(cost=1.4)])
    title, body = r.sent[0]
    assert title == "agentwatch: Claude Code · myproj — loop ~$1.40"
    assert body == "Repeated action: Bash (8x)"


def test_unlabelled_signal_and_no_project():
    a = Alerter(notify=True)
    sent = []
    a._desktop = lambda t, b: sent.append(t)
    a.observe("s", None, "agent.jsonl", [_w(signal="privilege_escalation")], _report())
    assert sent == ["agentwatch: agent.jsonl — privilege_escalation"]


def test_message_redacted_and_collapsed():
    key = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    r = _Recorder()
    r.observe([_w(message=f"leaked\n  token {key}\tin output")])
    body = r.sent[0][1]
    assert key not in body
    assert "\n" not in body and "\t" not in body
    assert body.startswith("leaked token ")


def test_headless_log_line_every_new_warning():
    lines = []
    a = Alerter(log=lines.append)
    w = [_w(severity=Severity.LOW, signal="stall", message="idle"), _w()]
    a.observe("s", "claude-code", "myproj", w, _report())
    a.observe("s", "claude-code", "myproj", w, _report())
    assert len(lines) == 2
    assert "LOW      Claude Code · myproj [stall] idle" in lines[0]
    assert "CRITICAL" in lines[1] and "[loop]" in lines[1]


def test_print_line_writes_real_stdout(monkeypatch, capsys):
    monkeypatch.setattr(sys, "__stdout__", sys.stdout)
    alerts.print_line("hello")
    assert capsys.readouterr().out == "hello\n"


# --- webhook -------------------------------------------------------------


class _Hook(BaseHTTPRequestHandler):
    status = 200
    received: list = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).received.append((self.path, self.headers["Content-Type"], body))
        self.send_response(self.status)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    _Hook.received = []
    _Hook.status = 200
    srv = HTTPServer(("127.0.0.1", 0), _Hook)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}/services/T000/SECRETPATH"
    srv.shutdown()
    srv.server_close()


def test_webhook_payload(server):
    a = Alerter(webhook=server)
    a.observe("s", "claude-code", "myproj", [_w(cost=1.4)], _report())
    [(path, ctype, body)] = _Hook.received
    assert path == "/services/T000/SECRETPATH"
    assert ctype == "application/json"
    assert json.loads(body) == {
        "text": "agentwatch: Claude Code · myproj — loop ~$1.40\nRepeated action: Bash (8x)"
    }


def test_webhook_http_error_warns_once_masked(server):
    _Hook.status = 500
    warned = []
    a = Alerter(webhook=server)
    a.warn = warned.append
    a.observe("s", "a", "p", [_w(signal="one")], _report())
    a.observe("s", "a", "p", [_w(signal="one"), _w(signal="two")], _report())
    assert len(_Hook.received) == 2
    assert len(warned) == 1
    assert "SECRETPATH" not in warned[0] and "T000" not in warned[0]
    assert "http://127.0.0.1/***" in warned[0] and "500" in warned[0]


def test_webhook_unreachable_never_raises():
    warned = []
    url = "http://127.0.0.1:9/hooks/SECRET"  # discard port: refused
    a = Alerter(webhook=url)
    a.warn = warned.append
    a.observe("s", "a", "p", [_w()], _report())
    assert len(warned) == 1 and "SECRET" not in warned[0]


def test_post_webhook_timeout_is_bounded(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["timeout"] = timeout
        raise OSError("boom")

    monkeypatch.setattr(alerts.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(OSError):
        post_webhook("http://x/y", "t")
    assert seen["timeout"] == 5


def test_mask_url():
    assert mask_url("https://hooks.slack.com/services/A/B/C") == "https://hooks.slack.com/***"
    assert mask_url("https://user:pw@example.com:8443/x?k=1") == "https://example.com/***"


# --- notifier backends + escaping ----------------------------------------


def _which(found):
    return lambda name: f"/bin/{name}" if name in found else None


def test_backend_windows():
    argv, data = notify_command("T", "B", "win32", _which({"powershell"}))
    assert argv[:4] == ["/bin/powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand"]
    assert json.loads(data) == {"title": "T", "body": "B"}


def test_backend_macos():
    argv, data = notify_command("T", "B", "darwin", _which({"osascript"}))
    assert argv[0] == "/bin/osascript" and argv[-2:] == ["T", "B"] and data is None


def test_backend_linux():
    argv, data = notify_command("T", "B", "linux", _which({"notify-send"}))
    assert argv == ["/bin/notify-send", "--app-name=agentwatch", "--", "T", "B"]


@pytest.mark.parametrize("platform", ["win32", "darwin", "linux"])
def test_backend_missing(platform):
    assert notify_command("T", "B", platform, _which(set())) is None


def test_escaping_text_never_in_script():
    """The text is argv/stdin data only: no script or flag carries any of it."""
    win, data = notify_command(NASTY, NASTY, "win32", _which({"powershell"}))
    plain, _ = notify_command("x", "y", "win32", _which({"powershell"}))
    assert win == plain  # the encoded script is constant
    assert json.loads(data) == {"title": NASTY, "body": NASTY}
    assert data.isascii()

    mac, _ = notify_command(NASTY, NASTY, "darwin", _which({"osascript"}))
    assert mac[-2:] == [NASTY, NASTY]
    assert not any(NASTY in a for a in mac[:-2])

    lin, _ = notify_command(NASTY, NASTY, "linux", _which({"notify-send"}))
    assert lin[-2:] == [NASTY, NASTY] and lin[-3] == "--"


@pytest.mark.skipif(not shutil.which("powershell"), reason="needs Windows PowerShell")
def test_powershell_reads_text_verbatim():
    """Real PowerShell parses the stdin JSON back to the exact text."""
    script = alerts._PS_READ + (
        "[Console]::Out.Write([Convert]::ToBase64String("
        "[Text.Encoding]::UTF8.GetBytes($d.title + '|' + $d.body)))"
    )
    _, data = notify_command(NASTY, NASTY, "win32", _which({"powershell"}))
    out = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand",
         alerts.encode_ps(script)],
        input=data, capture_output=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert base64.b64decode(out.stdout).decode("utf-8") == f"{NASTY}|{NASTY}"


def test_desktop_runs_without_shell(monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, "notify_command", lambda t, b: (["n", t, b], None))

    def fake_run(argv, **kw):
        calls.append((argv, kw))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(alerts.subprocess, "run", fake_run)
    a = Alerter(notify=True)
    a.warn = lambda m: pytest.fail(m)
    a._desktop("T", NASTY)
    [(argv, kw)] = calls
    assert argv == ["n", "T", NASTY]
    assert "shell" not in kw and kw["timeout"] == alerts.NOTIFY_TIMEOUT_S


@pytest.mark.parametrize("outcome", ["rc1", "oserror", "timeout", "none"])
def test_desktop_failure_warns_once(monkeypatch, outcome):
    if outcome == "none":
        monkeypatch.setattr(alerts, "notify_command", lambda t, b: None)
    else:
        monkeypatch.setattr(alerts, "notify_command", lambda t, b: (["n"], b"{}"))

    def fake_run(argv, **kw):
        if outcome == "oserror":
            raise FileNotFoundError("n")
        if outcome == "timeout":
            raise subprocess.TimeoutExpired(argv, 1)
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(alerts.subprocess, "run", fake_run)
    warned = []
    a = Alerter(notify=True)
    a.warn = warned.append
    a._desktop("T", "B")
    a._desktop("T", "B")
    assert len(warned) == 1
    expected = "no desktop notifier" if outcome == "none" else "notification failed"
    assert expected in warned[0]


# --- CLI + headless engine -------------------------------------------------


def test_webhook_option_rejects_non_http_without_echo():
    res = CliRunner().invoke(cli, ["watch-all", "--webhook", "file:///etc/SECRETFILE"])
    assert res.exit_code == 2
    assert "SECRETFILE" not in res.output


def test_headless_starts_with_no_agents_and_reads_env_webhook(monkeypatch):
    seen = {}

    def fake_run(self, **kw):
        seen.update(kw, alerter=self.alerter, procs=self._process_mode)

    monkeypatch.setattr("agentwatch.cli.find_running_agents", lambda *a: [])
    monkeypatch.setattr("agentwatch.ui.multi_app.MultiAgentWatchApp.run", fake_run)
    monkeypatch.setenv("AGENTWATCH_WEBHOOK", "https://hooks.example.com/SECRET")
    res = CliRunner().invoke(cli, ["watch-all", "--headless", "--notify"])
    assert res.exit_code == 0, res.output
    assert seen["headless"] is True and seen["procs"] is True
    assert seen["alerter"].webhook == "https://hooks.example.com/SECRET"
    assert seen["alerter"].notify and seen["alerter"].log is alerts.print_line
    assert "SECRET" not in res.output


def test_watch_all_without_headless_still_needs_agents(monkeypatch):
    monkeypatch.setattr("agentwatch.cli.find_running_agents", lambda *a: [])
    res = CliRunner().invoke(cli, ["watch-all", "--notify"])
    assert res.exit_code == 1


def _fixture_log(path: Path) -> Path:
    """A Claude Code transcript: a failing loop, then `sudo` (CRITICAL)."""

    def ts(i):
        return f"2026-10-17T10:00:{i:02d}Z"

    entries = []
    for i, cmd in enumerate(["pytest tests/test_x.py"] * 8 + ["sudo chmod 777 /etc/passwd"]):
        entries.append({"type": "assistant", "sessionId": "s1", "timestamp": ts(i),
                        "message": {"role": "assistant", "content": [
                            {"type": "tool_use", "id": f"t{i}", "name": "Bash",
                             "input": {"command": cmd}}]}})
        entries.append({"type": "user", "sessionId": "s1", "timestamp": ts(i),
                        "message": {"role": "user", "content": [
                            {"type": "tool_result", "tool_use_id": f"t{i}",
                             "content": "AssertionError: boom", "is_error": True}]}})
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")
    return path


async def test_headless_engine_smoke(tmp_path):
    """The watch-all engine, run headless on a fixture, logs and alerts."""
    from agentwatch.ui.multi_app import MultiAgentWatchApp

    log = _fixture_log(tmp_path / "s1.jsonl")
    lines, sent = [], []
    alerter = Alerter(notify=True, log=lines.append)
    alerter._desktop = lambda t, b: sent.append(t)
    app = MultiAgentWatchApp(watch_paths=[log], security_mode=True, alerter=alerter)
    async with app.run_test(headless=True) as pilot:
        for _ in range(50):
            await pilot.pause(0.1)
            if sent:
                break
    assert any("[loop]" in line for line in lines)
    assert any("[privilege_escalation]" in line for line in lines)
    assert sent == ["agentwatch: s1.jsonl — privilege_escalation"]
