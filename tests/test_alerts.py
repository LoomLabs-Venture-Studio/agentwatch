"""Alerts: rate limiting, text, webhook, notifier backends, escaping, headless."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
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
    """Alerter whose sends are captured instead of dispatched. No startup
    baseline unless asked (notify_existing=False): most tests are about what
    happens after it."""

    def __init__(self, **kw):
        kw.setdefault("notify_existing", True)
        self.sent: list[tuple[str, str]] = []
        self.alerter = Alerter(notify=True, **kw)
        self.alerter._desktop = lambda title, body: self.sent.append((title, body))

    def observe(self, warnings, report=None, session="s1", actions=10):
        self.alerter.observe(session, "claude-code", "myproj", warnings, report or _report(),
                             actions=actions)


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


# --- startup baseline ----------------------------------------------------


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(alerts, "_monotonic", lambda: now[0])
    return now


def test_startup_existing_findings_send_nothing_then_new_one_sends(clock):
    r = _Recorder(notify_existing=False, notify_min="high")
    old = [_w(severity=Severity.CRITICAL), _w(signal="thrash", severity=Severity.HIGH)]
    r.observe(old, _report(critical=True), actions=400)
    clock[0] += alerts.BASELINE_S + 1
    r.observe(old, _report(critical=True), actions=400)
    assert r.sent == []
    r.observe([*old, _w(signal="error_spiral")], _report(critical=True), actions=401)
    assert [t for t, _ in r.sent] == ["agentwatch: Claude Code · myproj — errors"]


def test_session_discovered_later_is_baselined_too(clock):
    r = _Recorder(notify_existing=False)
    r.observe([], actions=5)
    clock[0] += 3600
    r.observe([_w()], session="late", actions=900)  # its log already has history
    assert r.sent == []


def test_baseline_waits_for_history_to_load(clock):
    """A pass before the log is read (no actions) does not start the clock, so a
    history load that blocks past BASELINE_S is still baselined."""
    r = _Recorder(notify_existing=False)
    r.observe([], actions=0)
    clock[0] += 30
    r.observe([_w()], _report(critical=True), actions=2000)
    clock[0] += 1
    r.observe([_w()], _report(critical=True), actions=2000)
    assert r.sent == []


def test_critical_at_startup_then_recurrence_alerts(clock):
    r = _Recorder(notify_existing=False)
    medium = [_w(severity=Severity.MEDIUM)]
    r.observe(medium, _report(critical=True), actions=50)
    clock[0] += alerts.BASELINE_S + 1
    r.observe(medium, _report(critical=True), actions=50)  # still the same episode
    assert r.sent == []
    r.observe(medium, _report(), actions=51)
    r.observe(medium, _report(critical=True), actions=52)
    assert [t for t, _ in r.sent] == ["agentwatch: Claude Code · myproj — critical 20%"]


def test_notify_existing_alerts_at_startup(clock):
    r = _Recorder(notify_existing=True)
    r.observe([_w()], actions=400)
    assert len(r.sent) == 1


def test_headless_log_not_baselined(clock):
    lines = []
    a = Alerter(log=lines.append, notify=True)
    a._desktop = lambda *_: pytest.fail("baseline sent")
    a.observe("s", "claude-code", "p", [_w()], _report(), actions=400)
    assert len(lines) == 1


# --- budget --------------------------------------------------------------


def _budget(**kw):
    r = _Recorder(budget=5.0, **kw)
    return r, lambda cost, session="s1", actions=10: r.alerter.observe(
        session, "claude-code", "myproj", [], _report(), actions=actions, cost=cost)


def test_budget_crossing_alerts_once():
    r, see = _budget()
    see(4.99)
    assert r.sent == []
    see(5.0)
    see(5.12)
    see(9.0)
    assert r.sent == [("agentwatch: Claude Code · myproj — budget $5.00 hit", "session cost $5.00")]


def test_budget_under_or_unknown_cost_never_alerts():
    r, see = _budget()
    for cost in (0.0, 1.0, 4.99, None, None):
        see(cost)
    assert r.sent == []


def test_budget_already_over_alerts_during_baseline(clock):
    lines = []
    r, see = _budget(notify_existing=False, log=lines.append)
    see(5.12, actions=400)
    assert [b for _, b in r.sent] == ["session cost $5.12"]
    assert len(lines) == 1 and "budget $5.00 hit: session cost $5.12" in lines[0]
    clock[0] += alerts.BASELINE_S + 1
    see(6.0, actions=401)
    assert len(r.sent) == 1


def test_failing_on_send_never_drops_the_delivery():
    r = _Recorder()
    warned = []
    r.alerter.warn = warned.append
    r.alerter.on_send = lambda title, body: 1 / 0
    r.observe([_w()])
    r.observe([_w(), _w("thrash")])
    assert len(r.sent) == 2  # both delivered
    assert warned == ["alert feed update failed: ZeroDivisionError"]  # warned once


def test_budget_once_per_session():
    r, see = _budget()
    see(6.0, session="a")
    see(7.0, session="b")
    see(8.0, session="a")
    assert len(r.sent) == 2


def test_budget_rise_dip_rise_alerts_once():
    r, see = _budget()
    for cost in (5.5, 4.0, 6.0):
        see(cost)
    assert len(r.sent) == 1


def test_budget_sub_cent_not_shown_as_zero():
    r = _Recorder(budget=0.005)
    r.alerter.observe("s1", "claude-code", "myproj", [], _report(), actions=10, cost=0.006)
    assert r.sent == [("agentwatch: Claude Code · myproj — budget $0.005 hit",
                       "session cost $0.006")]


@pytest.mark.parametrize("bad", ["0", "-1", "abc", "nan", "inf", "-inf"])
def test_budget_option_rejects_bad_values(bad):
    res = CliRunner().invoke(cli, ["watch-all", "--budget", bad])
    assert res.exit_code == 2, res.output


def test_budget_alone_enables_notify(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr("agentwatch.cli.find_running_agents", lambda *a: [])
    monkeypatch.setattr("agentwatch.ui.multi_app.MultiAgentWatchApp.run",
                        lambda self, **kw: seen.update(alerter=self.alerter))
    res = CliRunner().invoke(cli, ["watch-all", "--headless", "--budget", "5"])
    assert res.exit_code == 0, res.output
    assert seen["alerter"].notify and seen["alerter"].budget == 5.0
    log = tmp_path / "s.jsonl"
    log.write_text(_entries(["ls"]))
    seen.clear()
    res = CliRunner().invoke(cli, ["watch", "--log", str(log), "--budget", "2.5"])
    assert res.exit_code == 0, res.output
    assert seen["alerter"].notify and seen["alerter"].budget == 2.5
    seen.clear()
    res = CliRunner().invoke(cli, ["watch-all", "--headless", "--budget", "5",
                                   "--webhook", "https://example.com/hook"])
    assert res.exit_code == 0, res.output
    assert not seen["alerter"].notify and seen["alerter"].budget == 5.0


# --- text ----------------------------------------------------------------


def test_text_format_with_cost():
    r = _Recorder()
    r.observe([_w(cost=1.4)])
    title, body = r.sent[0]
    assert title == "agentwatch: Claude Code · myproj — loop ~$1.40"
    assert body == "Repeated action: Bash (8x)"


def test_unlabelled_signal_and_no_project():
    a = Alerter(notify=True, notify_existing=True)
    sent = []
    a._desktop = lambda t, b: sent.append(t)
    a.observe("s", None, "agent.jsonl", [_w(signal="made_up_signal")], _report())
    assert sent == ["agentwatch: agent.jsonl — made_up_signal"]


def test_security_signals_have_labels():
    r = _Recorder()
    r.observe([_w(signal="privilege_escalation"), _w(signal="dangerous_command")])
    assert [t.split(" — ")[1] for t, _ in r.sent] == ["privilege escalation",
                                                     "dangerous command"]


CONTROL = "\x1b[2J\x07\x1b]52;c;ZXZpbA==\x07\r\nCRITICAL forged\u202e\x9b\x00\t"


def _printable(text: str) -> bool:
    return all(c.isprintable() for c in text)


def test_control_chars_in_message_project_and_agent_are_cleaned():
    lines, sent = [], []
    a = Alerter(notify=True, notify_existing=True, log=lines.append)
    a._desktop = lambda t, b: sent.append((t, b))
    a.observe("s", f"claude{CONTROL}code", f"repo{CONTROL}" + "x" * 500,
              [_w(message=f"boom{CONTROL}end")], _report())
    [(title, body)] = sent
    [line] = lines
    for text in (title, body, line):
        assert _printable(text), repr(text)
        assert "\x1b" not in text and "\n" not in text
    assert body.startswith("boom [2J ]52;c;ZXZpbA== CRITICAL forged")
    project = title.split(" · ")[1].split(" — ")[0]
    assert len(project) <= alerts._NAME_MAX


def test_coach_note_text_is_cleaned_by_the_same_helper():
    from agentwatch import coach
    from agentwatch.detectors.security.secret_scanner import one_line

    assert coach._clean(f"a{CONTROL}b") == one_line(f"a{CONTROL}b", coach._MAX_LINE)
    assert _printable(coach._clean(f"a{CONTROL}b"))


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
    a = Alerter(webhook=server, notify_existing=True)
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
    a = Alerter(webhook=server, notify_existing=True)
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
    a = Alerter(webhook=url, notify_existing=True)
    a.warn = warned.append
    a.observe("s", "a", "p", [_w()], _report())
    assert len(warned) == 1 and "SECRET" not in warned[0]


def test_post_webhook_timeout_is_bounded(monkeypatch):
    seen = {}

    def fake_open(req, timeout):
        seen["timeout"] = timeout
        raise OSError("boom")

    monkeypatch.setattr(alerts._OPENER, "open", fake_open)
    with pytest.raises(OSError):
        post_webhook("http://x/y", "t")
    assert seen["timeout"] == 5


def test_webhook_text_is_slack_escaped(server):
    a = Alerter(webhook=server, notify=True, notify_existing=True)
    desktop = []
    a._desktop = lambda t, b: desktop.append(b)
    a.observe("s", "claude-code", "<!channel>", [_w(message="a & <http://evil|click> <!here>")],
              _report())
    text = json.loads(_Hook.received[0][2])["text"]
    assert "<" not in text and ">" not in text
    assert "&lt;!channel&gt;" in text
    assert "a &amp; &lt;http://evil|click&gt; &lt;!here&gt;" in text
    assert desktop == ["a & <http://evil|click> <!here>"]  # toast text is not Slack


class _Redirect(BaseHTTPRequestHandler):
    location = ""

    def do_POST(self):  # noqa: N802
        # Read the body first: closing with unread data is a TCP reset on
        # Windows, which the client can see instead of the 302.
        self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(302)
        self.send_header("Location", type(self).location)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.mark.parametrize("target", ["other-host", "ftp"])
def test_webhook_redirect_is_refused(server, target):
    _Redirect.location = (server.replace("SECRETPATH", "followed") if target == "other-host"
                          else "ftp://127.0.0.1/x")
    srv = HTTPServer(("127.0.0.1", 0), _Redirect)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        warned = []
        a = Alerter(webhook=f"http://127.0.0.1:{srv.server_port}/hook/SECRET",
                    notify_existing=True)
        a.warn = warned.append
        a.observe("s", "a", "p", [_w()], _report())
    finally:
        srv.shutdown()
        srv.server_close()
    assert _Hook.received == []  # never followed
    assert len(warned) == 1 and "302" in warned[0] and "SECRET" not in warned[0]


def test_post_webhook_rejects_non_http():
    with pytest.raises(ValueError):
        post_webhook("file:///etc/passwd", "t")


def test_queue_is_bounded_and_coalesced(monkeypatch):
    """One worker, one notifier at a time; alerts that pile up while it is busy
    become one summary."""
    monkeypatch.setattr(alerts, "Thread", threading.Thread)
    gate, delivered, running, peak = threading.Event(), [], [0], [0]

    def slow_desktop(title, body):
        running[0] += 1
        peak[0] = max(peak[0], running[0])
        gate.wait(5)
        delivered.append((title, body))
        running[0] -= 1

    a = Alerter(notify=True, notify_existing=True)
    a._desktop = slow_desktop
    a.observe("s", "claude-code", "p", [_w(signal="first")], _report())
    a.observe("s", "claude-code", "p",
              [_w(signal="first")] + [_w(signal=f"sig{i}") for i in range(12)], _report())
    assert threading.active_count() < 20
    gate.set()
    for _ in range(100):
        if len(delivered) == 2:
            break
        threading.Event().wait(0.05)
    assert peak[0] == 1
    assert [t for t, _ in delivered] == ["agentwatch: Claude Code · p — first",
                                         "agentwatch: 12 new alerts"]
    assert delivered[1][1].endswith("... and 9 more")


def _wait_for(cond, timeout=5.0):
    for _ in range(int(timeout / 0.05)):
        if cond():
            return True
        threading.Event().wait(0.05)
    return cond()


def test_sink_raising_does_not_kill_the_worker(monkeypatch):
    monkeypatch.setattr(alerts, "Thread", threading.Thread)
    delivered, warned, calls = [], [], [0]

    def flaky_desktop(title, body):
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("WinRT exploded")
        delivered.append(title)

    def bad_post(text):
        raise KeyError("http://hooks.example.com/SECRET")

    a = Alerter(notify=True, webhook="http://hooks.example.com/SECRET", notify_existing=True)
    a._desktop, a._post, a.warn = flaky_desktop, bad_post, warned.append
    a.observe("s", "claude-code", "p", [_w(signal="first")], _report())
    assert _wait_for(lambda: not a._busy)
    a.observe("s", "claude-code", "p", [_w(signal="first"), _w(signal="second")], _report())
    assert _wait_for(lambda: delivered)
    assert delivered == ["agentwatch: Claude Code · p — second"]
    assert sorted(warned) == ["notify delivery failed: RuntimeError",
                              "webhook delivery failed: KeyError"]  # once each, no URL


def test_worker_crash_resets_busy(monkeypatch):
    monkeypatch.setattr(alerts, "Thread", threading.Thread)
    monkeypatch.setattr(threading, "excepthook", lambda args: None)  # expected crash
    delivered = []
    a = Alerter(notify=True, notify_existing=True)
    a._desktop = lambda t, b: delivered.append(t)
    real = Alerter._coalesce
    a._coalesce = lambda batch: (_ for _ in ()).throw(MemoryError())
    a.observe("s", "claude-code", "p", [_w(signal="first")], _report())
    assert _wait_for(lambda: not a._busy)
    a._coalesce = real
    a.observe("s", "claude-code", "p", [_w(signal="first"), _w(signal="second")], _report())
    assert _wait_for(lambda: delivered)  # the crashed batch is lost, later ones are not
    assert delivered == ["agentwatch: Claude Code · p — second"]


def test_small_batch_not_coalesced():
    batch = [("t1", "b"), ("t2", "b"), ("t3", "b")]
    assert Alerter._coalesce(batch) == batch


def test_mask_url():
    assert mask_url("http://[::1/x") == "<invalid url>"
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


def test_webhook_option_rejects_malformed_url_without_traceback():
    res = CliRunner().invoke(cli, ["watch-all", "--webhook", "http://[::1/SECRETX"])
    assert res.exit_code == 2
    assert "SECRETX" not in res.output and "Traceback" not in res.output
    assert not isinstance(res.exception, ValueError)


def test_plain_http_webhook_warns(monkeypatch):
    monkeypatch.setattr("agentwatch.cli.find_running_agents", lambda *a: [])
    monkeypatch.setattr("agentwatch.ui.multi_app.MultiAgentWatchApp.run", lambda self, **kw: None)
    res = CliRunner().invoke(cli, ["watch-all", "--headless", "--webhook",
                                   "http://hooks.example.com/SECRET"])
    assert res.exit_code == 0, res.output
    assert "plain http" in res.output and "SECRET" not in res.output


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
    assert seen["alerter"].notify_existing is False
    assert seen["alerter"].webhook == "https://hooks.example.com/SECRET"
    assert seen["alerter"].notify and seen["alerter"].log is alerts.print_line
    assert "SECRET" not in res.output
    res = CliRunner().invoke(cli, ["watch-all", "--headless", "--notify", "--notify-existing"])
    assert res.exit_code == 0, res.output
    assert seen["alerter"].notify_existing is True


def test_webhook_flag_overrides_env(monkeypatch):
    seen = {}
    monkeypatch.setattr("agentwatch.cli.find_running_agents", lambda *a: [])
    monkeypatch.setattr("agentwatch.ui.multi_app.MultiAgentWatchApp.run",
                        lambda self, **kw: seen.update(alerter=self.alerter))
    monkeypatch.setenv("AGENTWATCH_WEBHOOK", "https://env.example.com/ENVSECRET")
    res = CliRunner().invoke(cli, ["watch-all", "--headless", "--webhook",
                                   "https://flag.example.com/FLAGSECRET"])
    assert res.exit_code == 0, res.output
    assert seen["alerter"].webhook == "https://flag.example.com/FLAGSECRET"
    assert "ENVSECRET" not in res.output and "FLAGSECRET" not in res.output


def test_watch_all_without_headless_still_needs_agents(monkeypatch):
    monkeypatch.setattr("agentwatch.cli.find_running_agents", lambda *a: [])
    res = CliRunner().invoke(cli, ["watch-all", "--notify"])
    assert res.exit_code == 1


def _entries(commands: list[str], start: int = 0) -> str:
    """Claude Code transcript lines: each command a failing Bash call."""

    def ts(i):
        return f"2026-10-17T10:00:{i:02d}Z"

    entries = []
    for i, cmd in enumerate(commands, start):
        entries.append({"type": "assistant", "sessionId": "s1", "timestamp": ts(i),
                        "message": {"role": "assistant", "content": [
                            {"type": "tool_use", "id": f"t{i}", "name": "Bash",
                             "input": {"command": cmd}}]}})
        entries.append({"type": "user", "sessionId": "s1", "timestamp": ts(i),
                        "message": {"role": "user", "content": [
                            {"type": "tool_result", "tool_use_id": f"t{i}",
                             "content": "AssertionError: boom", "is_error": True}]}})
    return "".join(json.dumps(e) + "\n" for e in entries)


async def test_headless_engine_smoke(tmp_path, monkeypatch):
    """The watch-all engine, run headless on a fixture: the log's history (a
    HIGH loop) is logged but baselined; `sudo` appended later alerts once."""
    from agentwatch.ui.multi_app import MultiAgentWatchApp

    monkeypatch.setattr(alerts, "BASELINE_S", 1.0)
    log = tmp_path / "s1.jsonl"
    log.write_text(_entries(["pytest tests/test_x.py"] * 8), encoding="utf-8")
    lines, sent = [], []
    alerter = Alerter(notify=True, notify_min="high", log=lines.append)
    alerter._desktop = lambda t, b: sent.append(t)
    app = MultiAgentWatchApp(watch_paths=[log], security_mode=True, alerter=alerter)
    async with app.run_test(headless=True) as pilot:
        for _ in range(50):
            await pilot.pause(0.1)
            if any("[loop]" in line for line in lines):
                break
        await pilot.pause(1.5)  # past the baseline
        assert sent == []
        with log.open("a", encoding="utf-8") as f:
            f.write(_entries(["sudo chmod 777 /etc/passwd"], start=8))
        for _ in range(80):
            await pilot.pause(0.1)
            if sent:
                break
    assert any("[loop]" in line for line in lines)
    assert any("[privilege_escalation]" in line for line in lines)
    assert sent == ["agentwatch: s1.jsonl — privilege escalation"]
