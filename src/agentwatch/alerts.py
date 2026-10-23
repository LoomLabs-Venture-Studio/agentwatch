"""Alerts for unattended sessions: `--notify`, `--webhook`, `--headless` lines.

The watch apps call `Alerter.observe()` with each session's warnings and
health report after every scoring pass. It decides what is new and fans out:

- headless log: one stdout line per new warning (any severity);
- desktop notification (`--notify`) and webhook (`--webhook`): one alert per
  (session, `warning_dedup_key`) at or above `--notify-min`, plus one when the
  session's overall status turns Critical (at most once per session per
  `CRITICAL_COOLDOWN_S`). A warning that clears is forgotten, so a recurrence
  alerts again.

Alerts start from a baseline: what a session already shows when it is first
seen (its log's history) is recorded as alerted without sending, so opening
`watch-all` over old sessions is not a burst. The baseline lasts `BASELINE_S`
from the session's first pass with actions, not just one pass, because
history loads asynchronously (a pass can run before the log is read, or
between a watcher's chunks). `notify_existing` turns it off. The headless log
is not baselined: it prints the current warnings at start.

Text is agent + project, a short label, the cost if known, and the warning's
own message after secret redaction; never other transcript content. Text
reaches subprocesses as argv or stdin, never through a shell string. Sends
run on daemon threads; a failing sink warns once and never raises.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock, Thread
from time import monotonic as _monotonic
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from agentwatch.detectors.base import Severity, findings_spend, warning_dedup_key
from agentwatch.detectors.security.secret_scanner import one_line
from agentwatch.statusline import _LABELS, _cost
from agentwatch.themes import ascii_safe, get_theme

if TYPE_CHECKING:
    from collections.abc import Callable

    from agentwatch.detectors.base import Warning
    from agentwatch.health.score import HealthReport

CRITICAL_COOLDOWN_S = 600
BASELINE_S = 5.0
WEBHOOK_TIMEOUT_S = 5
NOTIFY_TIMEOUT_S = 30
_MESSAGE_MAX = 200
_NAME_MAX = 60
COALESCE_AT = 3  # more alerts than this waiting -> one summary alert
# Short labels: statusline's (health) plus the security signals. Kept out of
# statusline._LABELS, whose keys decide which signals the status line shows.
_ALERT_LABELS = {
    **_LABELS,
    "privilege_escalation": "privilege escalation", "dangerous_command": "dangerous command",
    "mass_delete": "mass delete", "mass_overwrite": "mass overwrite",
    "credential_access": "credential access", "credential_exfil": "credential exfil",
    "secret_leak": "secret leak", "secret_in_command": "secret leak",
    "secret_in_output": "secret leak", "sensitive_directory": "sensitive dir",
    "prompt_injection": "injection", "indirect_injection": "injection",
    "hidden_instruction": "injection",
    "c2_beacon": "beacon", "repeated_beacon": "beacon", "dns_exfil": "exfil",
    "exfil_pattern": "exfil", "data_upload": "upload", "large_outgoing": "upload",
    "suspicious_host": "suspicious host", "suspicious_port": "suspicious port",
    "undeclared_egress": "undeclared egress",
    "malicious_skill": "malicious skill", "skill_credential_access": "skill credentials",
    "skill_network": "skill network", "skill_install": "skill install",
    "skill_chain": "skill chain", "new_skill": "new skill",
}
_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
NOTIFY_LEVELS = {"high": Severity.HIGH, "critical": Severity.CRITICAL}

# PowerShell's own registered AppUserModelID: an unregistered id makes Show()
# succeed silently with no toast on Windows 10, and registering one needs a
# Start-menu shortcut or a registry write.
WINDOWS_APP_ID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
# Fixed script; the text arrives as JSON on stdin and becomes XML text nodes,
# so nothing in it is ever parsed as PowerShell or XML.
_PS_READ = "$ErrorActionPreference = 'Stop'\n$d = [Console]::In.ReadToEnd() | ConvertFrom-Json\n"
_PS_TOAST = (
    "$m = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications,"
    " ContentType = WindowsRuntime]\n"
    "$x = $m::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)\n"
    "$t = $x.GetElementsByTagName('text')\n"
    "[void]$t.Item(0).AppendChild($x.CreateTextNode($d.title))\n"
    "[void]$t.Item(1).AppendChild($x.CreateTextNode($d.body))\n"
    "$n = New-Object Windows.UI.Notifications.ToastNotification $x\n"
    f"$m::CreateToastNotifier('{WINDOWS_APP_ID}').Show($n)\n"
)


def encode_ps(script: str) -> str:
    """`-EncodedCommand` form: base64 of UTF-16LE, no command-line quoting."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def notify_command(
    title: str, body: str, platform: str | None = None, which=shutil.which
) -> tuple[list[str], bytes | None] | None:
    """(argv, stdin) for this platform's notifier, or None when there is none."""
    platform = platform or sys.platform
    if platform == "win32":
        exe = which("powershell")
        if not exe:
            return None
        argv = [exe, "-NoProfile", "-NonInteractive", "-EncodedCommand",
                encode_ps(_PS_READ + _PS_TOAST)]
        # ensure_ascii: non-ASCII travels as \u escapes, whatever stdin's code page.
        return argv, json.dumps({"title": title, "body": body}, ensure_ascii=True).encode()
    if platform == "darwin":
        exe = which("osascript")
        if not exe:
            return None
        # Text as run-handler arguments: never spliced into AppleScript source.
        return [exe, "-e", "on run argv",
                "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
                "-e", "end run", title, body], None
    exe = which("notify-send")
    if not exe:
        return None
    return [exe, "--app-name=agentwatch", "--", title, body], None


def mask_url(url: str) -> str:
    """'https://hooks.slack.com/***': a webhook URL's path is its secret."""
    try:
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.hostname or '?'}/***"
    except ValueError:
        return "<invalid url>"


def slack_escape(text: str) -> str:
    """Slack's three control characters, so `<!channel>` or `<http://x|y>` in a
    path or repo name is shown, not acted on."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx is a failure: the POST never follows to another host or scheme."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def post_webhook(url: str, text: str, timeout: float = WEBHOOK_TIMEOUT_S) -> None:
    """POST {"text": text} (Slack-compatible); raises on any failure, a 3xx
    included."""
    if urlsplit(url).scheme not in ("http", "https"):
        raise ValueError("webhook URL must be http(s)")
    req = urllib.request.Request(
        url,
        data=json.dumps({"text": text}).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "agentwatch"},
        method="POST",
    )
    with _OPENER.open(req, timeout=timeout) as resp:
        resp.read()


def print_line(line: str) -> None:
    """Headless log sink: the real stdout (Textual redirects sys.stdout), flushed
    so a redirected background run's log file is current."""
    out = sys.__stdout__
    if out is not None:
        out.write(line + "\n")
        out.flush()


def tui_warn(app) -> Callable[[str], None]:
    """Warn sink for a running Textual app, whose TUI hides stderr. Called from
    a send thread, so it hops to the app's thread."""

    def warn(msg: str) -> None:
        try:
            app.call_from_thread(app.notify, msg, title="Alerts", severity="warning")
        except RuntimeError:
            pass  # app not running

    return warn


def _warn_stderr(msg: str) -> None:
    print(f"agentwatch: {msg}", file=sys.stderr, flush=True)


def _clean(message: str) -> str:
    return one_line(message, _MESSAGE_MAX)


def _label(signal: str) -> str:
    return _ALERT_LABELS.get(signal) or one_line(signal, _NAME_MAX)


def who(agent: str | None, project: str | None) -> str:
    """'Claude Code · myproj'. Both come from logs and process data, so they
    are cleaned like a message."""
    name = one_line(agent.replace("-", " ").title(), _NAME_MAX) if agent else ""
    project = one_line(project, _NAME_MAX) if project else ""
    return f" {ascii_safe('·', '|')} ".join(p for p in (name, project) if p) or "agent"


@dataclass
class _Session:
    logged: set[str] = field(default_factory=set)
    alerted: set[str] = field(default_factory=set)
    critical: bool = False  # this Critical episode already alerted (or baselined)
    last_critical: float = float("-inf")
    baseline_until: float | None = None  # set at the first pass with actions


class Alerter:
    def __init__(
        self,
        *,
        notify: bool = False,
        notify_min: str = "critical",
        webhook: str | None = None,
        log: Callable[[str], None] | None = None,
        notify_existing: bool = False,
    ) -> None:
        self.notify = notify
        self.notify_existing = notify_existing
        self.min_severity = NOTIFY_LEVELS[notify_min]
        self.webhook = webhook
        self.log = log
        self.warn: Callable[[str], None] = _warn_stderr
        self._warned: set[str] = set()
        self._sessions: dict[str, _Session] = {}
        self._pending: list[tuple[str, str]] = []
        self._lock = Lock()
        self._busy = False

    def observe(
        self,
        session: str,
        agent: str | None,
        project: str | None,
        warnings: list[Warning],
        report: HealthReport,
        actions: int = 0,
    ) -> None:
        """Feed one scoring pass for *session* (*actions*: its buffer's action
        count, which starts the baseline clock); emit whatever is new."""
        s = self._sessions.setdefault(session, _Session())
        name = who(agent, project)
        by_key = {warning_dedup_key(w): w for w in warnings}

        if self.log is not None:
            for key, w in by_key.items():
                if key not in s.logged:
                    self.log(self._log_line(name, w))
            s.logged = set(by_key)

        if not (self.notify or self.webhook):
            return
        floor = _RANK[self.min_severity]
        hot = {k: w for k, w in by_key.items() if _RANK[w.severity] >= floor}
        critical = report.status == get_theme().level_3
        now = _monotonic()
        if actions and s.baseline_until is None:
            s.baseline_until = now + BASELINE_S
        if not self.notify_existing and (s.baseline_until is None or now < s.baseline_until):
            s.alerted = set(hot)  # already there: not news
            s.critical = critical  # last_critical untouched: a recurrence alerts
            return
        sent = False
        for key, w in hot.items():
            if key not in s.alerted:
                self._send(f"{_label(w.signal)}{_cost(w.cost_usd)}", name, w.message)
                sent = True
        s.alerted = set(hot)

        if not critical:
            s.critical = False
            return
        if s.critical or now - s.last_critical < CRITICAL_COOLDOWN_S:
            return
        if not sent:  # a finding alert this pass already said it
            worst = max(warnings, key=lambda w: _RANK[w.severity], default=None)
            cost = _cost(findings_spend(warnings)[2])
            self._send(f"critical {report.overall_score}%{cost}", name,
                       worst.message if worst else "")
        s.critical = True
        s.last_critical = now

    @staticmethod
    def _log_line(name: str, w: Warning) -> str:
        cost = f"  {w.cost_label}" if w.cost_label else ""
        return (f"{datetime.now():%H:%M:%S} {w.severity.value.upper():8} {name} "
                f"[{one_line(w.signal, _NAME_MAX)}] {_clean(w.message)}{cost}")

    def _send(self, label: str, name: str, message: str) -> None:
        """Queue one alert for the single delivery worker."""
        item = (f"agentwatch: {name} {ascii_safe('—', '-')} {label}", _clean(message))
        with self._lock:
            self._pending.append(item)
            if self._busy:
                return
            self._busy = True
        Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        """Deliver queued alerts one at a time (one notifier process at most),
        until the queue is empty. A sink that raises is warned about once and
        skipped; the worker never dies holding _busy."""
        try:
            while True:
                with self._lock:
                    batch, self._pending = self._pending, []
                    if not batch:
                        self._busy = False  # same lock as the check: no lost wakeup
                        return
                for title, body in self._coalesce(batch):
                    # ponytail: one worker for both sinks; a slow webhook (5 s)
                    # delays the next toast. Split per sink if that matters.
                    if self.notify:
                        self._safely("notify", self._desktop, title, body)
                    if self.webhook:
                        self._safely("webhook", self._post,
                                     f"{title}\n{body}" if body else title)
        except BaseException:
            with self._lock:
                self._busy = False  # unexpected exit: the next _send starts a worker
            raise

    def _safely(self, kind: str, deliver, *args) -> None:
        try:
            deliver(*args)
        except Exception as exc:
            # Type only: a webhook error's text can hold the URL.
            self._warn_once(kind, f"{kind} delivery failed: {type(exc).__name__}")

    @staticmethod
    def _coalesce(batch: list[tuple[str, str]]) -> list[tuple[str, str]]:
        if len(batch) <= COALESCE_AT:
            return batch
        heads = [title.removeprefix("agentwatch: ") for title, _ in batch]
        more = len(heads) - COALESCE_AT
        body = "\n".join(heads[:COALESCE_AT]) + f"\n... and {more} more"
        return [(f"agentwatch: {len(batch)} new alerts", body)]

    def _warn_once(self, kind: str, msg: str) -> None:
        if kind in self._warned:
            return
        self._warned.add(kind)
        try:
            self.warn(msg)
        except Exception:
            pass

    def _desktop(self, title: str, body: str) -> None:
        cmd = notify_command(title, body)
        ok = False
        if cmd is not None:
            argv, data = cmd
            io = {"input": data} if data is not None else {"stdin": subprocess.DEVNULL}
            try:
                ok = subprocess.run(
                    argv, capture_output=True, timeout=NOTIFY_TIMEOUT_S,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), **io,
                ).returncode == 0
            except (OSError, subprocess.SubprocessError):
                ok = False
        if ok:
            return
        if sys.platform == "win32":
            try:
                import winsound

                winsound.MessageBeep()
            except Exception:
                pass
        what = "notification failed" if cmd else "no desktop notifier found"
        self._warn_once("notify", f"{what}; --notify alerts are not shown")

    def _post(self, text: str) -> None:
        try:
            post_webhook(self.webhook, slack_escape(text))
        except Exception as exc:
            masked = mask_url(self.webhook)
            detail = str(exc).replace(self.webhook, masked)
            path = urlsplit(self.webhook).path
            if len(path) > 1:
                detail = detail.replace(path, "/***")
            self._warn_once("webhook", f"webhook {masked} failed: {type(exc).__name__}: {detail}")
