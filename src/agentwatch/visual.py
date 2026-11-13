"""`agentwatch visual`: the reporting commands in a local browser page.

stdlib only: a ThreadingHTTPServer on 127.0.0.1 serves one inline page and
GET /api/<name> JSON, each built by the same function as the command's
--json. Every request needs the random token and a loopback Host header
(DNS rebinding); every string sent is redacted. Read only: audit and
history sync run only when asked (?run=1).
"""

from __future__ import annotations

import hmac
import json
import re
import secrets
import sqlite3
import threading
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from agentwatch import cli
from agentwatch.agent_status import build as agents_build
from agentwatch.agents import DISPLAY_NAMES
from agentwatch.cc_stats import compute_stats, find_all_project_dirs, project_dir_to_name
from agentwatch.detectors.security.secret_scanner import assess_impact, redact_truncate
from agentwatch.history import connect, sync
from agentwatch.parser.logs import LogUnreadableError, UnsupportedLogFormatError
from agentwatch.report import build
from agentwatch.subagents import build as subagents_build
from agentwatch.subagents import session_of
from agentwatch.themes import SECURITY_TIER_EXIT_CODES, THEMES

_STR_LIMIT = 2000
# audit and history sync each read every log: one at a time, a second request
# waits (the sync after it is then cheap).
# ponytail: one global lock, per-endpoint locks if audit and sync must overlap
_RUN_LOCK = threading.Lock()
_TOKEN_RE = re.compile(r"([?&]t=)[^&\s]*")


class _NoDataError(Exception):
    """Nothing to report (no logs, no actions); shown to the user as is."""


def _scan(mode: str):
    log, note = cli._default_log()
    if log is None:
        raise _NoDataError("No log files found")
    buffer = cli.ActionBuffer()
    warnings = cli.create_registry(mode=mode).scan(cli.parse_file(log), buffer)
    if len(buffer) == 0:
        raise _NoDataError("No actions found in log file")
    return warnings, buffer, note, log


def _with_project(data: dict, note: str | None, log) -> dict:
    """Page-only field: the fallback session's project as a folder name ("~"
    for home), so the page never shows the note's encoded dir or cwd."""
    data["session_project"] = project_dir_to_name(log.parent, log) if note else None
    return data


def _ps(run: bool):
    return cli._ps_json(cli.find_running_agents())


def _check(run: bool):
    warnings, buffer, note, log = _scan("health")
    report = cli.calculate_health(warnings, include_security=False)
    efficiency = cli.calculate_efficiency(warnings, buffer)
    return _with_project(cli._check_json(report, efficiency, warnings, buffer, note), note, log)


def _agents(run: bool):
    return agents_build(cli.find_running_agents())


def _subagents(run: bool):
    log, _ = cli._default_log()
    if log is None:
        raise _NoDataError("No log files found")
    return subagents_build(session_of(log))


def _security(run: bool):
    warnings, buffer, note, log = _scan("security")
    return _with_project(cli._security_json(warnings, buffer, note), note, log)


def _audit(run: bool):
    if not run:
        return {"not_run": True}
    with _RUN_LOCK:
        findings, scanned, names = cli._audit_scan(find_all_project_dirs(), None, {})
    if scanned == 0:
        raise _NoDataError("No Claude Code session logs found.")
    assess_impact(findings)
    return cli._audit_json(findings, scanned, names)


def _stats(run: bool):
    report = compute_stats(all_projects=True)
    if report.message_count == 0:
        raise _NoDataError("No Claude Code session logs found.")
    return report.to_dict()


def _report(run: bool):
    with closing(connect()) as conn:
        return build(conn)


def _history(run: bool):
    with closing(connect()) as conn:
        synced = None
        if run:
            with _RUN_LOCK:
                synced = sync(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT agent, session_id, project, started, ended, actions, tokens,"
            " cost_usd, waste_usd, health_score, status"
            " FROM sessions ORDER BY ended DESC LIMIT 200"
        ).fetchall()
    return {"synced": synced, "sessions": [dict(r) for r in rows]}


API = {
    "ps": _ps,
    "agents": _agents,
    "check": _check,
    "subagents": _subagents,
    "security-scan": _security,
    "audit": _audit,
    "stats": _stats,
    "report": _report,
    "history": _history,
}


def redact(value: Any) -> Any:
    """Every string (keys too) in *value* through redact_truncate; any other
    non-JSON value (Path, datetime, ...) becomes its str(), redacted."""
    if isinstance(value, str):
        return redact_truncate(value, _STR_LIMIT)
    if isinstance(value, dict):
        return {redact(k): redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact(str(value))


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def __getattr__(self, name: str):
        # Every method but GET (POST, PUT, HEAD, ...) -> 405.
        if name.startswith("do_"):
            return self._not_allowed
        raise AttributeError(name)

    def _not_allowed(self) -> None:
        self._send(405, b"method not allowed\n", "text/plain", Allow="GET")

    def _send(self, code: int, body: bytes, ctype: str, **headers: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (http.server naming)
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        port = self.server.server_address[1]
        host_ok = self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}")
        token = query.get("t", [""])[0]
        if not (host_ok and hmac.compare_digest(token.encode(), self.server.token.encode())):
            self._send(403, b"forbidden\n", "text/plain")
            return
        if url.path == "/":
            self._send(200, PAGE.encode(), "text/html")
            return
        fn = API.get(url.path.removeprefix("/api/")) if url.path.startswith("/api/") else None
        if fn is None:
            self._send(404, b"not found\n", "text/plain")
            return
        code = 200
        try:
            data = fn(query.get("run") == ["1"])
        except (_NoDataError, UnsupportedLogFormatError, LogUnreadableError, OSError,
                RuntimeError, sqlite3.Error) as e:
            data = {"error": str(e)}
        except Exception as e:  # never leak a traceback to the page
            code, data = 500, {"error": f"internal error ({type(e).__name__})"}
        body = json.dumps(redact(data)).encode()
        self._send(code, body, "application/json")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # The request line carries the token (maybe percent-encoded): mask the
        # whole t= value.
        super().log_message("%s", _TOKEN_RE.sub(r"\1[token]", format % args))


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    token: str


def make_server(port: int = 0) -> _Server:
    """Bind 127.0.0.1:<port> (0 = a free port) with a fresh token."""
    server = _Server(("127.0.0.1", port), _Handler)
    server.token = secrets.token_urlsafe(24)
    return server


def serve(port: int = 0, open_browser: bool = True) -> None:
    import webbrowser

    import click

    server = make_server(port)
    url = f"http://127.0.0.1:{server.server_address[1]}/?t={server.token}"
    click.echo(f"agentwatch visual: {url}")
    click.echo("Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        click.echo("Stopped.")
    finally:
        server.server_close()


CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
       "style-src 'self' 'unsafe-inline'; img-src 'none'; frame-ancestors 'none'")

TONES = ("good", "warn", "bad", "bad")  # theme level_0..level_3 (exit 0 / 0 / 1 / 1)
_RANK = {"good": 0, "neutral": 1, "warn": 2, "bad": 3}


def status_tones() -> dict[str, dict[str, str]]:
    """The tone (good / warn / bad / neutral) of every status word the page
    shows: each theme's health levels, the security tiers (by exit code) and
    finding severities. A word two themes use at different levels gets the
    worse tone; the page prefers a score over a word when it has one."""
    health: dict[str, str] = {}
    for theme in THEMES.values():
        for word, tone in zip(theme.labels, TONES):
            if _RANK[tone] > _RANK.get(health.get(word, ""), -1):
                health[word] = tone
    security = {tier: ("good", "warn", "bad")[code]
                for tier, code in SECURITY_TIER_EXIT_CODES.items()}
    severity = {"critical": "bad", "high": "bad", "medium": "warn", "low": "neutral",
                "info": "neutral"}
    return {"health": health, "security": security, "severity": severity}


# Static data for the page (no request data): agent names and status tones.
def script_json(value: Any) -> str:
    """JSON safe to put inside a <script> element: "<" is escaped, so no value
    can close the element ("</script>") or open a comment ("<!--")."""
    return json.dumps(value, sort_keys=True).replace("<", "\\u003c")


_PAGE_DATA = script_json({"names": DISPLAY_NAMES, "tones": status_tones()})

_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>agentwatch</title>
<style>
/* Design system (ui-ux-pro-max, Sprint 47; recommendations, adapted):
   Style   Data-Dense Dashboard: KPI row, card grid, compact panels; no glass
           blur (the tool's first pick) so dense text stays crisp.
   Palette "Dark tech + status green" (Smart Home/IoT Dashboard row):
           bg #0F172A, card #1B2336, muted #272F42, muted-fg #94A3B8,
           border #475569, fg #F8FAFC. Green is kept for "good" only; the
           interactive accent is agentwatch's petrol/cyan. Light theme pairs.
   Status  good / warn / bad / neutral tokens, always with an icon and a word.
   Type    system-ui (Fira pairing not used: no web fonts), ui-monospace for
           code; scale 12 / 13 / 14 / 16 / 20 / 28 / 32 px; tabular numbers.
   Space   4 / 8 / 12 / 16 / 24 / 32 px (density 8/10), radius 8 / 12 px.
   Charts  sparkline = line + 16% area fill, only with >= 2 distinct samples,
           padded y-range, low-high label; bars for comparisons. */
:root{color-scheme:dark;
--bg:#0f172a;--surface:#1b2336;--raised:#222b40;--muted:#272f42;--line:#2c3750;
--line-strong:#475569;--ink:#f8fafc;--ink-2:#cbd5e1;--mute:#94a3b8;
--acc:#67c3d9;--acc-ink:#0f172a;--acc-soft:rgb(103 195 217/14%);
--good:#4ade80;--warn:#fbbf24;--bad:#f87171;--neutral:#94a3b8;
--shadow:0 1px 2px rgb(0 0 0/30%);
--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
@media (prefers-color-scheme:light){:root:not([data-theme=dark]){color-scheme:light;
--bg:#f1f5f9;--surface:#fff;--raised:#f8fafc;--muted:#e2e8f0;--line:#e2e8f0;
--line-strong:#cbd5e1;--ink:#0f172a;--ink-2:#334155;--mute:#475569;
--acc:#0e5f76;--acc-ink:#fff;--acc-soft:#e3f0f4;
--good:#166534;--warn:#92400e;--bad:#b91c1c;--neutral:#475569;
--shadow:0 1px 2px rgb(15 23 42/6%)}}
:root[data-theme=light]{color-scheme:light;
--bg:#f1f5f9;--surface:#fff;--raised:#f8fafc;--muted:#e2e8f0;--line:#e2e8f0;
--line-strong:#cbd5e1;--ink:#0f172a;--ink-2:#334155;--mute:#475569;
--acc:#0e5f76;--acc-ink:#fff;--acc-soft:#e3f0f4;
--good:#166534;--warn:#92400e;--bad:#b91c1c;--neutral:#475569;
--shadow:0 1px 2px rgb(15 23 42/6%)}
*{box-sizing:border-box}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%;scrollbar-color:var(--line-strong) var(--bg)}
body{margin:0;background:var(--bg);color:var(--ink);font:400 1rem/1.5 var(--sans);
font-variant-numeric:tabular-nums}
::selection{background:var(--acc-soft);color:var(--ink)}
:focus-visible{outline:3px solid var(--acc);outline-offset:2px;border-radius:6px}
button{font:inherit;color:inherit;cursor:pointer;touch-action:manipulation}
p{margin:0;text-wrap:pretty;overflow-wrap:anywhere}
h1,h2,h3{text-wrap:balance;margin:0}
.wrap{max-width:84rem;margin:auto;padding-inline:24px}
.mute{color:var(--mute)}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);
white-space:nowrap}
.ic{width:1em;height:1em;flex:none;fill:none;stroke:currentColor;stroke-width:2.2;
stroke-linecap:round;stroke-linejoin:round}
/* Header: brand, tabs, live indicator, theme. */
header{position:sticky;top:0;z-index:5;background:var(--surface);
border-bottom:1px solid var(--line)}
.bar{display:flex;flex-wrap:wrap;align-items:center;gap:0 16px;min-height:60px}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:1.0625rem;
letter-spacing:-.01em}
.logo{display:grid;place-items:center;width:32px;height:32px;border-radius:8px;
background:var(--acc-soft);color:var(--acc)}
.logo .ic{width:20px;height:20px}
[role=tablist]{display:flex;gap:4px;order:5;width:100%;overflow-x:auto;
margin:0 -4px;padding:0 4px 8px;scrollbar-width:none}
[role=tab]{background:none;border:0;border-radius:8px;padding:0 14px;min-height:44px;
color:var(--mute);font-weight:600;font-size:.9375rem;white-space:nowrap}
[role=tab]:hover{color:var(--ink);background:var(--muted)}
[role=tab]:focus-visible{outline-offset:-3px}
[role=tablist].more,[role=tablist].less{--fade:linear-gradient(90deg,transparent,#000 var(--l,0px),
#000 calc(100% - var(--r,0px)),transparent);-webkit-mask-image:var(--fade);mask-image:var(--fade)}
[role=tablist].more{--r:48px}[role=tablist].less{--l:48px}
[role=tab][aria-selected=true]{color:var(--ink);background:var(--acc-soft);
box-shadow:inset 0 -2px 0 var(--acc)}
.tools{display:flex;align-items:center;gap:8px;margin-left:auto}
.live{display:flex;align-items:center;gap:8px;font-size:.8125rem;color:var(--mute);
min-height:44px;min-width:0}
.live .txt{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.live .dot{width:8px;height:8px;border-radius:50%;background:var(--neutral);flex:none}
.live.on .dot{background:var(--good)}
.live.warn .dot{background:var(--warn)}.live.warn{color:var(--warn)}
.live.off .dot{background:var(--bad)}.live.off{color:var(--bad)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:44px;
min-width:44px;padding:0 14px;border:1px solid var(--line-strong);border-radius:8px;
background:var(--surface);color:var(--ink);font-weight:600;font-size:.875rem;
line-height:1.2}
.btn:hover{background:var(--muted)}
.btn.primary{background:var(--acc);border-color:var(--acc);color:var(--acc-ink)}
.btn.primary:hover{filter:brightness(1.1)}
.btn:disabled{opacity:.55;cursor:progress}
.btn .ic{width:16px;height:16px}
@media (min-width:56em){
  [role=tablist]{order:0;width:auto;margin:0;padding:0}
  .bar{flex-wrap:nowrap;gap:0 24px}
  .live{margin-left:auto}.tools{margin-left:0}}
/* Narrow header: the live line gets its own row and the tabs scroll, with a
   fade at the edge; on phones the buttons are icon-only (aria-label names them). */
@media (max-width:55.99em){
  .bar{gap:0 8px}
  .live{order:4;width:100%;min-height:24px;margin-top:-6px}
  [role=tab]{padding:0 12px}}
@media (max-width:30em){
  .tools .btn{padding:0;width:44px}
  .tools .btn .lbl{position:absolute;width:1px;height:1px;overflow:hidden;
    clip-path:inset(50%);white-space:nowrap}}
/* Page */
main{padding-top:24px;padding-bottom:48px}
.pagehead{margin-bottom:20px}
.pagehead h1{margin-bottom:4px}
h1{font-size:1.75rem;line-height:1.2;letter-spacing:-.02em;font-weight:700}
.lead{color:var(--ink-2);max-width:72ch;width:100%;font-size:1rem}
.fallback{font-size:.8125rem;color:var(--mute);margin-top:4px}
.grid{display:grid;gap:16px;grid-template-columns:minmax(0,1fr);align-items:start}
@media (min-width:64em){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}
  .grid>.full{grid-column:1/-1}}
/* KPI tiles */
.kpis{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(min(15rem,100%),1fr));
margin-bottom:16px}
.kpi{background:var(--surface);border:1px solid var(--line);border-radius:12px;
padding:16px;box-shadow:var(--shadow);display:flex;flex-direction:column;gap:6px;min-width:0}
.kpi .lbl{color:var(--mute);font-size:.8125rem;font-weight:600;text-transform:uppercase;
letter-spacing:.06em}
.kpi .row{display:flex;align-items:flex-end;justify-content:space-between;gap:12px;
flex-wrap:wrap}
.kpi .val{font-size:2rem;line-height:1.1;font-weight:700;letter-spacing:-.02em}
.kpi .val small{font-size:.875rem;font-weight:500;color:var(--mute);letter-spacing:0;
margin-left:2px}
.kpi .cap{font-size:.8125rem;color:var(--mute)}
.kpi>.pill{align-self:flex-start}
/* Panels */
.panel{background:var(--surface);border:1px solid var(--line);border-radius:12px;
box-shadow:var(--shadow);min-width:0;display:flex;flex-direction:column}
.head{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;padding:14px 16px;
border-bottom:1px solid var(--line)}
h2{font-size:1rem;line-height:1.3;font-weight:700;margin-right:auto}
.when{display:none;width:100%;font-size:.8125rem;color:var(--mute)}
.stale .when{display:block;color:var(--warn)}
.body{padding:16px;flex:1}
.body>*+*{margin-top:16px}
.body>:first-child{margin-top:0}
.panel.bare{background:none;border:0;box-shadow:none}
.panel.bare>.head{padding:0 0 12px;border:0}
.panel.bare>.body{padding:0}
/* Status pills: tone colour + icon + word, never colour alone. */
.pill{display:inline-flex;align-items:center;gap:6px;max-width:100%;padding:3px 10px 3px 8px;
border-radius:999px;font-size:.8125rem;font-weight:600;line-height:1.35;white-space:nowrap;
color:var(--tone);background:color-mix(in srgb,var(--tone) 14%,transparent);
border:1px solid color-mix(in srgb,var(--tone) 35%,transparent)}
.pill>span{overflow:hidden;text-overflow:ellipsis;min-width:0}
.pill .ic{width:14px;height:14px}
.t-good{--tone:var(--good)}.t-warn{--tone:var(--warn)}.t-bad{--tone:var(--bad)}
.t-neutral{--tone:var(--neutral)}
.meta{display:inline-flex;align-items:center;gap:6px;font-size:.8125rem;color:var(--ink-2);
padding:3px 10px;border-radius:999px;background:var(--muted);white-space:nowrap}
.meta .ic{width:14px;height:14px;color:var(--mute)}
/* Agent cards */
.cards{display:grid;gap:16px;grid-template-columns:repeat(auto-fill,minmax(min(20rem,100%),1fr))}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;
box-shadow:var(--shadow);padding:16px;display:flex;flex-direction:column;gap:12px;min-width:0}
.card.child{border-left:3px solid var(--acc)}
.card .top{display:flex;align-items:flex-start;gap:12px}
.avatar{display:grid;place-items:center;width:40px;height:40px;border-radius:10px;flex:none;
background:var(--acc-soft);color:var(--acc);font-weight:700;font-size:.875rem}
.card .who{min-width:0;flex:1}
.card h3{font-size:1rem;line-height:1.3;font-weight:700}
.card .proj{display:flex;align-items:center;gap:6px;color:var(--mute);font-size:.875rem;
min-width:0}
.card .proj span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.card .proj .ic{width:14px;height:14px}
.state{flex:none}
.doing{background:var(--raised);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.doing .k{display:block;font-size:.75rem;font-weight:600;color:var(--mute);
text-transform:uppercase;letter-spacing:.06em;margin-bottom:2px}
.doing .v{font-weight:600;overflow-wrap:anywhere}
.doing .v .age{font-weight:400;color:var(--mute)}
.doing .why{font-size:.875rem;color:var(--mute)}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.card .who .posture{margin-top:6px}
.status{display:flex;flex-direction:column;gap:12px}
.card details{border-top:1px solid var(--line);margin-top:auto}
.card summary{min-height:44px;font-size:.8125rem}
.card dl{display:grid;grid-template-columns:auto minmax(0,1fr);gap:4px 16px;margin:0 0 4px;
font-size:.8125rem}
.card dt{color:var(--mute)}
.card dd{margin:0;overflow-wrap:anywhere}
/* Verdicts, facts, meters */
.verdict{display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px}
.score{font-size:2.5rem;line-height:1;font-weight:700;letter-spacing:-.03em}
.score small{font-size:1rem;font-weight:500;color:var(--mute);letter-spacing:0}
.facts{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(9rem,100%),1fr));gap:12px;
margin-inline:0;margin-bottom:0}
.facts div{background:var(--raised);border:1px solid var(--line);border-radius:8px;
padding:10px 12px;min-width:0}
.facts dt{color:var(--mute);font-size:.8125rem}
.facts dd{margin:0;font-weight:700;font-size:1.125rem;overflow-wrap:anywhere}
.meters{display:grid;grid-template-columns:minmax(6rem,10rem) minmax(0,1fr) auto auto;
gap:8px 12px;align-items:center;font-size:.875rem}
.meters svg,.bars svg{width:100%;height:8px;display:block}
.meters rect.bg,.bars rect.bg{fill:var(--muted)}
.meters rect.fg{fill:var(--tone)}.bars rect.fg{fill:var(--acc)}
.bars{display:grid;grid-template-columns:minmax(5rem,12rem) minmax(0,1fr) auto;gap:8px 12px;
align-items:center;font-size:.875rem}
.bars .l,.meters .l{overflow-wrap:anywhere}.bars .v,.meters .v{text-align:right}
/* Sparkline: line + area, a dot on the newest sample, low-high label. */
.trend{display:flex;align-items:center;gap:8px;min-width:0}
.spark{display:block;width:120px;height:32px;overflow:visible;flex:none}
.spark .line{fill:none;stroke:var(--acc);stroke-width:2;stroke-linejoin:round;
stroke-linecap:round}
.spark .area{fill:var(--acc);fill-opacity:.16;stroke:none}
.spark circle{fill:var(--acc);stroke:var(--surface);stroke-width:2}
.trend .range{font:.75rem/1.3 var(--mono);color:var(--mute);white-space:nowrap}
/* Notes, tables, disclosures */
.note{background:var(--raised);border:1px solid var(--line-strong);border-radius:8px;
padding:12px 14px}
.err{border-color:var(--bad)}.err b{color:var(--bad)}
.empty{display:flex;align-items:center;gap:8px;color:var(--mute)}
.empty .ic{color:var(--good)}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.875rem}
caption{text-align:left;font-weight:600;padding-bottom:8px;color:var(--ink-2)}
th,td{text-align:left;padding:10px 12px 10px 0;border-bottom:1px solid var(--line);
vertical-align:top;overflow-wrap:anywhere}
thead th{color:var(--mute);font-weight:600;font-size:.75rem;text-transform:uppercase;
letter-spacing:.06em;white-space:nowrap;border-bottom-color:var(--line-strong)}
tbody tr:last-child>*{border-bottom:0}
tbody th{font-weight:400;color:var(--mute);width:14rem}
td.num,th.num{text-align:right}
.code,code{font-family:var(--mono);font-size:.8125rem}
td .pill{vertical-align:middle;justify-self:start}
.findings .pill{white-space:nowrap}
@media (min-width:44.01em){.findings td:first-child{width:1%;white-space:nowrap}
  .findings td:last-child{width:30%;min-width:10rem}}
.advice{color:var(--ink-2);font-size:.9375rem}
.what p{margin:0}
.what .sig{font-weight:600}
.evidence{display:block;margin-top:6px;padding:6px 8px;border-radius:6px;background:var(--raised);
border:1px solid var(--line);white-space:pre-wrap;overflow-wrap:anywhere;color:var(--ink-2)}
.clamp .evidence{max-height:calc(3lh + 12px);overflow:hidden}
.clamp.open .evidence{max-height:none}
.link{background:none;border:0;padding:0 2px;min-height:32px;color:var(--acc);font-weight:600;
font-size:.8125rem}
details.raw{margin-top:16px;border-top:1px dashed var(--line)}
summary{cursor:pointer;min-height:40px;display:flex;align-items:center;gap:6px;color:var(--mute);
font-size:.8125rem;font-weight:600;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"";width:6px;height:6px;border:solid currentColor;
border-width:0 2px 2px 0;transform:rotate(-45deg);margin-right:4px}
details[open]>summary::before{transform:rotate(45deg)}
summary:hover{color:var(--ink)}
details.raw table{font-size:.8125rem}
/* Command reference */
footer{border-top:1px solid var(--line);background:var(--surface)}
footer .wrap{padding-top:8px;padding-bottom:24px}
footer summary{font-size:.875rem;min-height:44px}
.cmds{display:grid;gap:4px 32px;grid-template-columns:repeat(auto-fill,minmax(min(22rem,100%),1fr));
margin:8px 0 0;font-size:.875rem}
.cmds div{display:grid;grid-template-columns:minmax(0,12rem) minmax(0,1fr);gap:12px;
padding:6px 0;border-bottom:1px solid var(--line)}
.cmds dt code{color:var(--acc);font-weight:600}
.cmds dd{margin:0;color:var(--mute)}
/* Phones: 16 px gutter; table rows become labelled lists. */
@media (max-width:44em){
  .wrap{padding-inline:16px}
  main{padding-top:16px}
  h1{font-size:1.5rem}
  .kpis{grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
  .kpi{padding:12px}.kpi .val{font-size:1.5rem}
  .kpi .lbl{font-size:.75rem}
  .spark{width:96px}
  .bars{grid-template-columns:5.5rem minmax(0,1fr) auto}
  .meters{grid-template-columns:minmax(0,1fr) auto auto}
  .meters svg{grid-column:1/-1;order:0}
  .stack>thead{position:absolute;left:-9999px}
  .stack>tbody>tr{display:block;border-bottom:1px solid var(--line-strong);padding:8px 0}
  .stack>tbody>tr>td{display:grid;grid-template-columns:6.5rem minmax(0,1fr);gap:12px;
    border:0;padding:4px 0;text-align:left}
  .stack>tbody>tr>td::before{content:attr(data-label);color:var(--mute);font-size:.8125rem;
    font-family:var(--sans)}
  tbody th{width:auto}
  .kv>tbody>tr{display:block;padding:6px 0;border-bottom:1px solid var(--line)}
  .kv>tbody>tr>th,.kv>tbody>tr>td{display:block;border:0;padding:0}
  .cmds div{grid-template-columns:minmax(0,1fr);gap:0}
}
@media (max-width:22em){.kpis{grid-template-columns:minmax(0,1fr)}}
@media (prefers-reduced-motion:no-preference){
  .btn,[role=tab],summary,.link{transition:color .15s,background-color .15s}
  .live.on .dot,.pill .beat{animation:beat 2s ease-in-out infinite}
  @keyframes beat{50%{opacity:.35}}}
</style></head><body>
<header><div class="wrap bar">
<span class="brand"><span class="logo"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true">
<path d="M2 12h4l3-8 6 16 3-8h4"/></svg></span>agentwatch</span>
<div role="tablist" aria-label="Reports" id="tabs"></div>
<div class="live" id="live"><span class="dot" aria-hidden="true"></span>
<span class="txt" id="livetext">Connecting...</span></div>
<div class="tools">
<button class="btn" id="pause" type="button" aria-pressed="false">Pause</button>
<button class="btn" id="theme" type="button">Light</button>
</div></div></header>
<main class="wrap"><div id="panel" role="tabpanel"></div></main>
<footer><div class="wrap"><details id="cmdref">
<summary>Command reference</summary>
<p class="mute">Run these in a terminal; add <code>--help</code> for options.</p>
<dl class="cmds">
<div><dt><code>agentwatch watch-all</code></dt><dd>Live terminal dashboard of every
agent.</dd></div>
<div><dt><code>agentwatch watch</code></dt><dd>The same dashboard for one session.</dd></div>
<div><dt><code>agentwatch check</code></dt><dd>Health of one session: loops, failures,
stalls, cost.</dd></div>
<div><dt><code>agentwatch security-scan</code></dt><dd>Security verdict: secure, at risk or
compromised.</dd></div>
<div><dt><code>agentwatch audit</code></dt><dd>Leaked keys in all saved Claude Code logs.</dd></div>
<div><dt><code>agentwatch ps</code></dt><dd>AI agents running right now.</dd></div>
<div><dt><code>agentwatch tools</code></dt><dd>Every tool a session used, with failures and
time.</dd></div>
<div><dt><code>agentwatch subagents</code></dt><dd>Health of each subagent of a session.</dd></div>
<div><dt><code>agentwatch stats</code></dt><dd>Claude Code tokens and estimated cost.</dd></div>
<div><dt><code>agentwatch report</code></dt><dd>Cost, waste and findings over 7 days.</dd></div>
<div><dt><code>agentwatch history sync</code></dt><dd>Record past sessions for
<code>report</code>.</dd></div>
<div><dt><code>agentwatch scrub FILE</code></dt><dd>Copy of a file with secrets hidden.</dd></div>
<div><dt><code>agentwatch detect</code></dt><dd>Every program using AI right now.</dd></div>
<div><dt><code>agentwatch net</code></dt><dd>Servers local AI runtimes talk to.</dd></div>
<div><dt><code>agentwatch statusline</code></dt><dd>Warnings in Claude Code's status
line.</dd></div>
<div><dt><code>agentwatch list-detectors</code></dt><dd>Every check agentwatch runs.</dd></div>
<div><dt><code>agentwatch visual</code></dt><dd>This page.</dd></div>
</dl></details></div></footer>
<script>
"use strict";
const T = new URLSearchParams(location.search).get("t") || "";
// Static, from the server code: agent display names and status-word tones.
const DATA = __PAGE_DATA__;
const NAMES = DATA.names, TONES = DATA.tones;
// [tab id, label, intro, [endpoint, title, run button label or null, layout], ...]
// layout: "full" spans both columns on wide screens, "half" takes one, "bare"
// has no panel chrome. Tools and Config tabs are added once #198 and #196 merge.
const TABS = [
  ["overview", "Overview",
    "What your AI agents are doing on this computer right now. Updates by itself.",
    ["ps", "Running agents", null, "bare"], ["check", "Health of the newest session", null, "half"],
    ["security-scan", "Security of the newest session", null, "half"],
    ["subagents", "Subagents of the newest session", null, "full"]],
  ["security", "Security", "Secrets, risky commands and data leaving your machine.",
    ["security-scan", "Security of the newest session", null, "full"],
    ["audit", "Secrets in all saved sessions", "Run audit", "full"]],
  ["cost", "Cost", "Tokens and estimated spend. Prices are estimates.",
    ["stats", "Claude Code usage, all projects", null, "half"],
    ["report", "Last 7 days, from history", null, "half"]],
  ["history", "History", "Sessions agentwatch has recorded on this computer.",
    ["history", "Recorded sessions", "Sync history", "full"]],
];
const LABELS = {
  agent_type: "Agent", working_directory: "Folder", pid: "PID", cpu_percent: "CPU",
  memory_mb: "Memory", uptime: "Running for", overall_score: "Health score",
  security_score: "Security score", warning_count: "Findings", session_id: "Session",
  log_file: "Log file", session_fallback: "Note", estimated_cost_usd: "Estimated cost",
  cost_usd: "Cost", waste_usd: "Wasted", waste_pct: "Wasted share", health_score: "Health",
  total_tokens: "Total tokens", tool_calls: "Tool calls", action_count: "Actions",
  cache_hit_ratio: "Cache hits", secret_type: "Secret", matched_prefix: "Ends with",
  project_name: "Project", is_security: "Security finding", session_project: "Project",
};
// A value that is not there: shown as an em dash, never "None", "null",
// "undefined" or "NaN" (a Python None that became a string included).
const DASH = "\u2014", MISSING = new Set(["None", "null", "undefined", "NaN"]);
function missing(v) {
  return v === null || v === undefined || (typeof v === "number" && !Number.isFinite(v)) ||
    (typeof v === "string" && MISSING.has(v.trim()));
}
function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = missing(text) ? DASH : String(text);
  if (cls) e.className = cls;
  return e;
}
function human(k) {
  if (LABELS[k]) return LABELS[k];
  const s = String(k).replace(/_(usd|pct|mb)$/, "").replace(/_/g, " ");
  return s.charAt(0).toUpperCase() + s.slice(1);
}
// A machine word for people: "at_risk" -> "At risk", "smooth_sailing" -> "Smooth sailing".
function label(word) {
  const s = String(word === null || word === undefined ? "" : word).replace(/[_-]+/g, " ").trim();
  return s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : "Unknown";
}
// "claude-code" -> "Claude Code"; an unknown id is title-cased.
function agentName(type) {
  if (NAMES[type]) return NAMES[type];
  return String(type || "agent").split(/[-_ ]+/).filter(Boolean)
    .map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
}
// A project as a folder name: a home dir is "~", never the user name.
function folder(project, dir) {
  if (dir && /^(\/home\/|\/Users\/|[A-Za-z]:\\Users\\)[^/\\]+[/\\]?$/.test(dir)) return "~";
  return project || "No project";
}
function plural(n, one, many) { return `${num(n)} ${n === 1 ? one : many || one + "s"}`; }
function money(v) {
  if (typeof v !== "number" || !Number.isFinite(v)) return DASH;
  return v > 0 && v < 0.01 ? "<$0.01" : "$" + v.toFixed(2);
}
function num(v) {
  if (typeof v !== "number" || !Number.isFinite(v)) return DASH;
  if (Number.isInteger(v)) return v.toLocaleString();
  if (Math.abs(v) < 1) return String(+v.toPrecision(2));
  return v.toLocaleString(undefined, {maximumFractionDigits: 1});
}
function when(v) {
  if (missing(v)) return DASH;
  const d = typeof v === "number" ? new Date(v * 1000) : new Date(v);
  if (isNaN(d)) return DASH;
  return d.toLocaleString(undefined, {dateStyle: "medium", timeStyle: "short"});
}
// "[[DD-]HH:]MM:SS" (ps etime) -> "1 h 53 min".
function uptime(s) {
  const m = /^(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+)$/.exec(String(s || ""));
  if (!m) return String(s || "");
  const d = +(m[1] || 0), h = +(m[2] || 0), mi = +m[3];
  return d ? `${d} d ${h} h` : h ? `${h} h ${mi} min` : mi ? `${mi} min` : "under a minute";
}
// One value as display text: money, percent, dates, yes/no.
function fmt(k, v) {
  if (missing(v)) return DASH;
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (typeof v === "number") {
    if (k.endsWith("_usd")) return money(v);
    if (k === "pid" || k.endsWith("_pid") || k.endsWith("_id")) return String(v);
    if (k.endsWith("_pct") || k === "cpu_percent") return num(v) + "%";
    if (k.endsWith("_ratio")) return num(v * 100) + "%";
    if (k === "memory_mb") return num(v) + " MB";
    if (/^(started|ended)$/.test(k) && v > 1e9) return when(v);
    return num(v);
  }
  if (typeof v === "string" && /^\d{4}-\d\d-\d\dT\d\d:/.test(v)) return when(v);
  if (typeof v === "object") return JSON.stringify(v);
  return v;
}
// Status tones: good / warn / bad / neutral. A score wins over a word (words
// repeat across themes); security uses its own tiers, not the health bands.
function healthTone(score, word) {
  if (typeof score === "number") return score >= 80 ? "good" : score >= 60 ? "warn" : "bad";
  return TONES.health[String(word || "").toLowerCase()] || "neutral";
}
function securityTone(score, tier) {
  const t = TONES.security[String(tier || "").toLowerCase()];
  if (t) return t;
  if (typeof score === "number") return score >= 100 ? "good" : score >= 50 ? "warn" : "bad";
  return "neutral";
}
function severityTone(sev) { return TONES.severity[String(sev || "").toLowerCase()] || "neutral"; }
// Samples kept in this page (last SAMPLES per series) to draw the live charts.
const SAMPLES = 60, series = new Map(), SVGNS = "http://www.w3.org/2000/svg";
function sample(key, v) {
  if (typeof v !== "number" || !Number.isFinite(v)) return;
  const a = series.get(key) || [];
  a.push(v);
  if (a.length > SAMPLES) a.shift();
  series.set(key, a);
}
function svg(tag, attrs) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, String(v));
  return e;
}
// Icons (stroke, 24 px grid); always next to a word, so hidden from readers.
const ICONS = {
  good: ["M20 6 9 17l-5-5"],
  warn: ["M12 3 2 20h20L12 3z", "M12 10v4", "M12 17h.01"],
  bad: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z", "m15 9-6 6", "m9 9 6 6"],
  neutral: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z", "M8 12h8"],
  folder: ["M3 6a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"],
  clock: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z", "M12 7v5l3 2"],
  coin: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z",
    "M15 9a3 2.5 0 0 0-6 0c0 3 6 1.5 6 4.5a3 2.5 0 0 1-6 0", "M12 5v2m0 10v2"],
  pause: ["M9 5v14", "M15 5v14"],
  sun: ["M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z", "M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4" +
    "M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"],
  moon: ["M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z"],
  play: ["M7 4v16l13-8z"],
};
function icon(name) {
  const s = svg("svg", {viewBox: "0 0 24 24", class: "ic", "aria-hidden": "true"});
  for (const d of ICONS[name] || []) s.append(svg("path", {d}));
  return s;
}
function pill(text, tone) {
  const p = el("span", null, "pill t-" + (tone || "neutral"));
  p.append(icon(tone || "neutral"), el("span", text));
  return p;
}
function meta(name, text) {
  const m = el("span", null, "meta");
  m.append(icon(name), el("span", text));
  return m;
}
// Sparkline geometry, or null when there is nothing to draw: fewer than 2
// distinct samples is a flat line, which says nothing. The y-range is padded
// 15% so a small change is visible but not exaggerated.
function sparkGeom(a, w, h) {
  if (!a || new Set(a).size < 2) return null;
  const lo = Math.min(...a), hi = Math.max(...a), pad = (hi - lo) * 0.15;
  const y0 = lo - pad, y1 = hi + pad;
  const pts = a.map((v, i) => [2 + i / (a.length - 1) * (w - 4),
    h - 2 - (v - y0) / (y1 - y0) * (h - 4)]);
  return {lo, hi, pts};
}
// The trend of series *key*, with its low-high range as text; null if flat.
function spark(key, name, f) {
  const a = series.get(key) || [], w = 120, h = 32, g = sparkGeom(a, w, h);
  if (!g) return null;
  f = f || num;
  const pts = g.pts, first = pts[0], end = pts[pts.length - 1];
  const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1))
    .join("");
  const s = svg("svg", {viewBox: `0 0 ${w} ${h}`, class: "spark", role: "img",
    "aria-label": `${name} trend over the last ${a.length} updates: from ${f(a[0])} to ` +
      `${f(a[a.length - 1])}, low ${f(g.lo)}, high ${f(g.hi)}`});
  s.append(svg("path", {class: "area", d: `${line}L${end[0].toFixed(1)} ${h}` +
      `L${first[0].toFixed(1)} ${h}Z`}),
    svg("path", {class: "line", d: line}),
    svg("circle", {cx: end[0].toFixed(1), cy: end[1].toFixed(1), r: 3}));
  const box = el("div", null, "trend");
  const range = el("span", `${f(g.lo)}\u2013${f(g.hi)}`, "range");
  range.setAttribute("aria-hidden", "true");
  box.append(s, range);
  return box;
}
// Horizontal bars: rows = [label, value, value text].
function bars(rows) {
  const g = el("div", null, "bars"), top = Math.max(...rows.map(r => r[1]), 1);
  for (const [name, v, text] of rows) {
    const s = svg("svg", {viewBox: "0 0 100 8", preserveAspectRatio: "none",
      "aria-hidden": "true"});
    s.append(svg("rect", {class: "bg", width: 100, height: 8, rx: 4}),
      svg("rect", {class: "fg", width: Math.max(v / top * 100, 1), height: 8, rx: 4}));
    g.append(el("span", name, "l"), s, el("span", text, "v"));
  }
  return g;
}
function ago(at) {
  const s = Math.max(0, Math.round((Date.now() - at) / 1000));
  return s < 5 ? "just now" : s < 60 ? s + " s ago" : s < 3600 ? Math.floor(s / 60) +
    " min ago" : s < 172800 ? Math.floor(s / 3600) + " h ago" : Math.floor(s / 86400) +
    " days ago";
}
// A text that keeps counting its own age: data-at (ms) + data-prefix.
function aged(prefix, at, cls) {
  const e = el("span", null, cls);
  e.dataset.at = at; e.dataset.prefix = prefix;
  e.textContent = `${prefix} ${ago(at)}`;
  return e;
}
function tickAges() {
  document.querySelectorAll("[data-at]").forEach(e => {
    e.textContent = `${e.dataset.prefix} ${ago(+e.dataset.at)}`;
  });
}
function verdict(score, word, tone, what) {
  const v = el("div", null, "verdict"), s = el("p", null, "score");
  s.append(num(score), el("small", " / 100"));
  s.setAttribute("aria-label", `${what} ${score} out of 100`);
  v.append(s, pill(label(word), tone));
  return v;
}
function facts(pairs) {
  const dl = el("dl", null, "facts");
  for (const [k, v] of pairs) {
    const d = el("div");
    d.append(el("dt", k), el("dd", v));
    dl.append(d);
  }
  return dl;
}
// rows -> table; cols = [[key, label, kind]], kind: "num" | "code" | "sev" | fn(row)
function table(rows, cols, caption, cls) {
  const wrap = el("div", null, "scroll"), t = el("table", null, "stack" + (cls ? " " + cls : ""));
  if (caption) t.append(el("caption", caption));
  const head = el("thead"), hr = el("tr");
  cols.forEach(([, name, kind]) => {
    const th = el("th", name, kind === "num" ? "num" : "");
    th.scope = "col";
    hr.append(th);
  });
  head.append(hr);
  const body = el("tbody");
  rows.forEach(row => {
    const tr = el("tr");
    cols.forEach(([k, name, kind]) => {
      const td = el("td", null, kind === "num" ? "num" : kind === "code" ? "code" : "");
      td.dataset.label = name;
      const v = typeof kind === "function" ? kind(row) : row[k];
      if (kind === "sev") td.append(pill(label(v), severityTone(v)));
      else if (v instanceof Node) td.append(v);
      else td.textContent = fmt(k, v);
      tr.append(td);
    });
    body.append(tr);
  });
  t.append(head, body);
  wrap.append(t);
  return wrap;
}
// Everything else: the raw payload, labelled, behind a disclosure.
function render(v, k) {
  if (Array.isArray(v)) {
    if (!v.length) return el("p", DASH, "mute");
    if (typeof v[0] !== "object" || v[0] === null) {
      return el("p", v.map(x => fmt(k || "", x)).join(", "));
    }
    const keys = [...new Set(v.flatMap(o => Object.keys(o || {})))];
    return table(v.map(o => o || {}), keys.map(x => [x, human(x),
      r => (r[x] && typeof r[x] === "object") ? render(r[x], x) : fmt(x, r[x])]));
  }
  if (v && typeof v === "object") {
    const t = el("table", null, "kv"), tb = el("tbody");
    for (const [x, val] of Object.entries(v)) {
      const r = el("tr"), th = el("th", human(x)), td = el("td");
      th.scope = "row";
      if (val && typeof val === "object") td.append(render(val, x));
      else td.textContent = fmt(x, val);
      r.append(th, td); tb.append(r);
    }
    t.append(tb);
    return t;
  }
  return el("p", fmt(k || "", v));
}
function raw(d) {
  const det = el("details", null, "raw");
  det.append(el("summary", "Raw data"), render(d));
  return det;
}
function emptyOk(text) {
  const p = el("p", null, "empty");
  p.append(icon("good"), el("span", text));
  return p;
}
// Long evidence (a command, a path) is shown whole in a wrapped code block,
// clamped to 3 lines with a button, instead of a message cut mid-word.
function evidence(text) {
  const c = el("code", text, "evidence");
  if (text.length <= 160) return c;
  const box = el("div", null, "clamp"), b = el("button", "Show all", "link");
  b.type = "button";
  b.setAttribute("aria-expanded", "false");
  b.onclick = () => {
    const open = box.classList.toggle("open");
    b.setAttribute("aria-expanded", String(open));
    b.textContent = open ? "Show less" : "Show all";
  };
  box.append(c, b);
  return box;
}
function what(w) {
  const box = el("div", null, "what"), msg = String(w.message || "");
  if (w.signal) box.append(el("p", label(w.signal), "sig"));
  const i = msg.indexOf(": "), tail = i > 0 ? msg.slice(i + 2) : "";
  const full = tail && Object.values(w.details || {}).find(v =>
    typeof v === "string" && v.length > tail.length && v.startsWith(tail));
  if (full) box.append(el("p", msg.slice(0, i), "mute"), evidence(full));
  else box.append(el("p", msg, w.signal ? "mute" : ""));
  return box;
}
function findings(list, empty) {
  if (!list.length) return emptyOk(empty);
  return table(list, [
    ["severity", "Severity", "sev"], ["message", "What happened", what],
    ["fix", "What to do", r => r.suggestion || (r.details || {}).remediation || "No specific step"],
  ], plural(list.length, "finding"), "findings");
}
// The fallback note, as a small line: no cwd, the project as a folder name.
function fallback(d) {
  if (!d.session_fallback) return null;
  return el("p", "No session for this folder; showing the newest session" +
    (d.session_project ? ` (project ${d.session_project}).` : "."), "fallback");
}
// What one agent is doing now, in words. Text and icons, never colour alone.
const VERBS = {Edit: "Edited", MultiEdit: "Edited", NotebookEdit: "Edited", Write: "Wrote",
  Read: "Read", Bash: "Ran", Grep: "Searched", Glob: "Searched", WebFetch: "Fetched",
  WebSearch: "Searched the web"};
// Working = a tool call in the last WORKING_S seconds (agent_status.ACTIVE_S);
// a log written recently with an old last call is idle.
const WORKING_S = 120;
function working(s) {
  const la = s && s.last_action;
  return !!(s && s.active === true && la && typeof la.age_s === "number" &&
    la.age_s < WORKING_S);
}
function stateOf(s) {
  if (!s) return el("span", "Checking", "pill t-neutral");
  if (working(s)) {
    const p = pill("Working", "good");
    p.querySelector(".ic").classList.add("beat");
    return p;
  }
  return pill(s.active === null || s.active === undefined ? "No activity" : "Idle", "neutral");
}
function statusParts(s, up) {
  const box = el("div", null, "doing"), chips = el("div", null, "chips");
  if (up) chips.append(meta("clock", "Up " + uptime(up)));
  if (!s) {
    box.append(el("span", "Now", "k"), el("p", "Checking what it is doing...", "why"));
    return [box, chips];
  }
  const la = s.last_action;
  if (!la) {
    box.append(el("span", "Activity", "k"), el("p", s.health ? "No tool calls yet." :
      s.log_expected === false ? "Activity isn't tracked for this agent type; it keeps " +
        "its sessions in one database." :
      "Waiting for its session log. It appears after the agent's first message.", "why"));
  } else {
    const sub = !la.target && (la.tool === "Agent" || la.tool === "Task");
    const text = sub ? "Started a subagent" :
      (VERBS[la.tool] || "Used " + (la.tool || "a tool")) + (la.target ? " " + la.target : "");
    const v = el("p", text, "v");
    v.append(aged(" \u00b7", Date.now() - (la.age_s || 0) * 1000, "age"));
    if (la.ok === false) v.append(" (failed)");
    box.append(el("span", working(s) ? "Doing now" : "Last action", "k"), v);
  }
  if (s.health) chips.prepend(pill(`${label(s.health.label)} \u00b7 ${num(s.health.score)}`,
    healthTone(s.health.score, s.health.label)), meta("coin", money(s.cost_usd)));
  return [box, chips];
}
// Fill every card's status in place; no card is rebuilt.
function decorate() {
  const by = new Map(((state.agents || {}).agents || []).map(a => [a.pid, a]));
  document.querySelectorAll(".card[data-pid]").forEach(c => {
    const s = state.agents ? by.get(+c.dataset.pid) : null;
    const box = c.querySelector(".status"), st = c.querySelector(".state");
    if (box && state.agents) box.replaceChildren(...statusParts(s, c.dataset.up));
    if (st && state.agents) st.replaceChildren(stateOf(s));
  });
}
function statusBox(pid, up) {
  const box = el("div", null, "status");
  const s = ((state.agents || {}).agents || []).find(a => a.pid === pid);
  box.append(...statusParts(state.agents ? s : null, up));
  return box;
}
let pulling = false;
async function pullAgents() {
  if (pulling || document.hidden || expiredLink || paused) return;
  if (!document.querySelector(".card[data-pid]")) return;
  pulling = true;
  try {
    const r = await fetch(`/api/agents?t=${encodeURIComponent(T)}`);
    const d = JSON.parse(await r.text());
    if (d.agents) { state.agents = d; decorate(); summary(); }
  } catch (e) {} finally { pulling = false; }
}
function initials(name) {
  return name.split(" ").map(w => w.charAt(0)).join("").slice(0, 2).toUpperCase();
}
// Sandbox/permission posture (agentwatch.posture): one pill, red when
// approvals are skipped with no sandbox.
const APPROVALS = {skipped: "Approvals skipped", on: "Approvals on"};
const SANDBOX = {sandboxed: "sandboxed", container: "in a container", none: "no sandbox"};
function postureChip(p) {
  if (!p || typeof p !== "object") return null;
  const ap = APPROVALS[p.approvals], sb = SANDBOX[p.sandbox];
  if (!ap && !sb) return null;
  const tone = p.approvals === "skipped" ? (p.sandbox === "none" ? "bad" : "warn") :
    p.approvals === "on" && (p.sandbox === "sandboxed" || p.sandbox === "container") ?
      "good" : "neutral";
  const c = pill((ap || "Approvals unknown") + " \u00b7 " + (sb || "sandbox unknown"), tone);
  c.classList.add("posture");
  c.title = "Sandbox and permission posture" + (p.confidence === "low" ? " (low confidence)" : "");
  return c;
}
function cards(list) {
  const g = el("div", null, "cards");
  for (const a of list) {
    const c = el("article", null, "card" + (a.depth > 0 ? " child" : ""));
    c.dataset.pid = a.pid;
    c.dataset.up = a.uptime || "";
    const name = agentName(a.agent_type), top = el("div", null, "top");
    const who = el("div", null, "who"), proj = el("p", null, "proj");
    const av = el("span", initials(name), "avatar");
    av.setAttribute("aria-hidden", "true");
    proj.append(icon("folder"), el("span", folder(a.project, a.working_directory)));
    who.append(el("h3", a.depth > 0 ? `${name} subagent` : name), proj);
    const pc = postureChip(a.posture);
    if (pc) who.append(pc);
    const st = el("div", null, "state"), s = ((state.agents || {}).agents || [])
      .find(x => x.pid === a.pid);
    st.append(stateOf(state.agents ? s : null));
    top.append(av, who, st);
    const box = statusBox(a.pid, a.uptime);
    const det = el("details"), dl = el("dl");
    const cpu = el("dd", fmt("cpu_percent", a.cpu_percent));
    const tr = spark("cpu:" + a.pid, "CPU", v => num(v) + "%");
    if (tr) cpu.append(tr);
    for (const [k, v] of [["PID", String(a.pid)], ["CPU", cpu],
      ["Memory", fmt("memory_mb", a.memory_mb)], ["Folder", a.working_directory || "Unknown"]]) {
      dl.append(el("dt", k), v instanceof Node ? v : el("dd", v));
    }
    det.append(el("summary", "Process details"), dl);
    c.append(top, box, det);
    g.append(c);
  }
  return g;
}
// The answer in words and KPI tiles, from what the Overview views last loaded.
const state = {};
function tile(name, value, unit, extra, trend) {
  const t = el("div", null, "kpi"), v = el("p", null, "val"), row = el("div", null, "row");
  v.append(typeof value === "number" ? num(value) : missing(value) ? DASH : String(value));
  if (unit) v.append(el("small", unit));
  row.append(v);
  if (trend) row.append(trend);
  t.append(el("p", name, "lbl"), row);
  if (extra) t.append(extra);
  return t;
}
function summary() {
  const box = document.getElementById("summary");
  if (!box) return;
  const {ps, check, sec, subs, agents} = state, parts = [];
  if (ps) parts.push(ps.length ? plural(ps.length, "AI agent") + " running on this computer."
    : "No AI agents are running right now.");
  const open = (ps || []).filter(a => a.depth === 0 && a.posture &&
    a.posture.approvals === "skipped" && a.posture.sandbox === "none").length;
  if (open) parts.push(`${plural(open, "agent")} ${open === 1 ? "runs" : "run"} with ` +
    "approvals skipped and no sandbox.");
  if (check) parts.push(`The newest session is ${label(check.status).toLowerCase()} ` +
    `(health ${num(check.overall_score)}/100)` + (sec ? ` and ` +
    `${label(sec.status).toLowerCase()} (security ${num(sec.security_score)}/100)` : "") + ".");
  const cost = check && check.efficiency ? check.efficiency.cost_total : null;
  if (cost !== null && cost !== undefined) parts.push(`It has cost about ${money(cost)} so far.`);
  if (subs && subs.active) parts.push(`${plural(subs.active, "subagent")} working now.`);
  const tiles = el("div", null, "kpis");
  if (ps) {
    const rows = (agents || {}).agents || [], busy = rows.filter(working).length;
    tiles.append(tile("Agents running", ps.length, "", el("p", agents ?
      `${busy} working \u00b7 ${ps.length - busy} idle` : "On this computer", "cap"),
      spark("n:ps", "Agents running")));
  }
  if (check) tiles.append(tile("Health", check.overall_score, "/100",
    pill(label(check.status), healthTone(check.overall_score, check.status)),
    spark("n:health", "Health")));
  if (sec) tiles.append(tile("Security", sec.security_score, "/100",
    pill(label(sec.status), securityTone(sec.security_score, sec.status)),
    spark("n:sec", "Security")));
  if (cost !== null && cost !== undefined) tiles.append(tile("Cost", money(cost), "",
    el("p", "Newest session, estimated", "cap"), spark("n:cost", "Cost", money)));
  const lead = document.getElementById("lead");
  if (lead) lead.textContent = parts.join(" ") || "Loading...";
  box.replaceChildren(tiles);
}
// Per report: the answer first, then the raw data.
function areas(d) {
  const flagged = Object.entries(d.categories || {}).filter(([, c]) => c.warning_count);
  if (!flagged.length) {
    return emptyOk(`All ${plural(Object.keys(d.categories || {}).length, "area")} clear.`);
  }
  const g = el("div", null, "meters");
  for (const [name, c] of flagged) {
    const t = healthTone(c.score, c.status);
    const s = svg("svg", {viewBox: "0 0 100 8", preserveAspectRatio: "none",
      "aria-hidden": "true", class: "t-" + t});
    s.append(svg("rect", {class: "bg", width: 100, height: 8, rx: 4}),
      svg("rect", {class: "fg", width: Math.max(+c.score || 0, 1), height: 8, rx: 4}));
    g.append(el("span", human(name), "l"), s, el("span", `${num(c.score)}/100`, "v"),
      pill(plural(c.warning_count, "finding"), t));
  }
  return g;
}
const VIEWS = {
  ps: d => [
    d.length ? cards(d) : el("p", "No agents running right now. Start Claude Code, Codex, " +
      "Cursor or another supported agent and it shows up here.", "mute"),
    d.length ? raw(d) : null],
  check: d => [verdict(d.overall_score, d.status,
      healthTone(d.overall_score, d.status), "Health"),
    findings(d.warnings || [], "No health findings."),
    areas(d),
    d.efficiency ? facts([["Efficiency", num(d.efficiency.score) + " / 100"],
      ["Cost so far", money(d.efficiency.cost_total)]]) : null,
    d.efficiency && !missing(d.efficiency.recommendation) ?
      el("p", "Advice: " + d.efficiency.recommendation, "advice") : null,
    fallback(d), raw(d)],
  "security-scan": d => [verdict(d.security_score, d.status,
      securityTone(d.security_score, d.status), "Security"),
    el("p", `${plural(d.warnings.length, "finding")} in ${plural(d.action_count, "action")}.`,
      "mute"),
    findings(d.warnings, "No security findings."), fallback(d), raw(d)],
  audit: d => [
    d.total_findings ? el("p", `${plural(d.total_findings, "secret")} found in ` +
      `${plural(d.sessions_scanned, "session")}.`) :
      emptyOk(`No secrets in ${plural(d.sessions_scanned, "session")}.`),
    d.findings.length ? table(d.findings, [["severity", "Severity", "sev"],
      ["secret_type", "Secret", r => label(r.secret_type)], ["project_name", "Project"],
      ["matched_prefix", "Ends with", "code"], ["remediation", "What to do"]]) : null,
    raw(d)],
  stats: d => {
    const t = d.totals || {};
    const tools = Object.entries(d.by_tool || {}).map(([name, x]) => ({name, ...x}))
      .sort((a, b) => b.total_tokens - a.total_tokens);
    return [facts([["Estimated cost", money(t.estimated_cost_usd)],
      ["Tokens", num(t.total_tokens || 0)], ["Sessions", num(d.sessions || 0)],
      ["Messages", num(d.messages || 0)], ["Tool calls", num(d.tool_calls || 0)],
      ["Cache hits", fmt("_ratio", t.cache_hit_ratio)]]),
      tools.length ? bars(tools.slice(0, 8).map(x => [x.name, x.total_tokens,
        num(x.total_tokens)])) : null,
      tools.length ? table(tools, [["name", "Tool"], ["call_count", "Calls", "num"],
        ["total_tokens", "Tokens", "num"], ["estimated_cost_usd", "Estimated cost", "num"]],
        "By tool") : null,
      raw(d)];
  },
  report: d => {
    const t = d.totals || {}, p = d.period || {}, prev = d.previous || {};
    return [el("p", `${when(p.start)} to ${when(p.end)}`, "mute"),
      // No sessions: nothing was spent, so $0.00; a missing value otherwise is a dash.
      facts([["Sessions", num(t.sessions || 0)],
        ["Cost", t.sessions ? money(t.cost_usd) : "$0.00"],
        ["Wasted", !t.sessions ? "$0.00" : money(t.waste_usd) +
          (t.waste_pct == null ? "" : ` (${num(t.waste_pct)}%)`)],
        ["Tokens", num(t.tokens || 0)],
        ["Security findings", num((d.security || {}).total || 0)]]),
      prev.sessions ? el("p", `Previous 7 days: ${plural(prev.sessions, "session")}, ` +
        `${money(prev.cost_usd)}.`, "mute") : null,
      t.sessions ? null : el("p", "No sessions in this period. Use Sync history on the " +
        "History tab to record them.", "mute"),
      raw(d)];
  },
  subagents: d => [
    d.total ? el("p", `${num(d.active || 0)} active, ${num(d.total)} in all. ` +
      "Each is scored like the " +
      "session above. Newest first.", "mute") :
      el("p", "This session has not started any subagents.", "mute"),
    d.subagents.length ? table(d.subagents, [
      ["type", "Subagent", r => (r.depth > 1 ? "\u21b3 " : "") + r.type],
      ["description", "Task"],
      ["health_score", "Health", "num"],
      ["status", "Status", r => r.status ?
        pill(label(r.status), healthTone(r.health_score, r.status)) : DASH],
      ["cost_usd", "Cost", "num"], ["actions", "Actions", "num"],
      ["last_activity", "Last activity",
        r => r.active ? pill("Active", "good") : when(r.last_activity)],
      ["warnings", "Warnings",
        r => (r.warnings || []).map(w => `${label(w.severity)}: ${label(w.signal)}`)
          .join(", ") || DASH],
    ]) : null,
    d.subagents.length ? raw(d) : null],
  history: d => [
    d.synced ? syncNote(d.synced, Date.now()) : lastSync ? syncNote(lastSync.d, lastSync.at) : null,
    d.sessions.length ? table(d.sessions.slice(0, historyShown),
      [["agent", "Agent", r => agentName(r.agent)],
      ["project", "Project"], ["ended", "Last active"], ["actions", "Actions", "num"],
      ["tokens", "Tokens", "num"], ["cost_usd", "Cost", "num"],
      ["health_score", "Health", "num"],
      ["status", "Status", r => pill(label(r.status), healthTone(r.health_score, r.status))]],
      d.sessions.length > HISTORY_PAGE ?
        `Newest ${num(Math.min(historyShown, d.sessions.length))} of ` +
        `${num(d.sessions.length)} sessions` : null)
      : el("p", "No sessions recorded yet. Sync history reads your agent logs into a local " +
        "database on this computer.", "mute"),
    d.sessions.length > historyShown ? moreButton(d) : null],
};
// History shows HISTORY_PAGE rows, then more on each click; the count is kept
// across the 30 s reloads, so a reload never collapses what was opened.
const HISTORY_PAGE = 25;
let historyShown = HISTORY_PAGE;
function moreButton(d) {
  const left = d.sessions.length - historyShown;
  const b = el("button", `Show ${num(Math.min(left, HISTORY_PAGE))} more`, "btn");
  b.type = "button";
  b.onclick = () => {
    historyShown += HISTORY_PAGE;
    const body = b.closest(".body");
    if (body) swap(body, VIEWS.history(d).filter(Boolean));
  };
  return b;
}
// The sync result is only in the answer to the click: keep it, with its age.
let lastSync = null;
function syncNote(s, at) {
  lastSync = {d: s, at};
  const p = el("p", `Synced: ${num(s.new || 0)} new, ${num(s.updated || 0)} updated, ` +
    `${num(s.unchanged || 0)} unchanged` +
    (s.active ? `, ${num(s.active)} skipped because the agent wrote to them in the last ` +
      "minute" : "") + ". ", "mute");
  p.append(aged("Ran", at));
  return p;
}
// Every view reloads on its own while the page is visible, except RUN_ONLY
// ones: the audit reads every saved log, so only its button runs it. SLOW
// ones read stored data (stats, report, history; never a sync).
const LIVE = new Set(["ps", "agents", "check", "subagents", "security-scan"]), LIVE_MS = 5000;
const SLOW = new Set(["stats", "report", "history"]), SLOW_MS = 30000;
const RUN_ONLY = new Set(["audit"]);
const busy = new WeakMap(), last = new WeakMap(), inflight = new WeakSet();
const loadedAt = new WeakMap();
let expiredLink = false, paused = false, lastOk = 0;
const SLACK = 1000;  // a tick may land just before its view turns one cadence old
const ranCache = new Map();  // name -> {parts text is rebuilt from d, at}
// The one live indicator: "Live · updated 3 s ago", paused, failing or expired.
function liveStatus() {
  const box = document.getElementById("live"), t = document.getElementById("livetext");
  const stale = !!document.querySelector("section.stale");
  box.className = "live " + (expiredLink ? "off" : paused ? "paused" : stale ? "warn" : "on");
  document.getElementById("pause").hidden = expiredLink;
  if (expiredLink || !lastOk) {
    delete t.dataset.at;
    t.textContent = expiredLink ? "Link expired" : paused ? "Paused" : "Connecting...";
    return;
  }
  t.dataset.at = lastOk;
  t.dataset.prefix = paused ? "Paused \u00b7 updated" : stale ?
    "Update failed \u00b7 data from" : "Live \u00b7 updated";
  t.textContent = `${t.dataset.prefix} ${ago(lastOk)}`;
}
// Swap a section's content in place: same height while it happens, open
// details, horizontal scroll and a focused summary survive.
function swap(body, parts) {
  const open = [...body.querySelectorAll("details")].map(d => d.open);
  const fi = body.contains(document.activeElement) ?
    [...body.querySelectorAll("summary")].indexOf(document.activeElement) : -1;
  const sx = [...body.querySelectorAll(".scroll")].map(s => s.scrollLeft);
  body.style.minHeight = body.offsetHeight + "px";
  body.replaceChildren(...parts);
  body.querySelectorAll("details").forEach((d, i) => { d.open = !!open[i]; });
  body.querySelectorAll(".scroll").forEach((s, i) => { s.scrollLeft = sx[i] || 0; });
  if (fi >= 0) { const s = body.querySelectorAll("summary")[fi]; if (s) s.focus(); }
  requestAnimationFrame(() => { body.style.minHeight = ""; });
}
// quiet: a timer reload. No "Loading...", buttons stay usable, skipped while
// another load of the section runs, the view is kept if nothing changed or
// the update failed.
async function load(sec, name, run, quiet) {
  if (quiet && inflight.has(sec)) return;
  const body = sec.querySelector(".body"), stamp = sec.querySelector(".when");
  const seq = (busy.get(sec) || 0) + 1;
  busy.set(sec, seq);
  inflight.add(sec);
  if (!quiet) {
    sec.querySelectorAll("button").forEach(b => { b.disabled = true; });
    body.setAttribute("aria-busy", "true");
    body.replaceChildren(el("p", run ? "Running. This can take a minute..." : "Loading...",
      "mute"));
  }
  let parts, text, failed = false, expired = false, d;
  try {
    const r = await fetch(`/api/${name}?t=${encodeURIComponent(T)}${run ? "&run=1" : ""}`);
    if (r.status === 403) {
      expired = expiredLink = true;  // the token is dead: the timers stop
      throw new Error("This link has expired. Open the address that " +
        "agentwatch visual printed in your terminal.");
    }
    text = await r.text();
    d = JSON.parse(text);
    if (d.error) parts = [problem("Nothing to show yet.", d.error)];
    else if (d.not_run) parts = [el("p", "Not run yet. The audit reads every saved session " +
      "log, so it can take a while.", "mute")];
    else {
      feed(name, d, quiet);
      parts = VIEWS[name](d);
      if (RUN_ONLY.has(name)) {
        ranCache.set(name, {d, at: Date.now()});
        parts.unshift(el("p", null, "mute"));
        parts[0].append(aged("Ran", ranCache.get(name).at));
      }
    }
  } catch (e) {
    failed = true;
    parts = [problem("Could not load this report.", e instanceof TypeError ?
      "agentwatch is not answering. Is agentwatch visual still running?" : e.message)];
  }
  if (busy.get(sec) !== seq) return;  // a newer load replaced this one
  inflight.delete(sec);
  body.removeAttribute("aria-busy");
  sec.querySelectorAll("button").forEach(b => { b.disabled = false; });
  if (failed) {
    const ok = +stamp.dataset.ok;
    // A timer miss keeps the last good view (its real age); an expired link, or
    // a view that never loaded, shows the problem instead.
    if (quiet && !expired && ok && body.childElementCount) {
      sec.classList.add("stale");
      stamp.replaceChildren(aged("Update failed. Showing data from", ok));
      liveStatus();
      return;
    }
    swap(body, parts);
    last.delete(sec);
    sec.classList.add("stale");
    stamp.replaceChildren(el("span", expired ? "Link expired" : "Not loaded"));
    liveStatus();
    return;
  }
  if (!(quiet && text !== undefined && text === last.get(sec))) swap(body, parts.filter(Boolean));
  last.set(sec, text);
  if (name === "ps" && !failed) pullAgents();  // one scan per tick, here
  sec.classList.remove("stale");
  stamp.dataset.ok = loadedAt.set(sec, Date.now()).get(sec);
  stamp.replaceChildren(aged(sec.dataset.cadence ? "Last updated" : "Loaded", Date.now()));
  lastOk = Date.now();
  liveStatus();
  if (!sec.dataset.cadence || document.getElementById("summary")) summary();
}
// Series and cross-view state for the live charts and the summary.
// Samples are taken on timer ticks (and once to start a series), so a tab
// switch does not bend the time axis.
function feed(name, d, tick) {
  const take = (k, v) => { if (tick || !series.has(k)) sample(k, v); };
  if (name === "ps") {
    state.ps = d; take("n:ps", d.length);
    const live = new Set(d.map(a => "cpu:" + a.pid));
    for (const k of [...series.keys()]) {
      if (k.startsWith("cpu:") && !live.has(k)) series.delete(k);  // agent is gone
    }
    d.forEach(a => take("cpu:" + a.pid, a.cpu_percent));
  } else if (name === "check") {
    state.check = d; take("n:health", d.overall_score);
    take("n:cost", d.efficiency ? d.efficiency.cost_total : null);
  } else if (name === "security-scan") { state.sec = d; take("n:sec", d.security_score); }
  else if (name === "subagents") state.subs = d;
}
// Timer: reload every section of the current tab that is on *set*. Never
// sends the run flag; a section without data yet is skipped while its first load runs.
function refresh(set, minAge) {
  if (document.hidden || expiredLink) return;
  if (paused) return;
  document.querySelectorAll("section[data-name]").forEach(sec => {
    if (!set.has(sec.dataset.name)) return;
    if (minAge && Date.now() - (loadedAt.get(sec) || 0) < minAge) return;
    load(sec, sec.dataset.name, false, true);
  });
}
function problem(title, detail) {
  const p = el("div", null, "note err");
  p.append(el("b", title), el("p", detail));
  return p;
}
function show(id) {
  const i = Math.max(0, TABS.findIndex(t => t[0] === id));
  const [tid, tabName, intro, ...secs] = TABS[i];
  document.querySelectorAll("[role=tab]").forEach((b, j) => {
    b.setAttribute("aria-selected", String(i === j));
    b.tabIndex = i === j ? 0 : -1;
  });
  document.title = tabName + " - agentwatch";
  const main = document.getElementById("panel");
  main.setAttribute("aria-labelledby", "tab-" + tid);
  const head = el("div", null, "pagehead"), lead = el("p", intro, "lead");
  head.append(el("h1", tabName), lead);
  main.replaceChildren(head);
  if (tid === "overview") {
    lead.id = "lead";
    const box = el("div"); box.id = "summary";
    main.append(box);
    summary();
  }
  const grid = el("div", null, "grid");
  main.append(grid);
  for (const [name, title, button, layout] of secs) {
    const sec = el("section", null, "panel " + (layout === "half" ? "half" : "full") +
      (layout === "bare" ? " bare" : ""));
    const hd = el("div", null, "head"), h = el("h2", title), body = el("div", null, "body");
    h.id = "h-" + name;
    sec.setAttribute("aria-labelledby", h.id);
    sec.dataset.name = name;
    if (LIVE.has(name)) sec.dataset.cadence = LIVE_MS;
    else if (SLOW.has(name)) sec.dataset.cadence = SLOW_MS;
    // timer updates stay silent
    if (!sec.dataset.cadence) body.setAttribute("aria-live", "polite");
    hd.append(h);
    if (button) {
      const b = el("button", button, "btn primary");
      b.type = "button";
      b.onclick = () => load(sec, name, true);
      hd.append(b);
    }
    hd.append(el("p", null, "when"));
    sec.append(hd, body); grid.append(sec);
    const kept = ranCache.get(name);
    if (kept) {  // the audit's last result, kept while you look at other tabs
      const parts = VIEWS[name](kept.d), age = el("p", null, "mute");
      age.append(aged("Ran", kept.at));
      body.replaceChildren(age, ...parts.filter(Boolean));
    } else load(sec, name, false);
  }
  liveStatus();
}
setInterval(() => {
  refresh(LIVE, LIVE_MS - SLACK);
}, LIVE_MS);
setInterval(() => {
  refresh(SLOW, SLOW_MS - SLACK);
}, SLOW_MS);
setInterval(tickAges, 1000);
// Back on the tab: catch up now instead of waiting for the next tick.
document.addEventListener("visibilitychange", () => {
  refresh(LIVE, LIVE_MS);
  refresh(SLOW, SLOW_MS);
});
// Pause stops every timer reload (never a click); resume catches up at once.
const pauseBtn = document.getElementById("pause");
pauseBtn.onclick = () => {
  paused = !paused;
  pauseBtn.setAttribute("aria-pressed", String(paused));
  syncPause();
  liveStatus();
  refresh(LIVE, LIVE_MS);
  refresh(SLOW, SLOW_MS);
};
function syncPause() {
  const word = paused ? "Resume" : "Pause";
  pauseBtn.replaceChildren(icon(paused ? "play" : "pause"), el("span", word, "lbl"));
  pauseBtn.setAttribute("aria-label", paused ? "Resume live updates" : "Pause live updates");
}
syncPause();
const tabs = document.getElementById("tabs");
TABS.forEach(([id, name]) => {
  const b = el("button", name);
  b.type = "button"; b.id = "tab-" + id;
  b.setAttribute("role", "tab");
  b.setAttribute("aria-controls", "panel");
  b.onclick = () => { location.hash = id; };
  tabs.append(b);
});
tabs.addEventListener("keydown", e => {
  const ids = TABS.map(t => t[0]), cur = ids.indexOf(location.hash.slice(1));
  const step = {ArrowRight: 1, ArrowLeft: -1}[e.key];
  if (e.key === "Home" || e.key === "End" || step) {
    e.preventDefault();
    const n = e.key === "Home" ? 0 : e.key === "End" ? ids.length - 1 :
      (Math.max(cur, 0) + step + ids.length) % ids.length;
    location.hash = ids[n];
    document.getElementById("tab-" + ids[n]).focus();
  }
});
addEventListener("hashchange", () => { show(location.hash.slice(1)); tabIntoView(); });
// The tab bar scrolls on narrow screens: fade an edge while tabs are hidden
// past it, and keep the selected tab in view.
function tabCue() {
  tabs.classList.toggle("more", tabs.scrollLeft + tabs.clientWidth < tabs.scrollWidth - 1);
  tabs.classList.toggle("less", tabs.scrollLeft > 1);
}
function tabIntoView() {
  const sel = tabs.querySelector("[aria-selected=true]");
  if (!sel) return;
  const box = tabs.getBoundingClientRect(), r = sel.getBoundingClientRect();
  if (r.right > box.right) tabs.scrollLeft += r.right - box.right + 4;
  else if (r.left < box.left) tabs.scrollLeft -= box.left - r.left + 4;
  tabCue();
}
tabs.addEventListener("scroll", tabCue, {passive: true});
addEventListener("resize", tabIntoView);
// Theme: dark unless the system asks for light, until the button is used;
// the choice is kept.
const themeBtn = document.getElementById("theme");
function dark() {
  const t = document.documentElement.dataset.theme;
  return t ? t === "dark" : !matchMedia("(prefers-color-scheme: light)").matches;
}
function syncTheme() {
  themeBtn.replaceChildren(icon(dark() ? "sun" : "moon"),
    el("span", dark() ? "Light" : "Dark", "lbl"));
  themeBtn.setAttribute("aria-label", dark() ? "Switch to light theme" : "Switch to dark theme");
}
try {
  const t = localStorage.getItem("agentwatch-theme");
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
} catch (e) {}
themeBtn.onclick = () => {
  const t = dark() ? "light" : "dark";
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("agentwatch-theme", t); } catch (e) {}
  syncTheme();
};
syncTheme();
show(location.hash.slice(1));
tabIntoView();
</script></body></html>
"""
PAGE = _PAGE.replace("__PAGE_DATA__", _PAGE_DATA)
