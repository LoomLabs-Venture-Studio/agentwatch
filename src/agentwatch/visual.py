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
from agentwatch.cc_stats import compute_stats, find_all_project_dirs
from agentwatch.detectors.security.secret_scanner import assess_impact, redact_truncate
from agentwatch.history import connect, sync
from agentwatch.parser.logs import LogUnreadableError, UnsupportedLogFormatError
from agentwatch.report import build
from agentwatch.subagents import build as subagents_build
from agentwatch.subagents import session_of

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
    return warnings, buffer, note


def _ps(run: bool):
    return cli._ps_json(cli.find_running_agents())


def _check(run: bool):
    warnings, buffer, note = _scan("health")
    report = cli.calculate_health(warnings, include_security=False)
    efficiency = cli.calculate_efficiency(warnings, buffer)
    return cli._check_json(report, efficiency, warnings, buffer, note)


def _agents(run: bool):
    return agents_build(cli.find_running_agents())


def _subagents(run: bool):
    log, _ = cli._default_log()
    if log is None:
        raise _NoDataError("No log files found")
    return subagents_build(session_of(log))


def _security(run: bool):
    warnings, buffer, note = _scan("security")
    return cli._security_json(warnings, buffer, note)


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

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>agentwatch</title>
<style>
/* Tokens: the agentwatch.info palette (docs/assets/stylesheets/extra.css).
   Slate neutrals, one petrol accent, status colours only next to their word. */
:root{color-scheme:light;
--bg:#fff;--bg-alt:#f8fafc;--field:#f1f5f9;--ink:#0f172a;--mute:#475569;
--rule:#e2e8f0;--rule-strong:#cbd5e1;--acc:#0e5f76;--acc-strong:#0a4759;--acc-soft:#e3f0f4;
--on-acc:#fff;--ok:#15803d;--degraded:#b45309;--warn:#c2410c;--bad:#b91c1c;
--sans:"Atkinson Hyperlegible Next","Atkinson Hyperlegible",system-ui,-apple-system,
"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:"Atkinson Hyperlegible Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;
--bg:#0f172a;--bg-alt:#131d33;--field:#1e293b;--ink:#e2e8f0;--mute:#a3b1c6;
--rule:#1e293b;--rule-strong:#334155;--acc:#67c3d9;--acc-strong:#9ad8e7;
--acc-soft:rgb(103 195 217/12%);--on-acc:#0f172a;
--ok:#4ade80;--degraded:#fbbf24;--warn:#fb923c;--bad:#f87171}}
:root[data-theme=dark]{color-scheme:dark;
--bg:#0f172a;--bg-alt:#131d33;--field:#1e293b;--ink:#e2e8f0;--mute:#a3b1c6;
--rule:#1e293b;--rule-strong:#334155;--acc:#67c3d9;--acc-strong:#9ad8e7;
--acc-soft:rgb(103 195 217/12%);--on-acc:#0f172a;
--ok:#4ade80;--degraded:#fbbf24;--warn:#fb923c;--bad:#f87171}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;scrollbar-color:var(--rule-strong) var(--bg)}
body{margin:0;background:var(--bg);color:var(--ink);font:1rem/1.55 var(--sans);
font-variant-numeric:tabular-nums}
::selection{background:var(--acc-soft);color:var(--ink)}
:focus-visible{outline:3px solid var(--acc);outline-offset:2px;border-radius:4px}
header{border-bottom:1px solid var(--rule);background:var(--bg)}
.bar{max-width:72rem;margin:auto;padding:0 16px;display:flex;flex-wrap:wrap;
align-items:center;gap:0 24px}
.brand{display:flex;align-items:center;gap:8px;font-weight:700;font-size:1.05rem;
min-height:52px;margin-right:auto}
.brand svg{width:22px;height:22px;fill:none;stroke:var(--acc);stroke-width:2.2;
stroke-linecap:round;stroke-linejoin:round}
[role=tablist]{display:flex;gap:4px;order:3;width:100%;overflow-x:auto;
margin:0 -4px;padding:0 4px}
@media (min-width:44em){[role=tablist]{order:0;width:auto;margin:0}}
button{font:inherit;color:inherit;cursor:pointer}
[role=tab]{background:none;border:0;padding:0 12px;min-height:48px;color:var(--mute);
white-space:nowrap;text-decoration:none}
[role=tab]:hover{color:var(--ink)}
[role=tab][aria-selected=true]{color:var(--ink);font-weight:700;text-decoration:underline;
text-decoration-color:var(--acc);text-decoration-thickness:3px;text-underline-offset:.6em}
.btn{display:inline-flex;align-items:center;justify-content:center;min-height:44px;
padding:0 16px;border:2px solid var(--acc);border-radius:8px;background:none;
color:var(--acc);font-weight:700;line-height:1.2}
.btn:hover{border-color:var(--acc-strong);background:var(--acc-strong);color:var(--on-acc)}
.btn.primary{background:var(--acc);color:var(--on-acc)}
.btn.quiet{border-color:var(--rule-strong);color:var(--ink);font-weight:400}
.btn.quiet:hover{background:var(--field);border-color:var(--rule-strong);color:var(--ink)}
.btn:disabled{opacity:.55;cursor:progress}
#theme{min-height:44px}
main{max-width:72rem;margin:auto;padding:8px 16px 64px}
h1{font-size:1.6rem;line-height:1.2;letter-spacing:-.02em;margin:28px 0 4px}
.lead{margin:0 0 8px;color:var(--mute);max-width:60ch}
section{padding-top:16px;margin-top:32px;border-top:2px solid var(--ink)}
.head{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px}
h2{font-size:1.15rem;line-height:1.3;margin:0;margin-right:auto}
.when{color:var(--mute);font-size:.875rem;width:100%;margin:2px 0 0}
.body{margin-top:12px}
.body>*+*{margin-top:16px}
p{margin:0;text-wrap:pretty;overflow-wrap:anywhere}
h1,h2{text-wrap:balance}
.mute{color:var(--mute)}
.verdict{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 14px}
.score{font-size:2.25rem;line-height:1;font-weight:700;letter-spacing:-.02em}
.score small{font-size:1rem;font-weight:400;color:var(--mute);letter-spacing:0}
.chip{display:inline-flex;align-items:baseline;gap:.4em;color:var(--tone,var(--mute));
font-weight:700;white-space:nowrap}
.chip::before{content:"";width:.6em;height:.6em;border-radius:50%;
background:var(--tone,var(--mute));flex:none}
.ok{--tone:var(--ok)}.degraded{--tone:var(--degraded)}.warn{--tone:var(--warn)}
.bad{--tone:var(--bad)}
.facts{display:grid;grid-template-columns:repeat(auto-fill,minmax(10rem,1fr));gap:12px 24px;
margin-inline:0;margin-bottom:0}
.facts div{border-bottom:1px solid var(--rule);padding-bottom:8px}
.facts dt{color:var(--mute);font-size:.875rem}
.facts dd{margin:0;font-weight:700;font-size:1.15rem;overflow-wrap:anywhere}
.note{background:var(--bg-alt);border:1px solid var(--rule-strong);border-radius:8px;
padding:12px 14px}
.err{border-color:var(--bad)}
.err b{color:var(--bad)}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.9375rem}
caption{text-align:left;font-weight:700;padding-bottom:6px}
th,td{text-align:left;padding:8px 12px 8px 0;border-bottom:1px solid var(--rule);
vertical-align:top;overflow-wrap:anywhere}
thead th{color:var(--mute);font-weight:700;font-size:.875rem;white-space:nowrap;
border-bottom-color:var(--rule-strong)}
tbody th{font-weight:400;color:var(--mute);width:16rem}
td.num,th.num{text-align:right}
.code{font-family:var(--mono);font-size:.875rem}
.nowrap{white-space:nowrap}
details{border-top:1px solid var(--rule)}
summary{cursor:pointer;min-height:44px;display:flex;align-items:center;color:var(--acc);
font-weight:700}
details[open]>summary{margin-bottom:8px}
details table{font-size:.875rem}
footer{border-top:1px solid var(--rule);background:var(--bg-alt)}
footer .wrap{max-width:72rem;margin:auto;padding:24px 16px 48px}
footer h2{margin-bottom:4px}
code{font-family:var(--mono);font-size:.875rem}
.cmds{display:grid;gap:12px 32px;
grid-template-columns:repeat(auto-fill,minmax(min(20rem,100%),1fr));
margin:16px 0 0}
.cmds div{border-bottom:1px solid var(--rule);padding-bottom:10px}
.cmds dt code{color:var(--acc);font-weight:700}
.cmds dd{margin:2px 0 0;color:var(--mute);font-size:.9375rem}
/* Live overview: summary tiles, agent cards, charts. Charts are inline SVG and
   always sit next to their value as text; colour is never the only signal. */
.plain{font-size:1.15rem;max-width:60ch;margin:8px 0 0;text-wrap:pretty}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));gap:12px;
margin-top:16px}
.tile,.card{background:var(--bg-alt);border:1px solid var(--rule-strong);border-radius:10px;
padding:12px 14px;min-width:0}
.tile .lbl{color:var(--mute);font-size:.875rem}
.tile .val{font-size:1.75rem;font-weight:700;line-height:1.15;letter-spacing:-.02em}
.tile .val small{font-size:.9rem;font-weight:400;color:var(--mute);letter-spacing:0}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(16rem,1fr));gap:12px}
.card h3{margin:0;font-size:1.05rem;line-height:1.3}
.card .sub{color:var(--mute);font-size:.875rem;overflow-wrap:anywhere}
.card .row{display:flex;justify-content:space-between;align-items:center;gap:8px;
margin-top:8px;font-size:.9375rem}
.card .status{margin:8px 0;padding:8px 0;border-top:1px solid var(--rule-strong);
border-bottom:1px solid var(--rule-strong)}
.card .status .row{flex-wrap:wrap;justify-content:flex-start;gap:4px 12px}
.card .status .chip{min-width:0;overflow-wrap:anywhere}
.card .status p{margin:0 0 6px;overflow-wrap:anywhere}
.card.child{margin-left:12px;border-left:4px solid var(--acc)}
.spark{display:block;width:100%;max-width:9rem;height:28px;margin-top:6px;overflow:visible}
.spark path{fill:none;stroke:var(--acc);stroke-width:2;vector-effect:non-scaling-stroke;
stroke-linejoin:round;stroke-linecap:round}
.spark circle{fill:var(--acc)}
.bars{display:grid;grid-template-columns:minmax(6rem,12rem) minmax(0,1fr) auto;gap:6px 12px;
align-items:center;font-size:.9375rem}
.bars svg{width:100%;height:14px;display:block}
.bars rect.bg{fill:var(--field)}.bars rect.fg{fill:var(--acc)}
.bars .l{overflow-wrap:anywhere}.bars .v{text-align:right}
.pulse{display:inline-block;width:.55em;height:.55em;border-radius:50%;background:var(--ok);
margin-right:.4em}
.stale .pulse{background:var(--degraded)}
.stale .when{color:var(--degraded)}
/* Phones: each table row becomes a short list of labelled values. */
@media (max-width:44em){
  .bar{gap:0 12px}
  .stack>thead{position:absolute;left:-9999px}
  .stack>tbody>tr{display:block;border-bottom:1px solid var(--rule-strong);padding:8px 0}
  .stack>tbody>tr>td{display:grid;grid-template-columns:7.5rem minmax(0,1fr);gap:12px;
    border:0;padding:3px 0;text-align:left}
  .stack>tbody>tr>td::before{content:attr(data-label);color:var(--mute);font-size:.875rem;
    font-family:var(--sans)}
  tbody th{width:auto}
  .kv>tbody>tr{display:block;padding:6px 0;border-bottom:1px solid var(--rule)}
  .kv>tbody>tr>th,.kv>tbody>tr>td{display:block;border:0;padding:0}
}
@media (prefers-reduced-motion:no-preference){
  .btn,[role=tab]{transition:color .15s,background-color .15s}
  .live .pulse{animation:beat 2s ease-in-out infinite}
  @keyframes beat{50%{opacity:.35}}}
</style></head><body>
<header><div class="bar">
<span class="brand"><svg viewBox="0 0 24 24" aria-hidden="true">
<path d="M2 12h4l3-8 6 16 3-8h4"/></svg>agentwatch</span>
<div role="tablist" aria-label="Reports" id="tabs"></div>
<button class="btn quiet" id="theme" type="button">Dark theme</button>
</div></header>
<main><div id="panel" role="tabpanel"></div></main>
<footer aria-labelledby="cmds"><div class="wrap">
<h2 id="cmds">Commands</h2>
<p class="mute">Run these in a terminal. Add <code>--help</code> to any command for its options.</p>
<dl class="cmds">
<div><dt><code>agentwatch watch-all</code></dt>
  <dd>Live dashboard of every running assistant.</dd></div>
<div><dt><code>agentwatch watch</code></dt>
  <dd>The same dashboard for one session.</dd></div>
<div><dt><code>agentwatch check</code></dt>
  <dd>Health report for one session: loops, failures, stalls, cost. Overview tab.</dd></div>
<div><dt><code>agentwatch security-scan</code></dt>
  <dd>Security checks only, with a verdict: secure, at risk or compromised. Security tab.</dd></div>
<div><dt><code>agentwatch audit</code></dt>
  <dd>Searches all saved Claude Code logs for leaked passwords and keys. Security tab.</dd></div>
<div><dt><code>agentwatch ps</code></dt>
  <dd>Lists the AI assistants running right now. Overview tab.</dd></div>
<div><dt><code>agentwatch tools</code></dt>
  <dd>Every tool a session used: calls, failures, error types and time.</dd></div>
<div><dt><code>agentwatch subagents</code></dt>
  <dd>Health of each subagent (cto, engineer, qa) of a Claude Code session.
  Overview tab.</dd></div>
<div><dt><code>agentwatch stats</code></dt>
  <dd>Claude Code token use and estimated cost, by tool. Cost tab.</dd></div>
<div><dt><code>agentwatch report</code></dt>
  <dd>Cost, waste and findings over the last 7 days, with the trend. Cost tab.</dd></div>
<div><dt><code>agentwatch history sync</code></dt>
  <dd>Records past sessions in a local database for <code>report</code>. History tab.</dd></div>
<div><dt><code>agentwatch scrub FILE</code></dt>
  <dd>Writes a copy of a file with secrets and personal info hidden.</dd></div>
<div><dt><code>agentwatch detect</code></dt>
  <dd>Lists every program on this computer using AI right now.</dd></div>
<div><dt><code>agentwatch net</code></dt>
  <dd>Shows which servers local AI runtimes (Ollama, LM Studio, ...) talk to.</dd></div>
<div><dt><code>agentwatch statusline</code></dt>
  <dd>A short warning in Claude Code's status line when a session is in trouble.</dd></div>
<div><dt><code>agentwatch list-detectors</code></dt>
  <dd>Lists every check agentwatch runs.</dd></div>
<div><dt><code>agentwatch visual</code></dt>
  <dd>This page.</dd></div>
</dl>
</div></footer>
<script>
"use strict";
const T = new URLSearchParams(location.search).get("t") || "";
// [tab id, label, intro, [endpoint, title, run button label or null], ...]
// Tools and Config tabs are added here once #198 and #196 merge.
const TABS = [
  ["overview", "Overview",
    "What your AI agents are doing on this computer right now. Updates by itself.",
    ["ps", "Running agents", null], ["check", "Health of the newest session", null],
    ["security-scan", "Security of the newest session", null],
    ["subagents", "Subagents of the newest session", null]],
  ["security", "Security", "Secrets, risky commands and data leaving your machine.",
    ["security-scan", "Security of the newest session", null],
    ["audit", "Secrets in all saved sessions", "Run audit"]],
  ["cost", "Cost", "Tokens and estimated spend. Prices are estimates.",
    ["stats", "Claude Code usage, all projects", null],
    ["report", "Last 7 days, from history", null]],
  ["history", "History", "Sessions agentwatch has recorded on this computer.",
    ["history", "Recorded sessions", "Sync history"]],
];
const LABELS = {
  agent_type: "Agent", working_directory: "Folder", pid: "PID", cpu_percent: "CPU",
  memory_mb: "Memory", uptime: "Running for", overall_score: "Health score",
  security_score: "Security score", warning_count: "Findings", session_id: "Session",
  log_file: "Log file", session_fallback: "Note", estimated_cost_usd: "Estimated cost",
  cost_usd: "Cost", waste_usd: "Wasted", waste_pct: "Wasted share", health_score: "Health",
  total_tokens: "Total tokens", tool_calls: "Tool calls", action_count: "Actions",
  cache_hit_ratio: "Cache hits", secret_type: "Secret", matched_prefix: "Ends with",
  project_name: "Project", is_security: "Security finding",
};
function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}
function human(k) {
  if (LABELS[k]) return LABELS[k];
  const s = String(k).replace(/_(usd|pct|mb)$/, "").replace(/_/g, " ");
  return s.charAt(0).toUpperCase() + s.slice(1);
}
function plural(n, one, many) { return `${n} ${n === 1 ? one : many || one + "s"}`; }
function money(v) {
  if (v === null || v === undefined) return "Unpriced";
  return v > 0 && v < 0.01 ? "<$0.01" : "$" + v.toFixed(2);
}
function num(v) {
  if (!Number.isFinite(v)) return String(v);
  if (Number.isInteger(v)) return v.toLocaleString();
  if (Math.abs(v) < 1) return String(+v.toPrecision(2));
  return v.toLocaleString(undefined, {maximumFractionDigits: 1});
}
function when(v) {
  const d = typeof v === "number" ? new Date(v * 1000) : new Date(v);
  if (isNaN(d)) return String(v);
  return d.toLocaleString(undefined, {dateStyle: "medium", timeStyle: "short"});
}
// One value as display text: money, percent, dates, yes/no.
function fmt(k, v) {
  if (v === null || v === undefined) return k.endsWith("_usd") ? "Unpriced" : "None";
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
// A sparkline of series *key*; the value is always shown next to it as text.
function spark(key, label) {
  const a = series.get(key) || [], w = 120, h = 28;
  const s = svg("svg", {viewBox: `0 0 ${w} ${h}`, class: "spark", role: "img",
    "aria-label": `${label}: ${a.length ? num(a[a.length - 1]) : "no data"}, ` +
      `last ${a.length} samples`});
  if (a.length < 2) return s;
  const lo = Math.min(...a), hi = Math.max(...a), span = hi - lo || 1;
  const pts = a.map((v, i) => [i / (a.length - 1) * (w - 4) + 2,
    h - 3 - (v - lo) / span * (h - 6)]);
  s.append(svg("path", {d: pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " +
    p[1].toFixed(1)).join("")}), svg("circle", {cx: pts[pts.length - 1][0],
    cy: pts[pts.length - 1][1], r: 3}));
  return s;
}
// Horizontal bars: rows = [label, value, value text].
function bars(rows) {
  const g = el("div", null, "bars"), top = Math.max(...rows.map(r => r[1]), 1);
  for (const [label, v, text] of rows) {
    const s = svg("svg", {viewBox: "0 0 100 10", preserveAspectRatio: "none",
      "aria-hidden": "true"});
    s.append(svg("rect", {class: "bg", width: 100, height: 10, rx: 2}),
      svg("rect", {class: "fg", width: Math.max(v / top * 100, 1), height: 10, rx: 2}));
    g.append(el("span", label, "l"), s, el("span", text, "v"));
  }
  return g;
}
function ago(at) {
  const s = Math.max(0, Math.round((Date.now() - at) / 1000));
  return s < 5 ? "just now" : s < 60 ? s + " s ago" : s < 3600 ? Math.floor(s / 60) +
    " min ago" : Math.floor(s / 3600) + " h ago";
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
function tone(score) {
  if (score === null || score === undefined) return "";
  return score >= 80 ? "ok" : score >= 60 ? "degraded" : score >= 40 ? "warn" : "bad";
}
const SEVERITY = {critical: "bad", high: "warn", medium: "degraded", low: ""};
function chip(text, cls) { return el("span", text, "chip " + (cls || "")); }
function verdict(score, status, label) {
  const v = el("div", null, "verdict");
  const s = el("p", null, "score");
  s.append(String(score), el("small", " / 100 " + label));
  v.append(s, chip(status, tone(score)));
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
function table(rows, cols, caption) {
  const wrap = el("div", null, "scroll"), t = el("table", null, "stack");
  if (caption) t.append(el("caption", caption));
  const head = el("thead"), hr = el("tr");
  cols.forEach(([, label, kind]) => {
    const th = el("th", label, kind === "num" ? "num" : "");
    th.scope = "col";
    hr.append(th);
  });
  head.append(hr);
  const body = el("tbody");
  rows.forEach(row => {
    const tr = el("tr");
    cols.forEach(([k, label, kind]) => {
      const td = el("td", null, kind === "num" ? "num" : kind === "code" ? "code" : "");
      td.dataset.label = label;
      const v = typeof kind === "function" ? kind(row) : row[k];
      if (kind === "sev") td.append(chip(v, SEVERITY[v]));
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
    if (!v.length) return el("p", "None", "mute");
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
  const det = el("details");
  det.append(el("summary", "All fields"), render(d));
  return det;
}
function findings(list, empty) {
  if (!list.length) return el("p", empty, "mute");
  return table(list, [
    ["severity", "Severity", "sev"], ["message", "What happened"],
    ["fix", "What to do", r => r.suggestion || (r.details || {}).remediation || "No specific step"],
  ], plural(list.length, "finding"));
}
function note(text) { return text ? el("p", text, "mute") : null; }
// What one agent is doing now, in words. Text and chips only, never colour alone.
const VERBS = {Edit: "Edited", MultiEdit: "Edited", NotebookEdit: "Edited", Write: "Wrote",
  Read: "Read", Bash: "Ran", Grep: "Searched", Glob: "Searched", WebFetch: "Fetched",
  WebSearch: "Searched the web"};
function statusParts(s) {
  if (!s) return [el("p", "Checking what it is doing...", "mute")];
  const out = [], la = s.last_action;
  if (!la) out.push(el("p", s.health ? "No tool calls yet." :
    "Activity not available for this agent type.",
    "mute"));
  else {
    const p = el("p", null, "doing");
    const sub = !la.target && (la.tool === "Agent" || la.tool === "Task");
    const what = sub ? "Started a subagent" :
      (VERBS[la.tool] || "Used " + la.tool) + (la.target ? " " + la.target : "");
    p.append(aged(what, Date.now() - (la.age_s || 0) * 1000));
    if (la.ok === false) p.append(" (failed)");
    out.push(p);
  }
  const row = el("div", null, "row");
  if (s.health) row.append(chip(`Health ${s.health.label} ${s.health.score}/100`,
    tone(s.health.score)));
  if (s.active !== null && s.active !== undefined)
    row.append(el("span", s.active ? "Working now" : "Idle"));
  if (s.health) row.append(el("span", "Cost " + money(s.cost_usd)));
  if (row.childElementCount) out.push(row);
  return out;
}
// Fill every card's status block in place; no card is rebuilt.
function decorate() {
  const by = new Map(((state.agents || {}).agents || []).map(a => [a.pid, a]));
  document.querySelectorAll(".card[data-pid]").forEach(c => {
    const box = c.querySelector(".status");
    if (box && state.agents) box.replaceChildren(...statusParts(by.get(+c.dataset.pid)));
  });
}
function statusBox(pid) {
  const box = el("div", null, "status");
  const s = ((state.agents || {}).agents || []).find(a => a.pid === pid);
  box.append(...statusParts(state.agents ? s : null));
  return box;
}
let pulling = false;
async function pullAgents() {
  if (pulling || document.hidden || expiredLink) return;
  if (!document.querySelector(".card[data-pid]")) return;
  pulling = true;
  try {
    const r = await fetch(`/api/agents?t=${encodeURIComponent(T)}`);
    const d = JSON.parse(await r.text());
    if (d.agents) { state.agents = d; decorate(); }
  } catch (e) {} finally { pulling = false; }
}
function cards(list) {
  const g = el("div", null, "cards");
  for (const a of list) {
    const c = el("div", null, "card" + (a.depth > 0 ? " child" : ""));
    c.dataset.pid = a.pid;
    const row1 = el("div", null, "row"), row2 = el("div", null, "row");
    row1.append(el("span", "Running for"), el("b", a.uptime));
    row2.append(el("span", "CPU " + fmt("cpu_percent", a.cpu_percent) + ", memory " +
      fmt("memory_mb", a.memory_mb)));
    c.append(el("h3", human(a.agent_type || "agent")),
      el("div", (a.project || "No project") + (a.team_name ? " - " + a.team_name : ""), "sub"),
      el("div", a.working_directory || "", "sub code"), statusBox(a.pid), row1, row2,
      spark("cpu:" + a.pid, "CPU of " + a.agent_type), el("div", "PID " + a.pid, "sub"));
    g.append(c);
  }
  return g;
}
// The answer in words, from what the Overview views last loaded.
const state = {};
function summary() {
  const box = document.getElementById("summary");
  if (!box) return;
  const {ps, check, sec, subs} = state, parts = [];
  if (ps) parts.push(ps.length ? plural(ps.length, "AI agent") + " running on this computer."
    : "No AI agents are running right now.");
  if (check) parts.push(`The newest session is ${String(check.status).toLowerCase()} ` +
    `(health ${check.overall_score}/100)` + (sec ? ` and ${String(sec.status).toLowerCase()} ` +
    `(security ${sec.security_score}/100)` : "") + ".");
  const cost = check && check.efficiency ? check.efficiency.cost_total : null;
  if (cost !== null && cost !== undefined) parts.push(`It has cost about ${money(cost)} so far.`);
  if (subs && subs.active) parts.push(`${plural(subs.active, "subagent")} working now.`);
  const tile = (label, value, unit, cls, key, what) => {
    const t = el("div", null, "tile"), v = el("div", null, "val");
    v.append(String(value), el("small", unit));
    t.append(el("div", label, "lbl"));
    t.append(v);
    if (cls) t.append(chip(what, cls));
    t.append(spark(key, label));
    return t;
  };
  const tiles = el("div", null, "tiles");
  if (ps) tiles.append(tile("Agents running", ps.length, "", "", "n:ps", ""));
  if (check) tiles.append(tile("Health", check.overall_score, " / 100", tone(check.overall_score),
    "n:health", check.status));
  if (sec) tiles.append(tile("Security", sec.security_score, " / 100", tone(sec.security_score),
    "n:sec", sec.status));
  if (cost !== null && cost !== undefined) tiles.append(tile("Cost so far", money(cost), "", "",
    "n:cost", ""));
  box.replaceChildren(el("p", parts.join(" ") || "Loading...", "plain"), tiles);
}
// Per report: the answer first, then all fields.
const VIEWS = {
  ps: d => [
    el("p", d.length ? plural(d.length, "agent") + " running." : "No agents running right now."),
    d.length ? cards(d) : null,
    d.length ? raw(d) : null],
  check: d => {
    const flagged = Object.entries(d.categories || {}).filter(([, c]) => c.warning_count);
    return [verdict(d.overall_score, d.status, "health"),
      findings(d.warnings || [], "No health findings."),
      flagged.length ? table(flagged.map(([name, c]) => ({name, ...c})),
        [["name", "Area", r => human(r.name)], ["score", "Score", "num"],
         ["status", "Status", r => chip(r.status, tone(r.score))],
         ["warning_count", "Findings", "num"]], "Areas with findings")
        : el("p", `All ${plural(Object.keys(d.categories || {}).length, "area")} clear.`, "mute"),
      d.efficiency ? facts([["Efficiency", d.efficiency.score + " / 100"],
        ["Advice", d.efficiency.recommendation || "None"],
        ["Cost so far", money(d.efficiency.cost_total)]]) : null,
      note(d.session_fallback), raw(d)];
  },
  "security-scan": d => [verdict(d.security_score, d.status, "security"),
    el("p", `${plural(d.warnings.length, "finding")} in ${plural(d.action_count, "action")}.`),
    findings(d.warnings, "No security findings."), note(d.session_fallback), raw(d)],
  audit: d => [
    el("p", `${plural(d.total_findings, "secret")} found in ` +
      `${plural(d.sessions_scanned, "session")}.`,
      "chip " + (d.total_findings ? "bad" : "ok")),
    d.findings.length ? table(d.findings, [["severity", "Severity", "sev"],
      ["secret_type", "Secret"], ["project_name", "Project"],
      ["matched_prefix", "Ends with", "code"], ["remediation", "What to do"]]) : null,
    raw(d)],
  stats: d => {
    const t = d.totals || {};
    const tools = Object.entries(d.by_tool || {}).map(([name, x]) => ({name, ...x}))
      .sort((a, b) => b.total_tokens - a.total_tokens);
    return [facts([["Sessions", num(d.sessions)], ["Messages", num(d.messages)],
      ["Tool calls", num(d.tool_calls)], ["Tokens", num(t.total_tokens || 0)],
      ["Estimated cost", money(t.estimated_cost_usd)],
      ["Cache hits", fmt("_ratio", t.cache_hit_ratio)]]),
      tools.length ? bars(tools.slice(0, 8).map(x => [x.name, x.total_tokens,
        num(x.total_tokens) + " tokens"])) : null,
      tools.length ? table(tools, [["name", "Tool"], ["call_count", "Calls", "num"],
        ["total_tokens", "Tokens", "num"], ["estimated_cost_usd", "Estimated cost", "num"]],
        "By tool") : null,
      raw(d)];
  },
  report: d => {
    const t = d.totals || {}, p = d.period || {};
    return [el("p", `${when(p.start)} to ${when(p.end)}`, "mute"),
      facts([["Sessions", num(t.sessions)], ["Cost", t.sessions ? money(t.cost_usd) : "None"],
        ["Wasted", !t.sessions ? "None" : money(t.waste_usd) +
          (t.waste_pct == null ? "" : ` (${num(t.waste_pct)}%)`)],
        ["Tokens", num(t.tokens)], ["Security findings", num((d.security || {}).total || 0)]]),
      t.sessions ? null : el("p", "No sessions in this period. Use Sync history on the " +
        "History tab to record them.", "mute"),
      raw(d)];
  },
  subagents: d => [
    el("p", d.total ? `${d.active} active, ${d.total} in all. Each is scored like the ` +
      "session above. Newest first." : "This session has not started any subagents.",
      d.total ? "" : "mute"),
    d.subagents.length ? table(d.subagents, [
      ["type", "Subagent", r => (r.depth > 1 ? "\u21b3 " : "") + r.type],
      ["description", "Task"],
      ["health_score", "Health", "num"],
      ["status", "Status", r => r.status ? chip(r.status, tone(r.health_score)) : "None"],
      ["cost_usd", "Cost", "num"], ["actions", "Actions", "num"],
      ["last_activity", "Last activity",
        r => r.active ? chip("active", "ok") : when(r.last_activity)],
      ["warnings", "Warnings",
        r => r.warnings.map(w => `${w.severity} ${w.signal}`).join(", ") || "None"],
    ]) : null,
    d.subagents.length ? raw(d) : null],
  history: d => [
    d.synced ? syncNote(d.synced, Date.now()) : lastSync ? syncNote(lastSync.d, lastSync.at) : null,
    d.sessions.length ? table(d.sessions, [["agent", "Agent"], ["project", "Project"],
      ["ended", "Last active"], ["actions", "Actions", "num"], ["tokens", "Tokens", "num"],
      ["cost_usd", "Cost", "num"], ["health_score", "Health", "num"],
      ["status", "Status", r => chip(r.status, tone(r.health_score))]])
      : el("p", "No sessions recorded yet. Sync history reads your agent logs into a local " +
        "database on this computer.", "mute")],
};
// The sync result is only in the answer to the click: keep it, with its age.
let lastSync = null;
function syncNote(s, at) {
  lastSync = {d: s, at};
  const p = el("p", `Synced: ${s.new} new, ${s.updated} updated, ${s.unchanged} unchanged` +
    (s.active ? `, ${s.active} skipped because the agent wrote to them in the last minute` : "")
    + ". ", "mute");
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
let expiredLink = false;
const SLACK = 1000;  // a tick may land just before its view turns one cadence old
const ranCache = new Map();  // name -> {parts text is rebuilt from d, at}
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
      return;
    }
    swap(body, parts);
    last.delete(sec);
    sec.classList.add("stale");
    stamp.replaceChildren(el("span", expired ? "Link expired" : "Not loaded"));
    return;
  }
  if (!(quiet && text !== undefined && text === last.get(sec))) swap(body, parts.filter(Boolean));
  last.set(sec, text);
  if (name === "ps" && !failed) pullAgents();  // one scan per tick, here
  sec.classList.remove("stale");
  stamp.dataset.ok = loadedAt.set(sec, Date.now()).get(sec);
  const when = aged(sec.dataset.cadence ? "Last updated" : "Loaded", Date.now());
  const dot = el("span", null, "pulse");
  dot.setAttribute("aria-hidden", "true");
  stamp.replaceChildren(...(sec.dataset.cadence ? [dot] : []), when);
  if (!sec.dataset.cadence || document.getElementById("summary")) summary();
}
// Series and cross-view state for the live charts and the summary.
// Samples are taken on timer ticks (and once to start a series), so a manual
// Refresh or a tab switch does not bend the time axis.
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
  const [tid, label, intro, ...secs] = TABS[i];
  document.querySelectorAll("[role=tab]").forEach((b, j) => {
    b.setAttribute("aria-selected", String(i === j));
    b.tabIndex = i === j ? 0 : -1;
  });
  document.title = label + " - agentwatch";
  const main = document.getElementById("panel");
  main.setAttribute("aria-labelledby", "tab-" + tid);
  main.replaceChildren(el("h1", label), el("p", intro, "lead"));
  if (tid === "overview") {
    const box = el("div"); box.id = "summary";
    main.append(box);
    summary();
  }
  for (const [name, title, button] of secs) {
    const sec = el("section"), head = el("div", null, "head");
    const h = el("h2", title), body = el("div", null, "body");
    h.id = "h-" + name;
    sec.setAttribute("aria-labelledby", h.id);
    sec.dataset.name = name;
    if (LIVE.has(name)) sec.dataset.cadence = LIVE_MS;
    else if (SLOW.has(name)) sec.dataset.cadence = SLOW_MS;
    if (sec.dataset.cadence) sec.classList.add("live");
    else body.setAttribute("aria-live", "polite");  // timer updates stay silent
    const again = el("button", "Refresh", "btn quiet");
    again.type = "button";
    again.onclick = () => load(sec, name, false);
    head.append(h);
    if (button) {
      const b = el("button", button, "btn primary");
      b.type = "button";
      b.onclick = () => load(sec, name, true);
      head.append(b);
    }
    if (!RUN_ONLY.has(name)) head.append(again);  // a plain reload would hide the audit
    head.append(el("p", null, "when"));
    sec.append(head, body); main.append(sec);
    const kept = ranCache.get(name);
    if (kept) {  // the audit's last result, kept while you look at other tabs
      const parts = VIEWS[name](kept.d), age = el("p", null, "mute");
      age.append(aged("Ran", kept.at));
      body.replaceChildren(age, ...parts.filter(Boolean));
    } else load(sec, name, false);
  }
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
const tabs = document.getElementById("tabs");
TABS.forEach(([id, label]) => {
  const b = el("button", label);
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
addEventListener("hashchange", () => show(location.hash.slice(1)));
// Theme: the system setting until the button is used; the choice is kept.
const themeBtn = document.getElementById("theme");
function dark() {
  const t = document.documentElement.dataset.theme;
  return t ? t === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
}
function syncTheme() {
  themeBtn.textContent = dark() ? "Light theme" : "Dark theme";
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
</script></body></html>
"""
