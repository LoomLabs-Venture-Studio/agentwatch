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
import secrets
import sqlite3
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from agentwatch import cli
from agentwatch.cc_stats import compute_stats, find_all_project_dirs
from agentwatch.detectors.security.secret_scanner import assess_impact, redact_truncate
from agentwatch.history import connect, sync
from agentwatch.parser.logs import LogUnreadableError, UnsupportedLogFormatError
from agentwatch.report import build

_STR_LIMIT = 2000


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


def _security(run: bool):
    warnings, buffer, note = _scan("security")
    return cli._security_json(warnings, buffer, note)


def _audit(run: bool):
    if not run:
        return {"not_run": True}
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
        synced = sync(conn) if run else None
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT agent, session_id, project, started, ended, actions, tokens,"
            " cost_usd, waste_usd, health_score, status"
            " FROM sessions ORDER BY ended DESC LIMIT 200"
        ).fetchall()
    return {"synced": synced, "sessions": [dict(r) for r in rows]}


API = {
    "ps": _ps,
    "check": _check,
    "security-scan": _security,
    "audit": _audit,
    "stats": _stats,
    "report": _report,
    "history": _history,
}


def redact(value: Any) -> Any:
    """Every string (keys too) in *value* through redact_truncate."""
    if isinstance(value, str):
        return redact_truncate(value, _STR_LIMIT)
    if isinstance(value, dict):
        return {redact(k): redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


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
        body = json.dumps(redact(data), default=str).encode()
        self._send(code, body, "application/json")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # The request line carries the token: mask it.
        super().log_message("%s", (format % args).replace(self.server.token, "[token]"))


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
p{margin:0;text-wrap:pretty}
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
  .btn,[role=tab]{transition:color .15s,background-color .15s}}
</style></head><body>
<header><div class="bar">
<span class="brand"><svg viewBox="0 0 24 24" aria-hidden="true">
<path d="M2 12h4l3-8 6 16 3-8h4"/></svg>agentwatch</span>
<div role="tablist" aria-label="Reports" id="tabs"></div>
<button class="btn quiet" id="theme" type="button">Dark theme</button>
</div></header>
<main><div id="panel" role="tabpanel"></div></main>
<script>
"use strict";
const T = new URLSearchParams(location.search).get("t") || "";
// [tab id, label, intro, [endpoint, title, run button label or null], ...]
// Tools and Config tabs are added here once #198 and #196 merge.
const TABS = [
  ["overview", "Overview", "Your running agents and the newest session's health.",
    ["ps", "Running agents", null], ["check", "Health of the newest session", null]],
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
// Per report: the answer first, then all fields.
const VIEWS = {
  ps: d => [
    el("p", d.length ? plural(d.length, "agent") + " running." : "No agents running right now."),
    d.length ? table(d, [["agent_type", "Agent"], ["project", "Project"],
      ["working_directory", "Folder", "code"], ["pid", "PID", "num"],
      ["cpu_percent", "CPU", "num"], ["memory_mb", "Memory", "num"],
      ["uptime", "Running for"]]) : null,
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
  history: d => [
    d.synced ? el("p", `Synced: ${d.synced.new} new, ${d.synced.updated} updated, ` +
      `${d.synced.unchanged} unchanged` + (d.synced.active ? `, ${d.synced.active} skipped ` +
      "because the agent wrote to them in the last minute" : "") + ".", "mute") : null,
    d.sessions.length ? table(d.sessions, [["agent", "Agent"], ["project", "Project"],
      ["ended", "Last active"], ["actions", "Actions", "num"], ["tokens", "Tokens", "num"],
      ["cost_usd", "Cost", "num"], ["health_score", "Health", "num"],
      ["status", "Status", r => chip(r.status, tone(r.health_score))]])
      : el("p", "No sessions recorded yet. Sync history reads your agent logs into a local " +
        "database on this computer.", "mute")],
};
const busy = new WeakMap();
async function load(sec, name, run) {
  const body = sec.querySelector(".body"), stamp = sec.querySelector(".when");
  const seq = (busy.get(sec) || 0) + 1;
  busy.set(sec, seq);
  sec.querySelectorAll("button").forEach(b => { b.disabled = true; });
  body.setAttribute("aria-busy", "true");
  body.replaceChildren(el("p", run ? "Running. This can take a minute..." : "Loading...", "mute"));
  let parts;
  try {
    const r = await fetch(`/api/${name}?t=${encodeURIComponent(T)}${run ? "&run=1" : ""}`);
    if (r.status === 403) throw new Error("This link has expired. Open the address that " +
      "agentwatch visual printed in your terminal.");
    const d = await r.json();
    if (d.error) parts = [problem("Nothing to show yet.", d.error)];
    else if (d.not_run) parts = [el("p", "Not run yet. The audit reads every saved session " +
      "log, so it can take a while.", "mute")];
    else parts = VIEWS[name](d);
  } catch (e) {
    parts = [problem("Could not load this report.", e instanceof TypeError ?
      "agentwatch is not answering. Is agentwatch visual still running?" : e.message)];
  }
  if (busy.get(sec) !== seq) return;  // a newer load replaced this one
  body.replaceChildren(...parts.filter(Boolean));
  body.removeAttribute("aria-busy");
  stamp.textContent = "Updated " + new Date().toLocaleTimeString(undefined, {timeStyle: "short"});
  sec.querySelectorAll("button").forEach(b => { b.disabled = false; });
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
  for (const [name, title, button] of secs) {
    const sec = el("section"), head = el("div", null, "head");
    const h = el("h2", title), body = el("div", null, "body");
    h.id = "h-" + name;
    sec.setAttribute("aria-labelledby", h.id);
    body.setAttribute("aria-live", "polite");
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
    head.append(again, el("p", null, "when"));
    sec.append(head, body); main.append(sec);
    load(sec, name, false);
  }
}
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
