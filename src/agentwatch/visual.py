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
<title>agentwatch</title>
<style>
:root{color-scheme:light dark;--bg:#fff;--fg:#1d1d1f;--mute:#666;--line:#ddd;
--card:#f6f6f7;--acc:#2456c7;
--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e}
@media (prefers-color-scheme:dark){:root{--bg:#16171a;--fg:#e6e6e6;--mute:#9a9a9a;
--line:#33353a;--card:#1f2125;--acc:#7aa2ff;--ok:#4ac26b;--warn:#d4a72c;--bad:#ff6b6b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,sans-serif}
header{padding:12px 16px;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;
gap:8px;align-items:center}
header b{margin-right:12px}
nav button,.act{background:none;border:1px solid var(--line);color:var(--fg);border-radius:6px;
padding:6px 12px;font:inherit;cursor:pointer}
nav button[aria-selected=true]{border-color:var(--acc);color:var(--acc)}
main{padding:16px;max-width:1100px;margin:auto}
section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;
margin-bottom:16px;overflow-x:auto}
h2{font-size:16px;margin:0 0 8px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.sum{font-size:20px;margin:4px 0 8px}.mute{color:var(--mute)}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:4px 8px;border-bottom:1px solid var(--line);vertical-align:top}
td{min-width:9ch;max-width:48ch;overflow-wrap:anywhere}
th{color:var(--mute);font-weight:600;white-space:nowrap}
</style></head><body>
<header><b>agentwatch</b><nav id="tabs"></nav></header>
<main id="main"></main>
<script>
"use strict";
const T = new URLSearchParams(location.search).get("t") || "";
// [tab, [endpoint, title, button label or null], ...]
// Tools and Config tabs are added here once #198 and #196 merge.
const TABS = [
  ["Overview", ["ps", "Running agents", null], ["check", "Health check (newest session)", null]],
  ["Security", ["security-scan", "Security scan (newest session)", null],
               ["audit", "Secret audit (all projects)", "Run audit"]],
  ["Cost", ["stats", "Claude Code token usage (all projects)", null],
           ["report", "Report, last 7 days (from history)", null]],
  ["History", ["history", "Recorded sessions", "Sync history"]],
];
function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}
function cell(v) {
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return JSON.stringify(v);
  if (typeof v === "number" && !Number.isInteger(v)) return v.toFixed(2);
  return v;
}
// Generic renderer: list of objects -> table, object -> key/value rows.
function render(v) {
  if (Array.isArray(v)) {
    if (!v.length) return el("p", "None.", "mute");
    if (typeof v[0] !== "object" || v[0] === null) return el("p", v.join(", "));
    const keys = [...new Set(v.flatMap(o => Object.keys(o || {})))];
    const t = el("table"), hr = el("tr");
    keys.forEach(k => hr.append(el("th", k)));
    t.append(hr);
    v.forEach(o => {
      const r = el("tr");
      keys.forEach(k => r.append(el("td", cell((o || {})[k]))));
      t.append(r);
    });
    return t;
  }
  if (v && typeof v === "object") {
    const t = el("table");
    for (const [k, x] of Object.entries(v)) {
      const r = el("tr"), td = el("td");
      r.append(el("th", k));
      if (x && typeof x === "object" && (!Array.isArray(x) || x.length)) td.append(render(x));
      else td.textContent = cell(Array.isArray(x) ? "" : x);
      r.append(td); t.append(r);
    }
    return t;
  }
  return el("p", cell(v));
}
function scoreClass(n) { return n >= 80 ? "ok" : n >= 50 ? "warn" : "bad"; }
function summary(name, d) {
  let text = null, cls = "";
  if (name === "check") {
    text = `Health ${d.overall_score} (${d.status})`;
    cls = scoreClass(d.overall_score);
  } else if (name === "security-scan") {
    text = `Security ${d.security_score} (${d.status}), ` +
      `${d.warnings.length} finding(s) in ${d.action_count} actions`;
    cls = scoreClass(d.security_score);
  } else if (name === "audit") {
    text = `${d.total_findings} finding(s) in ${d.sessions_scanned} session(s)`;
    cls = d.total_findings ? "bad" : "ok";
  } else if (name === "ps") {
    text = `${d.length} agent(s) running`;
  }
  return text === null ? null : el("p", text, "sum " + cls);
}
async function load(sec, name, run) {
  const body = sec.querySelector(".body");
  body.replaceChildren(el("p", run ? "Running..." : "Loading...", "mute"));
  try {
    const r = await fetch(`/api/${name}?t=${encodeURIComponent(T)}${run ? "&run=1" : ""}`);
    const d = await r.json();
    if (d.error) { body.replaceChildren(el("p", d.error, "warn")); return; }
    if (d.not_run) {
      body.replaceChildren(el("p", "Not run yet: it reads every session log.", "mute"));
      return;
    }
    const parts = [summary(name, d), render(name === "history" ? d.sessions : d)];
    if (name === "history" && d.synced) {
      parts.unshift(el("p", "Synced: " + JSON.stringify(d.synced), "mute"));
    }
    body.replaceChildren(...parts.filter(Boolean));
  } catch (e) { body.replaceChildren(el("p", "Request failed: " + e, "bad")); }
}
function show(i) {
  document.querySelectorAll("nav button")
    .forEach((b, j) => b.setAttribute("aria-selected", i === j));
  const main = document.getElementById("main");
  main.replaceChildren();
  for (const [name, title, button] of TABS[i].slice(1)) {
    const sec = el("section"), h = el("h2", title), body = el("div", null, "body");
    const again = el("button", "Refresh", "act");
    again.onclick = () => load(sec, name, false);
    h.append(again);
    if (button) {
      const b = el("button", button, "act");
      b.onclick = () => load(sec, name, true);
      h.append(b);
    }
    sec.append(h, body); main.append(sec);
    load(sec, name, false);
  }
}
TABS.forEach(([label], i) => {
  const b = el("button", label);
  b.onclick = () => show(i);
  document.getElementById("tabs").append(b);
});
show(0);
</script></body></html>
"""
