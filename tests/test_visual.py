"""`agentwatch visual` (Sprint 41 item 1): local page, token + Host gate,
redacted JSON, and the --json builders it shares with the commands."""

from __future__ import annotations

import http.client
import json
import re
import shutil
import threading
from datetime import datetime
from pathlib import Path

import pytest
from click.testing import CliRunner

from agentwatch import agent_status, visual
from agentwatch.agents.claude_code import ClaudeCodeAdapter
from agentwatch.cli import cli
from agentwatch.discovery import AgentProcess

FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "ghp_" + "Zq8wXv3Lk9Pm2Rt7Yb4Nc6Hd1Fg5Js0Ae8Ui3"  # fake GitHub PAT
AGENT = AgentProcess(pid=42, agent_type="claude-code", working_directory=Path("/w"),
                     log_file=Path(f"/w/{SECRET}.jsonl"), command="claude")


SVG_NS = "http://www.w3.org/2000/svg"
# The one place the namespace may appear: the constant that createElementNS uses.
NS_DECL = f'SVGNS = "{SVG_NS}"'


def _no_ns(page):
    assert page.count(NS_DECL) == 1
    return page.replace(NS_DECL, "SVGNS = ns")


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    projects = tmp_path / "projects"
    proj = projects / "-home-x-demo"
    proj.mkdir(parents=True)
    shutil.copy(FIXTURES / "check_security_critical.jsonl", proj / "a.jsonl")
    entry = {
        "type": "assistant", "sessionId": "leak", "timestamp": "2026-11-01T10:00:00Z",
        "cwd": "/home/x/demo",
        "message": {"role": "assistant", "content": [{
            "type": "tool_use", "id": "t1", "name": "Bash",
            "input": {"command": f"export GH_TOKEN={SECRET} && cat .env"},
        }], "usage": {"input_tokens": 10, "output_tokens": 5}},
    }
    (proj / "leak.jsonl").write_text(json.dumps(entry) + "\n", encoding="utf-8")
    monkeypatch.setattr("agentwatch.cc_stats.CLAUDE_PROJECTS_DIR", projects)
    monkeypatch.setattr("agentwatch.parser.logs.DEFAULT_SEARCH_PATHS", [projects])
    monkeypatch.setattr("agentwatch.agents.ADAPTERS", [ClaudeCodeAdapter()])
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr("agentwatch.cli.find_running_agents", lambda: [AGENT])
    monkeypatch.setattr(
        "agentwatch.detectors.security.secret_scanner._build_active_session_map", dict)
    monkeypatch.chdir(tmp_path)
    return proj


@pytest.fixture
def server():
    srv = visual.make_server(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _get(srv, path, *, method="GET", host=None, token=True):
    port = srv.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    if token:
        path += ("&" if "?" in path else "?") + f"t={srv.token}"
    conn.putrequest(method, path, skip_host=True)
    conn.putheader("Host", host or f"127.0.0.1:{port}")
    conn.endheaders()
    r = conn.getresponse()
    return r, r.read().decode()


def test_binds_loopback_only(server):
    assert server.server_address[0] == "127.0.0.1"


@pytest.mark.parametrize("path", ["/", "/api/ps", "/api/ps?t=wrong", "/?t="])
def test_missing_or_wrong_token_is_403(server, path):
    r, _ = _get(server, path, token=False)
    assert r.status == 403


@pytest.mark.parametrize("host", ["evil.example:80", "127.0.0.1", "127.0.0.1:1",
                                  "attacker.test"])
def test_bad_host_is_403(server, host):
    r, _ = _get(server, "/api/ps", host=host)
    assert r.status == 403


def test_localhost_host_allowed(server, sandbox):
    r, _ = _get(server, "/api/ps", host=f"localhost:{server.server_address[1]}")
    assert r.status == 200


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def test_only_get(server, method):
    r, _ = _get(server, "/api/audit?run=1", method=method)
    assert r.status == 405


def test_page_headers_and_no_external_urls(server):
    r, body = _get(server, "/")
    assert r.status == 200
    csp = r.getheader("Content-Security-Policy")
    assert "default-src 'self'" in csp
    assert r.getheader("X-Content-Type-Options") == "nosniff"
    assert r.getheader("Referrer-Policy") == "no-referrer"
    assert r.getheader("Access-Control-Allow-Origin") is None
    assert not re.search(r"https?://", _no_ns(body))
    assert "innerHTML" not in body


def test_every_endpoint_json_and_secret_never_sent(server, sandbox):
    bodies = []
    for name in visual.API:
        for q in ("", "?run=1"):
            r, body = _get(server, f"/api/{name}{q}")
            assert r.status == 200, (name, body)
            assert r.getheader("Content-Type").startswith("application/json")
            data = json.loads(body)
            assert "error" not in data if isinstance(data, dict) else True, (name, data)
            bodies.append(body)
    joined = "\n".join(bodies)
    assert SECRET not in joined
    assert SECRET[4:20] not in joined
    # The secret really was in the data: audit found it.
    _, audit = _get(server, "/api/audit?run=1")
    assert json.loads(audit)["total_findings"] >= 1


def test_audit_waits_for_button(server, sandbox):
    _, body = _get(server, "/api/audit")
    assert json.loads(body) == {"not_run": True}


def test_unknown_api_404(server):
    r, _ = _get(server, "/api/nope")
    assert r.status == 404


def test_log_lines_hide_token(server, capsys):
    _get(server, "/api/nope")
    err = capsys.readouterr().err
    assert "/api/nope" in err and server.token not in err


def test_redact_walks_nested():
    out = visual.redact({"a": [SECRET, {"b": (SECRET, 1)}], SECRET: None})
    assert SECRET not in json.dumps(out)


def test_redact_non_json_values_become_redacted_strings():
    class Obj:
        def __str__(self):
            return f"obj {SECRET}"

    when = datetime(2026, 11, 1, 10, 0)
    out = visual.redact({"p": Path(f"/w/{SECRET}.jsonl"), "o": [Obj()], "d": when,
                         "n": [1, 2.5, True, None]})
    text = json.dumps(out)  # no default=: everything is JSON already
    assert SECRET not in text
    assert out["d"] == str(when) and out["n"] == [1, 2.5, True, None]


def test_log_lines_hide_percent_encoded_token(server, capsys):
    encoded = "".join(f"%{ord(c):02X}" for c in server.token)
    r, _ = _get(server, f"/api/nope?t={encoded}&x=1", token=False)
    assert r.status == 404  # parse_qs decodes it: the token is accepted
    err = capsys.readouterr().err
    assert encoded not in err and server.token not in err
    assert "t=[token]&x=1" in err


def test_concurrent_history_sync_runs_one_at_a_time(sandbox, monkeypatch):
    active, peak, calls = [0], [0], []
    gate = threading.Event()

    def fake_sync(conn):
        active[0] += 1
        peak[0] = max(peak[0], active[0])
        gate.wait(0.3)
        calls.append(1)
        active[0] -= 1
        return {"scanned": 0}

    monkeypatch.setattr(visual, "sync", fake_sync)
    threads = [threading.Thread(target=visual._history, args=(True,)) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    assert len(calls) == 2 and peak[0] == 1


def test_audit_run_shares_the_lock(sandbox, monkeypatch):
    seen = []
    monkeypatch.setattr(visual.cli, "_audit_scan",
                        lambda *a: seen.append(visual._RUN_LOCK.locked()) or ([], 0, {}))
    with pytest.raises(visual._NoDataError):
        visual._audit(True)
    assert seen == [True]


# The commands' --json output is exactly the shared builders' output.

def _cli_json(args):
    r = CliRunner().invoke(cli, [*args, "--json"])
    return r.stdout


def _dumps(payload):
    return json.dumps(payload, indent=2) + "\n"


def test_ps_json_matches_builder(sandbox):
    assert _cli_json(["ps"]) == _dumps(visual.API["ps"](False))


def _page_only(payload):
    # visual adds one field the command doesn't have: the fallback's project.
    payload.pop("session_project")
    return payload


def test_check_json_matches_builder(sandbox):
    assert _cli_json(["check"]) == _dumps(_page_only(visual.API["check"](False)))


def test_security_json_matches_builder(sandbox):
    assert _cli_json(["security-scan"]) == _dumps(_page_only(visual.API["security-scan"](False)))


def test_fallback_project_is_a_folder_name_not_the_encoded_dir(sandbox):
    for name in ("check", "security-scan"):
        data = visual.API[name](False)
        assert data["session_fallback"]  # tmp cwd has no session: fallback used
        assert data["session_project"] == "demo", data["session_project"]


def test_audit_json_matches_builder(sandbox):
    assert _cli_json(["audit", "--all"]) == _dumps(visual.API["audit"](True))


def test_stats_json_matches_builder(sandbox):
    assert _cli_json(["stats", "--all"]) == _dumps(visual.API["stats"](False))


def test_audit_json_shape_unchanged(sandbox):
    out = json.loads(_cli_json(["audit", "--all"]))
    assert list(out) == ["projects", "sessions_scanned", "total_findings", "redacted",
                         "skipped_active", "backups", "redact_errors", "findings"]
    assert out["findings"][0]["secret_type"] == "github_pat"


def test_cli_no_open_prints_url_once(monkeypatch):
    seen = {}

    def fake_serve(port, open_browser):
        seen.update(port=port, open_browser=open_browser)

    monkeypatch.setattr(visual, "serve", fake_serve)
    r = CliRunner().invoke(cli, ["visual", "--no-open", "--port", "0"])
    assert r.exit_code == 0
    assert seen == {"port": 0, "open_browser": False}


def test_serve_prints_tokened_url_and_stops_on_ctrl_c(monkeypatch, capsys):
    opened = []
    monkeypatch.setattr("webbrowser.open", opened.append)

    def interrupt(self):
        raise KeyboardInterrupt

    monkeypatch.setattr(visual._Server, "serve_forever", interrupt)
    visual.serve(0, open_browser=True)
    out = capsys.readouterr().out
    url = re.search(r"http://127\.0\.0\.1:\d+/\?t=\S+", out).group(0)
    assert opened == [url] and out.count(url) == 1 and "Stopped." in out


# Sprint 46: live page. The page source is checked as text (no browser here).

def _js_set(name):
    m = re.search(rf"const {name} = new Set\(\[([^\]]*)\]\)", visual.PAGE)
    assert m, name
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def test_every_view_has_a_refresh_path():
    live, slow, run_only = _js_set("LIVE"), _js_set("SLOW"), _js_set("RUN_ONLY")
    assert live | slow | run_only == set(visual.API)
    assert not (live & slow) and not (live | slow) & run_only
    assert run_only == {"audit"}


def test_timers_never_pass_run():
    # run=1 reads every saved log: only a click (run === true) may send it, and
    # every timer path calls load(..., false, true).
    timers = re.findall(r"setInterval\((.*?)\n\}, \w+\);", visual.PAGE, re.S)
    assert len(timers) >= 2
    for t in timers:
        assert "true)" not in t.replace("false, true)", "")
        assert "RUN_ONLY" in t or "LIVE" in t or "SLOW" in t
    assert visual.PAGE.count("load(sec, name, true)") == 1  # the run button


def test_csp_is_unchanged():
    assert visual.CSP == ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
                          "style-src 'self' 'unsafe-inline'; img-src 'none'; "
                          "frame-ancestors 'none'")


def test_page_builds_dom_without_html_strings_or_foreign_resources():
    page = visual.PAGE
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                "<canvas", "@import", "<link", "eval(", "new Function"):
        assert bad not in page, bad
    assert "createElementNS" in page
    assert not re.search(r"https?://", _no_ns(page))
    assert "url(" not in page
    for m in re.finditer(r"fetch\(([^)]*)\)", page):
        assert m.group(1).startswith("`/api/"), m.group(1)


def test_page_has_a11y_and_motion_basics():
    page = visual.PAGE
    assert "prefers-reduced-motion" in page and ":focus-visible" in page
    assert 'role="tablist"' in page and "agentwatch-theme" in page


def test_unauthenticated_page_still_403_and_authed_serves_new_page(server):
    r, _ = _get(server, "/", token=False)
    assert r.status == 403
    r, body = _get(server, "/")
    assert r.status == 200 and "Last updated" in body


def _fn(name):
    m = re.search(rf"\n(?:async )?function {name}\(.*?\n\}}\n", visual.PAGE, re.S)
    assert m, name
    return m.group(0)


def test_refresh_is_quiet_hidden_aware_and_never_runs():
    body = _fn("refresh")
    assert "if (document.hidden || expiredLink) return;" in body
    assert body.count("load(") == 1
    assert "load(sec, sec.dataset.name, false, true)" in body
    assert "run" not in body and "=1" not in body


def test_visibilitychange_only_refreshes_with_a_min_age():
    m = re.search(r'addEventListener\("visibilitychange", (.*?)\n\}\);\n', visual.PAGE, re.S)
    assert m
    handler = m.group(1)
    assert "load(" not in handler and "fetch" not in handler and "run" not in handler
    assert "refresh(LIVE, LIVE_MS)" in handler and "refresh(SLOW, SLOW_MS)" in handler
    assert "Date.now() - (loadedAt.get(sec) || 0) < minAge" in _fn("refresh")


def test_series_are_capped_and_pruned():
    assert "const SAMPLES = 60" in visual.PAGE
    body = _fn("sample")
    assert "a.length > SAMPLES" in body and "a.shift()" in body
    feed = _fn("feed")
    assert "series.delete(k)" in feed and 'k.startsWith("cpu:")' in feed
    assert "tick || !series.has(k)" in feed  # manual Refresh does not add samples


def test_failed_timer_reload_rules():
    body = _fn("load")
    assert 'sec.classList.add("stale")' in body and "Showing data from" in body
    assert "expired = expiredLink = true" in body and "quiet && !expired && ok" in body
    assert "stamp.dataset.ok = " in body  # age is that of the last success only
    assert "+stamp.dataset.ok || Date.now()" not in body


def test_run_param_only_when_the_run_argument_is_true():
    assert visual.PAGE.count("run=1") == 1
    assert '${run ? "&run=1" : ""}' in _fn("load")
    assert "expired = expiredLink = true" in _fn("load")  # a dead link stops the timers


def test_timer_ticks_skip_fresh_views():
    ticks = re.findall(r"setInterval\(\(\) => \{\n  (refresh\([^\n]*\));\n\}, (\w+)\);",
                       visual.PAGE)
    assert ticks == [("refresh(LIVE, LIVE_MS - SLACK)", "LIVE_MS"),
                     ("refresh(SLOW, SLOW_MS - SLACK)", "SLOW_MS")]

# Per-agent status on the cards.

@pytest.mark.parametrize("kw", [{"token": False}, {"host": "evil.example:80"}])
def test_agents_endpoint_needs_token_and_host(server, kw):
    r, _ = _get(server, "/api/agents", **kw)
    assert r.status == 403


def test_agents_endpoint_is_read_only_and_has_no_secret(server, sandbox, monkeypatch):
    agent = AgentProcess(pid=7, agent_type="claude-code", working_directory=Path("/w"),
                         log_file=sandbox / "leak.jsonl", command="claude")
    monkeypatch.setattr("agentwatch.cli.find_running_agents", lambda: [agent, AGENT])
    r, body = _get(server, "/api/agents")
    data = json.loads(body)
    assert r.status == 200 and [a["pid"] for a in data["agents"]] == [7, 42]
    assert data["agents"][0]["last_action"]["tool"] == "Bash"
    assert data["agents"][0]["last_action"]["target"] == "export"  # program only
    assert data["agents"][1]["health"] is None  # no readable log
    assert SECRET not in body and "cat .env" not in body
    built = json.dumps(agent_status.build([agent, AGENT]))  # builder itself, before redact
    assert SECRET not in built and "cat .env" not in built and "GH_TOKEN" not in built
    r, _ = _get(server, "/api/agents", method="POST")
    assert r.status == 405


def test_page_has_agent_status_refresh_path():
    assert "agents" in _js_set("LIVE")
    assert "/api/agents?t=" in visual.PAGE and "pullAgents" in visual.PAGE
    assert "dataset.pid" in visual.PAGE


# Sprint 47: status tones, human labels, sparklines (ui-ux-pro-max redesign).

def test_status_tones_security_tiers_are_not_health_bands():
    tones = visual.status_tones()
    assert tones["security"] == {"secure": "good", "at_risk": "warn", "compromised": "bad"}
    assert tones["security"]["at_risk"] != "good"  # Sprint 46 showed a green dot


def test_status_tones_cover_every_theme_level():
    from agentwatch.themes import THEMES
    health = visual.status_tones()["health"]
    for theme in THEMES.values():
        assert health[theme.level_0] == "good", theme.name
        assert health[theme.level_1] != "good", theme.name
        assert health[theme.level_3] == "bad", theme.name
    assert health["productive"] == "good" and health["stuck"] == "bad"
    assert health["warning"] == "bad"  # classic level_2 beats ascii level_1: worse wins


def test_page_embeds_names_and_tones_from_the_server_code():
    from agentwatch.agents import DISPLAY_NAMES
    m = re.search(r"\nconst DATA = (\{.*\});\n", visual.PAGE)
    assert m and "__PAGE_DATA__" not in visual.PAGE
    data = json.loads(m.group(1))
    assert data == {"names": DISPLAY_NAMES, "tones": visual.status_tones()}


def test_security_views_use_security_tone():
    page = visual.PAGE
    assert page.count("securityTone(d.security_score, d.status)") == 1
    assert "securityTone(sec.security_score, sec.status)" in page
    assert "tone(sec.security_score" not in page and "tone(d.security_score)" not in page


def test_pause_stops_timer_reloads_only():
    assert "if (paused) return;" in _fn("refresh")
    assert "paused) return;" in _fn("pullAgents")
    handler = re.search(r"pauseBtn.onclick = \(\) => \{(.*?)\n\};", visual.PAGE, re.S).group(1)
    assert "load(" not in handler and "run" not in handler.replace("aria", "")


def test_cards_show_no_team_or_raw_ids_up_front():
    cards = _fn("cards")
    assert "team_name" not in cards  # "claude-code:zaid" stays out of the card
    assert "agentName(a.agent_type)" in cards and "folder(a.project" in cards
    assert '"Process details"' in cards  # pid, cpu, memory, path behind a disclosure


def _js(name):
    m = re.search(rf"\n(?:async )?function {name}\(.*?\n\}}\n", visual.PAGE, re.S)
    if m is None or "\nfunction " in m.group(0)[1:]:
        m = re.search(rf"\nfunction {name}\([^\n]*\}}\n", visual.PAGE)
    assert m, name
    return m.group(0)


@pytest.fixture
def run_js(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed")
    import subprocess

    data = re.search(r"\nconst DATA = .*?;\n", visual.PAGE).group(0)
    funcs = "".join(_js(n) for n in (
        "label", "agentName", "folder", "uptime", "healthTone", "securityTone",
        "severityTone", "sparkGeom"))
    prelude = data + "const NAMES = DATA.names, TONES = DATA.tones;\n" + funcs

    def run(expr):
        script = tmp_path / "t.js"
        script.write_text(prelude + f"\nprocess.stdout.write(JSON.stringify({expr}));\n",
                          encoding="utf-8")
        out = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=30)
        assert out.returncode == 0, out.stderr
        return json.loads(out.stdout)
    return run


def test_js_tone_mapping(run_js):
    assert run_js('securityTone(85, "at_risk")') == "warn"
    assert run_js('securityTone(100, "secure")') == "good"
    assert run_js('securityTone(10, "compromised")') == "bad"
    assert run_js("securityTone(85, null)") == "warn"  # by tier threshold, not health bands
    assert run_js('healthTone(100, "productive")') == "good"
    assert run_js('healthTone(70, "productive")') == "warn"  # the score wins
    assert run_js('healthTone(null, "stuck")') == "bad"
    assert run_js('healthTone(null, "???")') == "neutral"
    assert run_js('[severityTone("critical"), severityTone("medium"), severityTone("low")]') == [
        "bad", "warn", "neutral"]


def test_js_human_labels(run_js):
    assert run_js('[label("at_risk"), label("productive"), label("smooth_sailing"), label(null)]'
                  ) == ["At risk", "Productive", "Smooth sailing", "Unknown"]
    assert run_js('[agentName("claude-code"), agentName("copilot-vscode"), agentName("new-bot")]'
                  ) == ["Claude Code", "Copilot VS Code", "New Bot"]
    assert run_js('[folder("zaid", "/home/zaid"), folder("app", "/home/zaid/app"), '
                  'folder("x", "C:\\\\Users\\\\x"), folder("", null)]'
                  ) == ["~", "app", "~", "No project"]
    assert run_js('[uptime("01:53:59"), uptime("2-03:04:05"), uptime("04:10"), uptime("00:09")]'
                  ) == ["1 h 53 min", "2 d 3 h", "4 min", "under a minute"]


def test_js_sparkline_needs_two_distinct_points(run_js):
    assert run_js("[sparkGeom([], 120, 32), sparkGeom([5], 120, 32), "
                  "sparkGeom([7, 7, 7, 7], 120, 32)]") == [None, None, None]
    g = run_js("sparkGeom([10, 20, 15], 120, 32)")
    assert g["lo"] == 10 and g["hi"] == 20 and len(g["pts"]) == 3
    ys = [y for _, y in g["pts"]]
    assert all(0 < y < 32 for y in ys)  # padded range: no point on the edge
    assert ys[1] < ys[2] < ys[0]  # higher value draws higher


def test_spark_draws_nothing_without_geometry():
    body = _fn("spark")
    assert "if (!g) return null;" in body and "sparkGeom(a, w, h)" in body
    assert 'class: "area"' in body and '"range"' in body  # area fill + low-high label


# Every view, fed nulls, NaN and Python "None" strings, prints none of them.

_DOM_SHIM = r"""
class Node {
  constructor(tag) { this.tag = tag; this.kids = []; this.attrs = {}; this.dataset = {};
    this.className = ""; this._text = null; this.style = {};
    this.classList = {add: c => { this.className += " " + c; }, toggle: () => true}; }
  set textContent(t) { this._text = String(t); this.kids = []; }
  get textContent() {
    return this._text !== null ? this._text :
      this.kids.map(k => typeof k === "string" ? k : k.textContent).join(" ");
  }
  append(...xs) { this.kids.push(...xs.filter(x => x !== null && x !== undefined)); }
  prepend(...xs) { this.kids.unshift(...xs); }
  replaceChildren(...xs) { this.kids = []; this._text = null; this.append(...xs); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  querySelector() { return new Node("x"); }
  get childElementCount() { return this.kids.length; }
}
globalThis.Node = Node;
globalThis.document = {createElement: t => new Node(t), createElementNS: (n, t) => new Node(t),
  getElementById: () => null, querySelectorAll: () => []};
"""

_NULLS = {
    "ps": [{"pid": 1, "agent_type": None, "project": None, "working_directory": None,
            "cpu_percent": None, "memory_mb": None, "uptime": None, "depth": 0}],
    "check": {"overall_score": None, "status": None, "warnings": [],
              "categories": {"context": {"score": None, "status": None, "warning_count": 1}},
              "efficiency": {"score": None, "cost_total": None, "recommendation": None},
              "session_fallback": None},
    "security-scan": {"security_score": float("nan"), "status": "None", "action_count": None,
                      "warnings": [{"severity": None, "signal": None, "message": None,
                                    "details": None, "suggestion": None}],
                      "session_fallback": "x", "session_project": None},
    "audit": {"total_findings": 0, "sessions_scanned": None, "findings": []},
    "stats": {"sessions": None, "messages": None, "tool_calls": None,
              "totals": {"total_tokens": None, "estimated_cost_usd": None,
                         "cache_hit_ratio": None},
              "by_tool": {"Bash": {"call_count": None, "total_tokens": 5,
                                   "estimated_cost_usd": None}}},
    "report": {"period": {"start": None, "end": None},
               "totals": {"sessions": 0, "cost_usd": None, "tokens": 0, "waste_usd": None,
                          "waste_pct": None},
               "security": {"total": 0}, "previous": {"sessions": 2, "cost_usd": None}},
    "subagents": {"total": 1, "active": None, "subagents": [
        {"type": "qa", "description": None, "health_score": None, "status": None,
         "cost_usd": None, "actions": None, "last_activity": None, "active": False,
         "warnings": None, "depth": 1}]},
    "history": {"synced": {"new": None, "updated": 1, "unchanged": None, "active": None},
                "sessions": [{"agent": "claude-code", "project": None, "ended": None,
                              "actions": None, "tokens": None, "cost_usd": None,
                              "health_score": None, "status": None}]},
}


def test_no_view_prints_none_null_undefined_or_nan(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed")
    import subprocess

    m = re.search(r"\nconst DATA = .*?\n(?=// Every view reloads)", visual.PAGE, re.S)
    assert m
    payloads = json.dumps(_NULLS)  # NaN is written as a JS NaN literal
    script = tmp_path / "views.js"
    script.write_text(_DOM_SHIM + m.group(0) + f"""
const P = {payloads}, out = {{}};
for (const [name, d] of Object.entries(P)) {{
  const box = new Node("div");
  box.append(...VIEWS[name](d).filter(Boolean));
  out[name] = box.textContent;
}}
process.stdout.write(JSON.stringify(out));
""", encoding="utf-8")
    run = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr
    texts = json.loads(run.stdout)
    assert set(texts) == set(_NULLS)
    for name, text in texts.items():
        bad = re.findall(r"\b(None|null|undefined|NaN|Unpriced)\b", text)
        assert not bad, (name, bad, text)
    report = texts["report"]
    assert "Cost $0.00" in report and "Wasted $0.00" in report  # no sessions: nothing spent
    assert "—" in texts["stats"] and "—" in texts["history"]


# QA #238 fixes.

def _views_js(tmp_path, body):
    """Run *body* (JS, prints with process.stdout.write) after the page's
    declarations, on the DOM shim; returns the parsed JSON output."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed")
    import subprocess

    m = re.search(r"\nconst DATA = .*?\n(?=// Every view reloads)", visual.PAGE, re.S)
    assert m
    script = tmp_path / "page.js"
    script.write_text(_DOM_SHIM + m.group(0) + "\n" + body, encoding="utf-8")
    run = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


def test_home_folder_project_is_tilde_never_the_user_name(sandbox):
    from agentwatch.cli import _ps_json

    home = AgentProcess(pid=9, agent_type="claude-code", working_directory=Path.home(),
                        log_file=None, command="claude")
    proj = AgentProcess(pid=8, agent_type="claude-code",
                        working_directory=Path.home() / "code" / "demo", log_file=None,
                        command="claude")
    assert [a["project"] for a in _ps_json([home, proj])] == ["~", "demo"]
    assert [a["project"] for a in agent_status.build([home, proj])["agents"]] == ["~", "demo"]
    nowhere = AgentProcess(pid=7, agent_type="codex", working_directory=None, log_file=None,
                           command="codex")
    assert _ps_json([nowhere])[0]["project"] == ""


def test_script_json_cannot_close_the_script_element():
    out = visual.script_json({"x": "</script><script>alert(1)</script><!--"})
    assert "<" not in out and json.loads(out)["x"].startswith("</script>")
    m = re.search(r"\nconst DATA = (.*?);\n", visual.PAGE)
    assert "<" not in m.group(1)


def test_hidden_beats_display_and_focus_ring_is_inside_the_tab_scroller():
    assert "[hidden]{display:none!important}" in visual.PAGE
    assert "[role=tab]:focus-visible{outline-offset:-3px}" in visual.PAGE
    assert 'document.getElementById("pause").hidden = expiredLink;' in visual.PAGE


def test_working_needs_a_recent_tool_call(tmp_path):
    out = _views_js(tmp_path, """
const row = (active, age) => ({active, health: {score: 100, label: "productive"},
  cost_usd: 1, last_action: age === null ? null : {tool: "Edit", target: "a.py", age_s: age,
  ok: true}});
const cases = [row(true, 30), row(true, 119), row(true, 120), row(true, 9000), row(false, 30),
  row(true, null), row(null, null)];
process.stdout.write(JSON.stringify(cases.map(s => [working(s), stateOf(s).textContent,
  statusParts(s, "")[0].textContent])));
""")
    assert [w for w, _, _ in out] == [True, True, False, False, False, False, False]
    states = [st.strip() for _, st, _ in out]
    assert states == ["Working", "Working", "Idle", "Idle", "Idle", "Idle", "No activity"]
    assert out[0][2].startswith("Doing now") and out[3][2].startswith("Last action")


def test_advice_line_only_with_a_real_recommendation(tmp_path):
    check = {"overall_score": 90, "status": "productive", "warnings": [], "categories": {},
             "session_fallback": None}
    out = _views_js(tmp_path, f"""
const text = rec => {{
  const box = new Node("div");
  box.append(...VIEWS.check({{...{json.dumps(check)}, efficiency: {{score: 80,
    cost_total: 1, recommendation: rec}}}}).filter(Boolean));
  return box.textContent;
}};
process.stdout.write(JSON.stringify([text(null), text("None"), text("Wrap up soon")]));
""")
    assert "Advice" not in out[0] and "Advice" not in out[1]
    assert "Advice: Wrap up soon" in out[2]


def test_history_shows_25_rows_then_more_on_click(tmp_path):
    rows = [{"agent": "claude-code", "project": f"proj{i:03d}", "ended": 1.79e9 - i,
             "actions": 1, "tokens": 1, "cost_usd": 0.1, "health_score": 100,
             "status": "healthy"} for i in range(60)]
    out = _views_js(tmp_path, f"""
const d = {{synced: null, sessions: {json.dumps(rows)}}};
const page = () => {{
  const box = new Node("div");
  box.append(...VIEWS.history(d).filter(Boolean));
  return box;
}};
const shown = box => (box.textContent.match(/proj\\d{{3}}/g) || []).length;
const first = page(), btn = first.kids[first.kids.length - 1];
const firstText = first.textContent;
historyShown += HISTORY_PAGE;  // what the button's click does
const second = page();
historyShown += HISTORY_PAGE;
const third = page();
process.stdout.write(JSON.stringify([shown(first), btn.tag, btn.textContent,
  /Newest 25 of 60 sessions/.test(firstText), shown(second), shown(third),
  third.kids.some(k => k.tag === "button")]));
""")
    assert out == [25, "button", "Show 25 more", True, 50, 60, False]
    more = _fn("moreButton")
    assert "historyShown += HISTORY_PAGE" in more and "swap(body" in more


# Every tab fits 320 px without sideways scroll (headless Chrome, when installed).

_WIDTH_CHECK = r"""
import { spawn } from "node:child_process";
const [chromePath, url, tabs, prof] = process.argv.slice(2);
const port = 9400 + Math.floor(Math.random() * 400);
const chrome = spawn(chromePath, ["--headless=new", "--no-sandbox", "--hide-scrollbars",
  `--remote-debugging-port=${port}`, `--user-data-dir=${prof}`, "about:blank"],
  {stdio: "ignore"});
const sleep = ms => new Promise(r => setTimeout(r, ms));
try {
  let targets;
  for (let i = 0; i < 100 && !targets; i++) {
    try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); }
    catch { await sleep(100); }
  }
  const ws = new WebSocket(targets.find(t => t.type === "page").webSocketDebuggerUrl);
  await new Promise(r => ws.addEventListener("open", r));
  let id = 0; const wait = new Map();
  ws.addEventListener("message", e => {
    const m = JSON.parse(e.data);
    if (wait.has(m.id)) { wait.get(m.id)(m); wait.delete(m.id); }
  });
  const send = (method, params = {}) => new Promise(r => {
    wait.set(++id, r); ws.send(JSON.stringify({id, method, params}));
  });
  await send("Emulation.setDeviceMetricsOverride",
    {width: 320, height: 640, deviceScaleFactor: 1, mobile: true});
  const out = [];
  for (const scheme of ["dark", "light"]) {
    await send("Emulation.setEmulatedMedia",
      {features: [{name: "prefers-color-scheme", value: scheme}]});
    for (const tab of tabs.split(",")) {
      await send("Page.navigate", {url: `${url}#${tab}`});
      let r;
      for (let i = 0; i < 80; i++) {  // until every section has loaded
        await sleep(250);
        r = await send("Runtime.evaluate", {returnByValue: true, expression: `
          JSON.stringify({loading: document.querySelectorAll("[aria-busy=true]").length,
            sections: document.querySelectorAll("section[data-name]").length,
            sw: document.documentElement.scrollWidth, iw: innerWidth,
            tabs: document.getElementById("tabs").scrollWidth})`});
        const v = JSON.parse(r.result.result.value);
        if (v.sections && !v.loading) break;
      }
      out.push({scheme, tab, ...JSON.parse(r.result.result.value)});
    }
  }
  process.stdout.write(JSON.stringify(out));
  ws.close();
} finally { chrome.kill(); }
"""


def _chrome():
    import glob

    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        if shutil.which(name):
            return shutil.which(name)
    found = sorted(glob.glob(str(Path.home() / ".cache/ms-playwright/chromium-*/"
                                 "chrome-linux64/chrome")))
    return found[-1] if found else None


def test_every_tab_fits_320px_without_sideways_scroll(server, sandbox, tmp_path):
    node, chrome = shutil.which("node"), _chrome()
    if node is None or chrome is None:
        pytest.skip("needs node and a headless Chrome")
    import subprocess

    script = tmp_path / "width.mjs"
    script.write_text(_WIDTH_CHECK, encoding="utf-8")
    url = f"http://127.0.0.1:{server.server_address[1]}/?t={server.token}"
    tabs = ",".join(t for t in ("overview", "security", "cost", "history"))
    run = subprocess.run([node, str(script), chrome, url, tabs, str(tmp_path / "prof")],
                         capture_output=True, text=True, timeout=240)
    assert run.returncode == 0, run.stderr
    results = json.loads(run.stdout)
    assert len(results) == 8 and all(r["sections"] for r in results)
    for r in results:
        assert r["sw"] <= r["iw"] == 320, r
