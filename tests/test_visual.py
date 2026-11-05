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

from agentwatch import visual
from agentwatch.agents.claude_code import ClaudeCodeAdapter
from agentwatch.cli import cli
from agentwatch.discovery import AgentProcess

FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "ghp_" + "Zq8wXv3Lk9Pm2Rt7Yb4Nc6Hd1Fg5Js0Ae8Ui3"  # fake GitHub PAT
AGENT = AgentProcess(pid=42, agent_type="claude-code", working_directory=Path("/w"),
                     log_file=Path(f"/w/{SECRET}.jsonl"), command="claude")


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
    assert not re.search(r"https?://", body)
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


def test_check_json_matches_builder(sandbox):
    assert _cli_json(["check"]) == _dumps(visual.API["check"](False))


def test_security_json_matches_builder(sandbox):
    assert _cli_json(["security-scan"]) == _dumps(visual.API["security-scan"](False))


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
