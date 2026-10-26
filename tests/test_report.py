"""`agentwatch report` math and output on a synthetic history DB."""

import json

import pytest
from click.testing import CliRunner

from agentwatch import history, report
from agentwatch.cli import cli

NOW = 1_800_000_000.0
DAY = 86400.0


def add(conn, h, *, days_ago, agent="claude-code", project="web", cost=1.0, tokens=1000,
        waste=0.0, actions=10, findings=()):
    ended = NOW - days_ago * DAY
    conn.execute(
        "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (h, agent, h, project, ended - 60, ended, actions, tokens, cost,
         1 if waste else 0, None, waste, 90, "healthy", 1, 1, NOW),
    )
    for i, (signal, category, f_cost, f_tokens) in enumerate(findings):
        conn.execute("INSERT INTO findings VALUES (?, ?, ?, 'high', ?, 'msg', ?, ?, ?)",
                     (h, f"k{i}", signal, category, f_cost, f_tokens, ended))
    conn.commit()


@pytest.fixture
def conn(tmp_path):
    c = history.connect(tmp_path / "h.db")
    add(c, "a", days_ago=1, cost=10.0, tokens=5000, waste=2.0, findings=[
        ("loop", "progress", 1.5, 300), ("error_spiral", "errors", 0.8, 200),
        ("secret_leak", "credential", None, None),
    ])
    add(c, "b", days_ago=2, project="api", agent="codex", cost=None, tokens=700, waste=None,
        findings=[("thrash", "progress", None, 900), ("undeclared_egress", "network", None, None)])
    add(c, "c", days_ago=3, project="api", cost=5.0, tokens=2000, waste=1.0, findings=[
        ("loop", "progress", 3.0, 100), ("prompt_injection", "injection", None, None),
    ])
    add(c, "empty", days_ago=1, actions=0, cost=99.0)  # unreadable log: not counted
    add(c, "prev", days_ago=9, cost=4.0, tokens=100, waste=0.5)  # previous period
    add(c, "old", days_ago=20, cost=50.0, waste=9.0)  # outside both periods
    return c


def test_totals_waste_and_unknown_cost(conn):
    rep = report.build(conn, days=7, now=NOW)
    t = rep["totals"]
    assert (t["sessions"], t["unpriced_sessions"]) == (3, 1)
    assert t["cost_usd"] == 15.0  # the n/a session is not counted as $0 or guessed
    assert t["tokens"] == 7700
    assert t["waste_usd"] == 3.0
    assert t["waste_pct"] == 20.0  # 3 / 15, the n/a session left out of both sides
    assert rep["previous"]["sessions"] == 1 and rep["previous"]["cost_usd"] == 4.0
    assert rep["trend"] == {"cost_usd": 11.0, "waste_usd": 2.5}


def test_top_findings_and_security(conn):
    rep = report.build(conn, days=7, now=NOW)
    top = [(f["signal"], f["project"], f["cost_usd"]) for f in rep["top_findings"]]
    # priced findings by cost first (the unpriced thrash would be next); security has no cost
    assert top == [("loop", "api", 3.0), ("loop", "web", 1.5), ("error_spiral", "web", 0.8)]
    assert rep["security"] == {"total": 3, "leaks": 1, "egress": 1, "injection": 1, "other": 0}


def test_breakdowns_and_filters(conn):
    rep = report.build(conn, days=7, now=NOW)
    assert [(g["agent"], g["sessions"], g["cost_usd"]) for g in rep["by_agent"]] == [
        ("claude-code", 2, 15.0), ("codex", 1, None)]
    assert [(g["project"], g["cost_usd"]) for g in rep["by_project"]] == [
        ("web", 10.0), ("api", 5.0)]
    only = report.build(conn, days=7, project="api", now=NOW)
    assert only["totals"]["sessions"] == 2 and only["totals"]["unpriced_sessions"] == 1
    assert [f["project"] for f in only["top_findings"]] == ["api", "api"]
    assert report.build(conn, days=7, agent="codex", now=NOW)["totals"]["cost_usd"] is None


def test_no_previous_period_has_no_trend(conn):
    rep = report.build(conn, days=7, now=NOW + 30 * DAY)
    assert rep["totals"]["sessions"] == 0
    assert rep["trend"] == {"cost_usd": None, "waste_usd": None}
    assert "No sessions" in "\n".join(report.render(rep))


def test_render(conn):
    text = "\n".join(report.render(report.build(conn, days=7, now=NOW)))
    assert "Sessions 3   Spend ~$15.00" in text
    assert "Waste: ~$3.00 (20%) on stalls, loops, rereads and repeated errors" in text
    assert "spend +$11.00, waste +$2.50" in text
    assert "1 session without a price" in text
    assert "n/a" in text  # codex row
    assert "Security: 3 findings (1 leak findings, 1 egress, 1 injection, 0 other)" in text


def test_render_cuts_long_names_so_columns_align(conn):
    rep = report.build(conn, days=7, now=NOW)
    rep["by_project"][0]["project"] = "scratch-2026-10-23-ea6b5d"
    lines = report.render(rep)
    rows = lines[lines.index("  By project") + 1:]
    rows = rows[:rows.index("")]
    assert "    scratch-2026-10-23-ea… " in rows[0], rows
    assert len({row.index("waste") for row in rows}) == 1, rows  # costs in one column


JSON_KEYS = {"schema", "period", "filters", "totals", "top_findings", "by_agent",
             "by_project", "security", "previous", "trend"}
TOTAL_KEYS = {"sessions", "unpriced_sessions", "cost_usd", "tokens", "waste_usd",
              "waste_pct", "waste_findings"}


def test_json_schema(tmp_path, monkeypatch, conn):
    monkeypatch.setattr(history, "db_path", lambda: tmp_path / "h.db")
    out = CliRunner().invoke(cli, ["report", "--no-sync", "--json", "--days", "30"])
    assert out.exit_code == 0, out.output
    rep = json.loads(out.stdout)
    assert set(rep) == JSON_KEYS and rep["schema"] == report.JSON_SCHEMA == 1
    assert set(rep["totals"]) == set(rep["previous"]) == TOTAL_KEYS
    assert set(rep["period"]) == {"days", "start", "end"}
    assert set(rep["filters"]) == {"agent", "project"}
    assert set(rep["trend"]) == {"cost_usd", "waste_usd"}
    assert set(rep["security"]) == {"total", "leaks", "egress", "injection", "other"}
    assert all(set(g) == TOTAL_KEYS | {"agent"} for g in rep["by_agent"])
    assert all(set(g) == TOTAL_KEYS | {"project"} for g in rep["by_project"])
    assert all(set(f) == {"signal", "severity", "agent", "project", "cost_usd", "tokens",
                          "date", "message"} for f in rep["top_findings"])


def test_report_warm_is_fast(tmp_path, monkeypatch, conn):
    import time

    monkeypatch.setattr(history, "db_path", lambda: tmp_path / "h.db")
    monkeypatch.setattr("agentwatch.agents.ADAPTERS", [])
    t = time.perf_counter()
    out = CliRunner().invoke(cli, ["report"])
    assert out.exit_code == 0
    assert time.perf_counter() - t < 1.0
