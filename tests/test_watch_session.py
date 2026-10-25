"""`agentwatch watch` (PR 9): the watch-all dashboard scoped to one session,
opened straight into that session's detail view."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner
from test_cursor_source import SCHEMA_SQL, build_multi_composer_db
from test_multi_app_table import _wait

from agentwatch.cli import _session_proc, cli
from agentwatch.parser.watcher import CursorWatcher
from agentwatch.ui.detail import DetailScreen
from agentwatch.ui.multi_app import MultiAgentWatchApp


def _env_read_log(path: Path) -> None:
    """One action that trips a real security detector (a .env read)."""
    path.write_text(json.dumps({
        "sessionId": "s1", "timestamp": "2026-01-01T12:00:00", "tool": "Read",
        "file": ".env", "input_tokens": 100,
    }) + "\n", encoding="utf-8")


def test_cli_passes_session_and_every_flag(tmp_path, monkeypatch):
    seen = {}

    def run(self, **kw):
        seen.update(vars(self))

    monkeypatch.setattr(MultiAgentWatchApp, "run", run)
    monkeypatch.setattr("agentwatch.cli.find_running_agents", lambda: [])
    log, siem = tmp_path / "s.jsonl", tmp_path / "siem.jsonl"
    _env_read_log(log)
    res = CliRunner().invoke(cli, [
        "watch", "--log", str(log), "--security", "--siem-log", str(siem),
        "--llm", "--llm-model", "mistral", "--webhook", "https://example.com/h",
        "--notify-min", "high", "--budget", "3",
    ])
    assert res.exit_code == 0, res.output
    assert seen["session"] == log and seen["security_mode"] and seen["siem_log"] == siem
    assert seen["llm"] and seen["llm_model"] == "mistral"
    alerter = seen["alerter"]
    assert alerter.webhook == "https://example.com/h" and alerter.budget == 3.0
    assert seen["watch_paths"] == [] and not seen["_process_mode"]


@pytest.mark.usefixtures("needs_siem")
async def test_opens_detail_on_the_session_real_watcher_and_siem(tmp_path):
    """No seeding: the real watcher feeds the session, the detail view opens
    on it by itself, and the real detector's finding reaches the SIEM log."""
    log, siem = tmp_path / "session.jsonl", tmp_path / "siem.jsonl"
    _env_read_log(log)
    app = MultiAgentWatchApp(session=log, security_mode=True, siem_log=siem)
    async with app.run_test(size=(120, 40)) as pilot:
        await _wait(pilot, lambda: isinstance(app.screen, DetailScreen) and app.screen.ready)
        assert app.screen.path == log and list(app.agents) == [log]
        await _wait(pilot, lambda: siem.exists() and siem.read_text(encoding="utf-8").strip())
        assert json.loads(siem.read_text(encoding="utf-8").splitlines()[0])["signal"] == (
            "credential_access")
        await pilot.press("escape")  # back to the table: just this session
        await pilot.pause()
        assert not isinstance(app.screen, DetailScreen)
        assert app.query_one("#sessions").row_count == 1


async def test_aider_markdown_session_is_followed(tmp_path):
    log = tmp_path / ".aider.chat.history.md"
    log.write_text("# aider chat started at 2026-01-01 12:00:00\n\n#### hi\n", encoding="utf-8")
    app = MultiAgentWatchApp(session=log)
    async with app.run_test() as pilot:
        await _wait(pilot, lambda: isinstance(app.screen, DetailScreen))
        assert app.agents[log]["agent_name"] == "aider"


def test_session_proc_cursor_picks_newest_agent_composer(tmp_path):
    db = tmp_path / "state.vscdb"
    build_multi_composer_db(db)
    proc = _session_proc(db)
    assert proc.agent_type == "cursor" and proc.session_id == "c-real"
    assert proc.log_file == db and proc.cursor_db_path == db
    app = MultiAgentWatchApp(session=db, session_proc=proc)
    w = app.watcher._make_watcher(db)
    assert isinstance(w, CursorWatcher) and w.composer_id_filter == "c-real"


@pytest.mark.parametrize("make", ["no_agent", "missing"])
def test_watch_cursor_without_agent_composer_exits_clearly(tmp_path, make):
    db = tmp_path / "state.vscdb"
    if make == "no_agent":
        conn = sqlite3.connect(str(db))
        conn.executescript(SCHEMA_SQL)
        conn.close()
    else:
        db.write_bytes(b"not sqlite")
    res = CliRunner().invoke(cli, ["watch", "--log", str(db)])
    assert res.exit_code == 1
    assert "No Cursor agent-mode conversation found" in res.output
