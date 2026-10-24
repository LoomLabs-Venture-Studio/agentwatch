"""Log text must never be read as Textual markup, and dict-shaped errors
must not crash scoring.

Before the fix, a command or error containing ``[/]`` raised MarkupError and
exited the TUI, ``[link=...]``/``[@click=...]`` from a log became live links
and actions, ``[a-z]+`` vanished, and our own ``[claude-code]``/``[loop``
labels vanished too. A Claude Code ``system/api_error`` entry (its ``error``
is a dict) crashed ``normalize_error`` from inside the refresh tick.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from textual.app import App, ComposeResult
from textual.widgets import ListView

from agentwatch.detectors.base import normalize_error
from agentwatch.parser.logs import parse_claude_code_entry
from agentwatch.ui.app import AgentWatchApp, WarningsList
from agentwatch.ui.multi_app import AgentItem, MultiAgentWatchApp

COMMAND = 'grep "[a-z]+" a[i]'
ERROR = "[/] [link=https://x]click[/link] [@click=app.quit]x[/]"

# Shape of a real Claude Code entry (values synthetic).
API_ERROR = {
    "type": "system",
    "subtype": "api_error",
    "level": "error",
    "error": {
        "message": "Connection error.",
        "formatted": "Connection error.",
        "connection": None,
        "isNetworkDown": False,
        "rateLimits": None,
        "noResponse": None,
    },
    "retryInMs": 500,
    "retryAttempt": 1,
    "maxRetries": 10,
    "uuid": "u",
    "sessionId": "s1",
}


def _write_log(path: Path) -> None:
    lines = []
    for i in range(6):
        lines.append({**API_ERROR, "timestamp": f"2026-01-01T12:00:{i:02d}Z"})
    for i in range(8):
        lines.append(
            {
                "sessionId": "s1",
                "timestamp": f"2026-01-01T12:01:{i:02d}Z",
                "tool": "Bash",
                "command": COMMAND,
                "error": ERROR,
            }
        )
    path.write_text("".join(json.dumps(e) + "\n" for e in lines), encoding="utf-8")


def _assert_plain(widget, *literals: str) -> None:
    content = widget.render()
    text = str(content)
    for literal in literals:
        assert literal in text, (literal, text)
    styles = " ".join(str(span.style) for span in getattr(content, "spans", []))
    assert "link" not in styles and "@click" not in styles, styles


def test_api_error_dict_becomes_string():
    action = parse_claude_code_entry({**API_ERROR, "timestamp": "2026-01-01T12:00:00Z"})
    assert action.error_message == "Connection error."


def test_error_without_message_is_compact_json():
    entry = {**API_ERROR, "timestamp": "2026-01-01T12:00:00Z", "error": {"code": 5}}
    assert parse_claude_code_entry(entry).error_message == '{"code":5}'


@pytest.mark.parametrize("value", [{"message": "x"}, None, 42, ["a"]])
def test_normalize_error_accepts_non_strings(value):
    assert isinstance(normalize_error(value), str)


async def _wait_for_warnings(app, pilot) -> WarningsList:
    widget = app.query_one("#warnings-list", WarningsList)
    for _ in range(80):
        await pilot.pause(0.05)
        if widget._warnings:
            break
    return widget


async def test_watch_renders_log_text_literally(tmp_path):
    log = tmp_path / "session.jsonl"
    _write_log(log)
    app = AgentWatchApp(log_path=log)
    async with app.run_test() as pilot:
        widget = await _wait_for_warnings(app, pilot)
        assert app.is_running
        _assert_plain(widget, ERROR, COMMAND, "[loop")


async def test_watch_all_renders_log_text_literally(tmp_path):
    _write_log(tmp_path / "session.jsonl")
    app = MultiAgentWatchApp(watch_paths=[tmp_path])
    async with app.run_test() as pilot:
        widget = await _wait_for_warnings(app, pilot)
        assert app.is_running
        _assert_plain(widget, ERROR, COMMAND, "[loop")


@pytest.mark.parametrize(
    "make", [lambda p: AgentWatchApp(log_path=p), lambda p: MultiAgentWatchApp()]
)
async def test_notify_defaults_to_plain_text(tmp_path, make):
    app = make(tmp_path / "none.jsonl")
    async with app.run_test() as pilot:
        app.notify(f"[proj] {ERROR}", title="t")
        await pilot.pause()
        assert app.is_running
        assert [n.markup for n in app._notifications] == [False]


async def test_agent_labels_render_literally():
    item = AgentItem(Path("a.jsonl"), agent_type="claude-code", project_name="p[/]", pid=1)

    class Host(App):
        def compose(self) -> ComposeResult:
            yield ListView(item)

    async with Host().run_test() as pilot:
        item.update_status(90, "healthy")
        await pilot.pause()
        _assert_plain(item.query_one("#agent-name-label"), "[claude-code] p[/]")
        _assert_plain(item.query_one("#health-label"), "[root]")
