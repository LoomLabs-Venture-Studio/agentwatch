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

from agentwatch.detectors import create_registry
from agentwatch.detectors.base import normalize_error
from agentwatch.parser.logs import error_text, parse_claude_code_entry, parse_moltbot_entry
from agentwatch.parser.models import ActionBuffer
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


def _write_markup_only_log(path: Path) -> None:
    """Commands/errors carrying markup, no dict errors: on the old code this
    fails with MarkupError, not the api_error dict crash."""
    lines = [
        {
            "sessionId": "s1",
            "timestamp": f"2026-01-01T12:01:{i:02d}Z",
            "tool": "Bash",
            "command": COMMAND,
            "error": ERROR,
        }
        for i in range(12)  # loop detector needs a full 10-action window
    ]
    path.write_text("".join(json.dumps(e) + "\n" for e in lines), encoding="utf-8")


def _assert_plain(widget, *literals: str) -> None:
    content = widget.render()
    text = " ".join(str(content).split())  # lines may be pre-wrapped (hanging indent)
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


@pytest.mark.parametrize("value", [None, "", False, 0, {}, []])
def test_error_text_falsy_is_no_error(value):
    assert error_text(value) is None


@pytest.mark.parametrize("value", [False, {}])
def test_moltbot_falsy_error_stays_success(value):
    entry = {"type": "tool_call", "tool_call": {"name": "Read", "input": {}}, "error": value,
             "timestamp": "2026-01-01T12:00:00Z"}
    action = parse_moltbot_entry(entry)
    assert action.success is True
    assert action.error_message is None


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


async def _wait_for_selected(app, pilot):
    """watch-all: the Selected strip once it shows the loop warning."""
    widget = app.query_one("#selected")
    for _ in range(80):
        await pilot.pause(0.05)
        if "loop" in str(widget.render()):
            break
    return widget


async def test_watch_all_renders_log_text_literally(tmp_path):
    _write_log(tmp_path / "session.jsonl")
    app = MultiAgentWatchApp(watch_paths=[tmp_path])
    app._show_idle = True  # the log's actions are old
    async with app.run_test(size=(120, 40)) as pilot:
        await _wait_for_selected(app, pilot)
        assert app.is_running
        _assert_plain(app.query_one("#selected"), ERROR, "Repeated action: Bash")
        signal = app.query_one("#sessions").get_cell(str(tmp_path / "session.jsonl"), "signal")
        assert "loop: Bash" in signal.plain


@pytest.mark.parametrize(
    "make",
    [lambda d: AgentWatchApp(log_path=d / "session.jsonl"),
     lambda d: MultiAgentWatchApp(watch_paths=[d])],
)
async def test_markup_only_log_renders_literally(tmp_path, make):
    _write_markup_only_log(tmp_path / "session.jsonl")
    app = make(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        if isinstance(app, MultiAgentWatchApp):  # the strip shows the error, not the command
            _assert_plain(await _wait_for_selected(app, pilot), ERROR, "Repeated action")
        else:
            _assert_plain(await _wait_for_warnings(app, pilot), ERROR, COMMAND)
        assert app.is_running


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


async def test_table_cells_render_literally():
    """Table cells are rich Text: a project or tool named like markup shows as is."""
    path = Path("a.jsonl")
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        item = AgentItem(path, agent_type="[b]x[/b]", project_name="p[/]", pid=1)
        app.agents[path] = app._new_agent_state(
            buffer=ActionBuffer(), registry=create_registry(mode="health"), item=item,
            pid=1, team_id=None, log_path=path, agent_type=item.agent_type,
        )
        app.selected_path = path
        app.refresh_ui()
        await pilot.pause()
        screen = "\n".join(strip.text for strip in app.screen._compositor.render_strips())
        assert "p[/]" in screen and "[b]x[/b]" in screen
