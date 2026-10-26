"""watch-all graphs, gauges and colour (Sprint 36, PR 8b): the per-session
history, sparklines, gauges, the TREND column, colours and --theme ascii."""

from __future__ import annotations

import re
from collections import deque

import pytest
from rich.color import Color
from test_multi_app_table import _action, _screen, _seed, _warning

from agentwatch.alerts import Alerter
from agentwatch.detectors.base import Severity
from agentwatch.parser.models import ActionBuffer
from agentwatch.ui import multi_app
from agentwatch.ui.multi_app import (
    AGENT_COLORS,
    HISTORY_MAX,
    SAMPLE_S,
    MultiAgentWatchApp,
    _gauge,
    _spark,
)

BLOCKS = re.compile("[▁▂▃▄▅▆▇█▮▯▲▼]")


@pytest.fixture
def ascii_theme(monkeypatch):
    monkeypatch.setattr("agentwatch.themes._current_theme", "ascii")


def _data() -> dict:
    buffer = ActionBuffer()
    buffer.add(_action())
    return {"buffer": buffer}


def _fill(data: dict, samples: list[tuple]) -> None:
    """History as if sampled SAMPLE_S apart, the last one now-ish."""
    now = multi_app.time.monotonic()
    n = len(samples)
    data["_hist"] = deque(((now - (n - i) * SAMPLE_S, *s) for i, s in enumerate(samples)),
                          maxlen=HISTORY_MAX)
    data["_samples"] = data.get("_samples", 0) + n


# -- history ------------------------------------------------------------


def test_history_samples_on_change_rate_limited_and_capped():
    data = _data()
    sample = MultiAgentWatchApp._sample
    t = 1000.0
    sample(data, (90, 1.0, 10), t)
    sample(data, (88, 1.0, 10), t + 1)  # settling: replaces the first sample
    assert list(data["_hist"]) == [(t, 88, 1.0, 10)]
    sample(data, (88, 1.0, 10), t + 6)  # unchanged: nothing
    sample(data, (87, 1.01, 10), t + 7)  # a small change: waits for SAMPLE_S
    assert len(data["_hist"]) == 1
    sample(data, (87, 1.01, 10), t + SAMPLE_S)
    assert len(data["_hist"]) == 2
    sample(data, (60, 1.01, 10), t + SAMPLE_S + 1)  # a 5+ point move: at once
    assert data["_hist"][-1] == (t + SAMPLE_S + 1, 60, 1.01, 10)
    n = data["_samples"]
    for i in range(200):
        sample(data, (i % 2 * 50, 1.0 + i, 10), t + 100 + i * SAMPLE_S)
    assert len(data["_hist"]) == HISTORY_MAX
    assert data["_samples"] == n + 200


def test_history_needs_actions_and_a_minute_for_a_reference():
    data = {"buffer": ActionBuffer()}
    assert MultiAgentWatchApp._sample(data, (90, 0.0, 0), 0.0) is None
    assert "_hist" not in data
    data = _data()
    assert MultiAgentWatchApp._sample(data, (90, 0.0, 0), 0.0) is None
    assert MultiAgentWatchApp._sample(data, (90, 0.0, 0), 59.0) is None
    assert MultiAgentWatchApp._sample(data, (90, 0.0, 0), 60.0) == (0.0, 90, 0.0, 0)


def test_arrows_health_cost_ctx():
    arrows = MultiAgentWatchApp._arrows
    assert arrows(None, (50, 1.0, 50)) == dict.fromkeys(("health", "cost", "ctx"), ("", ""))
    got = arrows((0, 80, 1.0, 40), (70, 1.5, 50))
    assert got == {"health": ("▼", "red"), "cost": ("▲", "yellow"), "ctx": ("▲", "yellow")}
    got = arrows((0, 60, None, 40), (66, None, 41))
    assert got == {"health": ("▲", "green"), "cost": ("", ""), "ctx": ("", "")}


# -- sparklines and gauges ----------------------------------------------


def test_spark_scaling():
    assert _spark([], 8) == ""
    assert _spark([None, None], 8) == ""  # unknown cost: blank
    assert _spark([5.0], 8) == "       ▁"  # single point, padded left
    assert _spark([0.0, 0.0, 0.0], 4) == " ▁▁▁"  # all zero
    assert _spark([3.0] * 8, 8) == "▁" * 8  # flat: bottom (min..max scale)
    assert _spark([100] * 8, 8, 0, 100) == "█" * 8  # flat on a fixed scale: its level
    assert _spark([0, 50, 100], 3, 0, 100) == "▁▅█"
    assert _spark([1.0, None, 2.0], 3) == "▁ █"  # a gap
    assert _spark(list(range(20)), 8) == "▁▂▃▄▅▆▇█"  # the last 8, min..max


def test_spark_ascii(ascii_theme):
    assert _spark([0, 50, 100], 3, 0, 100) == "_=#"
    assert _spark(list(range(8)), 8) == "_.:-=+*#"


@pytest.mark.parametrize(("share", "health", "text", "style"), [
    (0.0, False, "▯▯▯▯▯▯▯▯▯▯ 0%", "green"),
    (0.79, False, "▮▮▮▮▮▮▮▯▯▯ 79%", "green"),
    (0.8, False, "▮▮▮▮▮▮▮▮▯▯ 80%", "yellow"),
    (0.99, False, "▮▮▮▮▮▮▮▮▮▯ 99%", "yellow"),
    (1.0, False, "▮▮▮▮▮▮▮▮▮▮ 100%", "bold red"),
    (3.5, False, "▮▮▮▮▮▮▮▮▮▮ 350%", "bold red"),
    (0.9, True, "▮▮▮▮▮▮▮▮▮▯ 90%", "green"),  # health: inverted, by status
    (0.5, True, "▮▮▮▮▮▯▯▯▯▯ 50%", "dark_orange"),
    (0.2, True, "▮▮▯▯▯▯▯▯▯▯ 20%", "red"),
])
def test_gauge_thresholds(share, health, text, style):
    assert _gauge(share, health=health) == (text, style)


def test_gauge_ascii(ascii_theme):
    assert _gauge(0.82) == ("[########..] 82%", "yellow")
    assert _gauge(0.3, pct=False)[0] == "[###.......]"


# -- table, strip, detail -------------------------------------------------


def _history(app, path, healths, costs):
    """*healths*/*costs* as the session's samples; the last one is its
    current values (so a tick adds none): health from its scoring, cost set."""
    data = app.agents[path]
    data["buffer"].stats.total_cost = costs[-1]
    score = app._score(data).overall_score
    _fill(data, [(h, c, None) for h, c in zip([*healths[:-1], score], costs, strict=True)])
    return score


async def test_trend_column_follows_the_sort_and_is_cached():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        a = _seed(app, "a", ago=1)
        score = _history(app, a, [100, 80, 60, 40, 20, 0, 50, 0], [0.0, 1, 2, 3, 4, 5, 6, 7])
        app.refresh_ui()
        await pilot.pause()
        table = app.query_one("#sessions")
        assert table.columns["trend"].label.plain == "TREND H"
        cell = table.get_cell("a.jsonl", "trend")
        assert cell.plain == "█▇▅▄▂▁▅" + multi_app._spark([score], 1, 0, 100)
        colors = {span.style for span in cell.spans}
        assert {"green", "yellow", "dark_orange", "red"} <= colors  # each point by health

        calls = []
        real = multi_app._spark
        multi_app._spark = lambda *a, **k: calls.append(a) or real(*a, **k)
        try:
            for _ in range(5):
                app.refresh_ui()  # no new sample: no sparkline recomputed
            assert calls == []
            await pilot.press("o")  # cost sort: TREND $, computed once
            await pilot.pause()
            assert table.columns["trend"].label.plain == "TREND $"
            assert table.get_cell("a.jsonl", "trend").plain == "▁▂▃▄▅▆▇█"
            n = len(calls)
            app.refresh_ui()
            assert len(calls) == n
        finally:
            multi_app._spark = real


async def test_narrow_layout_drops_trend_before_top_signal_gets_short():
    for size, budget, shown in (((120, 40), 5.0, True), ((80, 24), None, False),
                                ((84, 24), None, True), ((84, 24), 5.0, True),
                                ((83, 24), 5.0, False), ((100, 30), None, False)):
        app = MultiAgentWatchApp(alerter=Alerter(budget=budget) if budget else None)
        async with app.run_test(size=size) as pilot:
            _seed(app, "a")
            app.refresh_ui()
            await pilot.pause()
            table = app.query_one("#sessions")
            assert ("trend" in table.columns) == shown, (size, budget)
            assert table.columns["signal"].width >= multi_app.SIGNAL_MIN
            assert table.max_scroll_x == 0


def _segments(app, needle: str):
    for strip in app.screen._compositor.render_strips():
        for seg in strip:
            if needle in seg.text:
                yield seg


def _rgb(name: str):
    return Color.parse(name).get_truecolor()


@pytest.mark.parametrize("size", ((120, 40), (80, 24)))
async def test_colours_by_agent_and_severity(size):
    app = MultiAgentWatchApp()
    async with app.run_test(size=size) as pilot:
        _seed(app, "crit", warnings=[_warning(Severity.CRITICAL, "crit_sig")])
        _seed(app, "high", warnings=[_warning(Severity.HIGH, "high_sig")])
        _seed(app, "med", warnings=[_warning(Severity.MEDIUM, "med_sig")])
        app.refresh_ui()
        await pilot.pause()
        table = app.query_one("#sessions")
        assert str(table.get_cell("high.jsonl", "signal").style) == "dark_orange"
        assert str(table.get_cell("med.jsonl", "signal").style) == "yellow"
        # on screen (crit is the cursor row: the highlight wins there)
        seg = next(_segments(app, "high sig"))
        assert seg.style.color.get_truecolor() == _rgb("dark_orange")
        if size[0] >= 100:
            seg = next(_segments(app, "Claude Code"))  # AGENT column, first row below cursor
            colors = {s.style.color.get_truecolor() for s in _segments(app, "Claude Code")
                      if s.style.color is not None}
            assert _rgb(AGENT_COLORS["claude-code"]) in colors
            # the Selected strip: the top signal in its severity colour, the agent in its own
            content = app.query_one("#selected").content
            styles = {content.plain[span.start:span.end]: str(span.style)
                      for span in content.spans}
            assert next(v for k, v in styles.items() if "crit_sig warning" in k) == "bold red"
            assert styles["Claude Code"] == AGENT_COLORS["claude-code"]


async def test_strip_and_detail_show_graphs_and_gauges():
    app = MultiAgentWatchApp(alerter=Alerter(budget=10.0))
    async with app.run_test(size=(120, 40)) as pilot:
        a = _seed(app, "a", warnings=[_warning(Severity.HIGH, "high_sig")])
        _history(app, a, [90, 80, 70, 60, 50], [1.0, 2.0, 4.0, 6.0, 8.2])
        app.refresh_ui()
        await pilot.pause()
        lines = str(app.query_one("#selected").render()).splitlines()
        assert len(lines) <= 6
        assert lines[0].startswith("Selected: a · Claude Code")
        assert re.match(r"health +\d+% +[▁-█]+ ", lines[1])
        assert re.match(r"cost +\$8\.20 +▁▂▄▆█ ▲  budget ▮▮▮▮▮▮▮▮▯▯ 82%", lines[2])
        assert lines[3].startswith("ctx ") and "n/a" in lines[3]
        assert "high_sig warning" in lines[4]
        await pilot.press("enter")
        await pilot.pause(0.3)
        text = _screen(app)
        assert re.search(r"  health +\d+% +[▁-█]{5} ", text)  # every sample
        assert re.search(r"  cost +\$8\.20 +▁▂▄▆█ ▲  budget ▮▮▮▮▮▮▮▮▯▯ 82%", text)


@pytest.mark.parametrize("size", ((120, 40), (80, 24)))
async def test_ascii_theme_renders_no_unicode_blocks(ascii_theme, size):
    app = MultiAgentWatchApp(alerter=Alerter(budget=10.0))
    async with app.run_test(size=size) as pilot:
        a = _seed(app, "a", warnings=[_warning(Severity.HIGH)])
        _seed(app, "b")
        _history(app, a, [90, 80, 70, 60, 50], [1.0, 2.0, 4.0, 6.0, 8.2])
        app.refresh_ui()
        await pilot.pause()
        text = _screen(app)
        assert not BLOCKS.findall(text), text
        if size[0] >= 100:
            assert "[########..] 82%" in text and "_.-+# ^" in text
        await pilot.press("enter")
        await pilot.pause(0.3)
        text = _screen(app)
        assert "[########..] 82%" in text
        assert not BLOCKS.findall(text.split("Health [")[0]), text  # the graphs; the bars below
        # are the single-agent widgets' own (unchanged)


async def test_selected_strip_is_rebuilt_only_when_it_changes():
    app = MultiAgentWatchApp()
    async with app.run_test(size=(120, 40)) as pilot:
        a = _seed(app, "a")
        app.refresh_ui()
        await pilot.pause()
        built = []
        real = app._graph_rows
        app._graph_rows = lambda *a, **k: built.append(1) or real(*a, **k)
        for _ in range(5):
            app.refresh_ui()  # nothing changed
        assert built == []
        data = app.agents[a]
        data["registry"].check_all = lambda buffer: [_warning(Severity.HIGH, "new_sig")]
        data["buffer"].add(_action(0, 1))
        app.refresh_ui()
        await pilot.pause()
        assert built == [1]
        assert "new_sig warning" in str(app.query_one("#selected").render())
        app.refresh_ui()
        assert built == [1]
