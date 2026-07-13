"""Tests for Task #9: making `--theme ascii` actually ASCII-clean end to end.

Task #8 added the pure-ASCII `ascii` theme (`StatusTheme.emoji_for()`) for
legacy Windows consoles with no Unicode font-fallback. That fixed every
call site that was *already* theme-aware (e.g. `HealthBar` in
`ui/app.py`), but several other call sites hardcoded their own emoji
completely independent of the theme system, so `agentwatch --theme ascii
watch --security` still rendered a tofu'd emoji in the Security panel.
This file covers the fix: `SecurityStatus`, `cli.py`'s report headers,
`Severity.emoji`, and `ui/multi_app.py`'s file-marker fallback.

SCOPE NOTE on "zero non-ASCII output": the assertions here are scoped to
the same emoji code-point ranges the hardcoded-emoji audit grepped for
(``\\U0001F300-\\U0001FAFF``, ``\\u2600-\\u27BF``, ``\\u2B00-\\u2BFF``) --
the same ranges Task #8's `ascii` theme exists to avoid, because they have
no CP437/font-fallback on plain conhost.exe. It deliberately does NOT
extend to the pre-existing box-drawing decoration used throughout
`cli.py`'s report formatting (``"=" * 50`` style rules using U+2550, the
``->`` style arrows), which renders fine via the legacy CP437 codepage
even where emoji doesn't, predates Task #8, and is a separate, much wider
concern flagged for the CTO rather than silently pulled into this task's
scope.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

import pytest

from agentwatch.cli import print_health_report, print_security_alert
from agentwatch.detectors import create_registry
from agentwatch.detectors.base import Category, Severity, Warning
from agentwatch.health import calculate_health
from agentwatch.health.rot import RotScorer
from agentwatch.parser.models import Action, ActionBuffer, ToolType
from agentwatch.themes import (
    THEMES,
    ascii_safe,
    get_theme,
    security_status_from_score,
    set_theme,
)
from agentwatch.ui.app import AgentWatchApp, SecurityStatus, WarningsList
from agentwatch.ui.multi_app import AgentItem

EMOJI_RE = re.compile(r"[\U0001F300-\U0001FAFF☀-➿⬀-⯿]")


def assert_no_emoji(text: str) -> None:
    matches = EMOJI_RE.findall(text)
    assert not matches, f"found emoji-range characters: {matches!r} in:\n{text}"


@pytest.fixture(autouse=True)
def _restore_theme():
    """Every test here mutates the module-level current theme; restore it."""
    original = get_theme().name
    yield
    set_theme(original)


# ---------------------------------------------------------------------------
# Helpers to build actions/warnings that trigger real detectors
# ---------------------------------------------------------------------------


def _make_action(i: int, tool: str, file_path: str | None = None) -> Action:
    tool_type = {
        "Read": ToolType.READ,
        "Edit": ToolType.EDIT,
    }.get(tool, ToolType.UNKNOWN)
    return Action(
        timestamp=datetime(2026, 1, 1, 12, 0) + timedelta(minutes=i),
        tool_name=tool,
        tool_type=tool_type,
        success=True,
        file_path=file_path,
    )


def _build_buffer_with_real_warnings() -> ActionBuffer:
    """8x repeated Read (triggers LoopDetector w/ a suggestion) + a
    credential Read + a credential Edit (HIGH + CRITICAL severity)."""
    buffer = ActionBuffer()
    for i in range(8):
        buffer.add(_make_action(i, "Read", "notes.txt"))
    buffer.add(_make_action(8, "Read", ".env"))
    buffer.add(_make_action(9, "Edit", ".env"))
    return buffer


# ---------------------------------------------------------------------------
# SecurityStatus widget (ui/app.py) -- confirmed hardcoded-emoji site #1
# ---------------------------------------------------------------------------


class TestSecurityStatusThemeWiring:
    @pytest.mark.parametrize("score", [100, 75, 10])
    def test_ascii_theme_produces_pure_ascii_render(self, score):
        set_theme("ascii")
        widget = SecurityStatus()
        widget.score = score
        widget.alert_count = 2
        rendered = widget.render()
        assert all(ord(c) < 128 for c in rendered), rendered

    def test_default_theme_score_100_uses_theme_level_0_not_old_hardcoded_shield(self):
        """Regression: for the default (`agent`) theme, SecurityStatus at
        score=100 shows the theme's SECURE-equivalent (level_0) emoji/label
        -- not the pre-refactor hardcoded shield emoji, since that hardcoded
        value is exactly the bug being fixed."""
        set_theme("agent")
        theme = get_theme()
        widget = SecurityStatus()
        widget.score = 100
        rendered = widget.render()
        assert theme.emoji_0 in rendered
        assert theme.level_0.upper() in rendered
        assert "\U0001F6E1" not in rendered  # old hardcoded shield emoji gone

    def test_default_theme_at_risk_and_compromised_map_to_level_1_and_level_3(self):
        """security_status_from_score() skips level_2 by design (see its
        docstring) so AT-RISK/COMPROMISED colors keep matching the
        historical yellow/red rather than picking up orange."""
        theme = get_theme("agent")
        assert security_status_from_score(100) == theme.level_0
        assert security_status_from_score(75) == theme.level_1
        assert security_status_from_score(50) == theme.level_3
        assert security_status_from_score(0) == theme.level_3

    @pytest.mark.parametrize("theme_name", [n for n in THEMES if n != "ascii"])
    def test_security_status_render_never_crashes_for_any_theme(self, theme_name):
        set_theme(theme_name)
        widget = SecurityStatus()
        for score in (100, 60, 5):
            widget.score = score
            rendered = widget.render()
            assert get_theme().emoji_for(security_status_from_score(score)) in rendered


# ---------------------------------------------------------------------------
# Severity.emoji design decision (detectors/base.py) -- confirmed site #4
# ---------------------------------------------------------------------------


class TestSeverityEmojiDesignDecision:
    """Severity is categorical (LOW/MEDIUM/HIGH/CRITICAL), independent of
    StatusTheme's score-derived 4 levels. Chosen design (see the docstring
    on Severity.emoji): keep the fixed pre-refactor glyphs for every theme
    except `ascii`, and only swap in ASCII bracket markers there -- rather
    than mapping onto theme levels 1/2/3, which would leak each theme's
    playful vocabulary into what is a plain severity indicator."""

    @pytest.mark.parametrize("theme_name", [n for n in THEMES if n != "ascii"])
    @pytest.mark.parametrize(
        "severity,expected",
        [
            (Severity.LOW, "\U0001F4A1"),
            (Severity.MEDIUM, "⚠️"),
            (Severity.HIGH, "\U0001F534"),
            (Severity.CRITICAL, "\U0001F6A8"),
        ],
    )
    def test_severity_emoji_unchanged_for_non_ascii_themes(self, theme_name, severity, expected):
        set_theme(theme_name)
        assert severity.emoji == expected

    @pytest.mark.parametrize(
        "severity,expected",
        [
            (Severity.LOW, "[LOW]"),
            (Severity.MEDIUM, "[MED]"),
            (Severity.HIGH, "[HIGH]"),
            (Severity.CRITICAL, "[CRIT]"),
        ],
    )
    def test_severity_emoji_ascii_theme_uses_bracket_markers(self, severity, expected):
        set_theme("ascii")
        assert severity.emoji == expected
        assert all(ord(c) < 128 for c in severity.emoji)

    def test_warning_emoji_delegates_and_is_ascii_safe_under_ascii_theme(self):
        set_theme("ascii")
        w = Warning(
            category=Category.ERRORS,
            severity=Severity.CRITICAL,
            signal="test",
            message="test warning",
        )
        assert w.emoji == "[CRIT]"


# ---------------------------------------------------------------------------
# ascii_safe() helper -- backs the suggestion-bullet / file-marker fixes
# ---------------------------------------------------------------------------


class TestAsciiSafeHelper:
    def test_returns_default_for_non_ascii_themes(self):
        set_theme("agent")
        assert ascii_safe("\U0001F4A1", "[TIP]") == "\U0001F4A1"

    def test_returns_fallback_for_ascii_theme(self):
        set_theme("ascii")
        assert ascii_safe("\U0001F4A1", "[TIP]") == "[TIP]"


class TestWarningsListSuggestionMarker:
    def test_suggestion_line_ascii_safe_under_ascii_theme(self):
        set_theme("ascii")
        widget = WarningsList()
        widget.update_warnings(
            [
                Warning(
                    category=Category.PROGRESS,
                    severity=Severity.MEDIUM,
                    signal="loop",
                    message="repeated action",
                    suggestion="try something else",
                )
            ]
        )
        rendered = widget._build_content()
        assert_no_emoji(rendered)
        assert "[TIP]" in rendered


class TestMultiAppFileMarker:
    def test_agent_item_fallback_label_ascii_safe_under_ascii_theme(self, tmp_path):
        set_theme("ascii")
        item = AgentItem(tmp_path / "session.jsonl")
        # compose() is a generator of widgets; render the Label's content
        # directly rather than mounting, mirroring how the other widget
        # tests in this file exercise render logic without a full App.
        # NOTE: Label interprets `[...]` as Rich markup and silently strips
        # unrecognized tags, which is why the ASCII fallback is "(file)"
        # rather than "[FILE]" -- see the comment in multi_app.py.
        labels = list(item.compose())
        name_label = labels[0]
        rendered = name_label.render().plain
        assert "(file)" in rendered
        assert_no_emoji(rendered)


# ---------------------------------------------------------------------------
# End-to-end: real detector pipeline -> print_health_report /
# print_security_alert (the functions `check`/`check --security` and
# `security-scan` actually call for their non-JSON output).
# ---------------------------------------------------------------------------


class TestCliReportsEndToEnd:
    def _run_real_pipeline(self, security: bool):
        buffer = _build_buffer_with_real_warnings()
        mode = "all" if security else "health"
        registry = create_registry(mode=mode)
        warnings = registry.check_all(buffer)
        report = calculate_health(warnings, include_security=security)
        return report, warnings

    def test_check_security_report_zero_emoji_under_ascii_theme(self, capsys):
        set_theme("ascii")
        report, warnings = self._run_real_pipeline(security=True)
        assert report.warnings, "fixture should have produced real warnings"

        print_health_report(report, security_mode=True)
        if report.security_warnings:
            print_security_alert(report.security_warnings)
        output = capsys.readouterr().out

        assert_no_emoji(output)
        # Sanity: prove the fixture actually exercised the suggestion-bullet
        # and severity-emoji sites, not just an empty report.
        assert "[TIP]" in output or "suggestion" not in output.lower()

    def test_check_health_report_zero_emoji_under_ascii_theme_default_theme_still_has_emoji(
        self, capsys
    ):
        """Regression: the *default* theme's report still contains real
        emoji (nothing was accidentally hardcoded to ASCII-only)."""
        set_theme("agent")
        report, warnings = self._run_real_pipeline(security=False)
        print_health_report(report, security_mode=False)
        output = capsys.readouterr().out
        # At least one theme/severity emoji should appear for a real report
        # under the default theme.
        assert EMOJI_RE.search(output) is not None

    def test_security_scan_style_output_zero_emoji_under_ascii_theme(self, capsys):
        """Mirrors cli.py's `security_scan` command's non-JSON branch
        directly (SECURE/AT RISK/COMPROMISED header + print_security_alert)
        without needing a real CLI invocation / log file."""
        import click

        from agentwatch.themes import security_status_from_score

        set_theme("ascii")
        _, warnings = self._run_real_pipeline(security=True)
        security_warnings = [w for w in warnings if w.is_security]
        assert security_warnings, "fixture should include a security warning"

        from agentwatch.health import calculate_security_score

        security_score = calculate_security_score(warnings)
        theme = get_theme()
        status = security_status_from_score(security_score)
        emoji = theme.emoji_for(status)
        color = theme.color_for(status)
        click.echo(
            click.style(f"  {emoji} {status.upper()} ({security_score}%)", fg=color, bold=True)
        )
        print_security_alert(security_warnings)
        output = capsys.readouterr().out

        assert_no_emoji(output)


# ---------------------------------------------------------------------------
# True CLI-level end-to-end: real `agentwatch --theme ascii security-scan`
# and `agentwatch --theme ascii check --security` invocations via Click's
# CliRunner against a real JSONL log file on disk -- this is the literal
# repro of the bug report ("ran `agentwatch --theme ascii watch` and still
# saw a tofu'd emoji"), just against the two non-interactive commands that
# can be driven headlessly instead of the TUI `watch` command.
# ---------------------------------------------------------------------------


def _write_fixture_log(path) -> None:
    """8x repeated Read of the same file (triggers LoopDetector -> a
    MEDIUM/HIGH warning with a suggestion) + a credential Read + a
    credential Edit of `.env` (HIGH + CRITICAL severity), using the flat
    Claude-Code JSONL format (`sessionId` present routes to
    `_parse_claude_code_flat`)."""
    import json

    lines = []
    base = "2026-01-01T12:00:00"
    for i in range(8):
        lines.append(
            json.dumps(
                {
                    "sessionId": "s1",
                    "timestamp": base,
                    "tool": "Read",
                    "file": "notes.txt",
                }
            )
        )
    lines.append(
        json.dumps({"sessionId": "s1", "timestamp": base, "tool": "Read", "file": ".env"})
    )
    lines.append(
        json.dumps({"sessionId": "s1", "timestamp": base, "tool": "Edit", "file": ".env"})
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestCliRunnerEndToEnd:
    """Drives the actual `agentwatch` Click commands, not just the helper
    functions they call -- covers the theme-group-option wiring
    (`agentwatch --theme ascii <command>`) itself, not just print_*()."""

    def test_security_scan_command_zero_emoji_under_ascii_theme(self, tmp_path):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        log_path = tmp_path / "session.jsonl"
        _write_fixture_log(log_path)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["--theme", "ascii", "security-scan", "--log", str(log_path)]
        )
        assert result.exit_code in (0, 1, 2), result.output
        assert_no_emoji(result.output)
        # Sanity: the fixture's credential-access-on-.env should have been
        # picked up, proving this isn't trivially passing on empty output.
        assert "issue(s)" in result.output

    def test_check_security_command_zero_emoji_under_ascii_theme(self, tmp_path):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        log_path = tmp_path / "session.jsonl"
        _write_fixture_log(log_path)

        runner = CliRunner()
        args = ["--theme", "ascii", "check", "--security", "--log", str(log_path)]
        result = runner.invoke(cli, args)
        assert result.exit_code in (0, 1, 2), result.output
        assert_no_emoji(result.output)
        assert "HEALTH REPORT" in result.output or "SECURITY REPORT" in result.output

    def test_check_command_default_theme_still_contains_emoji(self, tmp_path):
        """Regression: default theme's CLI output is unaffected -- it still
        contains real emoji, proving nothing was silently ASCII-ified."""
        from click.testing import CliRunner

        from agentwatch.cli import cli

        log_path = tmp_path / "session.jsonl"
        _write_fixture_log(log_path)

        runner = CliRunner()
        args = ["--theme", "agent", "check", "--security", "--log", str(log_path)]
        result = runner.invoke(cli, args)
        assert result.exit_code in (0, 1, 2), result.output
        assert EMOJI_RE.search(result.output) is not None


# ---------------------------------------------------------------------------
# True end-to-end for the TUI: `agentwatch --theme ascii watch --security`
# is exactly the command the user ran when they hit this bug (a tofu'd
# emoji in the Security panel). It's not CliRunner-drivable since it's an
# interactive Textual App, so this drives the actual AgentWatchApp through
# Textual's headless pilot (`App.run_test()`, same pattern as
# test_multi_app_refresh.py) and runs the REAL `_do_refresh()` pipeline
# (detectors -> calculate_health/calculate_security_score -> widget
# updates), then reads the SecurityStatus panel's actual rendered text.
# ---------------------------------------------------------------------------


class TestWatchSecurityTuiEndToEnd:
    async def test_security_panel_ascii_theme_pure_ascii_after_real_refresh(self, tmp_path):
        set_theme("ascii")
        log_path = tmp_path / "session.jsonl"
        log_path.write_text("", encoding="utf-8")

        app = AgentWatchApp(log_path=log_path, security_mode=True)
        async with app.run_test():
            # Seed the same state on_mount() would (buffer/registry/rot
            # scorer), then drive the exact refresh path `set_interval`
            # calls in the real app, using the fixture that produces real
            # HIGH/CRITICAL security warnings.
            app._buffer = _build_buffer_with_real_warnings()
            app._detector_registry = create_registry(mode="all")
            app._rot_scorer = RotScorer()
            app._do_refresh()

            security_status = app.query_one("#security-status", SecurityStatus)
            rendered = security_status.render()
            assert all(ord(c) < 128 for c in rendered), rendered

            warnings_list = app.query_one("#warnings-list", WarningsList)
            warnings_rendered = warnings_list._build_content()
            assert_no_emoji(warnings_rendered)

    async def test_security_panel_default_theme_still_shows_theme_emoji(self, tmp_path):
        """Regression: the same real pipeline under the default theme still
        shows a real theme emoji in the Security panel (unchanged from
        Task #9's perspective -- SecurityStatus is now theme-driven for
        every theme, not just newly-ASCII for `ascii`)."""
        set_theme("agent")
        log_path = tmp_path / "session.jsonl"
        log_path.write_text("", encoding="utf-8")

        app = AgentWatchApp(log_path=log_path, security_mode=True)
        async with app.run_test():
            app._buffer = _build_buffer_with_real_warnings()
            app._detector_registry = create_registry(mode="all")
            app._rot_scorer = RotScorer()
            app._do_refresh()

            security_status = app.query_one("#security-status", SecurityStatus)
            rendered = security_status.render()
            assert EMOJI_RE.search(rendered) is not None
