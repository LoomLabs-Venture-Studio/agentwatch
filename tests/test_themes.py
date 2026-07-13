"""Tests for status theme registration/lookup, including the `ascii` theme.

The `ascii` theme (Task #8) exists as an escape hatch for legacy Windows
consoles (plain cmd.exe/powershell.exe via conhost.exe) that have no
Unicode font-fallback and render every other theme's glyphs -- including
the `technical` theme's single-codepoint ✓/~/!/✗ -- as "?" or a tofu box.
Every `emoji_*` value on that theme must therefore be 7-bit ASCII.
"""

from __future__ import annotations

import pytest

from agentwatch.themes import (
    THEMES,
    StatusTheme,
    get_theme,
    list_themes,
)


def test_list_themes_includes_ascii():
    assert "ascii" in list_themes()


def test_get_theme_ascii_retrievable():
    theme = get_theme("ascii")
    assert isinstance(theme, StatusTheme)
    assert theme.name == "ascii"


def test_ascii_theme_labels_best_to_worst():
    theme = THEMES["ascii"]
    assert theme.labels == ("ok", "warning", "alert", "failure")


@pytest.mark.parametrize("level", ["level_0", "level_1", "level_2", "level_3"])
def test_ascii_theme_emoji_fields_are_pure_ascii(level):
    theme = THEMES["ascii"]
    status_label = getattr(theme, level)
    emoji = theme.emoji_for(status_label)
    assert emoji, f"emoji for {level} should not be empty"
    assert all(ord(c) < 128 for c in emoji), (
        f"ascii theme emoji for {level!r} ({emoji!r}) contains non-ASCII characters"
    )


def test_ascii_theme_emoji_for_all_levels():
    theme = THEMES["ascii"]
    assert theme.emoji_for("ok") == "[OK]"
    assert theme.emoji_for("warning") == "[WARN]"
    assert theme.emoji_for("alert") == "[ALERT]"
    assert theme.emoji_for("failure") == "[FAIL]"


def test_ascii_theme_status_from_score_roundtrips_to_ascii_emoji():
    theme = THEMES["ascii"]
    for score in (95, 70, 50, 10):
        status = theme.status_from_score(score)
        emoji = theme.emoji_for(status)
        assert all(ord(c) < 128 for c in emoji)


@pytest.mark.parametrize("name", list(THEMES.keys()))
def test_every_registered_theme_has_four_distinct_levels(name):
    """Sanity check applied to all themes, ascii included."""
    theme = THEMES[name]
    assert len(set(theme.labels)) == 4
