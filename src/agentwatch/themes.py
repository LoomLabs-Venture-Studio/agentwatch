"""Configurable status themes for agentwatch.

This module provides multiple naming schemes for agent health statuses.
The default theme uses agent-specific language (productive, struggling, spinning, stuck).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StatusTheme:
    """A theme defining status labels, emojis, and colors.

    Each theme has 4 status levels from best to worst:
    - level_0: Best state (healthy/productive/optimal)
    - level_1: Slightly degraded
    - level_2: Warning state
    - level_3: Critical/worst state
    """

    name: str
    level_0: str  # Best (healthy equivalent)
    level_1: str  # Degraded equivalent
    level_2: str  # Warning equivalent
    level_3: str  # Critical/worst equivalent

    emoji_0: str = "✅"
    emoji_1: str = "⚠️"
    emoji_2: str = "🟠"
    emoji_3: str = "🔴"

    color_0: str = "green"
    color_1: str = "yellow"
    color_2: str = "orange"
    color_3: str = "red"

    @property
    def labels(self) -> tuple[str, str, str, str]:
        """Return all labels as a tuple (best to worst)."""
        return (self.level_0, self.level_1, self.level_2, self.level_3)

    @property
    def emojis(self) -> dict[str, str]:
        """Return emoji mapping for each status label."""
        return {
            self.level_0: self.emoji_0,
            self.level_1: self.emoji_1,
            self.level_2: self.emoji_2,
            self.level_3: self.emoji_3,
        }

    @property
    def colors(self) -> dict[str, str]:
        """Return color mapping for each status label."""
        return {
            self.level_0: self.color_0,
            self.level_1: self.color_1,
            self.level_2: self.color_2,
            self.level_3: self.color_3,
        }

    def status_from_score(self, score: float) -> str:
        """Get status label from a 0-100 health score."""
        if score >= 80:
            return self.level_0
        elif score >= 60:
            return self.level_1
        elif score >= 40:
            return self.level_2
        return self.level_3

    def emoji_for(self, status: str) -> str:
        """Get emoji for a status label.

        The "❓" fallback below is intentionally non-ASCII (it would defeat
        the point of the `ascii` theme if it were ever actually emitted by
        it). In practice this is unreachable: every call site passes a
        `status` string that was itself derived from the *current* theme
        (`status_from_score()`, `RotState.label`, or a value already stored
        from `theme.level_0`), so `status` always matches one of the four
        keys `self.emojis` was just built from. It only fires if a caller
        passes a label from a *different* theme than the one currently
        active, which no code in this codebase does today.
        """
        return self.emojis.get(status, "❓")

    def color_for(self, status: str) -> str:
        """Get color for a status label."""
        return self.colors.get(status, "white")


# =============================================================================
# Predefined Themes
# =============================================================================

THEME_AGENT = StatusTheme(
    name="agent",
    level_0="productive",
    level_1="struggling",
    level_2="spinning",
    level_3="stuck",
    emoji_0="🚀",
    emoji_1="😓",
    emoji_2="🔄",
    emoji_3="🧱",
)

THEME_CLASSIC = StatusTheme(
    name="classic",
    level_0="healthy",
    level_1="degraded",
    level_2="warning",
    level_3="critical",
)

THEME_TRAFFIC = StatusTheme(
    name="traffic",
    level_0="green",
    level_1="yellow",
    level_2="orange",
    level_3="red",
    emoji_0="🟢",
    emoji_1="🟡",
    emoji_2="🟠",
    emoji_3="🔴",
)

THEME_PERFORMANCE = StatusTheme(
    name="performance",
    level_0="optimal",
    level_1="suboptimal",
    level_2="impaired",
    level_3="failing",
    emoji_0="⚡",
    emoji_1="📉",
    emoji_2="⚠️",
    emoji_3="💥",
)

THEME_MEDICAL = StatusTheme(
    name="medical",
    level_0="stable",
    level_1="guarded",
    level_2="serious",
    level_3="terminal",
    emoji_0="💚",
    emoji_1="💛",
    emoji_2="🧡",
    emoji_3="💔",
)

THEME_WEATHER = StatusTheme(
    name="weather",
    level_0="clear",
    level_1="cloudy",
    level_2="stormy",
    level_3="severe",
    emoji_0="☀️",
    emoji_1="☁️",
    emoji_2="⛈️",
    emoji_3="🌪️",
)

THEME_NAUTICAL = StatusTheme(
    name="nautical",
    level_0="smooth_sailing",
    level_1="choppy",
    level_2="rough_seas",
    level_3="mayday",
    emoji_0="⛵",
    emoji_1="🌊",
    emoji_2="🌀",
    emoji_3="🆘",
)

THEME_ENERGY = StatusTheme(
    name="energy",
    level_0="charged",
    level_1="draining",
    level_2="low",
    level_3="depleted",
    emoji_0="🔋",
    emoji_1="🪫",
    emoji_2="⚠️",
    emoji_3="💀",
)

THEME_SIMPLE = StatusTheme(
    name="simple",
    level_0="ok",
    level_1="moderate",
    level_2="high",
    level_3="severe",
    emoji_0="👍",
    emoji_1="👌",
    emoji_2="👎",
    emoji_3="🛑",
)

THEME_GAMING = StatusTheme(
    name="gaming",
    level_0="thriving",
    level_1="weakened",
    level_2="wounded",
    level_3="defeated",
    emoji_0="💪",
    emoji_1="😰",
    emoji_2="🩸",
    emoji_3="💀",
)

THEME_TECHNICAL = StatusTheme(
    name="technical",
    level_0="nominal",
    level_1="degraded",
    level_2="impaired",
    level_3="failure",
    emoji_0="✓",
    emoji_1="~",
    emoji_2="!",
    emoji_3="✗",
    color_0="green",
    color_1="yellow",
    color_2="orange",
    color_3="red",
)

# Pure 7-bit ASCII theme — for legacy Windows consoles (plain cmd.exe /
# powershell.exe via conhost.exe) that have no Unicode font-fallback and
# render every other theme's glyphs (including `technical`'s ✓/~/!/✗) as
# "?" or a tofu box. Bracketed text labels instead of dingbats, so this is
# safe even on the oldest conhost. See CLAUDE.md Known Issues.
THEME_ASCII = StatusTheme(
    name="ascii",
    level_0="ok",
    level_1="warning",
    level_2="alert",
    level_3="failure",
    emoji_0="[OK]",
    emoji_1="[WARN]",
    emoji_2="[ALERT]",
    emoji_3="[FAIL]",
    color_0="green",
    color_1="yellow",
    color_2="orange",
    color_3="red",
)


# =============================================================================
# Theme Registry
# =============================================================================

THEMES: dict[str, StatusTheme] = {
    "agent": THEME_AGENT,
    "classic": THEME_CLASSIC,
    "traffic": THEME_TRAFFIC,
    "performance": THEME_PERFORMANCE,
    "medical": THEME_MEDICAL,
    "weather": THEME_WEATHER,
    "nautical": THEME_NAUTICAL,
    "energy": THEME_ENERGY,
    "simple": THEME_SIMPLE,
    "gaming": THEME_GAMING,
    "technical": THEME_TECHNICAL,
    "ascii": THEME_ASCII,
}

# Default theme - agent-specific language
DEFAULT_THEME = "agent"

# Module-level current theme (can be changed at runtime)
_current_theme: str = DEFAULT_THEME


def get_theme(name: str | None = None) -> StatusTheme:
    """Get a theme by name, or the current theme if name is None."""
    if name is None:
        name = _current_theme
    return THEMES.get(name, THEMES[DEFAULT_THEME])


def set_theme(name: str) -> None:
    """Set the current theme by name."""
    global _current_theme
    if name not in THEMES:
        raise ValueError(f"Unknown theme: {name}. Available: {list(THEMES.keys())}")
    _current_theme = name


def get_current_theme_name() -> str:
    """Get the name of the current theme."""
    return _current_theme


def list_themes() -> list[str]:
    """List all available theme names."""
    return list(THEMES.keys())


# =============================================================================
# Convenience functions using current theme
# =============================================================================

def status_from_score(score: float) -> str:
    """Get status label from score using current theme."""
    return get_theme().status_from_score(score)


def get_status_emoji(status: str) -> str:
    """Get emoji for status using current theme."""
    return get_theme().emoji_for(status)


def get_status_color(status: str) -> str:
    """Get color for status using current theme."""
    return get_theme().color_for(status)


def get_status_labels() -> tuple[str, str, str, str]:
    """Get all status labels for current theme."""
    return get_theme().labels


def get_status_emojis() -> dict[str, str]:
    """Get all status emojis for current theme."""
    return get_theme().emojis


def get_status_colors() -> dict[str, str]:
    """Get all status colors for current theme."""
    return get_theme().colors


# =============================================================================
# Shared cross-surface helpers (Task #9: hardcoded-emoji audit)
# =============================================================================
#
# These exist so widgets/CLI commands that need theme-aware glyphs but don't
# fit `StatusTheme.emoji_for(status)`'s "look up a status label" model have
# ONE place to get it right, instead of each call site hand-rolling its own
# hardcoded emoji (which is exactly how the `--theme ascii` bug this task
# fixes was introduced: `HealthBar` was wired to the theme correctly,
# `SecurityStatus` right next to it in the same file was not).


def security_status_from_score(score: float) -> str:
    """Map a security score (0-100) onto a theme status label using the
    SECURE / AT-RISK / COMPROMISED 3-way threshold (score == 100 / > 50 /
    else) shared by ``ui/app.py``'s ``SecurityStatus`` widget and
    ``cli.py``'s ``security-scan`` command.

    Deliberately does NOT reuse ``StatusTheme.status_from_score()``'s 4-way
    80/60/40 banding: the security panel's "100 == fully secure, anything
    else is already degraded" semantics are a stricter, pre-existing
    threshold specific to this 3-way widget, not a general health-score
    band, and quietly changing it would be a behavior change disguised as a
    refactor.

    Maps onto 3 of the theme's 4 levels -- level_0 (secure), level_1 (at
    risk), level_3 (compromised) -- intentionally skipping level_2, so the
    at-risk/compromised colors line up with the yellow/red (not orange)
    this widget has always used.
    """
    theme = get_theme()
    if score == 100:
        return theme.level_0
    elif score > 50:
        return theme.level_1
    return theme.level_3


def ascii_safe(default_glyph: str, ascii_fallback: str) -> str:
    """Return ``default_glyph`` normally, or ``ascii_fallback`` when the
    ``ascii`` theme is active.

    For decorative glyphs that are NOT a status-level indicator at all (a
    suggestion "tip" bullet, a generic file marker, ...) and so have no
    natural home on ``StatusTheme``'s 4-level model -- unlike
    ``emoji_for()``, which maps a *status label* onto that theme's glyph for
    it, this is for one-off decoration that every theme otherwise renders
    identically and only needs an ASCII-safe substitute under `ascii`.
    """
    if get_current_theme_name() == "ascii":
        return ascii_fallback
    return default_glyph
