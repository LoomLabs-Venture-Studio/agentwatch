"""`agentguard` (the security-first entry point) takes every option of its
agentwatch counterpart: each command is built from the agentwatch command's
own params, so the two can't drift (QA sweep 2026-11-13: most flags were
missing)."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from agentwatch import cli as cli_mod
from agentwatch.cli import _GUARD_ALIASES, _build_guard_cli, cli

# agentwatch options agentguard deliberately leaves out: (command, option name).
ALLOWED_MISSING: set[tuple[str, str]] = set()


def _opts(command) -> set[str]:
    return {opt for p in command.params for opt in (*p.opts, *p.secondary_opts)}


def test_group_options_match():
    assert _opts(cli) <= _opts(_build_guard_cli())  # --version, -t/--theme


@pytest.mark.parametrize("name", sorted(_GUARD_ALIASES))
def test_every_agentwatch_option_exists_on_the_alias(name):
    target = cli.commands[_GUARD_ALIASES[name][0].replace("_", "-")]
    guard = _build_guard_cli().commands[name]
    missing = {o for o in _opts(target) - _opts(guard) if (name, o) not in ALLOWED_MISSING}
    assert not missing, f"agentguard {name} lacks {sorted(missing)}"


def test_aliases_cover_their_named_commands():
    assert set(_build_guard_cli().commands) == {"scan", "watch", "check", "watch-all",
                                                "audit", "config-scan"}


@pytest.mark.parametrize("name", ["check", "watch", "watch-all"])
def test_security_is_always_on(name, monkeypatch):
    seen = {}
    target = cli.commands[name]
    monkeypatch.setattr(target, "callback", lambda **kw: seen.update(kw))
    result = CliRunner().invoke(_build_guard_cli(), [name])
    assert result.exit_code == 0, result.output
    assert seen["security"] is True


@pytest.fixture
def default_theme():
    from agentwatch.themes import set_theme

    yield
    set_theme("agent")


@pytest.mark.usefixtures("default_theme")
def test_options_reach_the_command(monkeypatch):
    seen = {}
    monkeypatch.setattr(cli_mod.watch_all, "callback", lambda **kw: seen.update(kw))
    result = CliRunner().invoke(_build_guard_cli(), [
        "-t", "ascii", "watch-all", "--headless", "--notify", "--notify-min", "high",
        "--notify-existing", "--notify-done", "--budget", "2.5",
        "--webhook", "https://example.com/h", "--all-logs", "--since", "2h",
    ])
    assert result.exit_code == 0, result.output
    assert seen["headless"] and seen["notify"] and seen["notify_existing"]
    assert seen["notify_done"] and seen["notify_min"] == "high" and seen["budget"] == 2.5
    assert seen["webhook"] == "https://example.com/h" and seen["all_logs"]
    assert seen["since"] == 7200
    from agentwatch.themes import get_theme

    assert get_theme().name == "ascii"


def test_audit_pii_reaches_audit(monkeypatch):
    seen = {}
    monkeypatch.setattr(cli_mod.audit, "callback", lambda **kw: seen.update(kw))
    result = CliRunner().invoke(_build_guard_cli(), ["audit", "--pii", "--json"])
    assert result.exit_code == 0, result.output
    assert seen["pii"] and seen["json_output"]
