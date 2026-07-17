"""Regression test for the `--version` string on both entry points.

`agentwatch.cli` used to hardcode `@click.version_option(version="0.1.4")`
independently on both the main `cli` group and the nested `guard_cli` group
built inside `security_main()` -- disconnected from the real version tracked
in `agentwatch.__version__` (and `pyproject.toml`). Both decorators now read
`version=__version__` imported from `agentwatch`, so this test asserts
against the real `agentwatch.__version__` symbol rather than a hardcoded
literal: it must fail automatically if `cli.py`'s version ever drifts from
`__init__.py`'s again, without anyone needing to update an expected-value
string here.
"""

from __future__ import annotations

from click.testing import CliRunner

from agentwatch import __version__
from agentwatch.cli import _build_guard_cli, cli


class TestMainCliVersion:
    def test_cli_version_matches_package_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0, result.output
        assert __version__ in result.output


class TestGuardCliVersion:
    def test_guard_cli_version_matches_package_version(self):
        guard_cli = _build_guard_cli()
        runner = CliRunner()
        result = runner.invoke(guard_cli, ["--version"])
        assert result.exit_code == 0, result.output
        assert __version__ in result.output
