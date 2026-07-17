"""Regression test for the `--json` / stdout contamination bug.

`check` and `security-scan` both auto-discover a log file via
`find_latest_session()` when `--log` is not passed explicitly, and used to
announce the discovered path with a bare `click.echo(f"Using log: {log}")`
-- no `err=True` -- unlike every other informational line in this file.
Because auto-discovery (no explicit `--log`) is the common case, that line
became the first line of *stdout* ahead of the JSON payload under `--json`,
breaking `json.loads()` on real output (confirmed empirically: "Expecting
value: line 1 column 1").

This test exercises the exact `log is None` auto-discovery branch (by
monkeypatching `agentwatch.cli.find_latest_session` rather than relying on
real filesystem search-path discovery, which is non-deterministic across
machines/CI) and asserts stdout, captured *separately* from stderr, parses
as clean JSON.

Note: existing `--json` CLI tests (see `test_security_stats.py`,
`test_goal_alignment.py`) all pass an explicit `--log <path>`, so they never
hit the `log is None` branch and never exercised this line -- that's why the
existing suite didn't catch this.
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from agentwatch.cli import cli


def _write_fixture_log(path) -> None:
    lines = []
    base = "2026-01-01T12:00:00"
    for _ in range(4):
        lines.append(
            json.dumps({"sessionId": "s1", "timestamp": base, "tool": "Read", "file": "a.txt"})
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestCheckJsonStdoutIsCleanOnAutoDiscovery:
    def test_check_json_stdout_parses_cleanly_without_explicit_log(
        self, tmp_path, monkeypatch
    ):
        log_path = tmp_path / "session.jsonl"
        _write_fixture_log(log_path)

        # Force the `log is None` auto-discovery branch in `check` to
        # resolve to our controlled fixture, without depending on real
        # filesystem search paths (~/.claude/projects, etc.).
        monkeypatch.setattr("agentwatch.cli.find_latest_session", lambda: log_path)

        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--json"])

        assert result.exit_code in (0, 1, 2), result.output
        # The "Using log: ..." announcement must be on stderr, not stdout.
        assert "Using log:" in result.stderr
        assert "Using log:" not in result.stdout
        # stdout alone must be valid, clean JSON -- the actual contract.
        payload = json.loads(result.stdout)
        assert isinstance(payload, dict)


class TestSecurityScanJsonStdoutIsCleanOnAutoDiscovery:
    def test_security_scan_json_stdout_parses_cleanly_without_explicit_log(
        self, tmp_path, monkeypatch
    ):
        log_path = tmp_path / "session.jsonl"
        _write_fixture_log(log_path)

        monkeypatch.setattr("agentwatch.cli.find_latest_session", lambda: log_path)

        runner = CliRunner()
        result = runner.invoke(cli, ["security-scan", "--json"])

        assert result.exit_code in (0, 1, 2), result.output
        assert "Using log:" in result.stderr
        assert "Using log:" not in result.stdout
        payload = json.loads(result.stdout)
        assert isinstance(payload, dict)
