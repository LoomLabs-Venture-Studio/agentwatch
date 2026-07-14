"""Tests for `--siem-log`/`--llm`/`--llm-model` CLI plumbing on `watch` and
`watch-all` (Sprint 13: closing the "live-TUI wiring" gap -- these two
commands previously had neither option at all, unlike `check`/
`security-scan`).

These stub out `AgentWatchApp`/`MultiAgentWatchApp` entirely (real TUI apps
call `.run()`, which takes over the terminal -- not something to drive via
`CliRunner`) and just assert the CLI passes the parsed option values
through to the app constructor unchanged. The apps' own handling of those
values is covered by `test_app_live_wiring.py` / `test_multi_app_live_wiring.py`.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from agentwatch.cli import cli


class _FakeApp:
    """Records constructor kwargs; `.run()` is a no-op so CliRunner never
    blocks on a real Textual event loop."""

    last_kwargs: dict | None = None

    def __init__(self, **kwargs):
        type(self).last_kwargs = kwargs

    def run(self):
        pass


def _write_fixture_log(path: Path) -> None:
    import json

    base = "2026-01-01T12:00:00"
    lines = [json.dumps({"sessionId": "s1", "timestamp": base, "tool": "Read", "file": "a.py"})]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestWatchSiemLlmOptions:
    def test_watch_passes_siem_log_and_llm_options_through(self, tmp_path, monkeypatch):
        import agentwatch.ui.app as app_mod

        monkeypatch.setattr(app_mod, "AgentWatchApp", _FakeApp)

        log_path = tmp_path / "session.jsonl"
        _write_fixture_log(log_path)
        siem_path = tmp_path / "siem.jsonl"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "watch",
                "--log", str(log_path),
                "--siem-log", str(siem_path),
                "--llm",
                "--llm-model", "mistral",
            ],
        )
        assert result.exit_code == 0, result.output
        assert _FakeApp.last_kwargs["siem_log"] == siem_path
        assert _FakeApp.last_kwargs["llm"] is True
        assert _FakeApp.last_kwargs["llm_model"] == "mistral"

    def test_watch_defaults_to_no_siem_no_llm(self, tmp_path, monkeypatch):
        import agentwatch.ui.app as app_mod

        monkeypatch.setattr(app_mod, "AgentWatchApp", _FakeApp)

        log_path = tmp_path / "session.jsonl"
        _write_fixture_log(log_path)

        runner = CliRunner()
        result = runner.invoke(cli, ["watch", "--log", str(log_path)])
        assert result.exit_code == 0, result.output
        assert _FakeApp.last_kwargs["siem_log"] is None
        assert _FakeApp.last_kwargs["llm"] is False


class TestWatchAllSiemLlmOptions:
    def test_watch_all_passes_options_through_in_all_logs_mode(self, tmp_path, monkeypatch):
        import agentwatch.ui.multi_app as multi_app_mod

        monkeypatch.setattr(multi_app_mod, "MultiAgentWatchApp", _FakeApp)
        monkeypatch.setattr(
            "agentwatch.parser.logs.DEFAULT_SEARCH_PATHS", [tmp_path]
        )

        siem_path = tmp_path / "siem.jsonl"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "watch-all",
                "--all-logs",
                "--siem-log", str(siem_path),
                "--llm",
                "--llm-model", "mistral",
            ],
        )
        assert result.exit_code == 0, result.output
        assert _FakeApp.last_kwargs["siem_log"] == siem_path
        assert _FakeApp.last_kwargs["llm"] is True
        assert _FakeApp.last_kwargs["llm_model"] == "mistral"

    def test_watch_all_passes_options_through_in_process_discovery_mode(self, monkeypatch):
        import agentwatch.ui.multi_app as multi_app_mod
        from agentwatch.discovery import AgentProcess

        monkeypatch.setattr(multi_app_mod, "MultiAgentWatchApp", _FakeApp)
        fake_proc = AgentProcess(
            pid=1234, agent_type="claude-code", working_directory=Path("/tmp/proj")
        )
        monkeypatch.setattr("agentwatch.cli.find_running_agents", lambda: [fake_proc])
        monkeypatch.setattr("agentwatch.cli.build_agent_tree", lambda agents: agents)

        runner = CliRunner()
        result = runner.invoke(cli, ["watch-all", "--llm"])
        assert result.exit_code == 0, result.output
        assert _FakeApp.last_kwargs["llm"] is True
        assert _FakeApp.last_kwargs["siem_log"] is None
