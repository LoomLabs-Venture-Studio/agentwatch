"""CLI tests for `agentwatch detect` (detect() is monkeypatched)."""

from __future__ import annotations

import json

from click.testing import CliRunner

from agentwatch.ai_detect import AI_PROVIDERS, AiUsage, DetectResult
from agentwatch.cli import cli

ALL_DOMAINS = [d for ds in AI_PROVIDERS.values() for d in ds]


def patch(monkeypatch, result):
    monkeypatch.setattr("agentwatch.ai_detect.detect", lambda: result)


def sample():
    return DetectResult(
        usages=[
            AiUsage(10, "Orca.exe", r"C:\Orca.exe", {"anthropic"}, 2),
            AiUsage(11, "claude.exe", None, {"anthropic"}, 8, adapter="claude-code"),
        ],
        partial=False,
        unresolved=[],
    )


def test_json_schema(monkeypatch):
    patch(monkeypatch, sample())
    result = CliRunner().invoke(cli, ["detect", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["partial"] is False and data["unresolved"] == []
    assert data["usages"][0] == {
        "pid": 10, "name": "Orca.exe", "exe": r"C:\Orca.exe",
        "providers": ["anthropic"], "connections": 2,
        "local_runtime": None, "adapter": None,
    }


def test_table_footer_counts_unmonitored(monkeypatch):
    patch(monkeypatch, sample())
    result = CliRunner().invoke(cli, ["detect"])
    assert result.exit_code == 0
    assert "Orca.exe" in result.output
    assert "2 program(s) using AI (1 not monitored by agentwatch)" in result.output


def test_partial_and_unresolved_notes(monkeypatch):
    r = sample()
    r.partial, r.unresolved = True, ["api.x.ai"]
    patch(monkeypatch, r)
    out = CliRunner().invoke(cli, ["detect"]).output
    assert "Partial scan" in out
    assert "Could not resolve: api.x.ai" in out


def test_offline_still_exits_zero_and_reports_local_runtime(monkeypatch):
    patch(monkeypatch, DetectResult(
        usages=[AiUsage(5, "ollama.exe", local_runtime="ollama")],
        unresolved=list(ALL_DOMAINS),
    ))
    result = CliRunner().invoke(cli, ["detect"])
    assert result.exit_code == 0
    assert "offline?" in result.output
    assert "ollama" in result.output


def test_nothing_found(monkeypatch):
    patch(monkeypatch, DetectResult(usages=[]))
    result = CliRunner().invoke(cli, ["detect"])
    assert result.exit_code == 0
    assert "No programs using AI found." in result.output
