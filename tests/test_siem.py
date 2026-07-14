"""Tests for `agentwatch.siem`: structured JSON-lines export for SIEM
ingestion (Task from the "what other features are left" follow-up,
2026-07-14).

Covers the `SiemLogger` class directly (field shape, severity->log-level
mapping, append behavior) and the `--siem-log` CLI wiring on `check`/
`security-scan`.
"""

from __future__ import annotations

import json

import pytest

from agentwatch.detectors.base import Category, Severity, Warning
from agentwatch.siem import SiemExportError, SiemLogger, _import_json_formatter

# ---------------------------------------------------------------------------
# SiemLogger
# ---------------------------------------------------------------------------


def _read_lines(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


class TestSiemLoggerWarnings:
    def test_writes_one_json_line_per_warning(self, tmp_path):
        path = tmp_path / "siem.jsonl"
        warning = Warning(
            category=Category.CREDENTIAL,
            severity=Severity.HIGH,
            signal="credential_access",
            message="Agent accessed sensitive path: .env",
            details={"path": ".env", "operation": "read"},
        )
        with SiemLogger(path, agent_type="claude_code", session_id="s1") as siem:
            siem.log_warning(warning)

        lines = _read_lines(path)
        assert len(lines) == 1
        entry = lines[0]
        assert entry["message"] == "Agent accessed sensitive path: .env"
        assert entry["category"] == "credential"
        assert entry["signal"] == "credential_access"
        assert entry["is_security"] is True
        assert entry["agent_type"] == "claude_code"
        assert entry["session_id"] == "s1"
        assert entry["details"] == {"path": ".env", "operation": "read"}
        assert entry["event_type"] == "agentwatch.warning"
        assert "timestamp" in entry

    def test_suggestion_included_only_when_present(self, tmp_path):
        path = tmp_path / "siem.jsonl"
        with_suggestion = Warning(
            category=Category.PROGRESS,
            severity=Severity.MEDIUM,
            signal="loop",
            message="repeated action",
            suggestion="try something else",
        )
        without_suggestion = Warning(
            category=Category.PROGRESS,
            severity=Severity.LOW,
            signal="stall",
            message="no progress",
        )
        with SiemLogger(path) as siem:
            siem.log_warning(with_suggestion)
            siem.log_warning(without_suggestion)

        lines = _read_lines(path)
        assert lines[0]["suggestion"] == "try something else"
        assert "suggestion" not in lines[1]

    @pytest.mark.parametrize(
        "severity,expected_log_level_name",
        [
            (Severity.LOW, "INFO"),
            (Severity.MEDIUM, "WARNING"),
            (Severity.HIGH, "ERROR"),
            (Severity.CRITICAL, "CRITICAL"),
        ],
    )
    def test_severity_maps_to_log_level(self, tmp_path, severity, expected_log_level_name):
        path = tmp_path / "siem.jsonl"
        warning = Warning(
            category=Category.ERRORS,
            severity=severity,
            signal="x",
            message="m",
        )
        with SiemLogger(path) as siem:
            siem.log_warning(warning)

        entry = _read_lines(path)[0]
        assert entry["severity"] == expected_log_level_name


class TestSiemLoggerReportSummary:
    def test_log_report_summary_fields(self, tmp_path):
        path = tmp_path / "siem.jsonl"
        with SiemLogger(path, agent_type="aider", session_id="s2") as siem:
            siem.log_report_summary("health", 91, 2)

        entry = _read_lines(path)[0]
        assert entry["event_type"] == "agentwatch.report_summary"
        assert entry["report_type"] == "health"
        assert entry["score"] == 91
        assert entry["warning_count"] == 2
        assert entry["agent_type"] == "aider"
        assert entry["session_id"] == "s2"
        assert entry["severity"] == "INFO"


class TestSiemLoggerAppendBehavior:
    def test_second_instance_appends_not_truncates(self, tmp_path):
        path = tmp_path / "siem.jsonl"
        w = Warning(category=Category.ERRORS, severity=Severity.LOW, signal="x", message="first")
        with SiemLogger(path) as siem:
            siem.log_warning(w)

        w2 = Warning(category=Category.ERRORS, severity=Severity.LOW, signal="x", message="second")
        with SiemLogger(path) as siem:
            siem.log_warning(w2)

        lines = _read_lines(path)
        assert len(lines) == 2
        assert lines[0]["message"] == "first"
        assert lines[1]["message"] == "second"

    def test_creates_parent_directories(self, tmp_path):
        path = tmp_path / "nested" / "dir" / "siem.jsonl"
        w = Warning(category=Category.ERRORS, severity=Severity.LOW, signal="x", message="m")
        with SiemLogger(path) as siem:
            siem.log_warning(w)
        assert path.is_file()

    def test_close_releases_file_handle(self, tmp_path):
        """Closing must not leave a locked/undeletable handle -- exercises
        the real failure mode on Windows if the handler weren't closed."""
        path = tmp_path / "siem.jsonl"
        siem = SiemLogger(path)
        siem.log_warning(
            Warning(category=Category.ERRORS, severity=Severity.LOW, signal="x", message="m")
        )
        siem.close()
        path.unlink()  # would raise PermissionError on Windows if still open
        assert not path.exists()


class TestImportJsonFormatterMissingExtra:
    def test_raises_siem_export_error_when_extra_missing(self, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name.startswith("pythonjsonlogger"):
                raise ImportError("simulated: siem extra not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(SiemExportError, match="siem"):
            _import_json_formatter()

    def test_siem_logger_construction_raises_when_extra_missing(self, monkeypatch, tmp_path):
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name.startswith("pythonjsonlogger"):
                raise ImportError("simulated")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(SiemExportError):
            SiemLogger(tmp_path / "siem.jsonl")


# ---------------------------------------------------------------------------
# CLI wiring: --siem-log on check / security-scan
# ---------------------------------------------------------------------------


def _write_fixture_log(path) -> None:
    lines = []
    base = "2026-01-01T12:00:00"
    for i in range(8):
        lines.append(
            json.dumps({"sessionId": "s1", "timestamp": base, "tool": "Read", "file": "notes.txt"})
        )
    lines.append(json.dumps({"sessionId": "s1", "timestamp": base, "tool": "Read", "file": ".env"}))
    lines.append(json.dumps({"sessionId": "s1", "timestamp": base, "tool": "Edit", "file": ".env"}))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestCliSiemLogWiring:
    def test_security_scan_siem_log_writes_findings(self, tmp_path):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        log_path = tmp_path / "session.jsonl"
        _write_fixture_log(log_path)
        siem_path = tmp_path / "siem.jsonl"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["security-scan", "--log", str(log_path), "--siem-log", str(siem_path)],
        )
        assert result.exit_code in (0, 1, 2), result.output
        assert siem_path.is_file()
        lines = _read_lines(siem_path)
        assert any(entry["event_type"] == "agentwatch.warning" for entry in lines)
        assert any(entry["event_type"] == "agentwatch.report_summary" for entry in lines)
        assert any(entry["signal"] == "credential_access" for entry in lines)

    def test_check_security_siem_log_writes_findings(self, tmp_path):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        log_path = tmp_path / "session.jsonl"
        _write_fixture_log(log_path)
        siem_path = tmp_path / "siem.jsonl"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["check", "--security", "--log", str(log_path), "--siem-log", str(siem_path)],
        )
        assert result.exit_code in (0, 1, 2), result.output
        lines = _read_lines(siem_path)
        summaries = [e for e in lines if e["event_type"] == "agentwatch.report_summary"]
        assert len(summaries) == 1
        assert summaries[0]["report_type"] == "health"

    def test_no_siem_log_flag_means_no_file_created(self, tmp_path):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        log_path = tmp_path / "session.jsonl"
        _write_fixture_log(log_path)

        runner = CliRunner()
        result = runner.invoke(cli, ["security-scan", "--log", str(log_path)])
        assert result.exit_code in (0, 1, 2), result.output
        assert not (tmp_path / "siem.jsonl").exists()
