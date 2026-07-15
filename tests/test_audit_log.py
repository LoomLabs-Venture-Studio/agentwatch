"""Tests for Sprint 14 item 5: wiring up `SecurityDetector.check_with_audit()`
(fully implemented but zero call sites before this sprint) via a new
`DetectorRegistry.check_security_with_audit()` method and the
`security-scan --audit-log <path>` CLI option.

Distinct from `--siem-log`: the audit log is a "prove you checked"
compliance trail covering every security detector's run (triggered or
not), not just positive findings.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from agentwatch.detectors.base import Category, Detector, Severity
from agentwatch.detectors.registry import DetectorRegistry, create_registry
from agentwatch.parser.models import Action, ActionBuffer, ToolType


def _make_action(file_path: str | None = None, offset: int = 0) -> Action:
    return Action(
        timestamp=datetime(2026, 1, 1, 12, 0) + timedelta(seconds=offset),
        tool_name="Read",
        tool_type=ToolType.READ,
        success=True,
        file_path=file_path,
    )


class _AlwaysCrashesDetector(Detector):
    """A security detector that always raises, to exercise the
    exception-isolation path of `check_security_with_audit()`."""

    category = Category.CREDENTIAL
    name = "always_crashes"
    description = "test-only detector that always raises"
    is_security_detector = True

    def check(self, buffer):
        raise RuntimeError("boom")

    def check_with_audit(self, buffer):
        raise RuntimeError("boom")


class TestCheckSecurityWithAudit:
    def test_returns_one_audit_entry_per_security_detector(self):
        registry = create_registry(mode="security")
        buffer = ActionBuffer()
        buffer.add(_make_action(file_path="a.txt"))

        warnings, audit_logs = registry.check_security_with_audit(buffer)
        assert len(audit_logs) == len(registry.security_detectors)
        assert len(audit_logs) > 0

    def test_audit_entry_shape(self):
        registry = create_registry(mode="security")
        buffer = ActionBuffer()
        buffer.add(_make_action(file_path="a.txt"))

        _, audit_logs = registry.check_security_with_audit(buffer)
        for entry in audit_logs:
            assert "detector" in entry
            assert "category" in entry
            assert "triggered" in entry
            assert "action_count" in entry
            assert entry["action_count"] == len(buffer)

    def test_triggered_detector_carries_warning_and_is_returned(self):
        registry = create_registry(mode="security")
        buffer = ActionBuffer()
        # 4+ consecutive credential-path reads is enough to trip
        # CredentialAccessDetector (last(10) window).
        buffer.add(_make_action(file_path=".env"))

        warnings, audit_logs = registry.check_security_with_audit(buffer)
        credential_entries = [e for e in audit_logs if e["detector"] == "credential_access"]
        assert len(credential_entries) == 1
        assert credential_entries[0]["triggered"] is True
        assert "warning" in credential_entries[0]
        assert any(w.signal == "credential_access" for w in warnings)

    def test_non_triggered_detector_has_no_warning_key(self):
        registry = create_registry(mode="security")
        buffer = ActionBuffer()
        buffer.add(_make_action(file_path="harmless.txt"))

        _, audit_logs = registry.check_security_with_audit(buffer)
        credential_entries = [e for e in audit_logs if e["detector"] == "credential_access"]
        assert len(credential_entries) == 1
        assert credential_entries[0]["triggered"] is False
        assert "warning" not in credential_entries[0]

    def test_a_crashing_detector_does_not_abort_the_whole_run(self):
        registry = DetectorRegistry(include_health=False, include_security=True)
        registry.add_detector(_AlwaysCrashesDetector())
        buffer = ActionBuffer()
        buffer.add(_make_action(file_path=".env"))

        warnings, audit_logs = registry.check_security_with_audit(buffer)
        # The crashing detector still gets a best-effort audit entry...
        crashed = [e for e in audit_logs if e["detector"] == "always_crashes"]
        assert len(crashed) == 1
        assert crashed[0]["triggered"] is False
        assert "error" in crashed[0]
        # ...and every other detector still ran normally.
        assert len(audit_logs) == len(registry.security_detectors)
        assert any(w.signal == "credential_access" for w in warnings)

    def test_only_security_detectors_included_even_in_all_mode(self):
        registry = create_registry(mode="all")
        buffer = ActionBuffer()
        buffer.add(_make_action(file_path="a.txt"))

        _, audit_logs = registry.check_security_with_audit(buffer)
        detector_names = {e["detector"] for e in audit_logs}
        security_names = {d.name for d in registry.security_detectors}
        assert detector_names == security_names


class TestAuditLogCliWiring:
    def _write_fixture_log(self, path) -> None:
        lines = []
        base = "2026-01-01T12:00:00"
        for _ in range(3):
            lines.append(
                json.dumps(
                    {"sessionId": "s1", "timestamp": base, "tool": "Read", "file": "a.txt"}
                )
            )
        lines.append(
            json.dumps({"sessionId": "s1", "timestamp": base, "tool": "Read", "file": ".env"})
        )
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_audit_log_writes_one_line_per_security_detector(self, tmp_path):
        from click.testing import CliRunner

        from agentwatch.cli import cli
        from agentwatch.detectors.registry import create_registry

        log_path = tmp_path / "session.jsonl"
        self._write_fixture_log(log_path)
        audit_path = tmp_path / "audit.jsonl"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["security-scan", "--log", str(log_path), "--audit-log", str(audit_path)],
        )
        assert result.exit_code in (0, 1, 2), result.output
        assert audit_path.is_file()

        entries = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
        registry = create_registry(mode="security")
        assert len(entries) == len(registry.security_detectors)

    def test_audit_log_covers_non_triggered_detectors_too(self, tmp_path):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        log_path = tmp_path / "session.jsonl"
        self._write_fixture_log(log_path)
        audit_path = tmp_path / "audit.jsonl"

        runner = CliRunner()
        runner.invoke(
            cli,
            ["security-scan", "--log", str(log_path), "--audit-log", str(audit_path)],
        )
        entries = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
        assert any(e["triggered"] is False for e in entries)
        assert any(e["triggered"] is True for e in entries)

    def test_audit_log_entries_carry_session_id(self, tmp_path):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        log_path = tmp_path / "session.jsonl"
        self._write_fixture_log(log_path)
        audit_path = tmp_path / "audit.jsonl"

        runner = CliRunner()
        runner.invoke(
            cli,
            ["security-scan", "--log", str(log_path), "--audit-log", str(audit_path)],
        )
        entries = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
        assert all(e["session_id"] == "s1" for e in entries)

    def test_no_audit_log_flag_means_no_file_created(self, tmp_path):
        from click.testing import CliRunner

        from agentwatch.cli import cli

        log_path = tmp_path / "session.jsonl"
        self._write_fixture_log(log_path)

        runner = CliRunner()
        result = runner.invoke(cli, ["security-scan", "--log", str(log_path)])
        assert result.exit_code in (0, 1, 2), result.output
        assert not (tmp_path / "audit.jsonl").exists()

    def test_audit_log_is_distinct_from_siem_log(self, tmp_path):
        """--audit-log and --siem-log can both be passed and produce two
        different files with different shapes (audit = every detector's
        run; siem = only positive findings + one report summary)."""
        from click.testing import CliRunner

        from agentwatch.cli import cli

        log_path = tmp_path / "session.jsonl"
        self._write_fixture_log(log_path)
        audit_path = tmp_path / "audit.jsonl"
        siem_path = tmp_path / "siem.jsonl"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "security-scan",
                "--log", str(log_path),
                "--audit-log", str(audit_path),
                "--siem-log", str(siem_path),
            ],
        )
        assert result.exit_code in (0, 1, 2), result.output

        audit_entries = [
            json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()
        ]
        siem_entries = [
            json.loads(line) for line in siem_path.read_text(encoding="utf-8").splitlines()
        ]
        # Audit log has an entry for every detector that ran, including
        # ones that never fired -- strictly more entries than SIEM's
        # warnings-only + one-summary-line export.
        assert len(audit_entries) > len(siem_entries)
        assert all("event_type" not in e for e in audit_entries)
        assert any("event_type" in e for e in siem_entries)


class TestSeverityWarning:
    """Sanity check that `Warning` still round-trips through
    `check_with_audit()` unchanged (guards against accidental signature
    drift while wiring the new registry method)."""

    def test_warning_to_dict_matches_audit_warning_field(self):
        registry = create_registry(mode="security")
        buffer = ActionBuffer()
        buffer.add(_make_action(file_path=".env"))

        warnings, audit_logs = registry.check_security_with_audit(buffer)
        w = next(w for w in warnings if w.signal == "credential_access")
        entry = next(e for e in audit_logs if e["detector"] == "credential_access")
        assert entry["warning"] == w.to_dict()
        assert isinstance(w.severity, Severity)
