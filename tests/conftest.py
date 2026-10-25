import pytest

from agentwatch.ui.app import AgentWatchApp


@pytest.fixture(autouse=True)
def _no_live_process_scan(monkeypatch):
    """`watch` resolves its agent's pid with a real psutil scan at mount (#130);
    tests that need it patch it back (see test_net_wiring.py)."""
    monkeypatch.setattr(AgentWatchApp, "_find_own_process", lambda self: None)


@pytest.fixture(autouse=True)
def _no_recent_write_guard(monkeypatch):
    """`redact_log_file` refuses a log written to in the last few seconds; test
    logs are written just before they are redacted. Tests of the guard itself
    turn it back on (see test_redact_data_safety.py)."""
    from agentwatch.detectors.security import secret_scanner

    monkeypatch.setattr(secret_scanner, "_RECENT_WRITE_SECONDS", 0.0)


@pytest.fixture
def needs_siem():
    """Skip unless the `siem` extra (python-json-logger) is installed."""
    pytest.importorskip("pythonjsonlogger")
