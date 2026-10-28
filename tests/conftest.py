import pytest

from agentwatch import history

REAL_HISTORY_DIR = history.data_dir()  # from the real env, before any test patches it


@pytest.fixture(autouse=True)
def _private_coach_dirs(monkeypatch, tmp_path):
    """The coach hook writes a pointer file in the per-user cache dir
    (coach.user_state_dir()); no test may write the developer's real one."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))  # the history DB
    yield
    # Runs before monkeypatch's own teardown: a test that undid this (say with
    # monkeypatch.undo()) could have opened the developer's real history DB.
    assert history.data_dir() != REAL_HISTORY_DIR, (
        "this test could open the developer's real history DB: re-apply the isolation")


@pytest.fixture(autouse=True)
def _no_machine_checks(monkeypatch):
    """watch-all's detect() and history sync workers (DNS, psutil, a
    subprocess) are off; tests/test_multi_app_machine.py turns them on."""
    from agentwatch.ui.multi_app import MultiAgentWatchApp

    monkeypatch.setattr(MultiAgentWatchApp, "MACHINE_CHECKS", False)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)


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
