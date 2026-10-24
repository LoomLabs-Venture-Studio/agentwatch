import pytest

from agentwatch.ui.app import AgentWatchApp


@pytest.fixture(autouse=True)
def _no_live_process_scan(monkeypatch):
    """`watch` resolves its agent's pid with a real psutil scan at mount (#130);
    tests that need it patch it back (see test_net_wiring.py)."""
    monkeypatch.setattr(AgentWatchApp, "_find_own_process", lambda self: None)


@pytest.fixture(autouse=True)
def _private_coach_dirs(monkeypatch, tmp_path):
    """The coach hook writes a pointer file in the per-user cache dir
    (coach.user_state_dir()); no test may write the developer's real one."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))  # the history DB


@pytest.fixture(autouse=True)
def _no_machine_checks(monkeypatch):
    """watch-all's detect() and history sync workers (DNS, psutil, a
    subprocess) are off; tests/test_multi_app_machine.py turns them on."""
    from agentwatch.ui.multi_app import MultiAgentWatchApp

    monkeypatch.setattr(MultiAgentWatchApp, "MACHINE_CHECKS", False)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)


@pytest.fixture
def needs_siem():
    """Skip unless the `siem` extra (python-json-logger) is installed."""
    pytest.importorskip("pythonjsonlogger")
