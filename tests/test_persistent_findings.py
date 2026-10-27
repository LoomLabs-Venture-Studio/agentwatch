"""Security findings persist for the whole session (Sprint 38 fix C).

Security detectors only look at the last 5-50 actions. The dashboard used to
run them once per refresh on the current buffer, so a dangerous command
followed by many harmless actions was never seen. These tests feed synthetic
actions through the dashboard's real ingestion path (`SessionScan.add`, as
`_watch_loop` does) and the scoring path (`refresh_ui`).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from agentwatch.detectors import create_registry
from agentwatch.detectors.registry import SessionScan
from agentwatch.detectors.security.secret_scanner import SecretLeakScanner
from agentwatch.health import calculate_security_score
from agentwatch.parser.models import Action, ActionBuffer, ToolType
from agentwatch.ui.multi_app import AgentItem, MultiAgentWatchApp

# Assembled so no secret-shaped literal sits in the source.
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def _bash(command: str) -> Action:
    return Action(
        timestamp=datetime.now(), tool_name="Bash", tool_type=ToolType.BASH,
        success=True, command=command,
    )


def _read(i: int) -> Action:
    return Action(
        timestamp=datetime.now(), tool_name="Read", tool_type=ToolType.READ,
        success=True, file_path=f"src/file_{i}.py",
    )


def _security(warnings):
    return [w for w in warnings if w.category.value in {"security", "credential", "injection"}
            or w.signal == "secret_leak"]


def _seed(app: MultiAgentWatchApp, name: str = "a") -> Path:
    path = Path(f"{name}.jsonl")
    app.agents[path] = app._new_agent_state(
        buffer=ActionBuffer(max_size=2000),
        registry=create_registry(mode="all"),
        item=AgentItem(path, agent_type="claude-code", project_name=name, pid=1, team_id=1),
        pid=1, team_id=1, log_path=path, agent_type="claude-code",
    )
    app.selected_path = path
    return path


def _ingest(app: MultiAgentWatchApp, path: Path, actions) -> None:
    """What `_watch_loop` does for each action event."""
    state = app.agents[path]
    for action in actions:
        app._session_scan(state).add(state["buffer"], action)


async def test_dashboard_keeps_finding_after_window_passes():
    app = MultiAgentWatchApp(watch_paths=[], security_mode=True)
    async with app.run_test():
        path = _seed(app)
        _ingest(app, path, [_bash("sudo rm -rf /tmp/x")] + [_read(i) for i in range(60)])
        app.refresh_ui()
        report = app.agents[path]["_last_report"]
        assert report.security_warnings, "dangerous command lost after 60 harmless actions"
        assert calculate_security_score(report.security_warnings) < 100


async def test_windowed_check_alone_misses_it():
    """Guards the premise: the current-buffer check no longer sees the command."""
    registry = create_registry(mode="all")
    buffer = ActionBuffer(max_size=2000)
    for a in [_bash("sudo rm -rf /tmp/x")] + [_read(i) for i in range(60)]:
        buffer.add(a)
    assert not registry.check_security(buffer)


def test_scan_keeps_higher_severity_for_same_key():
    registry = create_registry(mode="all")
    scan = SessionScan(registry)
    buffer = ActionBuffer()
    scan.add(buffer, _bash("sudo rm -rf /tmp/x"))
    kept = dict(scan.findings)
    assert kept
    scan.add(buffer, _read(0))
    assert scan.findings == kept


def test_secret_scanner_reports_unchanged_buffer_every_time():
    scanner = SecretLeakScanner()
    buffer = ActionBuffer()
    buffer.add(_bash(f"export AWS_ACCESS_KEY_ID={AWS_KEY}"))
    first, second = scanner.check(buffer), scanner.check(buffer)
    assert first is not None and second is not None
    assert first.details["secret_type"] == second.details["secret_type"]


def test_security_score_stable_when_buffer_checked_twice():
    registry = create_registry(mode="all")
    buffer = ActionBuffer()
    buffer.add(_bash(f"export AWS_ACCESS_KEY_ID={AWS_KEY}"))
    scores = [calculate_security_score(registry.check_all(buffer)) for _ in range(2)]
    assert scores[0] == scores[1] < 100


async def test_kept_secret_toasts_once_across_refreshes():
    app = MultiAgentWatchApp(watch_paths=[], security_mode=True)
    async with app.run_test():
        toasts: list = []
        app.notify = lambda *a, **k: toasts.append((a, k))
        path = _seed(app)
        _ingest(app, path, [_bash(f"export AWS_ACCESS_KEY_ID={AWS_KEY}")]
                + [_read(i) for i in range(60)])
        for i in range(3):
            app.refresh_ui()
            _ingest(app, path, [_read(100 + i)])  # new action: rescored each time
        assert app.agents[path]["_last_report"].security_warnings
        assert len([t for t in toasts if t[1].get("title") == "SECURITY ALERT"]) == 1


async def test_toggling_security_on_recovers_earlier_findings():
    app = MultiAgentWatchApp(watch_paths=[], security_mode=False)
    async with app.run_test():
        path = _seed(app)
        state = app.agents[path]
        state["registry"] = create_registry(mode="health")
        _ingest(app, path, [_bash("sudo rm -rf /tmp/x")] + [_read(i) for i in range(3)])
        app.action_toggle_security()
        assert app.agents[path]["_last_report"].security_warnings


def test_two_secrets_in_one_window_are_both_kept():
    """Equal-severity secrets must not mask each other (one Warning per check)."""
    scan = SessionScan(create_registry(mode="all"))
    buffer = ActionBuffer()
    scan.add(buffer, _bash(f"export AWS_ACCESS_KEY_ID={AWS_KEY}"))
    scan.add(buffer, _bash("echo sk-ant-api03-" + "SyntheticKeyForTestingOnly0123456789abcdef"))
    types = {w.details["secret_type"] for w in scan.findings.values() if w.signal == "secret_leak"}
    assert len(types) == 2
