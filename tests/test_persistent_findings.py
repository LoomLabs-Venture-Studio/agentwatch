"""Security findings persist for the whole session (Sprint 38 fix C).

Security detectors only look at the last 5-50 actions. The dashboard used to
run them once per refresh on the current buffer, so a dangerous command
followed by many harmless actions was never seen. These tests feed synthetic
actions through the dashboard's real ingestion path (`SessionScan.add`, as
`_watch_loop` does) and the scoring path (`refresh_ui`).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from agentwatch.detectors import create_registry
from agentwatch.detectors.registry import SessionScan
from agentwatch.detectors.security.secret_scanner import SecretLeakScanner
from agentwatch.health import calculate_security_score
from agentwatch.parser.models import Action, ActionBuffer, ToolType
from agentwatch.ui.multi_app import AgentItem, MultiAgentWatchApp

# Assembled so no secret-shaped literal sits in the source.
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _bash(command: str) -> Action:
    return Action(
        timestamp=_now(), tool_name="Bash", tool_type=ToolType.BASH,
        success=True, command=command,
    )


def _read(i: int) -> Action:
    return Action(
        timestamp=_now(), tool_name="Read", tool_type=ToolType.READ,
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


# -- Codex round 1 -----------------------------------------------------------


async def test_toggle_off_on_keeps_finding_that_left_the_buffer():
    app = MultiAgentWatchApp(watch_paths=[], security_mode=True)
    async with app.run_test():
        path = _seed(app)
        _ingest(app, path, [_bash("sudo rm -rf /tmp/x")] + [_read(i) for i in range(2100)])
        assert len(app.agents[path]["buffer"].actions) == 2000  # the command is gone
        app.action_toggle_security()
        assert not app.agents[path]["_last_report"].security_warnings  # hidden while off
        app.action_toggle_security()
        assert app.agents[path]["_last_report"].security_warnings


async def test_watch_loop_does_not_block_the_event_loop_during_a_burst():
    import asyncio
    import time

    class Burst:
        def __init__(self, path, actions):
            self.path, self.actions = path, actions

        async def watch(self):  # never suspends, like a history drain
            for a in self.actions:
                yield "action", (a, self.path)

        def get_process_meta(self, path):
            return None

    app = MultiAgentWatchApp(watch_paths=[], security_mode=True)
    async with app.run_test():
        path = _seed(app)
        blob = "x = compute(value)  # padding line\n" * 60  # ~2 KB of tool output
        actions = [
            Action(timestamp=_now(), tool_name="Bash", tool_type=ToolType.BASH, success=True,
                   command=f"echo {i}", raw={"content": blob + str(i)})
            for i in range(1000)
        ]
        app.watcher = Burst(path, actions)
        gaps, done = [], False

        async def ticker():
            last = time.monotonic()
            while not done:
                await asyncio.sleep(0)
                now = time.monotonic()
                gaps.append(now - last)
                last = now

        tick = asyncio.create_task(ticker())
        await app._watch_loop()
        done = True
        await tick
        assert app.agents[path]["buffer"].stats.action_count == 1000
        assert max(gaps) < 0.25, f"event loop blocked for {max(gaps):.2f}s"


def test_secret_scanner_scans_each_action_once():
    scanner = SecretLeakScanner()
    calls = []
    original = scanner._scan_action
    scanner._scan_action = lambda a: calls.append(a) or original(a)
    buffer = ActionBuffer()
    for i in range(20):
        buffer.add(_read(i))
        scanner.check_many(buffer)
    assert len(calls) == 20


def test_neon_connection_string_is_one_finding():
    url = "postgres://app_user:Zq8vLm3Rt9Wx@ep-cool-sky-123456.us-east-2.aws.neon.tech/db"
    scan = SessionScan(create_registry(mode="all"))
    buffer = ActionBuffer()
    scan.add(buffer, _bash(f"psql {url}"))
    types = [w.details["secret_type"] for w in scan.findings.values() if w.signal == "secret_leak"]
    assert types == ["neondb_connection_string"]


def test_pending_dns_is_retried_on_refresh_without_a_new_action():
    from agentwatch.detectors.security import network
    from agentwatch.detectors.security.network import UndeclaredEgressDetector

    network._DNS.clear()
    network._INFLIGHT.clear()

    def resolve(host, port):
        return [(0, 0, 0, "", ("93.184.216.34", port))]

    spawned = []
    detector = UndeclaredEgressDetector(resolve=resolve, spawn=spawned.append)
    registry = create_registry(mode="all")
    registry.remove_detector("undeclared_egress")
    registry.add_detector(detector)
    scan = SessionScan(registry)
    buffer = ActionBuffer()
    scan.add(buffer, Action(
        timestamp=_now(), tool_name="WebFetch", tool_type=ToolType.BASH, success=True,
        network_host="docs.example.org", network_port=443,
        observed_endpoints=[("203.0.113.9", 443)],
    ))
    egress = [w for w in scan.warnings(buffer) if w.signal == "undeclared_egress"]
    assert scan.pending and not egress
    for job in spawned:
        job()  # the lookups resolve
    assert [w for w in scan.warnings(buffer) if w.signal == "undeclared_egress"]
    assert not scan.pending
    network._DNS.clear()


def test_replay_uses_the_live_buffer_capacity():
    from agentwatch.detectors.security.network import UndeclaredEgressDetector

    def resolve(host, port):
        return [(0, 0, 0, "", ("93.184.216.34", port))]

    def fetch(host, endpoint):
        return Action(timestamp=_now(), tool_name="WebFetch", tool_type=ToolType.BASH,
                      success=True, network_host=host, observed_endpoints=endpoint)

    actions = [fetch("198.51.100.7", None)] + [_read(i) for i in range(510)]
    actions.append(fetch(None, [("198.51.100.7", 443)]))
    registry = create_registry(mode="all")
    registry.remove_detector("undeclared_egress")
    registry.add_detector(UndeclaredEgressDetector(resolve=resolve, spawn=lambda f: f()))
    scan = SessionScan(registry)
    scan.replay(actions, max_size=2000)
    assert not [w for w in scan.findings.values() if w.signal == "undeclared_egress"]


def test_audit_records_every_secret_finding():
    registry = create_registry(mode="all")
    buffer = ActionBuffer()
    buffer.add(_bash(f"export AWS_ACCESS_KEY_ID={AWS_KEY}"))
    buffer.add(_bash("echo sk-ant-api03-" + "SyntheticKeyForTestingOnly0123456789abcdef"))
    warnings, audit = registry.check_security_with_audit(buffer)
    entry = next(e for e in audit if e["detector"] == "secret_leak_scanner")
    assert len(entry["warnings"]) == 2
    assert len([w for w in warnings if w.signal == "secret_leak"]) == 2
