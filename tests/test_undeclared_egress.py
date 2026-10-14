"""#130 Wave 3: UndeclaredEgressDetector. Fake resolver, no real DNS."""

from __future__ import annotations

import socket

import pytest

from agentwatch.detectors import create_registry
from agentwatch.detectors.base import Severity, warning_dedup_key
from agentwatch.detectors.security import network
from agentwatch.detectors.security.network import UndeclaredEgressDetector
from agentwatch.parser.models import Action, ActionBuffer, ToolType

ANTHROPIC_IP = "160.79.104.10"
FETCH_IP = "93.184.216.34"


@pytest.fixture(autouse=True)
def _clear_dns_cache():
    network._DNS.clear()
    network._INFLIGHT.clear()
    yield
    network._DNS.clear()
    network._INFLIGHT.clear()


class FakeResolver:
    def __init__(self, table=None):
        self.table = table or {}
        self.calls: list[str] = []

    def __call__(self, host, port):
        self.calls.append(host)
        if host not in self.table:
            raise socket.gaierror("nope")
        return [(2, 1, 6, "", (ip, port)) for ip in self.table[host]]


def _sync(fn):
    fn()


def _detector(table=None, spawn=_sync):
    resolver = FakeResolver(table)
    return UndeclaredEgressDetector(resolve=resolver, spawn=spawn), resolver


def _action(endpoints=None, host=None) -> Action:
    return Action(
        timestamp=None, tool_name="WebFetch" if host else "Read",
        tool_type=ToolType.READ, success=True, network_host=host,
        observed_endpoints=endpoints,
    )


def _buf(*actions) -> ActionBuffer:
    buf = ActionBuffer()
    for a in actions:
        buf.add(a)
    return buf


def test_undeclared_public_endpoint_warns():
    det, _ = _detector()
    w = det.check(_buf(_action([("8.8.4.4", 443)])))
    assert w is not None
    assert w.severity is Severity.MEDIUM and w.signal == "undeclared_egress"
    assert w.message == "Undeclared egress to 8.8.4.4:443"
    assert w.details == {"endpoint": "8.8.4.4:443", "undeclared": ["8.8.4.4:443"], "count": 1}


def test_several_undeclared_most_recent_first():
    det, _ = _detector()
    w = det.check(_buf(_action([("8.8.4.4", 443)]), _action([("9.9.9.9", 53), ("8.8.4.4", 443)])))
    assert w.details["endpoint"] == "8.8.4.4:443"
    assert w.details["count"] == 2
    assert w.message == "Undeclared egress to 8.8.4.4:443 (+1 more)"


def test_llm_provider_ip_not_flagged():
    det, _ = _detector({"api.anthropic.com": [ANTHROPIC_IP]})
    assert det.check(_buf(_action([(ANTHROPIC_IP, 443)]))) is None


def test_known_agent_host_not_flagged():
    det, _ = _detector({"downloads.claude.ai": ["34.36.57.103"]})
    assert det.check(_buf(_action([("34.36.57.103", 443)]))) is None


def test_declared_host_not_flagged_even_long_before_observation():
    det, _ = _detector({"example.com": [FETCH_IP]})
    actions = [_action(host="example.com")] + [_action() for _ in range(40)]
    actions.append(_action([(FETCH_IP, 443)]))
    assert det.check(_buf(*actions)) is None


def test_ip_literal_host_used_without_dns():
    det, resolver = _detector()
    assert det.check(_buf(_action(host="203.0.113.7"), _action([("203.0.113.7", 8443)]))) is None
    assert "203.0.113.7" not in resolver.calls


def test_local_addresses_ignored_without_dns():
    det, resolver = _detector()
    local = [("127.0.0.1", 9000), ("::1", 9000), ("169.254.1.1", 80), ("fe80::1", 80),
             ("224.0.0.251", 5353), ("0.0.0.0", 1), ("not-an-ip", 1)]
    assert det.check(_buf(_action(local))) is None
    assert resolver.calls == []


def test_rfc1918_flagged():
    det, _ = _detector()
    w = det.check(_buf(_action([("10.0.0.5", 22)])))
    assert w is not None and w.details["endpoint"] == "10.0.0.5:22"


def test_no_observed_endpoints_no_dns():
    det, resolver = _detector()
    assert det.check(_buf(_action(None, host="example.com"), _action([]))) is None
    assert resolver.calls == []


def test_pending_then_warns_once_resolved():
    queued = []
    det, _ = _detector({"api.anthropic.com": [ANTHROPIC_IP]}, spawn=queued.append)
    buf = _buf(_action([("8.8.4.4", 443)]))
    assert det.check(buf) is None  # warm-up: lookups queued, nothing resolved
    assert queued
    n = len(queued)
    assert det.check(buf) is None and len(queued) == n  # no duplicate lookups in flight
    for fn in queued:
        fn()
    w = det.check(buf)
    assert w is not None and w.details["endpoint"] == "8.8.4.4:443"


def test_stale_entry_refreshed_and_unioned(monkeypatch):
    queued = []
    det, resolver = _detector({"api.anthropic.com": ["1.1.1.1"]}, spawn=queued.append)
    buf = _buf(_action([("1.1.1.1", 443), ("2.2.2.2", 443)]))
    det.check(buf)
    for fn in queued:
        fn()
    queued.clear()
    resolver.table["api.anthropic.com"] = ["2.2.2.2"]
    clock = network.time.monotonic() + network._DNS_TTL + 1
    monkeypatch.setattr(network.time, "monotonic", lambda: clock)
    assert det.check(buf).details["undeclared"] == ["2.2.2.2:443"]  # stale set still served
    for fn in queued:
        fn()
    assert det.check(buf) is None  # old and new IPs both allowed


def test_registered_in_security_mode():
    names = {d.name for d in create_registry(mode="security").security_detectors}
    assert "undeclared_egress" in names


def test_dedup_key_differs_per_endpoint():
    det, _ = _detector()
    w1 = det.check(_buf(_action([("8.8.4.4", 443)])))
    w2 = det.check(_buf(_action([("9.9.9.9", 443)])))
    assert warning_dedup_key(w1) != warning_dedup_key(w2)
