"""Detectors for network anomalies and data exfiltration."""

from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from collections import Counter

from agentwatch.ai_detect import AI_PROVIDERS
from agentwatch.parser.models import ActionBuffer

from ..base import Category, SecurityDetector, Severity, Warning
from .secret_scanner import redact_truncate


class NetworkAnomalyDetector(SecurityDetector):
    """Detects unusual network activity patterns."""

    category = Category.NETWORK
    name = "network_anomaly"
    description = "Unusual network activity detected"

    # Known suspicious hosts/patterns
    SUSPICIOUS_HOSTS = [
        r"pastebin\.com",
        r"paste\.ee",
        r"hastebin\.com",
        r"ghostbin\.",
        r"transfer\.sh",
        r"file\.io",
        r"0x0\.st",
        r"ngrok\.io",
        r"localhost\.run",
        r"serveo\.net",
        r"webhook\.site",
        r"requestbin\.",
        r"pipedream\.net",
    ]

    # Suspicious ports
    SUSPICIOUS_PORTS = {
        4444,   # Metasploit default
        5555,   # Common backdoor
        6666,   # IRC/backdoor
        6667,   # IRC
        8080,   # Common proxy
        9001,   # Tor
        31337,  # Elite/backdoor
    }

    def __init__(self):
        self._host_pattern = re.compile(
            "|".join(self.SUSPICIOUS_HOSTS),
            re.IGNORECASE
        )

    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(20)

        for action in recent:
            # Check for suspicious hosts
            if action.network_host:
                if self._host_pattern.search(action.network_host):
                    return Warning(
                        category=self.category,
                        severity=Severity.HIGH,
                        signal="suspicious_host",
                        message=f"Connection to suspicious host: {action.network_host}",
                        details={
                            "host": action.network_host,
                            "port": action.network_port,
                        },
                    )

            # Check for suspicious ports
            if action.network_port and action.network_port in self.SUSPICIOUS_PORTS:
                return Warning(
                    category=self.category,
                    severity=Severity.HIGH,
                    signal="suspicious_port",
                    message=f"Connection to suspicious port: {action.network_port}",
                    details={
                        "host": action.network_host,
                        "port": action.network_port,
                    },
                )

            # Check commands for network activity
            if action.command:
                cmd = action.command.lower()
                if any(x in cmd for x in ["curl", "wget", "nc ", "ncat"]):
                    # Check if posting data somewhere
                    if any(x in cmd for x in ["-d ", "--data", "-X POST", "| curl"]):
                        return Warning(
                            category=self.category,
                            severity=Severity.MEDIUM,
                            signal="data_upload",
                            message="Data being uploaded via command line",
                            details={"command": redact_truncate(action.command, 80)},
                        )

        return None


class DataExfiltrationDetector(SecurityDetector):
    """Detects patterns consistent with data exfiltration."""

    category = Category.EXFILTRATION
    name = "data_exfiltration"
    description = "Potential data exfiltration detected"

    def __init__(self, window: int = 30):
        self.window = window

    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < 5:
            return None

        recent = buffer.last(self.window)

        # Pattern: Multiple file reads followed by network activity
        file_reads = []
        network_after_reads = False

        for action in recent:
            if action.is_file_read and action.file_path:
                file_reads.append(action.file_path)

            if file_reads and action.is_network:
                network_after_reads = True
                break

        if network_after_reads and len(file_reads) >= 3:
            return Warning(
                category=self.category,
                severity=Severity.HIGH,
                signal="exfil_pattern",
                message=f"Network activity after reading {len(file_reads)} files",
                details={
                    "files_read": file_reads[:5],
                    "file_count": len(file_reads),
                },
            )

        # Pattern: Large data in outgoing messages
        for action in recent:
            if action.outgoing_data and len(action.outgoing_data) > 10000:
                return Warning(
                    category=self.category,
                    severity=Severity.MEDIUM,
                    signal="large_outgoing",
                    message=f"Large data payload ({len(action.outgoing_data)} bytes) in output",
                    details={"size_bytes": len(action.outgoing_data)},
                )

        return None


class C2CommunicationDetector(SecurityDetector):
    """Detects patterns consistent with command-and-control communication."""

    category = Category.NETWORK
    name = "c2_communication"
    description = "Potential C2 communication pattern detected"

    # C2 beacon patterns. Whole words only: "nc" inside "sync"/"function"
    # and "cron" inside "synchronous" flagged a KDE restart command (#41).
    BEACON_INDICATORS = [
        r"\bsleep\s+\d+\s*;.*\b(?:curl|wget|nc)\b",  # Sleep + network
        r"\bwhile\s+true\b.*\b(?:curl|wget)\b",  # Loop + network
        r"\bcron.*\b(?:curl|wget)\b",  # Scheduled network (cron, crontab)
    ]

    def __init__(self, window: int = 50):
        self.window = window
        self._pattern = re.compile("|".join(self.BEACON_INDICATORS), re.IGNORECASE)

    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < 10:
            return None

        recent = buffer.last(self.window)

        # Check for beacon-like command patterns
        for action in recent:
            if action.command and self._pattern.search(action.command):
                return Warning(
                    category=self.category,
                    severity=Severity.CRITICAL,
                    signal="c2_beacon",
                    message="Command pattern consistent with C2 beacon",
                    details={"command": redact_truncate(action.command, 80)},
                )

        # Check for regular network polling
        network_actions = [a for a in recent if a.is_network]
        if len(network_actions) >= 5:
            # Check if hitting same host repeatedly
            hosts = [a.network_host for a in network_actions if a.network_host]
            host_counts = Counter(hosts)

            for host, count in host_counts.most_common(1):
                if count >= 4:
                    return Warning(
                        category=self.category,
                        severity=Severity.MEDIUM,
                        signal="repeated_beacon",
                        message=f"Repeated connections to {host} ({count}x)",
                        details={
                            "host": host,
                            "connection_count": count,
                        },
                    )

        return None


class DNSExfiltrationDetector(SecurityDetector):
    """Detects potential DNS-based data exfiltration."""

    category = Category.EXFILTRATION
    name = "dns_exfiltration"
    description = "Potential DNS exfiltration detected"

    DNS_EXFIL_PATTERNS = [
        r"dig\s+.*\.",  # DNS queries
        r"nslookup\s+",
        r"host\s+\S+\.\S+\.",  # Subdomain queries
        r"curl.*\.burpcollaborator\.",
        r"curl.*\.oast\.",
        r"curl.*\.dnslog\.",
    ]

    def __init__(self):
        self._pattern = re.compile("|".join(self.DNS_EXFIL_PATTERNS), re.IGNORECASE)

    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(15)

        for action in recent:
            if action.command and self._pattern.search(action.command):
                return Warning(
                    category=self.category,
                    severity=Severity.HIGH,
                    signal="dns_exfil",
                    message="Potential DNS exfiltration pattern",
                    details={"command": redact_truncate(action.command, 80)},
                )

        return None


# Claude Code telemetry and auto-update, observed live from claude.exe 2026-10-15; add, don't guess
KNOWN_AGENT_HOSTS = ("http-intake.logs.us5.datadoghq.com", "downloads.claude.ai")

# Non-blocking DNS cache shared by all detector instances: host -> (resolved_at, ips).
# ponytail: IP-level matching, so a CDN IP shared with an allowed host masks an
# undeclared one, and DoH/VPN/proxy traffic isn't seen; refreshed sets are unioned
# (never shrink) so CDN rotation can't cause false positives.
_DNS: dict[str, tuple[float, frozenset[str]]] = {}
_INFLIGHT: set[str] = set()
_DNS_LOCK = threading.Lock()
_DNS_TTL = 300.0


def _daemon(fn) -> None:
    threading.Thread(target=fn, name="egress-dns", daemon=True).start()


def _refresh(host: str, resolve) -> None:
    try:
        ips = frozenset(info[4][0] for info in resolve(host, 443))
    except Exception:  # any failure: empty set, else the host stays pending forever
        ips = frozenset()
    with _DNS_LOCK:
        old = _DNS.get(host)
        _DNS[host] = (time.monotonic(), ips | old[1] if old else ips)
        _INFLIGHT.discard(host)


def _lookup(host: str, resolve, spawn) -> frozenset[str] | None:
    """Cached IPs of *host*; None while its first resolution is pending. A miss
    or a stale entry (re-resolved while the old set is still served) is looked
    up via *spawn*, a background thread by default."""
    with _DNS_LOCK:
        hit = _DNS.get(host)
        start = host not in _INFLIGHT and (hit is None or time.monotonic() - hit[0] > _DNS_TTL)
        if start:
            _INFLIGHT.add(host)
    if start:
        spawn(lambda: _refresh(host, resolve))
    hit = _DNS.get(host)
    return hit[1] if hit else None


def _ip(text: str):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _flaggable(ip: str) -> bool:
    a = _ip(ip)
    return a is not None and not (
        a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified
    )


class UndeclaredEgressDetector(SecurityDetector):
    """Flags endpoints seen on the wire that no declared host explains.

    Allowed: LLM provider hosts, KNOWN_AGENT_HOSTS and every network_host in
    the buffer, by resolved IP. Loopback/link-local/multicast/unspecified are
    never flagged; private (RFC 1918) addresses are.

    Limits: connections shorter than the sampler's poll interval are missed;
    matching is IP-level; editor-hosted sessions are never sampled, so they
    never carry observed endpoints.
    """

    category = Category.NETWORK
    name = "undeclared_egress"
    description = "Network connection no action declared"

    def __init__(self, resolve=socket.getaddrinfo, spawn=_daemon):
        self._resolve = resolve
        self._spawn = spawn

    def check(self, buffer: ActionBuffer) -> Warning | None:
        seen = [
            (ip, port) for a in buffer.last(20) for ip, port in a.observed_endpoints or ()
            if _flaggable(ip)
        ]
        if not seen:
            return None  # one-shot scans never sample: no DNS
        hosts = {h for domains in AI_PROVIDERS.values() for h in domains}
        hosts.update(KNOWN_AGENT_HOSTS)
        # Whole buffer: a keep-alive socket from an early WebFetch can outlive 20 actions.
        hosts.update(a.network_host for a in buffer.actions if a.network_host)
        allowed: set[str] = set()
        pending = False
        for host in hosts:
            if _ip(host) is not None:
                allowed.add(host)
                continue
            ips = _lookup(host, self._resolve, self._spawn)
            pending |= ips is None
            allowed |= ips or set()
        if pending:
            return None  # warm-up: the next tick decides
        undeclared = list(dict.fromkeys(  # most recent first
            f"{ip}:{port}" for ip, port in reversed(seen) if ip not in allowed
        ))
        if not undeclared:
            return None
        more = f" (+{len(undeclared) - 1} more)" if len(undeclared) > 1 else ""
        return Warning(
            category=self.category,
            severity=Severity.MEDIUM,
            signal="undeclared_egress",
            message=f"Undeclared egress to {undeclared[0]}{more}",
            details={
                "endpoint": undeclared[0],
                "undeclared": undeclared[:5],
                "count": len(undeclared),
            },
        )
