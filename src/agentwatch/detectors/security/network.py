"""Detectors for network anomalies and data exfiltration."""

from __future__ import annotations

import re
from collections import Counter

from agentwatch.parser.models import ActionBuffer

from ..base import Category, SecurityDetector, Severity, Warning


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
                            details={"command": action.command[:80]},
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
    
    # C2 beacon patterns
    BEACON_INDICATORS = [
        r"sleep\s+\d+\s*;.*(?:curl|wget|nc)",  # Sleep + network
        r"while\s+true.*(?:curl|wget)",  # Loop + network
        r"cron.*(?:curl|wget)",  # Scheduled network
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
                    details={"command": action.command[:80]},
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
                    details={"command": action.command[:80]},
                )
        
        return None
