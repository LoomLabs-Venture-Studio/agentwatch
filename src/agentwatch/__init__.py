"""AgentWatch - Health and security monitoring for AI agents.

AgentWatch monitors AI coding agents (Claude Code, Moltbot, Cursor, etc.)
for behavioral issues and security threats in real-time.

Quick Start:
    # Health check
    agentwatch check

    # Security scan
    agentwatch security-scan

    # Real-time monitoring
    agentwatch watch --security

Features:
    - Health monitoring: loops, thrashing, context rot, error spirals
    - Security monitoring: credential access, prompt injection, exfiltration
    - Support for multiple agents: Claude Code, Moltbot, Cursor
    - TUI dashboard for real-time monitoring
    - JSON output for CI/CD integration
"""

__version__ = "0.2.0"

from agentwatch.detectors import (
    Category,
    Detector,
    DetectorRegistry,
    SecurityDetector,
    Severity,
    Warning,
    create_registry,
)
from agentwatch.health import HealthReport, calculate_health, calculate_security_score
from agentwatch.parser import (
    Action,
    ActionBuffer,
    LogWatcher,
    SessionStats,
    find_latest_session,
    parse_file,
)
from agentwatch.themes import (
    StatusTheme,
    get_theme,
    set_theme,
    list_themes,
    THEMES,
)

__all__ = [
    # Version
    "__version__",
    # Parser
    "Action",
    "ActionBuffer",
    "SessionStats",
    "LogWatcher",
    "parse_file",
    "find_latest_session",
    # Detectors
    "Detector",
    "SecurityDetector",
    "DetectorRegistry",
    "create_registry",
    "Category",
    "Severity",
    "Warning",
    # Health
    "HealthReport",
    "calculate_health",
    "calculate_security_score",
    # Themes
    "StatusTheme",
    "get_theme",
    "set_theme",
    "list_themes",
    "THEMES",
]
