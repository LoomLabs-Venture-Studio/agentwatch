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

__version__ = "0.2.1"

# Public names load on first access (PEP 562), so `import agentwatch._entry`
# (the hook and the status line, run on every tool call / UI update) does not
# pay for the parser, detectors and Textual.
_EXPORTS = {
    "agentwatch.cc_stats": ("BashCategory", "StatsReport", "ToolCategory", "compute_stats"),
    "agentwatch.detectors": ("Category", "Detector", "DetectorRegistry", "SecurityDetector",
                             "Severity", "Warning", "create_registry"),
    "agentwatch.health": ("HealthReport", "calculate_health", "calculate_security_score"),
    "agentwatch.parser": ("Action", "ActionBuffer", "LogWatcher", "SessionStats",
                          "find_latest_session", "parse_file"),
    "agentwatch.themes": ("THEMES", "StatusTheme", "get_theme", "list_themes", "set_theme"),
}
_MODULE_OF = {name: module for module, names in _EXPORTS.items() for name in names}


def __getattr__(name: str):
    import importlib

    module = _MODULE_OF.get(name)
    if module is not None:
        value = getattr(importlib.import_module(module), name)
        globals()[name] = value
        return value
    if not name.startswith("_"):
        # A submodule (agentwatch.parser, .detectors, ...): the eager imports
        # used to make these attributes as a side effect.
        try:
            return importlib.import_module(f"{__name__}.{name}")
        except ModuleNotFoundError as e:
            if e.name != f"{__name__}.{name}":
                raise
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_MODULE_OF))


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
    # Stats
    "BashCategory",
    "StatsReport",
    "ToolCategory",
    "compute_stats",
    # Themes
    "StatusTheme",
    "get_theme",
    "set_theme",
    "list_themes",
    "THEMES",
]
