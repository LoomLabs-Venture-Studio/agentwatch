# AgentWatch 🔍

Real-time health and security monitoring for AI coding agents.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What is AgentWatch?

AgentWatch monitors AI agents (Claude Code, Moltbot, Cursor, Aider) for:

- **Health Issues**: Loops, thrashing, context rot, error spirals
- **Security Threats**: Credential theft, prompt injection, data exfiltration

Think of it as a fitness tracker for your AI agent, plus a security guard.

## Quick Start

```bash
pip install agentwatch

# Health check
agentwatch check

# Security scan
agentwatch security-scan

# Real-time monitoring with TUI
agentwatch watch --security
```

## Why AgentWatch?

AI agents with system access can:
- Get stuck in infinite loops, wasting time and money
- Forget important context (context rot)
- Access sensitive credentials
- Be manipulated via prompt injection
- Exfiltrate data to external services

AgentWatch detects these issues in real-time.

## Features

### Health Monitoring

| Detector | What It Catches |
|----------|-----------------|
| `loop` | Agent repeating the same action |
| `thrash` | Edit→test→fail cycles |
| `reread` | Re-reading files excessively |
| `stall` | Lots of reading, no writing |
| `error_spiral` | Consecutive failures |
| `error_blindness` | Same error repeated without fix |
| `context_rot` | Early important files forgotten |
| `context_pressure` | Context window filling up |

### Security Monitoring

| Detector | What It Catches |
|----------|-----------------|
| `credential_access` | Reading ~/.aws, ~/.ssh, .env files |
| `secret_in_output` | API keys, tokens in output |
| `prompt_injection` | "Ignore previous instructions" attacks |
| `hidden_instruction` | Zero-width chars, encoded commands |
| `privilege_escalation` | sudo, chmod +s, etc. |
| `dangerous_command` | rm -rf /, fork bombs |
| `network_anomaly` | Connections to pastebin, webhook.site |
| `data_exfiltration` | File reads followed by network |
| `malicious_skill` | Skills accessing credentials |

## Supported Agents

- ✅ **Claude Code** - `~/.claude/projects/*/` logs
- ✅ **Moltbot** - `~/.moltbot/agents/*/sessions/` logs
- 🔜 Cursor
- 🔜 Aider
- 🔜 Codex CLI

## Usage

### One-Time Health Check

```bash
# Auto-detect latest session
agentwatch check

# Specific log file
agentwatch check --log ~/.claude/projects/myapp/session.jsonl

# Include security checks
agentwatch check --security

# JSON output (for CI/CD)
agentwatch check --json
```

### Security Scan

```bash
# Security-only scan
agentwatch security-scan

# JSON output
agentwatch security-scan --json
```

### Real-Time Monitoring

```bash
# Health monitoring TUI
agentwatch watch

# With security monitoring
agentwatch watch --security
```

### AgentGuard (Security-Focused CLI)

```bash
# Same tool, security-first defaults
agentguard scan
agentguard watch
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Healthy / Secure |
| 1 | Warnings detected |
| 2 | Critical issues |

Use in CI/CD:

```bash
agentwatch check --json || echo "Agent health issues detected"
agentwatch security-scan || echo "Security issues detected"
```

## Configuration

```python
from agentwatch import create_registry, ActionBuffer, parse_file

# Create custom registry
registry = create_registry(mode="all")  # "health", "security", or "all"

# Parse logs
buffer = ActionBuffer()
for action in parse_file(Path("session.jsonl")):
    buffer.add(action)

# Run checks
warnings = registry.check_all(buffer)

for w in warnings:
    print(f"{w.emoji} [{w.signal}] {w.message}")
```

### Custom Detectors

```python
from agentwatch import Detector, Category, Severity, Warning, ActionBuffer

class MyDetector(Detector):
    category = Category.PROGRESS
    name = "my_detector"
    description = "Detects my custom pattern"
    
    def check(self, buffer: ActionBuffer) -> Warning | None:
        # Your detection logic here
        if some_condition:
            return Warning(
                category=self.category,
                severity=Severity.HIGH,
                signal="my_signal",
                message="Something bad detected",
            )
        return None

# Register it
registry.add_detector(MyDetector())
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  TIER 1: Deterministic Detectors (always on)            │
│  - Pattern matching, regex, thresholds                  │
│  - Zero cost, zero latency, auditable                   │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼ (optional, on suspicious activity)
┌─────────────────────────────────────────────────────────┐
│  TIER 2: LLM Analysis (opt-in)                          │
│  - Semantic analysis of ambiguous cases                 │
│  - Local model (Ollama) or cheap API (Haiku)            │
└─────────────────────────────────────────────────────────┘
```

All built-in detectors are deterministic (Tier 1) for:
- **Auditability**: Can explain exactly why alerts fired
- **Speed**: Real-time detection
- **Cost**: No API calls
- **No meta-injection**: Can't fool a regex

## Why Deterministic?

For security monitoring, you need:
- **Audit trails**: "Why did this alert fire?"
- **Reliability**: No hallucinated false negatives
- **Speed**: Detect credential theft before exfiltration
- **Independence**: Works offline, no API dependencies

LLM-based analysis is available as optional Tier 2 for semantic analysis of ambiguous cases.

## Moltbot Security Context

AgentWatch was built with [Moltbot](https://molt.bot) security in mind:

- Detects access to `~/.moltbot/credentials/`
- Monitors skill behavior for malicious patterns
- Catches prompt injection via messaging integrations
- Alerts on supply chain attacks via ClawdHub skills

## Contributing

Contributions welcome! Especially:

- New detectors for failure patterns you've observed
- Support for additional agents (Cursor, Aider, etc.)
- Better heuristics for existing detectors
- SIEM integration (Splunk, Elastic, etc.)

## License

MIT

---

Built for developers who give AI agents real power and want to keep that power in check.
