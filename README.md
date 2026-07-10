# AgentWatch

Real-time health and security monitoring for AI coding agents.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What is AgentWatch?

AgentWatch monitors AI agents (full support for Claude Code; experimental/partial support for Aider, Codex CLI, and Moltbot — see [Supported Agents](#supported-agents)) for:

- **Health Issues**: Loops, thrashing, context rot, error spirals
- **Security Threats**: Credential theft, prompt injection, data exfiltration
- **Operational Efficiency**: Token burn rate, context pressure, cache utilization

Think of it as a fitness tracker for your AI agent, plus a security guard.

### Installation

**As a CLI tool (Recommended):**

```bash
pipx install agentwatch-monitor
```

**As a library:**

```bash
pip install agentwatch-monitor
```

> [!TIP]
> Use `pipx` for CLI tools to avoid "externally managed environment" errors and keep your system Python clean.

## Quick Start

```bash
# Health check
agentwatch check

# Security scan
agentwatch security-scan

# Real-time monitoring TUI
agentwatch watch --security

# Monitor all running agents
agentwatch watch-all

# List running agent processes
agentwatch ps

# Token usage stats
agentwatch stats
agentwatch stats --burn
```

## Scoring System

AgentWatch produces three independent scores that blend into one overall health score.

### Overall Health Score

The overall score is a weighted blend of three components:

| Component          | Weight | What it measures                                   |
| ------------------ | ------ | -------------------------------------------------- |
| **Detectors**      | 40%    | Behavioral warnings from pattern detectors         |
| **Efficiency**     | 30%    | Operational resource usage (tokens, cache, pacing) |
| **Context Health** | 30%    | Session rot (repetition, thrashing, stalling)      |

Weights are configurable via `HealthWeights(detectors=0.4, efficiency=0.3, rot=0.3)`.

### Status States

All three scoring systems share a unified 4-state status:

| Status       | Score Range | Meaning                                |
| ------------ | ----------- | -------------------------------------- |
| **Healthy**  | 80 - 100    | Everything is operating normally       |
| **Degraded** | 60 - 79     | Performance declining, monitor closely |
| **Warning**  | 40 - 59     | Significant issues, consider acting    |
| **Critical** | 0 - 39      | Immediate action needed                |

### Detector Categories

Detectors produce warnings with severity levels that deduct from a per-category score (starting at 100):

| Severity | Score Impact |
| -------- | ------------ |
| LOW      | -5           |
| MEDIUM   | -15          |
| HIGH     | -30          |
| CRITICAL | -50          |

Health detector categories and their weights in the detector score:

| Category     | Weight | What it covers                     |
| ------------ | ------ | ---------------------------------- |
| **Progress** | 35%    | Loops, stalls, thrashing           |
| **Errors**   | 30%    | Error spirals, repeated failures   |
| **Context**  | 20%    | Context rot, rediscovery, pressure |
| **Goal**     | 15%    | Goal drift, wasted effort          |

### Efficiency Score

Pure operational resource metrics, independent of behavioral signals. Sub-metrics grouped into three penalty categories:

| Category     | Sub-metrics                                              | What it tracks                                              |
| ------------ | -------------------------------------------------------- | ----------------------------------------------------------- |
| **Pressure** | Context pressure (30%), burn rate (20%), I/O ratio (10%) | How fast the session is consuming its token budget          |
| **Cache**    | Cache hit rate (15%)                                     | How effectively the session reuses cached context           |
| **Pacing**   | Duration (15%), actions per turn (10%)                   | How long the session has been running and tool call density |

Context pressure uses cumulative throughput against a 2M token session budget. This is monotonically increasing and survives auto-compaction and tool restarts.

Cost (estimated from token counts) is displayed as informational only and does not affect the score.

### Context Health (Rot Detection)

Deterministic rot detection tracks five metric families:

| Metric          | What it detects                                                |
| --------------- | -------------------------------------------------------------- |
| **Behavioral**  | Output length inflation, hedge word density                    |
| **Repetition**  | Repeated sentences, self-repeating n-grams                     |
| **Tool Thrash** | Repeated commands, error loops, stalls                         |
| **Progress**    | Edit deficit, file churn                                       |
| **Constraints** | Violated project constraints (forbidden paths, required files) |

The rot score uses EMA smoothing and a state machine that requires sustained degradation before escalating status.

#### Session Maturity Scaling

Progress-based metrics (edit deficit, stall detection) use **session maturity scaling** to avoid penalizing early conversation. This prevents casual greetings or questions from immediately tanking the health score.

Maturity reaches 1.0 (full penalties) when:

- Any file edit occurs (coding has started), OR
- 3+ turns of code exploration (Read/Search) without edits (agent should be coding by now)

Otherwise, penalties ramp gradually from 0.0 to 1.0 over the first 10 turns.

| Session Pattern                 | Maturity | Effect                         |
| ------------------------------- | -------- | ------------------------------ |
| Greeting + quick question       | 0.2      | Progress penalties reduced 80% |
| 3+ turns reading code, no edits | 1.0      | Full penalties (stalling)      |
| First edit on turn 1            | 1.0      | Full penalties (coding mode)   |
| 10+ turns of pure chat          | 1.0      | Full penalties (ramped up)     |

This scaling only affects progress/stall metrics. Behavioral signals (repetition, error loops, thrashing) always apply at full strength since they indicate real context degradation regardless of session phase.

## Health Detectors (15)

| Detector                  | What It Catches                                       |
| ------------------------- | ----------------------------------------------------- |
| `loop`                    | Agent repeating the same action                       |
| `reread`                  | Re-reading same file multiple times                   |
| `thrash`                  | Repeated edit -> test -> fail cycle                   |
| `stall`                   | No meaningful progress detected                       |
| `same_outcome`            | Different fixes producing the same error              |
| `file_churn`              | File edited repeatedly without a successful test      |
| `exploration_stall`       | No new files explored despite continued activity      |
| `error_class_persistence` | Same type of error persisting despite different fixes |
| `error_spiral`            | Multiple consecutive failures                         |
| `error_blindness`         | Same error repeated without fix                       |
| `syntax_loop`             | Repeated syntax/import errors                         |
| `high_error_rate`         | Unusually high failure rate                           |
| `context_rot`             | Important early files no longer being referenced      |
| `context_pressure`        | Context window filling up                             |
| `rediscovery`             | Agent re-discovering previously learned information   |

## Security Detectors (20)

| Detector               | What It Catches                                           |
| ---------------------- | --------------------------------------------------------- |
| `credential_access`    | Agent accessing credential or secret files                |
| `secret_in_output`     | Potential secret/credential in agent output               |
| `credential_exfil`     | Credential access followed by network activity            |
| `secret_leak_scanner`  | Real-time scanning for secrets leaked through any channel |
| `prompt_injection`     | "Ignore previous instructions" attacks                    |
| `hidden_instruction`   | Zero-width chars, encoded commands                        |
| `indirect_injection`   | Potential injection from external content                 |
| `network_anomaly`      | Unusual network activity                                  |
| `data_exfiltration`    | File reads followed by network activity                   |
| `c2_communication`     | Potential C2 communication pattern                        |
| `dns_exfiltration`     | Potential DNS exfiltration/tunneling                      |
| `privilege_escalation` | sudo, chmod +s, etc.                                      |
| `dangerous_command`    | rm -rf /, fork bombs                                      |
| `mass_file_operation`  | Mass file operation detected                              |
| `sensitive_directory`  | Access to sensitive system directory                      |
| `malicious_skill`      | Skill exhibiting suspicious behavior                      |
| `skill_network`        | Skill making network requests                             |
| `new_skill`            | New skill started executing                               |
| `skill_chain`          | Suspicious skill chaining                                 |
| `skill_install`        | New skill being installed                                 |

AgentWatch registers **35 detectors total** (15 health + 20 security), enumerated at runtime via `agentwatch.detectors.registry.get_all_health_detectors()` / `get_all_security_detectors()` — this is the source of truth if the numbers above ever drift.

Security categories and weights:

| Category     | Weight |
| ------------ | ------ |
| Injection    | 25%    |
| Credential   | 20%    |
| Exfiltration | 20%    |
| Privilege    | 15%    |
| Network      | 10%    |
| Supply Chain | 10%    |

A single CRITICAL severity security warning immediately sets the security score to 0.

## Supported Agents

| Agent                  | Process Discovery                                | Log Parsing (health/security analysis)      | Status                                              |
| ---------------------- | ------------------------------------------------ | ------------------------------------------- | --------------------------------------------------- |
| **Claude Code**        | Yes (`~/.claude/projects/*/` logs)               | Yes                                         | Fully supported                                     |
| **Moltbot / Clawdbot** | No (not auto-discovered by `agentwatch ps`)      | Yes (`~/.moltbot/agents/*/sessions/` logs)  | Partial — point AgentWatch at the log file directly |
| **Aider**              | Yes (process + `.aider.chat.history.md` located) | No (log format not yet parsed into actions) | Partial — detected but not analyzed                 |
| **Codex CLI**          | Yes (process pattern only)                       | No                                          | Detection only                                      |
| Cursor                 | No                                               | No                                          | Planned                                             |

Verified against `src/agentwatch/discovery.py` (`AGENT_PATTERNS`, log-file resolution) and `src/agentwatch/parser/logs.py` (`detect_log_format`, `parse_claude_code_entry`, `parse_moltbot_entry`).

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
# Single agent TUI
agentwatch watch

# With security monitoring
agentwatch watch --security

# All running agents
agentwatch watch-all
```

### Process Discovery

```bash
# List running agent processes with PIDs and session IDs
agentwatch ps

# JSON output for scripting
agentwatch ps --json
```

### Token Usage Stats

```bash
# Stats for current project
agentwatch stats

# Stats across all projects
agentwatch stats --all

# Analyze a specific session
agentwatch stats --session <SESSION_ID>

# Efficiency analysis — see how many tokens went to trivial
# commands (git, ls, npm run dev) vs substantive AI work
agentwatch stats --burn

# JSON output
agentwatch stats --json
```

### AgentGuard (Security-Focused CLI)

```bash
# Same tool, security-first defaults
agentguard scan
agentguard watch
```

## Exit Codes

| Code | Meaning             |
| ---- | ------------------- |
| 0    | Healthy or Degraded |
| 1    | Warning             |
| 2    | Critical            |

Use in CI/CD:

```bash
agentwatch check --json || echo "Agent health issues detected"
agentwatch security-scan || echo "Security issues detected"
```

## Configuration

```python
from agentwatch import create_registry, ActionBuffer, parse_file
from agentwatch.health import HealthWeights, calculate_health, calculate_efficiency

# Create custom registry
registry = create_registry(mode="all")  # "health", "security", or "all"

# Parse logs
buffer = ActionBuffer()
for action in parse_file(Path("session.jsonl")):
    buffer.add(action)

# Run checks
warnings = registry.check_all(buffer)

# Calculate scores with custom weights
eff = calculate_efficiency(warnings, buffer)
report = calculate_health(
    warnings,
    efficiency_score=eff.score,
    rot_score=0.2,
    weights=HealthWeights(detectors=0.5, efficiency=0.25, rot=0.25),
)

print(f"Overall: {report.overall_score}% ({report.status})")
```

### Custom Detectors

```python
from agentwatch import Detector, Category, Severity, Warning, ActionBuffer

class MyDetector(Detector):
    category = Category.PROGRESS
    name = "my_detector"
    description = "Detects my custom pattern"

    def check(self, buffer: ActionBuffer) -> Warning | None:
        if some_condition:
            return Warning(
                category=self.category,
                severity=Severity.HIGH,
                signal="my_signal",
                message="Something bad detected",
            )
        return None

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
                          v (optional, on suspicious activity)
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

## Multi-Agent Monitoring

`agentwatch watch-all` auto-discovers running agents via process scanning and monitors them on a unified dashboard. Each agent gets its own isolated scoring pipeline. Agent identification uses `lsof` to resolve the exact log file each process has open, preventing cross-contamination when multiple agents work on the same project.

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
