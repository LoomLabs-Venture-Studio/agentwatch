<p align="center">
  <img src="docs/assets/images/banner.svg" alt="AgentWatch: know when your AI coding assistant needs you" width="100%">
</p>

<p align="center">
  <a href="https://pypi.org/project/agentwatch-monitor/"><img src="https://img.shields.io/pypi/v/agentwatch-monitor.svg" alt="PyPI"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="MIT license"></a>
  <br>
  <a href="https://agentwatch.info"><b>agentwatch.info</b></a>
</p>

AgentWatch watches Claude Code, Cursor, Codex and other AI coding assistants
while they work. It tells you when one is going in circles, keeps failing,
burns money, or does something risky with your keys or data. It runs on
your own computer and reads the logs your assistant already writes.

![The AgentWatch dashboard with four sessions](docs/assets/images/dashboard.svg)

## Install

```bash
pipx install agentwatch-monitor
```

## Quick start

```bash
agentwatch check           # check your latest session
agentwatch watch-all       # live dashboard of every running assistant
agentwatch security-scan   # leaked keys, prompt injection, risky commands
```

Run `agentwatch --help` for all commands, or see
[agentwatch.info/commands](https://agentwatch.info/commands/).

## Works with

Claude Code · Cursor · Aider · Codex · GitHub Copilot (CLI and VS Code) ·
Antigravity · Gemini CLI · OpenCode · Kilo Code · Cline · Claude Desktop

Some are tested against sample logs only. See
[supported agents](https://agentwatch.info/supported-agents/).

## Claude Code plugin

Coaches Claude when it gets stuck and blocks a looping step:

```text
/plugin marketplace add LoomLabs-Venture-Studio/agentwatch
/plugin install agentwatch@agentwatch
```

## Privacy

No server, no account, no telemetry. Your code and conversations stay on
your computer.

## Contributing

Pull requests target `develop`. Setup: `pip install -e ".[dev,siem,llm]"`,
then `python -m pytest tests/` and `ruff check .`

MIT licensed. Built by [LoomLabs](https://loomlabs.io).
