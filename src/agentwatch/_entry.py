"""Console-script entry. `agentwatch hook` runs on every Claude Code tool call
and `agentwatch statusline` on every status line update, so both skip
importing the full CLI (Click, Textual, discovery, ...)."""

import sys


def main() -> None:
    if sys.argv[1:2] == ["hook"]:
        from agentwatch.coach import main as coach_main

        coach_main()
    if sys.argv[1:2] == ["statusline"] and set(sys.argv[2:]) <= {"--ok", "--cost"}:
        from agentwatch.statusline import main as statusline_main

        statusline_main(ok="--ok" in sys.argv[2:], cost="--cost" in sys.argv[2:])
    from agentwatch.cli import main as cli_main

    cli_main()
