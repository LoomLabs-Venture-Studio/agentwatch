"""Console-script entry. `agentwatch hook` runs on every Claude Code tool call,
so it skips importing the full CLI (Click, Textual, discovery, ...)."""

import sys


def main() -> None:
    if sys.argv[1:2] == ["hook"]:
        from agentwatch.coach import main as coach_main

        coach_main()
    from agentwatch.cli import main as cli_main

    cli_main()
