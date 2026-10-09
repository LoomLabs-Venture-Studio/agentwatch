"""Process -> adapter routing: the agent is identified by its program, not its args."""

from __future__ import annotations

import pytest

from agentwatch.discovery import match_process_adapter, program_path

NVM = "/home/u/.nvm/versions/node/v24/lib/node_modules"


def _route(argv: list[str]) -> str | None:
    adapter = match_process_adapter(argv)
    return adapter.name if adapter else None


@pytest.mark.parametrize(
    "argv, expected",
    [
        # Agent arguments that mention another agent's name (manager audit, PR #29).
        ([f"{NVM}/@github/copilot/node_modules/@github/copilot-linux-x64/copilot",
          "--model", "claude-sonnet-4.5"], "copilot"),
        (["copilot", "--model", "gpt-5.1-codex"], "copilot"),
        (["agy", "-p", "compare claude and codex output"], "agy"),
        (["/home/u/.venv/bin/python3", "/home/u/.venv/bin/aider",
          "--model", "claude-3-5-sonnet"], "aider"),
    ],
)
def test_arguments_do_not_steal_pid(argv, expected):
    assert _route(argv) == expected


@pytest.mark.parametrize(
    "argv, expected",
    [
        # Seen live on this machine (2026-10-03).
        (["claude"], "claude-code"),
        (["claude", "--agent", "cto", "--dangerously-skip-permissions"], "claude-code"),
        (["/home/u/.local/share/claude/versions/2.1.288"], "claude-code"),  # native install target
        # npm package 2.1.288: postinstall copies the native binary over bin/claude.exe;
        # cli-wrapper.cjs spawns the platform package's `claude` binary.
        ([f"{NVM}/@anthropic-ai/claude-code/bin/claude.exe"], "claude-code"),
        ([f"{NVM}/@anthropic-ai/claude-code-linux-x64/claude", "-p", "hi"], "claude-code"),
        # Pre-native npm releases ran the agent in node.
        (["node", f"{NVM}/@anthropic-ai/claude-code/cli.js"], "claude-code"),
        (["node", "/usr/local/bin/claude", "--resume"], "claude-code"),
        ([r"C:\Users\u\AppData\Roaming\npm\claude.exe"], "claude-code"),
        # `npx @openai/codex` chain seen live (0.160.0), then the native binary it spawns.
        (["node", "/home/u/.npm/_npx/c8ab/node_modules/.bin/codex", "--version"], "codex"),
        (["node", f"{NVM}/@openai/codex/bin/codex.js"], "codex"),
        ([f"{NVM}/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex"], "codex"),
        (["codex", "exec", "fix it"], "codex"),
        (["python", "-m", "aider", "--model", "gpt-4o"], "aider"),
        (["aider"], "aider"),
        (["agy", "--dangerously-skip-permissions", "-p", "hi"], "agy"),
    ],
)
def test_real_invocations_route_to_their_adapter(argv, expected):
    assert _route(argv) == expected


@pytest.mark.parametrize(
    "argv",
    [
        # Seen live: Claude Desktop (Electron) and its helpers.
        ["/usr/lib/claude-desktop/claude-desktop", "--type=zygote"],
        ["/usr/lib/claude-desktop/resources/cowork-linux-helper", "-socket",
         "/run/user/1000/claude-cowork-vm.sock"],
        # Seen live: the npx launcher and its shell are not the agent (the child is).
        ["npm", "exec", "@openai/codex", "--version"],
        ["sh", "-c", "'codex'", "--version"],
        [f"{NVM}/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex-code-mode-host"],
        # Shells and scripts that merely mention an agent.
        ["/bin/bash", "-c", "source ~/.claude/shell-snapshots/s.sh && agentwatch ps"],
        ["python", "-c", "print('claude')"],
        ["grep", "-iE", "claude|codex|aider"],
    ],
)
def test_non_agents_do_not_match(argv):
    assert _route(argv) is None


def test_program_path():
    assert program_path(["node", "--no-warnings", "/x/cli.js", "a"]) == "/x/cli.js"
    assert program_path(["python3.12", "-m", "aider"]) == "aider"
    assert program_path(["node", "-e", "x"]) == "node"
    assert program_path([], "claude") == "claude"


@pytest.mark.parametrize(
    "argv",
    [
        # A session's own arguments must not hide it (manager re-audit, PR #29).
        ["claude", "-p", "look at shell-snapshots"],
        ["claude", "--agent", "claude-code-guide"],
        ["/home/u/.local/bin/claude", "--add-dir", "/Applications/Claude.app"],
    ],
)
def test_claude_args_do_not_trigger_exclude(argv):
    assert _route(argv) == "claude-code"


def test_excludes_still_apply_to_the_program():
    assert _route(["/Applications/Claude.app/Contents/Resources/claude"]) is None
    assert _route(["node", "/Applications/Claude.app/Contents/Resources/cli.js"]) is None
    # Copilot's node loader (seen live) still yields to the native binary it spawns.
    assert _route(["node", "/home/u/.nvm/versions/node/v24/bin/copilot", "-p", "hi"]) is None
    assert _route(["node", f"{NVM}/@github/copilot/npm-loader.js"]) is None
    # Claude Desktop's Windows Store install (seen live 2026-10-09).
    desktop = r"C:\Program Files\WindowsApps\Claude_2.31226.0.0_x64__pzs8sxrjxfjjc\app"
    assert _route([desktop + r"\claude.exe"]) is None
    assert _route([desktop + r"\Claude.exe", "--type=renderer"]) is None


def test_chrome_native_host_is_not_a_session():
    # Claude in Chrome's bridge runs the CLI binary but is no session (seen live).
    assert _route([r"C:\Users\u\.local\bin\claude.exe", "--chrome-native-host"]) is None
    assert _route(["claude", "-p", "explain --chrome-native-host"]) == "claude-code"


def test_pythonw_is_an_interpreter():
    assert program_path([r"C:\Python312\pythonw.exe", r"C:\venv\Scripts\aider"]) == (
        r"C:\venv\Scripts\aider"
    )
