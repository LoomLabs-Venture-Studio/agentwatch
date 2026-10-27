"""Claude Code adapter (also owns Moltbot-format JSONL, which is a log
format, not a discoverable agent)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import BaseAdapter, Watcher, sniff_jsonl_format, source_path

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action


class ClaudeCodeAdapter(BaseAdapter):
    name = "claude-code"
    kind = "process"
    # Matched against the program path (discovery.program_path), never the args.
    # Native binary (`claude`, npm `bin/claude.exe`, `claude-<platform>/claude`), the
    # native installer's `claude/versions/<ver>`, and pre-native npm `cli.js`.
    process_pattern = (
        r"(^|[/\\])claude(\.exe)?$"
        r"|[/\\]claude[/\\]versions[/\\][^/\\]+$"
        r"|[/\\]@anthropic-ai[/\\]claude-code[/\\]cli\.js$"
    )
    # Claude Desktop is not the CLI: macOS bundle, Windows Store (MSIX) install, and
    # the non-Store Squirrel install `AnthropicClaude\app-<ver>\claude.exe`
    # (anthropics/claude-code#36079).
    process_exclude = (
        r"Claude\.app|Claude Helper|WindowsApps[/\\]Claude_|AnthropicClaude[/\\]app-"
    )
    # Claude in Chrome's bridge runs the CLI binary but is no session.
    process_exclude_args = frozenset({"--chrome-native-host"})

    def resolve_log(self, cwd: Path, pid: int | None) -> tuple[Path | None, str | None]:
        from agentwatch import discovery  # call-time lookup: tests monkeypatch this

        return discovery._resolve_claude_code_log(cwd, pid=pid)

    def claims(self, path: Path) -> bool:
        # Every JSONL that isn't another agent's or unrecognised -- including
        # missing/undecidable files, which parse_file() has always treated as
        # Claude Code/Moltbot.
        return path.suffix == ".jsonl" and sniff_jsonl_format(path) not in (
            "codex", "copilot", "agy", "gemini", "copilot_vscode", "unknown",
        )

    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher:
        from agentwatch.parser.watcher import LogWatcher

        return LogWatcher(source_path(source), session_id=session_id)

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        from agentwatch.parser.logs import _parse_jsonl

        return _parse_jsonl(path, session_id)

    def history_logs(self) -> Iterator[Path]:
        from agentwatch.cc_stats import find_all_project_dirs

        for project_dir in find_all_project_dirs():
            yield from project_dir.rglob("*.jsonl")  # subagents/ too: their calls are billed

    def history_meta(self, path: Path) -> tuple[str, str | None]:
        from agentwatch.cc_stats import _projects_dir, project_dir_to_name

        try:
            project_dir = _projects_dir() / path.relative_to(_projects_dir()).parts[0]
        except (ValueError, IndexError):
            return path.stem, None
        return path.stem, project_dir_to_name(project_dir, log=path)
