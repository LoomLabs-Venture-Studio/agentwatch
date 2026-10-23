"""Codex (OpenAI) adapter."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import BaseAdapter, Watcher, folder_name, sniff_jsonl_format, source_path

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess
    from agentwatch.parser.models import Action


class CodexAdapter(BaseAdapter):
    name = "codex"
    kind = "process"
    # Program path: the native binary, or node running `.bin/codex` / `bin/codex.js`.
    # GitHub release archives ship it unrenamed as `codex-<target-triple>[.exe]`
    # (openai/codex README L55-64 @ 6f47fcb; rust-v0.162.1 assets): `codex-aarch64-apple-darwin`.
    process_pattern = r"(^|[/\\])codex(-(aarch64|x86_64)-[\w-]+)?(\.exe|\.js)?$"
    process_exclude = None

    def resolve_log(self, cwd: Path, pid: int | None) -> tuple[Path | None, str | None]:
        from agentwatch import discovery

        return discovery._resolve_codex_log(cwd, pid=pid)

    def claims(self, path: Path) -> bool:
        return path.suffix == ".jsonl" and sniff_jsonl_format(path) == "codex"

    def make_watcher(self, source: AgentProcess | Path, session_id: str | None) -> Watcher:
        # LogWatcher auto-detects Codex and owns the no-flush-on-poll rule.
        from agentwatch.parser.watcher import LogWatcher

        return LogWatcher(source_path(source), session_id=session_id)

    def parse_file(
        self, path: Path, session_id: str | None = None, **opts: Any
    ) -> Iterator[Action]:
        from agentwatch.parser.logs import _parse_jsonl

        return _parse_jsonl(path, session_id)

    def history_logs(self) -> Iterator[Path]:
        from agentwatch.discovery import _codex_sessions_root

        return _codex_sessions_root().rglob("rollout-*.jsonl")

    def history_meta(self, path: Path) -> tuple[str, str | None]:
        from agentwatch.discovery import _read_codex_session_meta

        meta = _read_codex_session_meta(path) or {}
        return str(meta.get("id") or path.stem), folder_name(meta.get("cwd"))
