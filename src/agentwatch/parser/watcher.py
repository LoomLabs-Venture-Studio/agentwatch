"""Real-time file watching for log files."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import AsyncIterator, Callable

from watchfiles import awatch, Change

from .logs import parse_claude_code_entry, parse_moltbot_entry, detect_log_format
from .models import Action

from agentwatch.discovery import AgentProcess


class LogWatcher:
    """Watches a log file for new entries in real-time."""
    
    def __init__(self, path: Path, session_id: str | None = None):
        self.path = path
        self.session_id = session_id
        self._position = 0
        self._log_format: str | None = None
        self._callbacks: list[Callable[[Action], None]] = []
    
    def on_action(self, callback: Callable[[Action], None]) -> None:
        """Register a callback for new actions."""
        self._callbacks.append(callback)
    
    def _parse_entry(self, entry: dict) -> list[Action]:
        """Parse an entry using the detected format. Returns list of actions."""
        if self._log_format is None or self._log_format == "skip":
            self._log_format = detect_log_format(entry)
            if self._log_format == "skip":
                return []

        if self._log_format == "moltbot":
            result = parse_moltbot_entry(entry)
        else:
            result = parse_claude_code_entry(entry)

        if isinstance(result, list):
            return result
        if result:
            return [result]
        return []
    
    def _read_new_lines(self) -> list[Action]:
        """Read any new lines since last check."""
        actions = []
        
        try:
            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self._position)
                
                while True:
                    last_pos = f.tell()
                    line = f.readline()
                    
                    if not line:
                        break
                    
                    # If the line doesn't end with a newline, it might be a partial write
                    # unless we've reached EOF and the file is closed (not our case).
                    if not line.endswith("\n"):
                        # Peek ahead - if there's really nothing more, then it's partial.
                        # Move back to where we started this line.
                        f.seek(last_pos)
                        break
                        
                    line_stripped = line.strip()
                    if not line_stripped:
                        self._position = f.tell()
                        continue
                        
                    try:
                        entry = json.loads(line_stripped)
                        parsed = self._parse_entry(entry)
                        if self.session_id:
                            parsed = [
                                a for a in parsed
                                if a.session_id is None or a.session_id == self.session_id
                            ]
                        actions.extend(parsed)
                        # Only update position if we successfully processed the line
                        self._position = f.tell()
                    except json.JSONDecodeError:
                        # If it's a full line but invalid JSON, skip it to avoid getting stuck
                        self._position = f.tell()
                        continue
        except FileNotFoundError:
            pass
        
        return actions
    
    async def watch(self) -> AsyncIterator[Action]:
        """Watch for new actions, yielding them as they arrive."""
        # First, read existing content
        for action in self._read_new_lines():
            yield action
        
        # Then watch for changes
        async for changes in awatch(self.path.parent):
            for change_type, changed_path in changes:
                if Path(changed_path) == self.path and change_type == Change.modified:
                    for action in self._read_new_lines():
                        yield action
    
    async def watch_with_callbacks(self) -> None:
        """Watch and dispatch to registered callbacks."""
        async for action in self.watch():
            for callback in self._callbacks:
                try:
                    callback(action)
                except Exception:
                    pass  # Don't let callback errors stop watching


class MultiLogWatcher:
    """Watches multiple log files and directories for new logs."""

    def __init__(self, paths: list[Path], poll_interval: float = 0.5):
        self.base_paths = paths
        self.poll_interval = poll_interval
        self.watchers: dict[Path, LogWatcher] = {}
        self._active_files: set[Path] = set()
        self._process_meta: dict[Path, AgentProcess] = {}  # log_path -> process info
        self._stopped_at: dict[Path, float] = {}  # log_path -> monotonic time when first stopped
        self._process_mode: bool = False

    @classmethod
    def from_processes(
        cls, processes: list[AgentProcess], poll_interval: float = 2.0
    ) -> MultiLogWatcher:
        """Create a MultiLogWatcher from discovered agent processes.

        Instead of scanning directories, this watches only the log files
        belonging to currently running agent processes.
        """
        instance = cls(paths=[], poll_interval=poll_interval)
        instance._process_mode = True
        for proc in processes:
            if proc.log_file and proc.log_file.exists():
                instance._process_meta[proc.log_file] = proc
        return instance

    def refresh_processes(self, processes: list[AgentProcess]) -> list[AgentProcess]:
        """Re-scan processes and return newly added agents.

        Updates internal process metadata, adds new log files,
        and marks stopped processes. Returns list of new processes.
        """
        current_pids = {proc.pid for proc in processes}
        new_agents: list[AgentProcess] = []

        # Track which log files belong to still-running processes
        active_log_files: set[Path] = set()

        for proc in processes:
            if proc.log_file and proc.log_file.exists():
                active_log_files.add(proc.log_file)

                if proc.log_file not in self._process_meta:
                    # New agent found
                    self._process_meta[proc.log_file] = proc
                    new_agents.append(proc)
                else:
                    # Update existing process metadata (CPU, MEM, etc.)
                    self._process_meta[proc.log_file] = proc
                # Process is alive, clear any stopped timestamp
                self._stopped_at.pop(proc.log_file, None)

        # Mark stopped processes (keep metadata but flag as stopped)
        stopped_paths = set(self._process_meta.keys()) - active_log_files
        for path in stopped_paths:
            old_proc = self._process_meta[path]
            if old_proc.command != "(stopped)":
                self._stopped_at[path] = time.monotonic()
            self._process_meta[path] = AgentProcess(
                pid=old_proc.pid,
                agent_type=old_proc.agent_type,
                working_directory=old_proc.working_directory,
                log_file=old_proc.log_file,
                session_id=old_proc.session_id,
                cpu_percent=0.0,
                memory_mb=0.0,
                uptime=old_proc.uptime,
                command="(stopped)",
            )

        return new_agents

    def reap_stopped(self, timeout: float = 60.0) -> list[Path]:
        """Remove processes that have been stopped longer than *timeout* seconds.

        Returns the log paths that were removed.
        """
        now = time.monotonic()
        expired: list[Path] = []
        for path, stopped_time in list(self._stopped_at.items()):
            if now - stopped_time >= timeout:
                expired.append(path)
        for path in expired:
            self._stopped_at.pop(path, None)
            self._active_files.discard(path)
            self.watchers.pop(path, None)
            # Keep path in _process_meta so refresh_processes won't re-add it
        return expired

    def get_process_meta(self, log_path: Path) -> AgentProcess | None:
        """Get process metadata for a given log file path."""
        return self._process_meta.get(log_path)

    def _find_all_logs(self) -> list[Path]:
        """Find all .jsonl files in base paths."""
        if self._process_mode:
            return [
                p for p, proc in self._process_meta.items()
                if p.suffix == ".jsonl" and proc.command != "(stopped)"
            ]

        logs = []
        for p in self.base_paths:
            if p.is_file() and p.suffix == ".jsonl":
                logs.append(p)
            elif p.is_dir():
                logs.extend(p.rglob("*.jsonl"))
        return logs

    async def watch(self) -> AsyncIterator[tuple[str, Action | Path]]:
        """
        Watch all files, yielding events.
        Events are (type, data) where type is 'action' or 'agent_added'.
        """
        queue: asyncio.Queue = asyncio.Queue()

        async def fill_queue(watcher: LogWatcher):
            async for action in watcher.watch():
                await queue.put(("action", (action, watcher.path)))

        tasks: dict[Path, asyncio.Task] = {}

        try:
            while True:
                # Check for new files
                current_logs = self._find_all_logs()
                for log_meta in current_logs:
                    if log_meta not in self._active_files:
                        self._active_files.add(log_meta)
                        proc = self._process_meta.get(log_meta)
                        sid = proc.session_id if proc else None
                        watcher = LogWatcher(log_meta, session_id=sid)
                        self.watchers[log_meta] = watcher
                        tasks[log_meta] = asyncio.create_task(fill_queue(watcher))
                        yield ("agent_added", log_meta)

                # Check queue for actions
                while not queue.empty():
                    yield await queue.get()

                await asyncio.sleep(self.poll_interval)
        finally:
            for task in tasks.values():
                task.cancel()
