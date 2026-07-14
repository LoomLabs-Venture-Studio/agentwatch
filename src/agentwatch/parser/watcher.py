"""Real-time file watching for log files."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import AsyncIterator, Callable

from watchfiles import Change, awatch

from agentwatch.discovery import AgentProcess

from .aider import parse_aider_sessions
from .codex import CodexParser
from .cursor_source import (
    bubble_to_action,
    fetch_bubbles,
    fetch_checkpoint,
    fetch_composer_headers,
    open_readonly,
)
from .logs import detect_log_format, parse_claude_code_entry, parse_moltbot_entry
from .models import Action


class LogWatcher:
    """Watches a log file for new entries in real-time."""

    def __init__(self, path: Path, session_id: str | None = None):
        self.path = path
        self.session_id = session_id
        self._position = 0
        self._log_format: str | None = None
        self._codex_parser: CodexParser | None = None
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
            if self._log_format == "codex":
                self._codex_parser = CodexParser()

        if self._log_format == "moltbot":
            result = parse_moltbot_entry(entry)
        elif self._log_format == "codex":
            # NOTE: deliberately never call self._codex_parser.flush() here.
            # parse_file()'s one-shot batch read flushes at EOF because
            # end-of-file there genuinely means "this is everything" -- but
            # a live LogWatcher tail re-reads the same still-growing file on
            # every poll cycle, and a function_call's output may simply not
            # have arrived yet. Flushing here would emit a call as
            # "output never arrived" prematurely, then have no way to
            # retract that once the real output line shows up moments
            # later. Pending calls are meant to sit in
            # self._codex_parser._pending indefinitely across polls until
            # matched (or the watcher itself is torn down). Do not "fix"
            # this by unifying with parse_file()'s flush-at-EOF behavior.
            return self._codex_parser.parse_line(entry)
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
                            # Strict filtering: only include actions from THIS session
                            # Excludes actions with no session_id to prevent log bleeding
                            parsed = [
                                a for a in parsed
                                if a.session_id == self.session_id
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


class AiderLogWatcher:
    """Watches a ``.aider.chat.history.md`` transcript for new turns/edits.

    PLAYBOOK Sprint 6 item 6 (live tailing) implementation. Unlike
    ``LogWatcher``'s byte-offset JSONL tailing, Aider's Markdown format has
    no fixed record boundary per line -- a turn's edit blocks can span many
    lines and are only safely "complete" once matched by
    ``aider.py::_extract_edit_blocks``'s closing-marker regexes (an
    in-progress diff/udiff block simply doesn't match yet, so re-parsing
    mid-write only ever emits actions that are already fully written -- see
    the one known exception noted below).

    Reparses the WHOLE file via ``parse_aider_sessions()`` on every
    file-change trigger (the same ``watchfiles.awatch`` signal ``LogWatcher``
    uses -- Aider's Markdown file is a real append-only file, unlike
    Cursor's rewritten-in-place SQLite DB, so an awatch-based trigger is the
    natural fit here rather than ``CursorWatcher``'s timer poll) and emits
    only the NEW tail of each session's action list, tracked by a
    per-session emitted-count cursor -- the same "count, not content-diff"
    idiom ``CursorWatcher._bubble_cursor`` already uses for exactly this
    kind of incremental-emit problem.

    **Known limitation, not fixed here (documented, not hidden)**: a turn's
    ``aider_prompt`` action is emitted as soon as its ``#### `` header line
    appears, using whatever body content has been written so far
    (``outgoing_data`` is a snapshot, truncated to 2000 chars) -- if polled
    mid-write, an early snapshot could be incomplete. This action is never
    re-emitted once its slot is counted, so the file's growth afterward is
    only reflected in *later* actions (edit blocks / the next turn), not by
    re-emitting a corrected prompt snapshot. Matches the same "accepted,
    documented" bar as PLAYBOOK Sprint 6 item 5's ``zip()``-shortest-wins
    caveat -- a live-tailing precision tradeoff, not a crash/data-loss risk.

    Analytics-log backfill (``parse_aider_log``'s token/cost merge) is
    deliberately NOT wired into live tailing -- ``--analytics-log`` merge
    is a whole-file, whole-session operation (see ``_session_time_windows``)
    that doesn't have an obvious incremental equivalent; live-tailed Aider
    actions keep ``tokens_in``/``tokens_out``/``cost_usd`` at their
    Markdown-only defaults (0/0/0.0), same as ``parse_aider_markdown()``
    without a sidecar.
    """

    def __init__(self, path: Path, session_id: str | None = None):
        self.path = path
        self.session_id = session_id
        self._emitted_count: dict[str, int] = {}
        self._callbacks: list[Callable[[Action], None]] = []

    def on_action(self, callback: Callable[[Action], None]) -> None:
        """Register a callback for new actions."""
        self._callbacks.append(callback)

    def _read_new_actions(self) -> list[Action]:
        if not self.path.exists():
            return []

        sessions = parse_aider_sessions(self.path)
        new_actions: list[Action] = []
        for session in sessions:
            already = self._emitted_count.get(session.session_id, 0)
            tail = session.actions[already:]
            if not tail:
                continue
            self._emitted_count[session.session_id] = len(session.actions)
            if self.session_id is None or session.session_id == self.session_id:
                new_actions.extend(tail)
        return new_actions

    async def watch(self) -> AsyncIterator[Action]:
        """Watch for new actions, yielding them as they arrive."""
        for action in self._read_new_actions():
            yield action

        async for changes in awatch(self.path.parent):
            for change_type, changed_path in changes:
                if Path(changed_path) == self.path and change_type == Change.modified:
                    for action in self._read_new_actions():
                        yield action

    async def watch_with_callbacks(self) -> None:
        """Watch and dispatch to registered callbacks."""
        async for action in self.watch():
            for callback in self._callbacks:
                try:
                    callback(action)
                except Exception:
                    pass  # Don't let callback errors stop watching


class CursorWatcher:
    """Polls a Cursor ``state.vscdb`` for new composer bubble activity.

    Unlike ``LogWatcher``, there is no append-only byte stream to tail --
    SQLite files are rewritten in place and Cursor does not leave a WAL to
    stream incrementally when idle (see
    ``C:\\Users\\Zaid\\.claude\\plans\\cursor-sqlite-architecture-review.md``).
    This watcher instead re-queries on an interval, using
    ``composerHeaders.lastUpdatedAt`` as a cheap per-composer change signal
    before paying to re-fetch that composer's ``bubbleId:*`` rows (the
    round-4-confirmed real per-bubble content store -- see
    ``cursor_source.py``'s module docstring for the schema-correction
    history this is built against, and for why ``Action`` field values like
    ``tokens_in``/``tokens_out``/``cost_usd`` stay at ``0``/``0.0`` rather
    than being estimated).

    Two-tier poll, matching the architecture review's recommendation (a)
    gated by (c) -- a plain timer-based loop is used as the baseline (no
    ``watchfiles.awatch`` early-wake optimization; not needed to satisfy
    this sprint's scope):

    1. Every ``header_poll_interval`` seconds, cheaply check every
       composer's ``lastUpdatedAt`` watermark via
       ``fetch_composer_headers``.
    2. Only for composers whose watermark advanced *and* whose last bubble
       refetch was at least ``min_blob_poll_interval`` seconds ago, pay for
       the more expensive ``fetch_bubbles`` query and emit ``Action``s for
       any bubbles not yet seen, tracked via a per-composer emitted-count
       cursor. If a composer is throttled by ``min_blob_poll_interval``,
       its watermark is deliberately left un-advanced so the next tick
       retries it -- a delta is only ever delayed, never silently dropped.
    """

    def __init__(
        self,
        db_path: Path,
        header_poll_interval: float = 5.0,
        min_blob_poll_interval: float = 1.0,
        composer_id_filter: str | None = None,
    ):
        self.db_path = db_path
        self.header_poll_interval = header_poll_interval
        self.min_blob_poll_interval = min_blob_poll_interval
        # Restricts polling to one composer -- needed when multiple
        # AgentProcess entries share one state.vscdb (MultiLogWatcher spins
        # up one CursorWatcher per composer via cursor_discovery.py); None
        # preserves the original whole-DB behavior for direct/standalone use.
        self.composer_id_filter = composer_id_filter
        self._last_updated: dict[str, int] = {}  # composer_id -> lastUpdatedAt watermark
        self._bubble_cursor: dict[str, int] = {}  # composer_id -> bubbles already emitted
        self._last_blob_fetch: dict[str, float] = {}  # composer_id -> monotonic fetch time
        self._callbacks: list[Callable[[Action], None]] = []

    def on_action(self, callback: Callable[[Action], None]) -> None:
        """Register a callback for new actions."""
        self._callbacks.append(callback)

    def _poll_once(self) -> list[Action]:
        """Run one full poll tick: cheap header scan, then a selective
        bubble refetch for composers whose watermark advanced.

        Synchronous and side-effect-only-via-instance-state, so tests can
        drive it directly without running the async ``watch()`` loop.
        """
        actions: list[Action] = []
        conn = open_readonly(self.db_path)
        try:
            headers = fetch_composer_headers(conn)
            if self.composer_id_filter is not None:
                headers = {
                    cid: h for cid, h in headers.items() if cid == self.composer_id_filter
                }
            for composer_id, header in headers.items():
                last_updated = header.get("lastUpdatedAt")
                if last_updated is None:
                    continue  # composer exists but never got a message (real case)

                prev = self._last_updated.get(composer_id)
                if prev is not None and last_updated <= prev:
                    continue  # unchanged since last poll

                now = time.monotonic()
                last_fetch = self._last_blob_fetch.get(composer_id)
                if last_fetch is not None and (now - last_fetch) < self.min_blob_poll_interval:
                    # Throttled: leave the watermark un-advanced so the next
                    # tick retries this composer instead of losing the delta.
                    continue

                self._last_blob_fetch[composer_id] = now
                self._last_updated[composer_id] = last_updated

                bubbles = fetch_bubbles(conn, composer_id)
                seen = self._bubble_cursor.get(composer_id, 0)
                new_bubbles = bubbles[seen:]
                self._bubble_cursor[composer_id] = len(bubbles)

                for bubble in new_bubbles:
                    checkpoint = None
                    checkpoint_id = bubble.get("checkpointId")
                    if checkpoint_id:
                        checkpoint = fetch_checkpoint(conn, composer_id, checkpoint_id)
                    actions.append(bubble_to_action(bubble, composer_id, checkpoint))
        finally:
            conn.close()
        return actions

    async def watch(self) -> AsyncIterator[Action]:
        """Watch for new bubble actions, yielding them as they arrive."""
        for action in self._poll_once():
            yield action

        while True:
            await asyncio.sleep(self.header_poll_interval)
            for action in self._poll_once():
                yield action

    async def watch_with_callbacks(self) -> None:
        """Watch and dispatch to registered callbacks."""
        async for action in self.watch():
            for callback in self._callbacks:
                try:
                    callback(action)
                except Exception:
                    pass  # Don't let callback errors stop watching


def _has_live_log(proc: AgentProcess) -> bool:
    """Whether *proc* has a real, currently-readable data source.

    For every non-Cursor agent this means the real ``log_file`` exists on
    disk. Cursor entries use a synthetic, never-created ``log_file`` as a
    ``MultiLogWatcher`` identity key (see
    ``cursor_discovery.py::_cursor_synthetic_log_key``) -- their liveness
    check instead looks at the real ``cursor_db_path``.
    """
    if proc.agent_type == "cursor":
        return proc.cursor_db_path is not None and proc.cursor_db_path.exists()
    return proc.log_file is not None and proc.log_file.exists()


class MultiLogWatcher:
    """Watches multiple log files and directories for new logs."""

    def __init__(self, paths: list[Path], poll_interval: float = 0.5):
        self.base_paths = paths
        self.poll_interval = poll_interval
        self.watchers: dict[Path, LogWatcher | AiderLogWatcher | CursorWatcher] = {}
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
            if proc.log_file and _has_live_log(proc):
                instance._process_meta[proc.log_file] = proc
        return instance

    def refresh_processes(self, processes: list[AgentProcess]) -> list[AgentProcess]:
        """Re-scan processes and return newly added agents.

        Updates internal process metadata, adds new log files,
        and marks stopped processes. Returns list of new processes.
        """
        new_agents: list[AgentProcess] = []

        # Track which log files belong to still-running processes
        active_log_files: set[Path] = set()

        for proc in processes:
            if proc.log_file and _has_live_log(proc):
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
                parent_pid=old_proc.parent_pid,
                parent_agent_pid=old_proc.parent_agent_pid,
                depth=old_proc.depth,
                team_id=old_proc.team_id,
                cursor_db_path=old_proc.cursor_db_path,
            )

        return new_agents

    def get_team_members(self, team_id: int) -> list[AgentProcess]:
        """Return all process metadata entries belonging to a given team."""
        return [
            proc for proc in self._process_meta.values()
            if proc.team_id == team_id
        ]

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
        """Find all watchable log entries in base paths.

        In process mode this is ``.jsonl`` files (Claude Code/Moltbot/Codex),
        ``.md`` files (Aider -- PLAYBOOK Sprint 6 item 6), plus Cursor
        entries (identified by ``agent_type``, not suffix, since their key
        is a synthetic never-created path -- see ``cursor_discovery.py``).
        """
        if self._process_mode:
            return [
                p for p, proc in self._process_meta.items()
                if (p.suffix in (".jsonl", ".md") or proc.agent_type == "cursor")
                and proc.command != "(stopped)"
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

        async def fill_queue(watcher: LogWatcher | AiderLogWatcher | CursorWatcher, key: Path):
            async for action in watcher.watch():
                await queue.put(("action", (action, key)))

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
                        watcher: LogWatcher | AiderLogWatcher | CursorWatcher
                        if proc is not None and proc.agent_type == "cursor":
                            watcher = CursorWatcher(
                                db_path=proc.cursor_db_path, composer_id_filter=sid
                            )
                        elif log_meta.suffix == ".md":
                            watcher = AiderLogWatcher(log_meta, session_id=sid)
                        else:
                            watcher = LogWatcher(log_meta, session_id=sid)
                        self.watchers[log_meta] = watcher
                        tasks[log_meta] = asyncio.create_task(fill_queue(watcher, log_meta))
                        yield ("agent_added", log_meta)

                # Check queue for actions
                while not queue.empty():
                    yield await queue.get()

                await asyncio.sleep(self.poll_interval)
        finally:
            for task in tasks.values():
                task.cancel()
