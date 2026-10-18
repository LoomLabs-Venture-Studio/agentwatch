"""Local session history: the store behind `agentwatch history` and `agentwatch report`.

One SQLite file per user, ``history.db`` in the data dir (``data_dir()``):
``%LOCALAPPDATA%\\agentwatch`` on Windows, else ``$XDG_DATA_HOME/agentwatch``
or ``~/.local/share/agentwatch``, created 0700 on POSIX. Kept until
``history prune``; the default retention is unlimited.

What is stored, and nothing else (no transcript text, prompts, commands,
tool output or full paths):

- sessions: agent name; session id; project folder name (last path component
  only); a hash of the log path (``log_hash``, to recognise the file again);
  first/last action time; action count; billed tokens and USD (NULL when the
  log has no token data or the model has no listed price); the waste figure
  `check` prints (tokens/USD on the calls behind health findings, each call
  once); health score and status; the log's size and mtime (to skip
  unchanged files) and when it was synced.
- findings: per session, one row per distinct finding (a hash of
  ``warning_dedup_key``, which itself holds paths and commands): signal,
  severity, category, its tokens/USD, when it was first seen and, for health
  findings only, the detector's message cut to 120 chars on one line with
  secrets redacted and paths cut to their last component (security messages
  can quote a command, so none is kept).

A log file is one session. Logs that disappear stay as history.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import sys
import time
from datetime import timezone
from pathlib import Path
from typing import Any

ACTIVE_S = 60  # a log written this recently is still being written
_POOL_MIN = 8  # parse in worker processes from this many changed logs
_MSG_LIMIT = 120

# Statements per schema version; migrate() runs the ones the DB lacks.
_MIGRATIONS: list[list[str]] = [[
    """
    CREATE TABLE IF NOT EXISTS sessions (
        log_hash TEXT PRIMARY KEY,
        agent TEXT NOT NULL,
        session_id TEXT,
        project TEXT,
        started REAL,
        ended REAL,
        actions INTEGER NOT NULL,
        tokens INTEGER,
        cost_usd REAL,
        waste_findings INTEGER NOT NULL DEFAULT 0,
        waste_tokens INTEGER,
        waste_usd REAL,
        health_score INTEGER,
        status TEXT,
        size INTEGER NOT NULL,
        mtime_ns INTEGER NOT NULL,
        synced REAL NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS sessions_ended ON sessions(ended)",
    """
    CREATE TABLE IF NOT EXISTS findings (
        log_hash TEXT NOT NULL REFERENCES sessions(log_hash) ON DELETE CASCADE,
        key_hash TEXT NOT NULL,
        signal TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        message TEXT,
        cost_usd REAL,
        tokens INTEGER,
        first_seen REAL NOT NULL,
        PRIMARY KEY (log_hash, key_hash)
    )""",
]]
SCHEMA_VERSION = len(_MIGRATIONS)


def data_dir() -> Path:
    """Per-user data dir, same rules as the coach's per-user dir (data, not cache)."""
    if sys.platform == "win32":
        root = os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local"
    else:
        root = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(root) / "agentwatch"


def db_path() -> Path:
    return data_dir() / "history.db"


def connect(path: Path | None = None) -> sqlite3.Connection:
    """Open (creating, 0700 dir) and migrate the history DB."""
    from agentwatch.coach import _private_dir

    path = path or db_path()
    if not _private_dir(path.parent):
        raise OSError(f"{path.parent} is not a directory owned by you")
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    if conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION:
        return
    # One writer at a time: two first runs must not both create the tables.
    conn.execute("BEGIN IMMEDIATE")
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                f"history DB schema {version} is newer than this agentwatch ({SCHEMA_VERSION})"
            )
        for steps in _MIGRATIONS[version:]:
            for statement in steps:
                conn.execute(statement)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


def log_hash(path: Path) -> str:
    return hashlib.sha256(os.path.normcase(os.path.abspath(path)).encode()).hexdigest()[:16]


def _key_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:16]


_SEP = re.compile(r"[\\/]")
_PATHISH = re.compile(r"[^\s'\"()\[\]]*[\\/][^\s'\"()\[\]]*")
# The path slot of health messages: "... on <path> (4x)", "Re-reading file: <path>
# (3x)", "Re-reading <path> after long gaps", "Edited <path> 5x with ...". Paths
# can hold spaces, so the slot runs to the text that follows it.
_AFTER = re.compile(
    r"(Re-reading file: |file: |Re-reading | on |Edited )(.+?)"
    r"(?= \(| after long gaps| \d+x with|$)"
)
_PATH_DETAILS = ("file_path", "file", "path")
_MASK_TAIL = re.compile("….{0,4}")  # redaction keeps a secret's last 4 chars


def _base(path: str) -> str:
    return _SEP.split(path.strip("'\"`").rstrip("\\/"))[-1]


def safe_message(message: str, details: dict[str, Any] | None = None) -> str:
    """One line, <= 120 chars, secrets hidden (their tail too), every path cut
    to its last part: the warning's own path details (spaces and all), the
    path slot of health messages, then any other token with a slash."""
    from agentwatch.detectors.security.secret_scanner import one_line

    s = one_line(message, 1000)  # redact before cutting: a secret can contain "/"
    for key in _PATH_DETAILS:
        value = (details or {}).get(key)
        if isinstance(value, str) and _SEP.search(value):
            s = s.replace(one_line(value, 1000), _base(value))
    s = _AFTER.sub(lambda m: m[1] + _base(m[2]) if _SEP.search(m[2]) else m[0], s)
    s = _PATHISH.sub(lambda m: _base(m[0]), s)
    return one_line(_MASK_TAIL.sub("[secret]", s), _MSG_LIMIT)


def _epoch(dt: Any) -> float | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


_EMPTY: dict[str, Any] = {"actions": 0, "findings": {}}


def scan_log(agent: str, path: str) -> dict[str, Any]:
    """Parse one log and run every detector, as `check` does; plain data only
    (it crosses a process boundary). An unreadable or unsupported log is
    recorded with 0 actions (not counted, not retried until it changes)."""
    try:
        return _scan(agent, path)
    except Exception:
        return _EMPTY


def _scan(agent: str, path: str) -> dict[str, Any]:
    from agentwatch.agents import get
    from agentwatch.detectors import create_registry
    from agentwatch.detectors.base import warning_dedup_key, waste_summary
    from agentwatch.health import calculate_health
    from agentwatch.parser import ActionBuffer
    from agentwatch.themes import THEME_CLASSIC

    buffer = ActionBuffer()
    warnings = create_registry(mode="all").scan(get(agent).parse_file(Path(path)), buffer)
    stats = buffer.stats
    if len(buffer) == 0:
        return _EMPTY
    health = [w for w in warnings if w.is_health]
    score = calculate_health(health).overall_score  # `check`'s score: health only
    waste = waste_summary(warnings, stats)
    tokens = stats.billed_tokens or None
    has_usage = tokens is not None or stats.total_cost > 0  # else cost unknown, not $0
    cost = stats.estimated_cost if has_usage else None
    findings: dict[str, dict[str, Any]] = {}
    for w in warnings:  # severity order: the first of a key is the worst
        findings.setdefault(_key_hash(warning_dedup_key(w)), {
            "signal": w.signal,
            "severity": w.severity.value,
            "category": w.category.value,
            # Security messages can quote a command or path: not kept.
            "message": safe_message(w.message, w.details) if w.is_health else None,
            "cost_usd": w.cost_usd,
            "tokens": w.tokens,
        })
    return {
        "actions": stats.activity_count,
        "started": _epoch(stats.start_time),
        "ended": _epoch(stats.last_action_time),
        "tokens": tokens,
        "cost_usd": cost,
        "waste_findings": waste["findings"] if waste else 0,
        "waste_tokens": waste["tokens"] if waste else 0,
        "waste_usd": waste["cost_usd"] if waste else (None if cost is None else 0.0),
        "health_score": score,
        "status": THEME_CLASSIC.status_from_score(score),  # theme-independent
        "findings": findings,
    }


def _store(conn, h, agent, sid, project, st, res, now) -> None:
    ended = res.get("ended") or st.st_mtime
    with conn:
        first = dict(conn.execute(
            "SELECT key_hash, first_seen FROM findings WHERE log_hash = ?", (h,)
        ))
        conn.execute("DELETE FROM findings WHERE log_hash = ?", (h,))
        conn.execute(
            """INSERT INTO sessions VALUES
               (:h, :agent, :sid, :project, :started, :ended, :actions, :tokens, :cost_usd,
                :waste_findings, :waste_tokens, :waste_usd, :health_score, :status,
                :size, :mtime_ns, :now)
               ON CONFLICT(log_hash) DO UPDATE SET
                 agent=excluded.agent, session_id=excluded.session_id,
                 project=excluded.project, started=excluded.started, ended=excluded.ended,
                 actions=excluded.actions, tokens=excluded.tokens,
                 cost_usd=excluded.cost_usd, waste_findings=excluded.waste_findings,
                 waste_tokens=excluded.waste_tokens, waste_usd=excluded.waste_usd,
                 health_score=excluded.health_score, status=excluded.status,
                 size=excluded.size, mtime_ns=excluded.mtime_ns, synced=excluded.synced""",
            {
                "started": None, "tokens": None, "cost_usd": None, "waste_findings": 0,
                "waste_tokens": None, "waste_usd": None, "health_score": None,
                "status": None, **res, "ended": ended, "h": h, "agent": agent, "sid": sid,
                "project": project, "size": st.st_size, "mtime_ns": st.st_mtime_ns, "now": now,
            },
        )
        conn.executemany(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (h, k, f["signal"], f["severity"], f["category"], f["message"],
                 f["cost_usd"], f["tokens"], first.get(k, ended))
                for k, f in res["findings"].items()
            ],
        )


def sync(
    conn: sqlite3.Connection,
    days: float | None = None,
    include_active: bool = False,
    now: float | None = None,
) -> dict[str, int]:
    """Bring the store up to date with every agent's logs on disk.

    Logs come from each adapter's history_logs(). A log whose (size, mtime)
    matches its row is skipped; a changed one is re-scanned whole and its
    findings replaced (first_seen kept). Logs written in the last ACTIVE_S
    seconds wait unless *include_active*; *days* skips logs not written in
    that many days. Returns counts.
    """
    from agentwatch.agents import ADAPTERS

    now = time.time() if now is None else now
    known = {h: (size, mt) for h, size, mt in conn.execute(
        "SELECT log_hash, size, mtime_ns FROM sessions"
    )}
    counts = {"new": 0, "updated": 0, "unchanged": 0, "active": 0, "older": 0}
    todo: list[tuple[Any, Path, str, os.stat_result]] = []
    seen: set[str] = set()
    for adapter in ADAPTERS:
        try:
            logs = list(adapter.history_logs())
        except Exception:
            continue  # one agent's store must not stop the others
        for path in logs:
            h = log_hash(path)
            if h in seen:
                continue
            seen.add(h)
            try:
                st = path.stat()
            except OSError:
                continue
            if days is not None and now - st.st_mtime > days * 86400:
                counts["older"] += 1
            elif known.get(h) == (st.st_size, st.st_mtime_ns):
                counts["unchanged"] += 1
            elif not include_active and now - st.st_mtime < ACTIVE_S:
                counts["active"] += 1
            else:
                todo.append((adapter, path, h, st))
                counts["updated" if h in known else "new"] += 1

    def store(i: int, res: dict[str, Any]) -> None:
        adapter, path, h, st = todo[i]
        _store(conn, h, adapter.name, *adapter.history_meta(path), st, res, now)

    jobs = [(a.name, str(p)) for a, p, _, _ in todo]
    done = 0
    if len(jobs) >= _POOL_MIN:
        from concurrent.futures import ProcessPoolExecutor
        from concurrent.futures.process import BrokenProcessPool

        pool = None
        try:
            pool = ProcessPoolExecutor()
            for res in pool.map(scan_log, *zip(*jobs)):
                store(done, res)
                done += 1
        except (BrokenProcessPool, OSError):
            pass  # a worker died or none could start: the rest run in this process
        finally:
            if pool is not None:  # on Ctrl+C too: drop the queued logs
                pool.shutdown(wait=False, cancel_futures=True)
    for i in range(done, len(jobs)):
        store(i, scan_log(*jobs[i]))
    return counts


def prune(conn: sqlite3.Connection, older_than_days: float, now: float | None = None) -> int:
    """Delete sessions (and their findings) last active before the cutoff."""
    cutoff = (time.time() if now is None else now) - older_than_days * 86400
    with conn:
        return conn.execute("DELETE FROM sessions WHERE ended < ?", (cutoff,)).rowcount
