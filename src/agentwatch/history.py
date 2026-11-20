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
- session_models: per session and model id, the API calls, their tokens
  (input, output, cache write with its 1h part, cache read), USD and the USD
  the cache reads saved against the input rate (NULL when unpriced).
- session_errors: per session, failed calls counted by error kind
  (``ERROR_KINDS``) and tool name. Never the error text.

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
], [
    """
    CREATE TABLE IF NOT EXISTS session_models (
        log_hash TEXT NOT NULL REFERENCES sessions(log_hash) ON DELETE CASCADE,
        model TEXT NOT NULL,
        calls INTEGER NOT NULL,
        input_tokens INTEGER NOT NULL,
        output_tokens INTEGER NOT NULL,
        cache_write_tokens INTEGER NOT NULL,
        cache_write_1h_tokens INTEGER NOT NULL,
        cache_read_tokens INTEGER NOT NULL,
        cost_usd REAL,
        cache_saved_usd REAL,
        PRIMARY KEY (log_hash, model)
    )""",
    """
    CREATE TABLE IF NOT EXISTS session_errors (
        log_hash TEXT NOT NULL REFERENCES sessions(log_hash) ON DELETE CASCADE,
        kind TEXT NOT NULL,
        tool TEXT NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (log_hash, kind, tool)
    )""",
    # Rows synced before this version have no breakdown: make the next sync
    # re-read their logs (a log no longer on disk keeps none).
    "UPDATE sessions SET size = -1",
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
    _private_file(path)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    return conn


def _private_file(path: Path) -> None:
    """POSIX: create the DB 0600 (sqlite3 would use the umask, usually 0644;
    its -journal/-wal files copy the DB's mode). An existing DB we own is
    tightened to 0600; one we don't own is left alone."""
    if os.name != "posix":
        return  # %LOCALAPPDATA%: per-user ACLs, not modes
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        st = os.stat(path)
        if st.st_uid == os.getuid() and st.st_mode & 0o077:
            os.chmod(path, 0o600)
        return
    os.close(fd)  # an empty file is an empty SQLite database


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
    """Last part of a path or URL, without quotes, query string or fragment."""
    path = re.split(r"[?#]", path.strip("'\"`"), maxsplit=1)[0]
    return _SEP.split(path.rstrip("\\/"))[-1]


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


_EMPTY: dict[str, Any] = {"actions": 0, "findings": {}, "models": {}, "errors": {}}

# Error kinds of a failed call, the first rule that matches wins. Matched on
# the parser's error text (and the tail of a failed result, where a test
# runner prints its summary); only the kind and a count are stored.
ERROR_KINDS = (
    "permission_denied", "blocked", "test_failure", "timeout", "edit_failed",
    "command_not_found", "file_not_found", "network", "nonzero_exit", "other",
)
_DENIED = re.compile(  # the user or the permission system said no (Claude Code's wording)
    r"doesn't want to proceed with this tool use|tool use was rejected"
    r"|Permission for this action was denied", re.I)
# A hook or the agent's own guard refused the call.
_BLOCKED = re.compile(
    r"\bhook error:|<tool_use_error>Blocked:|This agent is isolated in the worktree", re.I)
_TEST_FAILED = re.compile(
    r"\b[1-9]\d* (?:failed|failing)\b|^FAILED\b|\bFAILED \(|test result: FAILED|^--- FAIL"
    r"|^FAIL\b|errors? during collection|ImportError while importing test module", re.M)
_ERROR_RULES = [
    ("timeout", re.compile(
        r"\btimed out\b|\bTimeoutError\b|\bTimeoutExpired\b|\bETIMEDOUT\b"
        r"|deadline exceeded", re.I)),
    ("edit_failed", re.compile(
        r"String to replace not found|Found \d+ matches of the string to replace"
        r"|File has not been read yet|File has been (?:unexpectedly )?modified since"
        r"|Failed to find expected lines|apply_patch verification failed"
        r"|patch (?:does|did) not apply|error: patch failed", re.I)),
    ("command_not_found", re.compile(
        r"command not found|is not recognized as an internal or external command"
        r"|is not recognized as the name of a cmdlet", re.I)),
    ("file_not_found", re.compile(
        r"No such file or directory|\bENOENT\b|File does not exist|Path does not exist"
        r"|FileNotFoundError|cannot find the (?:path|file) specified", re.I)),
    ("permission_denied", re.compile(
        r"permission denied|\bEACCES\b|\bEPERM\b|operation not permitted|access is denied",
        re.I)),
    ("network", re.compile(
        r"\bE(?:CONNREFUSED|CONNRESET|NOTFOUND|AI_AGAIN|NETUNREACH|HOSTUNREACH)\b"
        r"|Connection (?:refused|reset)|Network is unreachable|Could not resolve host"
        r"|Temporary failure in name resolution|Name or service not known|getaddrinfo"
        r"|Failed to establish a new connection|certificate verify failed", re.I)),
]
# "Exit code 1" (Claude Code), "exit 1: ..." (Codex), "exit code 1" (others)
_EXIT = re.compile(r"\s*exit(?: code| status)?[:\s]+-?\d+", re.I)
# A model id or tool name; one "provider/" prefix at most, so never a path.
_SAFE_NAME = re.compile(r"(?:[\w.:@-]{1,40}/)?[\w.:@\[\]-]{1,80}")
# "user@host.tld"; a Vertex "model@20250514" version suffix has no dot.
_EMAIL = re.compile(r"@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}")
_TAIL = 4000  # a test summary is at the end of the output
# A line that leads with an error's name: "Error: ENOENT: ...", "TypeError: x",
# "Error [ERR_MODULE_NOT_FOUND]: ..." (Node prints it mid-output).
_ERROR_LINE = re.compile(r"(?:[A-Z][A-Za-z0-9_]*)?Error(?: \[\w+\])?: ")


def _is_test_command(command: str | None) -> bool:
    from agentwatch.cc_stats import BashCategory, _split_shell_commands, classify_bash_command

    return bool(command) and any(
        classify_bash_command(c) is BashCategory.Testing for c in _split_shell_commands(command)
    )


def error_kind(action: Any) -> str:
    """The ``ERROR_KINDS`` entry of a failed action."""
    head = action.error_message or ""
    text = head + "\n" + (action.incoming_message or "")[-_TAIL:]
    exited = _EXIT.match(head)
    if exited:
        # A command that ran and exited nonzero: its output is free text, so
        # only its own error counts -- the first and last output lines, and
        # the first line that leads with "Error:" / "<Name>Error:". On real
        # Claude Code logs the error is one of them: a tool's message leads
        # ("ls: cannot access ...") or stderr, appended after stdout, ends it
        # ("bash: x: command not found", a traceback's last line); a Node
        # crash prints "Error: ENOENT ..." between its stack's first line
        # and "Node.js vN".
        lines = [ln for ln in text.splitlines() if ln.strip() and not _EXIT.fullmatch(ln)]
        error_line = next((ln for ln in lines if _ERROR_LINE.match(ln)), None)
        envelope = "\n".join(lines[:1] + lines[-1:] + ([error_line] if error_line else []))
    else:
        envelope = head
    if _DENIED.search(envelope):
        return "permission_denied"
    if _BLOCKED.search(envelope):
        return "blocked"
    if _is_test_command(action.command) and _TEST_FAILED.search(text):
        return "test_failure"
    for kind, rule in _ERROR_RULES:
        if rule.search(envelope if exited else text):
            return kind
    return "nonzero_exit" if exited else "other"


def _name(value: str | None) -> str:
    """A model id or tool name as stored: as logged if it looks like one."""
    from agentwatch.detectors.security.secret_scanner import redact_secrets

    if not value:
        return ""
    safe = (_SAFE_NAME.fullmatch(value) and ".." not in value and not _EMAIL.search(value)
            and redact_secrets(value) == value)
    return value if safe else "other"


class _Tap:
    """Watches the actions a scan reads: each API call's largest copy (as
    ActionBuffer bills it) and every action that can end up failed."""

    def __init__(self) -> None:
        self.calls: dict[Any, Any] = {}
        self.maybe_failed: list[Any] = []

    def __call__(self, actions):
        from agentwatch.parser.models import call_tokens, is_tool_call

        for a in actions:
            tokens = call_tokens(a)
            if tokens or a.cost_usd > 0:
                key = a.message_id or id(a)
                best = self.calls.get(key)
                if best is None or tokens > call_tokens(best):
                    self.calls[key] = a
            if is_tool_call(a) or not a.success:
                self.maybe_failed.append(a)
            yield a

    def models(self) -> dict[str, dict[str, Any]]:
        from agentwatch.cc_stats import price_for, usage_cost_usd
        from agentwatch.parser.models import call_cost

        out: dict[str, dict[str, Any]] = {}
        for a in self.calls.values():
            m = out.setdefault(_name(a.model), {
                "calls": 0, "input_tokens": 0, "output_tokens": 0, "cache_write_tokens": 0,
                "cache_write_1h_tokens": 0, "cache_read_tokens": 0, "cost_usd": 0.0,
                "cache_saved_usd": 0.0,
            })
            m["calls"] += 1
            m["input_tokens"] += a.tokens_in
            m["output_tokens"] += a.tokens_out
            m["cache_write_tokens"] += a.cache_creation_tokens
            m["cache_write_1h_tokens"] += min(a.cache_creation_1h_tokens, a.cache_creation_tokens)
            m["cache_read_tokens"] += a.cache_read_tokens
            cost = call_cost(a)
            m["cost_usd"] = None if cost is None or m["cost_usd"] is None else m["cost_usd"] + cost
            saved = None
            if not a.unpriced and price_for(a.model):
                # The same call with its cache reads billed as fresh input.
                usage = (a.tokens_out, a.cache_creation_tokens)
                full = usage_cost_usd(a.model, a.tokens_in + a.cache_read_tokens, *usage,
                                      0, a.cache_creation_1h_tokens)
                billed = usage_cost_usd(a.model, a.tokens_in, *usage, a.cache_read_tokens,
                                        a.cache_creation_1h_tokens)
                saved = full - billed  # type: ignore[operator]
            prev = m["cache_saved_usd"]
            m["cache_saved_usd"] = None if saved is None or prev is None else prev + saved
        return out

    def errors(self) -> dict[tuple[str, str], int]:
        out: dict[tuple[str, str], int] = {}
        for a in self.maybe_failed:
            if not a.success and a.error_message:  # what ActionBuffer counts as an error
                # Claude Code logs a failed model request ("Request timed
                # out.") as a "system" entry: not a tool.
                tool = "api" if a.tool_name == "system" else _name(a.tool_name)
                key = (error_kind(a), tool or "other")
                out[key] = out.get(key, 0) + 1
        return out


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
    tap = _Tap()
    warnings = create_registry(mode="all").scan(tap(get(agent).parse_file(Path(path))), buffer)
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
        "models": tap.models(),
        "errors": tap.errors(),
    }


def _store(conn, h, agent, sid, project, st, res, now) -> None:
    ended = res.get("ended") or st.st_mtime
    with conn:
        first = dict(conn.execute(
            "SELECT key_hash, first_seen FROM findings WHERE log_hash = ?", (h,)
        ))
        for table in ("findings", "session_models", "session_errors"):
            conn.execute(f"DELETE FROM {table} WHERE log_hash = ?", (h,))
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
        conn.executemany(
            "INSERT INTO session_models VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (h, model, m["calls"], m["input_tokens"], m["output_tokens"],
                 m["cache_write_tokens"], m["cache_write_1h_tokens"], m["cache_read_tokens"],
                 m["cost_usd"], m["cache_saved_usd"])
                for model, m in res.get("models", {}).items()
            ],
        )
        conn.executemany(
            "INSERT INTO session_errors VALUES (?, ?, ?, ?)",
            [(h, kind, tool, n) for (kind, tool), n in res.get("errors", {}).items()],
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
