"""Read-only access to Cursor's ``state.vscdb`` SQLite conversation store.

Cursor (a VS Code fork) persists its AI chat/agent history in
``<Cursor globalStorage>/state.vscdb``, not in an append-only log file the
way Claude Code/Moltbot/Aider/Codex CLI do. This module isolates "how do I
read Cursor's DB correctly" from ``CursorWatcher``'s poll/diff/dispatch loop
(``watcher.py``), per the architecture review's module-boundary reasoning
(``C:\\Users\\Zaid\\.claude\\plans\\cursor-sqlite-architecture-review.md``).

**Schema history -- read this before touching field names.** The original
architecture review guessed bubble/message content lives in a
``composerData.conversationMap`` JSON blob field. That guess is CONFIRMED
WRONG: four rounds of investigation found ``conversationMap`` empty/vestigial
on every composer observed, on every account tested. Round 4
(2026-07-12) found the real per-bubble content store: ``cursorDiskKV`` rows
keyed ``bubbleId:<composerId>:<bubbleId>`` -- one row per bubble, not nested
inside ``composerData``. Every field name/shape below is built against that
round-4-confirmed schema, not the original sketch.

**Known limitation, documented rather than hidden**: a bubble's
``toolResults`` field is confirmed to exist structurally, but its *populated*
shape has never been observed in any of the 4 investigation rounds -- no
tool call happened in the one real exchange available. ``classify_cursor_tool``
below defaults conservatively to ``ToolType.UNKNOWN`` whenever it can't
confidently recognize a shape, mirroring the accepted precedent from Sprint
4's ``classify_codex_tool`` (``parser/codex.py``). Likewise, a checkpoint
row's ``files`` list has only ever been observed empty -- the populated item
shape (bare path string vs. a dict with a path-like key) is a best-effort
guess in ``_extract_checkpoint_file_path``, not a confirmed mapping.

**``tokenCount`` is a real field, observed as always zero.** Every bubble
carries ``tokenCount: {"inputTokens": int, "outputTokens": int}`` as a real
structural field, but it was observed as ``{0, 0}`` on every sample seen so
far (for the ``composer-2.5`` free-tier model). This module does NOT fall
back to any estimated-cost heuristic when that reads zero -- it leaves
``tokens_in``/``tokens_out``/``cost_usd`` at ``0``/``0.0``, matching how
``SessionStats.estimated_cost``'s blended-rate fallback (``parser/models.py``)
already exists for exactly this "no real numbers" case and should not be
duplicated here.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .logs import classify_tool
from .models import Action, ToolType


def open_readonly(db_path: Path) -> sqlite3.Connection:
    """Open ``state.vscdb`` read-only via a ``mode=ro`` SQLite URI connection.

    AgentWatch must NEVER write to Cursor's own database. ``mode=ro`` was
    empirically confirmed (investigation round 1) to actively reject writes
    (``sqlite3.OperationalError``, not a silent no-op), and to support
    concurrent reads while Cursor itself holds the file open for writes on
    Windows (20 rapid read-only queries against a live, actively-writing
    ``Cursor.exe``, 0 errors, sub-10ms latency).
    """
    uri = f"file:{db_path.as_posix()}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def fetch_composer_headers(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    """Cheap poll target: ``composerId`` -> header dict.

    Real, round-4-corrected ``composerHeaders`` schema: ``composerId``
    (primary key), ``workspaceId``, ``createdAt`` (int), ``lastUpdatedAt``
    (int, nullable -- NULL on composers created but never sent a message),
    ``isArchived``, ``isSubagent``, ``recency``, ``checkpointAt``, and
    ``value`` (a JSON blob duplicating several of the above plus
    ``unifiedMode``/``forceMode``/``isDraft``). ``lastUpdatedAt`` is a real
    queryable INTEGER *column*, not JSON-only -- this is what makes the
    two-tier poll cheap: no per-row JSON parsing is needed just to read the
    watermark.
    """
    rows = conn.execute(
        "SELECT composerId, workspaceId, createdAt, lastUpdatedAt, isArchived, "
        "isSubagent, recency, checkpointAt, value FROM composerHeaders"
    ).fetchall()

    out: dict[str, dict[str, Any]] = {}
    for (
        composer_id,
        workspace_id,
        created_at,
        last_updated_at,
        is_archived,
        is_subagent,
        recency,
        checkpoint_at,
        value,
    ) in rows:
        header: dict[str, Any] = {}
        if value:
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    header = parsed
            except (json.JSONDecodeError, TypeError):
                header = {}
        header["composerId"] = composer_id
        header["workspaceId"] = workspace_id
        header["createdAt"] = created_at
        header["lastUpdatedAt"] = last_updated_at
        header["isArchived"] = bool(is_archived)
        header["isSubagent"] = bool(is_subagent)
        header["recency"] = recency
        header["checkpointAt"] = checkpoint_at
        out[composer_id] = header
    return out


def _bubble_sort_key(bubble: dict[str, Any]) -> str:
    """Sort key for ordering bubbles within a composer by ``createdAt``.

    ``createdAt`` is an ISO-8601 string on every bubble observed, which
    sorts correctly lexicographically. Bubbles missing it (never observed,
    but not structurally impossible) sort first rather than raising.
    """
    created_at = bubble.get("createdAt")
    return created_at if isinstance(created_at, str) else ""


def fetch_bubbles(conn: sqlite3.Connection, composer_id: str) -> list[dict[str, Any]]:
    """Fetch every bubble for *composer_id*, ordered by ``createdAt``.

    Queries ``cursorDiskKV WHERE key LIKE 'bubbleId:' || ? || ':%'`` -- the
    real per-bubble content store confirmed in round 4, one row per bubble
    (not nested inside a ``composerData.conversationMap`` blob, which is
    confirmed empty/vestigial). Each returned dict is the parsed JSON value
    with a ``bubbleId`` key injected (extracted from the row's own key,
    since the bubble id is not duplicated inside the JSON value itself).
    """
    rows = conn.execute(
        "SELECT key, value FROM cursorDiskKV WHERE key LIKE 'bubbleId:' || ? || ':%'",
        (composer_id,),
    ).fetchall()

    bubbles: list[dict[str, Any]] = []
    for key, value in rows:
        if not value:
            continue
        try:
            bubble = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(bubble, dict):
            continue
        bubble["bubbleId"] = key.split(":", 2)[-1]
        bubbles.append(bubble)

    bubbles.sort(key=_bubble_sort_key)
    return bubbles


def fetch_checkpoint(
    conn: sqlite3.Connection, composer_id: str, checkpoint_id: str
) -> dict[str, Any] | None:
    """Fetch a checkpoint row for file/diff cross-reference.

    Queries ``cursorDiskKV WHERE key = 'checkpointId:' || ? || ':' || ?`` --
    the real join target confirmed in round 4 for a bubble's ``checkpointId``
    field. Holds ``files``/``nonExistentFiles``/``newlyCreatedFolders``/
    ``activeInlineDiffs`` when populated; every checkpoint observed so far
    had all of these empty (no file edits happened in the one real exchange
    available), so the *populated* item shape of ``files`` is unconfirmed --
    see ``_extract_checkpoint_file_path``.
    """
    row = conn.execute(
        "SELECT value FROM cursorDiskKV WHERE key = 'checkpointId:' || ? || ':' || ?",
        (composer_id, checkpoint_id),
    ).fetchone()
    if not row or not row[0]:
        return None
    try:
        data = json.loads(row[0])
    except (json.JSONDecodeError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _extract_checkpoint_file_path(checkpoint: dict[str, Any] | None) -> str | None:
    """Best-effort extraction of a representative file path from a
    checkpoint's ``files`` list.

    UNCONFIRMED populated shape (see module docstring / ``fetch_checkpoint``):
    every checkpoint observed during the investigation had an empty
    ``files`` list, so whether a populated entry is a bare path string or a
    dict with a path-like key has never been directly observed. This
    handles both plausible shapes defensively and returns ``None`` rather
    than guessing further if neither matches.
    """
    if not checkpoint:
        return None
    files = checkpoint.get("files")
    if not isinstance(files, list) or not files:
        return None
    first = files[0]
    if isinstance(first, str):
        return first
    if isinstance(first, dict):
        for key in ("path", "filePath", "file", "relativePath"):
            value = first.get(key)
            if isinstance(value, str):
                return value
    return None


def _parse_bubble_timestamp(bubble: dict[str, Any]):
    """Parse a bubble's ``createdAt`` ISO-8601 string.

    Small local copy of ``logs.py``'s ISO-parse-with-``datetime.now()``-
    fallback pattern (see ``codex.py::_parse_codex_timestamp`` for the same
    precedent), kept self-contained rather than importing a private helper
    from ``logs.py``.
    """
    from datetime import datetime

    created_at = bubble.get("createdAt")
    if isinstance(created_at, str):
        try:
            parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=None)
        except ValueError:
            pass
    return datetime.now()


def classify_cursor_tool(bubble: dict[str, Any]) -> ToolType:
    """Classify a bubble's tool activity into a ``ToolType``.

    ``toolResults`` (list) is confirmed to exist structurally on every
    ``bubbleId:*`` row, but its POPULATED shape has never been observed in
    any of the 4 investigation rounds -- no tool call happened in the one
    real exchange available across the whole investigation. This defaults
    conservatively to ``ToolType.UNKNOWN`` whenever it can't confidently
    recognize a shape, mirroring the accepted precedent from Sprint 4's
    ``classify_codex_tool`` (``parser/codex.py``), which documented the same
    "expected to misclassify until confirmed against real data" limitation
    rather than hiding it. If a populated ``toolResults`` entry does turn up
    with a recognizable name-like field, reuse ``logs.classify_tool``'s
    substring rules as a best-effort base case.
    """
    tool_results = bubble.get("toolResults")
    if not isinstance(tool_results, list) or not tool_results:
        return ToolType.UNKNOWN

    first = tool_results[0]
    if not isinstance(first, dict):
        return ToolType.UNKNOWN

    name = first.get("name") or first.get("toolName") or first.get("tool_name")
    if isinstance(name, str) and name:
        return classify_tool(name)
    return ToolType.UNKNOWN


def bubble_to_action(
    bubble: dict[str, Any],
    composer_id: str,
    checkpoint: dict[str, Any] | None = None,
) -> Action:
    """Map one ``bubbleId:*`` row to an ``Action``.

    Field mapping, all round-4-confirmed real field names (not the original
    review's wrong ``conversationMap`` guess):
    - ``type`` (int) -> role: ``1`` = user, ``2`` = assistant.
    - ``text`` -> content: goes into ``incoming_message`` for a user bubble,
      ``outgoing_data`` for an assistant bubble -- matching the existing
      pattern every other parser in this package uses (see
      ``logs.py``/``aider.py``/``codex.py``) for how a "what did the model
      say" field maps onto ``Action``.
    - ``tokenCount.inputTokens``/``outputTokens`` -> ``tokens_in``/
      ``tokens_out``. Real field, but observed as always ``{0, 0}`` for the
      ``composer-2.5`` model in every sample seen -- NOT filled in with any
      estimated-cost fallback (see module docstring). ``cost_usd`` is left
      at ``0.0`` for the same reason.
    - ``checkpointId`` -> resolved by the caller via ``fetch_checkpoint``
      and passed in as *checkpoint*; ``file_path`` comes from
      ``_extract_checkpoint_file_path(checkpoint)``.
    - ``session_id`` -> *composer_id*.
    - ``raw`` -> the original bubble dict, unchanged pattern: every existing
      parser stuffs the source object into ``raw`` for detector access to
      fields not promoted to top-level ``Action`` attributes (e.g.
      ``thinking``/``thinkingDurationMs``/``thinkingStyle``, ``modelInfo``,
      which have no dedicated ``Action`` field).

    **Known detector-calibration limitation, found via a live smoke test
    against a real 58-bubble conversation (PLAYBOOK Sprint 7, 2026-07-14)**:
    ``tool_name`` is always one of the ``NON_TOOL_ROLE_LABELS`` sentinels
    (``"user_message"``/``"assistant_message"``/``"unknown_bubble"``) for
    every bubble, unlike Claude Code/Aider/Codex where it reflects the
    actual tool invoked. Left as-is rather than guessed at: richer per-turn
    ``tool_name`` values would need to come from ``toolResults``, whose
    populated shape is still unconfirmed (see ``classify_cursor_tool``).
    Repetition-based detectors (``detectors/health/loops.py::LoopDetector``)
    are the consumer that cares about this -- they exclude
    ``NON_TOOL_ROLE_LABELS`` from their counts (a detector-side carve-out)
    so a normal multi-turn Cursor conversation doesn't trip a "loop" false
    positive purely from the constant role label.
    """
    bubble_type = bubble.get("type")
    is_user = bubble_type == 1
    is_assistant = bubble_type == 2

    text = bubble.get("text")
    text = text if isinstance(text, str) else ""

    token_count = bubble.get("tokenCount")
    tokens_in = 0
    tokens_out = 0
    if isinstance(token_count, dict):
        tokens_in = int(token_count.get("inputTokens") or 0)
        tokens_out = int(token_count.get("outputTokens") or 0)

    duration_ms = int(bubble.get("turnDurationMs") or 0)

    if is_user:
        tool_name = "user_message"
    elif is_assistant:
        tool_name = "assistant_message"
    else:
        tool_name = "unknown_bubble"

    return Action(
        timestamp=_parse_bubble_timestamp(bubble),
        tool_name=tool_name,
        tool_type=classify_cursor_tool(bubble),
        success=True,
        file_path=_extract_checkpoint_file_path(checkpoint),
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        duration_ms=duration_ms,
        cost_usd=0.0,
        incoming_message=text if is_user and text else None,
        outgoing_data=text if is_assistant and text else None,
        session_id=composer_id,
        raw=bubble,
    )


def select_latest_agent_composer(headers: dict[str, dict[str, Any]]) -> str | None:
    """Pick the most-recently-updated non-archived agent-mode composer.

    Mirrors how ``parser/logs.py::find_latest_session()`` auto-picks the
    most-recently-modified JSONL file when no explicit session is given --
    the Cursor equivalent of "just parse whatever's most current" for a
    one-shot ``check``/``security-scan`` run with no ``--session`` filter.

    Excludes ``isDraft`` composers -- confirmed real on a live install
    (2026-07-14): Cursor creates a placeholder composer (literal id
    ``"empty-state-draft"``, ``isDraft: true``) that carries its own
    ``lastUpdatedAt`` timestamp but zero real bubbles, so without this
    filter both this function and ``cursor_discovery.py::find_cursor_agents``
    would pick/surface a phantom empty "agent" ahead of the real
    conversation whenever the draft's timestamp happens to be newer.
    """
    candidates = [
        (header["lastUpdatedAt"], composer_id)
        for composer_id, header in headers.items()
        if header.get("unifiedMode") == "agent"
        and not header.get("isArchived")
        and not header.get("isDraft")
        and header.get("lastUpdatedAt") is not None
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda pair: pair[0], reverse=True)
    return candidates[0][1]


def parse_cursor_session(db_path: Path, composer_id: str | None = None) -> list[Action]:
    """One-shot parse of a single Cursor composer's bubbles into an Action list.

    Unlike ``CursorWatcher`` (which tails every composer live via
    ``lastUpdatedAt`` polling), this mirrors ``parser/logs.py::parse_file()``'s
    one-shot semantics for JSONL/Markdown logs: read everything that exists
    right now for ONE composer and return. When *composer_id* is omitted,
    auto-picks via ``select_latest_agent_composer`` -- the same "most
    recent, no explicit selection" convention every other agent's one-shot
    ``check``/``security-scan`` path already uses.

    Returns an empty list (rather than raising) for every failure mode: no
    such composer, unreadable DB, or a *composer_id* that doesn't exist --
    consistent with ``parse_file()``'s existing "no actions found" handling
    in ``cli.py`` for any other empty/unparseable log.
    """
    conn = open_readonly(db_path)
    try:
        headers = fetch_composer_headers(conn)
        target = composer_id or select_latest_agent_composer(headers)
        if target is None or target not in headers:
            return []

        actions: list[Action] = []
        for bubble in fetch_bubbles(conn, target):
            checkpoint = None
            checkpoint_id = bubble.get("checkpointId")
            if checkpoint_id:
                checkpoint = fetch_checkpoint(conn, target, checkpoint_id)
            actions.append(bubble_to_action(bubble, target, checkpoint))
        return actions
    finally:
        conn.close()
