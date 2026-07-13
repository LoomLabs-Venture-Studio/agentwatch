"""Aider chat-history (Markdown) and analytics (JSONL) log parsing.

Sprint 6 additions on top of the original Sprint 3 implementation (see
PLAYBOOK.md "Sprint 6 -- Aider Log Parser, Phase 2"):
  - Resumed-session handling: a file with multiple
    ``# aider chat started at`` headers is split into independent
    per-resume segments, each with its own ``session_id`` and its own
    ordinal turn numbering restarting at 0 (see `_split_sessions`,
    `_parse_aider_sessions`).
  - Analytics session-boundary detection: `parse_aider_log()` no longer
    pairs ``message_send`` events to turns by blind whole-file ordinal
    position. Events are first partitioned into the Markdown session whose
    time window they actually fall into (see `_session_time_windows`),
    with an ``exit`` event treated as a hard session-end boundary, before
    ordinal pairing happens *within* that session only.
  - `udiff` and `whole` edit-format transcript coverage alongside the
    original `diff` (SEARCH/REPLACE / ORIGINAL-UPDATED) support (see
    `UDIFF_BLOCK_RE`, `WHOLE_FILE_BLOCK_RE`, `_extract_edit_blocks`).
  - Visible (logged) signal when an analytics session's `message_send`
    event count disagrees with its turn count, instead of silently
    degrading via `zip()`'s shortest-wins behavior.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from .models import Action, ToolType

logger = logging.getLogger(__name__)

SESSION_HEADER_RE = re.compile(r"^# aider chat started at (?P<ts>.+)$", re.MULTILINE)
TURN_HEADER_RE = re.compile(r"^#### (?P<prompt>.*)$", re.MULTILINE)
COMMIT_RE = re.compile(r"^Commit (?P<hash>[0-9a-f]{7,40}) (?P<message>.+)$", re.MULTILINE)

# Matches both the current (SEARCH/REPLACE) and legacy (ORIGINAL/UPDATED)
# diff-block delimiter styles from day one -- see PRD design decision #3.
#
# `search`/`replace` deliberately do NOT require a literal "\n" immediately
# before the "=======" / ">>>>>>> REPLACE" delimiters -- that would make
# empty SEARCH (pure insertion) or empty REPLACE (pure deletion) blocks
# unmatchable, since aider emits those with the marker lines directly
# adjacent (no blank line in between). Anchoring each delimiter with `^`
# under re.MULTILINE instead correctly matches both the empty and
# multi-line-content cases, since the position right after a marker line's
# own "\n" already *is* a line start. (Regression fix -- QA bug #1.)
#
# `filename` allows any non-newline character, including backticks, since
# aider transcripts have been observed wrapping the filename line in
# backticks (e.g. `` `config.py` ``); the surrounding backticks are
# stripped when the filename is used. (Regression fix -- QA bug #2.)
DIFF_BLOCK_RE = re.compile(
    r"^(?P<filename>\S[^\n]*)\n"
    r"```\w*\n"
    r"<{7} (?:SEARCH|ORIGINAL)\n"
    r"(?P<search>.*?)"
    r"^={7}\n"
    r"(?P<replace>.*?)"
    r"^>{7} (?:REPLACE|UPDATED)\n"
    r"```",
    re.MULTILINE | re.DOTALL,
)

# `udiff` edit format: a git-style unified diff inside a reserved
# ```` ```diff ```` fence. Verified directly against real Aider source
# (Aider-AI/aider @ main, 2026-07-14): `aider/coders/udiff_coder.py`'s
# `find_diffs()`/`process_fenced_block()` requires the fence to literally
# start with "```diff", and `aider/coders/udiff_prompts.py`'s literal
# `example_messages` confirms the body shape -- a "--- <path>" / "+++
# <path>" header pair (aider's prompt tells the model to omit numeric
# line ranges in "@@ ... @@" hunk headers, unlike real `diff -U0` output)
# followed by one or more hunks of +/-/space-prefixed lines. Both the
# coder's own round-trip parsing logic and the prompt's literal example
# agree on this shape, so this is source-derived, not guessed.
UDIFF_BLOCK_RE = re.compile(
    r"^```diff\n"
    r"-{3} (?P<a_path>\S[^\n]*)\n"
    r"\+{3} (?P<b_path>\S[^\n]*)\n"
    r"(?P<hunks>.*?)\n"
    r"^```",
    re.MULTILINE | re.DOTALL,
)

# `whole` edit format: the LLM rewrites the entire file inline. Verified
# directly against `aider/coders/wholefile_coder.py::get_edits()` (the
# code that parses this shape back out of real LLM output) and
# `aider/coders/wholefile_prompts.py`'s literal `example_messages` -- both
# agree: a filename line immediately followed by a fence (the default
# fence is a bare ```` ``` ````, but a language tag after it, e.g.
# ```python, is also accepted since the parser only checks the fence
# prefix), then the file's full raw content, then a closing fence.
#
# Unlike `diff`/`udiff`, there is no internal marker distinguishing a real
# `whole`-format edit block from an ordinary illustrative code sample the
# assistant might show for an unrelated reason -- this is a real,
# source-confirmed structural fact about the format, not a gap in this
# regex. Aider's own coder has exactly the same ambiguity when re-parsing
# its own model's output (it also just looks for "line before a fence"),
# so matching on the same heuristic mirrors a real, accepted convention
# rather than introducing a new source of error. The `(?!diff\b)` negative
# lookahead keeps this from also swallowing `udiff`-format blocks, which
# reserve the ```` ```diff ```` fence tag for themselves.
WHOLE_FILE_BLOCK_RE = re.compile(
    r"^(?P<filename>\S[^\n]*)\n"
    r"```(?!diff\b)\w*\n"
    r"(?P<content>.*?)\n"
    r"^```",
    re.MULTILINE | re.DOTALL,
)

# `.aider/logs/*.log` fallback researched and confirmed DEAD -- see
# `_extract_edit_blocks`'s sibling note in discovery.py::_resolve_aider_log
# for the removal and its citations. Nothing to parse here: no format was
# ever confirmed to exist.

# Real analytics `time` values are absolute Unix epoch seconds; a Markdown
# session header's timestamp is a naive local wall-clock string with no
# timezone info, so converting it via `.timestamp()` assumes the *parsing*
# machine's local zone, which may differ from the zone the header was
# actually written in. `_SESSION_LOWER_BOUND_GRACE` absorbs that ambiguity
# for the very first session in a file (later sessions' lower bound is
# already exactly the previous session's upper bound, so no grace is
# needed there -- windows stay contiguous). `_SESSION_FALLBACK_WINDOW` is
# the generous window used for the last/only session's upper bound when
# there's no next session's start to bound it.
_SESSION_LOWER_BOUND_GRACE = timedelta(hours=24)
_SESSION_FALLBACK_WINDOW = timedelta(hours=24)


@dataclass
class _Turn:
    """One `#### ` prompt block and everything until the next one."""
    prompt: str
    body: str
    ordinal: int


@dataclass
class _Session:
    """One resumed-session segment of a `.aider.chat.history.md` file.

    A file can contain multiple `# aider chat started at` headers if the
    user resumes aider against the same project more than once; each
    segment gets its own `session_id` and its own ordinal turn numbering,
    both restarting from scratch within the segment (see `_split_sessions`).
    """
    session_id: str
    session_start: datetime
    actions: list[Action]


def _parse_session_start(text: str) -> datetime | None:
    m = SESSION_HEADER_RE.search(text)
    if not m:
        return None
    try:
        return datetime.fromisoformat(m.group("ts").strip())
    except ValueError:
        return None


def _fenced_line_starts(text: str) -> set[int]:
    """Return the character offset of every line that lies *inside* a
    ``` fenced code block (the opening/closing fence lines themselves are
    not included).

    Used by `_split_turns` to stay fence-aware: a `#### `-prefixed line
    appearing inside a SEARCH/REPLACE block's code content (e.g. a Python
    comment banner like ``#### Configuration Section ####``) must not be
    mistaken for a real turn boundary. (Regression fix -- QA bug #3.)
    """
    in_fence = False
    offsets: set[int] = set()
    pos = 0
    for line in text.split("\n"):
        if line.strip().startswith("```"):
            in_fence = not in_fence
        elif in_fence:
            offsets.add(pos)
        pos += len(line) + 1  # +1 for the split-out "\n"
    return offsets


def _split_turns(text: str) -> list[_Turn]:
    fenced_starts = _fenced_line_starts(text)
    matches = [m for m in TURN_HEADER_RE.finditer(text) if m.start() not in fenced_starts]
    turns = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        turns.append(_Turn(prompt=m.group("prompt").strip(), body=text[m.end():end], ordinal=i))
    return turns


def _split_sessions(text: str) -> list[str]:
    """Split raw transcript text into one segment per resumed session.

    Each `# aider chat started at ...` header begins a new segment running
    up to (but not including) the next header, or end of file. A file with
    zero headers -- e.g. a hand-written fixture missing the header, or a
    truncated/corrupted log -- is returned as a single segment (the whole
    text), which preserves the original single-session/mtime-fallback
    behavior exactly (regression-critical: single-header files must also
    come out byte-identical, which holds here since one header produces
    exactly one segment spanning the whole file).
    """
    starts = [m.start() for m in SESSION_HEADER_RE.finditer(text)]
    if not starts:
        return [text]
    segments = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(text)
        segments.append(text[start:end])
    return segments


def _udiff_filename(a_path: str, b_path: str) -> str:
    """Resolve the real filename from a udiff block's --- / +++ header
    pair. Aider's prompt tells the model to use plain paths (no git a/ b/
    prefixes) but the leading prefix is stripped defensively if present;
    `/dev/null` on the b_path side signals a deletion, so fall back to
    a_path in that case.
    """

    def _clean(p: str) -> str:
        p = p.strip()
        for prefix in ("a/", "b/"):
            if p.startswith(prefix):
                return p[len(prefix):]
        return p

    b_clean = _clean(b_path)
    if b_clean == "/dev/null":
        return _clean(a_path)
    return b_clean


def _extract_edit_blocks(body: str) -> list[dict]:
    """Find all file-edit blocks in a turn's body text, across every
    supported Aider edit format (`diff` default SEARCH/REPLACE or legacy
    ORIGINAL/UPDATED, `udiff`, and `whole`), returned in document order
    with no double-counting across formats.

    `diff`/`udiff` blocks are matched first since both have an unambiguous
    internal marker (`<<<<<<< SEARCH`/`ORIGINAL`, or a reserved ```diff
    fence). `whole`-format blocks are matched last and only where they
    don't overlap an already-claimed `diff`/`udiff` span -- this keeps a
    real diff/udiff block from also being re-classified as a whole-file
    edit, but does not eliminate `whole` format's inherent ambiguity
    against ordinary non-edit illustrative code blocks (see
    `WHOLE_FILE_BLOCK_RE`'s docstring).
    """
    claimed: list[tuple[int, int]] = []
    blocks: list[dict] = []

    for m in DIFF_BLOCK_RE.finditer(body):
        claimed.append((m.start(), m.end()))
        blocks.append({
            "start": m.start(),
            "end": m.end(),
            "filename": m.group("filename").strip().strip("`").strip(),
            "edit_format": "diff",
            "search_snippet": m.group("search").rstrip("\n")[:200],
        })

    for m in UDIFF_BLOCK_RE.finditer(body):
        claimed.append((m.start(), m.end()))
        blocks.append({
            "start": m.start(),
            "end": m.end(),
            "filename": _udiff_filename(m.group("a_path"), m.group("b_path")),
            "edit_format": "udiff",
            "search_snippet": m.group("hunks").strip()[:200],
        })

    def _overlaps_claimed(start: int, end: int) -> bool:
        return any(start < c_end and end > c_start for c_start, c_end in claimed)

    for m in WHOLE_FILE_BLOCK_RE.finditer(body):
        if _overlaps_claimed(m.start(), m.end()):
            continue
        blocks.append({
            "start": m.start(),
            "end": m.end(),
            "filename": m.group("filename").strip().strip("`").strip(),
            "edit_format": "whole",
            "search_snippet": m.group("content").strip()[:200],
        })

    blocks.sort(key=lambda b: b["start"])
    return blocks


def _parse_aider_sessions(path: Path) -> list[_Session]:
    """Parse a `.aider.chat.history.md` transcript into per-resume
    `_Session` segments (see `_split_sessions`), each with its own
    `session_id` and ordinal turn numbering that restarts at 0.
    """
    text = path.read_text(encoding="utf-8", errors="ignore")
    file_mtime = datetime.fromtimestamp(path.stat().st_mtime)

    sessions: list[_Session] = []
    for segment in _split_sessions(text):
        session_start = _parse_session_start(segment) or file_mtime
        session_id = f"aider:{path.name}:{session_start.isoformat()}"

        actions: list[Action] = []
        for turn in _split_turns(segment):
            # Synthetic per-turn timestamp: real per-turn timestamps don't
            # exist in this file (see PRD design decision #2). Ordinal-second
            # increments preserve strict chronological ordering for
            # ActionBuffer/turns_from_actions/rot-metric consumers without
            # claiming to measure real elapsed wall-clock time.
            ts = datetime.fromtimestamp(session_start.timestamp() + turn.ordinal)

            # The prompt itself feeds prompt-injection detection.
            prompt_action = Action(
                timestamp=ts,
                tool_name="aider_prompt",
                tool_type=ToolType.UNKNOWN,
                success=True,
                incoming_message=turn.prompt or None,
                outgoing_data=turn.body.strip()[:2000] or None,
                session_id=session_id,
                raw={"turn": turn.ordinal},
            )
            actions.append(prompt_action)

            for edit in _extract_edit_blocks(turn.body):
                filename = edit["filename"]
                edit_end = edit["end"]
                # Success signal: a `Commit ...` line appears before the next
                # edit block or the end of the turn. Absence is an inference,
                # not an explicit failure marker -- see PRD design decision #4.
                tail = turn.body[edit_end:edit_end + 500]
                committed = COMMIT_RE.search(tail) is not None
                actions.append(Action(
                    timestamp=ts,
                    tool_name="aider_edit",
                    tool_type=ToolType.EDIT,
                    success=committed,
                    file_path=filename,
                    error_message=None if committed else "no commit found after edit block",
                    session_id=session_id,
                    raw={
                        "turn": turn.ordinal,
                        "edit_format": edit["edit_format"],
                        "search": edit["search_snippet"],
                    },
                ))

        sessions.append(
            _Session(session_id=session_id, session_start=session_start, actions=actions)
        )

    return sessions


def parse_aider_markdown(path: Path) -> list[Action]:
    """Parse a `.aider.chat.history.md` transcript into an Action stream.

    Degraded-but-useful by design: tokens_in/tokens_out are always 0 and
    cost_usd is always 0.0 (nothing in this file carries them) unless
    `parse_aider_log()` backfills them from an analytics sidecar. EDIT
    actions and incoming_message/outgoing_data are still fully populated.

    Files containing multiple `# aider chat started at` headers (resumed
    sessions) are split into independent segments -- see `_split_sessions`
    -- each with its own `session_id` and turn ordinals restarting at 0.
    A single-header (or headerless) file produces exactly one segment, so
    this is a strict superset of the original single-session behavior.
    """
    return [action for session in _parse_aider_sessions(path) for action in session.actions]


def _read_analytics_entries(path: Path) -> list[dict]:
    """Read every well-formed JSON line from an aider `--analytics-log`
    JSONL sidecar (any event type), sorted by `time`. Malformed lines are
    skipped, matching `parse_aider_analytics`'s original tolerance.
    """
    entries = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            entries.append(entry)
    entries.sort(key=lambda e: e.get("time", 0))
    return entries


def parse_aider_analytics(path: Path) -> list[dict]:
    """Parse an aider `--analytics-log` JSONL sidecar into message_send
    events, sorted by time. Returns raw dicts (not Actions) -- callers
    correlate them against markdown turns themselves.
    """
    return [e for e in _read_analytics_entries(path) if e.get("event") == "message_send"]


def _session_time_windows(
    sessions: list[_Session], exit_times: list[float]
) -> list[tuple[float, float]]:
    """Compute a (lower, upper) Unix-epoch-seconds window for each session,
    used to partition analytics `message_send` events by which Markdown
    session they actually belong to, instead of blind whole-file ordinal
    pairing across a long-lived `--analytics-log` file reused for many
    aider invocations (see PLAYBOOK Sprint 6 item 2).

    - Lower bound is each session's own `session_start`, except the first
      session gets `_SESSION_LOWER_BOUND_GRACE` of backward slack (see that
      constant's docstring for why). Sessions after the first don't need
      their own grace: their lower bound is already exactly the previous
      session's upper bound, so windows stay contiguous and non-overlapping.
    - Upper bound is the next session's start (exact -- both timestamps go
      through the same local-zone conversion, so the *difference* between
      them is robust even though either one's absolute value in isolation
      isn't), or `_SESSION_FALLBACK_WINDOW` past this session's own start
      for the last/only session in the file.
    - If an `exit` event's time falls inside a session's window, that caps
      the upper bound early -- an explicit `exit` is a harder session-end
      signal than an inferred time gap (per the PRD's schema notes, `exit`
      events represent aider actually quitting).
    """
    windows: list[tuple[float, float]] = []
    n = len(sessions)
    for i, session in enumerate(sessions):
        lower = session.session_start.timestamp()
        if i == 0:
            lower -= _SESSION_LOWER_BOUND_GRACE.total_seconds()
        if i + 1 < n:
            upper = sessions[i + 1].session_start.timestamp()
        else:
            upper = session.session_start.timestamp() + _SESSION_FALLBACK_WINDOW.total_seconds()

        exits_in_window = [t for t in exit_times if lower <= t <= upper]
        if exits_in_window:
            upper = min(exits_in_window)

        windows.append((lower, upper))
    return windows


def parse_aider_log(markdown_path: Path, analytics_path: Path | None = None) -> list[Action]:
    """Top-level entry point: parse the Markdown transcript (including any
    resumed-session splitting), and if an analytics sidecar is given,
    backfill tokens/cost/real timestamps onto each session's turns.

    Analytics `message_send` events are first partitioned by which
    session's time window they fall into (`_session_time_windows`), then
    paired to that session's turns by ordinal position -- see PRD design
    decision #2. Ordinal pairing within a session is still a heuristic,
    not a guarantee (e.g. two-model architect+editor edit formats or
    retry-on-malformed-edit behavior could emit more than one
    `message_send` per turn -- this needs a live install to confirm and
    is intentionally NOT resolved here, see PLAYBOOK Sprint 6 item 5).
    Mismatched event/turn counts degrade gracefully via `zip()`'s
    shortest-wins behavior, same as before, but now also emit a
    `WARNING`-level log line so the mismatch is visible instead of silent.
    """
    sessions = _parse_aider_sessions(markdown_path)
    all_actions = [action for session in sessions for action in session.actions]
    if analytics_path is None or not analytics_path.exists():
        return all_actions

    entries = _read_analytics_entries(analytics_path)
    events = [e for e in entries if e.get("event") == "message_send"]
    exit_times = [e["time"] for e in entries if e.get("event") == "exit" and "time" in e]

    windows = _session_time_windows(sessions, exit_times)
    for session, (lower, upper) in zip(sessions, windows):
        session_events = [e for e in events if "time" in e and lower <= e["time"] <= upper]

        turn_ordinals = sorted({a.raw.get("turn") for a in session.actions if "turn" in a.raw})
        if len(turn_ordinals) != len(session_events):
            # Visible degradation for Sprint 6 item 5: the underlying
            # ordinal-pairing-reliability question stays open (needs a
            # live install with a two-model edit format or retry behavior
            # to resolve properly) -- this only makes today's best-effort
            # zip() pairing visible instead of silent.
            logger.warning(
                "aider analytics merge: %d turn(s) vs %d message_send event(s) in "
                "session window for %s -- pairing will degrade to zip()'s "
                "shortest-wins behavior, so some turns/events may go unmatched",
                len(turn_ordinals),
                len(session_events),
                session.session_id,
            )

        for ordinal, event in zip(turn_ordinals, session_events):
            props = event.get("properties", {})
            real_ts = datetime.fromtimestamp(event["time"]) if "time" in event else None
            for action in session.actions:
                if action.raw.get("turn") != ordinal:
                    continue
                action.tokens_in = props.get("prompt_tokens", 0) or 0
                action.tokens_out = props.get("completion_tokens", 0) or 0
                action.cost_usd = props.get("cost", 0.0) or 0.0
                if real_ts:
                    action.timestamp = real_ts

    return all_actions
