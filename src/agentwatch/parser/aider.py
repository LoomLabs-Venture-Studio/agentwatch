"""Aider chat-history (Markdown) and analytics (JSONL) log parsing."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .models import Action, ToolType

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


@dataclass
class _Turn:
    """One `#### ` prompt block and everything until the next one."""
    prompt: str
    body: str
    ordinal: int


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


def parse_aider_markdown(path: Path) -> list[Action]:
    """Parse a `.aider.chat.history.md` transcript into an Action stream.

    Degraded-but-useful by design: tokens_in/tokens_out are always 0 and
    cost_usd is always 0.0 (nothing in this file carries them) unless
    `parse_aider_log()` backfills them from an analytics sidecar. EDIT
    actions and incoming_message/outgoing_data are still fully populated.
    """
    text = path.read_text(encoding="utf-8", errors="ignore")
    session_start = _parse_session_start(text) or datetime.fromtimestamp(path.stat().st_mtime)
    session_id = f"aider:{path.name}:{session_start.isoformat()}"

    actions: list[Action] = []
    for turn in _split_turns(text):
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

        for edit in DIFF_BLOCK_RE.finditer(turn.body):
            # Strip optional surrounding backticks from a markdown-rendered
            # filename line (e.g. `` `config.py` ``) -- see QA bug #2.
            filename = edit.group("filename").strip().strip("`").strip()
            edit_end = edit.end()
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
                raw={"turn": turn.ordinal, "search": edit.group("search").rstrip("\n")[:200]},
            ))

    return actions


def parse_aider_analytics(path: Path) -> list[dict]:
    """Parse an aider `--analytics-log` JSONL sidecar into message_send
    events, sorted by time. Returns raw dicts (not Actions) -- callers
    correlate them against markdown turns themselves.
    """
    events = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("event") == "message_send":
                events.append(entry)
    events.sort(key=lambda e: e.get("time", 0))
    return events


def parse_aider_log(markdown_path: Path, analytics_path: Path | None = None) -> list[Action]:
    """Top-level entry point: parse the Markdown transcript, and if an
    analytics sidecar is given, backfill tokens/cost/real timestamps onto
    each turn's actions by ordinal position -- see PRD design decision #2.
    """
    actions = parse_aider_markdown(markdown_path)
    if analytics_path is None or not analytics_path.exists():
        return actions

    events = parse_aider_analytics(analytics_path)
    # Ordinal pairing: the Nth message_send event is assumed to correspond
    # to the Nth prompt turn. This is a heuristic, not a guarantee -- see
    # PRD Open Questions. Mismatched counts degrade gracefully: excess
    # turns keep zero-cost/synthetic-timestamp actions, excess events are
    # unused.
    turn_ordinals = sorted({a.raw.get("turn") for a in actions if "turn" in a.raw})
    for ordinal, event in zip(turn_ordinals, events):
        props = event.get("properties", {})
        real_ts = datetime.fromtimestamp(event["time"]) if "time" in event else None
        for action in actions:
            if action.raw.get("turn") != ordinal:
                continue
            action.tokens_in = props.get("prompt_tokens", 0) or 0
            action.tokens_out = props.get("completion_tokens", 0) or 0
            action.cost_usd = props.get("cost", 0.0) or 0.0
            if real_ts:
                action.timestamp = real_ts

    return actions
