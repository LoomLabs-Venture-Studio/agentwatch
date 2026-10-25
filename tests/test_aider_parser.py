"""Tests for the Aider Markdown chat-history + analytics-JSONL parser.

Covers both halves of `agentwatch.parser.aider`:
  - Markdown-only parsing (`_parse_session_start`, `_split_turns`,
    `parse_aider_markdown`) -- the "degraded but useful" path with no
    real install required.
  - Analytics JSONL parsing + ordinal merge (`parse_aider_analytics`,
    `parse_aider_log`).
Plus a regression test that `parser/logs.py::parse_file()` dispatches
`.md` paths to this module and leaves `.jsonl` handling untouched.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime

from agentwatch.parser.aider import (
    DIFF_BLOCK_RE,
    UDIFF_BLOCK_RE,
    WHOLE_FILE_BLOCK_RE,
    _fenced_line_starts,
    _parse_session_start,
    _split_sessions,
    _split_turns,
    parse_aider_analytics,
    parse_aider_log,
    parse_aider_markdown,
)
from agentwatch.parser.logs import parse_file
from agentwatch.parser.models import ToolType

SEARCH_REPLACE_MD = """# aider chat started at 2024-01-15T10:30:00

#### add a hello function

Sure, I'll add that.

foo.py
```python
<<<<<<< SEARCH
# TODO: implement hello
=======
def hello():
    print("hello")
>>>>>>> REPLACE
```

Commit abc1234 add hello function

#### now add a goodbye function

Sure thing.

foo.py
```python
<<<<<<< SEARCH
def hello():
    print("hello")
=======
def hello():
    print("hello")

def goodbye():
    print("goodbye")
>>>>>>> REPLACE
```
"""

ORIGINAL_UPDATED_MD = """# aider chat started at 2024-02-01T09:00:00

#### rename the variable

Okay.

bar.py
```python
<<<<<<< ORIGINAL
x = 1
=======
y = 1
>>>>>>> UPDATED
```

Commit def5678 rename variable
"""

ZERO_TURN_MD = """# aider chat started at 2024-03-01T12:00:00

aider launched, no user input yet.
"""

# Sprint 6 item 1 fixture: a real resumed-session file with 2 separate
# `# aider chat started at` headers, each with its own single turn.
RESUMED_SESSION_MD = """# aider chat started at 2024-08-01T09:00:00

#### fix bug in session one

Sure.

foo.py
```python
<<<<<<< SEARCH
a = 1
=======
a = 2
>>>>>>> REPLACE
```

Commit aaa1111 fix bug in session one

# aider chat started at 2024-08-05T09:00:00

#### fix bug in session two

Sure.

bar.py
```python
<<<<<<< SEARCH
b = 1
=======
b = 2
>>>>>>> REPLACE
```

Commit bbb2222 fix bug in session two
"""

# Sprint 6 item 4 fixture: `whole` edit format -- filename + fence + full
# raw file content, no internal SEARCH/REPLACE-style marker. Shape
# verified directly against aider/coders/wholefile_coder.py +
# wholefile_prompts.py source (see DIFF_BLOCK_RE-adjacent regex comments
# in parser/aider.py). Kept clearly separate from the SEARCH/REPLACE and
# ORIGINAL/UPDATED fixtures above.
WHOLE_FORMAT_MD = """# aider chat started at 2024-04-01T08:00:00

#### rewrite the greeting script

Sure, here's the whole file.

show_greeting.py
```python
import sys

def greeting(name):
    print(f"Hey {name}")

if __name__ == '__main__':
    greeting(sys.argv[1])
```

Commit cccc111 rewrite greeting script
"""

# Sprint 6 item 4 fixture: `udiff` edit format -- a reserved ```diff fence
# with a --- / +++ header pair and @@ ... @@ hunks. Shape verified
# directly against aider/coders/udiff_coder.py + udiff_prompts.py source.
# Kept clearly separate from the other edit-format fixtures.
UDIFF_FORMAT_MD = """# aider chat started at 2024-04-05T08:00:00

#### refactor MathWeb import

Sure, here's the diff.

```diff
--- mathweb/flask/app.py
+++ mathweb/flask/app.py
@@ ... @@
-class MathWeb:
+import sympy
+
+class MathWeb:
```

Commit dddd222 refactor MathWeb import
"""


class TestParseSessionStart:
    def test_extracts_header_timestamp(self):
        ts = _parse_session_start(SEARCH_REPLACE_MD)
        assert ts is not None
        assert ts.year == 2024
        assert ts.month == 1
        assert ts.day == 15
        assert ts.hour == 10
        assert ts.minute == 30

    def test_missing_header_returns_none(self):
        assert _parse_session_start("#### just a prompt, no session header\n") is None

    def test_malformed_header_returns_none(self):
        text = "# aider chat started at not-a-real-timestamp\n\n#### hi\n"
        assert _parse_session_start(text) is None

    def test_mtime_fallback(self, tmp_path):
        # No session header at all -> parse_aider_markdown falls back to
        # the file's mtime rather than raising or using None.
        path = tmp_path / ".aider.chat.history.md"
        path.write_text("#### hello with no session header\n", encoding="utf-8")
        actions = parse_aider_markdown(path)
        assert len(actions) == 1
        # session_id embeds the fallback timestamp; just confirm it parsed
        # without error and produced a real session_id string.
        assert actions[0].session_id.startswith("aider:")


class TestSplitTurns:
    def test_splits_on_turn_headings(self):
        turns = _split_turns(SEARCH_REPLACE_MD)
        assert len(turns) == 2
        assert turns[0].prompt == "add a hello function"
        assert turns[0].ordinal == 0
        assert turns[1].prompt == "now add a goodbye function"
        assert turns[1].ordinal == 1
        # Each turn's body should contain only its own content
        assert "hello function" in turns[0].body
        assert "goodbye function" not in turns[0].body

    def test_zero_turns_edge_case(self):
        turns = _split_turns(ZERO_TURN_MD)
        assert turns == []


class TestDiffBlockStyles:
    def test_search_replace_style_matches(self):
        actions = parse_aider_markdown_from_text(SEARCH_REPLACE_MD)
        edits = [a for a in actions if a.tool_type == ToolType.EDIT]
        assert len(edits) == 2
        assert edits[0].file_path == "foo.py"

    def test_original_updated_legacy_style_matches(self):
        actions = parse_aider_markdown_from_text(ORIGINAL_UPDATED_MD)
        edits = [a for a in actions if a.tool_type == ToolType.EDIT]
        assert len(edits) == 1
        assert edits[0].file_path == "bar.py"


class TestDiffBlockRegressionBugs:
    """QA-reported correctness bugs in DIFF_BLOCK_RE / TURN_HEADER_RE.

    Each test regresses one of the three bugs found in independent QA
    review of the initial implementation.
    """

    def test_empty_search_pure_insertion_matches(self):
        # Bug #1a: a pure-insertion edit (nothing between "SEARCH" and
        # "=======") previously failed to match at all -> zero EDIT
        # actions for a real edit, with no error signal.
        text = (
            "foo.py\n"
            "```python\n"
            "<<<<<<< SEARCH\n"
            "=======\n"
            "def new_func():\n"
            "    pass\n"
            ">>>>>>> REPLACE\n"
            "```\n"
        )
        m = DIFF_BLOCK_RE.search(text)
        assert m is not None
        assert m.group("search") == ""
        assert "def new_func():" in m.group("replace")

    def test_empty_replace_pure_deletion_matches(self):
        # Bug #1b: the mirror case -- pure deletion, nothing between
        # "=======" and ">>>>>>> REPLACE".
        text = (
            "foo.py\n"
            "```python\n"
            "<<<<<<< SEARCH\n"
            "def old_func():\n"
            "    pass\n"
            "=======\n"
            ">>>>>>> REPLACE\n"
            "```\n"
        )
        m = DIFF_BLOCK_RE.search(text)
        assert m is not None
        assert "def old_func():" in m.group("search")
        assert m.group("replace") == ""

    def test_empty_search_produces_edit_action_end_to_end(self):
        # End-to-end: a full turn whose only edit is a pure insertion must
        # still produce a real EDIT action, not silently disappear.
        md = (
            "# aider chat started at 2024-05-01T00:00:00\n\n"
            "#### add a new function\n\n"
            "Sure.\n\n"
            "foo.py\n"
            "```python\n"
            "<<<<<<< SEARCH\n"
            "=======\n"
            "def new_func():\n"
            "    pass\n"
            ">>>>>>> REPLACE\n"
            "```\n\n"
            "Commit abc1234 add new_func\n"
        )
        actions = parse_aider_markdown_from_text(md)
        edits = [a for a in actions if a.tool_type == ToolType.EDIT]
        assert len(edits) == 1
        assert edits[0].file_path == "foo.py"
        assert edits[0].success is True

    def test_backtick_wrapped_filename_matches_and_is_normalized(self):
        # Bug #2: a markdown-rendered filename line wrapped in backticks
        # (e.g. `` `config.py` ``) previously failed to match at all.
        text = (
            "`config.py`\n"
            "```python\n"
            "<<<<<<< SEARCH\n"
            "x = 1\n"
            "=======\n"
            "x = 2\n"
            ">>>>>>> REPLACE\n"
            "```\n"
        )
        m = DIFF_BLOCK_RE.search(text)
        assert m is not None
        assert m.group("filename") == "`config.py`"

        md = (
            "# aider chat started at 2024-06-01T00:00:00\n\n"
            "#### bump x\n\n"
            "Sure.\n\n" + text + "\nCommit fedcba9 bump x\n"
        )
        actions = parse_aider_markdown_from_text(md)
        edits = [a for a in actions if a.tool_type == ToolType.EDIT]
        assert len(edits) == 1
        # Surrounding backticks are stripped from the stored file_path.
        assert edits[0].file_path == "config.py"

    def test_turn_header_inside_fence_is_not_a_turn_boundary(self):
        # Bug #3: a "#### "-prefixed line inside a fenced SEARCH/REPLACE
        # block (e.g. a Python comment banner) must not be treated as a
        # new turn boundary -- doing so both destroys the real edit and
        # fabricates a spurious prompt turn from code/diff content.
        md = (
            "# aider chat started at 2024-07-01T00:00:00\n\n"
            "#### add config banner\n\n"
            "Sure.\n\n"
            "banner.py\n"
            "```python\n"
            "<<<<<<< SEARCH\n"
            "=======\n"
            "#### Configuration Section ####\n"
            "x = 1\n"
            ">>>>>>> REPLACE\n"
            "```\n\n"
            "Commit abc1234 add config banner\n\n"
            "#### second real prompt\n\n"
            "ok\n"
        )
        turns = _split_turns(md)
        assert len(turns) == 2
        assert turns[0].prompt == "add config banner"
        assert turns[1].prompt == "second real prompt"

        actions = parse_aider_markdown_from_text(md)
        prompts = [a for a in actions if a.tool_name == "aider_prompt"]
        edits = [a for a in actions if a.tool_type == ToolType.EDIT]
        assert len(prompts) == 2
        assert prompts[0].incoming_message == "add config banner"
        assert prompts[1].incoming_message == "second real prompt"
        # The real edit inside the fenced block must survive intact.
        assert len(edits) == 1
        assert edits[0].file_path == "banner.py"
        assert edits[0].success is True

    def test_fenced_line_starts_tracks_fence_state(self):
        text = (
            "outside line\n"
            "```python\n"
            "inside line 1\n"
            "#### looks like a turn but isn't\n"
            "```\n"
            "outside again\n"
        )
        offsets = _fenced_line_starts(text)
        lines = text.split("\n")
        # "inside line 1" and the fake turn header are inside the fence;
        # the fence markers themselves and lines outside are not.
        assert lines[2] in [text[o:].split("\n", 1)[0] for o in offsets]
        assert lines[3] in [text[o:].split("\n", 1)[0] for o in offsets]
        assert lines[0] not in [text[o:].split("\n", 1)[0] for o in offsets]


class TestCommitLineInference:
    def test_commit_present_marks_success(self):
        actions = parse_aider_markdown_from_text(ORIGINAL_UPDATED_MD)
        edits = [a for a in actions if a.tool_type == ToolType.EDIT]
        assert edits[0].success is True
        assert edits[0].error_message is None

    def test_commit_absent_marks_failure(self):
        actions = parse_aider_markdown_from_text(SEARCH_REPLACE_MD)
        edits = [a for a in actions if a.tool_type == ToolType.EDIT]
        # Second edit block (goodbye function) has no following Commit line
        assert edits[1].success is False
        assert edits[1].error_message == "no commit found after edit block"


class TestMarkdownOnlyDegradedButUseful:
    def test_zero_cost_but_populated_edit_and_prompt_fields(self):
        actions = parse_aider_markdown_from_text(SEARCH_REPLACE_MD)
        assert len(actions) > 0
        for a in actions:
            assert a.tokens_in == 0
            assert a.tokens_out == 0
            assert a.cost_usd == 0.0

        prompts = [a for a in actions if a.tool_name == "aider_prompt"]
        edits = [a for a in actions if a.tool_type == ToolType.EDIT]
        assert len(prompts) == 2
        assert len(edits) == 2
        assert prompts[0].incoming_message == "add a hello function"
        assert prompts[1].incoming_message == "now add a goodbye function"


class TestAnalyticsParsing:
    def test_parses_and_sorts_message_send_events(self, tmp_path):
        path = tmp_path / "analytics.jsonl"
        lines = [
            {"event": "message_send", "properties": {"prompt_tokens": 10}, "time": 200},
            {"event": "exit", "properties": {"reason": "done"}, "time": 300},
            {"event": "message_send", "properties": {"prompt_tokens": 5}, "time": 100},
        ]
        path.write_text("\n".join(json.dumps(line) for line in lines), encoding="utf-8")
        events = parse_aider_analytics(path)
        assert len(events) == 2
        assert events[0]["time"] == 100
        assert events[1]["time"] == 200

    def test_skips_malformed_lines(self, tmp_path):
        path = tmp_path / "analytics.jsonl"
        path.write_text(
            '{"event": "message_send", "properties": {}, "time": 1}\n'
            "not json at all\n"
            "\n",
            encoding="utf-8",
        )
        events = parse_aider_analytics(path)
        assert len(events) == 1


class TestAnalyticsMerge:
    def test_merge_backfills_by_ordinal(self, tmp_path):
        md_path = tmp_path / ".aider.chat.history.md"
        md_path.write_text(SEARCH_REPLACE_MD, encoding="utf-8")

        analytics_path = tmp_path / "analytics.jsonl"
        events = [
            {
                "event": "message_send",
                "properties": {"prompt_tokens": 100, "completion_tokens": 50, "cost": 0.01},
                "time": 1705315800,
            },
            {
                "event": "message_send",
                "properties": {"prompt_tokens": 200, "completion_tokens": 75, "cost": 0.02},
                "time": 1705315900,
            },
        ]
        analytics_path.write_text(
            "\n".join(json.dumps(e) for e in events), encoding="utf-8"
        )

        actions = parse_aider_log(md_path, analytics_path=analytics_path)
        turn0_actions = [a for a in actions if a.raw.get("turn") == 0]
        turn1_actions = [a for a in actions if a.raw.get("turn") == 1]

        for a in turn0_actions:
            assert a.tokens_in == 100
            assert a.tokens_out == 50
            assert a.cost_usd == 0.01
        for a in turn1_actions:
            assert a.tokens_in == 200
            assert a.tokens_out == 75
            assert a.cost_usd == 0.02

    def test_more_turns_than_events_leaves_excess_zeroed(self, tmp_path):
        # 2 turns worth of markdown, only 1 analytics event.
        md_path = tmp_path / ".aider.chat.history.md"
        md_path.write_text(SEARCH_REPLACE_MD, encoding="utf-8")

        analytics_path = tmp_path / "analytics.jsonl"
        events = [
            {
                "event": "message_send",
                "properties": {"prompt_tokens": 42, "completion_tokens": 7, "cost": 0.005},
                "time": 1705315800,
            },
        ]
        analytics_path.write_text(json.dumps(events[0]), encoding="utf-8")

        actions = parse_aider_log(md_path, analytics_path=analytics_path)
        turn0_actions = [a for a in actions if a.raw.get("turn") == 0]
        turn1_actions = [a for a in actions if a.raw.get("turn") == 1]

        for a in turn0_actions:
            assert a.tokens_in == 42
        # Excess turn (no matching event) stays at zero-cost defaults.
        for a in turn1_actions:
            assert a.tokens_in == 0
            assert a.tokens_out == 0
            assert a.cost_usd == 0.0

    def test_more_events_than_turns_does_not_raise(self, tmp_path):
        # Only 1 turn's worth of markdown (ORIGINAL_UPDATED_MD), 2 events.
        md_path = tmp_path / ".aider.chat.history.md"
        md_path.write_text(ORIGINAL_UPDATED_MD, encoding="utf-8")

        # Event times are computed relative to the fixture's own session
        # header (rather than unrelated hardcoded epoch literals) so this
        # test is robust to Sprint 6's session-time-window partitioning
        # (item 2) regardless of the machine's local timezone -- both the
        # header and these times go through the same `.timestamp()`
        # conversion, so their *relative* offset is what matters, not
        # either one's absolute value in isolation.
        session_start = datetime.fromisoformat("2024-02-01T09:00:00")
        analytics_path = tmp_path / "analytics.jsonl"
        events = [
            {
                "event": "message_send",
                "properties": {"prompt_tokens": 1, "completion_tokens": 1, "cost": 0.001},
                "time": session_start.timestamp() + 100,
            },
            {
                "event": "message_send",
                "properties": {"prompt_tokens": 999, "completion_tokens": 999, "cost": 9.0},
                "time": session_start.timestamp() + 200,
            },
        ]
        analytics_path.write_text(
            "\n".join(json.dumps(e) for e in events), encoding="utf-8"
        )

        # Should not raise; only the one existing turn gets backfilled
        # (from the first/only ordinal), the second event is simply unused.
        actions = parse_aider_log(md_path, analytics_path=analytics_path)
        assert len(actions) > 0
        for a in actions:
            assert a.tokens_in == 1
            assert a.tokens_out == 1
            assert a.cost_usd == 0.001

    def test_missing_analytics_path_returns_markdown_only(self, tmp_path):
        md_path = tmp_path / ".aider.chat.history.md"
        md_path.write_text(SEARCH_REPLACE_MD, encoding="utf-8")

        missing_path = tmp_path / "does-not-exist.jsonl"
        actions = parse_aider_log(md_path, analytics_path=missing_path)
        for a in actions:
            assert a.tokens_in == 0
            assert a.cost_usd == 0.0

    def test_none_analytics_path_returns_markdown_only(self, tmp_path):
        md_path = tmp_path / ".aider.chat.history.md"
        md_path.write_text(SEARCH_REPLACE_MD, encoding="utf-8")

        actions = parse_aider_log(md_path, analytics_path=None)
        for a in actions:
            assert a.tokens_in == 0
            assert a.cost_usd == 0.0


class TestResumedSessions:
    """Sprint 6 item 1: a file with 2+ `# aider chat started at` headers
    splits into independent per-resume sessions, each with its own
    session_id and turn ordinals restarting at 0.
    """

    def test_split_sessions_segments_on_each_header(self):
        segments = _split_sessions(RESUMED_SESSION_MD)
        assert len(segments) == 2
        assert "session one" in segments[0]
        assert "session two" not in segments[0]
        assert "session two" in segments[1]

    def test_two_headers_produce_two_distinct_session_ids(self):
        actions = parse_aider_markdown_from_text(RESUMED_SESSION_MD)
        session_ids = {a.session_id for a in actions}
        assert len(session_ids) == 2

    def test_turn_ordinals_restart_within_each_session(self):
        actions = parse_aider_markdown_from_text(RESUMED_SESSION_MD)
        by_session: dict[str, list] = {}
        for a in actions:
            by_session.setdefault(a.session_id, []).append(a)
        assert len(by_session) == 2
        for session_actions in by_session.values():
            ordinals = sorted({a.raw.get("turn") for a in session_actions if "turn" in a.raw})
            # Each session has exactly one turn, restarting at ordinal 0.
            assert ordinals == [0]

    def test_single_header_file_unaffected(self):
        # Regression guard (regression-critical per Sprint 6 scope):
        # a single-header file must still produce exactly one segment/
        # session_id, byte-identical to Sprint 3 behavior.
        segments = _split_sessions(SEARCH_REPLACE_MD)
        assert len(segments) == 1
        assert segments[0] == SEARCH_REPLACE_MD

        actions = parse_aider_markdown_from_text(SEARCH_REPLACE_MD)
        assert len({a.session_id for a in actions}) == 1

    def test_zero_header_file_still_uses_single_segment(self):
        segments = _split_sessions("#### hello with no session header\n")
        assert segments == ["#### hello with no session header\n"]


class TestAnalyticsSessionBoundaries:
    """Sprint 6 item 2: analytics `message_send` events are partitioned by
    which Markdown session's time window they actually fall into, not
    blind whole-file ordinal pairing -- this matters once item 1 makes
    turn ordinals restart per session (two sessions can both have a turn
    with ordinal 0).
    """

    def test_events_partition_by_session_not_global_ordinal(self, tmp_path):
        md_path = tmp_path / ".aider.chat.history.md"
        md_path.write_text(RESUMED_SESSION_MD, encoding="utf-8")

        session1_start = datetime.fromisoformat("2024-08-01T09:00:00")
        session2_start = datetime.fromisoformat("2024-08-05T09:00:00")

        events = [
            {
                "event": "message_send",
                "properties": {"prompt_tokens": 111, "completion_tokens": 11, "cost": 0.011},
                "time": session1_start.timestamp() + 60,
            },
            {
                "event": "message_send",
                "properties": {"prompt_tokens": 222, "completion_tokens": 22, "cost": 0.022},
                "time": session2_start.timestamp() + 60,
            },
        ]
        analytics_path = tmp_path / "analytics.jsonl"
        analytics_path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")

        actions = parse_aider_log(md_path, analytics_path=analytics_path)
        by_session: dict[str, list] = {}
        for a in actions:
            by_session.setdefault(a.session_id, []).append(a)
        assert len(by_session) == 2

        # session_id embeds session_start.isoformat(), so lexicographic
        # sort on the id also sorts chronologically here.
        sessions_sorted = sorted(by_session.items(), key=lambda kv: kv[0])
        session1_actions, session2_actions = sessions_sorted[0][1], sessions_sorted[1][1]

        for a in session1_actions:
            assert a.tokens_in == 111
        for a in session2_actions:
            assert a.tokens_in == 222
        # Proves this isn't blind global ordinal pairing: both sessions'
        # turn ordinal is 0 (each restarts per item 1), so naive
        # whole-file ordinal pairing would have paired *both* sessions'
        # turn-0 actions to the same single event -- these must differ.
        assert session1_actions[0].tokens_in != session2_actions[0].tokens_in

    def test_exit_event_caps_session_window(self, tmp_path):
        md_path = tmp_path / ".aider.chat.history.md"
        md_path.write_text(ORIGINAL_UPDATED_MD, encoding="utf-8")

        session_start = datetime.fromisoformat("2024-02-01T09:00:00")
        events = [
            {
                "event": "message_send",
                "properties": {"prompt_tokens": 50, "completion_tokens": 5, "cost": 0.001},
                "time": session_start.timestamp() + 10,
            },
            {
                "event": "exit",
                "properties": {"reason": "user quit"},
                "time": session_start.timestamp() + 20,
            },
            {
                "event": "message_send",
                "properties": {"prompt_tokens": 999, "completion_tokens": 99, "cost": 9.0},
                "time": session_start.timestamp() + 30,
            },
        ]
        analytics_path = tmp_path / "analytics.jsonl"
        analytics_path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")

        actions = parse_aider_log(md_path, analytics_path=analytics_path)
        # ORIGINAL_UPDATED_MD has exactly one turn; the exit event at +20s
        # must exclude the message_send event at +30s (after exit) from
        # this session's window, leaving only the +10s event to pair.
        for a in actions:
            assert a.tokens_in == 50
            assert a.tokens_in != 999


class TestMismatchLogging:
    """Sprint 6 item 5: the analytics-event-count-vs-turn-count mismatch
    case now emits a visible WARNING log line instead of silently
    degrading. This does NOT change the underlying pairing behavior
    (still zip()'s shortest-wins, see TestAnalyticsMerge above) -- it only
    adds visibility, per the item's explicit scope.
    """

    def test_mismatched_counts_emits_warning(self, tmp_path, caplog):
        md_path = tmp_path / ".aider.chat.history.md"
        md_path.write_text(SEARCH_REPLACE_MD, encoding="utf-8")  # 2 turns

        session_start = datetime.fromisoformat("2024-01-15T10:30:00")
        analytics_path = tmp_path / "analytics.jsonl"
        analytics_path.write_text(
            json.dumps({
                "event": "message_send",
                "properties": {"prompt_tokens": 1},
                "time": session_start.timestamp() + 10,
            }),
            encoding="utf-8",
        )  # only 1 event

        with caplog.at_level(logging.WARNING, logger="agentwatch.parser.aider"):
            parse_aider_log(md_path, analytics_path=analytics_path)

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        message = warnings[0].getMessage()
        assert "2" in message  # 2 turns
        assert "1" in message  # 1 event

    def test_matched_counts_emits_no_warning(self, tmp_path, caplog):
        md_path = tmp_path / ".aider.chat.history.md"
        md_path.write_text(ORIGINAL_UPDATED_MD, encoding="utf-8")  # 1 turn

        session_start = datetime.fromisoformat("2024-02-01T09:00:00")
        analytics_path = tmp_path / "analytics.jsonl"
        analytics_path.write_text(
            json.dumps({
                "event": "message_send",
                "properties": {"prompt_tokens": 1},
                "time": session_start.timestamp() + 10,
            }),
            encoding="utf-8",
        )  # matching 1 event

        with caplog.at_level(logging.WARNING, logger="agentwatch.parser.aider"):
            parse_aider_log(md_path, analytics_path=analytics_path)

        assert not any(r.levelno == logging.WARNING for r in caplog.records)


class TestWholeFileEditFormat:
    """Sprint 6 item 4: `whole` edit format -- filename + fence + full-file
    content, no internal SEARCH/REPLACE-style marker. Kept separate from
    the SEARCH/REPLACE / ORIGINAL/UPDATED cases above.
    """

    def test_whole_file_block_matches(self):
        actions = parse_aider_markdown_from_text(WHOLE_FORMAT_MD)
        edits = [a for a in actions if a.tool_type == ToolType.EDIT]
        assert len(edits) == 1
        assert edits[0].file_path == "show_greeting.py"
        assert edits[0].raw.get("edit_format") == "whole"
        assert edits[0].success is True

    def test_whole_file_regex_matches_directly(self):
        m = WHOLE_FILE_BLOCK_RE.search(WHOLE_FORMAT_MD)
        assert m is not None
        assert m.group("filename") == "show_greeting.py"
        assert "def greeting(name):" in m.group("content")

    def test_diff_style_blocks_are_not_double_classified_as_whole(self):
        # A diff-marker block must be classified as "diff" only, never
        # also picked up by the generic whole-file matcher.
        actions = parse_aider_markdown_from_text(SEARCH_REPLACE_MD)
        edits = [a for a in actions if a.tool_type == ToolType.EDIT]
        assert len(edits) == 2
        assert all(e.raw.get("edit_format") == "diff" for e in edits)


class TestUdiffEditFormat:
    """Sprint 6 item 4: `udiff` edit format -- reserved ```diff fence +
    unified-diff hunks. Kept separate from the diff/whole cases above.
    """

    def test_udiff_block_matches(self):
        actions = parse_aider_markdown_from_text(UDIFF_FORMAT_MD)
        edits = [a for a in actions if a.tool_type == ToolType.EDIT]
        assert len(edits) == 1
        assert edits[0].file_path == "mathweb/flask/app.py"
        assert edits[0].raw.get("edit_format") == "udiff"
        assert edits[0].success is True

    def test_udiff_regex_matches_directly(self):
        m = UDIFF_BLOCK_RE.search(UDIFF_FORMAT_MD)
        assert m is not None
        assert m.group("a_path").strip() == "mathweb/flask/app.py"
        assert m.group("b_path").strip() == "mathweb/flask/app.py"
        assert "@@ ... @@" in m.group("hunks")

    def test_udiff_does_not_get_swallowed_by_whole_file_matcher(self):
        # The ```diff fence tag is reserved for udiff -- WHOLE_FILE_BLOCK_RE
        # must not also match it (would misclassify the diff as a whole-file
        # rewrite and mangle the filename).
        m = WHOLE_FILE_BLOCK_RE.search(UDIFF_FORMAT_MD)
        assert m is None


class TestParseFileDispatch:
    def test_md_extension_dispatches_to_aider_parser(self, tmp_path):
        md_path = tmp_path / ".aider.chat.history.md"
        md_path.write_text(SEARCH_REPLACE_MD, encoding="utf-8")

        actions = list(parse_file(md_path))
        assert len(actions) > 0
        assert any(a.tool_name == "aider_prompt" for a in actions)

    def test_jsonl_extension_still_uses_existing_logic(self, tmp_path):
        jsonl_path = tmp_path / "session.jsonl"
        entry = {
            "type": "assistant",
            "sessionId": "abc",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "hello from claude code"}],
            },
        }
        jsonl_path.write_text(json.dumps(entry) + "\n", encoding="utf-8")

        actions = list(parse_file(jsonl_path))
        assert len(actions) == 1
        assert actions[0].tool_name == "text_output"

    def test_vscdb_extension_dispatches_to_cursor_parser(self, tmp_path):
        """PLAYBOOK Sprint 7 (Cursor Phase 2): a `.vscdb` path dispatches to
        `cursor_source.parse_cursor_session`, auto-picking the latest
        agent-mode composer when no session_id filter is given."""
        import sqlite3

        db_path = tmp_path / "state.vscdb"
        conn = sqlite3.connect(str(db_path))
        try:
            conn.executescript(
                """
                CREATE TABLE composerHeaders (
                    composerId TEXT PRIMARY KEY, workspaceId TEXT, createdAt INTEGER,
                    lastUpdatedAt INTEGER, isArchived INTEGER, isSubagent INTEGER,
                    recency INTEGER, checkpointAt INTEGER, value TEXT
                );
                CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT);
                """
            )
            conn.execute(
                "INSERT INTO composerHeaders VALUES (?, 'ws', 0, 1000, 0, 0, 0, NULL, ?)",
                ("c1", json.dumps({"unifiedMode": "agent"})),
            )
            conn.execute(
                "INSERT INTO cursorDiskKV VALUES (?, ?)",
                (
                    "bubbleId:c1:b1",
                    json.dumps(
                        {
                            "type": 1,
                            "text": "hello from cursor",
                            "tokenCount": {"inputTokens": 0, "outputTokens": 0},
                            "toolResults": [],
                            "createdAt": "2026-07-14T00:00:00.000Z",
                        }
                    ),
                ),
            )
            conn.commit()
        finally:
            conn.close()

        actions = list(parse_file(db_path))
        assert len(actions) == 1
        assert actions[0].incoming_message == "hello from cursor"
        assert actions[0].session_id == "c1"

    def test_vscdb_session_id_filters_to_one_composer(self, tmp_path):
        import sqlite3

        db_path = tmp_path / "state.vscdb"
        conn = sqlite3.connect(str(db_path))
        try:
            conn.executescript(
                """
                CREATE TABLE composerHeaders (
                    composerId TEXT PRIMARY KEY, workspaceId TEXT, createdAt INTEGER,
                    lastUpdatedAt INTEGER, isArchived INTEGER, isSubagent INTEGER,
                    recency INTEGER, checkpointAt INTEGER, value TEXT
                );
                CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT);
                """
            )
            for cid, ts, text in (("c1", 1000, "first"), ("c2", 2000, "second")):
                conn.execute(
                    "INSERT INTO composerHeaders VALUES (?, 'ws', 0, ?, 0, 0, 0, NULL, ?)",
                    (cid, ts, json.dumps({"unifiedMode": "agent"})),
                )
                conn.execute(
                    "INSERT INTO cursorDiskKV VALUES (?, ?)",
                    (
                        f"bubbleId:{cid}:b1",
                        json.dumps(
                            {
                                "type": 1,
                                "text": text,
                                "tokenCount": {"inputTokens": 0, "outputTokens": 0},
                                "toolResults": [],
                                "createdAt": "2026-07-14T00:00:00.000Z",
                            }
                        ),
                    ),
                )
            conn.commit()
        finally:
            conn.close()

        actions = list(parse_file(db_path, session_id="c1"))
        assert len(actions) == 1
        assert actions[0].incoming_message == "first"


def parse_aider_markdown_from_text(text: str, tmp_path=None):
    """Helper: write `text` to a temp `.aider.chat.history.md` and parse it.

    Uses pytest's own tmp_path indirectly via a module-level fixture isn't
    available outside a test, so this helper creates its own throwaway
    directory via the stdlib to keep the diff-style/commit-inference tests
    above free of repetitive tmp_path plumbing.
    """
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / ".aider.chat.history.md"
        path.write_text(text, encoding="utf-8")
        return parse_aider_markdown(path)
