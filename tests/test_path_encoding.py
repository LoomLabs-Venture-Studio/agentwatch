"""Tests for the shared Claude Code path-encoding helper.

`encode_path_for_claude` is used by both `discovery.py` and `cc_stats.py`
to map a working directory to its `~/.claude/projects/<encoded>` directory
name. The replacement (`/`, `\\`, `:`, space -> `-`) is applied
unconditionally regardless of the host OS.
"""

from __future__ import annotations

from pathlib import Path

from agentwatch.path_encoding import encode_path_for_claude


class TestEncodePathForClaude:
    def test_posix_path(self):
        assert (
            encode_path_for_claude(Path("/Users/zaid/Projects/agentwatch"))
            == "-Users-zaid-Projects-agentwatch"
        )

    def test_posix_path_with_spaces(self):
        assert (
            encode_path_for_claude(Path("/Users/zaid/my project"))
            == "-Users-zaid-my-project"
        )

    def test_windows_path_empirical_case(self):
        # Empirically confirmed against a real ~/.claude/projects/ entry on
        # Windows: backslash, colon, and space all become '-'.
        windows_path = (
            r"C:\Users\Zaid\Desktop\claude work\agentwatch\agentwatch-main"
        )
        expected = "C--Users-Zaid-Desktop-claude-work-agentwatch-agentwatch-main"
        assert encode_path_for_claude(Path(windows_path)) == expected

    def test_windows_path_no_spaces(self):
        windows_path = r"C:\Users\zaid\Projects\agentwatch"
        assert (
            encode_path_for_claude(Path(windows_path))
            == "C--Users-zaid-Projects-agentwatch"
        )

    def test_adjacent_distinct_separators_each_replaced(self):
        # Path normalizes duplicate slashes, but distinct separator chars
        # (e.g. trailing colon then slash) are each replaced individually.
        assert encode_path_for_claude(Path("a: b")) == "a--b"

    def test_string_input_accepted_via_str_conversion(self):
        # Function takes a Path, but Path(str) round-trips consistently.
        assert encode_path_for_claude(Path("relative/dir")) == "relative-dir"

    def test_every_non_alphanumeric_becomes_dash(self):
        # Claude Code's rule is replace(/[^a-zA-Z0-9]/g, "-") (#75, read from
        # the 2.x CLI binary); `.` and `_` were missed before.
        assert encode_path_for_claude(Path("my_proj.v2")) == "my-proj-v2"

    def test_long_path_truncated_with_hash(self):
        # Past 200 chars the CLI keeps 200 and appends its 32-bit string hash
        # in base 36. Expected hash computed with the CLI's own JS function.
        name = "z\u00e9_" + "a_b.c" * 45
        prefix = "z--" + "a-b-c" * 45
        assert encode_path_for_claude(Path(name)) == prefix[:200] + "-8gw9cn"
