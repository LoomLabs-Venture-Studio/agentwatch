"""Tests for Claude Code token usage statistics (cc_stats module)."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from agentwatch.cc_stats import (
    BashCategory,
    StatsReport,
    TokenBucket,
    ToolCategory,
    TrivialCall,
    classify_bash_command,
    classify_tool_name,
    compute_stats,
    cwd_to_project_dir,
    is_trivial_bash,
    parse_session_stats,
    project_dir_to_name,
)


# ---------------------------------------------------------------------------
# Tool classification
# ---------------------------------------------------------------------------


class TestClassifyToolName:
    def test_known_tools(self):
        assert classify_tool_name("Bash") == ToolCategory.Bash
        assert classify_tool_name("Read") == ToolCategory.Read
        assert classify_tool_name("Edit") == ToolCategory.Edit
        assert classify_tool_name("Write") == ToolCategory.Write
        assert classify_tool_name("Grep") == ToolCategory.Grep
        assert classify_tool_name("Glob") == ToolCategory.Glob
        assert classify_tool_name("Task") == ToolCategory.Task

    def test_case_insensitive(self):
        assert classify_tool_name("bash") == ToolCategory.Bash
        assert classify_tool_name("BASH") == ToolCategory.Bash
        assert classify_tool_name("read") == ToolCategory.Read

    def test_web_tools(self):
        assert classify_tool_name("WebFetch") == ToolCategory.Web
        assert classify_tool_name("WebSearch") == ToolCategory.Web

    def test_planning_tools(self):
        assert classify_tool_name("TodoRead") == ToolCategory.Planning
        assert classify_tool_name("TodoWrite") == ToolCategory.Planning
        assert classify_tool_name("EnterPlanMode") == ToolCategory.Planning
        assert classify_tool_name("ExitPlanMode") == ToolCategory.Planning

    def test_mcp_tools(self):
        assert classify_tool_name("mcp_server:search") == ToolCategory.MCP
        assert classify_tool_name("some:tool") == ToolCategory.MCP

    def test_unknown_tool(self):
        assert classify_tool_name("SomeNewTool") == ToolCategory.Other

    def test_notebook_edit(self):
        assert classify_tool_name("NotebookEdit") == ToolCategory.Edit


# ---------------------------------------------------------------------------
# Bash classification
# ---------------------------------------------------------------------------


class TestClassifyBashCommand:
    def test_git_commands(self):
        assert classify_bash_command("git status") == BashCategory.Git
        assert classify_bash_command("git diff HEAD~1") == BashCategory.Git
        assert classify_bash_command("gh pr create") == BashCategory.Git

    def test_testing(self):
        assert classify_bash_command("pytest tests/ -v") == BashCategory.Testing
        assert classify_bash_command("jest --coverage") == BashCategory.Testing
        assert classify_bash_command("npm test") == BashCategory.Testing
        assert classify_bash_command("npx jest tests/") == BashCategory.Testing
        assert classify_bash_command("python -m pytest") == BashCategory.Testing
        assert classify_bash_command("cargo test") == BashCategory.Testing
        assert classify_bash_command("go test ./...") == BashCategory.Testing
        assert classify_bash_command("make test") == BashCategory.Testing

    def test_package_management(self):
        assert classify_bash_command("pip install requests") == BashCategory.PackageMgmt
        assert classify_bash_command("npm install lodash") == BashCategory.PackageMgmt
        assert classify_bash_command("yarn add react") == BashCategory.PackageMgmt
        assert classify_bash_command("brew install jq") == BashCategory.PackageMgmt

    def test_server_dev(self):
        assert classify_bash_command("npm run dev") == BashCategory.ServerDev
        assert classify_bash_command("npm start") == BashCategory.ServerDev
        assert classify_bash_command("node server.js") == BashCategory.ServerDev
        assert classify_bash_command("uvicorn app:app") == BashCategory.ServerDev
        assert classify_bash_command("npm run build") == BashCategory.ServerDev

    def test_file_ops(self):
        assert classify_bash_command("mkdir -p foo/bar") == BashCategory.FileOps
        assert classify_bash_command("cp src/a.py dst/") == BashCategory.FileOps
        assert classify_bash_command("rm -rf dist/") == BashCategory.FileOps

    def test_process_mgmt(self):
        assert classify_bash_command("ps aux") == BashCategory.Process
        assert classify_bash_command("kill -9 1234") == BashCategory.Process
        assert classify_bash_command("lsof -i :8080") == BashCategory.Process

    def test_pipeline_uses_first_cmd(self):
        assert classify_bash_command("git log | head -5") == BashCategory.Git
        assert classify_bash_command("ps aux | grep node") == BashCategory.Process

    def test_chain_uses_first_cmd(self):
        assert classify_bash_command("git add . && git commit -m 'msg'") == BashCategory.Git

    def test_env_var_prefix_skipped(self):
        assert classify_bash_command("NODE_ENV=test npm test") == BashCategory.Testing
        assert classify_bash_command("CI=true pytest") == BashCategory.Testing

    def test_empty_command(self):
        assert classify_bash_command("") == BashCategory.Other
        assert classify_bash_command("   ") == BashCategory.Other

    def test_full_path_program(self):
        assert classify_bash_command("/usr/bin/git status") == BashCategory.Git

    def test_other_commands(self):
        assert classify_bash_command("echo hello") == BashCategory.Other
        assert classify_bash_command("ls -la") == BashCategory.Other
        assert classify_bash_command("wc -l file.txt") == BashCategory.Other


# ---------------------------------------------------------------------------
# TokenBucket
# ---------------------------------------------------------------------------


class TestIsTrivialBash:
    """Tests for trivial command detection."""

    def test_simple_git_is_trivial(self):
        assert is_trivial_bash("git status") is True
        assert is_trivial_bash("git add .") is True
        assert is_trivial_bash("git commit -m 'msg'") is True
        assert is_trivial_bash("git push origin main") is True
        assert is_trivial_bash("git log --oneline -5") is True
        assert is_trivial_bash("gh pr create") is True

    def test_simple_cli_is_trivial(self):
        assert is_trivial_bash("ls -la") is True
        assert is_trivial_bash("pwd") is True
        assert is_trivial_bash("mkdir -p foo/bar") is True
        assert is_trivial_bash("rm -rf dist/") is True
        assert is_trivial_bash("cp src/a.py dst/") is True

    def test_testing_invocation_is_trivial(self):
        assert is_trivial_bash("pytest tests/ -v") is True
        assert is_trivial_bash("jest --coverage") is True
        assert is_trivial_bash("npm test") is True

    def test_server_dev_is_trivial(self):
        assert is_trivial_bash("npm run dev") is True
        assert is_trivial_bash("npm start") is True
        assert is_trivial_bash("node server.js") is True

    def test_package_mgmt_is_trivial(self):
        assert is_trivial_bash("pip install requests") is True
        assert is_trivial_bash("npm install lodash") is True
        assert is_trivial_bash("brew install jq") is True

    def test_process_mgmt_is_trivial(self):
        assert is_trivial_bash("ps aux") is True
        assert is_trivial_bash("kill -9 1234") is True
        assert is_trivial_bash("lsof -i :8080") is True

    def test_inline_python_is_substantive(self):
        assert is_trivial_bash('python3 -c "import json; print(json.dumps({}))"') is False
        assert is_trivial_bash("python -c 'print(1+1)'") is False

    def test_inline_node_is_substantive(self):
        assert is_trivial_bash('node -e "console.log(1)"') is False

    def test_awk_sed_is_substantive(self):
        assert is_trivial_bash("awk '{print $1}' file.txt") is False
        assert is_trivial_bash("sed -i 's/foo/bar/g' file.txt") is False

    def test_unknown_program_is_substantive(self):
        assert is_trivial_bash("custom_build_tool --flag") is False
        assert is_trivial_bash("my_script.sh") is False

    def test_running_python_script_is_trivial(self):
        assert is_trivial_bash("python3 app.py") is True
        assert is_trivial_bash("python manage.py runserver") is True

    def test_pipeline_of_trivial_is_trivial(self):
        assert is_trivial_bash("git log | head -5") is True
        assert is_trivial_bash("ps aux | grep node") is True

    def test_chain_of_trivial_is_trivial(self):
        assert is_trivial_bash("git add . && git commit -m 'msg'") is True

    def test_env_prefix_is_trivial(self):
        assert is_trivial_bash("NODE_ENV=test npm test") is True

    def test_empty_is_trivial(self):
        assert is_trivial_bash("") is True
        assert is_trivial_bash("   ") is True

    def test_full_path_trivial(self):
        assert is_trivial_bash("/usr/bin/git status") is True


# ---------------------------------------------------------------------------


class TestTokenBucket:
    def test_total_tokens(self):
        b = TokenBucket(
            input_tokens=100,
            output_tokens=50,
            cache_write_tokens=200,
            cache_read_tokens=300,
        )
        assert b.total_tokens == 650

    def test_merge(self):
        a = TokenBucket(input_tokens=10, output_tokens=5, call_count=1)
        b = TokenBucket(input_tokens=20, output_tokens=10, call_count=2)
        a.merge(b)
        assert a.input_tokens == 30
        assert a.output_tokens == 15
        assert a.call_count == 3

    def test_estimated_cost_sonnet(self):
        b = TokenBucket(
            input_tokens=1_000_000,
            output_tokens=1_000_000,
            cache_write_tokens=1_000_000,
            cache_read_tokens=1_000_000,
        )
        # sonnet: 3 + 15 + 3.75 + 0.30 = 22.05
        cost = b.estimated_cost_usd("sonnet")
        assert abs(cost - 22.05) < 0.01

    def test_estimated_cost_opus(self):
        b = TokenBucket(
            input_tokens=1_000_000,
            output_tokens=1_000_000,
            cache_write_tokens=1_000_000,
            cache_read_tokens=1_000_000,
        )
        # opus: 15 + 75 + 18.75 + 1.50 = 110.25
        cost = b.estimated_cost_usd("claude-opus-4-6")
        assert abs(cost - 110.25) < 0.01


# ---------------------------------------------------------------------------
# StatsReport
# ---------------------------------------------------------------------------


class TestStatsReport:
    def test_merge(self):
        a = StatsReport(
            by_tool={ToolCategory.Bash: TokenBucket(input_tokens=100, call_count=1)},
            totals=TokenBucket(input_tokens=100),
            message_count=5,
            session_count=1,
        )
        b = StatsReport(
            by_tool={
                ToolCategory.Bash: TokenBucket(input_tokens=200, call_count=2),
                ToolCategory.Read: TokenBucket(input_tokens=50, call_count=1),
            },
            totals=TokenBucket(input_tokens=250),
            message_count=3,
            session_count=1,
        )
        a.merge(b)
        assert a.by_tool[ToolCategory.Bash].input_tokens == 300
        assert a.by_tool[ToolCategory.Read].input_tokens == 50
        assert a.totals.input_tokens == 350
        assert a.message_count == 8
        assert a.session_count == 2

    def test_cache_hit_ratio(self):
        r = StatsReport(
            totals=TokenBucket(cache_write_tokens=100, cache_read_tokens=900)
        )
        assert abs(r.cache_hit_ratio - 0.9) < 0.001

    def test_cache_hit_ratio_zero(self):
        r = StatsReport(totals=TokenBucket())
        assert r.cache_hit_ratio == 0.0

    def test_to_dict(self):
        r = StatsReport(
            by_tool={ToolCategory.Bash: TokenBucket(input_tokens=100, call_count=2)},
            totals=TokenBucket(input_tokens=100),
            message_count=5,
            session_count=1,
            project_name="test",
            model="sonnet",
        )
        d = r.to_dict()
        assert d["project"] == "test"
        assert d["sessions"] == 1
        assert d["messages"] == 5
        assert "Bash" in d["by_tool"]


# ---------------------------------------------------------------------------
# CWD mapping
# ---------------------------------------------------------------------------


class TestCwdMapping:
    def test_cwd_to_project_dir_existing(self, tmp_path, monkeypatch):
        projects = tmp_path / ".claude" / "projects"
        projects.mkdir(parents=True)
        # Simulate: CWD = /Users/zaid/foo -> dir = -Users-zaid-foo
        cwd = Path("/Users/zaid/foo")
        expected_name = "-Users-zaid-foo"
        (projects / expected_name).mkdir()

        monkeypatch.setattr(
            "agentwatch.cc_stats.CLAUDE_PROJECTS_DIR", projects
        )
        result = cwd_to_project_dir(cwd)
        assert result is not None
        assert result.name == expected_name

    def test_cwd_to_project_dir_missing(self, tmp_path, monkeypatch):
        projects = tmp_path / ".claude" / "projects"
        projects.mkdir(parents=True)
        monkeypatch.setattr(
            "agentwatch.cc_stats.CLAUDE_PROJECTS_DIR", projects
        )
        result = cwd_to_project_dir(Path("/nonexistent/dir"))
        assert result is None

    def test_project_dir_to_name(self):
        assert project_dir_to_name(Path("-Users-zaid-Projects-agentwatch")) == "agentwatch"
        assert project_dir_to_name(Path("-private-tmp-foo")) == "foo"


# ---------------------------------------------------------------------------
# JSONL parsing
# ---------------------------------------------------------------------------


def _make_assistant_line(
    msg_id: str,
    content: list[dict],
    *,
    input_tokens: int = 100,
    output_tokens: int = 50,
    cache_write: int = 200,
    cache_read: int = 1000,
    model: str = "claude-sonnet-4-5-20250929",
) -> str:
    """Helper to create a single assistant JSONL line."""
    return json.dumps({
        "type": "assistant",
        "uuid": f"uuid-{msg_id}-{len(content)}",
        "message": {
            "id": msg_id,
            "model": model,
            "role": "assistant",
            "content": content,
            "stop_reason": None,
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cache_creation_input_tokens": cache_write,
                "cache_read_input_tokens": cache_read,
            },
        },
    })


def _make_user_line(msg_id: str = "user-1") -> str:
    return json.dumps({
        "type": "user",
        "uuid": msg_id,
        "message": {"role": "user", "content": "hello"},
    })


class TestParseSessionStats:
    def test_single_tool_call(self, tmp_path):
        """A single message with one Bash tool_use."""
        lines = [
            _make_user_line(),
            _make_assistant_line("msg-1", [
                {"type": "tool_use", "id": "t1", "name": "Bash",
                 "input": {"command": "git status"}},
            ]),
        ]
        jsonl = tmp_path / "session.jsonl"
        jsonl.write_text("\n".join(lines))

        report = parse_session_stats(jsonl)
        assert report.message_count == 1
        assert report.tool_call_count == 1
        assert ToolCategory.Bash in report.by_tool
        assert report.by_tool[ToolCategory.Bash].call_count == 1
        assert report.totals.input_tokens == 100
        assert report.totals.output_tokens == 50
        assert BashCategory.Git in report.by_bash_category

    def test_streaming_deduplication(self, tmp_path):
        """Multiple lines with same message.id are deduplicated."""
        lines = [
            _make_user_line(),
            # Chunk 1: thinking
            _make_assistant_line("msg-1", [
                {"type": "thinking", "thinking": "Let me think..."},
            ], output_tokens=10),
            # Chunk 2: text
            _make_assistant_line("msg-1", [
                {"type": "text", "text": "Here's my answer"},
            ], output_tokens=30),
            # Chunk 3: tool_use
            _make_assistant_line("msg-1", [
                {"type": "tool_use", "id": "t1", "name": "Read",
                 "input": {"file_path": "/foo.py"}},
            ], output_tokens=50),
        ]
        jsonl = tmp_path / "session.jsonl"
        jsonl.write_text("\n".join(lines))

        report = parse_session_stats(jsonl)
        # Should be 1 message, not 3
        assert report.message_count == 1
        # output_tokens should be the max (50), not sum
        assert report.totals.output_tokens == 50
        assert report.tool_call_count == 1
        assert ToolCategory.Read in report.by_tool

    def test_proportional_attribution(self, tmp_path):
        """Multi-tool message splits tokens proportionally."""
        lines = [
            _make_user_line(),
            _make_assistant_line("msg-1", [
                {"type": "tool_use", "id": "t1", "name": "Bash",
                 "input": {"command": "git status"}},
            ], input_tokens=300, output_tokens=150),
            _make_assistant_line("msg-1", [
                {"type": "tool_use", "id": "t2", "name": "Read",
                 "input": {"file_path": "/foo.py"}},
            ], input_tokens=300, output_tokens=150),
            _make_assistant_line("msg-1", [
                {"type": "tool_use", "id": "t3", "name": "Read",
                 "input": {"file_path": "/bar.py"}},
            ], input_tokens=300, output_tokens=150),
        ]
        jsonl = tmp_path / "session.jsonl"
        jsonl.write_text("\n".join(lines))

        report = parse_session_stats(jsonl)
        assert report.message_count == 1
        assert report.tool_call_count == 3
        # 1 Bash + 2 Read = 1/3 + 2/3 split
        bash_tokens = report.by_tool[ToolCategory.Bash].input_tokens
        read_tokens = report.by_tool[ToolCategory.Read].input_tokens
        assert bash_tokens == 100  # 300 / 3
        assert read_tokens == 200  # 300 * 2/3

    def test_thinking_only_message(self, tmp_path):
        """Message with only thinking content attributed to Thinking."""
        lines = [
            _make_user_line(),
            _make_assistant_line("msg-1", [
                {"type": "thinking", "thinking": "Deep thought..."},
            ]),
        ]
        jsonl = tmp_path / "session.jsonl"
        jsonl.write_text("\n".join(lines))

        report = parse_session_stats(jsonl)
        assert report.message_count == 1
        assert ToolCategory.Thinking in report.by_tool
        assert report.tool_call_count == 0

    def test_text_only_message(self, tmp_path):
        """Message with only text content attributed to Other."""
        lines = [
            _make_user_line(),
            _make_assistant_line("msg-1", [
                {"type": "text", "text": "Here you go"},
            ]),
        ]
        jsonl = tmp_path / "session.jsonl"
        jsonl.write_text("\n".join(lines))

        report = parse_session_stats(jsonl)
        assert ToolCategory.Other in report.by_tool

    def test_bash_subcategory_tracking(self, tmp_path):
        """Bash commands are sub-categorized correctly."""
        lines = [
            _make_user_line(),
            _make_assistant_line("msg-1", [
                {"type": "tool_use", "id": "t1", "name": "Bash",
                 "input": {"command": "git status"}},
            ]),
            _make_assistant_line("msg-2", [
                {"type": "tool_use", "id": "t2", "name": "Bash",
                 "input": {"command": "pytest tests/ -v"}},
            ]),
            _make_assistant_line("msg-3", [
                {"type": "tool_use", "id": "t3", "name": "Bash",
                 "input": {"command": "npm run dev"}},
            ]),
        ]
        jsonl = tmp_path / "session.jsonl"
        jsonl.write_text("\n".join(lines))

        report = parse_session_stats(jsonl)
        assert BashCategory.Git in report.by_bash_category
        assert BashCategory.Testing in report.by_bash_category
        assert BashCategory.ServerDev in report.by_bash_category

    def test_multiple_messages(self, tmp_path):
        """Multiple distinct messages accumulate correctly."""
        lines = [
            _make_user_line(),
            _make_assistant_line("msg-1", [
                {"type": "tool_use", "id": "t1", "name": "Bash",
                 "input": {"command": "ls"}},
            ], input_tokens=100, output_tokens=50),
            _make_assistant_line("msg-2", [
                {"type": "tool_use", "id": "t2", "name": "Read",
                 "input": {"file_path": "/f.py"}},
            ], input_tokens=200, output_tokens=80),
        ]
        jsonl = tmp_path / "session.jsonl"
        jsonl.write_text("\n".join(lines))

        report = parse_session_stats(jsonl)
        assert report.message_count == 2
        assert report.totals.input_tokens == 300
        assert report.totals.output_tokens == 130

    def test_skips_non_assistant_lines(self, tmp_path):
        """Non-assistant lines are ignored."""
        lines = [
            json.dumps({"type": "user", "message": {"role": "user", "content": "hi"}}),
            json.dumps({"type": "system", "message": {"content": "system msg"}}),
            json.dumps({"type": "progress", "data": {}}),
            _make_assistant_line("msg-1", [
                {"type": "text", "text": "hello"},
            ]),
        ]
        jsonl = tmp_path / "session.jsonl"
        jsonl.write_text("\n".join(lines))

        report = parse_session_stats(jsonl)
        assert report.message_count == 1

    def test_skips_malformed_lines(self, tmp_path):
        """Malformed JSON lines are skipped gracefully."""
        lines = [
            "not json at all",
            '{"broken json',
            _make_assistant_line("msg-1", [
                {"type": "text", "text": "good"},
            ]),
        ]
        jsonl = tmp_path / "session.jsonl"
        jsonl.write_text("\n".join(lines))

        report = parse_session_stats(jsonl)
        assert report.message_count == 1

    def test_empty_file(self, tmp_path):
        """Empty file produces empty report."""
        jsonl = tmp_path / "session.jsonl"
        jsonl.write_text("")

        report = parse_session_stats(jsonl)
        assert report.message_count == 0
        assert report.totals.total_tokens == 0

    def test_model_detection(self, tmp_path):
        """Most common model is set on report."""
        lines = [
            _make_assistant_line("msg-1", [
                {"type": "text", "text": "a"},
            ], model="claude-opus-4-6"),
            _make_assistant_line("msg-2", [
                {"type": "text", "text": "b"},
            ], model="claude-opus-4-6"),
            _make_assistant_line("msg-3", [
                {"type": "text", "text": "c"},
            ], model="claude-sonnet-4-5-20250929"),
        ]
        jsonl = tmp_path / "session.jsonl"
        jsonl.write_text("\n".join(lines))

        report = parse_session_stats(jsonl)
        assert "opus" in report.model

    def test_trivial_tracking(self, tmp_path):
        """Trivial bash commands are tracked separately."""
        lines = [
            _make_user_line(),
            # Trivial: git status
            _make_assistant_line("msg-1", [
                {"type": "tool_use", "id": "t1", "name": "Bash",
                 "input": {"command": "git status"}},
            ], input_tokens=100),
            # Trivial: ls
            _make_assistant_line("msg-2", [
                {"type": "tool_use", "id": "t2", "name": "Bash",
                 "input": {"command": "ls -la"}},
            ], input_tokens=100),
            # Substantive: inline python
            _make_assistant_line("msg-3", [
                {"type": "tool_use", "id": "t3", "name": "Bash",
                 "input": {"command": "python3 -c 'import json; print(1)'"}},
            ], input_tokens=100),
            # Substantive: Edit tool
            _make_assistant_line("msg-4", [
                {"type": "tool_use", "id": "t4", "name": "Edit",
                 "input": {"file_path": "/f.py", "old_string": "a", "new_string": "b"}},
            ], input_tokens=100),
        ]
        jsonl = tmp_path / "session.jsonl"
        jsonl.write_text("\n".join(lines))

        report = parse_session_stats(jsonl)
        assert report.trivial.call_count == 2  # git, ls
        assert report.substantive.call_count == 2  # python -c, Edit
        assert "git" in report.top_trivial_commands
        assert "ls" in report.top_trivial_commands

    def test_trivial_vs_substantive_tokens(self, tmp_path):
        """Trivial/substantive token sums match total."""
        lines = [
            _make_user_line(),
            _make_assistant_line("msg-1", [
                {"type": "tool_use", "id": "t1", "name": "Bash",
                 "input": {"command": "git status"}},
            ], input_tokens=200, output_tokens=50, cache_write=0, cache_read=1000),
            _make_assistant_line("msg-2", [
                {"type": "tool_use", "id": "t2", "name": "Edit",
                 "input": {"file_path": "/f.py"}},
            ], input_tokens=300, output_tokens=80, cache_write=0, cache_read=2000),
        ]
        jsonl = tmp_path / "session.jsonl"
        jsonl.write_text("\n".join(lines))

        report = parse_session_stats(jsonl)
        combined = report.trivial.total_tokens + report.substantive.total_tokens
        assert combined == report.totals.total_tokens

    def test_trivial_calls_list(self, tmp_path):
        """Trivial calls are collected with command and token details."""
        lines = [
            _make_user_line(),
            _make_assistant_line("msg-1", [
                {"type": "tool_use", "id": "t1", "name": "Bash",
                 "input": {"command": "git status"}},
            ], input_tokens=100, output_tokens=20),
            _make_assistant_line("msg-2", [
                {"type": "tool_use", "id": "t2", "name": "Bash",
                 "input": {"command": "ls -la"}},
            ], input_tokens=100, output_tokens=20),
            # Non-trivial — should NOT appear
            _make_assistant_line("msg-3", [
                {"type": "tool_use", "id": "t3", "name": "Bash",
                 "input": {"command": "python3 -c 'print(1)'"}},
            ], input_tokens=100, output_tokens=20),
        ]
        jsonl = tmp_path / "session.jsonl"
        jsonl.write_text("\n".join(lines))

        report = parse_session_stats(jsonl)
        assert len(report.trivial_calls) == 2
        cmds = [tc.command for tc in report.trivial_calls]
        assert "git status" in cmds
        assert "ls -la" in cmds
        assert all(tc.total_tokens > 0 for tc in report.trivial_calls)
        assert all(tc.estimated_cost_usd > 0 for tc in report.trivial_calls)

    def test_trivial_calls_with_prompt(self, tmp_path):
        """Trivial calls resolve the user prompt that triggered them."""
        lines = [
            # User message with known uuid
            json.dumps({
                "type": "user",
                "uuid": "user-abc",
                "message": {"role": "user", "content": "commit everything and push"},
            }),
            # Assistant message whose parentUuid points to user
            json.dumps({
                "type": "assistant",
                "uuid": "ast-1",
                "parentUuid": "user-abc",
                "message": {
                    "id": "msg-1",
                    "model": "claude-sonnet-4-5-20250929",
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "id": "t1", "name": "Bash",
                         "input": {"command": "git add ."}},
                    ],
                    "stop_reason": None,
                    "usage": {
                        "input_tokens": 100,
                        "output_tokens": 20,
                        "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 500,
                    },
                },
            }),
        ]
        jsonl = tmp_path / "session.jsonl"
        jsonl.write_text("\n".join(lines))

        report = parse_session_stats(jsonl)
        assert len(report.trivial_calls) == 1
        tc = report.trivial_calls[0]
        assert tc.command == "git add ."
        assert tc.user_prompt == "commit everything and push"

    def test_trivial_calls_session_id(self, tmp_path):
        """Trivial calls include the session ID from the filename."""
        lines = [
            _make_user_line(),
            _make_assistant_line("msg-1", [
                {"type": "tool_use", "id": "t1", "name": "Bash",
                 "input": {"command": "git status"}},
            ]),
        ]
        jsonl = tmp_path / "abc-123-def.jsonl"
        jsonl.write_text("\n".join(lines))

        report = parse_session_stats(jsonl)
        assert len(report.trivial_calls) == 1
        assert report.trivial_calls[0].session_id == "abc-123-def"


# ---------------------------------------------------------------------------
# compute_stats (end-to-end)
# ---------------------------------------------------------------------------


class TestComputeStats:
    def test_single_project(self, tmp_path, monkeypatch):
        """End-to-end: parse sessions from a project directory."""
        projects = tmp_path / "projects"
        pdir = projects / "-Users-test-myproject"
        pdir.mkdir(parents=True)

        # Session 1
        s1 = pdir / "session-1.jsonl"
        s1.write_text("\n".join([
            _make_user_line(),
            _make_assistant_line("msg-1", [
                {"type": "tool_use", "id": "t1", "name": "Bash",
                 "input": {"command": "git status"}},
            ], input_tokens=100),
        ]))

        # Session 2
        s2 = pdir / "session-2.jsonl"
        s2.write_text("\n".join([
            _make_user_line(),
            _make_assistant_line("msg-2", [
                {"type": "tool_use", "id": "t2", "name": "Read",
                 "input": {"file_path": "/f.py"}},
            ], input_tokens=200),
        ]))

        monkeypatch.setattr("agentwatch.cc_stats.CLAUDE_PROJECTS_DIR", projects)
        report = compute_stats(project_dir=pdir)
        assert report.session_count == 2
        assert report.message_count == 2
        assert report.totals.input_tokens == 300

    def test_session_filter(self, tmp_path, monkeypatch):
        """--session filters to a single session."""
        projects = tmp_path / "projects"
        pdir = projects / "-test"
        pdir.mkdir(parents=True)

        s1 = pdir / "abc-123.jsonl"
        s1.write_text("\n".join([
            _make_assistant_line("msg-1", [
                {"type": "text", "text": "a"},
            ], input_tokens=100),
        ]))

        s2 = pdir / "def-456.jsonl"
        s2.write_text("\n".join([
            _make_assistant_line("msg-2", [
                {"type": "text", "text": "b"},
            ], input_tokens=999),
        ]))

        monkeypatch.setattr("agentwatch.cc_stats.CLAUDE_PROJECTS_DIR", projects)
        report = compute_stats(project_dir=pdir, session_id="abc-123")
        assert report.session_count == 1
        assert report.totals.input_tokens == 100

    def test_all_projects(self, tmp_path, monkeypatch):
        """--all scans across all projects."""
        projects = tmp_path / "projects"
        p1 = projects / "-proj-a"
        p1.mkdir(parents=True)
        p2 = projects / "-proj-b"
        p2.mkdir(parents=True)

        (p1 / "s1.jsonl").write_text(_make_assistant_line("m1", [
            {"type": "text", "text": "a"},
        ], input_tokens=100))
        (p2 / "s2.jsonl").write_text(_make_assistant_line("m2", [
            {"type": "text", "text": "b"},
        ], input_tokens=200))

        monkeypatch.setattr("agentwatch.cc_stats.CLAUDE_PROJECTS_DIR", projects)
        report = compute_stats(all_projects=True)
        assert report.session_count == 2
        assert report.totals.input_tokens == 300
        assert "all" in report.project_name

    def test_no_project_found(self, tmp_path, monkeypatch):
        """Returns empty report when project dir doesn't exist."""
        projects = tmp_path / "projects"
        projects.mkdir(parents=True)
        monkeypatch.setattr("agentwatch.cc_stats.CLAUDE_PROJECTS_DIR", projects)
        report = compute_stats(project_dir=None)
        assert report.message_count == 0
