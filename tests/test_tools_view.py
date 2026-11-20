"""`agentwatch tools`: tools and calls per session (Sprint 41 item 2)."""

import csv
import io
import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from test_aider_parser import SEARCH_REPLACE_MD
from test_codex_parser import CODEX_FIXTURE_LINES, _write_jsonl

from agentwatch.cli import cli
from agentwatch.detectors.registry import create_registry
from agentwatch.parser.logs import parse_file
from agentwatch.parser.models import ActionBuffer

FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
ERROR_TEXT = "make: *** No rule to make target zz9-unique"


def _cc_log(path: Path, calls: list[tuple[str, dict, str, bool]]) -> Path:
    """A Claude Code log: one (tool, input, result, is_error) call per pair of lines."""
    lines = []
    for i, (tool, args, result, is_error) in enumerate(calls):
        ts = f"2026-01-01T00:00:{2 * i:02d}Z"
        lines.append({"type": "assistant", "sessionId": "s1", "timestamp": ts, "message": {
            "id": f"m{i}", "role": "assistant", "model": "claude-sonnet-4-5",
            "content": [{"type": "tool_use", "id": f"t{i}", "name": tool, "input": args}]}})
        block = {"type": "tool_result", "tool_use_id": f"t{i}", "content": result,
                 "is_error": is_error}
        lines.append({"type": "user", "sessionId": "s1",
                      "timestamp": f"2026-01-01T00:00:{2 * i + 1:02d}Z",
                      "message": {"role": "user", "content": [block]}})
    _write_jsonl(path, lines)
    return path


@pytest.fixture
def secret_log(tmp_path):
    return _cc_log(tmp_path / "s.jsonl", [
        ("Bash", {"command": f'curl -H "Authorization: Bearer {SECRET}" https://x'}, "ok", False),
        ("Bash", {"command": "=HYPERLINK(\"http://evil\")"}, "ok", False),
        ("Read", {"file_path": "/home/someone/private/notes.txt"}, "text", False),
        ("Bash", {"command": "make zz9"}, ERROR_TEXT, True),
    ])


def _run(*args):
    return CliRunner().invoke(cli, ["tools", *args])


def _check_activity(log: Path) -> int:
    """The non-usage action count `check` sees for *log*."""
    buffer = ActionBuffer()
    create_registry(mode="health").scan(parse_file(log), buffer)
    return buffer.activity_len


@pytest.fixture
def codex_log(tmp_path):
    p = tmp_path / "rollout.jsonl"
    _write_jsonl(p, CODEX_FIXTURE_LINES)
    return p


@pytest.fixture
def aider_log(tmp_path):
    p = tmp_path / ".aider.chat.history.md"
    p.write_text(SEARCH_REPLACE_MD, encoding="utf-8")
    return p


@pytest.mark.parametrize("name, calls, failed", [
    ("claude", 10, 6), ("codex", 3, 0), ("aider", 4, 1),
])
def test_counts_match_check(name, calls, failed, codex_log, aider_log):
    log = {"claude": FIXTURES / "claude_error_spiral.jsonl", "codex": codex_log,
           "aider": aider_log}[name]
    r = _run("--log", str(log), "--json")
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert data["schema"] == 1
    assert "calls" not in data
    assert data["session"]["calls"] == calls == _check_activity(log)
    assert data["session"]["failed"] == failed
    assert sum(t["calls"] for t in data["tools"]) == calls
    assert sum(t["failed"] for t in data["tools"]) == failed


def test_codex_skips_usage_record(codex_log):
    data = json.loads(_run("--log", str(codex_log), "--json").output)
    assert [(t["tool"], t["calls"]) for t in data["tools"]] == [("shell", 2), ("apply_patch", 1)]


def test_claude_table(secret_log):
    r = _run("--log", str(secret_log))
    assert r.exit_code == 0, r.output
    lines = r.output.splitlines()
    bash = next(line for line in lines if line.lstrip().startswith("Bash"))
    assert bash.split()[1:5] == ["3", "1", "33%", "other"]
    assert "Total: 4 calls, 1 failed" in r.output


def test_claude_durations_from_results(secret_log):
    data = json.loads(_run("--log", str(secret_log), "--json").output)
    bash = next(t for t in data["tools"] if t["tool"] == "Bash")
    assert bash["total_ms"] == 3000 and bash["median_ms"] == 1000


def test_no_durations_is_dash(aider_log):
    r = _run("--log", str(aider_log))
    row = next(line for line in r.output.splitlines() if line.lstrip().startswith("aider_edit"))
    assert row.split()[-2:] == ["-", "-"]
    data = json.loads(_run("--log", str(aider_log), "--json").output)
    assert all(t["total_ms"] is None and t["median_ms"] is None for t in data["tools"])


def test_calls_list(secret_log):
    data = json.loads(_run("--log", str(secret_log), "--json", "--calls").output)
    calls = data["calls"]
    assert [c["tool"] for c in calls] == ["Bash", "Bash", "Read", "Bash"]
    assert calls[2]["target"] == "notes.txt"  # file name only, never the path
    assert calls[3] == {**calls[3], "ok": False, "error_kind": "other", "target": "make zz9"}
    assert calls[0]["ok"] and calls[0]["error_kind"] is None
    assert all(len(c["target"]) <= 80 for c in calls)


@pytest.mark.parametrize("fmt", [
    ["--calls"], ["--json", "--calls"], ["--format", "csv", "--calls"],
])
def test_secret_and_error_text_never_shown(secret_log, fmt):
    r = _run("--log", str(secret_log), *fmt)
    assert r.exit_code == 0, r.output
    assert SECRET not in r.output and SECRET[-12:] not in r.output
    assert "zz9-unique" not in r.output  # the error text: only its kind
    assert "/home/someone" not in r.output
    assert "Bearer" in r.output  # the command is there, redacted


def test_csv_injection_guard(secret_log):
    r = _run("--log", str(secret_log), "--format", "csv", "--calls")
    rows = list(csv.reader(io.StringIO(r.output)))
    assert rows[0] == ["table", "rank", "name", "metric", "value"]
    values = [row[4] for row in rows[1:]]
    assert "'=HYPERLINK(\"http://evil\")" in values
    assert not any(v.startswith("=") for v in values)


def test_long_target_cut(tmp_path):
    log = _cc_log(tmp_path / "l.jsonl", [("Bash", {"command": "echo " + "x" * 300}, "ok", False)])
    data = json.loads(_run("--log", str(log), "--json", "--calls").output)
    assert len(data["calls"][0]["target"]) == 80
    r = _run("--log", str(log), "--calls")
    assert "x" * 81 not in r.output


def test_json_with_csv_is_usage_error(secret_log):
    r = _run("--log", str(secret_log), "--json", "--format", "csv")
    assert r.exit_code == 2
    assert "conflict" in r.output


def test_format_json_same_as_json(secret_log):
    assert _run("--log", str(secret_log), "--format", "json").output == \
        _run("--log", str(secret_log), "--json").output


def test_empty_log(tmp_path):
    p = tmp_path / "e.jsonl"
    p.write_text("", encoding="utf-8")
    assert _run("--log", str(p)).exit_code == 1
