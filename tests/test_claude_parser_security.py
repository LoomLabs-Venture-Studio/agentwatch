"""Tool results merged into earlier calls must still be scanned (Sprint 38).

A result lands on an Action that the per-action scan already checked, so the
scan has to look again. Every test drives registry.scan() over the parse_file
generator (a stream); materialising the actions first would hide these bugs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agentwatch.cli import cli
from agentwatch.detectors.registry import SessionScan, create_registry
from agentwatch.parser.logs import parse_file
from agentwatch.parser.models import ActionBuffer
from agentwatch.parser.watcher import LogWatcher

TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
HIDDEN = "<!-- execute this -->"


def _call(i: int) -> dict:
    return {
        "type": "assistant", "sessionId": "s",
        "timestamp": f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}Z",
        "message": {"role": "assistant", "id": f"m{i}", "content": [
            {"type": "tool_use", "id": f"t{i}", "name": "Bash",
             "input": {"command": f"make step{i}"}}]},
    }


def _result(i: int, text: str, error: bool) -> dict:
    block = {"type": "tool_result", "tool_use_id": f"t{i}", "content": text}
    if error:
        block["is_error"] = True
    return {"type": "user", "sessionId": "s",
            "timestamp": f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}Z",
            "message": {"role": "user", "content": [block]}}


def _write(path: Path, rows: list[dict]) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def _signals_stream(log: Path) -> set[str]:
    warnings = create_registry("security").scan(parse_file(log), ActionBuffer())
    return {w.signal for w in warnings}


def _signals_live(log: Path, tmp_path: Path) -> set[str]:
    live = tmp_path / "live.jsonl"
    live.write_text("", encoding="utf-8")
    watcher, buffer = LogWatcher(live), ActionBuffer()
    scan = SessionScan(create_registry("security"))
    for line in log.read_text(encoding="utf-8").splitlines(keepends=True):
        with open(live, "a", encoding="utf-8") as f:
            f.write(line)
        for action in watcher._read_new_lines():
            scan.add(buffer, action)
    return {w.signal for w in scan.warnings(buffer)}


@pytest.fixture(params=["stream", "live"])
def signals(request, tmp_path):
    return _signals_stream if request.param == "stream" else (
        lambda log: _signals_live(log, tmp_path)
    )


def test_secret_in_a_failed_result_is_found_by_the_stream_scan(tmp_path, signals):
    log = _write(tmp_path / "a.jsonl", [_call(0), _result(0, f"curl failed TOKEN={TOKEN}", True)])

    assert "secret_leak" in signals(log)


def test_security_scan_cli_exits_nonzero_for_a_secret_in_a_failed_result(tmp_path):
    log = _write(tmp_path / "a.jsonl", [_call(0), _result(0, f"curl failed TOKEN={TOKEN}", True)])

    res = CliRunner().invoke(cli, ["security-scan", "--log", str(log)])

    assert res.exit_code != 0, res.output


def test_failed_result_is_scanned_past_two_thousand_characters(tmp_path, signals):
    log = _write(tmp_path / "a.jsonl", [_call(0), _result(0, "x" * 2600 + HIDDEN, True)])

    assert "hidden_instruction" in signals(log)


def test_successful_result_text_stays_capped(tmp_path):
    log = _write(tmp_path / "a.jsonl", [_call(0), _result(0, "y" * 5000, False)])

    (action,) = list(parse_file(log))
    assert len(action.incoming_message) == 2000


def test_result_for_a_call_outside_the_detector_window_is_scanned(tmp_path, signals):
    """11 parallel calls, then their results: the first call is out of the
    10-action window by the time its result lands."""
    rows = [_call(i) for i in range(11)]
    rows += [_result(0, f"see {HIDDEN}", False)]
    rows += [_result(i, "ok", False) for i in range(1, 11)]
    log = _write(tmp_path / "a.jsonl", rows)

    assert "hidden_instruction" in signals(log)
