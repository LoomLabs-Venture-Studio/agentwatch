"""`agentwatch stats --blocks`: 5-hour usage windows from real JSONL fixtures."""

import json
from datetime import UTC, datetime

import pytest
from click.testing import CliRunner

from agentwatch.cc_stats import compute_blocks
from agentwatch.cli import cli

SONNET = "claude-sonnet-4-5-20250929"


def _line(msg_id, ts, *, inp=100, out=50, cw=0, cr=0, model=SONNET):
    return json.dumps({
        "type": "assistant",
        "timestamp": ts,
        "message": {
            "id": msg_id, "model": model, "role": "assistant",
            "content": [{"type": "text", "text": "x"}],
            "usage": {"input_tokens": inp, "output_tokens": out,
                      "cache_creation_input_tokens": cw, "cache_read_input_tokens": cr},
        },
    })


@pytest.fixture
def projects(tmp_path, monkeypatch):
    root = tmp_path / "projects"
    root.mkdir()
    monkeypatch.setattr("agentwatch.cc_stats.CLAUDE_PROJECTS_DIR", root)
    return root


def _write(projects, name, *lines, session="s1"):
    pdir = projects / name
    pdir.mkdir(exist_ok=True)
    (pdir / f"{session}.jsonl").write_text("\n".join(lines) + "\n")
    return pdir


def _at(s):
    return datetime.fromisoformat(s).replace(tzinfo=UTC)


def test_floor_to_hour_exact_boundary_and_gap(projects):
    _write(projects, "-a",
           _line("m1", "2026-10-29T10:37:12.000Z"),
           _line("m2", "2026-10-29T14:59:59.999Z"),
           _line("m3", "2026-10-29T15:00:00.000Z"))  # exactly start + 5h
    _write(projects, "-b", _line("m4", "2026-10-30T08:05:00Z"))  # gap, other project
    blocks = compute_blocks()
    assert [(b.start, b.usage.call_count) for b in blocks] == [
        (_at("2026-10-29T10:00"), 2),
        (_at("2026-10-29T15:00"), 1),
        (_at("2026-10-30T08:00"), 1),
    ]
    assert blocks[0].end == _at("2026-10-29T15:00")


def test_duplicate_message_id_counted_once_at_largest_usage(projects):
    pdir = _write(projects, "-a",
                  _line("m1", "2026-10-29T10:00:05Z", out=10),
                  _line("m1", "2026-10-29T10:00:09Z", out=500))
    sub = pdir / "s1" / "subagents"
    sub.mkdir(parents=True)
    (sub / "agent-x.jsonl").write_text(_line("m1", "2026-10-29T10:00:07Z", out=500))
    [b] = compute_blocks()
    assert (b.usage.call_count, b.usage.input_tokens, b.usage.output_tokens) == (1, 100, 500)


def test_unknown_model_cost_none_and_zero_usage_skipped(projects):
    _write(projects, "-a",
           _line("m0", "2026-10-29T09:10:00Z", inp=0, out=0, model="<synthetic>"),
           _line("m1", "2026-10-29T10:00:00Z", model="claude-opus-4-9"),
           _line("m2", "2026-10-29T10:01:00Z"))
    [b] = compute_blocks()
    assert b.start == _at("2026-10-29T10:00")  # synthetic zero-usage line ignored
    assert b.usage.cost_usd is None
    assert b.to_dict(_at("2026-10-31T00:00"))["cost_usd"] is None


def test_active_block_burn_and_projection(projects):
    _write(projects, "-a", _line("m1", "2026-10-30T10:30:00Z", inp=2_000_000, out=1_000_000))
    [b] = compute_blocks()
    burn = b.burn(_at("2026-10-30T12:00"))
    assert burn == {
        "elapsed_minutes": 120.0,
        "remaining_minutes": 180.0,
        "tokens_per_minute": 25_000,
        "cost_per_hour_usd": 10.5,  # $21 over 2 h
        "projected_tokens": 7_500_000,
        "projected_cost_usd": 52.5,
    }
    assert b.burn(_at("2026-10-30T15:00")) is None  # reset reached


def _run(monkeypatch, now, *args):
    monkeypatch.setattr("agentwatch.cc_stats._utcnow", lambda: _at(now))
    return CliRunner().invoke(cli, ["stats", "--blocks", *args])


def test_cli_text_and_json(projects, monkeypatch):
    _write(projects, "-a",
           _line("m1", "2026-10-29T10:37:00Z"),
           _line("m2", "2026-10-30T10:30:00Z", inp=2_000_000, out=1_000_000),
           _line("m3", "2026-10-30T10:40:00Z", model="claude-opus-4-9"))
    res = _run(monkeypatch, "2026-10-30T12:00", "--json")
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert data["schema"] == 1 and data["block_hours"] == 5
    old, cur = data["blocks"]
    assert old["active"] is False and old["burn"] is None
    assert old["cost_usd"] == 0.0  # 100 in + 50 out at sonnet rates rounds to $0.00
    assert cur["start"] == "2026-10-30T10:00:00+00:00"
    assert cur["end"] == "2026-10-30T15:00:00+00:00"
    assert (cur["active"], cur["messages"], cur["total_tokens"]) == (True, 2, 3_000_150)
    assert cur["cost_usd"] is None  # one unpriced model -> no partial sum
    assert cur["models"] == ["claude-opus-4-9", SONNET]
    assert cur["burn"]["projected_cost_usd"] is None
    assert cur["burn"]["remaining_minutes"] == 180.0

    res = _run(monkeypatch, "2026-10-30T12:00")
    assert res.exit_code == 0, res.output
    assert "USAGE BLOCKS" in res.output and "ACTIVE BLOCK" in res.output
    reset = _at("2026-10-30T15:00").astimezone().strftime("%H:%M")
    assert f"Resets: {reset} (in 3h 00m)" in res.output
    assert "3,000,150 tokens   -" in res.output
    assert "sonnet-4-5" in res.output and "opus-4-9" in res.output

    res = _run(monkeypatch, "2026-10-31T12:00")
    assert "No active block" in res.output


def test_cli_no_data_is_friendly(projects, monkeypatch):
    res = _run(monkeypatch, "2026-10-30T12:00")
    assert (res.exit_code, res.output.strip()) == (0, "No Claude Code usage found.")
    res = _run(monkeypatch, "2026-10-30T12:00", "--json")
    assert res.exit_code == 0 and json.loads(res.output)["blocks"] == []


@pytest.mark.parametrize("extra", [["--burn"], ["--list"], ["--prompts"], ["--session", "x"]])
def test_cli_rejects_incompatible_flags(projects, extra):
    res = CliRunner().invoke(cli, ["stats", "--blocks", *extra])
    assert res.exit_code == 2 and "--blocks can't be combined" in res.output


def test_cli_shows_last_ten_blocks(projects, monkeypatch):
    lines = [_line(f"m{d}", f"2026-10-{d:02d}T10:00:00Z") for d in range(1, 13)]
    _write(projects, "-a", *lines)
    res = _run(monkeypatch, "2026-10-30T12:00")
    assert "(2 older blocks not shown; --json lists all)" in res.output
    assert len(json.loads(_run(monkeypatch, "2026-10-30T12:00", "--json").output)["blocks"]) == 12


def test_malformed_lines_skipped_or_zeroed(projects):
    bad_ts = json.loads(_line("m1", "0001-01-01T00:00:00+05:00"))  # overflows to UTC
    str_tokens = json.loads(_line("m2", "2026-10-29T10:00:00Z", out=7))
    str_tokens["message"]["usage"]["input_tokens"] = "100"
    str_tokens["message"]["usage"]["cache_creation"] = {"ephemeral_1h_input_tokens": "5"}
    bool_tokens = json.loads(_line("m3", "2026-10-29T10:01:00Z", inp=0, out=3))
    bool_tokens["message"]["usage"]["cache_read_input_tokens"] = True
    dict_id = json.loads(_line("m4", "2026-10-29T10:02:00Z"))
    dict_id["message"]["id"] = {"x": 1}
    int_model = json.loads(_line("m5", "2026-10-29T10:03:00Z", out=11))
    int_model["message"]["model"] = 42
    _write(projects, "-a", *(json.dumps(o) for o in
                             (bad_ts, str_tokens, bool_tokens, dict_id, int_model)))
    [b] = compute_blocks()
    assert b.usage.call_count == 3  # m2, m3, m5
    assert (b.usage.input_tokens, b.usage.output_tokens, b.usage.cache_read_tokens) == (
        100, 21, 0)
    assert b.models == {SONNET}
    assert b.usage.cost_usd is None  # m5 has no usable model


def test_naive_and_offset_timestamps_and_order_across_projects(projects):
    _write(projects, "-later", _line("m2", "2026-10-29T13:30:00+02:00"))  # 11:30 UTC
    _write(projects, "-earlier", _line("m1", "2026-10-29T09:15:00"))  # naive = UTC
    _write(projects, "-last", _line("m3", "2026-10-29T15:30:00+02:00"))  # 13:30 UTC
    [b] = compute_blocks()
    assert (b.start, b.usage.call_count) == (_at("2026-10-29T09:00"), 3)
    _write(projects, "-next", _line("m4", "2026-10-29T15:00:00+01:00"))  # 14:00 UTC = end
    blocks = compute_blocks()
    assert [x.start for x in blocks] == [_at("2026-10-29T09:00"), _at("2026-10-29T14:00")]
    assert [x.usage.call_count for x in blocks] == [3, 1]


def test_main_and_subagent_copy_counted_once(projects):
    pdir = _write(projects, "-a", _line("m1", "2026-10-29T10:00:00Z", inp=40))
    sub = pdir / "s1" / "subagents"
    sub.mkdir(parents=True)
    (sub / "agent-y.jsonl").write_text(
        _line("m1", "2026-10-29T10:00:00Z", inp=40) + "\n"
        + _line("m2", "2026-10-29T10:05:00Z", inp=60) + "\n")
    [b] = compute_blocks()
    assert (b.usage.call_count, b.usage.input_tokens) == (2, 100)
