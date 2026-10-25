"""#40: `check` reports efficiency (JSON and plain text)."""

import json
from datetime import datetime, timedelta

from click.testing import CliRunner

from agentwatch.cli import cli
from agentwatch.health.score import EfficiencyReport

T0 = datetime(2026, 1, 1, 12, 0, 0)


def _write_log(path) -> None:
    lines = [
        {
            "type": "assistant",
            "sessionId": "s1",
            "timestamp": (T0 + timedelta(minutes=m)).isoformat() + "Z",
            "message": {
                "role": "assistant",
                "content": [{"type": "tool_use", "id": f"t{m}", "name": "Read",
                             "input": {"file_path": f"f{m}.py"}}],
                "usage": {"input_tokens": 2000, "output_tokens": 1000},
            },
        }
        for m in range(11)
    ]
    path.write_text("\n".join(json.dumps(e) for e in lines) + "\n", encoding="utf-8")


def test_check_json_has_efficiency(tmp_path):
    log = tmp_path / "s1.jsonl"
    _write_log(log)
    result = CliRunner().invoke(cli, ["check", "--log", str(log), "--json"])
    eff = json.loads(result.stdout)["efficiency"]
    assert set(eff) == set(EfficiencyReport.__dataclass_fields__)
    assert eff["duration_minutes"] == 10.0
    assert eff["token_burn_rate"] == 3300.0  # 33K fresh tokens / 10 min


def test_check_text_shows_efficiency_score(tmp_path):
    log = tmp_path / "s1.jsonl"
    _write_log(log)
    result = CliRunner().invoke(cli, ["check", "--log", str(log)])
    assert "Efficiency:" in result.output
