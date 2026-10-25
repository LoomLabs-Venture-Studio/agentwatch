"""#35: one-shot check/security-scan cover the whole session, not its tail."""

import json

from click.testing import CliRunner

from agentwatch.cli import cli

TOKEN = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"


def _write_log(path, n=30, leak_at=2):
    lines = []
    for i in range(n):
        cmd = f"git push https://{TOKEN}@github.com/o/r" if i == leak_at else f"ls dir{i}"
        lines.append({
            "type": "assistant", "sessionId": "s1",
            "timestamp": f"2026-01-01T12:00:{i:02d}Z",
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": f"t{i}", "name": "Bash", "input": {"command": cmd}}]},
        })
    path.write_text("\n".join(json.dumps(e) for e in lines) + "\n", encoding="utf-8")


def _signals(args):
    out = CliRunner().invoke(cli, args).stdout
    return [w["signal"] for w in json.loads(out)["warnings"]]


def test_secret_early_in_session_is_found(tmp_path):
    """QA repro: a token in action 3 of a session used to be missed once the
    session ran past the detectors' last-N window."""
    log = tmp_path / "s1.jsonl"
    _write_log(log)
    assert _signals(["security-scan", "--log", str(log), "--json"]).count("secret_leak") == 1
    assert "secret_leak" in _signals(["check", "--security", "--log", str(log), "--json"])
