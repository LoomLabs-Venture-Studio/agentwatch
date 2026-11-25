"""scripts/fp_corpus.py stays in step with the scanner it measures."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "security_benign.jsonl"


def _load():
    spec = importlib.util.spec_from_file_location("fp_corpus", ROOT / "scripts" / "fp_corpus.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_scan_log_matches_security_scan_and_names_rules():
    fc = _load()
    res = fc.scan_log(str(FIXTURE), examples=1)
    assert res["exit"] == "2"
    rules = {(f["signal"], f["rule"]) for f in res["findings"]}
    assert ("privilege_escalation", r"chmod\s+[0-7]*[4567][0-7]*") in rules
    assert ("secret_leak", "aws_access_key@file_write") in rules
    assert ("credential_access", "token") in rules
    assert all(f["rule"] != "?" for f in res["findings"])
    # evidence is one redacted line: the example key never appears in full
    assert not any("AKIAIOSFODNN7EXAMPLE" in f["evidence"] for f in res["findings"])


def test_summarize_counts_sessions_and_exit_codes():
    fc = _load()
    res = fc.scan_log(str(FIXTURE), examples=0)
    res["subagent"] = False
    clean = {"exit": "0", "findings": [], "subagent": True}
    out = fc.summarize([res, clean], examples=0)
    assert out["exit_distribution"]["all"] == {"0": 1, "1": 0, "2": 1, "3": 0, "error": 0}
    assert out["worst_severity"]["main"]["critical"] == 1
    assert out["worst_severity"]["subagent"]["none"] == 1
    row = next(r for r in out["signals"] if r["signal"] == "mass_delete")
    assert row["severity"]["high"] == 1 and row["sessions"] == 1
    assert "examples" not in row
