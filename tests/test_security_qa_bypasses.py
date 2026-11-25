"""Sprint 50 adversarial QA: 258 attack inputs pinned at develop's severity.

Each case (tests/_qa_bypass_cases.py, QA's generator) runs through the full
security registry exactly as QA's harness did: 12 `git status` actions,
then the case's actions. tests/fixtures/qa_bypass_expected.json records,
per case and finding key (fingerprint removed: it is per machine), the
severities develop gave and the ones this branch must give. They differ
only where the case carries an `accepted` reason (an intended safe shape,
for example a heredoc into notes.md); everything else must equal develop.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from _qa_bypass_cases import build

from agentwatch.detectors.base import warning_dedup_key
from agentwatch.detectors.registry import create_registry
from agentwatch.parser.models import Action, ActionBuffer, ToolType

EXPECTED = json.loads(
    (Path(__file__).parent / "fixtures" / "qa_bypass_expected.json").read_text("utf-8")
)
CASES = build()
_FP = re.compile(r"\|fingerprint=[0-9a-f]+")
_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _action(i: int, d: dict) -> Action:
    d = dict(d)
    tool_type = ToolType[d.pop("tool_type", "BASH")] if d.get("tool_type") != "WEB" else (
        d.pop("tool_type") and ToolType.BROWSER
    )
    d.setdefault("tool_name", "Bash")
    d.setdefault("success", True)
    return Action(timestamp=_T0 + timedelta(seconds=i), tool_type=tool_type, **d)


def _scan(actions: list[dict]) -> dict[str, list[str]]:
    acts = [{"command": "git status"}] * 12 + actions
    warnings = create_registry(mode="security").scan(
        [_action(i, a) for i, a in enumerate(acts)], ActionBuffer()
    )
    out: dict[str, list[str]] = {}
    for w in {(warning_dedup_key(w), w.severity.value) for w in warnings}:
        out.setdefault(_FP.sub("", w[0]), []).append(w[1])
    return {k: sorted(v) for k, v in out.items()}


def test_every_case_has_an_expectation():
    assert set(CASES) == set(EXPECTED)
    assert len(CASES) == 258


def test_expectations_never_above_develop_and_lowered_only_when_accepted():
    for name, e in EXPECTED.items():
        assert set(e["develop"]) == set(e["expected"]), name
        for key, devs in e["develop"].items():
            mine = e["expected"][key]
            assert all(_RANK[m] <= _RANK[d] for m, d in zip(mine, devs)), name
            if mine != devs:
                assert e["accepted"], f"{name}: lowered without an accepted reason"


@pytest.mark.parametrize("name", sorted(CASES), ids=lambda n: n.split(":", 1)[0])
def test_qa_case(name):
    assert _scan(CASES[name]) == EXPECTED[name]["expected"]
