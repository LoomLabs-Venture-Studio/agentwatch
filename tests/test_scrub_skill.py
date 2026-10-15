"""The agentwatch-scrub Claude Code skill file (spec AC12, static part)."""

from __future__ import annotations

from pathlib import Path

SKILL = Path(__file__).resolve().parents[1] / "skills" / "agentwatch-scrub" / "SKILL.md"


def test_skill_frontmatter_and_length():
    lines = SKILL.read_text(encoding="utf-8").splitlines()
    assert len(lines) < 150
    assert lines[0] == "---"
    end = lines.index("---", 1)
    meta = dict(line.split(":", 1) for line in lines[1:end])
    assert meta["name"].strip() == "agentwatch-scrub"
    assert meta["description"].strip()
