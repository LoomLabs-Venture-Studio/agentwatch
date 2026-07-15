"""Tests for Sprint 14 item 3: `Action.user_id` removal.

Board asked for an independently-verified safety check before removal
(repo-wide grep + serialization-round-trip check), not a blind delete. The
engineer's grep (separate from the CTO's own, see PR body) confirmed zero
readers/writers of `Action.user_id` beyond the declaration line itself
across `src/`, `tests/`, and `scripts/`, and that `Action` has no
`to_dict()`/serialization round-trip that could reference it implicitly.
This test file locks in the resulting removal so it can't silently
regress back in without a deliberate decision.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime

import pytest

from agentwatch.parser.models import Action, ToolType


class TestActionUserIdRemoved:
    def test_action_has_no_user_id_field(self):
        field_names = {f.name for f in dataclasses.fields(Action)}
        assert "user_id" not in field_names

    def test_action_construction_still_works_without_user_id(self):
        # Sanity: removing the field doesn't break normal construction /
        # any of the other security-relevant fields it sat alongside.
        action = Action(
            timestamp=datetime(2026, 1, 1, 12, 0),
            tool_name="Read",
            tool_type=ToolType.READ,
            success=True,
            incoming_message="hi",
            outgoing_data="hello back",
            network_host="example.com",
            network_port=443,
            skill_name="my-skill",
        )
        assert action.tool_name == "Read"
        assert not hasattr(action, "user_id")

    def test_passing_user_id_kwarg_raises(self):
        """Confirms this isn't just hidden/defaulted somewhere -- passing it
        explicitly must fail, proving the field is genuinely gone."""
        with pytest.raises(TypeError):
            Action(
                timestamp=datetime(2026, 1, 1, 12, 0),
                tool_name="Read",
                tool_type=ToolType.READ,
                success=True,
                user_id="someone",
            )
