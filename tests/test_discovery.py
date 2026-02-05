"""Tests for process discovery tree-building, PPID chain walking, and team grouping."""

from pathlib import Path

from agentwatch.discovery import (
    AgentProcess,
    AgentTeam,
    _walk_to_ancestor_agent,
    _compute_depths,
    _assign_team_ids,
    build_agent_tree,
    build_teams,
)


def _make_agent(pid: int, parent_pid: int | None = None, **kwargs) -> AgentProcess:
    return AgentProcess(
        pid=pid,
        agent_type=kwargs.get("agent_type", "claude-code"),
        working_directory=Path(kwargs.get("cwd", "/tmp/project")),
        parent_pid=parent_pid,
    )


# ---------------------------------------------------------------------------
# _walk_to_ancestor_agent
# ---------------------------------------------------------------------------


class TestWalkToAncestorAgent:
    def test_direct_parent(self):
        """Agent B's OS parent is Agent A."""
        pid_to_ppid = {100: 1, 200: 100}
        agent_pids = {100, 200}
        assert _walk_to_ancestor_agent(200, pid_to_ppid, agent_pids) == 100

    def test_intermediate_processes(self):
        """Agent B -> shell -> node -> Agent A."""
        pid_to_ppid = {100: 1, 150: 100, 160: 150, 200: 160}
        agent_pids = {100, 200}
        assert _walk_to_ancestor_agent(200, pid_to_ppid, agent_pids) == 100

    def test_no_ancestor_agent(self):
        """Agent with no agent ancestors returns None."""
        pid_to_ppid = {100: 1, 200: 1}
        agent_pids = {100, 200}
        assert _walk_to_ancestor_agent(100, pid_to_ppid, agent_pids) is None
        assert _walk_to_ancestor_agent(200, pid_to_ppid, agent_pids) is None

    def test_pid_not_in_map(self):
        """PID not in pid_to_ppid map returns None."""
        assert _walk_to_ancestor_agent(999, {}, {100}) is None

    def test_max_hops_guard(self):
        """Should stop after max_hops to avoid infinite loops."""
        # Long chain: 1 -> 2 -> 3 -> ... -> 10 -> agent 100
        pid_to_ppid = {i: i + 1 for i in range(1, 11)}
        pid_to_ppid[10] = 100
        pid_to_ppid[100] = 0
        agent_pids = {1, 100}
        # With max_hops=3, should not reach agent 100
        assert _walk_to_ancestor_agent(1, pid_to_ppid, agent_pids, max_hops=3) is None

    def test_nested_subagents(self):
        """A -> B -> C: C should find B, not A."""
        pid_to_ppid = {100: 1, 200: 100, 300: 200}
        agent_pids = {100, 200, 300}
        assert _walk_to_ancestor_agent(300, pid_to_ppid, agent_pids) == 200
        assert _walk_to_ancestor_agent(200, pid_to_ppid, agent_pids) == 100
        assert _walk_to_ancestor_agent(100, pid_to_ppid, agent_pids) is None


# ---------------------------------------------------------------------------
# _compute_depths
# ---------------------------------------------------------------------------


class TestComputeDepths:
    def test_all_roots(self):
        """Agents with no parent_agent_pid get depth 0."""
        agents = [_make_agent(100), _make_agent(200)]
        _compute_depths(agents)
        assert agents[0].depth == 0
        assert agents[1].depth == 0

    def test_nested(self):
        """A -> B -> C gets depths 0, 1, 2."""
        a = _make_agent(100)
        b = _make_agent(200)
        b.parent_agent_pid = 100
        c = _make_agent(300)
        c.parent_agent_pid = 200
        agents = [a, b, c]
        _compute_depths(agents)
        assert a.depth == 0
        assert b.depth == 1
        assert c.depth == 2

    def test_orphaned_promoted_to_root(self):
        """Agent whose parent_agent_pid is not in the list becomes root."""
        a = _make_agent(200)
        a.parent_agent_pid = 999  # non-existent parent
        agents = [a]
        _compute_depths(agents)
        assert a.depth == 0
        assert a.parent_agent_pid is None

    def test_multiple_children(self):
        """Parent with multiple children all get depth 1."""
        parent = _make_agent(100)
        child1 = _make_agent(200)
        child1.parent_agent_pid = 100
        child2 = _make_agent(300)
        child2.parent_agent_pid = 100
        agents = [parent, child1, child2]
        _compute_depths(agents)
        assert parent.depth == 0
        assert child1.depth == 1
        assert child2.depth == 1


# ---------------------------------------------------------------------------
# build_agent_tree
# ---------------------------------------------------------------------------


class TestBuildAgentTree:
    def test_flat_agents_sorted_by_pid(self):
        """Root agents should be sorted by PID."""
        agents = [_make_agent(300), _make_agent(100), _make_agent(200)]
        result = build_agent_tree(agents)
        assert [a.pid for a in result] == [100, 200, 300]

    def test_parent_before_children(self):
        """Parent appears before its children."""
        parent = _make_agent(100)
        child = _make_agent(200)
        child.parent_agent_pid = 100
        agents = [child, parent]  # reversed input
        result = build_agent_tree(agents)
        assert [a.pid for a in result] == [100, 200]

    def test_nested_tree_order(self):
        """A -> B -> C, plus D (root): order is A, B, C, D."""
        a = _make_agent(100)
        b = _make_agent(200)
        b.parent_agent_pid = 100
        c = _make_agent(300)
        c.parent_agent_pid = 200
        d = _make_agent(400)
        agents = [d, c, b, a]  # scrambled input
        result = build_agent_tree(agents)
        assert [ag.pid for ag in result] == [100, 200, 300, 400]

    def test_siblings_sorted_by_pid(self):
        """Children of the same parent are sorted by PID."""
        parent = _make_agent(100)
        child_b = _make_agent(300)
        child_b.parent_agent_pid = 100
        child_a = _make_agent(200)
        child_a.parent_agent_pid = 100
        agents = [child_b, parent, child_a]
        result = build_agent_tree(agents)
        assert [a.pid for a in result] == [100, 200, 300]

    def test_empty_list(self):
        """Empty input returns empty output."""
        assert build_agent_tree([]) == []

    def test_does_not_mutate_input(self):
        """build_agent_tree should not mutate the input list."""
        agents = [_make_agent(200), _make_agent(100)]
        original_order = [a.pid for a in agents]
        build_agent_tree(agents)
        assert [a.pid for a in agents] == original_order


# ---------------------------------------------------------------------------
# _assign_team_ids
# ---------------------------------------------------------------------------


class TestAssignTeamIds:
    def test_root_agents_get_own_pid(self):
        """Root agents (depth=0) get their own PID as team_id."""
        a = _make_agent(100)
        b = _make_agent(200)
        _compute_depths([a, b])
        _assign_team_ids([a, b])
        assert a.team_id == 100
        assert b.team_id == 200

    def test_subagent_gets_root_team_id(self):
        """Sub-agent gets team_id of its root ancestor."""
        root = _make_agent(100)
        child = _make_agent(200)
        child.parent_agent_pid = 100
        _compute_depths([root, child])
        _assign_team_ids([root, child])
        assert root.team_id == 100
        assert child.team_id == 100

    def test_nested_chain_all_share_root_team(self):
        """A -> B -> C: all share team_id of A."""
        a = _make_agent(100)
        b = _make_agent(200)
        b.parent_agent_pid = 100
        c = _make_agent(300)
        c.parent_agent_pid = 200
        _compute_depths([a, b, c])
        _assign_team_ids([a, b, c])
        assert a.team_id == 100
        assert b.team_id == 100
        assert c.team_id == 100

    def test_separate_trees_different_teams(self):
        """Two independent trees get different team_ids."""
        root1 = _make_agent(100)
        child1 = _make_agent(200)
        child1.parent_agent_pid = 100
        root2 = _make_agent(300)
        child2 = _make_agent(400)
        child2.parent_agent_pid = 300
        agents = [root1, child1, root2, child2]
        _compute_depths(agents)
        _assign_team_ids(agents)
        assert root1.team_id == 100
        assert child1.team_id == 100
        assert root2.team_id == 300
        assert child2.team_id == 300

    def test_orphaned_agent_is_own_team(self):
        """Agent with missing parent becomes its own team."""
        a = _make_agent(200)
        a.parent_agent_pid = 999
        _compute_depths([a])  # promotes to root
        _assign_team_ids([a])
        assert a.team_id == 200


# ---------------------------------------------------------------------------
# build_teams
# ---------------------------------------------------------------------------


class TestBuildTeams:
    def test_solo_agent_forms_team(self):
        """A single agent forms a single-member team."""
        a = _make_agent(100)
        _compute_depths([a])
        teams = build_teams([a])
        assert len(teams) == 1
        assert teams[0].team_id == 100
        assert teams[0].member_count == 1
        assert teams[0].subagent_count == 0

    def test_parent_child_one_team(self):
        """Parent + child = one team with 2 members."""
        root = _make_agent(100)
        child = _make_agent(200)
        child.parent_agent_pid = 100
        _compute_depths([root, child])
        teams = build_teams([root, child])
        assert len(teams) == 1
        assert teams[0].team_id == 100
        assert teams[0].member_count == 2
        assert teams[0].subagent_count == 1
        assert teams[0].root.pid == 100

    def test_two_independent_trees_two_teams(self):
        """Two independent agent trees = two teams."""
        a = _make_agent(100)
        b = _make_agent(200)
        b.parent_agent_pid = 100
        c = _make_agent(300)
        _compute_depths([a, b, c])
        teams = build_teams([a, b, c])
        assert len(teams) == 2
        team_ids = [t.team_id for t in teams]
        assert 100 in team_ids
        assert 300 in team_ids

    def test_team_members_in_tree_order(self):
        """Members within a team are sorted in tree order."""
        root = _make_agent(100)
        c1 = _make_agent(300)
        c1.parent_agent_pid = 100
        c2 = _make_agent(200)
        c2.parent_agent_pid = 100
        _compute_depths([root, c1, c2])
        teams = build_teams([root, c1, c2])
        assert len(teams) == 1
        pids = [m.pid for m in teams[0].members]
        assert pids == [100, 200, 300]  # tree order: root, then siblings by PID

    def test_team_name(self):
        """Team name is derived from root agent."""
        root = _make_agent(100)
        _compute_depths([root])
        teams = build_teams([root])
        assert teams[0].name == "claude-code:project"

    def test_max_depth(self):
        """max_depth reflects the deepest member."""
        root = _make_agent(100)
        child = _make_agent(200)
        child.parent_agent_pid = 100
        grandchild = _make_agent(300)
        grandchild.parent_agent_pid = 200
        _compute_depths([root, child, grandchild])
        teams = build_teams([root, child, grandchild])
        assert teams[0].max_depth == 2

    def test_empty_list(self):
        """Empty input returns empty teams."""
        assert build_teams([]) == []

    def test_teams_sorted_by_root_pid(self):
        """Teams are sorted by root PID."""
        a = _make_agent(300)
        b = _make_agent(100)
        _compute_depths([a, b])
        teams = build_teams([a, b])
        assert [t.team_id for t in teams] == [100, 300]


# ---------------------------------------------------------------------------
# AgentProcess properties
# ---------------------------------------------------------------------------


class TestAgentProcessProperties:
    def test_is_root(self):
        a = _make_agent(100)
        assert a.is_root is True

    def test_is_subagent(self):
        a = _make_agent(100)
        a.depth = 1
        assert a.is_subagent is True
        assert a.is_root is False
