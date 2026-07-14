"""Tests for `agentwatch.cursor_discovery`.

Covers the process gate (`is_cursor_running`), workspace-path resolution
(`build_workspace_map`/`_file_uri_to_path`), and the top-level
`find_cursor_agents()` entry point that turns qualifying composers into
synthetic `AgentProcess` entries for `discovery.py::find_running_agents()`
to merge in.

The `isDraft` exclusion tested below (`empty-state-draft`) was found via a
live smoke test against this machine's real Cursor install (PLAYBOOK Sprint
7, 2026-07-14): a real placeholder composer with a `lastUpdatedAt` newer
than an actual conversation but zero bubbles, which without the filter
would be surfaced/auto-picked as a phantom empty "agent".
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from agentwatch import cursor_discovery
from agentwatch.cursor_discovery import (
    _cursor_synthetic_log_key,
    _file_uri_to_path,
    _synthetic_pid,
    build_workspace_map,
    default_cursor_user_dir,
    find_cursor_agents,
)

SCHEMA_SQL = """
CREATE TABLE composerHeaders (
    composerId TEXT PRIMARY KEY,
    workspaceId TEXT,
    createdAt INTEGER,
    lastUpdatedAt INTEGER,
    isArchived INTEGER,
    isSubagent INTEGER,
    recency INTEGER,
    checkpointAt INTEGER,
    value TEXT
);
CREATE TABLE cursorDiskKV (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def _insert_header(conn, composer_id, workspace_id, last_updated_at, value_extra, archived=0):
    value = {"unifiedMode": "agent", "forceMode": "edit", **value_extra}
    conn.execute(
        "INSERT INTO composerHeaders "
        "(composerId, workspaceId, createdAt, lastUpdatedAt, isArchived, "
        "isSubagent, recency, checkpointAt, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (composer_id, workspace_id, 1000, last_updated_at, archived, 0, 1, None, json.dumps(value)),
    )


@pytest.fixture
def user_dir(tmp_path):
    """A fixture Cursor `User` dir: globalStorage/state.vscdb +
    workspaceStorage/<id>/workspace.json, matching the real on-disk layout."""
    root = tmp_path / "Cursor" / "User"
    (root / "globalStorage").mkdir(parents=True)
    (root / "workspaceStorage" / "ws-1").mkdir(parents=True)
    (root / "workspaceStorage" / "empty-window").mkdir(parents=True)

    (root / "workspaceStorage" / "ws-1" / "workspace.json").write_text(
        json.dumps({"folder": "file:///c%3A/Users/zaid/myproject"}), encoding="utf-8"
    )
    # "empty-window" real case: no workspace.json at all.

    db_path = root / "globalStorage" / "state.vscdb"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(SCHEMA_SQL)
        _insert_header(conn, "c-real", "ws-1", 2000, {})
        _insert_header(conn, "c-chat", "ws-1", 2500, {"unifiedMode": "chat"})
        _insert_header(conn, "c-archived", "ws-1", 3000, {}, archived=1)
        _insert_header(conn, "c-never-messaged", "ws-1", None, {})
        _insert_header(
            conn, "empty-state-draft", "empty-window", 9999, {"isDraft": True}
        )
        _insert_header(conn, "c-no-workspace", None, 4000, {})
        conn.commit()
    finally:
        conn.close()

    return root


# ---------------------------------------------------------------------------
# _file_uri_to_path
# ---------------------------------------------------------------------------


class TestFileUriToPath:
    def test_decodes_windows_drive_uri(self):
        uri = "file:///c%3A/Users/Zaid/Desktop/claude%20work/agentwatch/agentwatch-main"
        result = _file_uri_to_path(uri)
        assert str(result) in (
            "c:\\Users\\Zaid\\Desktop\\claude work\\agentwatch\\agentwatch-main",
            "c:/Users/Zaid/Desktop/claude work/agentwatch/agentwatch-main",
        )

    def test_non_file_uri_returns_none(self):
        assert _file_uri_to_path("https://example.com") is None


# ---------------------------------------------------------------------------
# default_cursor_user_dir -- per-OS path resolution.
#
# Sprint 9 (2026-07-14): fetched VS Code's own real getDefaultUserDataPath
# (src/vs/platform/environment/node/userDataPath.ts, microsoft/vscode @
# main) to check this function against, rather than leaving macOS/Linux as
# an unverified "same convention" guess. macOS matched exactly. Linux did
# not: the real source respects XDG_CONFIG_HOME before falling back to
# ~/.config, which this function previously ignored.
# ---------------------------------------------------------------------------


class TestDefaultCursorUserDir:
    def test_windows_uses_appdata_env_var(self, monkeypatch):
        monkeypatch.setattr(cursor_discovery.sys, "platform", "win32")
        monkeypatch.setenv("APPDATA", r"C:\Users\zaid\AppData\Roaming")
        result = default_cursor_user_dir()
        assert result == Path(r"C:\Users\zaid\AppData\Roaming") / "Cursor" / "User"

    def test_windows_falls_back_when_appdata_unset(self, monkeypatch):
        monkeypatch.setattr(cursor_discovery.sys, "platform", "win32")
        monkeypatch.delenv("APPDATA", raising=False)
        result = default_cursor_user_dir()
        assert result == Path.home() / "AppData" / "Roaming" / "Cursor" / "User"

    def test_macos_matches_real_vscode_getdefaultuserdatapath(self, monkeypatch):
        """join(homedir(), 'Library', 'Application Support') + productName,
        confirmed directly against the real VS Code source (see class
        docstring) -- not just "same convention as other forks"."""
        monkeypatch.setattr(cursor_discovery.sys, "platform", "darwin")
        result = default_cursor_user_dir()
        assert result == Path.home() / "Library" / "Application Support" / "Cursor" / "User"

    def test_linux_respects_xdg_config_home_when_set(self, monkeypatch):
        """The real bug this sprint fixed: XDG_CONFIG_HOME was previously
        ignored entirely on Linux."""
        monkeypatch.setattr(cursor_discovery.sys, "platform", "linux")
        monkeypatch.setenv("XDG_CONFIG_HOME", "/custom/xdg/config")
        result = default_cursor_user_dir()
        assert result == Path("/custom/xdg/config") / "Cursor" / "User"

    def test_linux_falls_back_to_dot_config_when_xdg_unset(self, monkeypatch):
        monkeypatch.setattr(cursor_discovery.sys, "platform", "linux")
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        result = default_cursor_user_dir()
        assert result == Path.home() / ".config" / "Cursor" / "User"

    def test_posix_style_uri_keeps_leading_slash(self):
        result = _file_uri_to_path("file:///home/zaid/project")
        assert str(result) in ("/home/zaid/project", "\\home\\zaid\\project")


# ---------------------------------------------------------------------------
# build_workspace_map
# ---------------------------------------------------------------------------


class TestBuildWorkspaceMap:
    def test_resolves_folder_from_workspace_json(self, user_dir):
        mapping = build_workspace_map(user_dir)
        assert "ws-1" in mapping
        assert mapping["ws-1"].name == "myproject"

    def test_skips_entries_with_no_workspace_json(self, user_dir):
        mapping = build_workspace_map(user_dir)
        assert "empty-window" not in mapping

    def test_missing_storage_root_returns_empty(self, tmp_path):
        assert build_workspace_map(tmp_path / "does-not-exist") == {}


# ---------------------------------------------------------------------------
# _synthetic_pid / _cursor_synthetic_log_key
# ---------------------------------------------------------------------------


class TestSyntheticIdentity:
    def test_synthetic_pid_is_deterministic(self):
        assert _synthetic_pid("composer-abc") == _synthetic_pid("composer-abc")

    def test_synthetic_pid_is_positive(self):
        assert _synthetic_pid("composer-abc") >= 0

    def test_synthetic_pid_differs_across_composers(self):
        assert _synthetic_pid("composer-a") != _synthetic_pid("composer-b")

    def test_synthetic_log_key_is_never_the_real_path(self, tmp_path):
        db_path = tmp_path / "state.vscdb"
        key = _cursor_synthetic_log_key(db_path, "composer-abc")
        assert key != db_path
        assert "composer-abc" in key.name
        assert not key.exists()


# ---------------------------------------------------------------------------
# find_cursor_agents
# ---------------------------------------------------------------------------


class TestFindCursorAgents:
    def test_returns_empty_when_not_running(self, user_dir, monkeypatch):
        monkeypatch.setattr(cursor_discovery, "is_cursor_running", lambda: False)
        assert find_cursor_agents(user_dir=user_dir) == []

    def test_require_running_false_bypasses_gate(self, user_dir, monkeypatch):
        monkeypatch.setattr(cursor_discovery, "is_cursor_running", lambda: False)
        agents = find_cursor_agents(user_dir=user_dir, require_running=False)
        assert len(agents) == 1

    def test_only_surfaces_qualifying_agent_mode_composer(self, user_dir, monkeypatch):
        """c-chat (chat mode), c-archived (archived), c-never-messaged (no
        lastUpdatedAt), empty-state-draft (isDraft), and c-no-workspace (no
        resolvable workspace) must all be excluded -- only c-real survives."""
        monkeypatch.setattr(cursor_discovery, "is_cursor_running", lambda: True)
        agents = find_cursor_agents(user_dir=user_dir)

        assert len(agents) == 1
        agent = agents[0]
        assert agent.session_id == "c-real"
        assert agent.agent_type == "cursor"
        assert agent.working_directory.name == "myproject"
        assert agent.cursor_db_path == user_dir / "globalStorage" / "state.vscdb"
        assert agent.log_file != agent.cursor_db_path

    def test_missing_db_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cursor_discovery, "is_cursor_running", lambda: True)
        empty_dir = tmp_path / "no-cursor-here"
        empty_dir.mkdir()
        assert find_cursor_agents(user_dir=empty_dir) == []

    def test_never_raises_on_corrupt_db(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cursor_discovery, "is_cursor_running", lambda: True)
        root = tmp_path / "Cursor" / "User"
        (root / "globalStorage").mkdir(parents=True)
        (root / "globalStorage" / "state.vscdb").write_text("not a sqlite file")
        assert find_cursor_agents(user_dir=root) == []
