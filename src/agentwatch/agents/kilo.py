"""Kilo Code 7.x adapter: an opencode fork with the same SQLite store.

Cited against Kilo-Org/kilocode @ ff20ca7 (fixture-verified only, no live
install). The store is ``$XDG_DATA_HOME/kilo/kilo.db`` (``packages/core/src/
global.ts:12,22``, ``database/database.ts:50-60``), ``KILO_DB`` overrides it,
and its session/message/part tables are opencode's (``session/sql.ts:24-102``),
so ``parser/opencode.py`` and ``OpencodeWatcher`` read it unchanged. Kilo 5.x's
Roo-style ``globalStorage`` task files are out of scope (#118).

Processes: the native ``kilo``/``kilo.exe`` binary. That is the CLI (npm's
``bin/kilo`` node wrapper spawns it, as ``bin/.kilo`` once postinstall has
cached it) and the VS Code extension's bundled ``<ext>/bin/kilo serve``
(``kilo-vscode/.../server-manager.ts:129,250-253``). The node wrapper is
excluded so one session is not listed twice (wrapper plus child).

``kilo serve`` runs with cwd = the window's first workspace folder
(``server-manager.ts:23-25,110,130``) and creates sessions in that folder by
default (``KiloProvider.ts:2241-2245,6166-6172``), so opencode's
newest-session-in-cwd rule holds there. Not surfaced: Agent Manager worktree
sessions and sessions routed to other folders of a multi-root workspace.
"""

from __future__ import annotations

from pathlib import Path

from .opencode import OpencodeAdapter


class KiloAdapter(OpencodeAdapter):
    name = "kilo-code"
    app = "kilo"
    db_env = "KILO_DB"
    process_pattern = r"(^|[/\\])\.?kilo(\.exe)?$"
    process_exclude = r"(^|[/\\])(node|nodejs|bun)(\.exe)?\s"

    def claims(self, path: Path) -> bool:
        # Registered before opencode, which claims any db with this schema.
        # ponytail: by filename, so a KILO_DB not named kilo*.db reads as opencode
        # (same parser, only the agent label differs).
        return path.name.startswith("kilo") and super().claims(path)
