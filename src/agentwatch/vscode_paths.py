"""Per-OS ``User`` directory of VS Code and its forks (Cursor, ...)."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def default_user_dir(app: str) -> Path:
    """``<user data>/<app>/User``, per VS Code's ``getDefaultUserDataPath``
    (``src/vs/platform/environment/node/userDataPath.ts``; see
    ``cursor_discovery.default_cursor_user_dir`` for what was verified).
    *app* is the folder name: ``"Code"``, ``"Cursor"``."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg_config_home) if xdg_config_home else Path.home() / ".config"
    return base / app / "User"
