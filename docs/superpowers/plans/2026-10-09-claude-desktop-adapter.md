# Claude Desktop (Cowork) adapter — implementation plan

Spec: `docs/superpowers/specs/2026-10-09-claude-desktop-adapter-design.md`. Issue #73.

## Files

- New `src/agentwatch/claude_desktop_discovery.py` — `claude_desktop_roots()`,
  `is_claude_desktop_running()`, `find_claude_desktop_agents(now=None)`.
  Reuses `cursor_discovery._synthetic_pid`.
- New `src/agentwatch/agents/claude_desktop.py` — `ClaudeDesktopAdapter`
  (editor kind, delegates watcher/parse to `ClaudeCodeAdapter`).
- `src/agentwatch/agents/__init__.py` — register after `GeminiAdapter`.
- New `tests/test_claude_desktop.py` — synthetic trees in `tmp_path`.
- `tests/test_agent_registry.py` — order/kinds updated.
- `CLAUDE.md`, `README.md` — agent list and architecture.

## Tests, in TDD order (each written to fail first)

1. Roots: MSIX glob, then `%APPDATA%\Claude`, then macOS path; only roots
   with `local-agent-mode-sessions/` returned.
2. Running gate on exe path: MSIX app exe true; Claude Code `claude.exe`
   (same name), `cowork-svc.exe`, None/AccessDenied exe false.
3. Not running -> `[]` with a valid session present.
4. Happy path: one active session -> one `AgentProcess` (type, log file,
   cwd, session id, command, synthetic pid).
5. Activity window via injected `now`: stale skipped; archived skipped.
6. Transcript by `cliSessionId` with a decoy `.jsonl` (newer mtime) and a
   `subagents/` file present.
7. Bad metadata (invalid JSON, non-dict, missing `cliSessionId`, missing
   `cwd`, missing transcript) skipped; `skills-plugin/` and stray files
   tolerated.
8. Registry order/kinds include `claude-desktop` after `gemini`.
9. Adapter: `discover()` delegates; `make_watcher` returns a `LogWatcher`
   on the transcript; `claims()` false; `parse_file` yields actions; and
   `adapter_for(transcript)` is `claude-code`.

Gate: `.venv\Scripts\python -m pytest tests/ -q` and `ruff check .`.
