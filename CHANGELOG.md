# Changelog

Notable changes to AgentWatch (`agentwatch-monitor`). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Issue and PR
numbers refer to the GitHub repository.

## [Unreleased] - develop, 2026-10-03 to 2026-10-14

### Added

- Per-agent adapter registry. Discovery, `parse_file`, `watch-all` and the
  TUI dispatch through it, and a failing adapter is skipped. Adds the GitHub
  Copilot CLI and Antigravity CLI (`agy`) adapters (PR #29).
- OpenCode adapter: reads the SQLite `opencode.db` store read-only (#67, PR #69).
- Gemini CLI adapter: parses `chats/session-*.jsonl` (#65, PR #68).
- GitHub Copilot in VS Code adapter: parses the `chatSessions/*.jsonl` mutation
  logs. Includes the design spec (#87, PRs #88, #89).
- Claude Desktop Cowork adapter (#73, PR #102).
- Cline adapter: covers the legacy globalStorage store, the SDK store
  (`~/.cline/data/sessions/`) and the Cline CLI (#104, PR #112).
- Cline: legacy store discovery for VS Code forks (#116, PR #124).
- Kilo Code 7.x adapter: reuses the OpenCode parser on `kilo.db`
  (#118, PR #123).
- `agentwatch detect`: machine-wide detection of AI use. It attributes
  connections to AI providers and local model ports to processes
  (#79, PR #80).
- `agentwatch check` reports session efficiency in text and JSON output
  (#40, PR #51).

### Changed

- Synthetic PIDs are a crc32 of the session id, so they stay stable across
  runs (#90, PR #92).
- Copilot in VS Code: finished requests settle for 1 s before they are
  emitted (#91, PR #93).
- Codex: the ChatGPT desktop app's app-server gets one `ps` entry per open
  thread (#105, PR #111).
- `check` prefers the current directory's session when `--log` is omitted
  (#47, PR #52).
- One-shot scans run the security detectors over the whole session
  (#35, PR #56).
- Rates show "--" until a session has 2 active minutes (#45, PR #50).
- Security: redaction of truncated windows is memoized (#25, PR #57).

### Fixed

- `detect`: `Code.exe` and `Cursor.exe` map to their editor adapters
  (#100, PR #101).
- `detect`: editor processes are credited to every candidate editor adapter
  that has live sessions (#119, PR #120).
- `detect`: Cline is credited to VS Code forks and to Cursor processes
  (#127, PR #128).
- Cline: `api_conversation_history.json` is routed by extension id
  (#117, PR #121).
- Cline: outside globalStorage, Roo Code 3.49.0+ tasks (marked by
  `history_item.json`) are no longer claimed as Cline. Kilo Code 5.x and
  Roo Code below 3.49 still fall back to Cline (#117, PR #125).
- Codex: ChatGPT desktop Codex sessions show the rollout's project instead
  of the app-server's cwd, and use the most recently modified open rollout
  (#74, PR #77).
- Codex: the ChatGPT app's bin dir is never reported as the project
  (#94, PR #95).
- Codex: action count, cache hit rate, context % and cost are corrected
  (#82, PR #83).
- Codex: `item_completed` exit codes and patch status are correlated by call
  id (#106, PR #113).
- Codex: tool calls made inside code-mode `exec` scripts are surfaced
  (#107, PR #114).
- Codex: unrenamed `codex-<arch>-<triple>` release binaries are matched on
  every OS. The macOS side is source-reviewed, not run on a Mac
  (#108, PR #122).
- Discovery: `claude-code` false positives are dropped from `ps`
  (#84, PR #85).
- Discovery: Claude Code's full project-dir encoding is matched
  (#75, PR #86).
- Discovery: the non-Store Claude Desktop is no longer matched as
  `claude-code` (#109, PR #110).
- OpenCode: malformed rows are skipped, and a locked DB is reported as
  unreadable (#70, PR #72).
- Fixes from the Sprint 26 follow-ups (#62, #63, #64, PR #66).
- Parser: unrecognised and binary logs are rejected instead of being parsed
  as Claude Code (#39, PR #48).
- Watcher: Claude metadata-only sessions are emitted the same way as in
  `parse_file` (#39, PR #61).
- Parser: Claude Code bookkeeping entries are skipped, and the loop key is
  fixed (#46, PR #54).
- Parser: unparseable timestamps stay untimed and never fall back to
  `datetime.now()` (#44, PR #53).
- Parser: session duration comes from real timestamps, with idle gaps capped
  (#38, PR #43).
- Health: burn rate and io ratio exclude cache reads (#36, PR #37).
- Health: context pressure measures how full the window is, not the
  cumulative budget (#36, PR #42).
- Security: the remaining secret leak sinks are closed. Network hosts keep
  only the hostname, so query-string tokens are dropped. Error text and LLM
  prompts are masked, and more secret forms are detected
  (`PGPASSWORD=`, `mysql -p`, `--password=`, `curl -u`, URL credentials,
  `Authorization: Bearer`) (#24, PR #30).
- Security: DB-URL redaction no longer runs past the password, a placeholder
  no longer hides a live URL after it, and masking never reveals password
  characters. Stock-default passwords are no longer reported (#26, PR #34).
- Security: DB URL scanner gaps are fixed, and `check --json` output is
  stable (#33, PR #58).
- Security: follow-ups from the secret scanner QA (#31, PR #59).
- Security: the Discord, JWT and high-entropy patterns run in linear time
  (#32, PR #60).
- Security: `c2_beacon` patterns match whole words only (#41, PR #55).
- Net: `watch-all` re-tracks a session's sockets when a new process takes
  over its log, and `net --once` exits 1 when every `--pid` is missing.

### Documentation

- README: GitHub Copilot in VS Code (#87, PR #96).
- CLAUDE.md: crc32 synthetic pids, the Copilot-in-VS-Code settle, Kilo Code,
  Cline forks, the Roo marker and macOS Codex (PRs #97, #126).
- Copilot in VS Code re-verified on VS Code 1.141, with a note on the write
  delay (#87, PR #98).
- PLAYBOOK Sprints 28 to 32 (PRs #71, #81, #99, #115).
- Research: live agent testing and adapter candidates (#39, PR #49). Also the
  agent landscape, adapter roadmap and AI-use detection (PR #78).
- ADR proposing a TLS-intercepting proxy for network visibility (PR #103,
  rebuilt from PR #21).

Earlier unreleased develop work since `v0.1.6` (PRs up to #28) is in the git
log. Released history is in the PyPI releases up to `v0.1.6`.
