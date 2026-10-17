# Changelog

Notable changes to AgentWatch (`agentwatch-monitor`). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Issue and PR
numbers refer to the GitHub repository.

## [Unreleased]

## [0.2.0] - Unreleased

Everything on `develop` since `v0.1.6` (2026-03-10).

### Added

- `agentwatch net`: shows which external servers local AI runtimes (Ollama,
  LM Studio, llama.cpp, ...) talk to, named from the DNS cache, known hosts or
  reverse DNS. Nothing is allow-listed. Supports `--once`, `--json`,
  `--pid`, `--interval` and `--duration` (PR #134).
- `agentwatch net` lists runtime listeners and flags the ones other machines
  can reach (bound to all interfaces or a LAN address), plus the clients
  connected to them (PR #135).
- `agentwatch net --local` also watches running agents (Aider, opencode, ...)
  and flags connections to cloud AI providers (PR #136).
- Per-action network tracking in `watch` / `watch-all`: each agent's live
  endpoints are sampled (unprivileged, about once a second) and the stats line
  shows `Net:`. New `undeclared_egress` security detector (medium) flags
  endpoints not explained by a declared host, a known AI provider or a known
  agent vendor host (#130, PR #130).
- `agentwatch scrub <file>`: hides secrets and personal info (email, phone,
  US SSN, card numbers, US street address) in a `.scrubbed` copy, or
  `--in-place` with a `.bak`. Also `--dry-run`, `--json`, `--secrets-only`
  (PR #133).
- `agentwatch audit --pii` reports personal info as low-severity findings
  that never change the exit code (PR #133).
- Claude Code skill `skills/agentwatch-scrub` for scrubbing a file or session
  log by asking Claude Code (PR #133).
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
- Cursor support: `check`, `security-scan` and `watch-all` read Cursor
  agent-mode sessions from `state.vscdb` (PR #2), and `watch --log
  state.vscdb` works in the single-agent TUI (PR #13).
- Aider support: parses `.aider.chat.history.md` in every edit format,
  including resumed sessions, with an optional `--analytics-log` sidecar for
  tokens and cost. Live tailing in `watch` / `watch-all` (PR #2).
- Codex CLI support: session discovery and rollout log parsing (PR #2).
  Rollouts are resolved from the process's open files when a pid is known,
  and more Codex tool names are classified (PR #14).
- Native Windows support: psutil process discovery, Windows path encoding
  and a UTF-8 console (PR #2).
- `ascii` theme for consoles without Unicode (PR #2).
- `--siem-log PATH` writes findings as JSON lines for SIEM ingestion
  (`siem` extra) on `check` and `security-scan` (PR #2), and on `watch` /
  `watch-all`, exporting each warning once (PR #15).
- `--llm` adds an optional local-Ollama second opinion on warnings (`llm`
  extra) (PR #2), plus a goal-alignment advisory that is never scored
  (PRs #9, #15).
- `security-scan --audit-log PATH` writes a JSON-lines record of every
  security detector run (PR #8).
- `security-scan` shows raw security-signal counts (`security_stats` in
  `--json`), and `check` and the TUI show peak context tokens (PR #8).

### Changed

- Claude Code and Gemini actions take their network host from a tool's
  `url`, so URL fetches reach the network detectors (#130, PR #130).
- Status messages such as "Using log ..." go to stderr, so `--json` stdout
  stays clean (PR #20).
- Secrets in findings are masked: values of 20+ characters show only the last
  4, shorter ones show `[hidden, N chars]`, and commands in warning details
  are masked too. Affects `matched_prefix`, SIEM, `audit --json` and the TUI
  (PR #23).
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
- Faster scans and TUI refreshes on long sessions (PR #2).
- `Action.user_id`, which was never set, is removed from the model (PR #8).

### Fixed

- Parser: a non-text `host` in a tool's input no longer hides the URL host,
  so network detectors still fire (PR #138).
- Security: PEM private-key bodies are redacted, not just the header line
  (PR #133).
- PII: a card number followed by a CVV or expiry is now hidden, and phone
  numbers with an invalid NANP area code or exchange (`100-200-3000`) are no
  longer flagged (PR #140).
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
- `watch`: the single-agent TUI showed no live data for any agent because the
  first action was dropped (PR #12).
- `stats` no longer crashes on non-UTF-8 bytes in a Claude Code log (PR #17).
- `--version` reports the installed package version (PR #19).
- `audit --redact` replaces only secret values, keeps JSON lines valid,
  preserves non-UTF-8 bytes, writes atomically and keeps a one-time `.bak`
  (PR #22). Its redaction count no longer includes false positives (PR #3).
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

- README: goal alignment, the GOAL category and Cursor's scope are described
  accurately (PR #16).
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

## [0.1.6] and earlier

Released history is in the PyPI releases up to `v0.1.6`.
