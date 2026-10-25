# agentwatch live-agent test — 2026-10-05

agentwatch: `~/Desktop/loomlabs/agentwatch` (branch `fix/efficiency-cache-reads-36`, no source changes).
Phase 0: `.venv` created, `pip install -e ".[dev,siem,llm]"` OK, `agentwatch --help` OK, `pytest tests/ -q` → **1035 passed**.

## Installed (Phase 1)

| Agent | Verified package / source | Version |
|---|---|---|
| Gemini CLI | `@google/gemini-cli` (repo google-gemini/gemini-cli) | 0.62.0 |
| Qwen Code | `@qwen-code/qwen-code` (repo QwenLM/qwen-code) | 0.25.0 |
| OpenCode | `opencode-ai` (named in sst→anomalyco/opencode README) | 1.18.34 |
| Goose | `download_cli.sh` from aaif-goose/goose releases (block/goose redirects) | 1.53.0 |
| Cursor CLI | `cursor.com/install` | 2026.10.01-e373342 |
| Crush | `@charmland/crush` (repo charmbracelet/crush) | 0.97.1 |
| Amp | `@ampcode/cli` (successor of `@sourcegraph/amp`) | 0.0.1791216048 |
| Kiro CLI | `cli.kiro.dev/install` (sha256-verified zip) | 2.27.1 |
| Codex | `@openai/codex` (repo openai/codex) | 0.160.0 |

## Results (Phase 2)

Tested: **Gemini, OpenCode**. Skipped by user: **Qwen** (no provider configured; 0.25.0 has no Qwen OAuth option, only API-key providers), **Codex** (`codex login status` → "Not logged in"). Goose/Cursor/Crush/Amp/Kiro: installed, not logged in, not tested.

Task in each throwaway repo (`~/agent-tests/<agent>`): "create hello.py that prints hello, run it, then read it back". Both agents completed it (Gemini in `--yolo`, OpenCode in `--auto` on free model `opencode/nemotron-3-ultra-free`).

| Agent | `ps` detects? | `check` works? | `watch-all` live? | Log path | Format | Tool calls? | Token usage? | Storage |
|---|---|---|---|---|---|---|---|---|
| Gemini CLI | No | No — default picks a Claude Code log; `--log` misparses (bug 1) | No | `~/.gemini/tmp/<project>/chats/session-<ts>-<id>.jsonl` | JSONL (header line + messages + `{"$set":…}` patch lines; messages re-emitted by `id` as they update) | Yes (`toolCalls[]` with `name`, `args`, `result`, `status`) | Yes, per model turn (`tokens.input/output/cached/thoughts/total`) | Local transcript (inference is cloud) |
| OpenCode | No | No — default picks a Claude Code log; `--log` crashes (bug 2) | No | `~/.local/share/opencode/opencode.db` (+ `-wal`) | SQLite (`session`, `message`, `part`; JSON in `part.data`) | Yes (`part.data.type=="tool"`, `tool`, `state.input/output/status`) | Yes (`step-finish` parts + session `tokens_*` columns, `cost`) | Local (opt-in `session_share` to cloud) |
| Qwen Code | — | — | — | `~/.qwen/projects/<encoded-cwd>/chats/<id>.runtime.json` seen; transcript format not observed | — | — | — | — |
| Codex | — | — | — | not produced (no login) | — | — | — | — |

Samples: `samples/gemini.jsonl` (session header + one model turn with a `run_shell_command` call, its result, and tokens), `samples/opencode.json` (session row + message + `bash` tool part + `step-finish` tokens). Home paths, username, and prompt text redacted.

## Adapter effort for unsupported agents

Reference points: `parser/copilot.py` (105 lines, call/result paired by id) and `parser/agy.py` (147 lines, positional pairing), plus a ~40–70-line `agents/<name>.py` each.

| Agent | Effort | Why |
|---|---|---|
| Gemini CLI | **S–M** | JSONL, call and result in the same `toolCalls[]` entry (simpler than Copilot). Extra work: dedupe re-emitted messages by `id`, ignore `$set` lines, and fix sniffing order — the header line has `sessionId`, so `detect_log_format` must recognise Gemini before the Claude Code check. Log resolution: project dir under `~/.gemini/tmp/` + newest `chats/session-*.jsonl` by mtime. Must not collide with `agy`, which also lives under `~/.gemini`. |
| OpenCode | **M–L** | SQLite like Cursor (`parser/cursor_source.py`, 408 lines), not JSONL: needs a `CursorWatcher`-style poller over a WAL db, read-only open, session picked by `session.directory == cwd`. Data itself is clean (tool + state + tokens per part). |
| Qwen Code | **S–M (unverified)** | Fork of Gemini CLI; likely the Gemini parser with a different home (`~/.qwen/projects/<encoded-cwd>/chats/`). Needs a live session to confirm. |
| Goose, Cursor CLI, Crush, Amp, Kiro | not estimated | Not logged in; no logs to inspect. |

## Codex rollout vs `parser/codex.py`

**Not verified.** No live session was run (not logged in), so there is no real rollout JSONL to compare against. `parser/codex.py` still describes itself as "fixture-based … not verified against a live Codex CLI install". The open item stays open: run one Codex session and diff `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl` against the parser's assumptions (`{timestamp, type, payload}` envelope, `function_call`/`function_call_output` paired by `call_id`, `ordinal` field, token-count `event_msg`).

## agentwatch bugs

### 1. Gemini JSONL misdetected as Claude Code
```
$ agentwatch check --log ~/.gemini/tmp/gemini/chats/session-2026-10-05T17-10-47cfddd2.jsonl
  Overall:   🚀 PRODUCTIVE (94%)
  🔄 1 warning(s):
     ⚠️ [loop] Repeated action: gemini (4x)
```
`sniff_jsonl_format` → `claude_code`, `adapter_for` → `claude-code`. Every line becomes `ToolType.UNKNOWN` named after its `type` (`user`, `gemini`, `unknown`); no tools or tokens extracted. Cause: `detect_log_format` (`parser/logs.py:451`) returns `claude_code` for any entry with a `sessionId` key, and Gemini's header line has one. The loop warning is a false positive from Gemini re-emitting the same message id as it updates.

### 2. `check --log` on a non-JSONL file crashes
```
$ agentwatch check --log ~/.local/share/opencode/opencode.db
  File "src/agentwatch/cli.py", line 402, in check
  File "src/agentwatch/parser/logs.py", line 590, in parse_file
  File "src/agentwatch/parser/logs.py", line 529, in _parse_jsonl
  File "src/agentwatch/parser/logs.py", line 459, in detect_log_format
AttributeError: 'int' object has no attribute 'get'
exit=1
```
A line of the binary file parses as a JSON scalar and is passed to `detect_log_format`. `sniff_jsonl_format` (`agents/base.py:105`) already skips non-dict entries; `_parse_jsonl` does not. Expected: a clean "unsupported/unrecognised log format" error.

### 3. Default `check` / `security-scan` silently report on an unrelated session
Run from `~/agent-tests/gemini` and `~/agent-tests/opencode` while those agents were live:
```
$ agentwatch check
Using log: /home/<user>/.claude/projects/-home-<user>/db75c4da-….jsonl
  Overall:   🚀 PRODUCTIVE (100%)
```
`find_latest_session()` ignores the cwd and picks the newest Claude Code log. Only the stderr "Using log" line hints that it is a different agent's session; the report looks like it describes the current directory.

### 4. Likely false positive: `c2_beacon` on a desktop-restart command
```
$ agentwatch security-scan
🧱 CRITICAL SECURITY ALERTS 🧱
  🚨 [c2_beacon] Command pattern consistent with C2 beacon
      command: cd ~/.config; F=plasma-org.kde.plasma.desktop-appletsrc; kquitapp6 plasmashell; …
```
From a Claude Code session editing KDE Plasma config. Not verified which rule fired; worth checking the pattern.

### 5. `watch-all` rate figures blow up at near-zero duration
```
$ timeout 20 agentwatch watch-all
▊     Pressure     [██████████] 1.00   100% budget, 425440.5k tok/min
▊     Pacing       [░░░░░░░░░░] 0.00   0min, 8.8 act/turn
▊   Est. cost: $1.15 ($5056.28/min)
```
Per-minute rates divided by a ~0 duration; should be suppressed or floored until the session has a minimum duration.

## Leftovers on this machine
- Installed globally: the 9 CLIs above (npm globals; `~/.local/bin/{goose,agent,cursor-agent,kiro-cli}`; `~/.local/share/cursor-agent/`).
- Test dirs: `~/agent-tests/{gemini,qwen,codex,opencode}`; OpenCode/Gemini test sessions remain in their stores.
- No commits, pushes, PRs or issues. agentwatch source unchanged (only `.venv/` added).
