# Agent landscape and machine-wide AI detection: research + plan (2026-10-09)

Two questions from the board:

1. Which agentic apps and CLIs are most used, and which should agentwatch
   support next?
2. How could agentwatch detect that *any* AI is being used on the current
   machine, including tools it has no adapter for?

Builds on `agent-adapter-candidates-2026-10-05.md` (per-agent storage
research for Gemini, Qwen, OpenCode, Kilo, Crush, Goose, Cline CLI, Continue,
Cursor CLI, Amp, Kiro, Roo). That doc is not repeated here.

## 1. Usage landscape

Usage numbers are survey estimates, not telemetry. Treat them as directional.

| Tool | Usage signal (2026) | Source |
|---|---|---|
| Claude Code | 39% of pro devs use it at work, most-used tool for 31% (JetBrains, May-Jul); 28.7% primary-tool share (First Page Sage, Q3) | [JetBrains][jb], [FPS][fps] |
| GitHub Copilot | 21% (JetBrains), 23.1% (FPS); still #2 | [JetBrains][jb], [FPS][fps] |
| OpenAI Codex (CLI + ChatGPT desktop app) | 3% -> 16% Jan-Jul (JetBrains); 11.2% (FPS) | [JetBrains][jb], [FPS][fps] |
| Cursor | 18% -> 12% (JetBrains); 13.5% (FPS) | [JetBrains][jb], [FPS][fps] |
| OpenCode | 7% adoption (JetBrains); most-starred open-source CLI | [JetBrains][jb], [morph][morph] |
| Cline | 5M+ VS Code installs; ~69k stars | [kilo][kilo], [morph][morph] |
| Gemini CLI | ~107k stars; one source says Google retired it 2026-06-18 for a closed successor (likely Antigravity `agy`, already supported). **Unverified, check.** | [morph][morph] |
| Goose / Aider / Kilo Code | ~55k / ~49k / ~27k stars | [morph][morph] |
| Windsurf (now Cognition), Zed, Amp, Warp, Devin | no reliable usage data | [faros][faros], [pragmatic][pe] |

### Coverage today

Supported: Claude Code, Codex CLI, Cursor (IDE), Copilot CLI, Antigravity
`agy`, Gemini CLI, OpenCode, Aider. In flight: Claude Desktop Cowork
(PR #76), ChatGPT desktop / Codex app (research on
`feature/chatgpt-desktop-adapter`).

This already covers the top 4 by usage *except* the biggest slice of
Copilot: **Copilot inside VS Code** (agent mode). The Copilot CLI is a small
part of Copilot's usage.

## 2. Adapter roadmap (ranked: usage x feasibility)

| # | Target | Why | Local data (unverified unless noted) | Effort | Reuses |
|---|---|---|---|---|---|
| 1 | **Copilot in VS Code** (agent mode) | #2 tool by usage; biggest uncovered slice | `<Code user dir>/workspaceStorage/<hash>/chatSessions/*.json` (some reports say JSONL; varies by version) + `chatEditingSessions/`; legacy `globalStorage/emptyWindowChatSessions/` ([source][vsc1], [source][vsc2]) | medium | `cursor_discovery.build_workspace_map()` (same VS Code `workspace.json` layout); process gate on `Code.exe`; `AiderLogWatcher`-style whole-file reparse if files are rewritten |
| 2 | **Cline** (VS Code extension) | 5M+ installs, most-installed VS Code agent | `<Code user dir>/globalStorage/saoudrizwan.claude-dev/tasks/<id>/{api_conversation_history,ui_messages,task_metadata}.json`, index `state/taskHistory.json`; newer versions may use `~/.cline/data` ([Cline docs][cline]) | medium | same VS Code root resolution as #1; whole-file reparse watcher |
| 3 | **Kilo CLI** | OpenCode fork, ~27k stars | `~/.local/share/kilo/kilo.db`, OpenCode schema (2026-10-05 doc) | **low** | `OpencodeAdapter` with a different db path + process name |
| 4 | **Qwen Code** | large user base in China; Gemini fork | Claude-Code-like JSONL (2026-10-05 doc) | **lowest** | `LogWatcher`, Claude Code cwd encoding |
| 5 | **Zed agent** | growing editor, native agent panel | `threads/threads.db` SQLite (WAL), thread JSON **zstd-compressed** in `data` ([Zed commit][zed1], [script][zed2]); macOS path seen, Windows/Linux unverified | medium | `OpencodeWatcher`-style poller; needs a zstd decoder (new dependency `zstandard`; stdlib `compression.zstd` only on Python 3.14+) |
| 6 | **Goose**, **Crush** | ~55k stars / Charm community | SQLite WAL (2026-10-05 doc) | medium | SQLite poller pattern |
| 7 | **Windsurf** | large IDE, now Cognition | **unknown**: docs only confirm `~/.codeium/windsurf/{memories,mcp_config.json,cache}` ([source][ws]); transcript storage undocumented | spike first | - |
| skip | Amp, Devin, ChatGPT/Claude **web**, Roo Code | server-side or shut down | none locally | - | covered by section 3 (detection) instead |

Recommendation: do #1 and #2 together as a "VS Code agents" track (shared
root resolution, workspace mapping, and process gate), then #3 and #4 as a
quick batch. #5 waits on a dependency decision. #7 needs a live-install spike.
Each item gets its own spec -> plan -> PR, like the earlier adapters.

## 3. Detecting AI use on this machine

Goal: answer "is any AI being used here right now, by what, talking to
whom?", including tools agentwatch has no parser for. This is inventory,
not content: it reports *that* AI is used, not what was said.

### Industry approach

Shadow-AI tooling layers three signals ([general analysis][ga],
[repello][rep], [vaikora][vai]): DNS/proxy matching against an AI-domain
list, process-to-connection attribution (EDR or eBPF), and endpoint
inventory (installed agents, local LLM runtimes, MCP configs). TLS hides
payloads, so network data shows *that* a tool talks to an AI API, never the
prompt. Local LLMs (Ollama etc.) make no AI-domain DNS lookups and need a
port/process check instead.

### What agentwatch can do without admin rights

Probed live on this machine (Windows 10, no elevation, 2026-10-09):
`psutil.net_connections()` returned 393 sockets, 239 with an owning PID.
Resolving 8 AI domains to IPs and matching remote addresses found:

| Process | Endpoint provider | Note |
|---|---|---|
| `claude.exe` | Anthropic | Claude Code (adapter exists) |
| `ChatGPT.exe` | OpenAI | ChatGPT desktop (in flight) |
| `codex.exe` | OpenAI | Codex (adapter exists) |
| `Orca.exe` | Anthropic | **no adapter: an AI app agentwatch didn't know about** |
| `brave.exe` | Anthropic | browser on claude.ai: web AI use |

So the approach works and already finds AI use the adapters miss.

### Proposed layers (all local, read-only, no admin, psutil only)

1. **Known-AI process catalog.** A data table of executable names/paths for
   AI apps (Claude, ChatGPT, Cursor, Windsurf, Zed, LM Studio, Ollama, ...),
   separate from adapters. Answers "AI app running" even with no parser.
2. **AI endpoint attribution.** Resolve a maintained AI-domain list (per
   provider) to IPs at scan time, then match `net_connections()` remote IPs
   to owning PIDs. Report per process: provider, connection count.
   Limits: CDN-shared IPs make the *domain* ambiguous (here
   `api.anthropic.com` and `claude.ai` share IPs), but the *provider* is
   reliable; connections can be missed between polls; DNS-over-HTTPS or
   proxies/VPNs hide the real endpoint.
3. **Local LLM runtimes.** Listening-port check (Ollama `11434`, LM Studio
   `1234`, common `8000`/`8080`) confirmed by owning process name. Optionally
   probe `GET http://127.0.0.1:11434/api/tags` to list loaded models.
4. **Installed-but-idle inventory.** Presence of known config dirs
   (`~/.claude`, `~/.codex`, `~/.gemini`, VS Code extension ids, MCP config
   files). Kept separate from "in use now".

Output: a new `agentwatch detect` command (table + `--json` for CI/SIEM),
and an "Other AI activity" panel in `watch-all` fed by the same scan.
Fits the existing `--siem-log` export.

### Platform caveats

- Windows: works unelevated (verified above).
- macOS: `net_connections()` needs root for other users' processes; for the
  current user it may need `lsof`-style fallbacks. **Unverified.**
- Linux: works for the current user's processes unelevated; other users'
  need root. **Unverified.**

### Relation to PR #21 (draft ADR)

PR #21 proposes a TLS-intercepting proxy to fill `network_host` for
*monitored* agents, which is deep visibility for one agent, opt-in. This
proposal is shallow, passive visibility across *all* processes, with no
interception and no trust-store changes. They complement each other; this
one should ship first because it carries no MITM risk.

### Privacy

Machine-wide detection is surveillance-shaped. Defaults should be: local
only, nothing leaves the machine unless `--siem-log` is set, no browser
history or page content read, process names and providers only (no URLs or
paths beyond the executable). Document this in the README.

## 4. Decisions needed from the board

1. Approve the adapter order (VS Code track: Copilot + Cline first).
2. Approve `agentwatch detect` (layers 1-3, layer 4 optional) as the next
   architectural feature, so it goes to a spec.
3. Zed: allow the `zstandard` dependency, or defer Zed?
4. Should detection flag browser-based AI use (e.g. `brave.exe` -> Anthropic)
   or only report apps and CLIs?

[jb]: https://blog.jetbrains.com/research/2026/08/ai-coding-agent-adoption-2026/
[fps]: https://firstpagesage.com/seo-blog/ai-coding-assistant-market-share
[morph]: https://www.morphllm.com/best-ai-cli-tools-2026
[kilo]: https://kilo.ai/articles/top-ai-coding-agents
[faros]: https://www.faros.ai/blog/best-ai-coding-agents-2026
[pe]: https://newsletter.pragmaticengineer.com/p/ai-tooling-2026
[vsc1]: https://medium.com/@Manikandan.K.S/how-to-transfer-github-copilot-chat-history-in-vscode-between-devices-97edf082c160
[vsc2]: https://github.com/microsoft/vscode/issues/305818
[cline]: https://docs.cline.bot/troubleshooting/task-history-recovery.md
[zed1]: https://git.secluded.site/zed/commit/c874f1fa9d70c889602e54a8f6ac3ad8c2a2734a
[zed2]: https://rud.is/git/gists.git/tree/2025/2025-09-20-zed-ai-history.sh
[ws]: https://aimemory.pro/blog/windsurf-memory
[ga]: https://generalanalysis.com/guides/how-to-detect-shadow-ai
[rep]: https://repello.ai/blog/shadow-ai-detection-playbook
[vai]: https://vaikora.com/blog/detecting-shadow-ai-unauthorized-llm-enterprise
