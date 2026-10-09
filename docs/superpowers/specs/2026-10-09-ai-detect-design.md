# `agentwatch detect`: machine-wide AI-use detection — design

**Date:** 2026-10-09
**Branch:** `feature/ai-detect` (from `develop`, PR targets `develop`)
**Status:** awaiting spec review
**Background:** `docs/research/agent-landscape-and-ai-detection-2026-10-09.md`
(PR #78), section 3. Board decisions 2026-10-09: build it (decision 2),
apps and CLIs only, no browser-based AI reporting (decision 4).

## Goal

One command that answers: **which programs on this machine are using AI
right now, and which provider are they talking to?** That includes programs
agentwatch has no adapter for.

It reports *that* AI is used, never *what* was said. Everything it reads is
local, read-only, and needs no admin rights on Windows.

## Non-goals (v1)

- Browser-based AI (chatgpt.com or claude.ai in a browser). Browser
  processes are excluded by name (board decision 4).
- Installed-but-idle inventory (config dirs, VS Code extensions). Detection
  is about use now. Possible follow-up.
- A `watch-all` panel and `--siem-log` export. Ship the command first, then
  add them if wanted.
- Prompt or payload visibility (needs the TLS proxy from draft PR #21).
- HTTP probing of local LLM servers (e.g. listing Ollama models).

## Evidence verified 2026-10-09 (Windows 10, unelevated)

- `psutil.net_connections(kind="inet")` returned 393 sockets, 239 with an
  owning PID, with no elevation.
- Resolving 8 AI domains to IPs and matching remote addresses attributed
  connections to `claude.exe` and `Orca.exe` (Anthropic), `ChatGPT.exe` and
  `codex.exe` (OpenAI), and `brave.exe` (Anthropic). `brave.exe` will be
  excluded under decision 4.
- `api.anthropic.com` and `claude.ai` resolved to shared IPs. Attribution is
  reliable at **provider** level, not domain level.

## Components

### `src/agentwatch/ai_detect.py` (new, one module)

Data tables (plain module-level constants; they are data, not config):

- `AI_PROVIDERS: dict[str, tuple[str, ...]]` maps a provider to its API and
  app domains. v1 set: `anthropic` (`api.anthropic.com`, `claude.ai`),
  `openai` (`api.openai.com`, `chatgpt.com`, `ab.chatgpt.com`), `google`
  (`generativelanguage.googleapis.com`, `aiplatform.googleapis.com`),
  `github-copilot` (`api.githubcopilot.com`,
  `api.individual.githubcopilot.com`), `cursor` (`api2.cursor.sh`),
  `mistral` (`api.mistral.ai`), `xai` (`api.x.ai`), `deepseek`
  (`api.deepseek.com`), `openrouter` (`openrouter.ai`), `groq`
  (`api.groq.com`). Each entry gets a comment saying where the domain comes
  from (vendor docs URL); unconfirmed domains are left out, not guessed.
- `LOCAL_LLM_PORTS: dict[int, str]`: `11434: "ollama"`, `1234: "lm-studio"`.
  A listener counts only if its owning process name also matches the
  runtime (e.g. contains `ollama`, or `LM Studio`/`lms`). Generic ports
  such as 8000 and 8080 are left out because they produce too many false
  positives.
- `BROWSER_NAMES: frozenset[str]` holds lowercase process names, without
  `.exe`, of browsers to exclude: chrome, msedge, firefox, brave, opera,
  vivaldi, arc, safari, iexplore, chromium.

Result type:

```python
@dataclass
class AiUsage:
    pid: int
    name: str                  # process name, e.g. "Orca.exe"
    exe: str | None            # executable path; None if access denied
    providers: set[str]        # from endpoint attribution
    connections: int           # matched established connections
    local_runtime: str | None  # "ollama" / "lm-studio" if listening
    adapter: str | None        # agentwatch adapter name if supported
```

Entry point, with injectable dependencies so tests need no network or real
processes:

```python
def detect(
    *,
    resolve=socket.getaddrinfo,
    connections=psutil.net_connections,
    process=psutil.Process,
) -> DetectResult  # usages: list[AiUsage], partial: bool, unresolved: list[str]
```

Algorithm:

1. Resolve every domain in `AI_PROVIDERS` to IPs, building `ip -> {provider}`.
   A domain that fails to resolve goes to `unresolved` and is skipped.
2. `connections(kind="inet")`. On `psutil.AccessDenied`, fall back to
   per-process `Process.net_connections()` (named `connections()` before psutil 6.0; the pin is `psutil>=5.9.0`, so use whichever exists) for processes we can access, and
   set `partial=True` (expected on macOS/Linux when unelevated).
3. Each connection with a PID and a remote IP in the map adds the provider
   to that PID and increments its count.
4. Each `LISTEN` socket on a `LOCAL_LLM_PORTS` port whose owner name matches
   sets `local_runtime`.
5. For each PID found: read name and exe (skip the PID on
   `NoSuchProcess`; `exe=None` on `AccessDenied`). Drop it if
   `name.lower().removesuffix(".exe")` is in `BROWSER_NAMES`. Set
   `adapter` via `discovery.match_process_adapter(cmdline, name)` (reuse,
   no new matching logic).
6. Sort: unsupported (`adapter is None`) first, then by connections, highest
   first.

Resolution happens at every run because CDN IPs rotate, so caching is
skipped. `# ponytail: DNS-based attribution misses DoH/VPN/proxy traffic and
connections opened and closed between scans; add a polling --watch mode if
one-shot misses too much.`

### `agentwatch detect` in `cli.py`

```
agentwatch detect [--json]
```

Table columns: `PID  PROGRAM  PROVIDERS  CONNS  LOCAL  SUPPORTED`. The
SUPPORTED column shows the adapter name, or `no` for unsupported programs,
which are the interesting rows. Footer lines:

- `N programs using AI (M not monitored by agentwatch)`;
- if `partial`: `Partial scan: run as administrator/root to see all processes`;
- if `unresolved`: `Could not resolve: <domains>`.

`--json` prints the same data as a list of objects plus `partial` and
`unresolved`. It always exits 0: this is inventory, not a gate. Styled with
the existing theme helpers like `ps`.

## Privacy

- Reads process names, executable paths, and socket tables. The command
  line is read in memory only to match an existing adapter
  (`match_process_adapter` needs the script path for interpreter-launched
  agents) and is never stored or printed. Files and payloads are never read.
- The only network activity is DNS resolution of the fixed domain list.
  That reveals to the user's DNS resolver that agentwatch looked up AI
  domains. Documented in the README.
- Nothing is written to disk or sent anywhere.

## Error handling

- Any per-process psutil error skips that process; the scan never raises.
- DNS failures per domain go to `unresolved`, and the scan continues.
- If every lookup fails (offline), print a clear message, still run the
  local-runtime check, and exit 0.

## Testing (TDD, failing test first)

All in `tests/test_ai_detect.py` with fake `resolve`, `connections`, and
`process` callables, so there is no real network or processes:

- provider attribution: one PID with two connections to the same provider
  gives count 2 and one provider; shared IP across two domains of the same
  provider gives one provider;
- browser exclusion (`brave.exe`, `chrome`);
- local runtime counted only when port and process name both match; port
  11434 owned by an unrelated process is not counted;
- `AccessDenied` from global `net_connections` falls back and sets `partial`;
- `NoSuchProcess` mid-scan is skipped; `AccessDenied` on exe gives
  `exe=None`;
- DNS failure lands in `unresolved`;
- adapter mapping: a fake `claude.exe` cmdline maps to `claude-code`, an
  unknown program maps to `None`; sort order puts unsupported first;
- CLI: `detect --json` schema; table footer text for the partial and
  unresolved cases (Click `CliRunner`, `detect` monkeypatched).

Gate: full suite + `ruff check .` green.

## Verification plan

- Live on this machine: run `agentwatch detect` with Claude Code, Claude
  Desktop and ChatGPT open. Expect `claude.exe`/`codex.exe` as supported,
  `ChatGPT.exe` and `Orca.exe` as listed, and `brave.exe` absent.
- macOS/Linux behaviour (partial scans) stays fixture-verified only, and the
  README says so.
- Update the CLAUDE.md architecture block and the README command list.
