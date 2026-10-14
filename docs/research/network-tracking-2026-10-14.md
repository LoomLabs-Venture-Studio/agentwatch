# Per-action network tracking: feasibility spike (2026-10-14)

Question: can agentwatch record the network activity (ingress and egress)
behind every agentic call it tracks, per agent?

Short answer: partly. Recording *which endpoints* each call talked to is
feasible today, unprivileged, on every OS. Recording *how many bytes* went
in and out needs admin/root on Windows and Linux, and per-call byte counts
are often not attributable even then.

This is a spike. No product code was written.

## What exists today

- `ai_detect.py` already attributes live sockets to PIDs via
  `psutil.net_connections` (falling back to per-process
  `net_connections()` when the global table is denied). It is a one-shot
  snapshot and records no byte counts.
- `Action.network_host` / `network_port` (`parser/models.py`) are filled
  only from what the log *declares*: WebFetch-style URLs and `host`/`url`
  tool inputs (`parser/logs.py`, `copilot.py`, `agy.py`, `opencode.py`,
  `cline.py`). Nothing is observed on the wire.
  `detectors/security/network.py` (`NetworkAnomalyDetector`) consumes
  these declared values.
- LLM call size is already logged as tokens (`tokens_in`, `tokens_out`,
  cache tokens). That is a proxy for model-call egress/ingress, not bytes.
- `duration_ms` is set by some parsers only (agy, copilot, copilot_vscode,
  cursor_source, opencode). Others leave it 0.

## Probe (Windows 10, psutil 7.2.2, unprivileged)

Ran against live `claude.exe` / `node.exe` processes on the dev machine:

- `Process.net_connections()` works per PID without admin. A live
  `claude.exe` showed 5 sockets, including `160.79.104.10:443`
  (Anthropic API).
- `Process.io_counters()` works without admin, but on Windows it lumps
  disk, pipe and network I/O together (`read_bytes`, `write_bytes`,
  `other_bytes`). Network bytes cannot be separated out.
- No per-socket byte counter is reachable unprivileged.

## Options, cheapest first

### 1. Endpoint sampler (no admin, cross-platform)

While `watch` / `watch-all` runs, poll `net_connections()` for the agent
PID and its descendants (discovery already builds PPID trees) at about
1 s. Record `(remote ip, port, first seen, last seen)` per connection and
attach to each action the endpoints seen in its window
`[timestamp - duration_ms, timestamp]`, or since the previous action when
`duration_ms` is 0.

Security value: a new detector can flag **undeclared egress**, meaning an
endpoint observed on the wire that no action's `network_host` explains
(for example a Bash `npm install` or a script that phones home).

Limits: connections shorter than the poll interval are missed; no bytes.

### 2. Byte counts (platform-specific, mostly privileged)

| OS | Mechanism | Privilege |
|---|---|---|
| Windows | ETW `Microsoft-Windows-Kernel-Network`, or `GetPerTcpConnectionEStats` | admin (EStats collection must be enabled by admin) |
| Linux | eBPF, or pcap (as nethogs does) | root or `CAP_BPF` / `CAP_NET_RAW` |
| macOS | `nettop -P -x` per-process bytes in/out | possibly unprivileged; **unverified** |

### 3. Log-only estimate (no new collection)

Surface `tokens_in` / `tokens_out` per LLM call as "model traffic". Free,
works for every adapter, but it is a token count, not bytes, and covers
model calls only.

## Attribution limits

- **Shared keep-alive connection.** Agents keep one long-lived HTTP/2
  connection to the LLM API. Bytes from many calls cross one socket, so
  per-call splits are by time window only, which is approximate.
- **In-process tools share the agent's PID.** Claude Code's WebFetch runs
  inside the agent process; only the remote IP separates it from LLM
  traffic.
- **Synthetic-pid adapters.** Cursor composers, Copilot in VS Code,
  Cline, Claude Desktop, ChatGPT-app Codex threads and `kilo serve` run
  many sessions in one editor/app process. Traffic can be attributed to
  the editor, not to a session.
- **Missing durations.** Where a parser leaves `duration_ms` at 0, the
  action window falls back to the gap since the previous action.

## Recommendation

Ship option 1 first: per-action observed endpoints plus an
"undeclared egress" security detector. It is unprivileged, cross-platform
and fits the existing detector plugin pattern. Treat byte counts
(option 2) as a later opt-in privileged backend, only if bandwidth/cost
is an actual requirement.

## Open question for the board

Is the goal **security** (where did the agent connect) or
**bandwidth/cost** (how many bytes)? Security points to option 1;
bandwidth points to option 2 and admin installs.
