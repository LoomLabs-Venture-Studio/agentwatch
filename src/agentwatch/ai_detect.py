"""Machine-wide AI-use detection (`agentwatch detect`).

Answers "which programs here are using AI right now?" for any program,
including ones agentwatch has no adapter for. Reads only socket tables and
process name/exe (cmdline is read in memory to match adapters, never
stored or printed). The only network activity is DNS resolution of
AI_PROVIDERS. Design: docs/superpowers/specs/2026-10-09-ai-detect-design.md
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

import psutil

from agentwatch import agents
from agentwatch.agents.copilot_vscode import _CODE_PROCESS_RE
from agentwatch.cursor_discovery import _CURSOR_PROCESS_RE
from agentwatch.discovery import match_process_adapter

# Editor adapters have no process pattern (match_process_adapter skips them),
# so map their gate process names here (#100). One editor can host several
# adapters (#119); candidates are in registry order, first is the default.
_EDITOR_PROCESSES = (
    (_CODE_PROCESS_RE, ("copilot-vscode", "cline")),
    (_CURSOR_PROCESS_RE, ("cursor",)),
)
# Cline sessions that run inside VS Code: the legacy store, or an SDK-store
# session with source "vscode" (agents/cline.py command strings). CLI etc. don't.
_CLINE_IN_VSCODE = ("vscode (cline)", "cline (vscode)")


def _has_live_session(name: str) -> bool:
    try:
        sessions = agents.get(name).discover()
    except Exception:
        return False
    if name == "cline":
        return any(s.command in _CLINE_IN_VSCODE for s in sessions)
    return bool(sessions)


def _editor_label(candidates: tuple[str, ...], live: dict[str, bool]) -> str:
    """Comma-joined candidates with live sessions; the first candidate if none."""
    if len(candidates) == 1:
        return candidates[0]
    for name in candidates:
        if name not in live:
            live[name] = _has_live_session(name)
    return ", ".join(n for n in candidates if live[n]) or candidates[0]

# Provider -> domains. Only domains confirmed in vendor docs; add, don't guess.
AI_PROVIDERS: dict[str, tuple[str, ...]] = {
    # docs.anthropic.com/en/api ; claude.ai web/desktop app
    "anthropic": ("api.anthropic.com", "claude.ai"),
    # platform.openai.com/docs/api-reference ; chatgpt.com app
    "openai": ("api.openai.com", "chatgpt.com", "ab.chatgpt.com"),
    # Google (Gemini/Vertex) left out: its API hosts share front-end IPs with
    # every googleapis.com service (Drive, sign-in), so IP matching can't
    # tell AI traffic apart. Verified 2026-10-09.
    # docs.github.com/en/copilot (network settings allowlist)
    "github-copilot": ("api.githubcopilot.com", "api.individual.githubcopilot.com"),
    # docs.cursor.com (network allowlist)
    "cursor": ("api2.cursor.sh",),
    # docs.mistral.ai/api
    "mistral": ("api.mistral.ai",),
    # docs.x.ai/docs/api-reference
    "xai": ("api.x.ai",),
    # api-docs.deepseek.com
    "deepseek": ("api.deepseek.com",),
    # openrouter.ai/docs/api-reference
    "openrouter": ("openrouter.ai",),
    # console.groq.com/docs/api-reference
    "groq": ("api.groq.com",),
}

# Local LLM runtimes: default port -> runtime. Counted only if the owning
# process name also matches (generic ports like 8000/8080 are too noisy).
LOCAL_LLM_PORTS: dict[int, str] = {11434: "ollama", 1234: "lm-studio"}
_RUNTIME_NAME_TOKENS: dict[str, tuple[str, ...]] = {
    "ollama": ("ollama",),
    "lm-studio": ("lm studio", "lm-studio", "lms"),
}

# Board decision 2026-10-09: report apps and CLIs only, never browsers.
BROWSER_NAMES = frozenset({
    "chrome", "chromium", "msedge", "firefox", "brave", "opera",
    "vivaldi", "arc", "safari", "iexplore",
})

_PROC_ERRORS = (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError)


@dataclass
class AiUsage:
    pid: int
    name: str
    exe: str | None = None
    providers: set[str] = field(default_factory=set)
    connections: int = 0
    local_runtime: str | None = None
    adapter: str | None = None


@dataclass
class DetectResult:
    usages: list[AiUsage]
    partial: bool = False
    unresolved: list[str] = field(default_factory=list)


def _resolve_ips(resolve) -> tuple[dict[str, set[str]], list[str]]:
    ip_map: dict[str, set[str]] = {}
    unresolved: list[str] = []
    for provider, domains in AI_PROVIDERS.items():
        for domain in domains:
            try:
                infos = resolve(domain, 443)
            except OSError:
                unresolved.append(domain)
                continue
            for info in infos:
                ip_map.setdefault(info[4][0], set()).add(provider)
    return ip_map, unresolved


def _connections_by_pid(connections, process_iter):
    """[(pid, conn)] and whether the scan was partial (no global table access)."""
    try:
        return [(c.pid, c) for c in connections(kind="inet")], False
    except (psutil.AccessDenied, OSError):
        pairs = []
        for p in process_iter():
            try:
                get = getattr(p, "net_connections", None) or p.connections
                pairs.extend((p.pid, c) for c in get(kind="inet"))
            except _PROC_ERRORS:
                continue
        return pairs, True


def _remote_ip(c) -> str | None:
    if not c.raddr:
        return None
    return c.raddr.ip.removeprefix("::ffff:")


def detect(
    *,
    resolve=socket.getaddrinfo,
    connections=psutil.net_connections,
    process_iter=psutil.process_iter,
    process=psutil.Process,
) -> DetectResult:
    # ponytail: DNS-based attribution misses DoH/VPN/proxy traffic and
    # connections opened and closed between scans; add a polling --watch
    # mode if one-shot misses too much.
    ip_map, unresolved = _resolve_ips(resolve)
    pairs, partial = _connections_by_pid(connections, process_iter)

    found: dict[int, AiUsage] = {}
    live: dict[str, bool] = {}  # editor adapter -> has live sessions, per run
    listeners: dict[int, str] = {}
    for pid, c in pairs:
        if not pid:
            # Linux reports other users' sockets with pid=None (no AccessDenied).
            if pid is None and _remote_ip(c) in ip_map:
                partial = True
            continue
        if c.status == psutil.CONN_LISTEN and c.laddr and c.laddr.port in LOCAL_LLM_PORTS:
            listeners[pid] = LOCAL_LLM_PORTS[c.laddr.port]
            continue
        ip = _remote_ip(c)
        if ip in ip_map:
            usage = found.setdefault(pid, AiUsage(pid=pid, name=""))
            usage.providers |= ip_map[ip]
            usage.connections += 1

    usages: list[AiUsage] = []
    for pid in found.keys() | listeners.keys():
        try:
            proc = process(pid)
            name = proc.name()
        except _PROC_ERRORS:
            continue
        lowered = name.lower()
        if lowered.removesuffix(".exe") in BROWSER_NAMES:
            continue
        runtime = listeners.get(pid)
        if runtime and not any(t in lowered for t in _RUNTIME_NAME_TOKENS[runtime]):
            runtime = None
        usage = found.get(pid)
        if usage is None and runtime is None:
            continue
        usage = usage or AiUsage(pid=pid, name=name)
        usage.name, usage.local_runtime = name, runtime
        try:
            usage.exe = proc.exe() or None
        except _PROC_ERRORS:
            usage.exe = None
        try:
            cmdline = proc.cmdline()
        except _PROC_ERRORS:
            cmdline = []
        adapter = match_process_adapter(cmdline, name)
        if adapter:
            usage.adapter = adapter.name
        else:
            candidates = next((c for rx, c in _EDITOR_PROCESSES if rx.match(name)), None)
            usage.adapter = candidates and _editor_label(candidates, live)
        usages.append(usage)

    usages.sort(key=lambda u: (u.adapter is not None, -u.connections, u.pid))
    return DetectResult(usages, partial, unresolved)
