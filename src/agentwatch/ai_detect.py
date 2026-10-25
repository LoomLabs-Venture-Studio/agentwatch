"""Machine-wide AI-use detection (`agentwatch detect`).

Answers "which programs here are using AI right now?" for any program,
including ones agentwatch has no adapter for. Reads only socket tables and
process name/exe (cmdline is read in memory to match adapters, never
stored or printed). The only network activity is DNS resolution of
AI_PROVIDERS. Design: docs/superpowers/specs/2026-10-09-ai-detect-design.md
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

import psutil

from agentwatch import agents
from agentwatch.agents.cline import _legacy_editors
from agentwatch.discovery import match_process_adapter

# Editor adapters have no process pattern (match_process_adapter skips them),
# so map their gate process names here (#100). One editor can host several
# adapters (#119): its own adapter first, then Cline, whose legacy store is
# read for every editor in _legacy_editors() (#124, #127). First is default.
_OWN_ADAPTER = {"vscode": "copilot-vscode", "cursor": "cursor"}
_EDITOR_PROCESSES = tuple(
    (rx, label, (_OWN_ADAPTER[label], "cline") if label in _OWN_ADAPTER else ("cline",))
    for label, _, rx in _legacy_editors()
)


def _commands(name: str, cache: dict[str, list[str]]) -> list[str]:
    """Live session commands of adapter *name*; discovered once per run."""
    if name not in cache:
        try:
            cache[name] = [s.command for s in agents.get(name).discover()]
        except Exception:
            cache[name] = []
    return cache[name]


def _is_live(name: str, editor: str, cache: dict[str, list[str]]) -> bool:
    commands = _commands(name, cache)
    if name != "cline":
        return bool(commands)
    # Cline counts only for a task from this editor's legacy store
    # (agents/cline.py command strings). An SDK-store session's source
    # "vscode" doesn't say which fork, so it is credited to stable Code only.
    hosted = {f"{editor} (cline)"} | ({"cline (vscode)"} if editor == "vscode" else set())
    return any(c in hosted for c in commands)


def _editor_label(editor: str, candidates: tuple[str, ...], cache: dict[str, list[str]]) -> str:
    """Comma-joined candidates live in *editor*; the first candidate if none."""
    if len(candidates) == 1:
        return candidates[0]
    return ", ".join(n for n in candidates if _is_live(n, editor, cache)) or candidates[0]


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


@dataclass(frozen=True)
class Runtime:
    """Process names (fnmatch patterns, matched whole against the lowercased
    name minus `.exe`) and default ports of one local LLM runtime. A *weak*
    name only counts if *cmdline_token* is in the cmdline or *exe_token* in
    the exe path. *hosts*: by-design outbound hosts (naming only, `net`)."""

    names: tuple[str, ...]
    ports: tuple[int, ...]
    weak: tuple[str, ...] = ()
    cmdline_token: str | None = None
    exe_token: str | None = None
    hosts: tuple[str, ...] = ()


# Local LLM runtimes, the one source of truth for `detect` and `net`. Sources:
# runtime research 2026-10-15 (PLAYBOOK Sprint 34 Part B). A port maps to
# one runtime only.
# hosts: source-confirmed by-design hosts only, never the UNVERIFIED ones.
LOCAL_RUNTIMES: dict[str, Runtime] = {
    "ollama": Runtime(("ollama", "ollama app"), (11434,),
                      hosts=("registry.ollama.ai", "ollama.com")),
    "llama.cpp": Runtime(("llama-server",), (9931, 8080),
                         hosts=("huggingface.co", "auth.docker.io", "registry-1.docker.io")),
    "llama-cpp-python": Runtime((), (8000,), weak=("python*",), cmdline_token="llama_cpp.server",
                                hosts=("huggingface.co",)),
    # UNVERIFIED: the "lm studio helper*" pattern (macOS Electron helpers);
    # "lm-studio" / "lmstudio" kept from detect's old substring tokens.
    "lm-studio": Runtime(("lm studio", "llmster", "lms", "lm-studio", "lmstudio",
                          "lm studio helper*"), (1234,),
                         hosts=("huggingface.co", "lmstudio.ai", "llmster.lmstudio.ai")),
    # UNVERIFIED: the legacy "jan" name (pre-0.6 Electron Jan.exe).
    "jan": Runtime(("jan-desktop", "jan", "jan-llama-worker"), (1337,),
                   hosts=("apps.jan.ai", "github.com", "raw.githubusercontent.com",
                          "huggingface.co")),
    "gpt4all": Runtime(("gpt4all",), (4891,), weak=("chat",), exe_token="gpt4all",
                       hosts=("gpt4all.io", "api.gpt4all.io", "huggingface.co")),
    # UNVERIFIED: the "msty" / "msty studio" app names and port 10000 (Msty 1.x).
    "msty": Runtime(("msty", "msty studio", "msty-local", "mstysidecar*"), (11964, 11932, 10000),
                    hosts=("registry.ollama.ai", "ollama.com", "huggingface.co", "github.com",
                           "msty.ai", "msty.studio")),
}

# Default port -> runtime. `detect` counts a listener only if the owning
# process is also that runtime by name (generic ports like 8000/8080 are noisy).
LOCAL_LLM_PORTS: dict[int, str] = {
    port: name for name, rt in LOCAL_RUNTIMES.items() for port in rt.ports
}


def _gate(rt: Runtime, proc) -> bool:
    try:
        if rt.cmdline_token:
            return rt.cmdline_token in " ".join(proc.cmdline()).lower()
        return bool(rt.exe_token) and rt.exe_token in (proc.exe() or "").lower()
    except _PROC_ERRORS:
        return False


def runtime_of(name: str, proc=None) -> str | None:
    """The local LLM runtime process *name* belongs to, or None. Exact match,
    never substring; weak names also need *proc* (cmdline / exe read)."""
    n = name.lower().removesuffix(".exe")
    for runtime, rt in LOCAL_RUNTIMES.items():
        if any(fnmatchcase(n, p) for p in rt.names):
            return runtime
        if proc is not None and any(fnmatchcase(n, p) for p in rt.weak) and _gate(rt, proc):
            return runtime
    return None

# Board decision 2026-10-09: report apps and CLIs only, never browsers.
BROWSER_NAMES = frozenset({
    "chrome", "chromium", "msedge", "firefox", "brave", "opera",
    "vivaldi", "arc", "safari", "iexplore",
})

_PROC_ERRORS = (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError)


_VERSION_NAME = re.compile(r"^\d+(\.\d+)+([-+.\w]*)?$")


@dataclass
class AiUsage:
    pid: int
    name: str
    exe: str | None = None
    providers: set[str] = field(default_factory=set)
    connections: int = 0
    local_runtime: str | None = None
    adapter: str | None = None

    @property
    def display_name(self) -> str:
        """Human label for *name*. A version-named binary (Claude Code's
        `claude/versions/2.1.310`) gets the matched adapter's name, else its
        exe's parent directory, else the raw name. `name` itself is unchanged."""
        if not _VERSION_NAME.match(self.name):
            return self.name
        if self.adapter:
            return self.adapter
        parts = re.split(r"[/\\]", self.exe or "")
        parent = parts[-2] if len(parts) >= 2 else ""
        if parent and not _VERSION_NAME.match(parent):
            return parent
        return self.name


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
    sessions: dict[str, list[str]] = {}  # editor adapter -> live commands, per run
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
        if runtime and runtime_of(name, proc) != runtime:
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
            editor = next((e for e in _EDITOR_PROCESSES if e[0].match(name)), None)
            usage.adapter = editor and _editor_label(editor[1], editor[2], sessions)
        usages.append(usage)

    usages.sort(key=lambda u: (u.adapter is not None, -u.connections, u.pid))
    return DetectResult(usages, partial, unresolved)
