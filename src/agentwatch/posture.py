"""Sandbox and permission posture of a running agent process.

``posture(agent)`` answers two questions for one live agent, from what is
cheap to read and already on this machine:

* approvals: does the agent ask before it runs a tool? ("skipped", "on",
  "unknown"), from the process's own argv flags plus, where it is one small
  file, the agent's own config (Claude Code user settings, Codex
  config.toml).
* sandbox: does it run inside a sandbox? ("sandboxed", "container", "none",
  "unknown"), from the process's ancestors (srt, bwrap, firejail, nsjail,
  sandbox-exec, codex-linux-sandbox; docker/podman/containerd), container
  marker files seen through ``/proc/<pid>/root``, and the agent's own
  command sandbox (Codex sandbox modes, Claude Code ``sandbox.enabled``).

``reasons`` are short fixed strings (flag names, never their argv, env or
paths). Every psutil call is wrapped: an error means "unknown". Results are
cached per (pid, create_time), so a reused pid is read again.

Flag sources (checked 2026-11-13; see also the report in the PR):

* Claude Code: ``--dangerously-skip-permissions``, ``--permission-mode
  <mode>`` (``bypassPermissions``), ``--allow-dangerously-skip-permissions``
  (bypass allowed but not on): code.claude.com/docs/en/cli-reference and
  ``claude --help`` 2.1.323. ``permissions.defaultMode: bypassPermissions``
  takes effect from user or managed settings only since 2.1.257
  (code.claude.com/docs/en/settings), so only the user settings file is
  read. ``sandbox.enabled`` (code.claude.com/docs/en/sandboxing): Bash
  commands run sandboxed.
* Codex: ``--dangerously-bypass-approvals-and-sandbox`` with its hidden
  alias ``--yolo`` (openai/codex codex-rs/utils/cli/src/shared_options.rs
  L54-56; cli/src/main.rs L2143-2149 sets approval never + danger-full-access);
  ``-s/--sandbox read-only|workspace-write|danger-full-access``
  (shared_options.rs L40, sandbox_mode_cli_arg.rs L12-16); ``-a/
  --ask-for-approval on-request|never`` (approval_mode_cli_arg.rs L9-15);
  ``--approve-for-me``/``--not-so-yolo`` (shared_options.rs L44-46:
  on-request + workspace-write); ``--full-auto`` (removed in #20133 and
  #36054; was ``-a on-failure --sandbox workspace-write``, tag rust-v0.40.0
  tui/src/cli.rs L53) for older installs. config.toml ``sandbox_mode`` and
  ``approval_policy`` (learn.chatgpt.com/docs/config-file/config-reference).
  The Linux helper re-runs Codex as ``codex-linux-sandbox`` (sandboxing/src/
  landlock.rs L7, arg0/src/lib.rs L72); macOS uses ``/usr/bin/sandbox-exec``
  (sandboxing/src/seatbelt.rs L61).
* Gemini CLI: ``--yolo``/``-y``, ``--approval-mode default|auto_edit|yolo|
  plan`` (google-gemini/gemini-cli packages/cli/src/config/config.ts
  L343-353).
* Copilot CLI: ``--allow-all-tools``, ``--allow-all``, ``--yolo``
  (docs.github.com/en/copilot/reference/copilot-cli-reference/
  cli-command-reference L676, L679, L750).
* sandbox-runtime: bin ``srt`` (anthropic-experimental/sandbox-runtime
  package.json), bubblewrap on Linux, sandbox-exec on macOS (README L5).
"""

from __future__ import annotations

import json
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import TYPE_CHECKING

import psutil

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess

APPROVALS = ("skipped", "on", "unknown")
SANDBOXES = ("sandboxed", "container", "none", "unknown")

MAX_DEPTH = 16  # ancestors walked
_CONFIG_MAX = 1024 * 1024  # a config file larger than this is not read
_CACHE_MAX = 512
_ERRORS = (psutil.Error, OSError, ValueError, TypeError)

# Program names (basename, no .exe) of sandbox launchers seen as an ancestor.
_SANDBOX_PROGRAMS = {
    "srt": "srt",
    "bwrap": "bwrap",
    "firejail": "firejail",
    "nsjail": "nsjail",
    "sandbox-exec": "sandbox-exec",
    "codex-linux-sandbox": "codex sandbox",
}
# Container runtimes whose processes parent a container's first process.
_CONTAINER_PROGRAMS = ("containerd-shim", "conmon", "runc", "crun", "docker-init",
                       "dockerd", "podman")
_CONTAINER_MARKERS = (".dockerenv", "run/.containerenv")
_process = psutil.Process  # tests swap in fakes


def _proc_root(pid: int) -> Path:
    return Path(f"/proc/{pid}/root")


@dataclass(frozen=True)
class Posture:
    approvals: str = "unknown"
    sandbox: str = "unknown"
    confidence: str = "low"
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def risky(self) -> bool:
        """Approvals skipped and no sandbox: nothing stops a bad command."""
        return self.approvals == "skipped" and self.sandbox == "none"

    def to_dict(self) -> dict:
        return {"approvals": self.approvals, "sandbox": self.sandbox,
                "confidence": self.confidence, "reasons": list(self.reasons)}


UNKNOWN = Posture()

_APPROVAL_WORDS = {"skipped": "yolo", "on": "approvals", "unknown": "approvals ?"}
_SANDBOX_WORDS = {"sandboxed": "sandboxed", "container": "container", "none": "no sandbox",
                  "unknown": "sandbox ?"}


def label(p: Posture, sep: str = " · ") -> str:
    """'yolo · no sandbox', 'approvals · sandboxed', ..."""
    return f"{_APPROVAL_WORDS[p.approvals]}{sep}{_SANDBOX_WORDS[p.sandbox]}"


def tone(p: Posture) -> str:
    """'bad' (skipped, no sandbox), 'warn' (skipped otherwise), 'good'
    (approvals on inside a sandbox or container), else 'neutral'."""
    if p.risky:
        return "bad"
    if p.approvals == "skipped":
        return "warn"
    if p.approvals == "on" and p.sandbox in ("sandboxed", "container"):
        return "good"
    return "neutral"


# -- argv ---------------------------------------------------------------


def _flag(argv: list[str], *names: str) -> str | None:
    """Value of the last ``--name value`` / ``--name=value`` / ``-n value`` in
    *argv* (before a bare ``--``); None when absent."""
    value = None
    for i, arg in enumerate(argv):
        if arg == "--":
            break
        for name in names:
            if arg == name and i + 1 < len(argv):
                value = argv[i + 1]
            elif arg.startswith(name + "="):
                value = arg[len(name) + 1:]
    return value


def _has(argv: list[str], *names: str) -> bool:
    for arg in argv:
        if arg == "--":
            return False
        if arg in names:
            return True
    return False


def _read_json(path: Path) -> dict | None:
    try:
        if path.stat().st_size > _CONFIG_MAX:
            return None
        data = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _read_toml(path: Path) -> dict | None:
    try:
        if path.stat().st_size > _CONFIG_MAX:
            return None
        return tomllib.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    except (OSError, ValueError, tomllib.TOMLDecodeError):
        return None


# Each returns (approvals, approvals_high, own_sandbox, own_sandbox_high,
# reasons); own_sandbox is the agent's own command sandbox: "sandboxed",
# "none" (explicitly off) or None (not known from the agent).
_Verdict = tuple[str, bool, str | None, bool, list[str]]


def _claude_code(argv: list[str], pid: int, create_time: float) -> _Verdict:
    from agentwatch.discovery import _claude_home

    reasons: list[str] = []
    settings = _read_json(_claude_home(pid, create_time) / "settings.json") or {}
    sandbox_cfg = settings.get("sandbox")
    own = None
    if isinstance(sandbox_cfg, dict) and sandbox_cfg.get("enabled") is True:
        own = "sandboxed"
        reasons.append("settings: sandbox.enabled")

    if _has(argv, "--dangerously-skip-permissions"):
        return "skipped", True, own, False, ["--dangerously-skip-permissions", *reasons]
    mode = _flag(argv, "--permission-mode")
    if mode is not None:
        if mode == "bypassPermissions":
            return "skipped", True, own, False, ["--permission-mode bypassPermissions",
                                                 *reasons]
        allowed = _has(argv, "--allow-dangerously-skip-permissions")
        return "on", not allowed, own, False, (
            ["--permission-mode", *(["bypass allowed"] if allowed else []), *reasons])
    perms = settings.get("permissions")
    if isinstance(perms, dict) and perms.get("defaultMode") == "bypassPermissions":
        # The file may have changed since the process started: low confidence.
        return "skipped", False, own, False, ["settings: bypassPermissions", *reasons]
    if _has(argv, "--allow-dangerously-skip-permissions"):
        return "on", False, own, False, ["bypass allowed", *reasons]
    return "on", True, own, False, ["default mode", *reasons]


def _codex(argv: list[str], pid: int, create_time: float) -> _Verdict:
    from agentwatch.discovery import _codex_sessions_root

    if _has(argv, "--dangerously-bypass-approvals-and-sandbox", "--yolo"):
        return "skipped", True, "none", True, ["--dangerously-bypass-approvals-and-sandbox"]
    sandbox = _flag(argv, "-s", "--sandbox")
    approval = _flag(argv, "-a", "--ask-for-approval")
    reasons: list[str] = []
    if _has(argv, "--full-auto", "--approve-for-me", "--not-so-yolo"):
        sandbox = sandbox or "workspace-write"
        approval = approval or "on-request"
        reasons.append("--full-auto" if _has(argv, "--full-auto") else "--approve-for-me")
    high_sb, high_ap = sandbox is not None, approval is not None
    if sandbox is not None:
        reasons.append(f"--sandbox {sandbox}" if sandbox in (
            "read-only", "workspace-write", "danger-full-access") else "--sandbox")
    if approval is not None:
        reasons.append(f"--ask-for-approval {approval}" if approval in (
            "never", "on-request", "on-failure", "untrusted") else "--ask-for-approval")
    if sandbox is None or approval is None:
        config = _read_toml(_codex_sessions_root().parent / "config.toml") or {}
        profiles = config.get("profiles")
        profile_name = _flag(argv, "-p", "--profile")
        profile = (profiles.get(profile_name) if isinstance(profiles, dict) and profile_name
                   else None)
        profile = profile if isinstance(profile, dict) else {}
        if sandbox is None:
            sandbox = profile.get("sandbox_mode", config.get("sandbox_mode"))
            if isinstance(sandbox, str):
                reasons.append(f"config: sandbox_mode {sandbox}" if sandbox in (
                    "read-only", "workspace-write", "danger-full-access") else "config")
        if approval is None:
            approval = profile.get("approval_policy", config.get("approval_policy"))
            if isinstance(approval, str):
                reasons.append(f"config: approval_policy {approval}" if approval in (
                    "never", "on-request", "on-failure", "untrusted") else "config")
    approvals = "skipped" if approval == "never" else "on"
    if approval is None:
        reasons.append("default approvals")
    if sandbox == "danger-full-access":
        own = "none"
    else:  # read-only, workspace-write, or Codex's default (one of them)
        own = "sandboxed"
        if sandbox is None:
            reasons.append("default sandbox")
    return approvals, high_ap, own, high_sb, reasons


def _gemini(argv: list[str], pid: int, create_time: float) -> _Verdict:
    mode = _flag(argv, "--approval-mode")
    if mode == "yolo":
        return "skipped", True, None, False, ["--approval-mode yolo"]
    if _has(argv, "--yolo", "-y"):
        return "skipped", True, None, False, ["--yolo"]
    if mode is not None:
        return "on", True, None, False, ["--approval-mode"]
    # Settings can set a default mode; not read: low confidence.
    return "on", False, None, False, ["default mode"]


def _copilot(argv: list[str], pid: int, create_time: float) -> _Verdict:
    for flag in ("--allow-all-tools", "--allow-all", "--yolo"):
        if _has(argv, flag):
            return "skipped", True, None, False, [flag]
    # COPILOT_ALLOW_ALL (env) also skips them; env is never read: low.
    return "on", False, None, False, ["no allow-all flag"]


_AGENTS = {"claude-code": _claude_code, "codex": _codex, "gemini": _gemini,
           "copilot": _copilot}


# -- sandbox ------------------------------------------------------------


def _program(proc: psutil.Process) -> str:
    """Basename (no .exe, lower case) of the program a process runs: the
    script after an interpreter, else argv[0], else its name."""
    from agentwatch.discovery import program_path

    try:
        cmdline = proc.cmdline()
    except _ERRORS:
        cmdline = []
    try:
        name = proc.name()
    except _ERRORS:
        name = ""
    path = program_path(cmdline, name) or name
    base = PurePath(path.replace("\\", "/")).name.lower()
    if base.endswith(".exe"):
        base = base[:-4]
    # srt runs as node .../@anthropic-ai/sandbox-runtime/dist/cli.js
    if "sandbox-runtime" in path.replace("\\", "/").split("/"):
        return "srt"
    return base or name.lower()


def _classify(proc: psutil.Process) -> tuple[str, str] | None:
    """("sandboxed", reason) / ("container", reason) for a launcher process."""
    prog = _program(proc)
    if prog in _SANDBOX_PROGRAMS:
        return "sandboxed", _SANDBOX_PROGRAMS[prog]
    try:
        name = proc.name().lower()
    except _ERRORS:
        name = ""
    for candidate in {prog, name}:
        if any(candidate.startswith(c) for c in _CONTAINER_PROGRAMS):
            return "container", "container runtime"
    return None


def _ancestry(proc: psutil.Process) -> tuple[tuple[str, str] | None, bool]:
    """The nearest sandbox/container launcher among *proc*'s ancestors, and
    whether the walk reached the top (pid 1 or 0) without an error."""
    current = proc
    for _ in range(MAX_DEPTH):
        try:
            parent = current.parent()
        except _ERRORS:
            return None, False
        if parent is None:
            return None, True
        hit = _classify(parent)
        if hit:
            return hit, True
        if parent.pid in (0, 1):
            return None, True
        current = parent
    return None, False


def _container_marker(pid: int) -> bool:
    """/.dockerenv or /run/.containerenv in the process's own root. Read only
    when /proc/<pid>/root is accessible; otherwise False."""
    if not sys.platform.startswith("linux"):
        return False
    root = _proc_root(pid)
    for marker in _CONTAINER_MARKERS:
        try:
            if (root / marker).exists():
                return True
        except OSError:
            return False
    return False


# -- entry --------------------------------------------------------------

_cache: dict[tuple[int, float], Posture] = {}


def posture(agent: AgentProcess) -> Posture:
    """The agent process's posture; ``UNKNOWN`` when its pid is synthetic,
    unreadable, gone, or no longer the agent."""
    from agentwatch import agents as _agents
    from agentwatch.discovery import match_process_adapter

    adapter = _agents.get(agent.agent_type)
    if adapter is None or adapter.kind != "process":
        return UNKNOWN  # editor sessions: synthetic pids, no process of their own
    try:
        proc = _process(agent.pid)
        key = (agent.pid, proc.create_time())
    except _ERRORS:
        return UNKNOWN
    hit = _cache.get(key)
    if hit is not None:
        return hit
    try:
        result = _compute(agent, proc, key[1], match_process_adapter)
    except Exception:  # one odd process must never break ps
        result = UNKNOWN
    if len(_cache) >= _CACHE_MAX:
        _cache.clear()
    _cache[key] = result
    return result


def _compute(agent: AgentProcess, proc: psutil.Process, create_time: float,
             match) -> Posture:
    try:
        argv = proc.cmdline()  # read in memory only: never stored or shown
        name = proc.name()
        if proc.status() == psutil.STATUS_ZOMBIE:
            return UNKNOWN
    except _ERRORS:
        return UNKNOWN
    matched = match(argv, name)
    if matched is None or matched.name != agent.agent_type:
        return UNKNOWN  # a synthetic pid (Codex app-server thread) or a reused one

    rule = _AGENTS.get(agent.agent_type)
    if rule is not None:
        approvals, approvals_high, own, own_high, reasons = rule(argv[1:], agent.pid,
                                                                  create_time)
    else:
        approvals, approvals_high, own, own_high, reasons = "unknown", False, None, False, []

    if sys.platform == "win32":
        # Ancestry does not tell a sandbox on Windows; only an explicit
        # "sandbox off" flag is clear.
        explicit_off = own == "none" and own_high
        sandbox, sandbox_high = ("none", True) if explicit_off else ("unknown", False)
        if not explicit_off:
            reasons.append("windows")
    else:
        launcher, complete = _ancestry(proc)
        if launcher is not None:
            sandbox, why = launcher
            sandbox_high = sandbox == "sandboxed"
            reasons.append(why)
        elif _container_marker(agent.pid):
            sandbox, sandbox_high = "container", False
            reasons.append("container marker")
        elif own is not None:
            sandbox, sandbox_high = own, own_high
            if own == "sandboxed":
                reasons.append("own sandbox")
        else:
            sandbox, sandbox_high = "none", complete
            if not complete:
                reasons.append("ancestry partly unreadable")

    high = approvals_high and sandbox_high and "unknown" not in (approvals, sandbox)
    return Posture(approvals=approvals, sandbox=sandbox,
                   confidence="high" if high else "low", reasons=tuple(reasons))


def clear_cache() -> None:
    _cache.clear()
