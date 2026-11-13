"""Sandbox and permission posture of a running agent process.

``posture(agent)`` answers two questions for one live agent, from what is
cheap to read and already on this machine:

* approvals: who approves the agent's tool calls? "skipped" (nobody),
  "auto" (a classifier/reviewer model, not a human), "on" (a human), or
  "unknown". From the process's own argv plus the agent's config files
  (Claude Code settings, Codex config.toml, profiles and project layers,
  Gemini settings). Claude Code allow rules that pre-approve every command
  (``Bash``, ``Bash(*)``, ``*``) make "on" low confidence.
* sandbox: "sandboxed", "container", "none" or "unknown". From the process's
  ancestors (srt, bwrap, firejail, nsjail, sandbox-exec, codex-linux-sandbox;
  docker/podman/containerd), marker files seen through ``/proc/<pid>/root``
  (.dockerenv, run/.containerenv, .flatpak-info), and the agent's own
  command sandbox (Codex sandbox modes, Claude Code ``sandbox.enabled``,
  Gemini ``--sandbox``).

The rule throughout: when a value is not certain it is "unknown" or low
confidence, never the green "good" tone (``tone()``), which needs high
confidence that a human approves AND a real sandbox. This is the posture the
process started with; a user can still switch modes inside a session.

``reasons`` are short fixed strings (flag names and known values, never argv
text, env or paths). Every psutil call is wrapped: an error means "unknown".
Results are cached per (pid, create_time), so a reused pid is read again.

Argv is parsed per CLI library: clap (Codex), commander (Claude Code,
Copilot CLI) and yargs (Gemini CLI): ``--x V``, ``--x=V``, ``-sV``, ``-s V``,
``-s=V``, grouped short booleans (``-dy``) and, for yargs, ``--x=true``,
``--x true``, ``--no-x``, camelCase names and no dash word as a value. Everything after ``--`` and
every positional (a prompt) is ignored.

Sources (checked 2026-11-13):

* Claude Code 2.1.323: ``--dangerously-skip-permissions``,
  ``--permission-mode <mode>`` (default/manual, acceptEdits, plan, auto,
  dontAsk, bypassPermissions), ``--allow-dangerously-skip-permissions``,
  ``--settings <file-or-json>``, ``--restricted`` (ignores user/project/local
  settings, refuses bypassPermissions), ``--allowedTools``: ``claude --help``
  and code.claude.com/docs/en/cli-reference. Starting mode: flag, then
  ``permissions.defaultMode`` (bypassPermissions/auto from project or local
  files do not apply), then the built-in default: Manual for ``-p`` and when
  ``disableAutoMode`` is "disable", else auto (v2.1.283+; v2.1.228+ on some
  plans; Manual before 2.1.228): code.claude.com/docs/en/permission-modes
  "Which mode a session starts in". ``disableBypassPermissionsMode``:
  docs/en/permissions. Managed settings, above every other level:
  ``/etc/claude-code/managed-settings.json`` (Linux, WSL),
  ``/Library/Application Support/ClaudeCode/managed-settings.json`` (macOS),
  ``C:\\Program Files\\ClaudeCode\\managed-settings.json`` (Windows), plus
  ``managed-settings.d/*.json``: docs/en/managed-settings. ``sandbox.enabled``:
  docs/en/sandboxing.
* Codex (openai/codex main 69231e1; codex-cli 0.160.0):
  ``--dangerously-bypass-approvals-and-sandbox`` alias ``--yolo``,
  ``-s/--sandbox``, ``--approve-for-me`` alias ``--not-so-yolo`` (auto review
  + workspace-write), ``-p/--profile`` (loads ``$CODEX_HOME/<name>.config.toml``
  over config.toml): codex-rs/utils/cli/src/shared_options.rs L34-56;
  ``-a/--ask-for-approval on-request|never``: approval_mode_cli_arg.rs L9-15;
  ``-c/--config key=value`` (value parsed as TOML, else a string);
  layers, lowest first: system ``/etc/codex/config.toml`` <
  ``$CODEX_HOME/config.toml`` < profile < project ``.codex/config.toml`` in
  each directory from the repo root (first ``.git`` up from the cwd, else
  the cwd alone) down to the cwd, the closest winning (honoured only in
  trusted projects, which agentwatch can't see, so a value from there is low
  confidence; ``profile``/``profiles`` are not read from them) < runtime
  overrides (``-c``, then ``-s``/``-a``): config/src/loader/mod.rs L124-136,
  project denylist L90-103, discover_project_root L1709, discover_project_layers
  L1857; a legacy ``profile = "x"`` selector or ``[profiles.x]`` table:
  L293-321; ``approvals_reviewer``: config/src/lib.rs (``auto_review``).
  ``codex exec``/``e``/``review`` force approval_policy Never unless the
  reviewer resolves to auto_review (exec/src/lib.rs L629-633, L844-875).
  Permission profiles ``default_permissions`` / ``[permissions]``
  (config/src/config_toml.rs L237-244; only ``-s`` beats them,
  config/src/permission_config.rs); built-in ``:danger-full-access`` is no
  sandbox (protocol/src/models.rs L419-425), any other name is not followed.
  ``--full-auto`` (removed in #20133/#36054; was on-failure + workspace-write)
  for old installs. Linux helper ``codex-linux-sandbox`` (sandboxing/src/
  landlock.rs L7), macOS ``/usr/bin/sandbox-exec`` (seatbelt.rs L61).
* Gemini CLI (google-gemini/gemini-cli b977656, 0.62.0): ``-y/--yolo``,
  ``--approval-mode default|auto_edit|yolo|plan``, ``-s/--sandbox``, short
  value options m p i w e r o, booleans d s y l: packages/cli/src/config/
  config.ts L298-353; approval mode = flag, else ``--yolo``, else settings
  ``general.defaultApprovalMode`` unless "yolo" (L776-813); ``tools.sandbox``
  setting (sandboxConfig.ts).
* Copilot CLI 1.0.90: ``--allow-all-tools``, ``--allow-all``, ``--yolo``
  (all permissions); ``--allow-tool``, ``--allow-all-paths``,
  ``--allow-all-urls`` (partial): ``copilot --help`` and
  docs.github.com copilot-cli-reference L676-750.
* sandbox-runtime: bin ``srt`` (package.json), bubblewrap / sandbox-exec
  (README L5). Flatpak apps run under bwrap with ``/.flatpak-info`` in their
  root. A bwrap, firejail, nsjail or sandbox-exec ancestor is low
  confidence: what it confines is in its argv (``bwrap --bind / /`` and
  ``sandbox-exec -p "(allow default)"`` confine nothing), which is never
  read. srt and codex-linux-sandbox (fixed agent policies) stay high.
* Gemini argv is yargs-parser's: a word starting with ``-`` is never an
  option's value, a boolean takes a following word only if it is
  ``true``/``false``, and in a short group (``-ms``) every letter but the
  last is a flag.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import TYPE_CHECKING, Any

import psutil

if TYPE_CHECKING:
    from agentwatch.discovery import AgentProcess

APPROVALS = ("skipped", "auto", "on", "unknown")
SANDBOXES = ("sandboxed", "container", "none", "unknown")

MAX_DEPTH = 16  # ancestors walked
_CONFIG_MAX = 1024 * 1024  # a config file larger than this is not read
_CACHE_MAX = 512
_ERRORS = (psutil.Error, OSError, ValueError, TypeError, AttributeError)

# Program names (basename, no .exe) of sandbox launchers seen as an ancestor.
_SANDBOX_PROGRAMS = {
    "srt": "srt",
    "bwrap": "bwrap",
    "flatpak-bwrap": "flatpak",
    "firejail": "firejail",
    "nsjail": "nsjail",
    "sandbox-exec": "sandbox-exec",
    "codex-linux-sandbox": "codex sandbox",
}
# Launchers whose argv decides whether anything is confined (``bwrap --bind /
# /`` and ``sandbox-exec -p "(allow default)"`` confine nothing); argv is
# never read, so they are low confidence.
_CONFIGURABLE_LAUNCHERS = frozenset({"bwrap", "firejail", "nsjail", "sandbox-exec"})
# Container runtimes whose processes parent a container's first process
# (exact program names; containerd-shim also as containerd-shim-runc-v2).
_CONTAINER_PROGRAMS = frozenset({"containerd-shim", "conmon", "runc", "crun", "docker-init",
                                 "dockerd", "podman", "containerd"})
_CONTAINER_SHIM = re.compile(r"containerd-shim(-[a-z0-9]+)*")
_CONTAINER_MARKERS = (".dockerenv", "run/.containerenv")
_FLATPAK_MARKER = ".flatpak-info"
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

_APPROVAL_WORDS = {"skipped": "yolo", "auto": "auto-review", "on": "approvals",
                   "unknown": "approvals ?"}
_SANDBOX_WORDS = {"sandboxed": "sandboxed", "container": "container", "none": "no sandbox",
                  "unknown": "sandbox ?"}


def label(p: Posture, sep: str = " · ") -> str:
    """'yolo · no sandbox', 'auto-review · sandboxed', 'approvals · sandboxed', ..."""
    return f"{_APPROVAL_WORDS[p.approvals]}{sep}{_SANDBOX_WORDS[p.sandbox]}"


def tone(p: Posture) -> str:
    """'bad' (skipped, no sandbox), 'warn' (skipped otherwise), 'good' (a human
    approves inside a real sandbox, high confidence), else 'neutral' (auto
    review, a container, anything not certain)."""
    if p.risky:
        return "bad"
    if p.approvals == "skipped":
        return "warn"
    if p.approvals == "on" and p.sandbox == "sandboxed" and p.confidence == "high":
        return "good"
    return "neutral"


# -- argv ---------------------------------------------------------------


@dataclass(frozen=True)
class _Cli:
    """How one agent's CLI reads its argv."""

    value_long: frozenset[str] = frozenset()  # long options that take a value
    value_short: str = ""  # short options that take a value
    aliases: dict[str, str] = field(default_factory=dict)  # short -> long name
    yargs: bool = False  # --no-x, --x=true, --x true, camelCase


def _kebab(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])([A-Z])", lambda m: "-" + m.group(1).lower(), name)


_YARGS_NUMBER = re.compile(r"-?\d+(\.\d*)?(e-?\d+)?")
_YARGS_DASH = re.compile(r"(-|--)[^-]")
# Marker in _parse's output: a yargs short group where a value option is
# followed by more letters (``-ms``). yargs reads every letter as a flag; if
# that reading is ever wrong the later letters were a value, so a flag found
# only there must not count as proof of anything safe.
_GROUP_AMBIGUOUS = "?group"


def _yargs_short(arg: str, argv: list[str], i: int, cli: _Cli, bools: frozenset[str],
                 out: list) -> int:
    """One yargs short group (``-abc``), the way yargs-parser reads it: each
    letter but the last is a flag unless ``=``, a non-word character or a
    number follows it (then the rest is its value); the last letter takes the
    next word, which is never a dash word, and for a boolean only a literal
    ``true``/``false``. Returns the new index into *argv*."""
    body = arg[1:]
    letters = body[:-1]
    broken = False
    for j, ch in enumerate(letters):
        name = cli.aliases.get(ch, ch)
        rest = body[j + 1:]
        if j + 1 < len(letters) and letters[j + 1] == "=":
            out.append((name, body[j + 2:]))
            broken = True
            break
        if rest == "-":
            out.append((name, "-"))
            continue
        if ch.isascii() and ch.isalpha() and _YARGS_NUMBER.fullmatch(rest):
            out.append((name, rest))
            broken = True
            break
        if j + 1 < len(letters) and re.match(r"[^A-Za-z0-9_]", letters[j + 1]):
            out.append((name, rest))
            broken = True
            break
        out.append((name, True))
        if ch in cli.value_short:
            out.append((_GROUP_AMBIGUOUS, True))
    last = body[-1]
    if broken or last == "-":
        return i
    name = cli.aliases.get(last, last)
    nxt = argv[i] if i < len(argv) else None
    # "--" and "-" do not match yargs' dash test, so they are values here.
    if nxt is not None and not _YARGS_DASH.match(nxt) and name not in bools:
        out.append((name, nxt))
        return i + 1
    if nxt in ("true", "false"):
        out.append((name, nxt))
        return i + 1
    out.append((name, True))
    return i


def _parse(argv: list[str], cli: _Cli, bools: frozenset[str] = frozenset(),
           positionals: list[str] | None = None) -> list:
    """[(long name, value)] in argv order; value is the option's string, True
    for a bare flag, False for yargs ``--no-x``. Positionals (collected into
    *positionals* when given) and everything after ``--`` are dropped.
    *bools*: yargs booleans, which take a following word only when it is
    ``true``/``false``. For yargs a dash word is never an option's value."""
    out: list[tuple[str, Any]] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        i += 1
        if arg == "--":
            break
        if arg.startswith("--") and len(arg) > 2:
            name, eq, val = arg[2:].partition("=")
            value: Any = val if eq else True
            if cli.yargs:
                name = _kebab(name)
                if name.startswith("no-") and not eq:
                    name, value = name[3:], False
            if not eq and value is True and i < len(argv):
                nxt = argv[i]
                if cli.yargs:
                    if name in bools:
                        if nxt in ("true", "false"):
                            value = nxt
                            i += 1
                    elif name in cli.value_long and not nxt.startswith("-"):
                        value = nxt
                        i += 1
                elif name in cli.value_long:
                    value = nxt
                    i += 1
            out.append((name, value))
        elif cli.yargs and arg.startswith("-") and len(arg) > 1 and not (
                _YARGS_NUMBER.fullmatch(arg)):
            i = _yargs_short(arg, argv, i, cli, bools, out)
        elif arg.startswith("-") and len(arg) > 1 and not arg[1].isdigit():
            body = arg[1:]
            for j, ch in enumerate(body):
                name = cli.aliases.get(ch, ch)
                rest = body[j + 1:]
                if ch in cli.value_short:
                    if rest:
                        value = rest[1:] if rest.startswith("=") else rest
                    elif i < len(argv):
                        value = argv[i]
                        i += 1
                    else:
                        value = True
                    out.append((name, value))
                    break
                if rest.startswith("="):  # -y=true
                    out.append((name, rest[1:]))
                    break
                out.append((name, True))
        elif positionals is not None:
            positionals.append(arg)
    return out


def _last(opts: list, *names: str) -> Any:
    """The last value given for any of *names*; None when absent."""
    value = None
    for name, v in opts:
        if name in names:
            value = v
    return value


def _on(value: Any) -> bool:
    """A boolean option's value: a bare flag, or yargs "true"."""
    return value is True or (isinstance(value, str) and value.lower() == "true")


# -- config files -------------------------------------------------------


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _CONFIG_MAX:
            return None
        return path.read_text(encoding="utf-8-sig", errors="replace")
    except (OSError, ValueError):
        return None


_MISSING = object()  # a config file that does not exist (unlike one that can't be read)


def _read_json(path: Path) -> Any:
    """The JSON object in *path*; _MISSING if there is no such file, None if it
    can't be read or parsed."""
    try:
        if not path.exists():
            return _MISSING
    except OSError:
        return None
    text = _read_text(path)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _read_toml(path: Path) -> Any:
    try:
        if not path.exists():
            return _MISSING
    except OSError:
        return None
    text = _read_text(path)
    if text is None:
        return None
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None


def _environ_value(proc, key: str) -> str | None:
    """One variable from the process's own environment (nothing else is
    kept); None when unset or unreadable."""
    try:
        value = proc.environ().get(key)
    except Exception:
        return None
    return value if isinstance(value, str) and value else None


@dataclass
class _Ctx:
    proc: Any
    pid: int
    create_time: float
    cwd: Path | None


# Each rule returns (approvals, approvals_high, own_sandbox, own_sandbox_high,
# reasons); own_sandbox is the agent's own command sandbox: "sandboxed",
# "none" (explicitly off), "unknown" (named but unreadable) or None.
_Verdict = tuple[str, bool, str | None, bool, list[str]]


# -- Claude Code ----------------------------------------------------------

_CLAUDE = _Cli(
    value_long=frozenset({
        "permission-mode", "settings", "setting-sources", "model", "allowed-tools",
        "allowedTools", "disallowed-tools", "disallowedTools", "add-dir", "mcp-config",
        "append-system-prompt", "system-prompt", "system-prompt-file", "session-id",
        "output-format", "input-format", "tools", "agents", "agent", "fallback-model",
        "permission-prompt-tool", "permission-prompts", "debug-file", "betas",
        "plugin-dir", "max-turns", "max-budget-usd", "json-schema", "name",
    }),
    value_short="",
)
_CLAUDE_MODES = {"bypassPermissions": "skipped", "auto": "auto", "default": "on",
                 "manual": "on", "acceptEdits": "on", "plan": "on", "dontAsk": "on"}
# Built-in auto default: v2.1.283+ everywhere (terminal, VS Code), plan-dependent
# from 2.1.228, Manual before.
_AUTO_DEFAULT = (2, 1, 283)
_AUTO_MAYBE = (2, 1, 228)


def _managed_claude_paths() -> list[Path]:
    if sys.platform == "win32":
        base = Path(r"C:\Program Files\ClaudeCode")
    elif sys.platform == "darwin":
        base = Path("/Library/Application Support/ClaudeCode")
    else:
        base = Path("/etc/claude-code")
    paths = [base / "managed-settings.json"]
    try:
        paths += sorted((base / "managed-settings.d").glob("*.json"))
    except OSError:
        pass
    return paths


def _claude_version(proc) -> tuple[int, ...] | None:
    """The native install's version from its executable path
    (``.../claude/versions/2.1.323``); None for npm installs and errors."""
    try:
        exe = proc.exe()
    except Exception:
        return None
    m = re.search(r"[/\\]versions[/\\](\d+)\.(\d+)\.(\d+)$", exe or "")
    return tuple(int(x) for x in m.groups()) if m else None


# Allow rules that pre-approve every shell command (or every tool): with one of
# these a human never sees a Bash prompt, so "approvals on" is not certain.
_ALLOW_EVERYTHING = frozenset({"bash", "bash(*)", "bash(:*)", "*"})


def _allows_everything(rules: Any) -> bool:
    return isinstance(rules, list) and any(
        isinstance(r, str) and r.strip().lower() in _ALLOW_EVERYTHING for r in rules)


def _claude_flag_allows_everything(argv: list[str]) -> bool:
    """``--allowedTools``/``--allowed-tools`` (variadic: every word up to the
    next option, each comma or space separated) holding an allow-all rule."""
    names = ("--allowedTools", "--allowed-tools")
    words: list[str] = []
    collecting = False
    for arg in argv:
        if arg == "--":
            break
        name, eq, val = arg.partition("=")
        if name in names:
            collecting = not eq
            if eq:
                words.append(val)
            continue
        if arg.startswith("-"):
            collecting = False
        elif collecting:
            words.append(arg)
    return _allows_everything([w for word in words for w in re.split(r"[,\s]+", word) if w])


def _claude_code(argv: list[str], ctx: _Ctx) -> _Verdict:
    from agentwatch.discovery import _claude_home

    opts = _parse(argv, _CLAUDE)
    reasons: list[str] = []
    restricted = _last(opts, "restricted") is not None
    if restricted:
        reasons.append("--restricted")

    # Settings layers, highest first: managed, --settings, local, project, user.
    layers: list[tuple[str, dict]] = []
    unreadable = False
    for path in _managed_claude_paths():
        data = _read_json(path)
        if isinstance(data, dict):
            layers.append(("managed", data))
        elif data is None:
            unreadable = True  # a managed file that exists but can't be read
    settings_arg = _last(opts, "settings")
    if isinstance(settings_arg, str):
        data = None
        if settings_arg.lstrip().startswith("{"):
            try:
                data = json.loads(settings_arg)
            except ValueError:
                data = None
        else:
            path = Path(settings_arg).expanduser()
            if not path.is_absolute() and ctx.cwd is not None:
                path = ctx.cwd / path
            data = _read_json(path)
        if isinstance(data, dict):
            layers.append(("cli", data))
        else:
            return "unknown", False, None, False, ["--settings unreadable", *reasons]
    if not restricted:
        if ctx.cwd is not None:
            for kind, name in (("local", "settings.local.json"), ("project", "settings.json")):
                data = _read_json(ctx.cwd / ".claude" / name)
                if isinstance(data, dict):
                    layers.append((kind, data))
        data = _read_json(_claude_home(ctx.pid, ctx.create_time) / "settings.json")
        if isinstance(data, dict):
            layers.append(("user", data))

    def perms(d: dict) -> dict:
        p = d.get("permissions")
        return p if isinstance(p, dict) else {}

    no_bypass = any(perms(d).get("disableBypassPermissionsMode") == "disable"
                    for _, d in layers)
    no_auto = any(perms(d).get("disableAutoMode") == "disable" for _, d in layers)

    own = None
    for _, d in layers:
        sb = d.get("sandbox")
        if isinstance(sb, dict) and isinstance(sb.get("enabled"), bool):
            if sb["enabled"]:
                own = "sandboxed"
                reasons.append("settings: sandbox.enabled")
            break

    allow_all = any(_allows_everything(perms(d).get("allow")) for _, d in layers) or (
        _claude_flag_allows_everything(argv))
    if allow_all:
        reasons.append("all commands pre-approved")
    elif _last(opts, "allowed-tools", "allowedTools") is not None:
        reasons.append("some tools pre-approved")
    if _last(opts, "allow-dangerously-skip-permissions") is not None and not no_bypass:
        reasons.append("bypass allowed")

    # Starting mode: the flag, then permissions.defaultMode, then the default.
    mode: str | None = None
    high = False
    if _last(opts, "dangerously-skip-permissions") is not None:
        mode, high = "bypassPermissions", True
        reasons.insert(0, "--dangerously-skip-permissions")
    elif isinstance(_last(opts, "permission-mode"), str):
        mode, high = _last(opts, "permission-mode"), True
        reasons.insert(0, f"--permission-mode {mode}" if mode in _CLAUDE_MODES
                       else "--permission-mode")
    else:
        for kind, d in layers:
            value = perms(d).get("defaultMode")
            if not isinstance(value, str):
                continue
            if kind in ("local", "project") and value == "bypassPermissions":
                mode = "default"  # not honoured from project files: Manual
            elif kind in ("local", "project") and value == "auto":
                mode = None  # not honoured: the built-in default
            else:
                mode = value
                reasons.insert(0, f"settings: {value}" if value in _CLAUDE_MODES
                               else "settings: defaultMode")
            break
    if mode is None:  # the built-in default
        version = _claude_version(ctx.proc)
        if _last(opts, "print", "p") is not None or no_auto:
            mode, high = "default", True
            reasons.insert(0, "default mode")
        elif version is not None and version >= _AUTO_DEFAULT:
            mode, high = "auto", True
            reasons.insert(0, "default mode (auto)")
        elif version is not None and version < _AUTO_MAYBE:
            mode, high = "default", True
            reasons.insert(0, "default mode")
        else:  # npm install (version unknown) or plan-dependent: probably auto
            mode, high = "auto", False
            reasons.insert(0, "default mode (auto)")

    if mode == "manual":
        mode = "default"
    if mode == "bypassPermissions" and (no_bypass or restricted):
        mode, high = "default", False
        if no_bypass:
            reasons.append("bypass disabled")
    if mode == "auto" and no_auto:
        mode = "default"
        reasons.append("auto disabled")
    approvals = _CLAUDE_MODES.get(mode or "", "unknown")
    if approvals == "unknown":
        high = False
    if unreadable:
        high = False
        reasons.append("managed settings unreadable")
    if "bypass allowed" in reasons or allow_all:
        high = False
    if any(r.startswith("settings: ") and r != "settings: sandbox.enabled" for r in reasons):
        high = False  # a file can change after the process started
    return approvals, high, own, False, reasons


# -- Codex ----------------------------------------------------------------

_CODEX = _Cli(
    value_long=frozenset({
        "sandbox", "ask-for-approval", "config", "profile", "model", "cd", "image",
        "add-dir", "local-provider", "enable", "disable", "output-schema", "color",
        "output-last-message", "remote", "remote-auth-token-env",
    }),
    value_short="sacpmCi",
    aliases={"s": "sandbox", "a": "ask-for-approval", "c": "config", "p": "profile",
             "m": "model", "C": "cd", "i": "image"},
)
_CODEX_APPROVALS = {"never": "skipped", "on-request": "on", "on-failure": "on",
                    "untrusted": "on"}
_CODEX_SANDBOXES = {"read-only": "sandboxed", "workspace-write": "sandboxed",
                    "danger-full-access": "none"}
_CODEX_KEYS = ("approval_policy", "sandbox_mode", "approvals_reviewer")
_CODEX_SYSTEM = Path("/etc/codex/config.toml")  # Unix system layer (loader/mod.rs L127)


def _codex_home(proc) -> Path:
    """The process's own CODEX_HOME (only that key is read), else
    agentwatch's, else ~/.codex."""
    value = _environ_value(proc, "CODEX_HOME") or os.environ.get("CODEX_HOME")
    return Path(value).expanduser() if value else Path.home() / ".codex"


def _toml_value(text: str) -> Any:
    """A ``-c key=value`` value: TOML if it parses, else the raw string (as Codex)."""
    try:
        return tomllib.loads(f"v = {text}")["v"]
    except (tomllib.TOMLDecodeError, KeyError):
        return text.strip()


_PROJECT_WALK_MAX = 64  # directories walked up from the cwd looking for the repo root
# Keys a project layer may not set (loader/mod.rs L90-103); the rest apply.
_CODEX_PROJECT_DENY = frozenset({"profile", "profiles"})
_CODEX_HEADLESS = frozenset({"exec", "e", "review"})  # cli/src/main.rs L155-159


def _codex_cwd(proc, ctx: _Ctx, cd: Any) -> Path | None:
    """The directory Codex loads project config for: the process's own cwd
    (else the discovered working directory), then ``-C/--cd`` against it."""
    try:
        base: Path | None = Path(proc.cwd())
    except _ERRORS:
        base = ctx.cwd
    if isinstance(cd, str) and cd:
        path = Path(cd).expanduser()
        if not path.is_absolute():
            if base is None:
                return None
            path = base / path
        return path
    return base


def _codex_project_layers(cwd: Path | None, home: Path) -> tuple[list[dict], bool]:
    """The project ``.codex/config.toml`` layers, lowest first (the repo root
    down to the cwd, so the closest directory wins), and whether they could
    not all be read. The walk stops at the first directory holding ``.git``
    (a directory with HEAD, or a worktree's file), else only the cwd counts
    (loader/mod.rs discover_project_root L1709-1745, discover_project_layers
    L1857-1985)."""
    if cwd is None:
        return [], True
    try:
        start = Path(os.path.abspath(cwd))
    except (OSError, ValueError):
        return [], True
    chain: list[Path] = []
    root: Path | None = None
    for d in (start, *start.parents):
        if len(chain) >= _PROJECT_WALK_MAX:
            return [], True  # too deep to tell where the project starts
        chain.append(d)
        git = d / ".git"
        try:
            if git.is_file() or (git.is_dir() and (git / "HEAD").exists()):
                root = d
                break
        except OSError:
            return [], True
    dirs = chain if root is not None else chain[:1]
    try:
        home_resolved = home.resolve()
    except (OSError, RuntimeError):
        home_resolved = home
    layers: list[dict] = []
    for d in reversed(dirs):
        dot = d / ".codex"
        try:
            if not dot.is_dir() or dot.resolve() == home_resolved:
                continue
        except (OSError, RuntimeError):
            return [], True
        data = _read_toml(dot / "config.toml")
        if data is _MISSING:
            continue
        if not isinstance(data, dict):
            return [], True  # exists but can't be read or parsed
        layers.append({k: v for k, v in data.items() if k not in _CODEX_PROJECT_DENY})
    return layers, False


def _codex(argv: list[str], ctx: _Ctx) -> _Verdict:
    positionals: list[str] = []
    opts = _parse(argv, _CODEX, positionals=positionals)
    reasons: list[str] = []
    if any(_last(opts, n) is not None for n in (
            "dangerously-bypass-approvals-and-sandbox", "yolo")):
        return "skipped", True, "none", True, ["--dangerously-bypass-approvals-and-sandbox"]
    headless = bool(positionals) and positionals[0] in _CODEX_HEADLESS

    # Runtime overrides: -c key=value (last wins), then the explicit flags.
    overrides: dict[str, Any] = {}
    for name, value in opts:
        if name == "config" and isinstance(value, str) and "=" in value:
            key, _, raw = value.partition("=")
            key = key.strip()
            top = key.split(".", 1)[0]
            if key in (*_CODEX_KEYS, "profile", "default_permissions"):
                overrides[key] = _toml_value(raw)
                reasons.append(f"-c {key}")
            elif top in ("permissions", "project_root_markers"):
                overrides[top] = True  # only whether it is set matters
                reasons.append(f"-c {top}")

    # Config layers, lowest first: system, user, profile, project (repo root
    # down to the cwd), then the -c overrides.
    layers: list[tuple[str, dict]] = []
    unknown_config = False
    home = _codex_home(ctx.proc)
    user: dict = {}
    for path in ([_CODEX_SYSTEM] if sys.platform != "win32" else []) + [home / "config.toml"]:
        data = _read_toml(path)
        if isinstance(data, dict):
            layers.append(("config", data))
            if path.name == "config.toml" and path.parent == home:
                user = data
        elif data is None:
            unknown_config = True  # exists but can't be read or parsed
    profile = _last(opts, "profile")
    if isinstance(profile, str):
        data = _read_toml(home / f"{profile}.config.toml")
        legacy = (user.get("profiles") or {}).get(profile) if isinstance(
            user.get("profiles"), dict) else None
        if isinstance(data, dict):
            layers.append(("config", data))
            reasons.append("--profile")
        elif isinstance(legacy, dict):
            layers.append(("config", legacy))
            reasons.append("--profile")
        else:
            return "unknown", False, "unknown", False, ["--profile unreadable"]
    else:
        selector = overrides.get("profile", user.get("profile"))
        if isinstance(selector, str):
            legacy = (user.get("profiles") or {}).get(selector) if isinstance(
                user.get("profiles"), dict) else None
            if isinstance(legacy, dict):
                layers.append(("config", legacy))
                reasons.append("config: profile")
            else:
                return "unknown", False, "unknown", False, ["config profile unreadable"]

    # A custom project_root_markers moves the project root: not followed.
    project_unknown = "project_root_markers" in overrides or any(
        "project_root_markers" in d for _, d in layers)
    project, unreadable = _codex_project_layers(
        _codex_cwd(ctx.proc, ctx, _last(opts, "cd")), home)
    if unreadable:
        project_unknown = True
    layers += [("project", d) for d in project]
    if project:
        reasons.append("project config")
    if project_unknown:
        reasons.append("project config unknown")

    def setting(key: str) -> tuple[Any, str]:
        """(value, source): 'flag' for a runtime override, 'project' or
        'config' for a file layer, or ''."""
        if key in overrides:
            return overrides[key], "flag"
        for src, layer in reversed(layers):
            if key in layer:
                return layer[key], src
        return None, ""

    approval, ap_src = setting("approval_policy")
    sandbox, sb_src = setting("sandbox_mode")
    reviewer, rv_src = setting("approvals_reviewer")
    if unknown_config:  # a config file Codex reads that we can't: only flags count
        approval, ap_src = (approval, ap_src) if ap_src == "flag" else ("?", "")
        sandbox, sb_src = (sandbox, sb_src) if sb_src == "flag" else ("?", "")
        reasons.append("config unreadable")

    flag_sandbox = _last(opts, "sandbox")
    flag_approval = _last(opts, "ask-for-approval")
    if _last(opts, "approve-for-me", "not-so-yolo") is not None:
        flag_sandbox = flag_sandbox if isinstance(flag_sandbox, str) else "workspace-write"
        reviewer, rv_src = "auto_review", "flag"
        approval, ap_src = (approval, ap_src) if isinstance(flag_approval, str) else (
            "on-request", "flag")
        reasons.append("--approve-for-me")
    elif _last(opts, "full-auto") is not None:
        flag_sandbox = flag_sandbox if isinstance(flag_sandbox, str) else "workspace-write"
        flag_approval = flag_approval if isinstance(flag_approval, str) else "on-failure"
        reasons.append("--full-auto")
    if isinstance(flag_sandbox, str):
        sandbox, sb_src = flag_sandbox, "flag"
        reasons.append(f"--sandbox {flag_sandbox}" if flag_sandbox in _CODEX_SANDBOXES
                       else "--sandbox")
    if isinstance(flag_approval, str):
        approval, ap_src = flag_approval, "flag"
        reasons.append(f"--ask-for-approval {flag_approval}" if flag_approval
                       in _CODEX_APPROVALS else "--ask-for-approval")
    for key, value, src in (("approval_policy", approval, ap_src),
                            ("sandbox_mode", sandbox, sb_src)):
        if src in ("config", "project"):
            reasons.append(f"config: {key} {value}" if isinstance(value, str) and value in (
                *_CODEX_APPROVALS, *_CODEX_SANDBOXES) else f"config: {key}")

    if approval is None:
        approvals = "unknown" if unknown_config else "on"
        if not unknown_config and not headless:
            reasons.append("default approvals")
    elif isinstance(approval, str) and approval in _CODEX_APPROVALS:
        approvals = _CODEX_APPROVALS[approval]
    else:
        approvals = "unknown"  # a granular table or a value this version doesn't know
    auto_review = reviewer == "auto_review"
    if approvals == "on" and auto_review:
        approvals = "auto"
        if rv_src in ("config", "project"):
            reasons.append("config: approvals_reviewer auto_review")
    # The reviewer could come from a project layer we can't see.
    reviewer_sure = rv_src == "flag" or (rv_src == "config" and not project_unknown)
    approvals_high = ap_src == "flag" and approvals != "unknown" and (
        approvals != "auto" or rv_src == "flag") and (
        rv_src == "flag" or not project_unknown) and rv_src != "project"

    if headless:
        # codex exec forces approval_policy Never (above -c approval_policy),
        # unless the resolved reviewer is auto_review: then it rebuilds without
        # it (exec/src/lib.rs L629-633, L844-875). Whether exec honours a root
        # -a is not confirmed: unknown.
        reasons.append("codex exec (no approvals)")
        # Whether Never beats -c approval_policy is not proven either.
        if isinstance(_last(opts, "ask-for-approval"), str) or "approval_policy" in overrides:
            approvals, approvals_high = "unknown", False
        elif auto_review:
            approvals_high = approvals_high and reviewer_sure
        else:
            approvals = "skipped"
            approvals_high = not (unknown_config or project_unknown or rv_src == "project")

    # Permission profiles: default_permissions (a named profile) or a
    # [permissions] table (config_toml.rs L237-244). Only -s beats them
    # (permission config resolve_permission_config); a built-in
    # ":danger-full-access" is no sandbox, any other name is not followed.
    named, named_src = None, ""
    for src, layer in layers:
        if "default_permissions" in layer:
            named, named_src = layer["default_permissions"], src
        elif "sandbox_mode" in layer and named is not None:
            named, named_src = None, ""  # a later layer's sandbox_mode wins
    if "default_permissions" in overrides:
        named, named_src = overrides["default_permissions"], "flag"
    elif "sandbox_mode" in overrides:
        named, named_src = None, ""
    permissions_set = named is not None or "permissions" in overrides or any(
        "permissions" in d for _, d in layers)
    # Any selector anywhere, even one a later sandbox_mode beats: not certain.
    selector_seen = permissions_set or "default_permissions" in overrides or any(
        "default_permissions" in d for _, d in layers)
    if selector_seen:
        reasons.append("permission profile")

    if sb_src == "flag" and isinstance(flag_sandbox, str):
        own = _CODEX_SANDBOXES.get(flag_sandbox, "unknown")
        own_high = own != "unknown" and not selector_seen and not project_unknown
    elif named is not None:
        own = "none" if named == ":danger-full-access" else "unknown"
        own_high = own == "none" and named_src == "flag"
    elif permissions_set:
        own, own_high = "unknown", False
    else:
        if sandbox is None:
            own = "unknown" if unknown_config else "sandboxed"
            if not unknown_config:
                reasons.append("default sandbox")
        elif isinstance(sandbox, str) and sandbox in _CODEX_SANDBOXES:
            own = _CODEX_SANDBOXES[sandbox]
        else:
            own = "unknown"
        own_high = sb_src == "flag" and own != "unknown" and not (
            project_unknown or selector_seen)
    return approvals, approvals_high, own, own_high, reasons


# -- Gemini CLI -----------------------------------------------------------

_GEMINI = _Cli(
    value_long=frozenset({
        "model", "prompt", "prompt-interactive", "worktree", "approval-mode", "policy",
        "admin-policy", "allowed-mcp-server-names", "allowed-tools", "extensions", "resume",
        "session-file", "session-id", "delete-session", "include-directories",
        "output-format", "fake-responses", "fake-responses-non-strict", "record-responses",
    }),
    value_short="mpiwero",
    aliases={"y": "yolo", "s": "sandbox", "d": "debug", "m": "model", "p": "prompt",
             "i": "prompt-interactive", "w": "worktree", "e": "extensions", "r": "resume",
             "o": "output-format", "l": "list-extensions"},
    yargs=True,
)
_GEMINI_BOOLS = frozenset({"yolo", "sandbox", "debug", "list-extensions", "acp",
                           "experimental-acp", "skip-trust", "screen-reader"})
_GEMINI_MODES = {"yolo": "skipped", "auto_edit": "on", "default": "on", "plan": "on"}


def _gemini(argv: list[str], ctx: _Ctx) -> _Verdict:
    from agentwatch.agents.gemini import _gemini_dir

    opts = _parse(argv, _GEMINI, _GEMINI_BOOLS)
    reasons: list[str] = []
    settings = _read_json(_gemini_dir() / "settings.json")
    settings = settings if isinstance(settings, dict) else {}
    general = settings.get("general") if isinstance(settings.get("general"), dict) else {}
    tools = settings.get("tools") if isinstance(settings.get("tools"), dict) else {}

    mode = _last(opts, "approval-mode")
    yolo = _last(opts, "yolo")
    high = True
    if isinstance(mode, str):
        reasons.append(f"--approval-mode {mode}" if mode in _GEMINI_MODES
                       else "--approval-mode")
    elif isinstance(yolo, str) and yolo not in ("true", "false"):
        mode = "?"  # --yolo=1 / =TRUE: how yargs coerces it is not relied on
        reasons.append("--yolo")
    elif _on(yolo):
        mode = "yolo"
        reasons.append("--yolo")
    else:
        default = general.get("defaultApprovalMode")
        high = False  # settings or the built-in default: the file can change
        if isinstance(default, str) and default != "yolo":
            mode = default
            reasons.append(f"settings: {default}" if default in _GEMINI_MODES
                           else "settings: defaultApprovalMode")
        else:
            mode = "default"
            reasons.append("default mode")
    approvals = _GEMINI_MODES.get(mode, "unknown")
    if _last(opts, "allowed-tools") is not None:
        reasons.append("some tools pre-approved")

    flag = _last(opts, "sandbox")
    own = None
    if flag is not None:
        if isinstance(flag, str) and flag not in ("true", "false"):
            own = "unknown"
            reasons.append("--sandbox")
        elif _on(flag) and _last(opts, _GROUP_AMBIGUOUS) is not None:
            own = "unknown"  # read from a group like -ms: not proof of a sandbox
            reasons.append("--sandbox")
        elif _on(flag):
            own = "sandboxed"
            reasons.append("--sandbox")
    else:
        setting = tools.get("sandbox")
        if setting is True or (isinstance(setting, str) and setting not in ("", "false")):
            own = "sandboxed"
            reasons.append("settings: tools.sandbox")
    return approvals, high and approvals != "unknown", own, False, reasons


# -- Copilot CLI ----------------------------------------------------------

_COPILOT = _Cli(
    value_long=frozenset({
        "prompt", "model", "add-dir", "allow-tool", "deny-tool", "available-tools",
        "excluded-tools", "allow-url", "deny-url", "resume", "log-level", "log-dir",
        "agent", "config-dir", "max-autopilot-continues",
    }),
    value_short="pr",
    aliases={"p": "prompt", "r": "resume"},
)


def _copilot(argv: list[str], ctx: _Ctx) -> _Verdict:
    opts = _parse(argv, _COPILOT)
    for flag in ("allow-all-tools", "allow-all", "yolo"):
        if _last(opts, flag) is not None:
            return "skipped", True, None, False, [f"--{flag}"]
    reasons = ["no allow-all flag"]
    if any(_last(opts, n) is not None for n in ("allow-tool", "allow-all-paths",
                                                "allow-all-urls", "allow-url")):
        reasons.append("some tools pre-approved")
    # COPILOT_ALLOW_ALL (env) also skips them; env is never read: low.
    return "on", False, None, False, reasons


_AGENTS = {"claude-code": _claude_code, "codex": _codex, "gemini": _gemini,
           "copilot": _copilot}


# -- sandbox ------------------------------------------------------------


def _program(proc) -> tuple[str, str]:
    """(basename without .exe, lower case; full program path) of what a
    process runs: the script after an interpreter, else argv[0], else its
    name."""
    from agentwatch.discovery import program_path

    try:
        cmdline = proc.cmdline()
    except _ERRORS:
        cmdline = []
    try:
        name = proc.name()
    except _ERRORS:
        name = ""
    path = (program_path(cmdline, name) or name).replace("\\", "/")
    base = PurePath(path).name.lower()
    if base.endswith(".exe"):
        base = base[:-4]
    # srt runs as node .../@anthropic-ai/sandbox-runtime/dist/cli.js
    if "sandbox-runtime" in path.split("/"):
        return "srt", path
    return base or name.lower(), path


def _classify(proc) -> tuple[str, str] | None:
    """("sandboxed", reason) / ("container", reason) / ("flatpak", reason)
    for a launcher process; exact program names only."""
    prog, _ = _program(proc)
    try:
        name = proc.name().lower()
    except _ERRORS:
        name = ""
    for candidate in (prog, name):
        if candidate.startswith("flatpak"):
            return "flatpak", "flatpak"
        if candidate in _SANDBOX_PROGRAMS:
            return "sandboxed", _SANDBOX_PROGRAMS[candidate]
        if candidate in _CONTAINER_PROGRAMS or _CONTAINER_SHIM.fullmatch(candidate):
            return "container", "container runtime"
    return None


def _ancestry(proc) -> tuple[tuple[str, str] | None, str]:
    """The nearest sandbox/container launcher among *proc*'s ancestors, and
    how the walk ended: "top" (pid 1/0 or no parent), "denied" (an error) or
    "deep" (MAX_DEPTH reached). A bwrap with a flatpak process above it is
    reported as ("flatpak", ...)."""
    current = proc
    found: tuple[str, str] | None = None
    for _ in range(MAX_DEPTH):
        try:
            parent = current.parent()
        except _ERRORS:
            return found, "denied"
        if parent is None:
            return found, "top"
        hit = _classify(parent)
        if found is not None:  # look one level above a bwrap for flatpak
            return (("flatpak", "flatpak") if hit and hit[0] == "flatpak" else found), "top"
        if hit:
            if hit[0] == "flatpak" or hit[1] != "bwrap":
                return hit, "top"
            found = hit
        if parent.pid in (0, 1):
            return found, "top"
        current = parent
    return found, "deep"


def _marker(pid: int, names: tuple[str, ...]) -> bool:
    """One of *names* in the process's own root. Read only when
    /proc/<pid>/root is accessible; otherwise False."""
    if not sys.platform.startswith("linux"):
        return False
    root = _proc_root(pid)
    for marker in names:
        try:
            if (root / marker).exists():
                return True
        except OSError:
            return False
    return False


def _flatpak(proc, pid: int) -> bool:
    """A Flatpak app: its program under /app/, or /.flatpak-info in its root
    (FLATPAK_ID is env, never read)."""
    return _program(proc)[1].startswith("/app/") or _marker(pid, (_FLATPAK_MARKER,))


def _container_marker(pid: int) -> bool:
    return _marker(pid, _CONTAINER_MARKERS)


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


def _compute(agent: AgentProcess, proc, create_time: float, match) -> Posture:
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
    ctx = _Ctx(proc=proc, pid=agent.pid, create_time=create_time,
               cwd=agent.working_directory)
    if rule is not None:
        approvals, approvals_high, own, own_high, reasons = rule(argv[1:], ctx)
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
        launcher, ended = _ancestry(proc)
        if launcher == ("sandboxed", "bwrap") and _flatpak(proc, agent.pid):
            launcher = ("flatpak", "flatpak")
        if launcher is not None:
            kind, why = launcher
            sandbox = "sandboxed" if kind == "flatpak" else kind
            sandbox_high = kind == "sandboxed" and why not in _CONFIGURABLE_LAUNCHERS
            reasons.append(why)
            if why in _CONFIGURABLE_LAUNCHERS:
                reasons.append("launcher options not read")
        elif _marker(agent.pid, (_FLATPAK_MARKER,)):
            sandbox, sandbox_high = "sandboxed", False
            reasons.append("flatpak")
        elif _container_marker(agent.pid):
            sandbox, sandbox_high = "container", False
            reasons.append("container marker")
        elif own is not None:
            sandbox, sandbox_high = own, own_high
            if own == "sandboxed":
                reasons.append("own sandbox")
        else:
            sandbox, sandbox_high = "none", ended == "top"
            if ended == "deep":
                reasons.append("ancestry too deep")
            elif ended == "denied":
                reasons.append("ancestry partly unreadable")

    high = approvals_high and sandbox_high and "unknown" not in (approvals, sandbox)
    return Posture(approvals=approvals, sandbox=sandbox,
                   confidence="high" if high else "low", reasons=tuple(reasons))


def clear_cache() -> None:
    _cache.clear()
