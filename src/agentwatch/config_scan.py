"""`agentwatch config-scan`: an offline, read-only audit of AI agents' configs.

Reads MCP server definitions, hooks, the status line, permissions and
tool-facing markdown (skills, commands, agents, CLAUDE.md, plugins) of Claude
Code, Cursor, VS Code (Copilot), Codex, Gemini CLI and Cline, and reports
risky settings. No network calls, nothing is written, secret values are never
shown (masked as in `audit`).

Formats (checked against each tool's docs, 2026-10-31):
- Claude Code: settings.json / settings.local.json (permissions, hooks,
  statusLine, env), .mcp.json and ~/.claude.json (mcpServers,
  projects.<path>.mcpServers); plugins from plugins/installed_plugins.json
  (installPath: .mcp.json, hooks/hooks.json, .claude-plugin/plugin.json,
  skills/commands/agents markdown).
- Cursor: ~/.cursor/mcp.json, <project>/.cursor/mcp.json (mcpServers).
- VS Code: <User>/mcp.json, <project>/.vscode/mcp.json (servers; JSONC).
- Codex: $CODEX_HOME/config.toml, <project>/.codex/config.toml
  ([mcp_servers.<id>], approval_policy, sandbox_mode), $CODEX_HOME/hooks.json.
- Gemini: ~/.gemini/settings.json, <project>/.gemini/settings.json
  (mcpServers, url/httpUrl, trust).
- Cline: <editor User>/globalStorage/saoudrizwan.claude-dev/settings/ and
  ~/.cline/data/settings/ cline_mcp_settings.json (mcpServers).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
import tomllib
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agentwatch.detectors.security.injection import (
    _COMMENT_KEYWORD_RE,
    PromptInjectionDetector,
)
from agentwatch.detectors.security.secret_scanner import (
    _SECRET_PATTERNS,
    _first_live_match,
    _mask_match_value,
    one_line,
)
from agentwatch.parser.security_patterns import is_sensitive_path

SCHEMA = 1
MAX_BYTES = 2 * 1024 * 1024
# ~/.claude.json holds every project's state; only its MCP servers are read.
MAX_CLAUDE_JSON_BYTES = 32 * 1024 * 1024
MAX_WALK_FILES = 2000
SEVERITIES = ("high", "medium", "low")


@dataclass
class Finding:
    severity: str
    kind: str
    agent: str
    file: str
    location: str
    message: str
    why: str
    fix: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    scanned: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)

    def summary(self) -> dict:
        counts = {s: sum(f.severity == s for f in self.findings) for s in SEVERITIES}
        return {**counts, "total": len(self.findings), "files_scanned": len(self.scanned),
                "files_skipped": len(self.skipped)}

    def exit_code(self) -> int:
        """0: nothing above low; 1: a medium; 2: a high (config-scan's top tier)."""
        sev = {f.severity for f in self.findings}
        return 2 if "high" in sev else 1 if "medium" in sev else 0

    def to_json(self) -> dict:
        return {"schema": SCHEMA, "findings": [asdict(f) for f in self.findings],
                "summary": self.summary(), "files_scanned": self.scanned,
                "files_skipped": self.skipped}


def show(path: Path | str) -> str:
    """*path* with the home dir shown as ~."""
    s, home = str(path), str(Path.home())
    if s == home or s.startswith(home + os.sep):
        return "~" + s[len(home):]
    return s


# ---------------------------------------------------------------------------
# Value checks
# ---------------------------------------------------------------------------

# ${VAR}, ${VAR:-x}, $VAR, ${env:VAR}, {env:VAR}, ${input:id}, %VAR%: resolved
# at launch, not a hard-coded value.
_VAR_REF = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_]\w*|\{env:[^}]*\}|%[A-Za-z_]\w*%")


def _secret(key: str, value: str) -> tuple[str, str] | None:
    """(label, masked value) of a hard-coded secret in *value*, else None.

    Judged as ``key=value`` so a key name (API_KEY, Authorization) lets the
    assignment patterns fire; placeholders are skipped by the scanner itself.
    """
    value = _VAR_REF.sub("", value).strip()
    if not value:
        return None
    text = f"{key}={value}" if key else value
    for pattern, label in _SECRET_PATTERNS:
        m = _first_live_match(pattern, label, text)
        if m is not None and m.end() > len(key) + 1:  # the match reaches the value
            return label, _mask_match_value(m, label)
    return None


_NPM_RUNNERS = {"npx", "bunx", "pnpx"}
_NPM_VALUE_FLAGS = {"-p", "--package", "--registry", "--cache", "-c", "--call", "--userconfig"}
_PY_VALUE_FLAGS = {"--from", "--with", "-w", "--python", "-p", "--index", "--index-url",
                   "--default-index", "--extra-index-url", "--with-requirements",
                   "--with-editable", "--spec"}
_DOCKER_VALUE_FLAGS = {"-e", "--env", "-v", "--volume", "-p", "--publish", "--name",
                       "--network", "-w", "--workdir", "--entrypoint", "-u", "--user",
                       "--env-file", "--mount", "--platform", "-l", "--label", "-h",
                       "--hostname", "--add-host", "--pull", "-m", "--memory", "--cpus"}
_SEMVER = re.compile(r"\d+\.\d+\.\d+(?:[-+][\w.-]+)?")
_SHA = re.compile(r"[0-9a-f]{40}")
_IMAGE = re.compile(r"[a-z0-9][a-z0-9._/-]*(?::[\w.-]+)?(?:@sha256:[0-9a-f]{64})?", re.I)


def _base(cmd: str) -> str:
    name = re.split(r"[/\\]", cmd)[-1].lower()
    return re.sub(r"\.(cmd|exe|bat|ps1)$", "", name)


def _runner(argv: list[str]) -> tuple[str, list[str]] | None:
    """(ecosystem, args after the runner) for a package runner, else None."""
    if not argv:
        return None
    b, rest = _base(argv[0]), argv[1:]
    if b in _NPM_RUNNERS:
        return "npm", rest
    if b in ("pnpm", "yarn") and rest[:1] == ["dlx"] or b == "npm" and rest[:1] == ["exec"]:
        return "npm", rest[1:]
    if b == "uvx":
        return "py", rest
    if b == "pipx" and rest[:1] == ["run"]:
        return "py", rest[1:]
    if b == "uv" and rest[:2] == ["tool", "run"]:  # not `uv run`: that runs a local project
        return "py", rest[2:]
    if b in ("docker", "podman") and rest[:1] == ["run"]:
        return "docker", rest[1:]
    return None


def _package(args: list[str], value_flags: set[str], from_flags: set[str]) -> str | None:
    """The package spec: a --from/--package value, else the first positional."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return args[i + 1] if i + 1 < len(args) else None
        if "=" in a and a.startswith("--"):
            flag, val = a.split("=", 1)
            if flag in from_flags:
                return val
        elif a in value_flags:
            if a in from_flags and i + 1 < len(args):
                return args[i + 1]
            i += 1
        elif not a.startswith("-"):
            return a
        i += 1
    return None


def _is_url_ref(spec: str) -> bool:
    return bool(re.match(r"(git\+|git:|github:|gitlab:|bitbucket:|https?://|file:)", spec, re.I))


def _unpinned(argv: list[str]) -> tuple[str, str, str] | None:
    """(severity, spec, reason) when a runner fetches an unpinned package."""
    r = _runner(argv)
    if r is None:
        return None
    eco, args = r
    if eco == "docker":
        img = _package(args, _DOCKER_VALUE_FLAGS, set())
        if not img or not _IMAGE.fullmatch(img) or not re.search(r"[a-z]", img, re.I):
            return None
        if "@sha256:" in img:
            return None
        tag = img.rsplit("/", 1)[-1].partition(":")[2]
        if not tag or tag == "latest":
            return "low", img, "image has no tag or :latest"
        return None
    if eco == "npm":
        spec = _package(args, _NPM_VALUE_FLAGS, {"-p", "--package"})
    else:
        spec = _package(args, _PY_VALUE_FLAGS, {"--from", "--spec"})
    if not spec or spec.startswith((".", "/", "~", "\\")) or re.match(r"[A-Za-z]:[\\/]", spec):
        return None  # a local path
    if spec.startswith("file:"):
        return None
    if _is_url_ref(spec) or eco == "npm" and "/" in spec and not spec.startswith("@"):
        if _SHA.search(spec.rsplit("#", 1)[-1].rsplit("@", 1)[-1]):
            return None  # pinned to a full commit
        return "medium", spec, "comes from a git ref or URL"
    if eco == "npm":
        name, at, ver = spec.rpartition("@") if spec.count("@") > spec.startswith("@") else (
            spec, "", "")
        if at and _SEMVER.fullmatch(ver):
            return None
        return "medium", spec, f"version '{ver}' is not exact" if at else "has no exact version"
    m = re.fullmatch(r"([A-Za-z0-9._\[\],-]+)\s*(==|@)\s*(\S+)", spec)
    if m and re.fullmatch(r"[\w.+!-]+", m.group(3)) and m.group(3) != "latest":
        return None
    return "medium", spec, "has no exact version"


# Credential dirs/files in a permission rule's path (beyond is_sensitive_path).
_CREDENTIAL_DIR = re.compile(
    r"(^|[/\s])\.(aws|ssh|gnupg|kube|docker)(/|\s|\*|$)|(^|/)\.env(?!\.(example|sample|template))\b"
)
_LOOPBACK = re.compile(r"(localhost|127(?:\.\d{1,3}){3}|::1|\[::1\])", re.I)


def _plain_http(url: str) -> str | None:
    """Host of a plain-http URL to a non-loopback host, else None."""
    if not url.lower().startswith("http://") or _VAR_REF.search(url.split("/")[2]):
        return None
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return None
    return None if not host or _LOOPBACK.fullmatch(host) else host


_PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:/\S*/)?"
    r"(?:(?:ba|z|da|k|fi)?sh|python3?|perl|ruby|node)\b"
    r"|\b(?:ba|z)?sh\s+(?:-c\s+)?[\"']?(?:<\(|\$\()\s*(?:curl|wget)\b"
    r"|\b(?:iex|invoke-expression)\b.*\b(?:iwr|irm|invoke-webrequest|invoke-restmethod"
    r"|downloadstring)\b"
    r"|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]*\|\s*(?:iex|invoke-expression)\b",
    re.I,
)

# Invisible or text-reordering chars: zero-width space and word joiners, bidi
# embeddings/overrides/isolates (Trojan Source) and Unicode tag chars (ASCII
# smuggling). ZWJ/ZWNJ only between ASCII letters: emoji and Indic/Persian
# text use them legitimately. LRM/RLM are left out (normal in RTL text).
_HIDDEN_CHAR = re.compile(
    "[\u200b\u2060-\u2064\u202a-\u202e\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
    "|(?<=[A-Za-z])[\u200c\u200d](?=[A-Za-z])"
)
# A small, high-confidence subset of the injection phrases: the full shared
# INJECTION_PATTERNS ("you are now", "act as a", "system:") match ordinary
# skill and agent prompts.
_INJECTION_TEXT = re.compile(
    "|".join(PromptInjectionDetector.HIGH_CONFIDENCE_PATTERNS[:2]
             + [r"<\|im_start\|>", r"<\|system\|>", r"<<SYS>>"]),
    re.I,
)


_QUOTES = set("\"'`\u201c\u2018")


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

_WHY = {
    "secret": "Anyone who can read this file, or a backup or repo that copies it, gets the "
              "credential.",
    "unpinned_package": "Each start runs whatever the registry serves next, so a hijacked "
                        "or typo-squatted release runs on your machine with your agent's access.",
    "plain_http": "Plain http sends every request, and any token in it, readable to anyone "
                  "on the network path.",
    "remote_script": "It downloads code and runs it each time the hook fires; whoever controls "
                     "that URL controls your machine.",
    "hidden_text": "Invisible or reordering characters hide text from you but not from the "
                   "model.",
    "injection_text": "Agents read this file as instructions; text like this tries to override "
                      "the user's.",
    "file_permissions": "Anyone who can write this file can make your agent run commands.",
}
_FIX = {
    "secret": "Move the value to an environment variable (${VAR}) and rotate the credential.",
    "unpinned_package": "Pin an exact version (pkg@1.2.3, pkg==1.2.3) or a commit, and update "
                        "it on purpose.",
    "plain_http": "Use https://, or a loopback address for a local server.",
    "remote_script": "Download the script once, review it, and run the local copy.",
    "hidden_text": "Open the file in an editor that shows invisible characters and delete them.",
    "injection_text": "Read the lines around it; remove the text if you didn't write it.",
    "file_permissions": "chmod go-w the file (and make sure you own it).",
}


class Scanner:
    def __init__(self, project: Path, home: Path | None = None):
        self.home = (home or Path.home()).resolve()
        self.project = project.resolve()
        self.report = Report()
        self._seen: set[Path] = set()

    # -- plumbing -----------------------------------------------------------

    def add(self, severity: str, kind: str, agent: str, file: Path, location: str,
            message: str, why: str | None = None, fix: str | None = None) -> None:
        self.report.findings.append(Finding(
            severity, kind, agent, show(file), location, message,
            why or _WHY.get(kind, ""), fix or _FIX.get(kind, "")))

    def _root(self, path: Path) -> Path:
        """The tree a config file must stay inside: the project, else home."""
        p = Path(os.path.abspath(path))
        if p.is_relative_to(self.project):
            return self.project
        return self.home if p.is_relative_to(self.home) else p.parent

    def read(self, path: Path, agent: str, limit: int = MAX_BYTES) -> str | None:
        """Text of a config file, or None (missing, unsafe, too big). Never
        follows a symlink out of its root; records scanned/skipped files."""
        try:
            path.lstat()
        except OSError:
            return None
        try:
            real = path.resolve(strict=True)
        except OSError:
            return None
        if real in self._seen:
            return None
        if not real.is_relative_to(self._root(path).resolve()):
            self.report.skipped.append({"file": show(path), "reason": "symlink leaves its root"})
            return None
        try:
            st = real.stat()
            if not stat.S_ISREG(st.st_mode):
                return None
            if st.st_size > limit:
                self.report.skipped.append(
                    {"file": show(path), "reason": f"larger than {limit // (1024 * 1024)} MB"})
                return None
            with open(real, "rb") as fh:
                data = fh.read(limit + 1)
        except OSError as exc:
            self.report.skipped.append({"file": show(path), "reason": exc.strerror or "unreadable"})
            return None
        if len(data) > limit:
            return None
        self._seen.add(real)
        self.report.scanned.append({"agent": agent, "file": show(path)})
        self._check_mode(path, st, agent)
        return data.decode("utf-8", errors="replace")

    def load(self, path: Path, agent: str, limit: int = MAX_BYTES) -> Any:
        text = self.read(path, agent, limit)
        if text is None:
            return None
        try:
            if path.suffix == ".toml":
                return tomllib.loads(text)
            try:
                return json.loads(text)
            except ValueError:
                return json.loads(_strip_jsonc(text))
        except (ValueError, tomllib.TOMLDecodeError):
            self.report.skipped.append({"file": show(path), "reason": "could not be parsed"})
            return None

    def _check_mode(self, path: Path, st: os.stat_result, agent: str) -> None:
        reason = _writable_by_others(st)
        if reason:
            self.add("medium", "file_permissions", agent, path, "(file)",
                     f"Config file is {reason}")

    def walk_md(self, base: Path, agent: str, name: str | None = None) -> None:
        """Scan markdown under *base* (a skills/commands/agents dir). Never
        descends into symlinked dirs; at most MAX_WALK_FILES files."""
        if base.is_symlink() or not base.is_dir():
            return
        n = 0
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames
                                 if not d.startswith(".") and d != "node_modules")
            for f in sorted(filenames):
                if (f == name) if name else f.endswith(".md"):
                    n += 1
                    if n > MAX_WALK_FILES:
                        return
                    self.markdown(Path(dirpath) / f, agent)

    # -- checks -------------------------------------------------------------

    def markdown(self, path: Path, agent: str) -> None:
        text = self.read(path, agent)
        if text is not None:
            self.text_checks(text.removeprefix("\ufeff"), agent, path, "(file)")

    def text_checks(self, text: str, agent: str, path: Path, loc: str) -> None:
        """Hidden chars, hidden HTML-comment instructions, override phrases."""
        def at(pos: int) -> str:
            return f"line {_line_of(text, pos)}" if loc == "(file)" else loc

        hidden = list(_HIDDEN_CHAR.finditer(text))
        if hidden:
            first = hidden[0]
            self.add("high", "hidden_text", agent, path, at(first.start()),
                     f"{len(hidden)} invisible character(s), first U+{ord(first.group()):04X} "
                     f"at {at(first.start())}")
        pos = 0
        while (start := text.find("<!--", pos)) >= 0:
            close = text.find("-->", start + 4)
            body = text[start + 4: len(text) if close < 0 else close]
            if _COMMENT_KEYWORD_RE.search(body):
                self.add("medium", "hidden_text", agent, path, at(start),
                         f"HTML comment with instruction words at {at(start)} "
                         "(hidden when the markdown is rendered, read by the model)")
                break
            if close < 0:
                break
            pos = close + 3
        m = _INJECTION_TEXT.search(text)
        if m:
            # A quoted phrase, or a file that names prompt injection, is most
            # likely a warning about it rather than an attack.
            quoted = text[:m.start()].rstrip()[-1:] in _QUOTES
            mention = quoted or re.search(r"injection", text, re.I) is not None
            self.add("low" if mention else "medium", "injection_text", agent, path,
                     at(m.start()), f"Instruction-override phrase at {at(m.start())}"
                     + (" (quoted or in a file about prompt injection)" if mention else ""))

    def mcp_servers(self, servers: Any, agent: str, path: Path, prefix: str) -> None:
        if not isinstance(servers, dict):
            return
        for name, srv in servers.items():
            if isinstance(srv, dict):
                self.server(str(name), srv, agent, path, f"{prefix}.{name}" if prefix else name)

    def server(self, name: str, srv: dict, agent: str, path: Path, loc: str) -> None:
        label = f'MCP server "{one_line(name, 60)}"'
        # 1. hard-coded secrets
        for key in ("env", "headers", "http_headers"):
            vals = srv.get(key)
            if isinstance(vals, dict):
                for k, v in vals.items():
                    self._secret_value(str(k), v, agent, path, f"{loc}.{key}.{k}", label)
        args = srv.get("args") if isinstance(srv.get("args"), list) else []
        for i, a in enumerate(args):
            prev = args[i - 1] if i else ""
            key = prev.lstrip("-") if isinstance(prev, str) and prev.startswith("-") else ""
            self._secret_value(key, a, agent, path, f"{loc}.args[{i}]", label)
        for key in ("url", "httpUrl", "bearer_token"):
            self._secret_value(key if key == "bearer_token" else "", srv.get(key), agent,
                               path, f"{loc}.{key}", label)
        oauth = srv.get("oauth")
        if isinstance(oauth, dict):
            self._secret_value("client_secret", oauth.get("client_secret"), agent, path,
                               f"{loc}.oauth.client_secret", label)
        # 2. unpinned package runners
        cmd = srv.get("command")
        if isinstance(cmd, str):
            argv = [cmd, *(a for a in args if isinstance(a, str))]
            if not args and " " in cmd.strip():
                try:
                    argv = shlex.split(cmd)
                except ValueError:
                    pass
            hit = _unpinned(argv)
            if hit:
                sev, spec, reason = hit
                self.add(sev, "unpinned_package", agent, path, f"{loc}.command",
                         f"{label} runs {one_line(spec, 80)} via {_base(argv[0])}: {reason}",
                         fix="Pin an image digest or version tag." if sev == "low" else None)
        # 3. plain http to a remote host
        for key in ("url", "httpUrl"):
            url = srv.get(key)
            host = _plain_http(url) if isinstance(url, str) else None
            if host:
                auth = any(isinstance(h, dict) and h for h in (
                    srv.get("headers"), srv.get("http_headers"), srv.get("env_http_headers"))
                ) or bool(srv.get("bearer_token_env_var")) or "token=" in url.lower()
                self.add("high" if auth else "medium", "plain_http", agent, path,
                         f"{loc}.{key}",
                         f"{label} talks plain http to {one_line(host, 80)}"
                         + (" and sends credentials" if auth else ""))
        # Gemini: trust bypasses every confirmation for this server's tools.
        if agent == "gemini" and srv.get("trust") is True:
            self.add("medium", "permissions", agent, path, f"{loc}.trust",
                     f"{label} is trusted: its tool calls run without confirmation",
                     "A trusted server's tools run with no prompt, so a compromised or "
                     "manipulated server acts unchecked.",
                     "Remove \"trust\": true and approve calls as they come.")
        desc = srv.get("description")
        if isinstance(desc, str):
            self.text_checks(desc, agent, path, f"{loc}.description")

    def _secret_value(self, key: str, value: Any, agent: str, path: Path, loc: str,
                      label: str) -> None:
        if not isinstance(value, str):
            return
        hit = _secret(key, value)
        if hit:
            kind, masked = hit
            self.add("high", "secret", agent, path, loc,
                     f"{label}: {loc.rsplit('.', 1)[-1]} holds a hard-coded {kind} ({masked})")

    def hooks(self, hooks: Any, agent: str, path: Path, prefix: str = "hooks") -> None:
        if not isinstance(hooks, dict):
            return
        for event, groups in hooks.items():
            if not isinstance(groups, list):
                continue
            for gi, group in enumerate(groups):
                inner = group.get("hooks") if isinstance(group, dict) else None
                for hi, h in enumerate(inner if isinstance(inner, list) else []):
                    if isinstance(h, dict) and isinstance(h.get("command"), str):
                        self.command(h["command"], agent, path,
                                     f"{prefix}.{event}[{gi}].hooks[{hi}].command",
                                     f"{event} hook")

    def command(self, cmd: str, agent: str, path: Path, loc: str, what: str) -> None:
        if _PIPE_TO_SHELL.search(cmd):
            self.add("high", "remote_script", agent, path, loc,
                     f"{what} downloads and runs a script: {one_line(cmd, 100)}")
        hit = _secret("", cmd)
        if hit:
            self.add("high", "secret", agent, path, loc,
                     f"{what} command holds a hard-coded {hit[0]} ({hit[1]})")

    def claude_settings(self, path: Path, user: bool) -> None:
        data = self.load(path, "claude-code")
        if not isinstance(data, dict):
            return
        agent = "claude-code"
        perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
        if perms.get("defaultMode") == "bypassPermissions":
            self.add(
                "high" if user else "medium", "permissions", agent, path,
                "permissions.defaultMode",
                "bypassPermissions: every tool call runs without asking"
                + ("" if user else " (Claude Code 2.1.257+ ignores it in project files; "
                   "older versions apply it)"),
                "Nothing stops a bad command, a prompt-injected action or a wrong file edit.",
                "Use the default mode, or bypassPermissions only inside a container or VM.")
        if data.get("skipDangerousModePermissionPrompt") is True:
            self.add("low", "permissions", agent, path, "skipDangerousModePermissionPrompt",
                     "The warning before bypassPermissions mode is turned off",
                     "Entering bypass mode no longer asks you to confirm.",
                     "Remove the key unless you work only in a sandbox.")
        if data.get("enableAllProjectMcpServers") is True:
            self.add("medium", "permissions", agent, path, "enableAllProjectMcpServers",
                     "Every server in a project's .mcp.json starts without approval",
                     "A cloned repo's .mcp.json can start any command on your machine.",
                     "Remove it and approve servers one by one (enabledMcpjsonServers).")
        allow = perms.get("allow") if isinstance(perms.get("allow"), list) else []
        for i, rule in enumerate(allow):
            if isinstance(rule, str):
                self._allow_rule(rule, path, f"permissions.allow[{i}]")
        self.hooks(data.get("hooks"), agent, path)
        sl = data.get("statusLine")
        if isinstance(sl, dict) and isinstance(sl.get("command"), str):
            self.command(sl["command"], agent, path, "statusLine.command", "Status line")
        env = data.get("env")
        if isinstance(env, dict):
            for k, v in env.items():
                self._secret_value(str(k), v, agent, path, f"env.{k}", "Settings env")

    _BROAD_TOOLS = {"Bash", "PowerShell", "Edit", "Write", "MultiEdit", "NotebookEdit",
                    "WebFetch"}

    def _allow_rule(self, rule: str, path: Path, loc: str) -> None:
        m = re.fullmatch(r"\s*([\w*]+)\s*(?:\((.*)\))?\s*", rule, re.S)
        if not m:
            return
        tool, arg = m.group(1), m.group(2)
        if tool in self._BROAD_TOOLS and (arg is None or arg.strip() in ("*", ":*", "")):
            self.add("medium", "permissions", "claude-code", path, loc,
                     f"Allow rule '{one_line(rule, 60)}' allows every {tool} call",
                     "Every call of this tool runs without a prompt, including ones a "
                     "prompt injection asks for.",
                     f"Allow specific commands or paths, such as {tool}(npm run test *).")
        elif arg and (is_sensitive_path(arg) or _CREDENTIAL_DIR.search(arg)):
            self.add("medium", "permissions", "claude-code", path, loc,
                     f"Allow rule '{one_line(rule, 80)}' covers credential files",
                     "Keys and tokens in these files can be read without a prompt and leak "
                     "into the transcript or a tool call.",
                     "Remove the rule; add a deny rule for these paths instead.")

    def codex_config(self, path: Path) -> None:
        data = self.load(path, "codex")
        if not isinstance(data, dict):
            return
        self.mcp_servers(data.get("mcp_servers"), "codex", path, "mcp_servers")
        if data.get("sandbox_mode") == "danger-full-access":
            never = data.get("approval_policy") == "never"
            self.add("high" if never else "medium", "permissions", "codex", path,
                     "sandbox_mode",
                     "danger-full-access sandbox" + (" with approval_policy = never: commands "
                                                     "run unsandboxed and unasked" if never
                                                     else ": commands run unsandboxed"),
                     "Codex commands can touch any file and the network.",
                     "Use workspace-write (the default) unless you're inside a container.")

    def json_mcp(self, path: Path, agent: str, key: str = "mcpServers") -> None:
        data = self.load(path, agent)
        if isinstance(data, dict):
            self.mcp_servers(data.get(key), agent, path, key)

    def plugin(self, root: Path) -> None:
        agent = "claude-code"
        if root.is_symlink() or not root.is_dir():
            return
        mcp = self.load(root / ".mcp.json", agent)
        if isinstance(mcp, dict):
            servers = mcp.get("mcpServers", mcp)
            self.mcp_servers(servers, agent, root / ".mcp.json",
                             "mcpServers" if "mcpServers" in mcp else "")
        hooks = self.load(root / "hooks" / "hooks.json", agent)
        if isinstance(hooks, dict):
            self.hooks(hooks.get("hooks"), agent, root / "hooks" / "hooks.json")
        manifest = self.load(root / ".claude-plugin" / "plugin.json", agent)
        if isinstance(manifest, dict):
            self.mcp_servers(manifest.get("mcpServers"), agent,
                             root / ".claude-plugin" / "plugin.json", "mcpServers")
            self.hooks(manifest.get("hooks"), agent, root / ".claude-plugin" / "plugin.json")
        for sub in ("skills", "commands", "agents"):
            self.walk_md(root / sub, agent)

    # -- entry --------------------------------------------------------------

    def run(self) -> Report:
        from agentwatch.agents.cline import LEGACY_EXTENSION_ID, _legacy_editors, cline_sessions_dir
        from agentwatch.agents.gemini import _gemini_dir
        from agentwatch.discovery import _codex_sessions_root
        from agentwatch.vscode_paths import default_user_dir

        p, home = self.project, self.home
        claude = Path(os.environ.get("CLAUDE_CONFIG_DIR") or home / ".claude")

        # Claude Code
        self.claude_settings(claude / "settings.json", user=True)
        self.claude_settings(claude / "settings.local.json", user=True)
        self.claude_settings(p / ".claude" / "settings.json", user=False)
        self.claude_settings(p / ".claude" / "settings.local.json", user=False)
        self.json_mcp(p / ".mcp.json", "claude-code")
        cj_path = (claude if os.environ.get("CLAUDE_CONFIG_DIR") else home) / ".claude.json"
        cj = self.load(cj_path, "claude-code", MAX_CLAUDE_JSON_BYTES)
        if isinstance(cj, dict):
            self.mcp_servers(cj.get("mcpServers"), "claude-code", cj_path, "mcpServers")
            projects = cj.get("projects")
            for proj, entry in (projects.items() if isinstance(projects, dict) else ()):
                if isinstance(entry, dict):
                    self.mcp_servers(entry.get("mcpServers"), "claude-code", cj_path,
                                     f'projects["{show(proj)}"].mcpServers')
        for md in (claude / "CLAUDE.md", p / "CLAUDE.md", p / "CLAUDE.local.md",
                   p / ".claude" / "CLAUDE.md"):
            self.markdown(md, "claude-code")
        for base in (claude, p / ".claude"):
            self.walk_md(base / "skills", "claude-code", "SKILL.md")
            self.walk_md(base / "commands", "claude-code")
            self.walk_md(base / "agents", "claude-code")
        installed = self.load(claude / "plugins" / "installed_plugins.json", "claude-code")
        plugins = installed.get("plugins") if isinstance(installed, dict) else None
        for entries in (plugins.values() if isinstance(plugins, dict) else ()):
            for e in entries if isinstance(entries, list) else ():
                ip = e.get("installPath") if isinstance(e, dict) else None
                if isinstance(ip, str) and Path(ip).resolve().is_relative_to(home):
                    self.plugin(Path(ip))

        # Cursor, VS Code (Copilot)
        self.json_mcp(home / ".cursor" / "mcp.json", "cursor")
        self.json_mcp(p / ".cursor" / "mcp.json", "cursor")
        self.json_mcp(default_user_dir("Code") / "mcp.json", "copilot-vscode", "servers")
        self.json_mcp(p / ".vscode" / "mcp.json", "copilot-vscode", "servers")

        # Codex
        codex_home = _codex_sessions_root().parent
        self.codex_config(codex_home / "config.toml")
        self.codex_config(p / ".codex" / "config.toml")
        hooks = self.load(codex_home / "hooks.json", "codex")
        if isinstance(hooks, dict):
            self.hooks(hooks.get("hooks"), "codex", codex_home / "hooks.json")

        # Gemini
        self.json_mcp(_gemini_dir() / "settings.json", "gemini")
        self.json_mcp(p / ".gemini" / "settings.json", "gemini")

        # Cline: each editor's extension store, and the SDK/CLI store
        for _, folder, _ in _legacy_editors():
            self.json_mcp(default_user_dir(folder) / "globalStorage" / LEGACY_EXTENSION_ID
                          / "settings" / "cline_mcp_settings.json", "cline")
        self.json_mcp(cline_sessions_dir().parent / "settings" / "cline_mcp_settings.json",
                      "cline")
        return self.report


_STR = r'("(?:\\.|[^"\\])*")'
_JSONC_COMMENT = re.compile(_STR + r"|//[^\n]*|/\*[\s\S]*?\*/")
_JSONC_COMMA = re.compile(_STR + r"|,(?=\s*[}\]])")


def _strip_jsonc(text: str) -> str:
    """JSON with comments and trailing commas (VS Code's mcp.json) -> JSON."""
    for rx in (_JSONC_COMMENT, _JSONC_COMMA):
        text = rx.sub(lambda m: m.group(1) or "", text)
    return text


@lru_cache(maxsize=64)
def _group_has_others(gid: int, owner: int) -> bool:
    """True if a user other than *owner* is in group *gid*."""
    try:
        import grp
        import pwd

        g = grp.getgrgid(gid)
        names = {u.pw_name: u.pw_uid for u in pwd.getpwall()}
        if any(names.get(m) != owner for m in g.gr_mem):
            return True
        return any(u.pw_gid == gid and u.pw_uid != owner for u in pwd.getpwall())
    except (ImportError, KeyError, OSError):
        return False


def _writable_by_others(st: os.stat_result) -> str | None:
    """Why someone else can change the file, POSIX only; else None."""
    if os.name != "posix":
        return None
    if st.st_uid not in (os.getuid(), 0):
        return "owned by another user"
    if st.st_mode & stat.S_IWOTH:
        return "world-writable"
    if st.st_mode & stat.S_IWGRP and _group_has_others(st.st_gid, st.st_uid):
        return "group-writable by a group with other members"
    return None


def scan(project: Path) -> Report:
    return Scanner(project).run()
