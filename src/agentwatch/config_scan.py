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

import hashlib
import hmac
import ipaddress
import json
import os
import re
import shlex
import socket
import stat
import time
import tomllib
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path, PurePath
from typing import Any
from urllib.parse import urlsplit

from agentwatch import claude_config
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
    # Set only when a config baseline was read or written (config_baseline.py).
    baseline: dict | None = None

    def summary(self) -> dict:
        counts = {s: sum(f.severity == s for f in self.findings) for s in SEVERITIES}
        return {**counts, "total": len(self.findings), "files_scanned": len(self.scanned),
                "files_skipped": len(self.skipped)}

    def exit_code(self) -> int:
        """0: nothing above low; 1: a medium; 2: a high (config-scan's top tier)."""
        sev = {f.severity for f in self.findings}
        return 2 if "high" in sev else 1 if "medium" in sev else 0

    def to_json(self) -> dict:
        out = {"schema": SCHEMA, "findings": [asdict(f) for f in self.findings],
               "summary": self.summary(), "files_scanned": self.scanned,
               "files_skipped": self.skipped}
        if self.baseline is not None:
            out["baseline"] = self.baseline
        return out


def show(path: PurePath | str) -> str:
    """*path* in / form on every OS, with the home dir shown as ~."""
    home = Path.home()
    p = type(home)(path)
    try:
        rel = p.relative_to(home)
    except ValueError:
        return p.as_posix()
    return "~/" + rel.as_posix() if rel.parts else "~"


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


def _unwrap_cmd(argv: list[str]) -> list[str]:
    """*argv* without a leading ``cmd [/d /s ...] /c|/k``, the Windows MCP form."""
    if argv and _base(argv[0]) == "cmd":
        for i, a in enumerate(argv[1:], 1):
            if a.lower() in ("/c", "/k"):
                inner = argv[i + 1:]
                if len(inner) == 1:  # cmd /c "npx -y pkg"
                    try:
                        inner = shlex.split(inner[0])
                    except ValueError:
                        pass
                return _unwrap_cmd(inner)
            if not a.startswith("/"):
                break
    return argv


def _runner(argv: list[str]) -> tuple[str, list[str]] | None:
    """(ecosystem, args after the runner) for a package runner, else None."""
    argv = _unwrap_cmd(argv)
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


def _plain_http(url: str) -> str | None:
    """Host of a plain-http URL to a non-loopback host, else None."""
    if not url.lower().startswith("http://") or _VAR_REF.search(url.split("/")[2]):
        return None
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return None
    return None if not host or _is_loopback(host) else host


def _is_loopback(host: str) -> bool:
    """localhost, 127.0.0.0/8 (short forms like 127.1 too), ::1, 0.0.0.0, ::.
    Parsed locally, never resolved."""
    if host.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:  # inet_aton takes the legacy short forms ("127.1") ip_address refuses
            ip = ipaddress.ip_address(socket.inet_aton(host))
        except OSError:
            return False
    return ip.is_loopback or ip.is_unspecified


_SHELLS = r"(?:(?:ba|z|da|k|fi)?sh|python3?|perl|ruby|node)"
_PIPE_TO_SHELL = re.compile(
    # curl ... | [tee f |] sh  (a single "|", not "||")
    r"\b(?:curl|wget)\b[^;&\n]*?(?<!\|)\|(?!\|)\s*(?:sudo\s+(?:-\S+\s+)*)?(?:/\S*/)?"
    + _SHELLS + r"\b"
    # bash <(curl ...), bash -c "$(curl ...)", python3 -c "$(curl ...)"
    r"|\b" + _SHELLS + r"\s+(?:-\w+\s+)*[\"']?(?:<\(|\$\()\s*(?:curl|wget)\b"
    # eval "$(curl ...)", source <(curl ...), . <(curl ...)
    r"|\beval\s+[\"']?\$\(\s*(?:curl|wget)\b"
    r"|(?:^|[\s;&|(])(?:source|\.)\s+<\(\s*(?:curl|wget)\b"
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
    "[\u200b\u2060-\u2064\u202a-\u202e\u2066-\u2069\ufeff\U000e0000-\U000e007f"
    "\U000e0100-\U000e01ef]"
    "|(?<=[A-Za-z])[\u200c\u200d](?=[A-Za-z])"
)
# Subdivision flags (England, Scotland, Wales) are a black flag plus tag
# letters plus CANCEL TAG: emoji, not smuggled text.
_FLAG = re.compile("\U0001f3f4[\U000e0020-\U000e007e]+\U000e007f")
# A small, high-confidence subset of the injection phrases: the full shared
# INJECTION_PATTERNS ("you are now", "act as a", "system:") match ordinary
# skill and agent prompts.
_INJECTION_TEXT = re.compile(
    "|".join(PromptInjectionDetector.HIGH_CONFIDENCE_PATTERNS[:2]
             + [r"<\|im_start\|>", r"<\|system\|>", r"<<SYS>>"]),
    re.I,
)


_QUOTES = set("\"'`\u201c\u2018")

# Skill scripts (drift pinning). Bounded repeats keep every pattern linear.
# Decode-then-run: `base64 -d | sh`, exec(b64decode(...)), eval(atob(...)),
# PowerShell FromBase64String / -EncodedCommand.
_DECODE_EXEC = re.compile(
    r"\bbase(?:64|32)\b[^\n|]{0,200}?\s(?:-d|-D|--decode)\b[^\n|]{0,200}\|\s*"
    r"(?:sudo\s+)?(?:/\S*/)?" + _SHELLS + r"\b"
    r"|\b(?:exec|eval)\s*\([^\n]{0,200}?\b(?:b64decode|b32decode|b85decode|a85decode|atob"
    r"|fromhex)\b"
    r"|\beval\s*\([^\n]{0,200}?\bBuffer\.from\([^\n]{0,200}?[\"']base64[\"']"
    r"|\b(?:iex|invoke-expression)\b[^\n]{0,200}?\bfrombase64string\b"
    r"|\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,200}?\s-(?:e|ec|enc|encodedcommand)\s+"
    r"[A-Za-z0-9+/=]{16,}",
    re.I,
)
# A download saved to a file: curl -o F / wget -O F / curl -O URL, iwr -OutFile F,
# urlretrieve(URL, F). The first non-empty group is the file.
_DOWNLOAD_TO = re.compile(
    r"\b(?:curl|wget)\b[^\n]{0,300}?\s(?:-o|-O|--output|--output-document)(?:\s+|=)"
    r"[\"']?([^\s\"';&|)]+)"
    r"|\b(?:iwr|invoke-webrequest)\b[^\n]{0,300}?\s-outfile\s+[\"']?([^\s\"';&|)]+)"
    r"|\burlretrieve\s*\([^\n,]{0,300},\s*[\"']([^\"'\n]+)",
    re.I,
)
# Then that file run: sh F, python F, ./F, chmod +x F, . F, & F (PowerShell).
_RUN_FILE = (r"(?:\b(?:(?:ba|z|da|k)?sh|python3?|node|perl|ruby|source|exec|start-process)"
             r"(?:[\"']\s*,\s*|\s+)(?:-\S+\s+){0,4}|\bchmod\s+\S*x\S*\s+|(?<![\w.])\.\s+|&\s*|\./)"
             r"[\"']?[^\s\"']{0,200}?")
# Credential files a script names (guard.secret_label has the last word).
_CRED_REF = re.compile(
    r"\.ssh/id_[\w.-]+|\.aws/credentials\b|(?<![\w.-])\.(?:netrc|npmrc|pypirc)\b"
    r"|\.docker/config\.json\b|\.kube/config\b|(?<![\w.-])\.env(?:\.[\w-]+)?\b"
)
# Data and docs: a credential path named there is not a read.
_DATA_EXT = {".json", ".yaml", ".yml", ".toml", ".txt", ".csv", ".lock", ".ini", ".cfg",
             ".rst", ".html", ".xml", ".svg"}
_SHELL_EXT = {".sh", ".bash", ".zsh", ".ksh", ".dash"}
_SHEBANG_SH = re.compile(r"#![^\n]{0,100}?\b(?:ba|z|da|k)?sh\b")
_MAX_DOWNLOADS = 20
_RUN_AFTER = 20_000  # chars after a download searched for its run
# Script checks: regexes run on windows of at most _WINDOW chars (a line, or
# overlapping slices of a longer one), within _SCRIPT_BUDGET_S CPU per file.
_WINDOW = 2_000
_OVERLAP = 400
_SCRIPT_BUDGET_S = 1.0
_SCRIPT_WHAT = {"remote_script": "downloads and runs a script",
                "encoded_exec": "decodes and runs hidden code",
                "download_exec": "downloads a file and runs it",
                "credential_read": "reads a credential file"}


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
    "encoded_exec": "It decodes hidden code and runs it, so what runs cannot be read in the "
                    "file.",
    "download_exec": "It downloads a file and runs it; whoever controls that URL controls "
                     "your machine.",
    "credential_read": "A skill that reads keys or tokens can leak them into the transcript "
                       "or a tool call.",
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
    "encoded_exec": "Decode it, read what it does, and remove the skill if you didn't write it.",
    "download_exec": "Download the file once, review it, and ship the reviewed copy.",
    "credential_read": "Check why the skill needs this file; remove the skill if it shouldn't.",
}
_SKILL_SCRIPT_WHY = ("A skill script runs with your agent's access; whoever controls that URL "
                     "controls your machine.")


class Scanner:
    def __init__(self, project: Path, home: Path | None = None, *,
                 key: bytes | None = None, scripts: bool = False):
        self.home = (home or Path.home()).resolve()
        self.project = project.resolve()
        self.report = Report()
        self._seen: set[Path] = set()
        # Drift pinning (config_baseline.py): with *key*, each skill dir,
        # plugin and MCP server entry gets an HMAC digest in self.items,
        # (agent, kind, scope, name) -> (section, digest), section "user" or
        # "project". With *scripts*, files in skill dirs are checked too.
        self.key = key
        self.scripts = scripts
        self.items: dict[tuple[str, str, str, str], tuple[str, str]] = {}
        self._in_plugin = False

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
        return data.decode("utf-8-sig", errors="replace")

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
                        self.report.skipped.append({
                            "file": show(base),
                            "reason": f"more than {MAX_WALK_FILES} files; the rest not scanned"})
                        return
                    self.markdown(Path(dirpath) / f, agent)

    # -- checks -------------------------------------------------------------

    def markdown(self, path: Path, agent: str) -> None:
        text = self.read(path, agent)
        if text is not None:
            self.text_checks(text, agent, path, "(file)")

    def text_checks(self, text: str, agent: str, path: Path, loc: str) -> None:
        """Hidden chars, hidden HTML-comment instructions, override phrases."""
        def at(pos: int) -> str:
            return f"line {_line_of(text, pos)}" if loc == "(file)" else loc

        # Flags blanked to spaces of the same length: positions (lines) hold.
        hidden = list(_HIDDEN_CHAR.finditer(_FLAG.sub(lambda m: " " * len(m.group()), text)))
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
                loc = f"{prefix}.{name}" if prefix else str(name)
                self.server(str(name), srv, agent, path, loc)
                if self.key is not None and not self._in_plugin:  # a plugin is pinned whole
                    canon = json.dumps(srv, sort_keys=True, default=str, ensure_ascii=False)
                    self._item(agent, "mcp_server", path, show(path), loc,
                               self._digest(b"mcp\0" + canon.encode("utf-8", "surrogatepass")))

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
        # 2. download-and-run commands, unpinned package runners
        cmd = srv.get("command")
        if isinstance(cmd, str):
            self._secret_value("", cmd, agent, path, f"{loc}.command", label)
            argv = [cmd, *(a for a in args if isinstance(a, str))]
            line = " ".join(argv)
            if _PIPE_TO_SHELL.search(line):
                self.add("high", "remote_script", agent, path, f"{loc}.command",
                         f"{label} downloads and runs a script: {one_line(line, 100)}",
                         "It downloads code and runs it each time it starts; whoever controls "
                         "that URL controls your machine.")
            if not args and " " in cmd.strip():
                try:
                    argv = shlex.split(cmd)
                except ValueError:
                    pass
            hit = _unpinned(argv)
            if hit:
                sev, spec, reason = hit
                self.add(sev, "unpinned_package", agent, path, f"{loc}.command",
                         f"{label} runs {one_line(spec, 80)} via "
                         f"{_base(_unwrap_cmd(argv)[0])}: {reason}",
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
        profiles = data.get("profiles") if isinstance(data.get("profiles"), dict) else {}
        # A profile's approval_policy falls back to the top-level one.
        for prefix, t in [("", data), *((f"profiles.{n}.", t) for n, t in profiles.items()
                                        if isinstance(t, dict))]:
            if t.get("sandbox_mode") != "danger-full-access":
                continue
            never = t.get("approval_policy", data.get("approval_policy")) == "never"
            self.add("high" if never else "medium", "permissions", "codex", path,
                     f"{prefix}sandbox_mode",
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
        self._in_plugin = True
        try:
            self._plugin(root)
        finally:
            self._in_plugin = False

    def _plugin(self, root: Path) -> None:
        agent = "claude-code"
        if root.is_symlink() or not root.is_dir():
            return
        self._plugin_mcp_file(root / ".mcp.json")
        self._plugin_hooks_file(root / "hooks" / "hooks.json")
        mpath = root / ".claude-plugin" / "plugin.json"
        manifest = self.load(mpath, agent)
        if isinstance(manifest, dict):
            # Each of hooks / mcpServers is inline config, a path, or a list of paths.
            for key, inline, load_file in (
                    ("mcpServers", lambda v: self.mcp_servers(v, agent, mpath, "mcpServers"),
                     self._plugin_mcp_file),
                    ("hooks", lambda v: self.hooks(v, agent, mpath), self._plugin_hooks_file)):
                value = manifest.get(key)
                if isinstance(value, dict):
                    inline(value)
                for ref in [value] if isinstance(value, str) else (
                        value if isinstance(value, list) else []):
                    if isinstance(ref, str):
                        target = self._plugin_path(root, ref)
                        if target is not None:
                            load_file(target)
                    elif isinstance(ref, dict):
                        inline(ref)
        for sub in ("skills", "commands", "agents"):
            self.walk_md(root / sub, agent)

    def _plugin_path(self, root: Path, ref: str) -> Path | None:
        """*ref* (``./x.json`` or ``${CLAUDE_PLUGIN_ROOT}/x.json``) under the
        plugin root; None, listed as skipped, if it resolves outside it."""
        rel = ref.replace("${CLAUDE_PLUGIN_ROOT}", ".")
        target = root / rel
        try:
            inside = target.resolve().is_relative_to(root.resolve())
        except OSError:
            inside = False
        if not inside:
            self.report.skipped.append({"file": show(target),
                                        "reason": "path leaves its plugin folder"})
            return None
        return target

    def _plugin_mcp_file(self, path: Path) -> None:
        mcp = self.load(path, "claude-code")
        if isinstance(mcp, dict):
            self.mcp_servers(mcp.get("mcpServers", mcp), "claude-code", path,
                             "mcpServers" if "mcpServers" in mcp else "")

    def _plugin_hooks_file(self, path: Path) -> None:
        hooks = self.load(path, "claude-code")
        if isinstance(hooks, dict):
            self.hooks(hooks.get("hooks"), "claude-code", path)

    # -- drift pinning ------------------------------------------------------

    def _digest(self, data: bytes) -> str | None:
        if self.key is None:
            return None
        return hmac.new(self.key, data, hashlib.sha256).hexdigest()

    def _is_project(self, path: Path) -> bool:
        """True for a config in the --path project (not one in home, unless
        the project sits inside home)."""
        p, proj, home = Path(os.path.abspath(path)), self.project, self.home
        if not p.is_relative_to(proj) or proj == home:
            return False
        return not p.is_relative_to(home) or proj.is_relative_to(home)

    def _item(self, agent: str, kind: str, src: Path, scope: str, name: str,
              digest: str | None) -> None:
        if digest is not None:
            section = "project" if self._is_project(src) else "user"
            self.items[(agent, kind, scope, name)] = (section, digest)

    def skills(self, base: Path) -> None:
        """Pin each skill dir (a dir holding SKILL.md) under *base*, every
        file in it, and check its scripts. Same walk rules as walk_md: a
        symlinked dir is never entered (it is pinned by its link text)."""
        if base.is_symlink() or not base.is_dir():
            return
        scope = show(base)
        for dirpath, dirnames, filenames in os.walk(base):
            here = Path(dirpath)
            dirnames[:] = sorted(d for d in dirnames
                                 if not d.startswith(".") and d != "node_modules")
            for d in list(dirnames):
                if (here / d).is_symlink():
                    dirnames.remove(d)
                    rel = (here / d).relative_to(base).as_posix()
                    self._item("claude-code", "skill", here / d, scope, rel,
                               self._digest(b"dirlink\0" + _link(here / d)))
            if "SKILL.md" in filenames:
                dirnames[:] = []  # this dir is the skill; its subdirs are its files
                rel = here.relative_to(base).as_posix()
                self._item("claude-code", "skill", here, scope, rel,
                           self._tree(here, lambda r: True))

    def plugin_item(self, installed: Path, name: str, root: Path) -> None:
        """Pin a plugin's whole installPath; check the scripts in its skills."""
        if root.is_symlink() or not root.is_dir():
            return
        digest = self._tree(root, lambda r: r.startswith("skills/"))
        self._item("claude-code", "plugin", installed, show(installed), name, digest)

    def _tree(self, top: Path, scripts) -> str | None:
        """HMAC over every file under *top* (path + sha256 of its bytes); with
        self.scripts, files *scripts(rel)* accepts are checked as scripts.
        Symlinks leaving their root and files over MAX_BYTES are pinned by
        link text / size, never read; .git is left out; at most
        MAX_WALK_FILES files."""
        h = hmac.new(self.key, digestmod=hashlib.sha256) if self.key is not None else None
        root = self._root(top).resolve()

        def pin(*parts: str | bytes) -> None:
            if h is not None:
                for part in parts:
                    h.update(part if isinstance(part, bytes)
                             else part.encode("utf-8", "surrogatepass"))
                    h.update(b"\0")

        n = 0
        for dirpath, dirnames, filenames in os.walk(top):
            here = Path(dirpath)
            dirnames.sort()
            for d in list(dirnames):
                if d == ".git" or (here / d).is_symlink():
                    dirnames.remove(d)
                    if d != ".git":
                        pin((here / d).relative_to(top).as_posix(), "dirlink", _link(here / d))
            for f in sorted(filenames):
                n += 1
                if n > MAX_WALK_FILES:
                    pin("truncated")
                    self.report.skipped.append({
                        "file": show(top),
                        "reason": f"more than {MAX_WALK_FILES} files; the rest not "
                                  + ("pinned" if h is not None else "script-checked")})
                    return h.hexdigest() if h is not None else None
                path = here / f
                rel = path.relative_to(top).as_posix()
                try:
                    st = path.lstat()
                    if stat.S_ISLNK(st.st_mode):
                        real = path.resolve(strict=True)
                        if not real.is_relative_to(root):
                            pin(rel, "link-out", _link(path))
                            continue
                        st = real.stat()
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    if st.st_size > MAX_BYTES:
                        pin(rel, "large", str(st.st_size))
                        continue
                    with open(path, "rb") as fh:
                        data = fh.read(MAX_BYTES + 1)
                except OSError:
                    pin(rel, "unreadable")
                    continue
                pin(rel, "file", hashlib.sha256(data).digest())
                if (self.scripts and scripts(rel) and not f.lower().endswith(".md")
                        and len(data) <= MAX_BYTES and b"\0" not in data[:8192]):
                    self.script_checks(data.decode("utf-8", errors="replace"), path)
        return h.hexdigest() if h is not None else None

    def script_checks(self, text: str, path: Path) -> None:
        """Pipe-to-shell, decode-then-run, download-then-run and credential
        reads in a skill's script: config_scan's and guard.py's patterns,
        regexes only (no shell parsing of our own). One finding per kind."""
        from agentwatch import guard

        found: dict[str, tuple[int, str]] = {}  # kind -> (pos, label)
        downloads: list[tuple[int, int, str]] = []  # (start, end, file name)
        deadline = time.process_time() + _SCRIPT_BUDGET_S
        # _PIPE_TO_SHELL backtracks badly on long lines: every pattern but
        # _CRED_REF runs on line windows of at most _WINDOW chars.
        for pos, chunk in _windows(text):
            if time.process_time() > deadline:
                self.report.skipped.append({"file": show(path),
                                            "reason": "script checks stopped (time limit)"})
                break
            for kind, rx in (("remote_script", _PIPE_TO_SHELL), ("encoded_exec", _DECODE_EXEC)):
                if kind not in found and (m := rx.search(chunk)):
                    found[kind] = (pos + m.start(), "")
            if len(downloads) < _MAX_DOWNLOADS:
                downloads.extend((pos + m.start(), pos + m.end(), next(g for g in m.groups() if g))
                                 for m in _DOWNLOAD_TO.finditer(chunk))
        for start, end, name in downloads[:_MAX_DOWNLOADS]:
            base = re.split(r"[/\\]", name.rstrip("/\\"))[-1]
            if base in ("", ".", "..", "-") or time.process_time() > deadline:
                continue
            # The run must follow within _RUN_AFTER chars of the download.
            run = re.compile(_RUN_FILE + re.escape(base) + r"(?![\w.-])", re.I)
            if run.search(text[end: end + _RUN_AFTER]):
                found["download_exec"] = (start, "")
                break
        suffix = path.suffix.lower()
        if suffix not in _DATA_EXT and not path.name.lower().endswith("ignore"):
            for m in _CRED_REF.finditer(text):
                label = guard.secret_label(m.group())
                if label:
                    found["credential_read"] = (m.start(), label)
                    break
        if suffix in _SHELL_EXT or _SHEBANG_SH.match(text):
            reason = guard.check_command(text)
            if reason == guard.REASONS["pipe_shell"]:
                found.setdefault("remote_script", (0, ""))
            elif reason and reason.startswith(guard.REASONS["secret"].split("(")[0]):
                found.setdefault("credential_read",
                                 (0, reason.split("(", 1)[-1].split(")", 1)[0]))
        for kind, (pos, label) in found.items():
            start = text.rfind("\n", 0, pos) + 1
            end = text.find("\n", pos)
            evidence = one_line(text[start: end if end >= 0 else len(text)], 100)
            what = _SCRIPT_WHAT[kind] + (f" ({label})" if label else "")
            self.add("medium" if kind == "credential_read" else "high", kind, "claude-code",
                     path, f"line {_line_of(text, pos)}", f"Skill script {what}: {evidence}",
                     _SKILL_SCRIPT_WHY if kind == "remote_script" else None)

    # -- entry --------------------------------------------------------------

    def run(self) -> Report:
        from agentwatch.agents.cline import LEGACY_EXTENSION_ID, _legacy_editors, cline_sessions_dir
        from agentwatch.agents.gemini import _gemini_dir
        from agentwatch.discovery import _codex_sessions_root
        from agentwatch.vscode_paths import default_user_dir

        p, home = self.project, self.home
        # Every Claude Code config dir: $CLAUDE_CONFIG_DIR and ~/.claude (each
        # existing one once). ~/.claude.json sits in home for ~/.claude, and in
        # the config dir itself for $CLAUDE_CONFIG_DIR.
        claudes = claude_config.config_dirs(home)
        env_claude = claude_config.env_config_dir()
        cj_paths = [home / ".claude.json"]
        if env_claude is not None:
            cj_paths.insert(0, claude_config.resolved(env_claude) / ".claude.json")
        cj_paths = list(dict.fromkeys(cj_paths))

        # Claude Code
        for claude in claudes:
            self.claude_settings(claude / "settings.json", user=True)
            self.claude_settings(claude / "settings.local.json", user=True)
        self.claude_settings(p / ".claude" / "settings.json", user=False)
        self.claude_settings(p / ".claude" / "settings.local.json", user=False)
        self.json_mcp(p / ".mcp.json", "claude-code")
        for cj_path in cj_paths:
            cj = self.load(cj_path, "claude-code", MAX_CLAUDE_JSON_BYTES)
            if not isinstance(cj, dict):
                continue
            self.mcp_servers(cj.get("mcpServers"), "claude-code", cj_path, "mcpServers")
            projects = cj.get("projects")
            for proj, entry in (projects.items() if isinstance(projects, dict) else ()):
                if isinstance(entry, dict):
                    self.mcp_servers(entry.get("mcpServers"), "claude-code", cj_path,
                                     f'projects["{show(proj)}"].mcpServers')
        for md in (*(c / "CLAUDE.md" for c in claudes), p / "CLAUDE.md", p / "CLAUDE.local.md",
                   p / ".claude" / "CLAUDE.md"):
            self.markdown(md, "claude-code")
        for base in (*claudes, p / ".claude"):
            self.walk_md(base / "skills", "claude-code", "SKILL.md")
            self.walk_md(base / "commands", "claude-code")
            self.walk_md(base / "agents", "claude-code")
            if self.key is not None or self.scripts:
                self.skills(base / "skills")
        for claude in claudes:
            ip_file = claude / "plugins" / "installed_plugins.json"
            installed = self.load(ip_file, "claude-code")
            plugins = installed.get("plugins") if isinstance(installed, dict) else None
            for pid, entries in (plugins.items() if isinstance(plugins, dict) else ()):
                for i, e in enumerate(entries if isinstance(entries, list) else ()):
                    ip = e.get("installPath") if isinstance(e, dict) else None
                    if isinstance(ip, str) and Path(ip).resolve().is_relative_to(home):
                        self.plugin(Path(ip))
                        if self.key is not None or self.scripts:
                            self.plugin_item(ip_file, f"{pid}#{i}" if i else str(pid),
                                             Path(ip))

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


def _windows(text: str):
    """(offset, piece) for each line of *text*; a line longer than _WINDOW
    comes as overlapping slices, so a pattern up to _OVERLAP chars long is
    never cut in two."""
    pos = 0
    while pos < len(text):
        nl = text.find("\n", pos)
        end = len(text) if nl < 0 else nl
        if end - pos <= _WINDOW:
            yield pos, text[pos:end]
        else:
            for s in range(pos, end, _WINDOW - _OVERLAP):
                yield s, text[s: min(s + _WINDOW, end)]
                if s + _WINDOW >= end:
                    break
        pos = end + 1


def _link(path: Path) -> bytes:
    """A symlink's own target text (never followed), for pinning."""
    try:
        return os.fsencode(os.readlink(path))
    except OSError:
        return b"?"


def scan(project: Path) -> Report:
    """The config scan with skill-script checks; no drift (config_baseline.run)."""
    return Scanner(project, scripts=True).run()
