"""Detectors for privilege escalation and dangerous commands.

`analyze_command()` checks what a shell command runs, not the text it holds.
The command is split into simple commands with the coach guard's parser
(`guard.split_commands`), so a quoted string, a commit message or an `echo`
argument is not a command. Each simple command is unwrapped (`VAR=value`,
`env`, `timeout`, `nohup`, ... and `sudo`/`doas`/`pkexec`/`run0`, noted
before they are stripped), checked with the guard's rules (`guard.check_argv`:
recursive rm of /, ~, $HOME, ., .., *; mkfs; dd of=/dev/<disk>; a write
redirect to a disk; a download piped to a shell; chmod -R 777 on / or ~) and
with this module's own rules (netcat/socat shells, /dev/tcp redirects,
history wipes, security switched off, setuid chmod, sudo and friends). Nested
scripts are walked the same way: `bash -c`, `su -c`, `eval`, `$(...)`,
backticks, a heredoc or here-string fed to a shell, and `echo ... | sh`.

Fail safe by construction: develop's regexes (LEGACY_DANGEROUS and the
shared PRIVILEGE_COMMAND_PATTERNS) still decide that a CRITICAL finding
exists. The parser only removes or lowers it when it understood every simple
command whose text matched (`_explained`: a data program such as echo/git
commit/grep whose output is not run or kept, or a program its own rules
decide, with no computed word) and nothing put the command in doubt:
unparseable, too long, too deep, out of time, fork-bomb text, arithmetic or
[[ ]], a heredoc / here-string / pipe into a shell or interpreter, an
interpreter payload, a wrapper (eval, su, ssh, docker, xargs, nohup, ...), a
$VAR or substitution as program or target. In doubt, develop's verdict and
severity stand. The parser's own findings are added either way. New forms
develop's regexes miss (rm -fr, rm -r -f, ...) are also matched as raw text,
at HIGH, where the command cannot be read.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from functools import lru_cache

from agentwatch import guard
from agentwatch.guard import _FORK_BOMB, _KEYWORDS, _PREFIXES, _SHELLS, _flags, _prog
from agentwatch.parser.models import ActionBuffer
from agentwatch.parser.security_patterns import PRIVILEGE_COMMAND_PATTERNS

from ..base import Category, SecurityDetector, Severity, Warning
from .secret_scanner import redact_truncate

DANGEROUS = "dangerous_command"
PRIVILEGE = "privilege_escalation"

# Raw-text patterns, matched only where a command cannot be read (see the
# module docstring) and reported at HIGH. They run on lowercased text and
# each starts with a literal (a word boundary is a lookbehind after it), so re
# can skip straight to it: a leading \b costs ~40 ms per MB per pattern.
RAW_DANGEROUS_PATTERNS = [
    # Recursive rm of /, ~, $HOME, ., .., * (not of a path under them)
    r"rm(?<![\w.-]rm)\s+(?:-[\w-]+\s+)*-(?:[a-z]*r[a-z]*|-recursive)\s+(?:-[\w-]+\s+)*"
    r"(?:/|~/?|\$home/?|\$\{home\}/?|\.\.?(?:/\.\.)*/?|\*)(?:\*|\.\*)?(?![\w.~/-])",
    r"mkfs(?<!\wmkfs)(?:\.\w+)?\s",
    r"dd(?<![\w-]dd)\s[^\n;|&]{0,300}?of=/dev/(?!null\b|zero\b|stdout\b|stderr\b|tty\b|fd/)",
    r">\s*/dev/(?:sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|disk\d)",
    r"curl(?<!\wcurl)\b[^\n|;&]{0,500}\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?(?:ba|z|da|k|fi)?sh\b",
    r"wget(?<!\wwget)\b[^\n|;&]{0,500}\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?(?:ba|z|da|k|fi)?sh\b",
    r"chmod(?<!\wchmod)\s+(?:-\S+\s+)*-\w*r\w*\s+(?:-\S+\s+)*(?:0?777|a\+rwx)\s+"
    r"(?:/|~|\$home)(?![\w.-])",
    r"while\s+true[^\n]{0,200}fork",
    r"nc(?<![\w-]nc)\s[^\n;|&]{0,200}?(?<!\S)-[a-z]*[el]\b",
    r"ncat(?<!\wncat)\s[^\n;|&]{0,200}?(?<!\S)-[a-z]*[el]\b",
    r"netcat(?<!\wnetcat)\s[^\n;|&]{0,200}?(?<!\S)-[a-z]*[el]\b",
    r"socat(?<!\wsocat)[^\n]{0,300}?(?:exec|system):",
    r"/dev/(?:tcp|udp)/",
    r"socket[^\n]{0,300}?\.connect\(",
    r"history(?<!\whistory)\s+-c\b",
    r">\s*(?:\S{0,200}/)?\.\w*history(?![\w.])",
    r"rm(?<![\w.-]rm)\s[^\n;|&]{0,200}?(?<![^\s/])\.\w*history(?![\w.])",
    r"shred(?<!\wshred)\s[^\n;|&]{0,200}?(?<![^\s/])\.\w*history(?![\w.])",
    r"truncate(?<!\wtruncate)\s[^\n;|&]{0,200}?(?<![^\s/])\.\w*history(?![\w.])",
    r"setenforce\s+(?:0|permissive)\b",
    r"iptables(?<!\wiptables)[^\n;|&]{0,100}?\s(?:-f|--flush)\b",
    r"ip6tables(?<!\wip6tables)[^\n;|&]{0,100}?\s(?:-f|--flush)\b",
    r"ufw(?<!\wufw)\s+disable\b",
]


def _literal_first(pattern: str) -> tuple[str, re.Pattern[str]]:
    r"""(leading literal, compiled) for a lowercase-text pattern; a leading
    \bword becomes word(?<!\wword)."""
    if m := re.match(r"\\b([a-z]+)(.*)", pattern, re.DOTALL):
        word, rest = m.groups()
        pattern = rf"{word}(?<!\w{word}){rest}"
    literal = re.match(r"(?:[a-z0-9/>.:-]|\\[.$])+", pattern)
    if not literal:
        raise ValueError(f"raw pattern must start with a literal: {pattern}")
    return literal.group().replace("\\", ""), re.compile(pattern)


_RAW_DANGEROUS = [_literal_first(p) for p in RAW_DANGEROUS_PATTERNS]
# The shared privilege patterns, in the same fast form.
_RAW_PRIVILEGE = [_literal_first(p) for p in PRIVILEGE_COMMAND_PATTERNS]

# develop's dangerous_command patterns, unchanged. With the privilege
# patterns above they decide that a finding exists: the parser only lowers
# or removes one when it understands the whole command (see analyze_command).
# Each comes with literals it cannot match without (a cheap pre-check) and
# whether it is quadratic on a long line (`.*` / `.+` twice).
LEGACY_DANGEROUS = [
    (guard.DESTRUCTIVE_PATTERNS[0], ("rm", "-rf"), False),
    (guard.DESTRUCTIVE_PATTERNS[1], ("rm", "-rf"), False),
    (guard.DESTRUCTIVE_PATTERNS[2], ("rm", "-rf"), False),
    (guard.DESTRUCTIVE_PATTERNS[3], (">", "/dev/sd"), False),
    (guard.DESTRUCTIVE_PATTERNS[4], ("mkfs",), False),
    (guard.DESTRUCTIVE_PATTERNS[5], ("dd", "if=", "of=/dev"), True),
    (r":\(\)\{:\|:&\};:", (":(){:|:&};:",), False),
    (r"while\s+true.*fork", ("while", "true", "fork"), True),
    (r"nc\s+-[el]", ("nc",), False),
    (r"ncat\s+-[el]", ("ncat",), False),
    (r"socat\s+.*EXEC", ("socat", "exec"), True),
    (r"bash\s+-i\s+>&\s*/dev/tcp", ("bash", "/dev/tcp"), False),
    (r"python.*socket.*connect", ("python", "socket", "connect"), True),
    (r"/bin/sh\s+-i", ("/bin/sh",), False),
    (r"history\s+-c", ("history",), False),
    (r">\s*~/.bash_history", (">", "bash_history"), False),
    (r"shred.*\.bash_history", ("shred", ".bash_history"), True),
    (r"rm.*\.bash_history", ("rm", ".bash_history"), True),
    (r"setenforce\s+0", ("setenforce",), False),
    (r"iptables\s+-F", ("iptables",), False),
    (r"ufw\s+disable", ("ufw",), False),
]
_LEGACY_D = [(lits, re.compile(p, re.IGNORECASE), quad) for p, lits, quad in LEGACY_DANGEROUS]
_LEGACY_P = [((lit,), re.compile(rx.pattern, re.IGNORECASE), False)
             for lit, rx in _RAW_PRIVILEGE]
_QUADRATIC_MAX = 20_000  # past this a quadratic pattern counts as matched
_FORK_TEXT = [x for x in _LEGACY_D if x[0][0] in (":(){:|:&};:", "while")]


def _legacy(text: str, patterns) -> bool:
    """develop's verdict: does any pattern match *text* (case-insensitive)?"""
    low = text.lower()
    for literals, rx, quadratic in patterns:
        if all(lit in low for lit in literals):
            if quadratic and len(text) > _QUADRATIC_MAX:
                return True  # too slow to run: fail safe
            if rx.search(text):
                return True
    return False

# guard.check_argv kinds that are dangerous_command findings. The guard's
# other kinds (force push, reset --hard, secret reads, ...) are not.
_GUARD_CRITICAL = {
    "rm_root": "recursive delete of /",
    "rm_home": "recursive delete of the home directory",
    "rm_cwd": "recursive delete of the current or parent directory",
    "disk": "overwrites or formats a disk",
    "pipe_shell": "download piped to a shell",
    "chmod": "chmod -R 777 on / or the home directory",
}
_GUARD_HIGH = {
    "fork_bomb": "fork bomb text",
    "destructive": "unparseable nested command (raw match)",
    "too_long": "nested command too long to check",
}

_MAX_DEPTH = 3
_MAX_HEREDOCS = 100
BUDGET_S = 0.5  # per command; past it the rest is reported HIGH, not checked
_ASSIGN = re.compile(r"[A-Za-z_]\w*=.*", re.DOTALL)
_ELEVATORS = {"sudo", "doas", "pkexec", "run0"}
# Short options that take a value, per elevator; long ones below.
_ELEV_VALUE = {"sudo": set("ugChpDRTUrt"), "doas": set("uC"), "pkexec": set(),
               "run0": set("uDg")}
_ELEV_LONG_VALUE = {"--user", "--group", "--chdir", "--chroot", "--prompt", "--host",
                    "--role", "--type", "--other-user", "--close-from",
                    "--command-timeout", "--setenv", "--unit", "--property",
                    "--description", "--slice", "--nice", "--background"}
_ELEV_SHELL = {"sudo": set("is"), "doas": set("s")}  # -i / -s run a shell
_ELEV_INFO = {"-V", "--version", "--help"}  # print something, run nothing
_INTERPRETERS = re.compile(r"(?:python|pypy)[\d.]*w?|py|node(?:js)?|deno|bun|perl|ruby"
                           r"|php[\d.]*|lua[\d.]*|rscript|osascript|tclsh|jshell")
_REDIRECT = re.compile(r"<<<|<<|<>|>>|>&|<&|>\||&>>|&>|<|>")
# Prefixes the parser models exactly; any other (nohup, setsid, exec,
# busybox, wsl, ...) leaves develop's verdict in place.
_KNOWN_PREFIXES = {"env", "timeout", "nice", "ionice", "stdbuf", "time", "command", "builtin"}
# Programs that run their arguments, a remote or another program's command:
# a develop match in such a command always stands.
_WRAPPERS = {"eval", "su", "ssh", "docker", "podman", "kubectl", "tmux", "screen", "xargs",
             "busybox", "powershell", "pwsh", "cmd", "setsid", "nohup", "exec", "find",
             "parallel", "watch", "script", "nsenter", "chroot", "flock", "unshare",
             "systemd-run", "runuser", "sg", "strace", "ltrace", "gdb", "wsl", "env",
             "time", "timeout", "nice", "sudo", "doas", "pkexec", "run0", "make", "npx",
             "uvx", "pipx", "entr", "nodemon", "trap", "source", ".", "alias", "function"}
# Programs whose arguments are data, never run: a develop match there is
# inert, as long as their output is not run either (see _explained).
_DATA = {"echo", "printf", "grep", "egrep", "fgrep", "rg", "ls", "cat", "head", "tail",
         "wc", "touch", "mkdir", "test", "[", "true", "false", ":", "cd", "pwd", "diff",
         "sort", "uniq", "cut", "tr", "basename", "dirname", "realpath", "stat", "file",
         "which", "type", "man", "sleep", "agentwatch", "agentguard"}
_GIT_DATA = {"commit", "log", "show", "diff", "grep", "status", "add", "tag", "notes",
             "branch", "worktree", "checkout", "switch", "fetch", "push", "blame"}
_GH_DATA = {"pr", "issue", "release", "repo", "search"}
# Programs whose develop match the parser's own rules decide.
_EVALUATED = {"rm", "unlink", "dd", "nc", "ncat", "netcat", "socat", "history", "shred",
              "truncate", "setenforce", "iptables", "ip6tables", "ufw", "chmod", "chown",
              "chgrp", "setcap", "getcap", "useradd", "usermod", "groupadd", "visudo",
              "systemctl", "service", "curl", "wget"}
_RUNS_INSIDE = re.compile(r"\$\(|`|[<>]\(")  # substitutions shlex leaves inside a word
_SAFE_SINKS = ("/dev/null", "/dev/stdout", "/dev/stderr")
_HOME_OPERAND = re.compile(r"(?:\$HOME|\$\{HOME\})(?=/|$)")
_NET_TOOLS = {"nc", "ncat", "netcat", "socat", "telnet", "openssl"}
_PRIV_PROGRAMS = {"setcap", "getcap", "useradd", "usermod", "groupadd", "visudo"}
_SYMBOLIC_MODE = re.compile(r"[ugoa]*[+=]([rwxXst]*)")
_HISTORY_FILE = re.compile(r"(?:.*/)?\.\w*history")  # ~/.bash_history, .zsh_history, ...
# Heredocs: `<<` / `<<-` outside quotes and comments, then the delimiter.
_HD_SCAN = re.compile(r"\\[\s\S]|['\"\n#]|<<-?")
_HD_DELIM = re.compile(r"[ \t]*(?:'([^'\n]*)'|\"([^\"\n]*)\"|\\?([^\s;&|()<>'\"`]+))")
# A long command's piece without any of these words cannot match a rule.
_RELEVANT = re.compile(
    r"rm|mkfs|dd|chmod|curl|wget|/dev/|sudo|doas|pkexec|run0|su\b|nc\b|ncat|netcat|socat"
    r"|history|setenforce|tables|ufw|chown|chgrp|cap\b|user|group|visudo|systemctl"
    r"|service|sh\b|eval|script|cmd|powershell|pwsh|python|pypy|node|deno|bun|perl"
    r"|ruby|php|lua|osascript|tclsh|jshell|py\b|<<|_history|:\(\)|fork",
    re.IGNORECASE)


@dataclass(frozen=True)
class CommandFinding:
    signal: str  # DANGEROUS or PRIVILEGE
    severity: Severity
    reason: str  # fixed text, never command text


@dataclass
class _Ctx:
    deadline: float
    hits: list[CommandFinding] = field(default_factory=list)
    bodies: dict[str, str] = field(default_factory=dict)  # heredoc placeholder -> body
    out_of_time: bool = False
    # Signals whose develop verdict stands: the parser could not show the
    # command is understood, so a legacy match is reported CRITICAL.
    doubt: set[str] = field(default_factory=set)

    def doubt_all(self) -> None:
        self.doubt |= {DANGEROUS, PRIVILEGE}

    def add(self, signal: str, severity: Severity, reason: str) -> None:
        self.hits.append(CommandFinding(signal, severity, reason))

    def expired(self) -> bool:
        if not self.out_of_time and time.perf_counter() > self.deadline:
            self.out_of_time = True
            self.doubt_all()
            self.add(DANGEROUS, Severity.HIGH, "command too long to check")
        return self.out_of_time


@dataclass
class _Unit:
    """One simple command, unwrapped."""

    elevators: list[str]  # sudo, doas, pkexec, run0 before the program
    elev_shell: bool  # sudo -i / -s, doas -s
    elev_info: bool  # sudo -V / --help: nothing runs
    argv: list[str]  # after the prefixes, redirections kept (what the guard sees)
    args: list[str]  # argv without redirections; args[0] is the program
    redirs: list[tuple[str, str]]  # (operator, target)
    positions: list[int] = field(default_factory=list)  # of each args word in argv
    raw: list[str] = field(default_factory=list)  # the simple command as parsed
    odd_prefix: bool = False  # a wrapper the parser does not model (nohup, exec, ...)
    lookup: bool = False  # `command -v X`: nothing runs

    @property
    def prog(self) -> str:
        return _prog(self.args[0]) if self.args else ""


def _unwrap(argv: list[str]) -> _Unit:
    elevators: list[str] = []
    shell = info = odd = False
    i = 0
    while i < len(argv):
        word = argv[i]
        prog = _prog(word)
        if _ASSIGN.fullmatch(word) or word in _KEYWORDS:
            odd |= "=" in word and (_RUNS_INSIDE.search(word) is not None or "$" in word
                                    or word.startswith(("PATH=", "LD_", "BASH_ENV=", "ENV=")))
            i += 1
        elif prog in _ELEVATORS:
            elevators.append(prog)
            i += 1
            while i < len(argv) and argv[i].startswith("-") and argv[i] != "-":
                opt = argv[i]
                i += 1
                if opt == "--":
                    break
                if opt in _ELEV_INFO:
                    info = True
                elif opt.startswith("--"):
                    shell |= opt in ("--login", "--shell")
                    if "=" not in opt and opt in _ELEV_LONG_VALUE:
                        i += 1
                else:
                    for k, letter in enumerate(opt[1:]):
                        shell |= letter in _ELEV_SHELL.get(prog, ())
                        if letter in _ELEV_VALUE[prog]:
                            i += k == len(opt) - 2  # last letter: the value is the next word
                            break
        elif prog == "command" and i + 1 < len(argv) and argv[i + 1] in ("-v", "-V"):
            return _Unit(elevators, shell, info, [], [], [], raw=argv, lookup=True)
        elif prog in _PREFIXES:
            odd |= prog not in _KNOWN_PREFIXES or (prog == "env" and any(
                a.startswith(("-S", "--split-string")) for a in argv[i + 1:]))
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                i += 2 if argv[i] in _PREFIXES[prog] else 1
            if prog == "timeout":
                i += 1  # the duration
        else:
            break
    rest = argv[i:]
    args: list[str] = []
    positions: list[int] = []
    redirs: list[tuple[str, str]] = []
    k = 0
    while k < len(rest):
        if _REDIRECT.fullmatch(rest[k]):
            if args and args[-1].isdigit():  # 2>&1: the fd belongs to the redirect
                args.pop()
                positions.pop()
            redirs.append((rest[k], rest[k + 1] if k + 1 < len(rest) else ""))
            k += 2
        else:
            args.append(rest[k])
            positions.append(k)
            k += 1
    return _Unit(elevators, shell, info, rest, args, redirs, positions, argv, odd)


def _preprocess(text: str, ctx: _Ctx) -> str:
    """*text* without its comments (a `#` that starts a word, outside quotes,
    to the end of the line) and with each heredoc body cut out, its `<<DELIM`
    replaced by a placeholder word that keys the body in ctx.bodies. `<<`
    inside quotes or a comment is not a heredoc, so a body is never cut from
    a quoted string. After _MAX_HEREDOCS heredocs the rest is left as is."""
    if "<<" not in text and "#" not in text:
        return text
    out: list[str] = []
    pending: list[tuple[str, str, bool]] = []
    pos = i = 0
    n = len(text)
    quote = ""
    while i < n:
        if quote == "'":
            j = text.find("'", i)
            if j < 0:
                break
            i, quote = j + 1, ""
            continue
        m = _HD_SCAN.search(text, i)
        if not m:
            break
        tok, i = m.group(), m.end()
        if tok[0] == "\\":
            continue
        if quote == '"':
            quote = "" if tok == '"' else quote
            continue
        if tok in ("'", '"'):
            quote = tok
        elif tok == "#":
            if m.start() == 0 or text[m.start() - 1] in " \t\n;&|(":
                j = text.find("\n", i)
                out.append(text[pos:m.start()])
                pos = i = n if j < 0 else j  # the newline still ends the line
        elif tok.startswith("<<"):
            if text.startswith("<", i):  # <<< here-string
                i += 1
                continue
            if len(ctx.bodies) + len(pending) >= _MAX_HEREDOCS:
                ctx.doubt_all()
                continue
            d = _HD_DELIM.match(text, i)
            if not d:
                continue
            key = f"__aw_heredoc_{len(ctx.bodies) + len(pending)}__"
            out.append(text[pos:m.start()] + "<<" + key)
            pending.append((key, next(g for g in d.groups() if g is not None), tok == "<<-"))
            pos = i = d.end()
        elif tok == "\n" and pending:
            out.append(text[pos:i])
            for key, delim, dash in pending:
                start = i
                while i < n:
                    j = text.find("\n", i)
                    end = n if j < 0 else j
                    line = text[i:end]
                    if (line.lstrip("\t") if dash else line) == delim:
                        ctx.bodies[key] = text[start:i]
                        i = end + 1 if j >= 0 else n
                        break
                    i = end + 1 if j >= 0 else n
                else:
                    ctx.bodies[key] = text[start:]  # unterminated: to the end
            pos, pending = i, []
    for key, _, _ in pending:
        ctx.bodies.setdefault(key, "")
    out.append(text[pos:])
    return "".join(out)


def _raw_match(low: str, patterns: list[tuple[str, re.Pattern[str]]]) -> bool:
    return any(literal in low and rx.search(low) for literal, rx in patterns)


def _raw(text: str, ctx: _Ctx, reason: str) -> None:
    low = text.lower()
    if ("()" in low and _FORK_BOMB.search(low)) or _raw_match(low, _RAW_DANGEROUS):
        ctx.add(DANGEROUS, Severity.HIGH, reason)
    if _raw_match(low, _RAW_PRIVILEGE):
        ctx.add(PRIVILEGE, Severity.HIGH, reason)


def _walk(text: str, depth: int, ctx: _Ctx) -> None:
    if ctx.expired():
        return
    if depth > _MAX_DEPTH:
        ctx.doubt_all()
        _raw(text, ctx, "nested too deep to check (raw match)")
        return
    stripped = _preprocess(text, ctx)
    if ("()" in stripped and _FORK_BOMB.search(stripped)) or _legacy(stripped, _FORK_TEXT):
        ctx.doubt.add(DANGEROUS)
        ctx.add(DANGEROUS, Severity.HIGH, _GUARD_HIGH["fork_bomb"])
    if "((" in stripped or "[[" in stripped:
        ctx.doubt_all()  # arithmetic and [[ ]]: `<<` and `>` are not redirects there
    if len(stripped) > guard.MAX_PARSE:
        ctx.doubt_all()
        _walk_long(stripped, depth, ctx)
        return
    tokens = guard.tokenize(stripped, comments=False)
    if tokens is None:
        ctx.doubt_all()
        _raw(text, ctx, "unparseable command (raw match)")
        return
    # Like guard._simple_commands, also noting each command whose output is
    # captured: inside $( ), backticks or a ( ) subshell.
    pipeline: list[tuple[list[str], bool]] = []
    argv: list[str] = []
    sep, parens, ticks, captured = "", 0, False, False
    for tok in [*tokens, ";"]:
        if tok and set(tok) <= guard._SEPARATORS | {"$"}:
            if argv:
                if sep not in ("|", "|&") and pipeline:
                    _check_pipeline(pipeline, depth, ctx)
                    pipeline = []
                if tok[0] in "$`(":  # `sudo $(x)`: the words go on in a substitution
                    argv = [*argv, "$(...)"]
                pipeline.append((argv, captured))
            argv, sep = [], tok
            parens = max(0, parens + tok.count("(") - tok.count(")"))
            ticks ^= tok.count("`") % 2 == 1
        else:
            if not argv:
                captured = parens > 0 or ticks
            argv.append(tok)
    if pipeline:
        _check_pipeline(pipeline, depth, ctx)


def _walk_long(text: str, depth: int, ctx: _Ctx) -> None:
    """Like guard._check_long: split on ; && || and newlines (quotes are not
    respected, so a piece may be unparseable: it then gets the raw patterns)."""
    seen: set[str] = set()
    for piece in guard._SPLIT.split(text):
        if piece in seen or ctx.expired():
            continue
        seen.add(piece)
        if len(piece) > guard._SMALL:
            _raw(piece, ctx, "command too long to parse (raw match)")
        elif _RELEVANT.search(piece.replace("'", "").replace('"', "").replace("\\", "")):
            _walk(piece, depth, ctx)


def _stdin_text(unit: _Unit, ctx: _Ctx) -> str | None:
    text = None
    for op, target in unit.redirs:
        if op == "<<":
            text = ctx.bodies.get(target, text)
        elif op == "<<<":
            text = target
    return text


def _nested_script(prog: str, args: list[str]) -> tuple[int, str] | None:
    """(index in args, script) for bash/sh -c, script -c, su -c."""
    if prog in _SHELLS or prog == "script" or prog == "su":
        for i, a in enumerate(args[1:-1], 1):
            if re.fullmatch(r"-[a-z]*c[a-z]*", a) or a == "--command":
                return i + 1, args[i + 1]
        if prog == "su":
            for i, a in enumerate(args):
                if a.startswith("--command="):
                    return i, a.split("=", 1)[1]
    return None


def _setid(mode: str) -> bool:
    """True when a chmod mode sets setuid or setgid."""
    if re.fullmatch(r"[0-7]{1,5}", mode):
        return bool(int(mode, 8) & 0o6000)
    return any((m := _SYMBOLIC_MODE.fullmatch(part)) and "s" in m.group(1)
               for part in mode.split(","))


def _computed(word: str) -> bool:
    """A word whose value the parser cannot know: $VAR, $(...), `...`, a glob
    or brace expansion, ~user. $HOME / ${HOME} at the start is known, and so
    are the globs the guard resolves (* and .* alone or after a final /)."""
    word = _HOME_OPERAND.sub("~", word, count=1) if _HOME_OPERAND.match(word) else word
    if "$" in word or "`" in word or "{" in word:
        return True
    if word.startswith("~") and not (word == "~" or word.startswith("~/")):
        return True
    rest = re.sub(r"(?:^|/)\.?\*$", "", word)
    return any(c in rest for c in "*?[")


def _sub_command(args: list[str]) -> str:
    """The first operand: git/gh's subcommand (after git -C dir / -c k=v)."""
    i = 1
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in ("-C", "-c", "-R", "--repo") else 1
    return args[i] if i < len(args) else ""


def _is_data(unit: _Unit) -> bool:
    prog = unit.prog
    if prog == "git":
        return _sub_command(unit.args) in _GIT_DATA and not any(
            a.startswith("--exec") or a == "-x" for a in unit.args)
    if prog == "gh":
        return _sub_command(unit.args) in _GH_DATA
    return prog in _DATA


def _explained(unit: _Unit, captured: bool, later: list[_Unit]) -> bool:
    """True when the parser fully understands this simple command, so a
    develop match in its text is decided by the parser's own rules (which
    have already added any finding it deserves)."""
    if unit.odd_prefix or any(_computed(w) for w in unit.raw[:1]) or (
            unit.args and _computed(unit.args[0])):
        return False
    if any(_RUNS_INSIDE.search(w) for w in unit.raw):
        return False  # "$(...)", "`...`" in double quotes, <(...): they run
    if any(_ASSIGN.fullmatch(w) for w in unit.raw[:len(unit.raw) - len(unit.argv)]):
        return False  # VAR=<text> keeps the text for later
    prog = unit.prog
    if not prog:
        return False
    if prog in _WRAPPERS or _INTERPRETERS.fullmatch(prog):
        return False
    if prog in _SHELLS:
        return _nested_script(prog, unit.args) is not None and not any(
            op.startswith("<<") for op, _ in unit.redirs)
    computed = any(_computed(a) for a in unit.args[1:]) or any(
        _computed(t) for _, t in unit.redirs)
    if prog in _EVALUATED or prog.startswith("mkfs"):
        return not computed
    if _is_data(unit):
        # Inert only if its output is not run or kept: not captured by $( ),
        # not piped on to anything but more data programs, not written to a file.
        return not captured and all(_is_data(u) for u in later) and all(
            t in _SAFE_SINKS or t in ("1", "2") or op.startswith("<")
            for op, t in unit.redirs)
    return False


def _plain_elevation(unit: _Unit) -> bool:
    """sudo/doas/pkexec/run0 running a program the parser knows: not computed,
    not a wrapper or interpreter, no prefix it does not model (or sudo -V)."""
    if not unit.elevators or unit.odd_prefix:
        return False
    if not unit.args:
        return True  # sudo -v, -l, -i, -V: its options say what runs
    prog = unit.prog
    return not (_computed(unit.args[0]) or prog in _WRAPPERS
                or _INTERPRETERS.fullmatch(prog))


def _check_pipeline(pipeline: list[tuple[list[str], bool]], depth: int, ctx: _Ctx) -> None:
    units = [_unwrap(argv) for argv, _ in pipeline]
    progs = {u.prog for u in units}
    earlier: set[str] = set()
    piped: str | None = None  # what the previous command writes, when known
    for k, (unit, (_, captured)) in enumerate(zip(units, pipeline)):
        if ctx.expired():
            return
        start = len(ctx.hits)
        own_stdin = _stdin_text(unit, ctx)
        stdin = own_stdin if own_stdin is not None else piped
        if (unit.prog in _SHELLS or _INTERPRETERS.fullmatch(unit.prog)) and (
                k > 0 or own_stdin is not None):
            ctx.doubt_all()  # a pipe, heredoc or here-string into a shell or interpreter
        text = " ".join(unit.raw) + ("\n" + own_stdin if own_stdin else "")
        legacy = {sig for sig, pats in ((DANGEROUS, _LEGACY_D), (PRIVILEGE, _LEGACY_P))
                  if _legacy(text, pats)}
        if PRIVILEGE in legacy and _plain_elevation(unit) and not _legacy(
                " ".join(unit.argv) + ("\n" + own_stdin if own_stdin else ""), _LEGACY_P):
            legacy.discard(PRIVILEGE)  # only the sudo itself: _check_elevation decides
        if legacy and not (unit.lookup or _explained(unit, captured, units[k + 1:])):
            ctx.doubt |= legacy
        nested = _check_unit(unit, earlier, stdin, progs, depth, ctx)
        _check_elevation(unit, nested, ctx.hits[start:], ctx)
        piped = None
        if unit.prog in ("echo", "printf"):
            piped = " ".join(a for a in unit.args[1:] if not a.startswith("-"))
        elif unit.prog == "cat" and len(unit.args) == 1:
            piped = own_stdin
        if unit.prog:
            earlier.add(unit.prog)


def _check_unit(unit: _Unit, earlier: set[str], stdin: str | None, progs: set[str],
                depth: int, ctx: _Ctx) -> bool:
    """Add the unit's findings; True when it runs a nested script."""
    prog, args = unit.prog, unit.args
    nested = _nested_script(prog, args)
    # The guard's rules; nested scripts are walked here, not by the guard.
    view = list(unit.argv)
    if nested is not None and prog != "su":
        view[unit.positions[nested[0]]] = ""  # the script after -c
    elif prog == "eval":
        view = view[:1]
    kind = guard.check_argv(view, earlier) if view else None
    if kind in _GUARD_CRITICAL:
        ctx.add(DANGEROUS, Severity.CRITICAL, _GUARD_CRITICAL[kind])
    elif kind in _GUARD_HIGH:
        ctx.add(DANGEROUS, Severity.HIGH, _GUARD_HIGH[kind])

    flags, ops = _flags(args[1:])
    if nested is not None:
        _walk(nested[1], depth + 1, ctx)
    elif prog == "eval":
        _walk(" ".join(args[1:]), depth + 1, ctx)
    elif prog in _SHELLS and stdin is not None and (not ops or "s" in flags):
        _walk(stdin, depth + 1, ctx)
    if _INTERPRETERS.fullmatch(prog):
        payload = " ".join(args[1:])
        if stdin is not None and (not ops or ops[0] == "-"):
            payload += "\n" + stdin
        _raw(payload, ctx, "interpreter payload (raw match)")

    out_targets = [t for op, t in unit.redirs if ">" in op]
    net_redirs = [op for op, t in unit.redirs if t.startswith(("/dev/tcp/", "/dev/udp/"))]
    if prog in ("nc", "ncat", "netcat") and flags & {
            "e", "c", "l", "--exec", "--sh-exec", "--lua-exec", "--listen"}:
        ctx.add(DANGEROUS, Severity.CRITICAL, "netcat runs a program or listens")
    if prog == "socat" and any(re.search(r"(?i)(?:^|[,!])(?:exec|system):", a) for a in args):
        ctx.add(DANGEROUS, Severity.CRITICAL, "socat runs a program")
    if net_redirs:
        if prog in _SHELLS or not prog or any(">" in op for op in net_redirs):
            ctx.add(DANGEROUS, Severity.CRITICAL, "shell redirected to a network socket")
        else:
            ctx.add(DANGEROUS, Severity.HIGH, "reads from a network socket")
    if prog in _SHELLS and "i" in flags and progs & _NET_TOOLS:
        ctx.add(DANGEROUS, Severity.CRITICAL, "interactive shell piped to the network")
    if (prog == "history" and "c" in flags) or any(
            _HISTORY_FILE.fullmatch(t) for t in out_targets) or (
            prog in ("rm", "shred", "truncate", "unlink")
            and any(_HISTORY_FILE.fullmatch(op) for op in ops)):
        ctx.add(DANGEROUS, Severity.CRITICAL, "wipes shell history")
    if prog == "setenforce" and ops[:1] and ops[0].lower() in ("0", "permissive"):
        ctx.add(DANGEROUS, Severity.CRITICAL, "turns SELinux enforcement off")
    if prog in ("iptables", "ip6tables") and flags & {"F", "--flush"}:
        ctx.add(DANGEROUS, Severity.CRITICAL, "flushes the firewall rules")
    if prog == "ufw" and ops[:1] == ["disable"]:
        ctx.add(DANGEROUS, Severity.CRITICAL, "turns the firewall off")

    if any(t.startswith("/etc/sudoers") for t in out_targets) or (
            prog in ("tee", "cp", "mv", "install", "ln") and ops
            and ops[-1].startswith("/etc/sudoers")):
        ctx.add(PRIVILEGE, Severity.CRITICAL, "writes the sudoers file")
    if prog == "chmod" and ops and _setid(ops[0]):
        ctx.add(PRIVILEGE, Severity.CRITICAL, "chmod sets setuid or setgid")
    elif prog == "chown" and ops and re.match(r"root(?:[:.]|$)", ops[0]):
        ctx.add(PRIVILEGE, Severity.CRITICAL, "chown to root")
    elif prog == "chgrp" and ops[:1] and ops[0] in ("root", "wheel", "admin"):
        ctx.add(PRIVILEGE, Severity.CRITICAL, "chgrp to an admin group")
    elif prog in _PRIV_PROGRAMS:
        ctx.add(PRIVILEGE, Severity.CRITICAL, "changes users, groups or capabilities")
    elif (prog == "systemctl" and "--user" not in flags and ops[:1]
          and ops[0] in ("enable", "start", "restart")):
        ctx.add(PRIVILEGE, Severity.CRITICAL, "starts or enables a system service")
    elif prog == "service" and len(ops) > 1 and ops[1] in ("start", "restart"):
        ctx.add(PRIVILEGE, Severity.CRITICAL, "starts a system service")
    return nested is not None


def _check_elevation(unit: _Unit, nested: bool, found: list[CommandFinding],
                     ctx: _Ctx) -> None:
    """sudo/doas/pkexec/run0 in front of the program, or su as the program."""
    if unit.elevators:
        if unit.elev_info and not unit.args:
            return
        name = unit.elevators[0]
        if unit.elev_shell or unit.prog in _SHELLS or unit.prog == "su":
            ctx.add(PRIVILEGE, Severity.CRITICAL, f"{name} runs a shell")
        elif any(f.signal == DANGEROUS and f.severity == Severity.CRITICAL for f in found):
            ctx.add(PRIVILEGE, Severity.CRITICAL, f"{name} runs a dangerous command")
        else:
            ctx.add(PRIVILEGE, Severity.HIGH, f"runs {name}")
    elif unit.prog == "su":
        if not nested:
            ctx.add(PRIVILEGE, Severity.CRITICAL, "su opens a shell")
        elif any(f.signal == DANGEROUS and f.severity == Severity.CRITICAL for f in found):
            ctx.add(PRIVILEGE, Severity.CRITICAL, "su runs a dangerous command")
        else:
            ctx.add(PRIVILEGE, Severity.HIGH, "runs su")


@lru_cache(maxsize=64)  # each command is re-checked while it sits in the window
def analyze_command(command: str) -> tuple[CommandFinding, ...]:
    """The most severe dangerous_command and privilege_escalation finding
    for *command* (at most one each).

    Fail safe by construction: develop's regexes (LEGACY_DANGEROUS and the
    shared privilege patterns) still decide that a CRITICAL finding exists.
    The parser only lowers or removes it when it understood every simple
    command whose text matched (_explained) and nothing put the whole command
    in doubt (unparseable, too long, too deep, out of time, fork-bomb text,
    arithmetic, a heredoc / here-string / pipe into a shell or interpreter).
    Its own findings (rm -fr, sudo bash, ...) are added either way."""
    ctx = _Ctx(deadline=time.perf_counter() + BUDGET_S)
    _walk(command, 0, ctx)
    # develop's verdict stands unless every match was understood.
    for signal, patterns in ((DANGEROUS, _LEGACY_D), (PRIVILEGE, _LEGACY_P)):
        if signal in ctx.doubt and _legacy(command, patterns):
            ctx.add(signal, Severity.CRITICAL, "matches a dangerous pattern; "
                    "the command could not be fully checked")
    best: dict[str, CommandFinding] = {}
    for hit in ctx.hits:
        kept = best.get(hit.signal)
        if kept is None or hit.severity.score_impact > kept.severity.score_impact:
            best[hit.signal] = hit
    return tuple(best.values())


def _most_severe(buffer: ActionBuffer, signal: str):
    """(finding, action) with the worst severity in the last 10 actions."""
    best = None
    for action in buffer.last(10):
        if not action.command:
            continue
        for finding in analyze_command(action.command):
            if finding.signal == signal and (
                    best is None
                    or finding.severity.score_impact > best[0].severity.score_impact):
                best = (finding, action)
    return best


class PrivilegeEscalationDetector(SecurityDetector):
    """Detects commands that run with raised privileges: sudo, doas, pkexec,
    run0 or su as the program run, setuid/setgid chmod, chown/chgrp to root,
    user, group, capability and service changes."""

    category = Category.PRIVILEGE
    name = "privilege_escalation"
    description = "Privilege escalation attempt detected"

    # Raw patterns, shared with `SessionStats.privilege_commands`; this
    # detector uses them only on text it cannot parse (at HIGH).
    PRIVILEGE_PATTERNS = PRIVILEGE_COMMAND_PATTERNS

    def check(self, buffer: ActionBuffer) -> Warning | None:
        best = _most_severe(buffer, PRIVILEGE)
        if best is None:
            return None
        finding, action = best
        return Warning(
            category=self.category,
            severity=finding.severity,
            signal="privilege_escalation",
            message=f"Privilege escalation command detected: {finding.reason}",
            details={
                "command": redact_truncate(action.command, 100),  # Truncate for safety
                "tool": action.tool_name,
                "reason": finding.reason,
            },
        )


class DangerousCommandDetector(SecurityDetector):
    """Detects dangerous or destructive commands (see analyze_command)."""

    category = Category.PRIVILEGE
    name = "dangerous_command"
    description = "Potentially dangerous command detected"

    # Raw patterns for text that cannot be parsed (reported at HIGH).
    DANGEROUS_PATTERNS = RAW_DANGEROUS_PATTERNS

    def check(self, buffer: ActionBuffer) -> Warning | None:
        best = _most_severe(buffer, DANGEROUS)
        if best is None:
            return None
        finding, action = best
        return Warning(
            category=self.category,
            severity=finding.severity,
            signal="dangerous_command",
            message=f"Dangerous command detected: {finding.reason}",
            details={
                "command": redact_truncate(action.command, 100),
                "tool": action.tool_name,
                "reason": finding.reason,
            },
        )


class MassFileOperationDetector(SecurityDetector):
    """Detects mass file operations that could be destructive."""

    category = Category.PRIVILEGE
    name = "mass_file_operation"
    description = "Mass file operation detected"

    def __init__(self, threshold: int = 10, window: int = 20):
        self.threshold = threshold
        self.window = window

    def check(self, buffer: ActionBuffer) -> Warning | None:
        if len(buffer) < self.window:
            return None

        recent = buffer.last(self.window)

        # Count file operations
        deletes = 0
        overwrites = 0

        for action in recent:
            cmd = action.command or ""

            # Count delete operations
            if "rm " in cmd or "unlink" in cmd or "shred" in cmd:
                deletes += 1

            # Count overwrite operations (> file)
            if action.is_file_edit:
                overwrites += 1

        if deletes >= self.threshold:
            return Warning(
                category=self.category,
                severity=Severity.HIGH,
                signal="mass_delete",
                message=f"Mass file deletion detected ({deletes} operations)",
                details={"delete_count": deletes},
            )

        if overwrites >= self.threshold * 2:  # Higher threshold for edits
            return Warning(
                category=self.category,
                severity=Severity.MEDIUM,
                signal="mass_overwrite",
                message=f"Unusual volume of file modifications ({overwrites})",
                details={"overwrite_count": overwrites},
            )

        return None


class SensitiveDirectoryAccessDetector(SecurityDetector):
    """Detects access to sensitive system directories."""

    category = Category.PRIVILEGE
    name = "sensitive_directory"
    description = "Access to sensitive system directory"

    SENSITIVE_DIRS = [
        r"^/etc/",
        r"^/var/log/",
        r"^/root/",
        r"^/boot/",
        r"^/sys/",
        r"^/proc/",
        r"/\.ssh/",
        r"/\.gnupg/",
        r"/\.config/",
        r"^/usr/local/bin/",
        r"^/usr/bin/",
    ]

    def __init__(self):
        self._pattern = re.compile("|".join(self.SENSITIVE_DIRS))

    def check(self, buffer: ActionBuffer) -> Warning | None:
        recent = buffer.last(10)

        for action in recent:
            path = action.file_path or action.command or ""

            if self._pattern.search(path):
                # The fallback is a whole command: mask secrets before any cut.
                path = redact_truncate(path, 200)
                # Write operations are more severe
                severity = Severity.HIGH if action.is_file_edit else Severity.MEDIUM

                return Warning(
                    category=self.category,
                    severity=severity,
                    signal="sensitive_directory",
                    message=f"Access to sensitive directory: {path[:50]}",
                    details={
                        "path": path,
                        "operation": "write" if action.is_file_edit else "read",
                    },
                )

        return None
