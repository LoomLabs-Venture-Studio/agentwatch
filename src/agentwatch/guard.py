r"""Command guard: the coach hook asks the user before a catastrophic call.

Runs on Claude Code's PreToolUse, before the loop breaker. A match returns a
fixed reason; coach turns it into `"permissionDecision": "ask"`, so Claude
Code shows the user a permission prompt. A false positive costs one click.

Bash commands are first read with bash's quoting rules (_Scan): comments
(`#` at a word start, up to the newline) and `\<newline>` continuations are
removed, and the commands bash runs inside `$(...)`, backticks, `<(...)` and
`>(...)` are checked on their own, also inside double quotes, `${...}` and
unquoted heredocs (not inside single quotes). The rest is split with shlex
into simple commands (on `;`, `&&`, `||`,
`|`, `&`, newlines, `(`, `)`, backticks and `$(`), leading `sudo`, `env`,
`VAR=value`, `timeout N`, `nohup`, `setsid`, `builtin`, `wsl [-d X] [-e]`, ...
and shell keywords (`if`, `do`, `{`, `!`, ...) are skipped, and
`bash/sh/zsh -c '<script>'`, `script -c '<cmd>'`, `eval ...`, `cmd /c|//c|/k ...`
(also glued `/c"..."`) and `powershell/pwsh` (-c, -Command or a prefix from -com,
or bare args) are checked recursively, as are scripts a shell reads on stdin
(heredocs, here-strings, `echo`/`printf` piped to it); `sh -c "$(curl ...)"`,
`bash <(curl ...)` and `source <(wget ...)` count as pipe to shell. Program
names are lowercased, without `.exe` and directory (`/` or backslash). Nesting
deeper than 3 (wrappers or substitutions) gets the raw patterns. Not caught:
`powershell -EncodedCommand`
(not decoded), `wsl --shell-type X`, `script --command=...`, `curl | cmd` or
`| powershell`, a script passed through a variable (`x=...; sh -c "$x"`),
unquoted backslash program
paths (shlex eats them), cmd's `^` escape (`g^it`), PowerShell syntax inside
-Command (`& {...}`, `iex`, cmdlets such as `Remove-Item -Recurse -Force`; the
PowerShell tool is not guarded either), and quote-split words (`r''m`) inside
commands over MAX_PARSE chars. Arguments of any other program are not inspected, so
`echo "rm -rf /"` or `git commit -m "rm -rf /"` pass. When the command cannot
be parsed (unbalanced quotes or substitutions), the raw string is also matched
against DESTRUCTIVE_PATTERNS. Commands over
MAX_PARSE chars are split on `;`, `&&`, `||` and newlines first; each piece up
to _SMALL chars that names a guarded program or path is checked as above,
longer pieces get the raw patterns on their first _PIECE chars.

The guard also asks before it is turned off: `agentwatch guard off` or
`agentguard guard off` (directly or through python -m / uvx / pipx / npx /
xargs), and Write/Edit or a Bash `>`, `tee`, `cp`/`mv` onto the settings file
(coach.guard_path()).

Stdlib only and imported on every PreToolUse: keep it cheap. It lives
outside `agentwatch.parser`, whose package __init__ imports the watchers
(~180 ms).
"""

from __future__ import annotations

import posixpath
import re
import shlex
import time

# Raw-string patterns for destructive commands. Shared with
# detectors.security.privilege.DangerousCommandDetector (its first entries),
# and the guard's fallback when a command cannot be tokenized.
DESTRUCTIVE_PATTERNS = [
    r"rm\s+-rf\s+[/~]",
    r"rm\s+-rf\s+\*",
    r"rm\s+-rf\s+\.",
    r">\s*/dev/sd[a-z]",  # Overwrite disk
    r"mkfs\.",
    r"dd\s+if=.+of=/dev",
]
_FALLBACK = re.compile("|".join(DESTRUCTIVE_PATTERNS), re.IGNORECASE)
# `:(){ :|:& };:` and renamed variants, spaces allowed (shlex garbles it). The
# lookbehind keeps it linear: without it a long word backtracks quadratically.
_FORK_BOMB = re.compile(
    r"(?<![\w:])(\w+|:)\s*\(\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1")
# shlex and `dd\s+if=.+of=` are quadratic on long tokens, so longer commands are
# checked piece by piece (see check_command).
MAX_PARSE = 20_000
_SMALL = 2_000
_PIECE = 500
_SPLIT = re.compile(r"&&|\|\||[;\n]")
# A piece without any of these cannot match a rule: skip its (~30 us) parse.
_RELEVANT = re.compile(r"rm|git|mkfs|dd|chmod|curl|wget|/dev/|\.env|\.ssh|\.aws|netrc"
                       r"|npmrc|pypirc|\.docker|\.kube|\.pem|\.key|agentwatch|agentguard",
                       re.IGNORECASE)
# ponytail: wall-clock cap on the long-command path; past it the guard asks
# instead of finishing. Raise it (under coach.BUDGET_S) if real commands hit it.
_LONG_BUDGET_S = 1.0
_HOME_RE = re.compile(r"(?:~|\$HOME|\$\{HOME\})(?=/|$)")
_DISK = re.compile(r"/dev/(?:sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|disk\d)")
_HARMLESS_DEV = ("/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/fd/")
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
# Prefix programs and their options that take a value. timeout also takes a duration.
_PREFIXES = {"sudo": {"-u", "-g", "-C", "-h", "-p"}, "doas": {"-u", "-C"},
             "env": {"-u", "-C"}, "nice": {"-n"}, "ionice": {"-c", "-n", "-p"},
             "stdbuf": {"-i", "-o", "-e"}, "timeout": {"-s", "-k"}, "command": set(),
             "exec": set(), "nohup": set(), "time": set(), "busybox": set(),
             "builtin": set(), "setsid": set(),
             "wsl": {"-d", "--distribution", "-u", "--user", "--cd"}}
# Shell keywords and grouping words before a command; fi/done/esac/} stand alone.
_KEYWORDS = {"{", "}", "!", "if", "then", "elif", "else", "do", "while", "until",
             "fi", "done", "esac"}
_SEPARATORS = set(";&|()`\n")
_READERS = {"cat", "less", "more", "head", "tail", "cp", "scp", "bat"}
# The guard's settings file is always <user_state_dir>/agentwatch/coach/guard
# (coach.guard_path()); matching the tail also catches ~, $HOME and %VAR% spellings.
_GUARD_FILE = "/agentwatch/coach/guard"
_AW_NAMES = {"agentwatch", "agentwatch-monitor", "agentwatch.cli", "agentguard"}
_LAUNCHERS = re.compile(r"python[\d.]*w?|py|uvx?|pipx|xargs|npx")
_AW_RAW = re.compile(r"agent(?:watch|guard)", re.IGNORECASE)
_GUARD_RAW = re.compile(r"\bguard\s+off\b|agentwatch[/\\]+coach[/\\]+guard\b", re.IGNORECASE)
# PowerShell options that take a value: matched as a prefix of the long name,
# plus the aliases that are not prefixes.
_PS_VALUE = ("windowstyle", "version", "workingdirectory", "outputformat", "inputformat",
             "configurationname", "configurationfile", "psconsolefile", "settingsfile",
             "custompipename")
_PS_ALIASES = {"wd", "of", "if"}
_FILE_TOOLS = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path",
               "NotebookEdit": "notebook_path"}

REASONS = {
    "rm_root": "agentwatch: this command deletes the whole filesystem. Allow it?",
    "rm_home": "agentwatch: this command deletes your home directory. Allow it?",
    "rm_cwd": "agentwatch: this command deletes everything in the current or "
              "parent directory. Allow it?",
    "push_force": "agentwatch: this command force-pushes and can overwrite remote "
                  "history (--force-with-lease is safer). Allow it?",
    "reset_hard": "agentwatch: git reset --hard discards uncommitted changes. Allow it?",
    "clean": "agentwatch: git clean -fd deletes untracked files and directories. Allow it?",
    "disk": "agentwatch: this command overwrites or formats a disk. Allow it?",
    "pipe_shell": "agentwatch: this command runs a downloaded script without "
                  "review (pipe to shell). Allow it?",
    "chmod": "agentwatch: this command makes every file world-writable. Allow it?",
    "fork_bomb": "agentwatch: this command is a fork bomb. Allow it?",
    "destructive": "agentwatch: this command looks destructive. Allow it?",
    "too_long": "agentwatch: this command is too long to check. Allow it?",
    "secret": "agentwatch: this reads a file that may hold secrets ({}). Allow it?",
    "guard_off": "agentwatch: this turns off the agentwatch command guard. Allow it?",
}


def secret_label(path: str) -> str | None:
    """A fixed label when *path* names a secrets file, else None."""
    p = path.replace("\\", "/").rstrip("/").lower()
    name = p.rsplit("/", 1)[-1]
    if name == ".env" or (name.startswith(".env.")
                          and name[5:] not in ("example", "sample", "template")):
        return ".env file"
    if "/" in p and p.rsplit("/", 2)[-2] == ".ssh" and name.startswith("id_") \
            and not name.endswith(".pub"):
        return "SSH private key"
    if p.endswith(".aws/credentials"):
        return "AWS credentials"
    if name in (".netrc", "_netrc", ".npmrc", ".pypirc"):
        return name
    if p.endswith(".docker/config.json"):
        return "Docker credentials"
    if p.endswith(".kube/config"):
        return "Kubernetes config"
    if name.endswith((".pem", ".key")):
        return "private key"
    return None


def is_guard_file(path: str) -> bool:
    """True when *path* is the guard's settings file (case-insensitive)."""
    p = posixpath.normpath(path.replace("\\", "/")).lower()
    return ("/" + p).endswith(_GUARD_FILE)


def _prog(word: str) -> str:
    r"""Program name: the lowercased basename without .exe (`C:\...\CMD.exe` -> cmd)."""
    word = word.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return word.removesuffix(".exe")


def _rest(args: list[str], depth: int) -> str | None:
    """cmd /c and powershell -Command run the rest of the line."""
    if not args:
        return None
    return check_command(args[0] if len(args) == 1 else shlex.join(args), depth + 1)


# ponytail: cmd ^ escapes and PowerShell syntax inside -Command (& {...}, iex,
# cmdlets) are not parsed; only commands they name as plain words are checked.
# Upgrade: strip ^ for cmd and guard cmdlets / the PowerShell tool.
def _cmd(args: list[str], depth: int) -> str | None:
    """cmd /c, //c (Git Bash), /k, /r, also glued: /c"..."."""
    for i, a in enumerate(args):
        if m := re.match(r"/{1,2}[ckr]", a, re.IGNORECASE):
            glued = a[m.end():]
            return _rest(([glued] if glued else []) + args[i + 1:], depth)
    return None


def _powershell(args: list[str], depth: int) -> str | None:
    """powershell/pwsh -c|-Command (or a prefix from -com), or bare args: 5.1
    runs them as a command (pwsh 7 as -File; asked the same). -File and
    -EncodedCommand return None."""
    i = 0
    while i < len(args):
        if not args[i].startswith(("-", "/")):
            return _rest(args[i:], depth)
        o = args[i].lstrip("-/").lower()
        if o == "c" or (len(o) >= 3 and "command".startswith(o)):
            return _rest(args[i + 1:], depth)
        if o in ("ex", "ep") or (len(o) > 1 and "executionpolicy".startswith(o)) or (
                o in _PS_ALIASES or (o and any(n.startswith(o) for n in _PS_VALUE))):
            i += 2
        elif o.startswith("e") or (o and "file".startswith(o)):
            return None  # -EncodedCommand (not decoded) or a script file
        else:
            i += 1  # a switch: -NoProfile, -NoLogo, -NonInteractive, ...
    return None


def _turns_guard_off(argv: list[str]) -> bool:
    """`agentwatch|agentguard [...] guard off`, also via python -m, uv/uvx, pipx,
    npx and xargs."""
    def name(word: str) -> str:
        word = word.replace("\\", "/").rsplit("/", 1)[-1].lower()
        return re.split(r"[@=<>\[]", word.removesuffix(".exe"), maxsplit=1)[0]

    args = argv[1:]
    if name(argv[0]) not in _AW_NAMES:
        if not _LAUNCHERS.fullmatch(name(argv[0])):
            return False
        at = next((i for i, a in enumerate(args) if name(a) in _AW_NAMES), None)
        if at is None:
            return False
        args = args[at + 1:]
    return "guard" in args and "off" in args[args.index("guard") + 1:]


def _simple_commands(tokens: list[str]) -> list[tuple[list[str], str]]:
    """(argv, separator before it) per simple command."""
    out, argv, sep = [], [], ""
    for tok in tokens:
        if tok and set(tok) <= _SEPARATORS | {"$"}:
            if argv:
                out.append((argv, sep))
            argv, sep = [], tok
        else:
            argv.append(tok)
    if argv:
        out.append((argv, sep))
    return out


def _strip_prefixes(argv: list[str]) -> list[str]:
    i = 0
    while i < len(argv):
        word = argv[i]
        if re.fullmatch(r"[A-Za-z_]\w*=.*", word, re.DOTALL):
            i += 1
        elif word in _KEYWORDS:
            i += 1
        elif (prefix := _prog(word)) in _PREFIXES:
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                i += 2 if argv[i] in _PREFIXES[prefix] else 1
            if prefix == "timeout":
                i += 1  # the duration
        else:
            break
    return argv[i:]


def _flags(args: list[str]) -> tuple[set[str], list[str]]:
    """Short flag letters plus long flags, and the operands."""
    flags, operands, done = set(), [], False
    for a in args:
        if done or not a.startswith("-") or a == "-":
            operands.append(a)
        elif a == "--":
            done = True
        elif a.startswith("--"):
            flags.add(a)
        else:
            flags.update(a[1:])
    return flags, operands


def _target(op: str) -> str | None:
    """"root", "home" (home or above it) or "cwd" (. .. * and up) for an rm operand."""
    if not op:
        return None
    home = _HOME_RE.match(op)
    path = "/H" + op[home.end():] if home else op
    path = posixpath.normpath(re.sub("/+", "/", path))
    while path.endswith("/*") or path.endswith("/.*"):
        path = path.rsplit("/", 1)[0] or "/"
    if home:
        return "home" if path in ("/", "/H") else None
    if path == "/":
        return "root"
    if path in ("*", ".*") or all(part == ".." for part in path.split("/")) or path == ".":
        return "cwd"
    return None


def _check_argv(argv: list[str], piped_from: set[str], depth: int) -> str | None:
    if not argv:
        return None
    prog, args = _prog(argv[0]), argv[1:]
    for i, tok in enumerate(argv[:-1]):  # redirections, any program
        if tok in (">", ">>", ">|", "&>") and _DISK.match(argv[i + 1]):
            return REASONS["disk"]
        if tok in (">", ">>", ">|", "&>") and is_guard_file(argv[i + 1]):
            return REASONS["guard_off"]
        if tok == "<" and (label := secret_label(argv[i + 1])):
            return REASONS["secret"].format(label)
    # ponytail: only direct writes to the guard file are caught (redirects, tee,
    # cp/mv onto it, the file tools); `python -c`, scripts, `cd` + a relative
    # path, Write/Edit through a relative path (`coach/guard` from inside the
    # agentwatch state dir), ln/install/dd and other indirect writes are not.
    # Upgrade: an integrity check on the file (owner-written marker) if agents
    # try those.
    if _turns_guard_off(argv):
        return REASONS["guard_off"]
    if prog == "eval":  # bash joins eval's args and parses them again
        return _script(" ".join(args), depth)
    if prog in _SHELLS and piped_from & {"curl", "wget"}:
        return REASONS["pipe_shell"]
    if prog in _SHELLS or prog in ("source", "."):  # bash <(curl ...), . <(wget ...)
        if any(a == "<(" and _prog(b) in ("curl", "wget") for a, b in zip(args, args[1:])):
            return REASONS["pipe_shell"]
    if prog in _SHELLS or prog == "script":
        for i, a in enumerate(args[:-1]):
            if re.fullmatch(r"-[a-z]*c[a-z]*", a) or a == "--command":
                return _script(args[i + 1], depth)
        return None
    if prog == "cmd":
        return _cmd(args, depth)
    if prog in ("powershell", "pwsh"):
        return _powershell(args, depth)
    flags, ops = _flags(args)
    if prog in ("cp", "mv", "tee") and any(
            is_guard_file(op) for op in (ops if prog == "tee" else ops[-1:])):
        return REASONS["guard_off"]
    if prog == "rm" and flags & {"r", "R", "--recursive"}:
        for op in ops:
            if kind := _target(op):
                return REASONS["rm_" + kind]
    if prog == "chmod" and flags & {"R", "--recursive"} and any(
            op in ("777", "0777", "a+rwx") for op in ops) and any(
            _target(op) in ("root", "home") for op in ops):
        return REASONS["chmod"]
    if prog.startswith("mkfs"):
        return REASONS["disk"]
    if prog == "dd" and any(a.startswith("of=/dev/") and not a[3:].startswith(_HARMLESS_DEV)
                            for a in args):
        return REASONS["disk"]
    if prog == "git":
        while args and args[0].startswith("-"):  # git -C dir / -c k=v
            args = args[2:] if args[0] in ("-C", "-c") else args[1:]
        sub, rest = (args[0], args[1:]) if args else ("", [])
        flags, ops = _flags(rest)
        if sub == "push" and ("--force" in flags or "f" in flags
                              or any(op.startswith("+") for op in ops)):  # +refspec
            return REASONS["push_force"]
        if sub == "reset" and "--hard" in flags:
            return REASONS["reset_hard"]
        if sub == "clean" and "d" in flags and flags & {"f", "--force"}:
            return REASONS["clean"]
    if prog in _READERS:
        for op in ops[:-1] if prog in ("cp", "scp") else ops:  # cp: sources only
            if label := secret_label(op):
                return REASONS["secret"].format(label)
    if prog == "curl":
        for i, a in enumerate(args):
            path = a.split("@", 1)[1] if re.match(r"(?:[^=@]*=)?@", a) else (
                args[i + 1] if a in ("-T", "--upload-file") and i + 1 < len(args) else "")
            if path and (label := secret_label(path.split(";", 1)[0])):
                return REASONS["secret"].format(label)
    return None


class _UnparsedError(Exception):
    """The scanner lost track of the command's quoting."""


_CODE_RUN = re.compile(r"[^ \t\n\\'\"`$#()<>;&|]+")
_DQ_RUN = re.compile(r'[^\\"$`]+')
_BRACE_RUN = re.compile(r"[^\\'\"`${}]+")
_ANSI = re.compile(r"(?:[^\\']|\\.)*'", re.DOTALL)  # the rest of a $'...' string
_BACKTICK = re.compile(r"(?:[^\\`]|\\.)*`", re.DOTALL)
_WORD_END = " \t\n;&|()<>"
_MAX_NEST = 50
_ECHOES = {"echo", "printf"}
# The script a shell runs is the output of curl/wget: sh -c "$(curl -fsSL URL)".
_DOWNLOAD = re.compile(r"\s*(?:\$\(|`)\s*(?:\S*[/\\])?(?:curl|wget)(?:\.exe)?\s",
                       re.IGNORECASE)


class _Scan:
    r"""One pass over a command with bash's quoting rules.

    `text` is the command without comments (`#` at a word start, up to the
    newline) and `\<newline>` continuations, and with `\$` and `` \` `` inside
    double quotes unescaped as bash does (shlex keeps the backslash). `bodies`
    are the commands bash runs inside `$(...)`, backticks, `<(...)` and
    `>(...)`, also inside double quotes, `${...}` and unquoted heredocs (only
    the outermost ones; check_command scans each body again). `skeleton` is
    `text` with those substitutions replaced by `_` and heredoc bodies cut
    (None when there is neither); `heredocs` are the heredoc bodies in order.
    Raises _UnparsedError on unbalanced quotes or substitutions.
    """

    def __init__(self, s: str):
        self.s, self.out, self.n = s, [], 0
        self.level = 0  # enclosing substitutions
        self.nest = 0
        self.spans: list[tuple[int, int, str]] = []  # skeleton cuts (start, end, filler)
        self.bodies: list[str | tuple[int, int]] = []
        self.heredocs: list[str] = []
        self.pending: list[tuple[str, bool, bool]] = []  # (delimiter, <<-, quoted)

    def result_bodies(self) -> list[str]:
        text = "".join(self.out)
        return [b if isinstance(b, str) else text[b[0]:b[1]] for b in self.bodies]

    def emit(self, text: str) -> None:
        self.out.append(text)
        self.n += len(text)

    def enter(self) -> None:
        self.nest += 1
        if self.nest > _MAX_NEST:
            raise _UnparsedError

    def result(self) -> tuple[str, list[str], str | None, list[str]]:
        self.code(0, False)
        text, bodies = "".join(self.out), self.result_bodies()
        if not self.spans:
            return text, bodies, None, self.heredocs
        parts, at = [], 0
        for a, b, filler in sorted(self.spans):
            if a >= at:
                parts += [text[at:a], filler]
                at = b
        parts.append(text[at:])
        return text, bodies, "".join(parts), self.heredocs

    def code(self, i: int, closes: bool) -> int:
        """Unquoted shell code up to the `)` that closes a substitution (closes)
        or the end; returns the index of that `)`."""
        s, end = self.s, len(self.s)
        word_start = cmd_pos = True
        parens = cases = 0
        while i < end:
            if m := _CODE_RUN.match(s, i):
                word = m.group()
                if cmd_pos and word == "case":
                    cases += 1
                elif cmd_pos and word == "esac" and cases:
                    cases -= 1
                cmd_pos = cmd_pos and word in _KEYWORDS
                self.emit(word)
                i, word_start = m.end(), False
                continue
            c = s[i]
            if c in " \t":
                self.emit(c)
                i, word_start = i + 1, True
                continue
            if c == "#" and word_start:  # a comment, up to the newline
                nl = s.find("\n", i)
                i = end if nl < 0 else nl
                continue
            if c == "\n":
                self.emit(c)
                i, word_start, cmd_pos = i + 1, True, True
                if self.pending:
                    i = self.heredoc_bodies(i)
                continue
            word_start = cmd_pos = False
            if c == "\\":
                if s.startswith("\n", i + 1):  # line continuation
                    i += 2
                else:
                    self.emit(s[i:i + 2])
                    i += 2
            elif c == "'":
                close = s.find("'", i + 1)
                if close < 0:
                    raise _UnparsedError
                self.emit(s[i:close + 1])
                i = close + 1
            elif c == '"':
                i = self.dq(i + 1, False)
            elif c == "$":
                i = self.dollar(i, False)
            elif c == "`":
                i = self.backtick(i, False)
            elif s.startswith("<<<", i):
                self.emit("<<<")
                i, word_start = i + 3, True
            elif s.startswith("<<", i):
                i = self.heredoc_op(i)
            elif c in "<>" and s.startswith("(", i + 1):  # process substitution
                i = self.sub(i, 2)
            else:  # ; & | ( ) < >
                word_start, cmd_pos = True, c in "(;&|"
                if c == "(":
                    parens += 1
                elif c == ")":
                    if parens:
                        parens -= 1
                    elif cases:  # a case pattern: `a) cmd ;;`
                        cmd_pos = True
                    elif closes:
                        return i
                self.emit(c)
                i += 1
        if closes:
            raise _UnparsedError
        return i

    def dq(self, i: int, heredoc: bool) -> int:
        """Inside double quotes (or an unquoted heredoc body: no closing quote)."""
        self.enter()
        s, end = self.s, len(self.s)
        if not heredoc:
            self.emit('"')
        while i < end:
            if m := _DQ_RUN.match(s, i):
                self.emit(m.group())
                i = m.end()
                continue
            c = s[i]
            if c == '"':
                self.emit(c)
                i += 1
                if not heredoc:
                    self.nest -= 1
                    return i
            elif c == "\\":
                nxt = s[i + 1:i + 2]
                if nxt != "\n":  # \<newline> is a continuation
                    self.emit(nxt if nxt and nxt in "$`" and not self.level else s[i:i + 2])
                i += 2
            elif c == "$":
                i = self.dollar(i, True)
            else:
                i = self.backtick(i, True)
        if not heredoc:
            raise _UnparsedError
        self.nest -= 1
        return i

    def dollar(self, i: int, quoted: bool) -> int:
        s = self.s
        nxt = s[i + 1:i + 2]
        if nxt == "(":  # $( and $(( (checked as a subshell; harmless for arithmetic)
            return self.sub(i, 2)
        if nxt == "{":
            return self.brace(i + 2, quoted)
        if nxt == "'" and not quoted:  # $'...' with backslash escapes
            if not (m := _ANSI.match(s, i + 2)):
                raise _UnparsedError
            self.emit(s[i:m.end()])
            return m.end()
        self.emit("$")
        return i + 1

    def brace(self, i: int, quoted: bool) -> int:
        """${...} up to its `}`: quotes and substitutions inside still count."""
        self.enter()
        s, end, depth = self.s, len(self.s), 0
        self.emit("${")
        while i < end:
            if m := _BRACE_RUN.match(s, i):
                self.emit(m.group())
                i = m.end()
                continue
            c = s[i]
            if c == "\\":
                if not s.startswith("\n", i + 1):
                    self.emit(s[i:i + 2])
                i += 2
            elif c == "'" and not quoted:
                close = s.find("'", i + 1)
                if close < 0:
                    raise _UnparsedError
                self.emit(s[i:close + 1])
                i = close + 1
            elif c == "'":
                self.emit(c)
                i += 1
            elif c == '"':
                i = self.dq(i + 1, False)
            elif c == "$":
                i = self.dollar(i, quoted)
            elif c == "`":
                i = self.backtick(i, quoted)
            else:
                self.emit(c)
                i += 1
                if c == "{":
                    depth += 1
                elif depth:
                    depth -= 1
                else:
                    self.nest -= 1
                    return i
        raise _UnparsedError

    def sub(self, i: int, op_len: int) -> int:
        """$(...), <(...) or >(...)."""
        self.enter()
        start = self.n
        self.emit(self.s[i:i + op_len])
        body = self.n
        outer, self.pending = self.pending, []  # a heredoc must end inside
        self.level += 1
        close = self.code(i + op_len, True)
        self.level -= 1
        self.pending = outer
        if not self.level:
            self.bodies.append((body, self.n))
        self.emit(")")
        if not self.level:
            self.spans.append((start, self.n, "_"))
        self.nest -= 1
        return close + 1

    def backtick(self, i: int, quoted: bool) -> int:
        if not (m := _BACKTICK.match(self.s, i + 1)):
            raise _UnparsedError
        start = self.n
        self.emit(self.s[i:m.end()])
        if not self.level:
            # Inside backticks bash drops the backslash before \ ` $ (and " when quoted).
            escaped = r'\\([\\`$"])' if quoted else r"\\([\\`$])"
            self.bodies.append(re.sub(escaped, r"\1", self.s[i + 1:m.end() - 1]))
            self.spans.append((start, self.n, "_"))
        return m.end()

    def heredoc_op(self, i: int) -> int:
        """`<<WORD` / `<<-WORD`: the body starts after the next newline."""
        s, end = self.s, len(self.s)
        j = i + 2
        strip = s.startswith("-", j)
        j += strip
        while j < end and s[j] in " \t":
            j += 1
        delim, quoted = [], False
        while j < end and s[j] not in _WORD_END:
            c = s[j]
            if c in "'\"":
                close = s.find(c, j + 1)
                if close < 0:
                    raise _UnparsedError
                delim.append(s[j + 1:close])
                quoted, j = True, close + 1
            elif c == "\\":
                delim.append(s[j + 1:j + 2])
                quoted, j = True, j + 2
            else:
                delim.append(c)
                j += 1
        if not delim:  # `<<` with no word: not a heredoc
            self.emit("<<")
            return i + 2
        self.emit(s[i:j])
        self.pending.append(("".join(delim), strip, quoted))
        return j

    def heredoc_bodies(self, i: int) -> int:
        """Skip the pending heredoc bodies that start at *i*."""
        s, end = self.s, len(self.s)
        for delim, strip, quoted in self.pending:
            start, stop = i, end
            while i < end:
                nl = s.find("\n", i)
                line_end = end if nl < 0 else nl
                line = s[i:line_end]
                bare = line.lstrip("\t") if strip else line
                if bare == delim:
                    stop, i = i, (end if nl < 0 else nl + 1)
                    break
                if self.level and bare.startswith(delim) and \
                        bare[len(delim):].lstrip(" \t").startswith(")"):  # EOF)
                    stop, i = i, i + len(line) - len(bare) + len(delim)
                    break
                i = end if nl < 0 else nl + 1
            body = s[start:stop]
            out_start = self.n
            self.emit(s[start:i])
            if not self.level:
                self.spans.append((out_start, self.n, ""))
                self.heredocs.append(body)
                if not quoted:  # $(...) and backticks run in an unquoted heredoc
                    inner = _Scan(body)
                    inner.nest = self.nest
                    inner.dq(0, True)
                    self.bodies += inner.result_bodies()
        self.pending = []
        return i


def _tokens(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>`\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""  # _Scan removes comments; shlex starts one mid-word
    return list(lexer)


def _raw(command: str) -> str | None:
    """The check for a command that cannot be parsed: raw patterns."""
    if _AW_RAW.search(command) and _GUARD_RAW.search(command):
        return REASONS["guard_off"]
    return REASONS["destructive"] if _FALLBACK.search(command) else None


def _script(script: str, depth: int) -> str | None:
    """A script a shell runs (-c, eval, its stdin)."""
    if _DOWNLOAD.match(script):
        return REASONS["pipe_shell"]
    return check_command(script, depth + 1)


def _stdin_scripts(prog: str, argv: list[str]) -> list[str]:
    """What a command writes to a shell it is piped to, or a shell reads: here-strings,
    and the text echo/printf print."""
    out = [b for a, b in zip(argv, argv[1:]) if a == "<<<"]
    if prog in _ECHOES:
        words = [a for a in argv[1:] if not re.fullmatch(r"-[neE]+", a)]
        out.append(" ".join(words).replace("\\n", "\n"))
    return out


def _check_tokens(command: str, depth: int, heredocs: list[str] | None = None) -> str | None:
    """Check each simple command. *heredocs* are the bodies cut from *command*,
    in the order of its `<<` operators. Raises ValueError when shlex cannot parse."""
    pipeline: set[str] = set()  # programs earlier in the current pipeline
    stdin: list[str] = []  # scripts flowing down the current pipeline
    docs = iter(heredocs or ())
    for argv, sep in _simple_commands(_tokens(command)):
        mine = [next(docs, "") for tok in argv if tok == "<<"] if heredocs else []
        argv = _strip_prefixes(argv)
        if sep != "|":
            pipeline, stdin = set(), []
        reason = _check_argv(argv, pipeline, depth)
        if reason:
            return reason
        if argv:
            prog = _prog(argv[0])
            mine += _stdin_scripts(prog, argv)
            if prog in _SHELLS:
                for script in stdin + mine:
                    if reason := _script(script, depth):
                        return reason
            stdin += mine
            pipeline.add(prog)
    return None


def check_command(command: str, depth: int = 0, _sub: bool = False) -> str | None:
    """The ask reason for a Bash command, or None. *_sub*: a substitution's body."""
    if depth > 3:
        return _raw(command)
    if _FORK_BOMB.search(command):
        return REASONS["fork_bomb"]
    if len(command) > MAX_PARSE:
        return _check_long(command, depth)
    try:
        text, bodies, skeleton, heredocs = _Scan(command).result()
    except (_UnparsedError, RecursionError):
        try:
            reason = _check_tokens(command, depth)
        except ValueError:
            reason = None
        return reason or _raw(command)
    # Both views of the command: the full text (substitutions and heredoc lines
    # read as commands, as before) and the skeleton, which follows bash's own
    # nesting. A substitution's heredoc is data unless a shell reads it, so a
    # commit message in `$(cat <<'EOF' ... EOF)` is not read as commands.
    if not (_sub and heredocs):
        try:
            if reason := _check_tokens(text, depth):
                return reason
        except ValueError:
            if reason := _raw(text):
                return reason
    for body in dict.fromkeys(bodies):
        if reason := check_command(body, depth + 1, _sub=True):
            return reason
    if skeleton is None:
        return None
    try:
        return _check_tokens(skeleton, depth, heredocs)
    except ValueError:
        return _raw(skeleton)


def _check_long(command: str, depth: int) -> str | None:
    deadline = time.perf_counter() + _LONG_BUDGET_S
    seen: set[str] = set()  # pieces already found safe
    for piece in _SPLIT.split(command):
        if piece in seen:
            continue
        if time.perf_counter() > deadline:
            return REASONS["too_long"]
        if len(piece) > _SMALL:
            head = piece.strip()[:_PIECE]
            if _AW_RAW.search(head) and _GUARD_RAW.search(head):
                return REASONS["guard_off"]
            if _FALLBACK.search(head):
                return REASONS["destructive"]
        elif _RELEVANT.search(piece) and (reason := check_command(piece, depth)):
            return reason
        seen.add(piece)
    return None


def check(tool_name: str, tool_input: object) -> str | None:
    """The ask reason for a PreToolUse call, or None."""
    if not isinstance(tool_input, dict):
        return None
    if tool_name == "Bash" and isinstance(tool_input.get("command"), str):
        return check_command(tool_input["command"])
    path = tool_input.get(_FILE_TOOLS.get(tool_name, ""))
    if isinstance(path, str) and is_guard_file(path):
        return REASONS["guard_off"]
    if tool_name == "Read" and isinstance(tool_input.get("file_path"), str):
        label = secret_label(tool_input["file_path"])
        return REASONS["secret"].format(label) if label else None
    return None
