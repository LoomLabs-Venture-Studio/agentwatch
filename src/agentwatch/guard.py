r"""Command guard: the coach hook asks the user before a catastrophic call.

Runs on Claude Code's PreToolUse, before the loop breaker. A match returns a
fixed reason; coach turns it into `"permissionDecision": "ask"`, so Claude
Code shows the user a permission prompt. A false positive costs one click.

Bash commands are read twice under one clock, and either reading asking asks
(check_command): the #222 reading below, and a new one that also decodes
`$'...'` (`\n`, `\xHH`, `\NNN`, `\uHHHH`, ...), reads `$"..."` as `"..."`, checks
`sh <(X)` / `sh < <(X)` as `X | bash`, and keeps `#` as code mid-word (`a##b`)
and inside `(( ))` / `$(( ))` whose `))` closes on the same line, an
`a[...]=` assignment subscript and an extglob group (`@( )`) closed on the same
line. Since #228 a third reading (the new one, run when the command has a `[`)
also reads any `name[...]` at a command's start up to its `]` (quotes, `$` and
`#` inside: `a[$i #x]=1`; without a `]` it is an ordinary word, a second one
asks). The new readings ask when a comment
with a quote or substitution sits inside a `((`, `$((` or extglob group still
open from an earlier line (bash may read that `#` as code), checks a
here-string, heredoc or `<(...)` on a group or loop end (`{ bash; } <<< X`,
`( sh ) < <(X)`, `(bash)<<<X`, `done < <(X)`, `env -S 'bash -s' < <(X)`) or an
`exec` with only redirections (also after `VAR=`, `command`, `-a NAME`, `{fd}<<<`:
`exec < <(X); bash`) as a script when the command names a shell anywhere, and both readings decode
`echo` escapes (unless the last of -e/-E is -E; zsh and dash decode them by
default), unwrap `env -S` / `--split-string` (`\c` ends it; 3 levels, deeper
asks), skip `a[...]=x` prefix assignments like `VAR=x`, take
`gxargs` as xargs, skip the value of a shell's long option (`bash --rcfile F`)
and match any shell name (bash5, bash-5.2, ksh93, mksh, yash, ...; fish -C
runs its script too). Each reading uses bash's quoting rules (_Scan): comments
(`#` at a word start, up to the newline) and `\<newline>`
continuations are removed, and the commands bash runs inside
`$(...)`, backticks, `<(...)` and `>(...)` are checked on their own, also
inside double quotes, `${...}` and unquoted heredocs (not inside single
quotes). The rest is split with shlex into simple commands (on `;`, `&&`, `||`,
`|`, `&`, newlines, `(`, `)`, backticks and `$(`), leading `sudo`, `env`,
`VAR=value`, `timeout N`, `nohup`, `setsid`, `builtin`, `wsl [-d X] [-e]`, ...,
`coproc [NAME]`, `function NAME` and shell keywords (`if`, `do`, `{`, `!`, ...)
are skipped, so a function body is checked as commands (a definition that only
holds a guarded command asks too), and `bash/sh/zsh -c '<script>'`,
`script -c '<cmd>'`, `eval ...`, `cmd /c|//c|/k ...` (also glued `/c"..."`),
`powershell/pwsh` (-c, -Command or a prefix from -com, or bare args) and
`xargs CMD` (CMD plus the items it reads when the guard knows them: echo or
printf output, here-strings, heredocs; `-I` replaces per line, `-0`/`-d` read
records; over _XARGS_MAX chars of input asks) are checked
recursively, as are scripts a shell or `. /dev/stdin` reads on stdin
(heredocs, here-strings, what `echo` and `printf` print: `%b`, `%c`, `.N`, `*`,
`\c`); `sh -c "$(curl ...)"`, `bash <(curl ...)`, `source <(wget ...)`, curl,
wget or a decoder (`base64 -d`, `xxd`, `openssl`, `gunzip`, `tr`, ...) piped
into a shell that reads stdin (not `-n` without `-i`), and a decoder inside `$( )` or
backticks run as a script or command count as pipe to shell. Program
names are lowercased, without `.exe` and directory (`/` or backslash). Nesting
deeper than 3 (wrappers or substitutions) gets the raw patterns. A check that
runs past _BUDGET_S (1 s) asks, as does an error in the guard itself. Not caught:
`powershell -EncodedCommand`
(not decoded), `wsl --shell-type X`, `script --command=...`, `curl | cmd` or
`| powershell`, scripts passed through variables, aliases, function calls,
traps, positional parameters or array subscripts (`x=...; sh -c "$x"`,
`$x -rf ~`, `alias`, `trap '...' EXIT`, `sh -c '$1 ...' _ rm`,
`x='a[$(...)]'`, PS4, BASH_ENV), a program name built at run time (`$(echo rm)`,
`${x:-rm}`), xargs items the guard cannot see (`find / | xargs rm -rf`,
`xargs -a FILE`), stdin scripts other programs print (`cat x.sh | bash`,
`python -c ... | sh`), `$'...'` in a command that cannot be parsed,
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
                       r"|npmrc|pypirc|\.docker|\.kube|\.pem|\.key|agentwatch|agentguard"
                       r"|\$['\"]|base(?:32|64|nc)|xxd|uudecode|openssl|z(?:std)?cat|unzstd"
                       r"|gunzip|gzip|bunzip2|bzcat|unxz|xzcat|unlzma|lzcat",
                       re.IGNORECASE)
# ponytail: wall-clock cap on one check; past it the guard asks instead of
# finishing. Raise it (under coach.BUDGET_S) if real commands hit it.
_BUDGET_S = 1.0
_deadline: float | None = None  # set by the outermost check_command
_legacy = False  # the reading in progress (see check_command)
_subscripts = False  # the third reading: `name[...]` read up to its `]`
# What the new reading reads differently: comments, $'...', $"...", <(...).
_NEW_SYNTAX = re.compile(r"#|\$['\"]|<\(|[;&|()]<")  # [;&|()]<: a glued `)<<<`
_HOME_RE = re.compile(r"(?:~|\$HOME|\$\{HOME\})(?=/|$)")
_DISK = re.compile(r"/dev/(?:sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|disk\d)")
_HARMLESS_DEV = ("/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/fd/")
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
# Any shell name, also versioned or renamed builds: bash5, bash-5.2, ksh93, mksh,
# rbash, yash, tcsh, zsh-5.9 (_is_shell). Linear: no nested quantifiers.
_SHELL_RE = re.compile(r"(?:(?:r?ba|da|z|k|mk|pdk|lk|ok|ya?|a|po|t?c|o|bo|hu)?sh|fish)"
                       r"(?:[-_]?\d+(?:\.\d+)*)?")
# Group and loop ends: a stdin redirection after one feeds every command inside.
_CLOSERS = {"}", "done", "fi", "esac"}
# bash/zsh long options that take no value; any other `--opt` is read as taking
# the next word, so a value (`--rcfile /dev/null`) is never mistaken for a script file.
_SHELL_LONG = {"login", "noediting", "noprofile", "norc", "posix", "protected", "restricted",
               "verbose", "version", "help", "debugger", "dump-strings", "dump-po-strings",
               "pretty-print", "interactive", "no-rcs", "no-globalrcs", "private", "features"}
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
# `coproc NAME <compound command>`: the NAME is skipped only before one of these.
_COMPOUND = {"{", "while", "until", "if", "for", "case", "select", "[[", "(("}
# Their output piped into a shell is a script nobody read (like curl | sh).
_DOWNLOADERS = {"curl", "wget"}
_DECODERS = {"base64", "base32", "basenc", "xxd", "uudecode", "openssl", "gzip", "gunzip",
             "zcat", "bzip2", "bunzip2", "bzcat", "xz", "unxz", "xzcat", "lzma", "unlzma",
             "lzcat", "zstd", "unzstd", "zstdcat", "rev", "tr"}
_STDIN = {"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"}
_SEPARATORS = set(";&|()`\n")
_OPS = set(";&|()")
_REDIR = re.compile(r"[<>]{1,3}[&|]?|&>{1,2}")  # shlex tokens of a redirection operator
_PIPES = ("|", "|&")
_READERS = {"cat", "less", "more", "head", "tail", "cp", "scp", "bat"}
# The guard's settings file is always <user_state_dir>/agentwatch/coach/guard
# (coach.guard_path()); matching the tail also catches ~, $HOME and %VAR% spellings.
_GUARD_FILE = "/agentwatch/coach/guard"
_AW_NAMES = {"agentwatch", "agentwatch-monitor", "agentwatch.cli", "agentguard"}
_LAUNCHERS = re.compile(r"python[\d.]*w?|py|uvx?|pipx|g?xargs|npx")
_XARGS = {"xargs", "gxargs"}  # gxargs: GNU xargs as Homebrew installs it
_AW_RAW = re.compile(r"agent(?:watch|guard)", re.IGNORECASE)
_GUARD_RAW = re.compile(r"\bguard\s+off\b|agentwatch[/\\]+coach[/\\]+guard\b", re.IGNORECASE)
# PowerShell options that take a value: matched as a prefix of the long name,
# plus the aliases that are not prefixes.
_PS_VALUE = ("windowstyle", "version", "workingdirectory", "outputformat", "inputformat",
             "configurationname", "configurationfile", "psconsolefile", "settingsfile",
             "custompipename")
_PS_ALIASES = {"wd", "of", "if"}
_ASSIGN_WORD = re.compile(r"[A-Za-z_]\w*\+?=")
_SUB_OPEN = re.compile(r"[A-Za-z_]\w*\[")
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
    "unchecked": "agentwatch: the guard could not check this command. Allow it?",
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


def _is_shell(prog: str) -> bool:
    """*prog* (from _prog) names a shell: sh, bash, bash5, ksh93, mksh, ..."""
    return prog in _SHELLS or _SHELL_RE.fullmatch(prog) is not None


def _mentions_shell(text: str) -> bool:
    """A shell name (or /dev/stdin, for `. /dev/stdin`) appears as a word in *text*."""
    return any(_is_shell(_prog(m.group())) or m.group() in _STDIN
               for m in re.finditer(r"[^\s;&|()<>`'\"{}=]+", text))


class _UnsureError(Exception):
    """The guard cannot tell how bash reads the command: check_command asks."""


_ENV_LONG_VALUE = ("unset", "chdir")  # env long options that take a value


def _env_split(argv: list[str]) -> list[str] | None:
    """argv with `env -S STRING` / `--split-string=STRING` replaced by the words
    env splits STRING into (`env -S 'rm -rf ~'` -> env rm -rf ~); None without one."""
    for k, w in enumerate(argv):
        if _prog(w) == "env" and (split := _env_split_at(argv, k + 1)) is not None:
            return split
    return None


def _env_split_at(argv: list[str], j: int) -> list[str] | None:
    """_env_split for the env options that start at argv[j]."""
    while j < len(argv) and argv[j].startswith("-") and argv[j] != "--":
        a = argv[j]
        name, eq, val = a[2:].partition("=")
        if a.startswith("--") and name and "split-string".startswith(name):
            after = j + 1 if eq else j + 2
            val = val if eq else (argv[j + 1] if j + 1 < len(argv) else "")
        elif m := re.fullmatch(r"-[0iv]*S(.*)", a, re.DOTALL):
            after = j + 1 if m.group(1) else j + 2
            val = m.group(1) or (argv[j + 1] if j + 1 < len(argv) else "")
        else:
            j += 2 if a in ("-u", "-C") or (
                a.startswith("--") and not eq and name in _ENV_LONG_VALUE) else 1
            continue
        # env's own escapes: \_ \t \n are separators (or spaces), \c ends the
        # string; the rest as shlex reads them.
        for esc in re.finditer(r"\\(.)", val, re.DOTALL):
            if esc.group(1) == "c":
                val = val[:esc.start()]
                break
        val = re.sub(r"\\(?:[_tnvfr]|(\\))", lambda e: e.group(0) if e.group(1) else " ", val)
        try:
            words = shlex.split(val)
        except ValueError:
            words = val.split()
        return argv[:j] + words + argv[after:]
    return None


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
        if not _legacy and (k := tok.find("<")) > 0 and set(tok[:k]) <= _OPS \
                and set(tok[k:]) <= _OPS | {"<", ">"}:
            # `( bash )<<<'x'`: shlex glues `)<<<`; the new reading splits it.
            if argv:
                out.append((argv, sep))
            argv, sep = [tok[k:]], tok[:k]
            continue
        if tok and set(tok) <= _SEPARATORS | {"$"}:
            if argv:
                out.append((argv, sep))
            argv, sep = [], tok
        else:
            argv.append(tok)
    if argv:
        out.append((argv, sep))
    return out


def _assign_end(argv: list[str], i: int) -> int | None:
    """The index after the assignment that starts at argv[i] (`x=1`, `x+=1`,
    `a[1]=x`, or `a[$i` `#x]=1`: shlex splits a subscript on blanks), else None."""
    word = argv[i]
    if _ASSIGN_WORD.match(word):
        return i + 1
    if not _SUB_OPEN.match(word):
        return None
    for k in range(i, len(argv)):  # the word holding `]=` ends it; a bare `]`: not one
        if "]=" in argv[k] or "]+=" in argv[k]:
            return k + 1
        if "]" in argv[k]:
            return None
    return None


def _bare_exec(argv: list[str]) -> bool:
    """`exec` with only redirections, also after VAR=x, `command`, `builtin` and
    with -a NAME / -c / -l: it changes the shell's own stdin (`exec <<< X; bash`)."""
    i, seen, n = 0, False, len(argv)
    while i < n:
        word = argv[i]
        if not seen and (j := _assign_end(argv, i)) is not None:
            i = j
        elif not seen and word in ("command", "builtin", "-p"):
            i += 1
        elif not seen and word == "exec":
            seen, i = True, i + 1
            while i < n and re.fullmatch(r"-[acl]+", argv[i]):
                i += 2 if "a" in argv[i] else 1
        elif _REDIR.fullmatch(word):
            i += 2
        elif i + 1 < n and _REDIR.fullmatch(argv[i + 1]) and (
                word.isdigit() or re.fullmatch(r"\{\w+\}", word)):
            i += 3  # 0<<< X, {fd}<<< X
        else:
            return False
    return seen


def _strip_prefixes(argv: list[str]) -> list[str]:
    """argv from the program on; leading redirections (`2>/dev/null rm ...`) are
    moved to the end, where _check_argv still sees them."""
    i, redirs = 0, []
    while i < len(argv):
        word = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else ""
        if _REDIR.fullmatch(word) or (word.isdigit() and _REDIR.fullmatch(nxt)):
            j = i + (1 if _REDIR.fullmatch(word) else 2)
            redirs += argv[i:j + 1]
            i = j + 1
        elif (j := _assign_end(argv, i)) is not None:  # VAR=x, a[1]=x, a[$i #x]=x
            i = j
        elif word in _KEYWORDS:
            i += 1
        elif word in ("function", "coproc"):  # function NAME { ...; }, coproc [NAME] cmd
            i += 1
            if (word == "function" and i < len(argv) and not _REDIR.fullmatch(argv[i])) or (
                    word == "coproc" and i + 1 < len(argv) and argv[i + 1] in _COMPOUND):
                i += 1  # the name (`function > /dev/sda` is a redirection, not a name)
        elif (prefix := _prog(word)) in _PREFIXES:
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                i += 2 if argv[i] in _PREFIXES[prefix] else 1
            if prefix == "timeout":
                i += 1  # the duration
        else:
            break
    return argv[i:] + redirs


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


def _runs_stdin(prog: str, args: list[str]) -> bool:
    """A shell, or `source`/`.` of /dev/stdin: it runs what it reads on stdin."""
    return _is_shell(prog) or (prog in ("source", ".") and bool(args) and args[0] in _STDIN)


def _script_on_stdin(prog: str, args: list[str]) -> bool:
    """The shell reads its script from stdin: no -c and no script file (or -s, -).
    -n (syntax check only) counts only without -i: bash ignores -n when interactive."""
    if not _is_shell(prog):
        return True  # source /dev/stdin
    interactive = any(re.fullmatch(r"-[a-zA-Z]*i[a-zA-Z]*", a) for a in args)
    skip = False
    for a in args:
        if re.fullmatch(r"-[a-zA-Z]*n[a-zA-Z]*", a) and not interactive:
            return False  # -n: syntax check only
        if skip:
            skip = False
        elif a == "--":
            continue
        elif re.fullmatch(r"-[a-z]*c[a-z]*", a) or a == "--command":
            return False
        elif a in ("-o", "+o", "-O", "+O") or (
                a.startswith("--") and "=" not in a and a[2:] not in _SHELL_LONG):
            skip = True  # --rcfile FILE, --init-file FILE, an unknown --opt VALUE
        elif re.fullmatch(r"-[a-zA-Z]*s[a-zA-Z]*", a):
            return True
        elif not a.startswith(("-", "+")):
            return a in _STDIN
    return True


_XARGS_VALUE = "adEILnPs"  # short options with a value (also -e, -i, -l when glued)
_XARGS_LONG = {"arg-file", "delimiter", "max-args", "max-procs", "max-chars",
               "process-slot-var"}
_XARGS_LINES = 100
_XARGS_MAX = 100_000  # more input than this asks (too_long): shlex is slow on it


def _xargs(args: list[str], piped_from: set[str], depth: int, stdin: list[str]) -> str | None:
    """xargs runs its command with the items it reads (when the guard knows them:
    echo/printf, here-strings, heredocs) appended, or put in place of -I's string."""
    if depth > 3:
        return _raw(" ".join(args))
    i, replace, reads_stdin, delim = 0, None, True, None
    while i < len(args) and args[i].startswith("-") and args[i] != "-":
        a = args[i]
        i += 1
        if a == "--":
            break
        if a.startswith("--"):
            name, eq, val = a[2:].partition("=")
            if name == "replace":
                replace = val or "{}"
            elif name == "null":
                delim = ""
            elif name == "delimiter":
                delim = _decode(val or (args[i] if i < len(args) else ""), "fmt")[0][:1]
            elif name == "arg-file":
                reads_stdin = False
            if not eq and name in _XARGS_LONG:
                i += 1
            continue
        for j, o in enumerate(a[1:], 1):
            if o == "0":
                delim = ""
            if o in _XARGS_VALUE or o in "eil":
                val = a[j + 1:]
                if not val and o in _XARGS_VALUE:
                    val, i = (args[i] if i < len(args) else ""), i + 1
                if o in "Ii":
                    replace = val or "{}"
                elif o == "a":
                    reads_stdin = False
                elif o == "d":
                    delim = _decode(val, "fmt")[0][:1]
                break
    cmd = args[i:] or ["echo"]
    text = "\n".join(stdin) if reads_stdin else ""
    if len(text) > _XARGS_MAX:
        return REASONS["too_long"]
    if delim is not None:  # -0 / -d: records, not shell words
        items = [r for piece in (stdin if reads_stdin else [])
                 for r in piece.split(delim or "\0") if r]
    if replace is None:
        if delim is None:
            text = text.replace("\0", " ")
            try:
                items = shlex.split(text)
            except ValueError:
                items = text.split()
        argvs = [cmd + items]
    else:
        lines = items if delim is not None else [
            ln.strip(" \t") for ln in text.split("\n") if ln.strip()]
        lines = lines[:_XARGS_LINES]
        if sum(len(ln) for ln in lines) * sum(a.count(replace) for a in cmd) > _PRINTF_MAX:
            return REASONS["too_long"]
        argvs = [[a.replace(replace, ln) for a in cmd] for ln in lines] or [cmd]
    for inner in argvs:
        _tick()
        inner = _strip_prefixes(inner)
        if inner and _is_shell(_prog(inner[0])) and piped_from & (_DOWNLOADERS | _DECODERS):
            return REASONS["pipe_shell"]
        if reason := _check_argv(inner, piped_from, depth + 1):
            return reason
    return None


def _check_argv(argv: list[str], piped_from: set[str], depth: int,
                stdin: list[str] | None = None) -> str | None:
    """*stdin*: the scripts the guard knows reach this command's stdin (for xargs)."""
    if not argv:
        return None
    prog, args = _prog(argv[0]), argv[1:]
    if argv[0] == _DL:  # $(curl ...) or $(... | base64 -d) run as the command
        return REASONS["pipe_shell"]
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
    if prog in _XARGS:
        return _xargs(args, piped_from, depth, stdin or [])
    if prog == "eval":  # bash joins eval's args and parses them again
        return _script(" ".join(args), depth)
    if _is_shell(prog) and piped_from & _DOWNLOADERS:
        return REASONS["pipe_shell"]
    if _runs_stdin(prog, args) and piped_from & (_DOWNLOADERS | _DECODERS) \
            and _script_on_stdin(prog, args):  # base64 -d | sh, curl | . /dev/stdin
        return REASONS["pipe_shell"]
    if _is_shell(prog) or prog in ("source", "."):  # bash <(curl ...), . <(wget ...)
        if _DL in args or any(
                a == "<(" and _prog(b) in ("curl", "wget") for a, b in zip(args, args[1:])):
            return REASONS["pipe_shell"]
    if _is_shell(prog) or prog == "script":
        for i, a in enumerate(args):
            if prog.startswith("fish") and (  # fish -C / --init-command runs a script too
                    a.startswith("--init-command=") or (a.startswith("-C") and len(a) > 2)):
                if reason := _script(a.split("=", 1)[1] if a.startswith("--") else a[2:], depth):
                    return reason
                continue
            if i == len(args) - 1:
                break
            if prog.startswith("fish") and a in ("-C", "--init-command"):
                if reason := _script(args[i + 1], depth):
                    return reason
                continue
            if re.fullmatch(r"-[a-z]*c[a-z]*", a) or a == "--command":
                j = i + 1
                while j < len(args) - 1 and args[j].startswith("-") and args[j] != "-":
                    j += 1  # bash -c -- 'cmd', bash -c -e 'cmd'
                    if args[j - 1] == "--":
                        break
                return _script(args[j], depth)
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
_HEX = r"\\(?:x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{1,4})|U([0-9A-Fa-f]{1,8})|"
# Per mode: $'...' (\cX is a control char), a printf format (\c is literal)
# and printf's %b (\0NNN octal too; \c ends all output).
_ESCAPE = {"ansi": re.compile(_HEX + r"([0-7]{1,3})|c(.)|(.))", re.DOTALL),
           "fmt": re.compile(_HEX + r"([0-7]{1,3})|()(.))", re.DOTALL),
           "b": re.compile(_HEX + r"(0[0-7]{0,3}|[0-7]{1,3})|(c)|(.))", re.DOTALL)}
_ESCAPES = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n",
            "r": "\r", "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _decode(text: str, mode: str) -> tuple[str, bool]:
    r"""Backslash escapes as bash reads them in *mode*; True when %b's \c stopped
    the output. In $'...' a NUL ends the string."""
    out, at = [], 0
    for m in _ESCAPE[mode].finditer(text):
        out.append(text[at:m.start()])
        at = m.end()
        hx, u, big, octal, ctl, other = m.groups()
        if other is not None:
            out.append(_ESCAPES.get(other, "\\" + other))
            continue
        if ctl is not None:
            if mode == "b":
                return "".join(out), True
            n = ord(ctl) & 0x1F
        else:
            n = int(octal, 8) & 0xFF if octal else int(hx or u or big, 16)
        out.append(chr(n) if n < 0x110000 else "")
    out.append(text[at:])
    text = "".join(out)
    return (text.split("\0", 1)[0] if mode == "ansi" else text), False


def _unescape(text: str) -> str:
    """bash's $'...' escapes; a NUL ends the string."""
    return _decode(text, "ansi")[0]


def _ansi_c(body: str) -> str:
    """$'...' as the single-quoted word bash reads it: `$'r\x6d'` -> `'rm'`."""
    return "'" + _unescape(body).replace("'", "'\\''") + "'"
_BACKTICK = re.compile(r"(?:[^\\`]|\\.)*`", re.DOTALL)
_WORD_END = " \t\n;&|()<>"
# An array element assignment `a[...]=` (`+=`): bash reads the subscript as one
# word, so a `#` in it is not a comment. Bounded so a scan stays linear.
_ASSIGN_SUB = re.compile(r"[A-Za-z_]\w*\[[^]\n;&|()'\"`$\\]{0,500}\]\+?=")
# Any other `name[` at a command's start (bash reads it the same way): _Scan.subscript.
_SUB_RUN = re.compile(r"[^\\'\"`$\[\]\n]+")
# A comment holding one of these could change how bash reads the lines after it.
_PAIR_CHARS = re.compile(r"[\\'\"`$()]")
_MAX_NEST = 50
_ECHOES = {"echo", "printf"}
# The script a shell runs is the output of curl/wget: sh -c "$(curl -fsSL URL)".
_DOWNLOAD = re.compile(r"\s*(?:\$\(|`)\s*(?:\S*[/\\])?(?:curl|wget)(?:\.exe)?\s",
                       re.IGNORECASE)
_DL_BODY = re.compile(r"\s*(?:\S*[/\\])?(?:curl|wget)(?:\.exe)?\s", re.IGNORECASE)
# A decoder in a substitution's pipeline: its output is no more reviewed than a
# download (`eval "$(echo ... | base64 -d)"`). rev and tr count only in pipes.
_DECODER = re.compile(
    r"(?:base(?:32|64|nc)|xxd|uudecode|openssl|g?unzip|gzip"
    r"|zcat|bzip2|bunzip2|bzcat|xz|unxz|xzcat|lzma|unlzma|lzcat|zstd|unzstd|zstdcat)"
    r"(?:\.exe)?(?=[\s|)`]|$)", re.IGNORECASE)


def _decode_stage(text: str) -> bool:
    r"""A decoder starts a pipeline stage in *text*: what the regex
    `(?:^|[|`(])\s*(?:\S*[/\\])?<decoder>` finds, in one linear pass (that regex
    backtracks quadratically on a long run such as `|/|/|/...`)."""
    starts = {m.start() for m in _DECODER.finditer(text)}
    if not starts:
        return False
    # state: 1 after `^`/a separator and blanks, 2 in a word after that, 0 neither.
    state, before, last = 1, 0, max(starts)
    for i, c in enumerate(text[:last + 1]):
        if i in starts and (state == 1 or (before and text[i - 1] in "/\\")):
            return True
        before = state
        if c in "|`(":
            state = 1
        elif c.isspace():
            state = 1 if state == 1 else 0
        else:
            state = 2 if state else 0
    return False
# In the skeleton a substitution running curl/wget becomes this word, so
# `eval $(curl ...)` and `bash <(curl ...)` still read as pipe to shell.
_DL = "__agentwatch_download__"


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
        self.new = not _legacy  # False: the #222 reading (see check_command)
        self.subs = self.new and _subscripts  # read `name[...]` like bash (#228)
        self._pairs: dict[int, int] | None = None
        self._has_shell: bool | None = None
        self.unclosed = False  # a `name[` without its `]` was seen (try_subscript)
        self.level = 0  # enclosing substitutions
        self.nest = 0
        self.spans: list[tuple[int, int, str]] = []  # skeleton cuts (start, end, filler)
        self.bodies: list[str | tuple[int, int, str]] = []
        self.heredocs: list[str] = []
        self.pending: list[tuple[str, bool, bool]] = []  # (delimiter, <<-, quoted)

    def result_bodies(self) -> list[str]:
        text = "".join(self.out)
        return [b if isinstance(b, str) else text[b[0]:b[1]] + b[2] for b in self.bodies]

    def closes_on_line(self, i: int) -> int | None:
        """Index of the `)` matching the `(` at *i* on the same line (quotes
        ignored), or None."""
        if self._pairs is None:
            self._pairs, stack = {}, []
            for m in re.finditer(r"[()\n]", self.s):
                c = m.group()
                if c == "(":
                    stack.append(m.start())
                elif c == ")" and stack:
                    self._pairs[stack.pop()] = m.start()
                elif c == "\n":
                    stack.clear()
        return self._pairs.get(i)

    def has_shell(self) -> bool:
        """The command names a shell anywhere (_mentions_shell), computed once."""
        if self._has_shell is None:
            self._has_shell = _mentions_shell(self.s)
        return self._has_shell

    def try_subscript(self, m: re.Match) -> int | None:
        """subscript() for the `name[` *m* matched; None (output rolled back) when
        it has no `]`, so the caller reads `name[` as an ordinary word. A second
        such `name[` asks: scanning each to the end would be quadratic."""
        if self.unclosed:
            raise _UnsureError
        saved = (len(self.out), self.n, len(self.spans), len(self.bodies),
                 len(self.heredocs), list(self.pending), self.level, self.nest)
        try:
            self.emit(m.group())
            return self.subscript(m.end())
        except _UnparsedError:
            out, self.n, spans, bodies, docs, self.pending, self.level, self.nest = saved
            del self.out[out:], self.spans[spans:], self.bodies[bodies:], self.heredocs[docs:]
            self.unclosed = True
            return None

    def subscript(self, i: int) -> int:
        """`name[` at a command's start: bash reads the word up to the matching `]`,
        across blanks and newlines, with quotes and substitutions inside and `#`
        as code (`a[$i #x]=1`). Returns the index after the `]`."""
        s, end, depth = self.s, len(self.s), 1
        while i < end:
            if m := _SUB_RUN.match(s, i):
                self.emit(m.group())
                i = m.end()
                continue
            c = s[i]
            if c == "\\":
                if not s.startswith("\n", i + 1):
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
            elif c == "\n" and self.pending:
                raise _UnparsedError  # a heredoc body inside a subscript: not read
            else:
                self.emit(c)
                i += 1
                depth += {"[": 1, "]": -1}.get(c, 0)
                if not depth:
                    return i
        raise _UnparsedError

    def arithmetic(self, i: int) -> bool:
        """`((` at *i* is arithmetic: its `))` closes on the same line. Otherwise
        bash reads it as nested subshells, where `#` starts a comment."""
        close = self.closes_on_line(i)
        return close is not None and self.closes_on_line(i + 1) == close - 1

    def emit(self, text: str) -> None:
        self.out.append(text)
        self.n += len(text)

    def enter(self) -> None:
        self.nest += 1
        if self.nest > _MAX_NEST:
            raise _UnparsedError

    def result(self) -> tuple[str, list[str], list[str]]:
        self.code(0, False)
        return "".join(self.out), self.result_bodies(), self.heredocs

    def skeleton(self, text: str) -> str | None:
        """The skeleton of result()'s *text*; None when nothing was cut."""
        if not self.spans:
            return None
        parts, at = [], 0
        for a, b, filler in sorted(self.spans):
            if a >= at:
                k = a + (1 if text[a:a + 1] == "`" else 2)  # a:a+1: an empty heredoc ends text
                if filler and (_DL_BODY.match(text, k, b) or _decode_stage(text[k:b - 1])):
                    filler = _DL
                parts += [text[at:a], filler]
                at = b
        parts.append(text[at:])
        return "".join(parts)

    def code(self, i: int, closes: bool, arith: bool = False) -> int:
        """Unquoted shell code up to the `)` that closes a substitution (closes)
        or the end; returns the index of that `)`. *arith*: inside `$((...))`,
        where `#` is not a comment."""
        s, end = self.s, len(self.s)
        word_start = cmd_pos = True
        new, subs = self.new, self.subs
        arith = arith and new
        shell = False  # the current command names a shell: `bash < <(...)` feeds it
        # The current command is a group/loop end (`}`, `done`, a subshell's `)`) or
        # `exec`: `{ bash; } < <(...)` and `exec < <(...); bash` feed a shell too.
        group = False
        pre = False  # after `command` / `builtin` at a command's start: `command exec`
        assign = False  # the current word is an assignment: the next word is a command too
        parens = cases = 0
        quiet: list[int] = []  # paren depths where `((` or an extglob `@(` opened
        # Paren depths where a `((`, `$((` or extglob group opened that does not close
        # on its line: bash may read `#` there as code or as a comment (see "#" below).
        unsure: list[int] = []
        while i < end:
            if new and word_start and cmd_pos:
                if m := _ASSIGN_SUB.match(s, i):
                    self.emit(m.group())  # a[... # ...]= : one word, `#` is not a comment
                    i, word_start, assign, cmd_pos = m.end(), False, True, cmd_pos and subs
                    continue
                if subs and (m := _SUB_OPEN.match(s, i)):  # a[$i #x]=1: bash reads up to the `]`
                    if (close := self.try_subscript(m)) is not None:
                        i, word_start = close, False
                        assign = cmd_pos = s.startswith(("=", "+="), i)
                        continue
                    # No `]`: an ordinary word (bash stops at a syntax error there).
                assign = _ASSIGN_WORD.match(s, i) is not None
            if m := _CODE_RUN.match(s, i):
                word = m.group()
                if word_start and (_is_shell(_prog(word)) or word in ("source", ".")):
                    shell = True
                if cmd_pos and word == "case":
                    cases += 1
                elif cmd_pos and word == "esac" and cases:
                    cases -= 1
                # `env -S 'bash -s' < <(...)`: env may run a shell named in a quoted word.
                if (cmd_pos and word in _CLOSERS) or ((cmd_pos or pre) and word == "exec") or (
                        word_start and _prog(word) == "env"):
                    group = True
                pre = (cmd_pos or pre) and word in ("command", "builtin", "-p")
                cmd_pos = cmd_pos and (word in _KEYWORDS or (subs and assign))
                self.emit(word)
                i, word_start = m.end(), False
                continue
            c = s[i]
            if c in " \t":
                self.emit(c)
                i, word_start = i + 1, True
                continue
            if c == "#" and new and not (word_start and not (arith or quiet)):
                self.emit(c)  # mid-word (a##b), or inside (( )), $(( )) or @( )
                i, word_start, cmd_pos = i + 1, False, False
                continue
            if c == "#" and word_start:  # a comment, up to the newline
                nl = s.find("\n", i)
                nl = end if nl < 0 else nl
                # Inside a `((`/extglob group still open from an earlier line, bash may
                # read this `#` as code: a quote, `$`, backtick, backslash or paren in it
                # could then hide what follows. Not sure how bash reads it: ask.
                if unsure and _PAIR_CHARS.search(s, i, nl):
                    raise _UnsureError
                i = nl
                continue
            if c == "\n":
                self.emit(c)
                i, word_start, cmd_pos, shell, group, pre = i + 1, True, True, False, False, False
                quiet.clear()
                if self.pending:
                    i = self.heredoc_bodies(i)
                continue
            word_start = pre = False
            cmd_pos = cmd_pos and subs and assign and c in "'\"$`\\"
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
                i = self.sub(i, 2, feeds_shell=new and c == "<" and (
                    shell or (group and self.has_shell())))
            else:  # ; & | ( ) < >
                word_start, cmd_pos = True, c in "(;&|"
                if c in ";&|()":
                    shell = group = False
                if c == "(":
                    if new and ((s.startswith("((", i) and self.arithmetic(i)) or (
                            i and s[i - 1] in "!@?*+" and self.closes_on_line(i))):
                        quiet.append(parens)  # (( arithmetic )) or @(extglob)
                    elif new and (s.startswith("((", i) or (i and s[i - 1] in "!@?*+") or (
                            i > 1 and s[i - 2:i] == "$(")):
                        unsure.append(parens)  # may be arithmetic or extglob over lines
                    parens += 1
                elif c == ")":
                    if parens:
                        parens -= 1
                        group = True  # `( bash ) < <(...)`
                        if quiet and parens <= quiet[-1]:
                            quiet.pop()
                        if unsure and parens <= unsure[-1]:
                            unsure.pop()
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
            return self.sub(i, 2, arith=s.startswith("(", i + 2) and self.arithmetic(i + 1))
        if nxt == "{":
            return self.brace(i + 2, quoted)
        if nxt == "'" and not quoted:  # $'...': decoded, then single-quoted
            if not (m := _ANSI.match(s, i + 2)):
                raise _UnparsedError
            self.emit(_ansi_c(s[i + 2:m.end() - 1]) if self.new else s[i:m.end()])
            return m.end()
        if nxt == '"' and not quoted and self.new:  # $"...": a translated "..."
            return self.dq(i + 2, False)
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

    def sub(self, i: int, op_len: int, arith: bool = False, feeds_shell: bool = False) -> int:
        """$(...), <(...) or >(...). *feeds_shell*: a shell runs what the body
        prints (`bash <(...)`, `bash < <(...)`), so it is checked as `body | bash`."""
        _tick()
        self.enter()
        start = self.n
        self.emit(self.s[i:i + op_len])
        body = self.n
        outer, self.pending = self.pending, []  # a heredoc must end inside
        self.level += 1
        close = self.code(i + op_len, True, arith)
        self.level -= 1
        self.pending = outer
        if not self.level:
            self.bodies.append((body, self.n, " | bash" if feeds_shell else ""))
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
            _tick()
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


class _ShlexError(ValueError):
    """shlex could not split the command (unbalanced quotes)."""


def _tokens(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>`\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""  # _Scan removes comments; shlex starts one mid-word
    try:
        return list(lexer)
    except ValueError as e:
        raise _ShlexError(str(e)) from None


def _raw(command: str) -> str | None:
    """The check for a command that cannot be parsed: raw patterns."""
    if _AW_RAW.search(command) and _GUARD_RAW.search(command):
        return REASONS["guard_off"]
    return REASONS["destructive"] if _FALLBACK.search(command) else None


def _script(script: str, depth: int) -> str | None:
    """A script a shell runs (-c, eval, its stdin)."""
    if _DOWNLOAD.match(script) or script.strip() == _DL or (
            script.lstrip().startswith(("$(", "`")) and _decode_stage(script)):
        return REASONS["pipe_shell"]
    return check_command(script, depth + 1)


def _stdin_scripts(prog: str, argv: list[str]) -> list[str]:
    """What a command writes to a shell it is piped to, or a shell reads: here-strings,
    and the text echo/printf print."""
    out = [b for a, b in zip(argv, argv[1:]) if a == "<<<"]
    if prog in _ECHOES:
        words = [a for a in argv[1:] if not re.fullmatch(r"-[neE]+", a)]
        out.append(" ".join(words).replace("\\n", "\n"))
        if prog == "echo":
            # `echo -e` (and zsh's and dash's echo by default) decodes escapes like
            # printf %b; only a last -E turns that off. Both texts are checked.
            mode = ""
            for a in argv[1:]:
                if not re.fullmatch(r"-[neE]+", a):
                    break
                mode = a.replace("n", "")[-1:] or mode
            if mode != "E":
                out.append(_decode(" ".join(words), "b")[0])
        if prog == "printf":
            args = argv[1:]
            args = args[1:] if args[:1] == ["--"] else args
            if args and args[0] != "-v":
                out.append(_printf(args[0], args[1:]))
    return out


_DIRECTIVE = re.compile(r"%(?:%|[-+ #0']*(\*|[0-9]*)(?:\.(\*|[0-9]*))?([a-zA-Z]))")
_PRINTF_MAX = 1_000_000


def _count(text: str) -> int | None:
    """A printf precision as a number: ASCII digits only, at most 9 of them
    (`²`, `٣`, `-5`, a 5,000-digit number, `abc` -> None)."""
    return int(text) if len(text) <= 9 and re.fullmatch(r"[0-9]+", text) else None


def _printf(fmt: str, args: list[str]) -> str:
    r"""What printf prints: the format reused until the arguments run out
    (`printf '%s\n' a b` -> "a\nb\n"). %b expands escapes (its \c ends the
    output), %c is one char, `.N` cuts %s/%b, `*` takes an argument. NULs are
    kept (xargs -0 splits on them; _check_tokens drops them from a script)."""
    out, k, size = [], 0, 0

    def take() -> str:
        nonlocal k
        val = args[k] if k < len(args) else ""
        k += 1
        return val

    while True:
        at, start = 0, k
        for m in _DIRECTIVE.finditer(fmt):
            out.append(_decode(fmt[at:m.start()], "fmt")[0])
            at = m.end()
            if m.group() == "%%":
                out.append("%")
                continue
            width, prec, conv = m.groups()
            if width == "*":
                take()
            if prec == "*":
                prec = take()
            val, stop = take(), False
            if conv == "b":
                val, stop = _decode(val, "b")
            elif conv == "c":
                val = val[:1]
            if prec is not None and conv in "sb":
                n = _count(prec)  # else negative, huge or not a number: all of it
                val = val[:n] if n is not None else ("" if prec == "" else val)
            out.append(val)
            size += len(val)
            if stop:
                return "".join(out)
        out.append(_decode(fmt[at:], "fmt")[0])
        size += len(fmt)
        if k == start or k >= len(args) or size > _PRINTF_MAX:
            return "".join(out)


def _check_tokens(command: str, depth: int, heredocs: list[str] | None = None) -> str | None:
    """Check each simple command. *heredocs* are the bodies cut from *command*,
    in the order of its `<<` operators. Raises _ShlexError when shlex cannot parse."""
    pipeline: set[str] = set()  # programs earlier in the current pipeline
    stdin: list[str] = []  # scripts flowing down the current pipeline
    checked: set[str] = set()
    docs = iter(heredocs or ())
    has_shell = None  # computed when a group, subshell or exec gets a here-string or heredoc
    for argv, sep in _simple_commands(_tokens(command)):
        _tick()
        mine = [next(docs, "") for tok in argv if tok == "<<"] if heredocs else []
        raw0, bare_exec = (argv[0] if argv else ""), _bare_exec(argv)
        alt = _env_split(argv)  # env -S 'cmd args': checked as the command env runs too
        for _ in range(3):  # env -S "env -S '...'": unwrapped up to 3 times, then ask
            if alt is None or (nested := _env_split(alt)) is None:
                break
            alt = nested
        else:
            raise _UnsureError
        argv = _strip_prefixes(argv)
        if sep not in _PIPES:
            pipeline, stdin = set(), []
        prog = _prog(argv[0]) if argv else ""
        if argv:
            mine += _stdin_scripts(prog, argv)
        # `{ bash; } <<< X`, `( sh ) <<< X`, `done <<EOF`, `exec <<< X; bash`: the
        # shell inside the group (or run after exec) reads X as its script.
        if mine and (raw0 in _CLOSERS or sep == ")" or bare_exec):
            if has_shell is None:
                has_shell = _mentions_shell(command)
            if has_shell:
                for script in mine:
                    if script not in checked:
                        checked.add(script)
                        if reason := _script(script.replace("\0", ""), depth):
                            return reason
        reason = _check_argv(argv, pipeline, depth, stdin + mine)
        if reason:
            return reason
        if alt is not None:
            alt = _strip_prefixes(alt)
            alt_prog = _prog(alt[0]) if alt else ""
            if alt:
                mine += _stdin_scripts(alt_prog, alt)
            if reason := _check_argv(alt, pipeline, depth, stdin + mine):
                return reason
            if alt and _runs_stdin(alt_prog, alt[1:]):  # env -S 'sh': checked, flow unchanged
                for script in stdin + mine:
                    if script not in checked:
                        checked.add(script)
                        if reason := _script(script.replace("\0", ""), depth):
                            return reason
            pipeline.add(alt_prog)
        if argv:
            if _runs_stdin(prog, argv[1:]):  # it reads its stdin: what it prints is not a script
                for script in stdin + mine:
                    if script not in checked:
                        checked.add(script)  # bash skips NULs in a script
                        if reason := _script(script.replace("\0", ""), depth):
                            return reason
                stdin = []
            else:
                stdin += mine
            pipeline.add(prog)
    return None


class _TimeUpError(Exception):
    """The check ran past _BUDGET_S."""


def _tick() -> None:
    if _deadline is not None and time.monotonic() > _deadline:
        raise _TimeUpError


def check_command(command: str, depth: int = 0, _sub: bool = False) -> str | None:
    """The ask reason for a Bash command, or None. *_sub*: a substitution's body.
    Past _BUDGET_S the answer is "too_long" (ask), never None.

    Up to three readings share the clock: the #222 one (comments as before,
    `$'...'` and `$"..."` left as they are), the new one, and (when the command
    has a `[`) the new one reading `name[...]` up to its `]` (#228); any asking
    asks, so each later reading can only add asks. The new ones are skipped
    when the command has nothing they read differently."""
    global _deadline, _legacy, _subscripts
    if _deadline is not None:  # a nested check: the outermost one owns the clock
        return _check_command(command, depth, _sub)
    _deadline = time.monotonic() + _BUDGET_S
    try:
        _legacy = True
        if reason := _check_command(command, depth, _sub):
            return reason
        if not _NEW_SYNTAX.search(command):
            return None
        _legacy = False
        if reason := _check_command(command, depth, _sub):
            return reason
        if "[" not in command:
            return None
        _subscripts = True  # a third reading, so a subscript read wrong never hides more
        return _check_command(command, depth, _sub)
    except _TimeUpError:
        return REASONS["too_long"]
    except Exception:  # a bug in the guard asks, never allows
        return REASONS["unchecked"]
    finally:
        _deadline, _legacy, _subscripts = None, False, False


def _check_command(command: str, depth: int, _sub: bool) -> str | None:
    _tick()
    if depth > 3:
        return _raw(command)
    if _FORK_BOMB.search(command):
        return REASONS["fork_bomb"]
    if len(command) > MAX_PARSE:
        return _check_long(command, depth)
    try:
        scan = _Scan(command)
        text, bodies, heredocs = scan.result()
    except (_UnparsedError, RecursionError):
        try:
            reason = _check_tokens(command, depth)
        except _ShlexError:
            reason = None
        return reason or _raw(command)
    # Both views of the command: the full text (substitutions and heredoc lines
    # read as commands, as before) and the skeleton, which follows bash's own
    # nesting. A substitution's heredoc is data unless a shell reads it, so a
    # commit message in `$(cat <<'EOF' ... EOF)` is not read as commands.
    # The full text goes first, as on develop, so the skeleton's extra work
    # (downloads, decoders) runs only when that check did not already ask.
    if not (_sub and heredocs):
        try:
            if reason := _check_tokens(text, depth):
                return reason
        except _ShlexError:
            if reason := _raw(text):
                return reason
    for body in dict.fromkeys(bodies):
        if reason := check_command(body, depth + 1, _sub=True):
            return reason
    if (skeleton := scan.skeleton(text)) is None:
        return None
    try:
        return _check_tokens(skeleton, depth, heredocs)
    except _ShlexError:
        return _raw(skeleton)


def _check_long(command: str, depth: int) -> str | None:
    seen: set[str] = set()  # pieces already found safe
    for piece in _SPLIT.split(command):
        if piece in seen:
            continue
        _tick()
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
