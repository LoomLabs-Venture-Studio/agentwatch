"""When a ``c2_beacon`` text match is safely not a beacon.

Detection is unchanged: ``C2CommunicationDetector`` flags any command that
matches one of its three text rules. This module only grants an
*exemption*, and only when it is fully confident. Any doubt means no
exemption, so the finding stands exactly as before (fail safe).

``beacon_exempt(command)`` is True only when all of these hold:

- the command is short enough (64 KB) and lexes completely: quotes,
  ``$(...)``, backticks and here-documents all balanced; no arithmetic
  outside single quotes (``((``, ``$((``, ``$[``, ``let``), process
  substitution, ``/dev/tcp``,
  function definitions, ``case``, ``coproc``, proxy variables, or cron
- every command name is a plain lowercase word (no ``$``, quotes,
  escapes, substitutions) and not a wrapper or code runner (eval, exec,
  sudo, su, ssh, docker, xargs, watch, setsid, torsocks, busybox, env,
  crontab, socat, PowerShell...); ``nohup CMD`` and ``timeout [opts] DUR
  CMD`` with literal words are unwrapped and CMD gets every check
- every curl/wget/nc word in the text is the name of a parsed command
  (none in strings, comments, here-documents or wrapper arguments)
- no shell or interpreter reads code from stdin (pipe, ``<``, here-doc,
  here-string) or from an inline flag (``-c``, ``-e``...)
- every curl/wget/nc call is fully understood: only known options, no
  proxy/resolve/config options, no ``$(...)``/backticks in its arguments,
  no env assignment in front, and each target a literal ``host[:port]``
  or ``http(s)://host[:port]/...``
- and EITHER there is no loop (a one-shot ``sleep 1; curl ...`` readiness
  probe) OR every network call targets loopback (``localhost``, 127/8,
  ``[::1]``, ``0.0.0.0``), read exactly, never by substring.

The lexer is linear; the size cap bounds the work.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache

_MAX_LEN = 64 * 1024
_MAX_DEPTH = 8          # nested $(...) and backticks

# Text that rules out an exemption before any parsing.
_REFUSE_TEXT = re.compile(
    r"[<>]\(|/dev/(?:tcp|udp)/|\bcron|\b(?:https?|ftp|all|no)_proxy\b",
    re.IGNORECASE,
)
# The network words the c2_beacon rules match (case-insensitive like them).
_NET_WORD = re.compile(r"\b(?:curl|wget|nc)\b", re.IGNORECASE)
_NET = {"curl", "wget", "nc"}

_LOOP_KEYWORDS = {"while", "until", "for", "select"}
_KEYWORDS = {"do", "done", "then", "else", "elif", "if", "fi", "!", "{", "}", "time"}
_REFUSE_NAMES = {
    # code runners and wrappers: what they run is not a parsed command
    "eval", "exec", "source", ".", "command", "builtin", "alias", "trap",
    "sudo", "doas", "su", "runuser", "sg", "pkexec", "env",
    "nice", "ionice", "stdbuf", "chroot", "unshare", "nsenter", "setsid",
    "flock", "xargs", "parallel", "watch", "torsocks", "torify", "proxychains",
    "proxychains4", "tsocks", "strace", "ltrace", "gdb", "busybox", "toybox",
    "script", "tmux", "screen", "byobu", "ssh", "autossh", "scp", "sftp", "mosh",
    "docker", "podman", "nerdctl", "kubectl", "oc", "lxc", "vagrant", "wsl",
    "find", "awk", "gawk", "mawk", "nawk", "sed", "vim", "vi", "nvim", "emacs",
    "socat", "telnet", "ncat", "netcat", "crontab", "at", "batch", "systemd-run",
    "launchctl", "schtasks", "cmd", "powershell", "pwsh", "goto", "foreach",
    "let", "case", "coproc", "function", "declare", "typeset", "local",
    "export", "readonly", "set", "shopt", "enable", "fc", "history", "hash",
    "compgen", "complete", "mapfile", "readarray", "wait", "disown", "jobs",
    "fg", "bg", "make", "just", "task",
}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "fish",
           "csh", "tcsh"}
_INTERPRETERS = {"python", "python2", "python3", "perl", "ruby", "node", "nodejs",
                 "deno", "bun", "php", "lua", "luajit", "tclsh", "osascript",
                 "rscript", "julia", "pypy", "pypy3"}
_PY_VERSION = re.compile(r"python\d+(?:\.\d+)*$")
# A program name is plain lowercase (no CURL, no Start-Sleep); the
# directories before it may hold capitals and start with ~/.
_PLAIN_NAME = re.compile(r"(?:~/|/)?(?:[A-Za-z0-9_.+-]+/)*[a-z0-9_.+][a-z0-9_.+-]*$")
_VERB_NOUN = re.compile(r"[a-z]+-[a-z]+$")   # PowerShell cmdlets (start-sleep)
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")

# Lexer.
_PLAIN = re.compile(r"[^\s'\"\\;&|()<>`$#]+")
_DQ_PLAIN = re.compile(r'[^"\\$`]+')
_OP = re.compile(r";;&?|;&|&&|\|\||\|&|[;&|()]")
_REDIR = re.compile(r"\d*(?:<<<|<<-|<<|<>|>>|>\||<&|>&|&>>|&>|<|>)")
_STDIN_REDIRS = {"<", "<<", "<<-", "<<<", "<>", "<&"}


class _RefuseError(Exception):
    """No exemption: something the checks do not fully understand."""


@dataclass
class Word:
    raw: str                      # source text, quotes included
    value: str                    # unquoted value
    nested: list[list] = field(default_factory=list)   # token lists of $(...)


@dataclass
class Cmd:
    argv: list[Word]
    piped_in: bool = False
    stdin_redirect: bool = False


# --- lexer ------------------------------------------------------------------

def _lex(s: str, i: int = 0, depth: int = 0, close: str | None = None):
    """Tokens of ``s`` from ``i`` until ``close`` (``)`` or a backtick).

    A token is a ``Word``, an operator string, or ``("redir", op)``.
    Raises ``_RefuseError`` on unbalanced quotes or substitutions, or too deep.
    """
    if depth > _MAX_DEPTH:
        raise _RefuseError("too deep")
    n = len(s)
    tokens: list = []
    raw: list[str] = []
    val: list[str] = []
    nested: list[list] = []
    in_word = False
    parens = 0

    def end_word():
        nonlocal in_word, raw, val, nested
        if in_word:
            tokens.append(Word("".join(raw), "".join(val), nested))
        in_word = False
        raw, val, nested = [], [], []

    while i < n:
        c = s[i]
        m = _PLAIN.match(s, i)
        if m:
            raw.append(m.group(0))
            val.append(m.group(0))
            in_word = True
            i = m.end()
            continue
        if c == "\n":
            end_word()
            tokens.append(";")
            i += 1
            continue
        if c in " \t\r\f\v":
            end_word()
            i += 1
            continue
        if c == "#":
            if not in_word:         # a comment, to the end of the line
                j = s.find("\n", i)
                i = n if j < 0 else j
                continue
            raw.append(c)
            val.append(c)
            i += 1
            continue
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise _RefuseError("unclosed '")
            raw.append(s[i:j + 1])
            val.append(s[i + 1:j])
            in_word = True
            i = j + 1
            continue
        if c == '"':
            i = _lex_dquote(s, i, depth, raw, val, nested)
            in_word = True
            continue
        if c == "\\":
            if i + 1 < n and s[i + 1] == "\n":
                i += 2
                continue
            raw.append(s[i:i + 2])
            val.append(s[i + 1:i + 2])
            in_word = True
            i += 2
            continue
        if c == "$":
            if s.startswith(("$((", "$["), i):
                raise _RefuseError("arithmetic")
            if s.startswith("$(", i):
                sub, j = _lex(s, i + 2, depth + 1, ")")
                raw.append(s[i:j])
                val.append("$()")
                nested.append(sub)
                in_word = True
                i = j
                continue
            raw.append(c)
            val.append(c)
            in_word = True
            i += 1
            continue
        if c == "`":
            if close == "`":
                end_word()
                return tokens, i + 1
            sub, j = _lex(s, i + 1, depth + 1, "`")
            raw.append(s[i:j])
            val.append("$()")
            nested.append(sub)
            in_word = True
            i = j
            continue
        if c in "<>" or (c == "&" and s.startswith(("&>", "&>>"), i)):
            # A redirection; digits right before it (2>) belong to it.
            if in_word and "".join(raw).isdigit():
                raw, val, nested, in_word = [], [], [], False
            end_word()
            r = _REDIR.match(s, i)
            op = r.group(0) if r else c
            tokens.append(("redir", op.lstrip("0123456789")))
            i += len(op)
            continue
        end_word()
        m = _OP.match(s, i)
        op = m.group(0)
        i = m.end()
        if op == "(":
            if s.startswith("(", i):
                raise _RefuseError("arithmetic")    # (( ... )), for ((;;))
            parens += 1
        elif op == ")":
            if close == ")" and parens == 0:
                return tokens, i
            parens -= 1
        tokens.append(op)
    end_word()
    if close is not None:
        raise _RefuseError("unclosed substitution")
    return tokens, n


def _lex_dquote(s, i, depth, raw, val, nested) -> int:
    n = len(s)
    start = i
    i += 1
    while i < n:
        m = _DQ_PLAIN.match(s, i)
        if m:
            val.append(m.group(0))
            i = m.end()
            continue
        c = s[i]
        if c == '"':
            raw.append(s[start:i + 1])
            return i + 1
        if c == "\\":
            val.append(s[i + 1:i + 2])
            i += 2
            continue
        if c == "$" and s.startswith(("$((", "$["), i):
            raise _RefuseError("arithmetic")     # expanded inside "..." too
        if c == "$" and s.startswith("$(", i):
            sub, i = _lex(s, i + 2, depth + 1, ")")
            val.append("$()")
            nested.append(sub)
            continue
        if c == "`":
            sub, i = _lex(s, i + 1, depth + 1, "`")
            val.append("$()")
            nested.append(sub)
            continue
        val.append(c)
        i += 1
    raise _RefuseError('unclosed "')


def _lex_script(s: str) -> list:
    """Lex ``s``, skipping here-document bodies (they are data).

    The text is lexed a line at a time around each ``<<``; any line that
    does not lex on its own (a quote spanning lines) refuses.
    """
    out: list = []
    pos = 0
    n = len(s)
    while pos < n:
        marker = s.find("<<", pos)
        line_end = s.find("\n", marker) if marker >= 0 else -1
        if line_end < 0:
            out.extend(_lex(s[pos:])[0])
            break
        tokens = _lex(s[pos:line_end])[0]
        out.extend(tokens)
        out.append(";")
        pos = line_end + 1
        for k, t in enumerate(tokens):
            if isinstance(t, tuple) and t[1] in ("<<", "<<-"):
                if k + 1 >= len(tokens) or not isinstance(tokens[k + 1], Word):
                    raise _RefuseError("heredoc without a delimiter")
                delim, strip = tokens[k + 1].value, t[1] == "<<-"
                while True:
                    if pos >= n:
                        raise _RefuseError("unterminated heredoc")
                    j = s.find("\n", pos)
                    line = s[pos:] if j < 0 else s[pos:j]
                    pos = n if j < 0 else j + 1
                    if (line.lstrip("\t") if strip else line) == delim:
                        break
    return out


# --- commands ---------------------------------------------------------------

def _commands(tokens: list, out: list[Cmd]) -> None:
    """Append every simple command in ``tokens`` (and its substitutions)."""
    cur = Cmd([])
    piped = False
    prev = None
    target = False
    for t in tokens:
        if isinstance(t, Word):
            if not target:      # a redirect target is not an argument
                cur.argv.append(t)
            target = False
            for sub in t.nested:
                _commands(sub, out)
        elif isinstance(t, tuple):
            if t[1] in _STDIN_REDIRS:
                cur.stdin_redirect = True
            target = True
        else:
            target = False
            if t == "(" and isinstance(prev, Word):
                raise _RefuseError("function definition or foreign syntax")
            if cur.argv:
                cur.piped_in = piped
                out.append(cur)
            piped = t in ("|", "|&")
            cur = Cmd([])
        prev = t
    if cur.argv:
        cur.piped_in = piped
        out.append(cur)


def _split(c: Cmd) -> tuple[list[str], list[Word], list[Word]]:
    """Leading keywords, leading assignments, and the command's argv.

    Assignments are kept apart only where a command follows them; a
    redirect target is part of argv but never its first word.
    """
    kws: list[str] = []
    argv = c.argv
    j = 0
    while j < len(argv) and argv[j].raw == argv[j].value and (
            argv[j].value in _KEYWORDS or argv[j].value in _LOOP_KEYWORDS):
        kws.append(argv[j].value)
        if argv[j].value in ("for", "select"):
            return kws, [], []      # the rest is the loop's word list
        j += 1
    k = j
    while k < len(argv) and _ASSIGN.match(argv[k].value):
        k += 1
    return kws, argv[j:k], argv[k:]


_DURATION = re.compile(r"\d+(?:\.\d+)?[smhd]?$")
_TIMEOUT_FLAGS = {"--preserve-status", "--foreground", "-v", "--verbose"}
_TIMEOUT_VALUES = {"-s", "--signal", "-k", "--kill-after"}


def _unwrap(argv: list[Word]) -> list[Word]:
    """The command run by ``nohup CMD`` / ``timeout [opts] DUR CMD``.

    Only plain literal words are read; anything else refuses. The inner
    command then gets every other check.
    """
    while argv and argv[0].raw == argv[0].value and argv[0].value in ("nohup", "timeout"):
        rest = argv[1:]
        if argv[0].value == "timeout":
            while rest and rest[0].value.startswith("-"):
                opt = rest[0]
                if opt.raw != opt.value:
                    raise _RefuseError("computed timeout option")
                name, eq, _value = opt.value.partition("=")
                if opt.value in _TIMEOUT_FLAGS:
                    rest = rest[1:]
                elif name in _TIMEOUT_VALUES and eq and name.startswith("--"):
                    rest = rest[1:]
                elif opt.value in _TIMEOUT_VALUES:
                    if len(rest) < 2 or rest[1].raw != rest[1].value or rest[1].nested:
                        raise _RefuseError("computed timeout option")
                    rest = rest[2:]
                else:
                    raise _RefuseError("unknown timeout option")
            if not rest or rest[0].raw != rest[0].value or rest[0].nested \
                    or not _DURATION.match(rest[0].value):
                raise _RefuseError("timeout duration not a literal")
            rest = rest[1:]
        elif rest and rest[0].value.startswith("-"):
            raise _RefuseError("nohup option")
        if not rest:
            raise _RefuseError("wrapper without a command")
        argv = rest
    return argv


def _basename(v: str) -> str:
    return v.rsplit("/", 1)[-1]


def _check_name(word: Word) -> str:
    """The command name if it is plain and allowed, else refuse."""
    v = word.value
    if word.raw != v or word.nested or not (v in ("[", "[[", ":") or _PLAIN_NAME.match(v)):
        raise _RefuseError("computed or unusual command name")
    name = _basename(v)
    if name in _REFUSE_NAMES or _VERB_NOUN.match(name) or name.endswith(".exe"):
        raise _RefuseError("wrapper or code runner")
    return name


def _check_interpreter(name: str, c: Cmd, args: list[Word]) -> None:
    shell = name in _SHELLS
    if not (shell or name in _INTERPRETERS or _PY_VERSION.match(name)):
        return
    if c.piped_in or c.stdin_redirect:
        raise _RefuseError("code fed to an interpreter on stdin")
    positional = False
    for a in args:
        v = a.value
        if v in ("-", "--"):
            raise _RefuseError("interpreter reads stdin")
        if not v.startswith("-"):
            positional = True
            break
        if shell or v.startswith("--") or any(ch in v[1:] for ch in "ceErpis"):
            raise _RefuseError("interpreter option")
    if not positional:
        raise _RefuseError("interpreter reads stdin")


# --- network calls ----------------------------------------------------------

_CURL_FLAGS = set("sSfLIivkgN46#OJlnqZGR") | {
    "--silent", "--show-error", "--fail", "--fail-with-body", "--location",
    "--head", "--include", "--verbose", "--insecure", "--globoff", "--no-buffer",
    "--ipv4", "--ipv6", "--progress-bar", "--remote-name", "--remote-header-name",
    "--list-only", "--netrc", "--disable", "--parallel", "--compressed",
    "--http1.0", "--http1.1", "--http2", "--http2-prior-knowledge", "--http3",
    "--no-keepalive", "--no-progress-meter", "--raw", "--tcp-nodelay",
    "--fail-early", "--no-sessionid", "--retry-connrefused", "--retry-all-errors",
    "--path-as-is", "--get", "--create-dirs", "--remote-time", "--styled-output",
    "--no-styled-output", "--location-trusted",
}
_CURL_VALUES = set("owmHXduAebcrCDYyTFEz") | {
    "--output", "--write-out", "--max-time", "--connect-timeout", "--header",
    "--request", "--data", "--data-raw", "--data-binary", "--data-ascii",
    "--data-urlencode", "--json", "--user", "--user-agent", "--referer",
    "--cookie", "--cookie-jar", "--range", "--continue-at", "--dump-header",
    "--retry", "--retry-delay", "--retry-max-time", "--max-filesize",
    "--limit-rate", "--speed-limit", "--speed-time", "--noproxy", "--upload-file",
    "--form", "--form-string", "--cacert", "--capath", "--cert", "--key",
    "--output-dir", "--trace", "--trace-ascii", "--stderr", "--oauth2-bearer",
    "--expect100-timeout", "--time-cond", "--max-redirs", "--keepalive-time",
    "--url",
}
_WGET_FLAGS = set("qvSc46N") | {
    "--quiet", "--verbose", "--no-verbose", "--server-response", "--spider",
    "--continue", "--timestamping", "--no-check-certificate", "--inet4-only",
    "--inet6-only", "--no-clobber", "--show-progress", "--no-cache",
    "--content-disposition", "--retry-connrefused", "--no-dns-cache",
    "--https-only", "--no-hsts", "--ignore-length", "--save-headers",
}
_WGET_VALUES = set("OoatTwUP") | {
    "--output-document", "--output-file", "--append-output", "--tries",
    "--timeout", "--dns-timeout", "--connect-timeout", "--read-timeout", "--wait",
    "--waitretry", "--header", "--user-agent", "--user", "--password",
    "--http-user", "--http-password", "--directory-prefix", "--post-data",
    "--post-file", "--body-data", "--body-file", "--method", "--referer",
    "--limit-rate", "--progress", "--max-redirect", "--load-cookies",
    "--save-cookies", "--ca-certificate", "--certificate", "--private-key",
}
_NC_FLAGS = set("zvnuND46dCt")
_NC_VALUES = set("wqisp")
_TABLES = {
    "curl": (_CURL_FLAGS, _CURL_VALUES),
    "wget": (_WGET_FLAGS, _WGET_VALUES),
    "nc": (_NC_FLAGS, _NC_VALUES),
}
_TARGET = re.compile(
    r"(?:(?P<scheme>[a-z][a-z0-9+.-]*)://)?"
    r"(?P<host>\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{1,5})?(?:[/?#].*)?",
    re.IGNORECASE | re.DOTALL,
)
_PORT = re.compile(r"\d{1,5}(?:-\d{1,5})?$")
_DOTTED = re.compile(r"(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$")


def _net_targets(tool: str, args: list[Word]) -> list[str]:
    """The hosts a fully understood curl/wget/nc call talks to, else refuse."""
    if any(a.nested or "`" in a.raw for a in args):
        raise _RefuseError("substitution in a network call")
    flags, values = _TABLES[tool]
    positional: list[str] = []
    k = 0
    while k < len(args):
        v = args[k].value
        if v.startswith("--") and len(v) > 2:
            name, eq, value = v.partition("=")
            if name in flags and not eq:
                pass
            elif name in values:
                if not eq:
                    k += 1
                    if k >= len(args):
                        raise _RefuseError("option without a value")
                    value = args[k].value
                if name == "--url":
                    positional.append(value)
            else:
                raise _RefuseError("unknown option")
        elif v.startswith("-") and len(v) > 1:
            for p in range(1, len(v)):
                ch = v[p]
                if ch in values:
                    if p + 1 == len(v):
                        k += 1
                        if k >= len(args):
                            raise _RefuseError("option without a value")
                    break
                if ch not in flags:
                    raise _RefuseError("unknown option")
        else:
            positional.append(v)
        k += 1
    if not positional:
        raise _RefuseError("no target")
    if tool == "nc":
        if not all(_PORT.match(p) for p in positional[1:]):
            raise _RefuseError("unexpected nc argument")
        positional = positional[:1]
    hosts = []
    for p in positional:
        m = _TARGET.fullmatch(p)
        if not m or (m.group("scheme") or "http").lower() not in ("http", "https"):
            raise _RefuseError("target not read exactly")
        hosts.append(m.group("host"))
    return hosts


def is_loopback(host: str) -> bool:
    """``localhost``, 127/8 or 0.0.0.0 in plain dotted form, or ``[::1]``."""
    h = host.lower()
    if h in ("localhost", "[::1]"):
        return True
    if not _DOTTED.match(h):
        return False
    ip = ipaddress.IPv4Address(h)
    return ip.is_loopback or ip.is_unspecified


# --- entry point ------------------------------------------------------------

def beacon_exempt(command: str) -> bool:
    """True only when ``command`` is surely not a beacon (see module doc)."""
    if not command or len(command) > _MAX_LEN or _REFUSE_TEXT.search(command):
        return False
    return _exempt(command)


@lru_cache(maxsize=256)
def _exempt(command: str) -> bool:
    try:
        cmds: list[Cmd] = []
        _commands(_lex_script(command), cmds)
        loop = False
        hosts: list[str] = []
        net_calls = 0
        for c in cmds:
            kws, assigns, argv = _split(c)
            argv = _unwrap(argv)
            if any(k in _LOOP_KEYWORDS for k in kws):
                loop = True
            if not argv:
                continue
            name = _check_name(argv[0])
            _check_interpreter(name, c, argv[1:])
            if argv[0].value in _NET:
                if assigns:
                    raise _RefuseError("environment set for a network call")
                net_calls += 1
                hosts.extend(_net_targets(argv[0].value, argv[1:]))
    except (_RefuseError, RecursionError):
        return False
    # Every curl/wget/nc in the text must be one of the parsed calls.
    if net_calls != len(_NET_WORD.findall(command)):
        return False
    return not loop or all(is_loopback(h) for h in hosts)
