"""Shell-command analysis for the ``c2_beacon`` signal.

A beacon is a command that keeps calling out on a timer: a ``while``/
``until``/``for`` loop whose condition or body runs both ``sleep`` and
``curl``/``wget``/``nc``, or a cron entry that runs ``curl``/``wget``. A
one-shot ``sleep 1; curl ...`` (a dev-server readiness probe) is not one,
and neither is a loop whose network calls all go to a loopback host.

``beacon_severity(command)`` returns ``(severity, reason)`` or ``None``:

- CRITICAL: a non-loopback beacon that also sends data (curl ``-d``/
  ``--data*``/``-T``/``-F``/``--json``/``-X POST``, wget ``--post-*``/
  ``--body-*``, data piped into nc, or ``$(...)``/backticks in an argument)
- CRITICAL (``download_to_shell``): a non-loopback beacon whose download
  is run as code (``curl ... | sh``, ``wget -O- | sudo bash``, ``| python3``,
  ``sh -c "$(curl ...)"``, ``eval "$(curl ...)"``, ``bash <(curl ...)``)
- HIGH: any other non-loopback beacon, or a command this module cannot
  parse that the old text rule would have flagged (fail safe)

The lexer is linear and bounded (nesting depth, cron segment length), so a
1 MB command is analysed well under a second. Hosts are read with
``urllib.parse`` and ``ipaddress``, never by substring.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import urlsplit

from ..base import Severity

_MAX_DEPTH = 8          # nested $(...), backticks and sh -c scripts
_CRON_SEGMENT = 2000    # chars read after each curl/wget in a cron entry
_CRON_CALLS = 64        # curl/wget occurrences read; more -> unknown target
_MAX_PARSE = 256 * 1024  # longer commands get the legacy text rule at HIGH

_NET = {"curl", "wget", "nc", "ncat", "netcat"}
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
_LOOP_OPEN = {"while", "until", "for", "select"}
_PREFIX_KEYWORDS = {
    "do", "then", "else", "elif", "if", "!", "{", "}", "time", "fi", "esac",
}
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")

# Cheap gates: the parser only runs when the text could hold a beacon.
_SLEEP_WORD = re.compile(r"\bsleep\b", re.IGNORECASE)
_NET_WORD = re.compile(r"\b(?:curl|wget|nc|ncat|netcat)\b", re.IGNORECASE)
_CRON_WORD = re.compile(r"\bcron", re.IGNORECASE)
_CRON_NET = re.compile(r"\b(?:curl|wget)\b", re.IGNORECASE)
_CRON_PATH = re.compile(r"/etc/cron|/var/spool/cron|\bcron\.d\b", re.IGNORECASE)

# The pre-fix rules, applied line by line in linear time. Used only for a
# command the lexer cannot read, and then at HIGH.
_LEGACY_SLEEP = re.compile(r"\bsleep\s+\d+\s*;", re.IGNORECASE)
_LEGACY_WHILE = re.compile(r"\bwhile\s+true\b", re.IGNORECASE)

_PLAIN = re.compile(r"[^\s'\"\\;&|()<>`$#]+")
_DQ_PLAIN = re.compile(r'[^"\\$`]+')
_OP = re.compile(r";;&?|;&|&&|\|\||\|&|[;&|()]")
_REDIR = re.compile(r"\d*(?:<<<|<<-|<<|<>|>>|>\||<&|>&|&>>|&>|<|>)")

# Stands in for a $(...) or backtick substitution in a word's value, so a
# host built from one reads as unknown.
_SUBST = "$()"

LOOPBACK_NAMES = {"localhost", "localhost."}


class UnparseableError(Exception):
    """The command is not shell the lexer can read."""


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
    writes: list[str] = field(default_factory=list)     # > and >> targets
    children: list[Cmd] = field(default_factory=list)
    resolved: tuple | None = None     # (keywords, argv, name), see _resolve
    pipe_next: Cmd | None = None      # the command this one pipes into
    via_subst: bool = False           # runs inside $(...), `...` or <(...)
    into_shell: bool = False          # its output is run as code (eval "$(..)")


def _resolve(c: Cmd) -> tuple[list[str], list[Word], str]:
    """Leading keywords, the argv without wrappers, and the command name."""
    if c.resolved is None:
        kws, argv = _strip_keywords(c.argv)
        argv = _effective(argv)
        c.resolved = (kws, argv, _basename(argv[0].value) if argv else "")
    return c.resolved


# --- lexer ------------------------------------------------------------------

def _lex(s: str, i: int = 0, depth: int = 0, close: str | None = None):
    """Tokens of ``s`` from ``i`` until ``close`` (``)`` or a backtick).

    Returns ``(tokens, end)``; a token is a ``Word``, an operator string, or
    ``("redir", op)``. Raises ``UnparseableError`` on unbalanced quotes or
    substitutions, or past ``_MAX_DEPTH``.
    """
    if depth > _MAX_DEPTH:
        raise UnparseableError("too deep")
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
            text = m.group(0)
            raw.append(text)
            val.append(text)
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
        if c == "#" and not in_word:
            j = s.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "#":
            raw.append(c)
            val.append(c)
            i += 1
            continue
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise UnparseableError("unclosed '")
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
            if s.startswith("$(", i):
                sub, j = _lex(s, i + 2, depth + 1, ")")
                raw.append(s[i:j])
                val.append(_SUBST)
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
            val.append(_SUBST)
            nested.append(sub)
            in_word = True
            i = j
            continue
        if c in "<>" and s.startswith("(", i + 1):
            # Process substitution <(...) / >(...): a nested script.
            sub, j = _lex(s, i + 2, depth + 1, ")")
            raw.append(s[i:j])
            val.append(_SUBST)
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
            parens += 1
        elif op == ")":
            if close == ")" and parens == 0:
                return tokens, i
            parens -= 1
        tokens.append(op)
    end_word()
    if close is not None:
        raise UnparseableError("unclosed substitution")
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
        if c == "$" and s.startswith("$(", i):
            sub, i = _lex(s, i + 2, depth + 1, ")")
            val.append(_SUBST)
            nested.append(sub)
            continue
        if c == "`":
            sub, i = _lex(s, i + 1, depth + 1, "`")
            val.append(_SUBST)
            nested.append(sub)
            continue
        val.append(c)
        i += 1
    raise UnparseableError('unclosed "')


def _skip_heredocs(s, i, heredocs) -> int:
    """Skip here-document bodies that start at ``i``; keep them as data."""
    for delim, strip in heredocs:
        while i < len(s):
            j = s.find("\n", i)
            line = s[i:] if j < 0 else s[i:j]
            i = len(s) if j < 0 else j + 1
            if (line.lstrip("\t") if strip else line) == delim:
                break
    return i


def _lex_script(s: str, depth: int = 0) -> list:
    """Lex ``s``, skipping here-document bodies.

    The body of ``cmd <<EOF`` starts on the next line, so the text is split
    at each heredoc: lex up to the end of the line holding ``<<``, skip the
    body, continue after it.
    """
    out: list = []
    pos = 0
    n = len(s)
    while pos < n:
        marker = s.find("<<", pos)
        if marker < 0:
            tokens, _ = _lex(s[pos:], 0, depth)
            out.extend(tokens)
            break
        line_end = s.find("\n", marker)
        if line_end < 0:
            tokens, _ = _lex(s[pos:], 0, depth)
            out.extend(tokens)
            break
        try:
            tokens, _ = _lex(s[pos:line_end], 0, depth)
        except UnparseableError:
            # The << was inside a quote spanning lines: lex the rest whole.
            tokens, _ = _lex(s[pos:], 0, depth)
            out.extend(tokens)
            break
        out.extend(tokens)
        out.append(";")
        delims = _heredoc_delims(tokens)
        pos = line_end + 1
        if delims:
            pos = _skip_heredocs(s, pos, delims)
    return out


def _heredoc_delims(tokens: list) -> list[tuple[str, bool]]:
    delims = []
    for k, t in enumerate(tokens):
        if isinstance(t, tuple) and t[1] in ("<<", "<<-") and k + 1 < len(tokens):
            w = tokens[k + 1]
            if isinstance(w, Word):
                delims.append((w.value, t[1] == "<<-"))
    return delims


# --- commands and loops -----------------------------------------------------

def _commands(tokens: list, depth: int) -> list[Cmd]:
    """Split tokens into simple commands; nested scripts become children."""
    cmds: list[Cmd] = []
    cur = Cmd([])
    piped = False
    k = 0
    while k < len(tokens):
        t = tokens[k]
        if isinstance(t, Word):
            cur.argv.append(t)
            for sub in t.nested:
                kids = _flat_script(sub, depth + 1)
                for kid in kids:
                    kid.via_subst = True
                cur.children.extend(kids)
        elif isinstance(t, tuple):
            if t[1] in ("<", "<<", "<<-", "<<<", "<>", "<&"):
                cur.stdin_redirect = True
            k += 1          # the redirect target is not an argument
            if k < len(tokens) and isinstance(tokens[k], Word):
                if ">" in t[1]:
                    cur.writes.append(tokens[k].value)
                for sub in tokens[k].nested:
                    cur.children.extend(_flat_script(sub, depth + 1))
            else:
                k -= 1
        else:
            _append(cmds, cur, piped)
            piped = t in ("|", "|&")
            cur = Cmd([])
        k += 1
    _append(cmds, cur, piped)
    for c in cmds:
        _expand_shell_c(c, depth)
        # eval "$(curl ...)", sh -c "$(curl ...)", bash <(curl ...): the
        # substitution's output is run as code.
        name = _name(c)
        if name in ("eval", "source", ".") or _is_interpreter(name):
            for ch in c.children:
                if ch.via_subst:
                    ch.into_shell = True
    return cmds


def _append(cmds: list[Cmd], cur: Cmd, piped: bool) -> None:
    if cur.argv or cur.children:
        cur.piped_in = piped
        if piped and cmds:
            cmds[-1].pipe_next = cur
        cmds.append(cur)


_INTERPRETERS = _SHELLS | {
    "fish", "python", "python2", "python3", "perl", "ruby", "node", "php",
    "pwsh", "powershell", "lua", "tclsh",
}
_PY_VERSION = re.compile(r"python\d+(?:\.\d+)*$")


def _is_interpreter(name: str) -> bool:
    return name in _INTERPRETERS or bool(_PY_VERSION.match(name))


def _runs_stdin(c: Cmd) -> bool:
    """Is ``c`` an interpreter running the program it reads on stdin?

    ``sh``, ``sudo bash -s``, ``python3 -`` do; ``python3 -m json.tool``,
    ``bash -c '...'`` and ``perl script.pl`` run something else.
    """
    _kws, argv, name = _resolve(c)
    if not _is_interpreter(name):
        return False
    for a in argv[1:]:
        v = a.value
        if v == "-" or v == "--":
            return True
        if not v.startswith("-"):
            return False        # a script file
        if v.startswith("--"):
            if v in ("--command", "--eval", "--print"):
                return False
            continue
        if name in _SHELLS or name == "fish":
            if "c" in v[1:]:
                return False
        elif v[1:2] in ("c", "m", "e", "E", "r", "p"):
            return False
    return True


def _feeds_shell(c: Cmd) -> bool:
    """Does ``c``'s output end up run as code?"""
    if c.into_shell:
        return True
    nxt, hops = c.pipe_next, 0
    while nxt is not None and hops < 16:     # curl | tee f | sh
        if _runs_stdin(nxt):
            return True
        nxt, hops = nxt.pipe_next, hops + 1
    return False


def _flat_script(tokens: list, depth: int) -> list[Cmd]:
    out: list[Cmd] = []
    for c in _commands(tokens, depth):
        out.extend(_flatten(c))
    return out


def _flatten(c: Cmd) -> list[Cmd]:
    out = [c]
    for ch in c.children:
        out.extend(_flatten(ch))
    return out


def _strip_keywords(argv: list[Word]) -> tuple[list[str], list[Word]]:
    """Leading shell keywords, then the command's own argv."""
    kws: list[str] = []
    j = 0
    while j < len(argv):
        v = argv[j].value
        if v in _LOOP_OPEN:
            kws.append(v)
            if v in ("for", "select"):
                return kws, []
            j += 1
            continue
        if v in _PREFIX_KEYWORDS or v == "done":
            kws.append(v)
            j += 1
            continue
        break
    return kws, argv[j:]


def _effective(argv: list[Word]) -> list[Word]:
    """Drop env assignments and wrapper commands (sudo, env, timeout...)."""
    j = 0
    while j < len(argv):
        v = argv[j].value
        if _ASSIGN.match(v):
            j += 1
            continue
        name = _basename(v)
        if name in ("nohup", "command", "exec", "builtin", "stdbuf", "time"):
            j += 1
            while j < len(argv) and argv[j].value.startswith("-"):
                j += 1
            continue
        if name in ("sudo", "doas", "env", "nice", "ionice", "timeout"):
            j += 1
            takes = {"sudo": "ugCDhpRT", "env": "uCS", "nice": "n", "ionice": "cnp",
                     "timeout": "sk"}.get(name, "")
            while j < len(argv):
                a = argv[j].value
                if a.startswith("-") and len(a) > 1:
                    j += 1
                    if len(a) == 2 and a[1] in takes:
                        j += 1
                    continue
                if name == "env" and _ASSIGN.match(a):
                    j += 1
                    continue
                break
            if name == "timeout" and j < len(argv):
                j += 1       # the duration
            continue
        break
    return argv[j:]


def _basename(v: str) -> str:
    name = v.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _expand_shell_c(c: Cmd, depth: int) -> None:
    """``bash -c 'script'``: parse the script as children of ``c``."""
    _kws, argv, name = _resolve(c)
    if name not in _SHELLS:
        return
    for k in range(1, len(argv)):
        a = argv[k].value
        if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
            if k + 1 < len(argv):
                if depth + 1 > _MAX_DEPTH:
                    raise UnparseableError("too deep")
                tokens = _lex_script(argv[k + 1].value, depth + 1)
                c.children.extend(_flat_script(tokens, depth + 1))
            return


def _name(c: Cmd) -> str:
    return _resolve(c)[2]


def _loops(cmds: list[Cmd]) -> list[list[Cmd]]:
    """Each outermost loop's commands (condition + body, nested scripts too).

    An inner loop's commands are a subset of its outer loop's, so the outer
    verdict covers it; keeping only outermost loops keeps this linear.
    """
    found: list[list[Cmd]] = []
    depth = 0
    start = 0
    for idx, c in enumerate(cmds):
        for kw in _resolve(c)[0]:
            if kw in _LOOP_OPEN:
                if depth == 0:
                    start = idx
                depth += 1
            elif kw == "done" and depth:
                depth -= 1
                if depth == 0:
                    found.append([x for cc in cmds[start:idx + 1] for x in _flatten(cc)])
    if depth:       # no `done`: the loop runs to the end of the text
        found.append([x for cc in cmds[start:] for x in _flatten(cc)])
    return found


def _nested_loops(c: Cmd) -> list[list[Cmd]]:
    """Loops inside a command's nested scripts (bash -c, $(...)).

    ``children`` lists every command of those scripts in text order, so
    their loop keywords stay in sequence.
    """
    return _loops(c.children) if c.children else []


# --- network targets --------------------------------------------------------

_CURL_SHORT_ARGS = set("bcdDeEFHKmorTuUwxXyYzACPQtz")
_CURL_LONG_ARGS = {
    "--url", "--output", "--header", "--data", "--data-ascii", "--data-binary",
    "--data-raw", "--data-urlencode", "--json", "--request", "--user",
    "--user-agent", "--referer", "--upload-file", "--form", "--form-string",
    "--write-out", "--max-time", "--connect-timeout", "--proxy", "--cookie",
    "--cookie-jar", "--config", "--cacert", "--capath", "--cert", "--key",
    "--range", "--continue-at", "--retry", "--retry-delay", "--retry-max-time",
    "--noproxy", "--proxy-user", "--dump-header", "--limit-rate", "--interface",
    "--resolve", "--connect-to", "--max-filesize", "--output-dir", "--trace",
    "--trace-ascii", "--stderr", "--speed-limit", "--speed-time", "--unix-socket",
    "--abstract-unix-socket", "--keepalive-time", "--ciphers", "--oauth2-bearer",
    "--variable", "--expect100-timeout", "--happy-eyeballs-timeout-ms",
}
_CURL_SEND_SHORT = set("dTF")
_CURL_SEND_LONG = re.compile(
    r"--(?:data(?:-[a-z]+)?|upload-file|form(?:-string)?|json)$")
_WGET_SHORT_ARGS = set("oaeOtTwiPUQlDBAIRXY")
_WGET_SEND_LONG = re.compile(r"--(?:post|body)-(?:data|file)$")
_NC_SHORT_ARGS = set("psweiqxXIOTVcmM")
_SEND_METHODS = {"POST", "PUT", "PATCH"}

_UNKNOWN = object()     # a target that cannot be read


@dataclass
class NetCall:
    targets: list           # str hosts or _UNKNOWN
    sends: bool
    to_shell: bool = False  # the download is run as code (curl | sh)


def _net_call(c: Cmd) -> NetCall | None:
    _kws, argv, tool = _resolve(c)
    if tool not in _NET:
        return None
    args = argv[1:]
    if any("$(" in a.raw or "`" in a.raw for a in args):
        sends = True
    else:
        sends = False
    targets: list = []
    if tool == "curl":
        t, s = _curl(args)
    elif tool == "wget":
        t, s = _wget(args)
    else:
        t, s = _nc(args, c)
        if t is None:      # a listener, not an outbound call
            return NetCall([], sends)
    targets.extend(t)
    return NetCall(targets or [_UNKNOWN], sends or s, _feeds_shell(c))


def _options(args: list[Word], short_args: set[str], long_args, on_opt):
    """Walk getopt-style args; return the positional words."""
    pos: list[Word] = []
    k = 0
    while k < len(args):
        a = args[k].value
        if a == "--":
            pos.extend(args[k + 1:])
            break
        if a.startswith("--"):
            name, eq, value = a.partition("=")
            takes = (name in long_args) if not callable(long_args) else long_args(name)
            if takes and not eq:
                k += 1
                value = args[k].value if k < len(args) else ""
            on_opt(name, value if (takes or eq) else None)
        elif a.startswith("-") and len(a) > 1:
            for p in range(1, len(a)):
                ch = a[p]
                if ch in short_args:
                    value = a[p + 1:]
                    if not value:
                        k += 1
                        value = args[k].value if k < len(args) else ""
                    on_opt("-" + ch, value)
                    break
                on_opt("-" + ch, None)
        else:
            pos.append(args[k])
        k += 1
    return pos


def _curl(args):
    targets: list = []
    sends = False

    def on_opt(name, value):
        nonlocal sends
        if name in ("-d", "-T", "-F") or _CURL_SEND_LONG.match(name):
            sends = True
        elif name in ("-X", "--request") and value and value.upper() in _SEND_METHODS:
            sends = True
        elif name in ("--url", "-x", "--proxy") and value is not None:
            targets.append(value)
        elif name in ("--resolve", "--connect-to", "--unix-socket",
                      "--abstract-unix-socket", "-K", "--config"):
            targets.append(_UNKNOWN)

    pos = _options(args, _CURL_SHORT_ARGS, _CURL_LONG_ARGS, on_opt)
    targets.extend(p.value for p in pos)
    return targets, sends


def _wget(args):
    targets: list = []
    sends = False

    def on_opt(name, value):
        nonlocal sends
        if _WGET_SEND_LONG.match(name):
            sends = True
        elif name == "--method" and value and value.upper() in _SEND_METHODS:
            sends = True
        elif name in ("-i", "--input-file", "-e", "--execute", "--config"):
            targets.append(_UNKNOWN)

    def long_takes(name):
        return name not in _WGET_FLAGS

    pos = _options(args, _WGET_SHORT_ARGS, long_takes, on_opt)
    targets.extend(p.value for p in pos)
    return targets, sends


# wget long options that take no value (anything else with no "=" is read
# as taking the next word, which can only hide a URL behind _UNKNOWN-free
# parsing; a missed URL leaves the call with no target -> counted).
_WGET_FLAGS = {
    "--quiet", "--verbose", "--no-verbose", "--continue", "--spider",
    "--no-check-certificate", "--server-response", "--timestamping",
    "--recursive", "--mirror", "--page-requisites", "--convert-links",
    "--no-parent", "--no-clobber", "--show-progress", "--no-cache",
    "--no-proxy", "--inet4-only", "--inet6-only", "--content-disposition",
    "--trust-server-names", "--ignore-case", "--debug", "--background",
    "--force-html", "--no-dns-cache", "--no-cookies", "--keep-session-cookies",
    "--auth-no-challenge", "--https-only", "--no-hsts", "--adjust-extension",
    "--backups", "--no-directories", "--force-directories", "--delete-after",
}


def _nc(args, c: Cmd):
    listen = False
    sends = c.piped_in or c.stdin_redirect

    def on_opt(name, value):
        nonlocal listen, sends
        if name in ("-l", "--listen"):
            listen = True
        elif name in ("-e", "-c", "--exec", "--sh-exec", "--lua-exec"):
            sends = True

    pos = _options(args, _NC_SHORT_ARGS, lambda n: n in (
        "--exec", "--sh-exec", "--lua-exec", "--source", "--wait", "--proxy"), on_opt)
    if listen:
        return None, sends
    return ([pos[0].value] if pos else []), sends


def _host(target: str) -> str | None:
    """The host a URL or host[:port] names, or None if it can't be read."""
    if not target:
        return None
    if "://" not in target:
        try:        # a bare IP, IPv6 included (nc ::1 4444)
            return str(ipaddress.ip_address(target.strip("[]")))
        except ValueError:
            pass
    try:
        host = urlsplit(target if "://" in target else "http://" + target).hostname
    except ValueError:
        return None
    if not host or any(ch in host for ch in "$`{}*?"):
        return None     # a variable, substitution or glob in the host
    return host


def is_loopback(host: str) -> bool:
    h = host.lower().strip("[]")
    if h in LOOPBACK_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        # curl and nc also accept short and numeric IPv4 forms (127.1,
        # 2130706433, 0x7f000001); inet_aton reads those, nothing else.
        if not re.fullmatch(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}", h):
            return False
        try:
            ip = ipaddress.IPv4Address(socket.inet_aton(h))
        except OSError:
            return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return ip.is_loopback or ip.is_unspecified


def _counts(target) -> bool:
    """True when a target is not provably loopback."""
    if target is _UNKNOWN:
        return True
    host = _host(target)
    return host is None or not is_loopback(host)


def _classify_calls(calls: list[NetCall], reason: str) -> tuple[Severity, str] | None:
    """Severity of a loop's (or cron entry's) calls; ``reason`` if plain."""
    outbound = [c for c in calls if any(_counts(t) for t in c.targets)]
    if not outbound:
        return None
    if any(c.to_shell for c in outbound):
        return Severity.CRITICAL, "download_to_shell"
    if any(c.sends for c in outbound):
        return Severity.CRITICAL, reason
    return Severity.HIGH, reason


# --- cron -------------------------------------------------------------------

def _cron_installs(cmds: list[Cmd]) -> bool:
    """Does the command install a cron entry (not just read one)?"""
    for c in cmds:
        for x in _flatten(c):
            _kws, argv, name = _resolve(x)
            if name == "crontab":
                # crontab -l lists and -r removes; anything else installs.
                if not {a.value for a in argv[1:]} & {"-l", "-r"}:
                    return True
            if any(_CRON_PATH.search(w) for w in x.writes):
                return True
            if name in ("tee", "cp", "mv", "install", "ln", "dd") and any(
                    _CRON_PATH.search(a.value) for a in argv[1:]):
                return True
    return False


def _cron_calls(text: str) -> list[NetCall]:
    """Each curl/wget mentioned in a cron entry, read up to its line's end."""
    calls = []
    for k, m in enumerate(_CRON_NET.finditer(text)):
        if k == _CRON_CALLS:
            calls.append(NetCall([_UNKNOWN], False))
            break
        seg = text[m.start():m.start() + _CRON_SEGMENT]
        seg = re.split(r"['\"\n]", seg, maxsplit=1)[0]
        try:
            cmds = _commands(_lex(seg)[0], 1)
        except UnparseableError:
            calls.append(NetCall([_UNKNOWN], False))
            continue
        call = _net_call(cmds[0]) if cmds else None
        calls.append(call or NetCall([_UNKNOWN], False))
    return calls


# --- entry point ------------------------------------------------------------

def _legacy(command: str) -> bool:
    """The pre-fix text rule, line by line, in linear time."""
    for line in command.splitlines():
        m = _LEGACY_SLEEP.search(line) or _LEGACY_WHILE.search(line)
        if m and _NET_WORD.search(line, m.end()):
            return True
        m = _CRON_WORD.search(line)
        if m and _CRON_NET.search(line, m.end()):
            return True
    return False


def _could_be_beacon(command: str) -> bool:
    if _NET_WORD.search(command) and _SLEEP_WORD.search(command):
        return True
    return bool(_CRON_WORD.search(command) and _CRON_NET.search(command))


def beacon_severity(command: str) -> tuple[Severity, str] | None:
    """``(severity, reason)`` if ``command`` looks like a C2 beacon."""
    if not command or not _could_be_beacon(command):
        return None
    return _analyse(command)


@lru_cache(maxsize=256)
def _analyse(command: str) -> tuple[Severity, str] | None:
    if len(command) > _MAX_PARSE:
        return (Severity.HIGH, "unparsed") if _legacy(command) else None
    try:
        tokens = _lex_script(command)
        cmds = _commands(tokens, 0)
        loops = _loops(cmds)
        for c in cmds:
            loops.extend(_nested_loops(c))
        worst: Severity | None = None
        reason = ""
        for loop in loops:
            if not any(_name(x) == "sleep" for x in loop):
                continue
            calls = [nc for x in loop if (nc := _net_call(x)) is not None]
            verdict = _classify_calls(calls, "loop")
            if verdict is not None and worst is not Severity.CRITICAL:
                worst, reason = verdict
        if worst is not Severity.CRITICAL and _CRON_WORD.search(command) \
                and _CRON_NET.search(command) and _cron_installs(cmds):
            verdict = _classify_calls(_cron_calls(command), "cron")
            if verdict is not None:
                worst, reason = verdict
    except (UnparseableError, RecursionError):
        return (Severity.HIGH, "unparsed") if _legacy(command) else None
    return (worst, reason) if worst is not None else None
