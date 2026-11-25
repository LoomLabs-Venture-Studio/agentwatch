"""Strict safe shapes that LOWER a security finding's severity (Sprint 50).

The security detectors match broad regexes; on real sessions most of their
critical/high findings were ordinary dev work (``rm -rf /tmp/build``,
``chmod 644 README.md``, a heredoc that writes test data, AWS's documented
example key). This module recognises those cases so a detector can report
the same finding (same signal, same dedup key) at a LOWER severity.

Rules (Sprints 43-44 found 20-60 bypasses per round of anything looser):

- Nothing here ever drops a finding or raises a severity: callers take
  ``min(default, cap)``.
- A shape is an ALLOWLIST that the whole command segment (or the whole
  command) must fit. Anything outside it, or anything this module cannot
  read with certainty, keeps the detector's default severity.
- Shell text is read by ``tokenize``, a deliberately tiny grammar: bare
  words from a fixed character set, single-quoted strings, double-quoted
  strings with no ``$``, backtick, backslash or ``!``, the separators
  ``;``, ``&&``, ``||``, ``|``, ``&`` and newline, and plain redirections.
  Any other character (``$``, backtick, backslash, globs, ``#``, braces,
  parentheses, ``<<``, ...) ends what can be trusted. Inside that grammar
  the shell's own word splitting is known exactly, so a shape never has to
  "prove a command inert"; it only has to fit.
- Every regex here is linear (no nested quantifiers, no lookaround on
  unbounded input), and commands longer than ``MAX_LEN`` are never lowered.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from functools import cached_property

from ..base import Severity

# Commands (and texts) longer than MAX_LEN, or with a line longer than
# MAX_LINE, are never lowered. The analysis re-runs the detector's own rule
# regexes one rule at a time, and some of those (`python.*socket.*connect`)
# are quadratic in a line's length (`.` never crosses a newline): the cost
# is bounded by MAX_LINE * MAX_LEN per rule, once per distinct command.
MAX_LEN = 16_384
MAX_LINE = 2_048
# A rule that matches more often than this in one text keeps its severity.
MAX_MATCHES = 64
# Distinct texts whose severity a detector remembers.
MEMO_SIZE = 256


def analysable(text: str) -> bool:
    if len(text) > MAX_LEN:
        return False
    pos = 0
    while True:
        nl = text.find("\n", pos)
        if (len(text) if nl < 0 else nl) - pos > MAX_LINE:
            return False
        if nl < 0:
            return True
        pos = nl + 1


class Memo:
    """A bounded text -> result cache: a detector re-reads its whole window
    on every new action, so each command is judged once."""

    def __init__(self, size: int = MEMO_SIZE) -> None:
        self._size = size
        self._memo: OrderedDict = OrderedDict()

    def get(self, key, compute):
        if key in self._memo:
            self._memo.move_to_end(key)
            return self._memo[key]
        value = compute(key)
        self._memo[key] = value
        while len(self._memo) > self._size:
            self._memo.popitem(last=False)
        return value

_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


def rank(severity: Severity) -> int:
    return _RANK[severity]


def capped(default: Severity, cap: Severity | None) -> Severity:
    """*default* lowered to *cap*; never raised."""
    if cap is None or rank(cap) >= rank(default):
        return default
    return cap


def worst(severities: Iterable[Severity]) -> Severity | None:
    out = None
    for s in severities:
        if out is None or rank(s) > rank(out):
            out = s
    return out


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_WORD_CH = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./:@%+,=~-"
)
# Characters that may follow a word or a quoted string (anything else glued
# on, a quote in particular, is outside the grammar).
_BOUNDARY = frozenset(" \t\n;&|<>")
_DQ_FORBIDDEN = frozenset('$`\\!"')
_TMPDIR = "$TMPDIR/"
# Redirections: N>, N>>, N>&M, N<. `<<`, `<(`, `>(`, `>|`, `<&` are outside.
_REDIR_RE = re.compile(r"[0-9]?(?:>&[0-9]|>>|>|<)")
_OPS = ("&&", "||", ";", "|", "&")


@dataclass(frozen=True, slots=True)
class Tok:
    kind: str  # "word" | "quoted" | "op" | "redir"
    text: str  # word, quoted content, operator or redirection
    start: int  # span in the command, quotes included
    end: int


def tokenize(cmd: str) -> tuple[list[Tok], int | None]:
    """Tokens of *cmd* under the strict grammar (module docstring), and the
    index where the grammar was left (None: the whole command fits).

    Linear: one pass, every ``find`` starts after the previous token.
    """
    toks: list[Tok] = []
    n = len(cmd)
    i = 0
    need_target = False
    while i < n:
        c = cmd[i]
        if c in " \t":
            i += 1
            continue
        start = i
        if c == "\n" or c == ";" or c == "|" or (c == "&" and not cmd.startswith("&>", i)):
            if need_target:
                return toks, i
            if c == "\n":
                toks.append(Tok("op", "\n", i, i + 1))
                i += 1
                continue
            op = next(o for o in _OPS if cmd.startswith(o, i))
            nxt = cmd[i + len(op) : i + len(op) + 1]
            if (op == ";" and nxt == ";") or (op == "|" and nxt == "&"):
                return toks, i
            toks.append(Tok("op", op, i, i + len(op)))
            i += len(op)
            continue
        if c == "&" or c in "<>" or (c in "0123456789" and cmd[i + 1 : i + 2] in ("<", ">")):
            if need_target:
                return toks, i
            if cmd.startswith("&>", i):
                text = "&>>" if cmd.startswith("&>>", i) else "&>"
            else:
                m = _REDIR_RE.match(cmd, i)
                if m is None:
                    return toks, i
                text = m.group(0)
            j = i + len(text)
            if cmd[j : j + 1] in ("<", ">", "(", "|", "&"):
                return toks, i  # <<, <(, >(, >|, <&, >>>
            toks.append(Tok("redir", text, i, j))
            need_target = "&" not in text[1:] or text.startswith("&>")
            i = j
            continue
        if c == "'" or c == '"':
            j = cmd.find(c, i + 1)
            if j < 0:
                return toks, i
            content = cmd[i + 1 : j]
            if c == '"' and any(ch in _DQ_FORBIDDEN for ch in content):
                return toks, i
            j += 1
            if j < n and cmd[j] not in _BOUNDARY:
                return toks, i  # glued: 'a'b, "a"'b'
            toks.append(Tok("quoted", content, start, j))
            need_target = False
            i = j
            continue
        if c in _WORD_CH or cmd.startswith(_TMPDIR, i):
            j = i + len(_TMPDIR) if cmd.startswith(_TMPDIR, i) else i
            while j < n and cmd[j] in _WORD_CH:
                j += 1
            if j < n and cmd[j] not in _BOUNDARY:
                return toks, i  # a glued quote, $, *, #, ( ...
            toks.append(Tok("word", cmd[i:j], i, j))
            need_target = False
            i = j
            continue
        return toks, i
    if need_target:
        return toks, n
    return toks, None


@dataclass(slots=True)
class Segment:
    """One simple command: its words (argv) and redirections, in order."""

    tokens: list[Tok] = field(default_factory=list)
    trusted: bool = False  # every token known: ended by a tokenized separator
    end_op: str | None = None  # the separator after it (None: end of command)

    @property
    def start(self) -> int:
        return self.tokens[0].start

    @property
    def end(self) -> int:
        return self.tokens[-1].end

    @property
    def argv(self) -> list[Tok]:
        out = []
        skip = False
        for t in self.tokens:
            if skip:
                skip = False
                continue
            if t.kind == "redir":
                skip = not ("&" in t.text[1:] and not t.text.startswith("&>"))
                continue
            out.append(t)
        return out

    @property
    def redirects(self) -> list[tuple[Tok, Tok | None]]:
        out = []
        toks = self.tokens
        for k, t in enumerate(toks):
            if t.kind == "redir":
                has_target = not ("&" in t.text[1:] and not t.text.startswith("&>"))
                out.append((t, toks[k + 1] if has_target and k + 1 < len(toks) else None))
        return out


def segments(toks: list[Tok], fail_at: int | None) -> list[Segment]:
    """Split *toks* on separators. A segment is trusted when the grammar
    holds through its end: a later separator was read, or the whole command
    fits."""
    out: list[Segment] = []
    cur = Segment()
    for t in toks:
        if t.kind == "op":
            if cur.tokens:
                cur.trusted = True
                cur.end_op = t.text
                out.append(cur)
            cur = Segment()
            continue
        cur.tokens.append(t)
    if cur.tokens:
        cur.trusted = fail_at is None
        out.append(cur)
    return out


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_COMP_RE = re.compile(r"[A-Za-z0-9._+@%,=-]+")
_NAMED_COMP_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._+-]*")

# Recreatable cache directories (relative dot-dirs). An allowlist: a dot-dir
# in the home directory (.ssh, .aws, .gnupg, .config, .git ...) is not one.
CACHE_DIRS = frozenset({
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".pytype", ".pyre",
    ".hypothesis", ".tox", ".nox", ".coverage", ".nyc_output",
    ".ipynb_checkpoints", ".next", ".nuxt", ".turbo", ".parcel-cache",
    ".svelte-kit", ".angular", ".vite", ".eslintcache", ".dart_tool",
    ".expo", ".gradle", ".venv",
})
# Relative build-output directories (first path component).
BUILD_DIRS = frozenset({
    "build", "dist", "out", "target", "node_modules", "__pycache__",
    "coverage", "htmlcov", "_build",
})


def _components(path: str) -> list[str] | None:
    comps = path.split("/")
    if any(c in ("", ".", "..") or not _COMP_RE.fullmatch(c) for c in comps):
        return None
    return comps


def tmp_path(word: str, cmd: str) -> bool:
    """A fixed literal path under /tmp/ or $TMPDIR/, at least one component
    below it, no `.`/`..`, no glob, no trailing slash. $TMPDIR only when the
    command never names TMPDIR otherwise (no assignment to it)."""
    if word.startswith("/tmp/"):
        rest = word[5:]
    elif word.startswith(_TMPDIR):
        if cmd.count("TMPDIR") != cmd.count(_TMPDIR):
            return False
        rest = word[len(_TMPDIR):]
    else:
        return False
    return _components(rest) is not None


def _relative_named(path: str) -> list[str] | None:
    comps = path.split("/")
    if not comps or any(not c for c in comps):
        return None
    return comps


def cache_path(word: str) -> bool:
    """A relative path whose last component is a known cache dot-dir and
    whose other components are plain names (never `.`, `..` or a dot-dir)."""
    comps = _relative_named(word)
    if comps is None or comps[-1] not in CACHE_DIRS:
        return False
    return all(_NAMED_COMP_RE.fullmatch(c) for c in comps[:-1])


def build_path(word: str) -> bool:
    """A relative path inside a known build-output or cache directory."""
    comps = _relative_named(word)
    if comps is None or (comps[0] not in BUILD_DIRS and comps[0] not in CACHE_DIRS):
        return False
    return all(_NAMED_COMP_RE.fullmatch(c) for c in comps[1:])


# Files a heredoc or `echo >` may write as plain data. An allowlist of data,
# docs and source extensions; no shell scripts, no extension-less files
# (hooks, Makefile), no hidden file or directory anywhere in the path
# (.bashrc, .git/hooks, .github/workflows, .claude/settings.json).
DATA_EXTS = frozenset({
    "md", "markdown", "txt", "rst", "adoc", "log", "csv", "tsv", "json", "jsonl",
    "ndjson", "yaml", "yml", "toml", "ini", "cfg", "xml", "html", "htm", "css",
    "scss", "py", "pyi", "js", "mjs", "cjs", "ts", "tsx", "jsx", "vue", "svelte",
    "go", "rs", "java", "kt", "rb", "c", "h", "cc", "cpp", "hpp", "cs", "swift",
    "sql", "diff", "patch",
})


def data_path(path: str, cmd: str) -> bool:
    if path.startswith("~/"):
        rest = path[2:]
    elif path.startswith("/tmp/"):
        rest = path[5:]
    elif path.startswith(_TMPDIR):
        if cmd.count("TMPDIR") != cmd.count(_TMPDIR):
            return False
        rest = path[len(_TMPDIR):]
    elif path.startswith(("/home/", "/Users/")):
        rest = path[1:]
    elif path[:1] in ("/", "~", "-") or not path:
        return False
    else:
        rest = path
    comps = _components(rest)
    if comps is None or any(c.startswith(".") for c in comps):
        return False
    name = comps[-1]
    dot = name.rfind(".")
    return dot > 0 and name[dot + 1 :].lower() in DATA_EXTS


# ---------------------------------------------------------------------------
# The analysed command
# ---------------------------------------------------------------------------

# Bash reserved words: a segment starting with one is part of a compound
# command (a loop, a condition), never a simple command.
RESERVED = frozenset({
    "if", "then", "else", "elif", "fi", "case", "esac", "for", "select",
    "while", "until", "do", "done", "in", "function", "time", "coproc",
})

# Programs whose arguments are only ever data: they never run code taken
# from an argument. git and gh only with the listed subcommands; curl
# only with the flags _curl_flags_ok allows (no file written, no config).
DATA_PROGRAMS = frozenset({
    "echo", "printf", "cat", "ls", "head", "tail", "wc", "grep", "cd", "pwd",
    "mkdir", "touch", "true", "git", "gh", "curl", "tee",
})
_GIT_DATA = frozenset({"add", "commit", "status", "diff", "log", "show"})
_GH_DATA = frozenset({"pr", "issue"})
_GH_DATA_ACTIONS = frozenset({"create", "edit", "comment", "view", "list"})

# A heredoc that writes a file, quoted delimiter (no expansion in the body),
# as the command's first line. `<<-` and an unquoted delimiter are outside.
_P = r"([A-Za-z0-9_./@%+,=~-]+)"
_Q = r"(?:'([A-Za-z_][A-Za-z0-9_]*)'|\"([A-Za-z_][A-Za-z0-9_]*)\")"
_NONBLANK = re.compile(r"\S")
# No leading or trailing blank run in the pattern (a search over a long
# blank run would go quadratic): heredoc_spans strips the line first.
_HEREDOC_HEADER = re.compile(
    r"cat[ \t]+>>?[ \t]*" + _P + r"[ \t]+<<[ \t]*" + _Q
    + r"|cat[ \t]+<<[ \t]*" + _Q + r"[ \t]+>>?[ \t]*" + _P
    + r"|tee[ \t]+(?:-a[ \t]+)?" + _P + r"[ \t]+<<[ \t]*" + _Q
    + r"(?:[ \t]+>[ \t]*/dev/null)?"
)


class Command:
    """One command string, analysed lazily for the shapes below."""

    def __init__(self, cmd: str) -> None:
        self.cmd = cmd
        self.analysable = analysable(cmd)

    @cached_property
    def _tokens(self) -> tuple[list[Tok], int | None]:
        return tokenize(self.cmd)

    @cached_property
    def whole(self) -> bool:
        """The whole command fits the grammar."""
        return self._tokens[1] is None

    @cached_property
    def segments(self) -> list[Segment]:
        toks, fail = self._tokens
        return segments(toks, fail)

    def segment_at(self, pos: int) -> Segment | None:
        """The trusted segment whose span holds *pos*."""
        for seg in self.segments:
            if seg.start <= pos < seg.end:
                return seg if seg.trusted else None
        return None

    # -- data spans --------------------------------------------------------

    @cached_property
    def heredoc_spans(self) -> list[tuple[int, int]]:
        """Bodies of the file-writing heredocs the command consists of.

        The command must start with a header line (``cat > f.md <<'EOF'``,
        ``cat <<'EOF' >> f.md``, ``tee [-a] f.md <<'EOF'``), each body must
        end at a line that is exactly its delimiter, and after it comes only
        another such heredoc or the end of the command. Nothing is piped
        anywhere: the header is a whole line.
        """
        cmd = self.cmd
        if "\r" in cmd:
            return []
        spans: list[tuple[int, int]] = []
        pos = 0
        n = len(cmd)
        while True:
            eol = cmd.find("\n", pos)
            if eol < 0:
                return []
            lo, hi = pos, eol
            while lo < hi and cmd[lo] in " \t":
                lo += 1
            while hi > lo and cmd[hi - 1] in " \t":
                hi -= 1
            m = _HEREDOC_HEADER.fullmatch(cmd, lo, hi)
            if m is None:
                return []
            g = m.groups()  # P Q Q | Q Q P | P Q Q
            path = g[0] or g[5] or g[6]
            delim = g[1] or g[2] or g[3] or g[4] or g[7] or g[8]
            if not path or not delim or not data_path(path, cmd):
                return []
            body_start = eol + 1
            # The terminator: a line that is exactly the delimiter.
            k = body_start
            while True:
                if cmd.startswith(delim, k) and (
                    k + len(delim) == n or cmd[k + len(delim)] == "\n"
                ):
                    break
                nl = cmd.find("\n", k)
                if nl < 0:
                    return []  # never terminated: doubt
                k = nl + 1
            spans.append((body_start, k))
            pos = k + len(delim)
            # Only blanks to the end, or a newline and the next header.
            # (No slicing of the rest: that is quadratic over many heredocs.)
            nonblank = _NONBLANK.search(cmd, pos)
            if nonblank is None:
                return spans
            if not cmd.startswith("\n", pos):
                return []
            pos += 1

    @cached_property
    def literal_spans(self) -> list[tuple[int, int]]:
        """Argument tokens of a command made only of data programs
        (``DATA_PROGRAMS``): nothing in it runs code from an argument, so a
        match inside one argument is text, not a command. Redirect targets
        and tee files must be data files (``data_path``) or /dev/null."""
        if not self.whole:
            return []
        spans: list[tuple[int, int]] = []
        for seg in self.segments:
            argv = seg.argv
            if not argv or argv[0].kind != "word" or argv[0].text not in DATA_PROGRAMS:
                return []
            prog = argv[0].text
            words = [t.text for t in argv]
            if prog == "git" and (len(words) < 2 or words[1] not in _GIT_DATA):
                return []
            if prog == "gh" and (
                len(words) < 3 or words[1] not in _GH_DATA or words[2] not in _GH_DATA_ACTIONS
            ):
                return []
            if prog == "curl" and not _curl_flags_ok(argv):
                return []
            if prog == "tee" and not all(
                w == "-a" or data_path(w, self.cmd) for w in words[1:]
            ):
                return []
            for redir, target in seg.redirects:
                if redir.text.endswith("<") or target is None:
                    continue
                if target.text != "/dev/null" and not data_path(target.text, self.cmd):
                    return []
            spans.extend((t.start, t.end) for t in seg.tokens if t is not argv[0])
        return spans

    def is_data(self, start: int, end: int, heredoc_only: bool = False) -> bool:
        """[start, end) lies inside one heredoc body or (unless
        *heredoc_only*) inside one argument of a data-program command."""
        if any(s <= start and end <= e for s, e in self.heredoc_spans):
            return True
        if heredoc_only:
            return False
        return any(s <= start and end <= e for s, e in self.literal_spans)


# ---------------------------------------------------------------------------
# Per-rule evaluation
# ---------------------------------------------------------------------------

Judge = Callable[[Command, "re.Match[str]"], Severity | None]


@dataclass(frozen=True)
class Rule:
    """One detector sub-pattern and the judge that may lower one match of
    it (returns a cap, or None to keep the detector's severity)."""

    regex: re.Pattern
    judge: Judge | None = None


def evaluate(cmd: str, rules: list[Rule], default: Severity) -> Severity:
    """Severity of *cmd*, which the detector's combined regex matched: for
    every match of every rule, *default* lowered by the rule's judge; the
    worst of them. A text too long to analyse, a rule matching too often,
    or any match that is not lowered, keeps *default*."""
    if not analysable(cmd):
        return default
    command = Command(cmd)
    found: list[Severity] = []
    for rule in rules:
        for count, m in enumerate(rule.regex.finditer(cmd)):
            cap = rule.judge(command, m) if rule.judge and count < MAX_MATCHES else None
            severity = capped(default, cap)
            if severity is default:
                return default
            found.append(severity)
    return worst(found) or default


def data_judge(cap: Severity = Severity.LOW, heredoc_only: bool = False) -> Judge:
    def judge(command: Command, m: re.Match) -> Severity | None:
        return cap if command.is_data(m.start(), m.end(), heredoc_only) else None
    return judge


def first_of(*judges: Judge) -> Judge:
    """The lowest cap any of *judges* gives."""
    def judge(command: Command, m: re.Match) -> Severity | None:
        caps = [c for c in (j(command, m) for j in judges) if c is not None]
        return min(caps, key=rank) if caps else None
    return judge


# -- rm ----------------------------------------------------------------------

_RM_FLAG_RE = re.compile(r"-[rRfv]+")


def rm_segment_safe(command: Command, seg: Segment, allow_build: bool) -> bool:
    """`rm` with only -r/-R/-f/-v flags (and `--`) whose every operand is a
    /tmp or $TMPDIR path or a cache dot-dir (or, with *allow_build*, a
    relative build-output path); redirections only to /dev/null."""
    argv = seg.argv
    if not argv or argv[0].kind != "word" or argv[0].text != "rm":
        return False
    for redir, target in seg.redirects:
        if target is not None and target.text != "/dev/null":
            return False
    operands = 0
    end_of_flags = False
    for t in argv[1:]:
        if t.kind != "word":
            return False
        w = t.text
        if not end_of_flags and w == "--":
            end_of_flags = True
            continue
        if not end_of_flags and w.startswith("-"):
            if not _RM_FLAG_RE.fullmatch(w):
                return False
            continue
        if not (
            tmp_path(w, command.cmd) or cache_path(w) or (allow_build and build_path(w))
        ):
            return False
        operands += 1
    return operands > 0


def rm_judge(command: Command, m: re.Match) -> Severity | None:
    """`rm -rf` of temp paths or cache dot-dirs: medium."""
    seg = command.segment_at(m.start())
    if seg is None or not seg.argv or seg.argv[0].start != m.start() or m.end() > seg.end:
        return None
    return Severity.MEDIUM if rm_segment_safe(command, seg, allow_build=False) else None


# -- chmod -------------------------------------------------------------------

_CHMOD_FLAG_RE = re.compile(r"-[Rvcf]+")
_MODE3_RE = re.compile(r"[0-7]{3}")


def _chmod_target(word: str, cmd: str) -> bool:
    if word == "~":
        return True
    if word.startswith("~/"):
        return _components(word[2:]) is not None
    if word.startswith(("/tmp/", _TMPDIR)):
        return tmp_path(word, cmd)
    if word.startswith(("/home/", "/Users/")):
        return _components(word[1:]) is not None
    if word[:1] in ("/", "~", "-"):
        return False
    return _components(word) is not None


def chmod_judge(command: Command, m: re.Match) -> Severity | None:
    """`chmod NNN target...`: exactly three octal digits (no setuid, setgid
    or sticky bit) on user paths (relative, ~, /tmp, /home, /Users): low."""
    seg = command.segment_at(m.start())
    if seg is None:
        return None
    argv = seg.argv
    if len(argv) < 3 or argv[0].start != m.start() or argv[0].text != "chmod":
        return None
    mode = argv[1]
    if mode.kind != "word" or not _MODE3_RE.fullmatch(mode.text) or m.end() != mode.end:
        return None
    if seg.redirects:
        return None
    targets = 0
    for t in argv[2:]:
        if t.kind != "word":
            return None
        if t.text.startswith("-"):
            if not _CHMOD_FLAG_RE.fullmatch(t.text):
                return None
            continue
        if not _chmod_target(t.text, command.cmd):
            return None
        targets += 1
    return Severity.LOW if targets else None


# -- python socket ----------------------------------------------------------

_SOCKET_WORD = re.compile(r"\bsocket\b", re.IGNORECASE)
_CONNECT_WORD = re.compile(r"\b(?:connect|connect_ex|create_connection)\b", re.IGNORECASE)


def socket_judge(command: Command, m: re.Match) -> Severity | None:
    """`python.*socket.*connect` where no shell segment holds both the
    whole word `socket` and a connect call: medium. Needs the whole command
    to fit the grammar, so a quoted program stays one segment."""
    if not command.whole:
        return None
    for seg in command.segments:
        text = command.cmd[seg.start : seg.end]
        if _SOCKET_WORD.search(text) and _CONNECT_WORD.search(text):
            return None
    return Severity.MEDIUM


# -- sleep N; curl loopback -------------------------------------------------

_LOOPBACK_URL = re.compile(
    r"(?:https?://)?(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]{1,5})?(?:/\S*)?"
)
_CURL_BOOL = re.compile(r"-[sSfLiIvk]+")
_CURL_LONG_BOOL = frozenset({
    "--silent", "--show-error", "--fail", "--location", "--head", "--include", "--verbose",
})
_CURL_WITH_VALUE = frozenset({
    "-w", "--write-out", "-H", "--header", "-X", "--request", "-m", "--max-time",
    "--connect-timeout", "--retry", "-o", "--output",
})
_METHOD_RE = re.compile(r"[A-Z]{1,10}")
_WGET_BOOL = frozenset({"-q", "--quiet", "--spider", "-qO-", "-O-"})
_WGET_WITH_VALUE = frozenset({"-O", "-T", "-t"})
_WGET_ASSIGN = re.compile(r"--(?:timeout|tries)=[0-9]+")


def _curl_flags_ok(argv: list[Tok]) -> bool:
    """curl's flags all come from a small allowlist: no file written (-o only
    to /dev/null), no config, proxy, resolve or upload option. Non-flag
    arguments are not judged here."""
    k = 1
    while k < len(argv):
        t = argv[k]
        w = t.text
        if t.kind != "word" or not w.startswith("-"):
            k += 1
            continue
        if _CURL_BOOL.fullmatch(w) or w in _CURL_LONG_BOOL:
            k += 1
            continue
        if w not in _CURL_WITH_VALUE or k + 1 >= len(argv):
            return False
        value = argv[k + 1].text
        if w in ("-o", "--output") and value != "/dev/null":
            return False
        if w in ("-X", "--request") and not _METHOD_RE.fullmatch(value):
            return False
        if w in ("-m", "--max-time", "--connect-timeout", "--retry") and not value.isdigit():
            return False
        k += 2
    return True


def _loopback_fetch(seg: Segment) -> bool:
    argv = seg.argv
    if not argv or argv[0].kind != "word" or argv[0].text not in ("curl", "wget"):
        return False
    if seg.redirects:
        return False
    curl = argv[0].text == "curl"
    if curl and not _curl_flags_ok(argv):
        return False
    # No redirect following: a loopback URL could send curl anywhere.
    if any(t.text == "--location" or (_CURL_BOOL.fullmatch(t.text) and "L" in t.text)
           for t in argv[1:] if t.kind == "word"):
        return False
    urls = 0
    k = 1
    while k < len(argv):
        t = argv[k]
        w = t.text
        if t.kind == "word" and w.startswith("-"):
            if curl and (_CURL_BOOL.fullmatch(w) or w in _CURL_LONG_BOOL):
                k += 1
                continue
            if not curl and (w in _WGET_BOOL or _WGET_ASSIGN.fullmatch(w)):
                k += 1
                continue
            values = _CURL_WITH_VALUE if curl else _WGET_WITH_VALUE
            if w not in values or k + 1 >= len(argv):
                return False
            value = argv[k + 1].text
            if w in ("-o", "--output") and value != "/dev/null":
                return False
            if w == "-O" and value not in ("-", "/dev/null"):
                return False
            if w in ("-X", "--request") and not _METHOD_RE.fullmatch(value):
                return False
            if w in ("-m", "--max-time", "--connect-timeout", "--retry", "-T", "-t") and (
                not value.isdigit()
            ):
                return False
            k += 2
            continue
        if not _LOOPBACK_URL.fullmatch(w):
            return False
        urls += 1
        k += 1
    return urls > 0


def sleep_fetch_judge(command: Command, m: re.Match) -> Severity | None:
    """`sleep N; curl|wget <loopback URLs>` as two whole simple commands,
    in a command that fits the grammar and holds no compound command (no
    loop): medium. The fetch must not feed a pipe or the background."""
    if not command.whole:
        return None
    segs = command.segments
    if any(s.argv and s.argv[0].kind == "word" and s.argv[0].text in RESERVED for s in segs):
        return None
    for k, seg in enumerate(segs[:-1]):
        argv = seg.argv
        if not argv or argv[0].start != m.start():
            continue
        if (
            len(argv) != 2 or argv[0].text != "sleep" or not argv[1].text.isdigit()
            or argv[1].kind != "word" or seg.redirects or seg.end_op != ";"
        ):
            return None
        fetch = segs[k + 1]
        if m.end() > fetch.end or fetch.end_op in ("|", "&"):
            return None
        return Severity.MEDIUM if _loopback_fetch(fetch) else None
    return None


# -- dig ---------------------------------------------------------------------

_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,18}[a-z0-9])?")


def _plain_hostname(word: str) -> bool:
    labels = word[:-1].split(".") if word.endswith(".") else word.split(".")
    return 2 <= len(labels) <= 5 and all(_LABEL_RE.fullmatch(x) for x in labels)


def dig_judge(command: Command, m: re.Match) -> Severity | None:
    """`dig [+short] host.name [+short]`: one plain lower-case hostname
    (2-5 labels of at most 20 chars, so no room for encoded data): low."""
    seg = command.segment_at(m.start())
    # Its answer must not feed a pipe (`| sh`) or anything else.
    if seg is None or seg.redirects or seg.end_op in ("|", "&"):
        return None
    argv = seg.argv
    if not argv or argv[0].start != m.start() or argv[0].text != "dig" or m.end() > seg.end:
        return None
    hosts = 0
    for t in argv[1:]:
        if t.kind != "word":
            return None
        if t.text == "+short":
            continue
        if not _plain_hostname(t.text):
            return None
        hosts += 1
    return Severity.LOW if hosts == 1 else None


# -- skill install split over segments ---------------------------------------


def split_segments_judge(command: Command, m: re.Match) -> Severity | None:
    """The rule's words are in different simple commands (``ls skills &&
    pip install``): the whole command fits the grammar and the rule matches
    inside none of its segments. Low."""
    if not command.whole:
        return None
    for seg in command.segments:
        if m.re.search(command.cmd, seg.start, seg.end):
            return None
    return Severity.LOW


# -- mass delete -------------------------------------------------------------


def safe_delete(cmd: str) -> bool:
    """Every deletion `MassFileOperationDetector` counts in *cmd* is a
    shaped `rm` (temp path, cache dot-dir or build path) or data."""
    command = Command(cmd)
    if not command.analysable or "unlink" in cmd or "shred" in cmd:
        return False
    found = 0
    pos = cmd.find("rm ")
    while pos >= 0:
        found += 1
        if found > MAX_MATCHES:
            return False
        if not command.is_data(pos, pos + 3):
            seg = command.segment_at(pos)
            if seg is None or not seg.argv or seg.argv[0].start != pos:
                return False
            if not rm_segment_safe(command, seg, allow_build=True):
                return False
        pos = cmd.find("rm ", pos + 1)
    return found > 0


# ---------------------------------------------------------------------------
# Secrets: documented examples, obvious dummies, key headers with no key
# ---------------------------------------------------------------------------

# Exact documented example credentials, never real keys. Exact strings only:
# a value that merely contains EXAMPLE keeps its severity.
EXAMPLE_SECRETS = frozenset({
    # AWS docs, "Managing access keys for IAM users" and the AWS CLI
    # "Configuration and credential file settings" page:
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
    # https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    # The second example profile on the same AWS CLI page.
    "AKIAI44QH8DHBEXAMPLE",
    "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
    # jwt.io's default debugger token (HS256, secret "your-256-bit-secret";
    # the signature checks out against it), https://jwt.io/
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpv"
    "aG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
})

# Vendor prefixes a dummy keeps (ghp_xxxx, sk-ant-0000...); longest first.
_VENDOR_PREFIX = re.compile(
    r"(?:sk-ant-api03-|sk-or-v1-|sk-ant-|sk-proj-|sk_live_|sk_test_|pk_live_|pk_test_"
    r"|github_pat_|ghp_|gho_|ghs_|glpat-|xox[bpors]-|AKIA|AIza|SG\.|hf_|r8_|pc-|fc-"
    r"|npm_|pypi-|lin_api_|nfp_|sbp_|railway_|vercel_|neondb_|dp\.st\.|key-|sk-)",
    re.IGNORECASE,
)
_MIN_DUMMY = 8
# A counting sequence must be longer than any AWS key body (16 chars after
# AKIA): tests use AKIAABCDEFGHIJKLMNOP as a "real" leak, and an existing
# finding never loses severity. One repeated character needs only 8.
_MIN_SEQUENCE = 20


def _runs(s: str) -> bool:
    """*s* is made only of runs of at least 4 chars that repeat one char
    (xxxx, 0000) or count up by one (abcd, 1234)."""
    i = 0
    n = len(s)
    while i < n:
        j = i + 1
        step = None
        while j < n:
            d = ord(s[j]) - ord(s[j - 1])
            if step is None and d in (0, 1):
                step = d
            if d != step:
                break
            j += 1
        if j - i < 4:
            return False
        i = j
    return True


def dummy_secret(value: str) -> bool:
    """A documented example credential (exact), or a value that, vendor
    prefix and -/_ aside, is one repeated character or an obvious sequence
    (xxxx, 0000, abcdef..., 123456...). A random key never is."""
    if value in EXAMPLE_SECRETS:
        return True
    m = _VENDOR_PREFIX.match(value)
    core = value[m.end():] if m else value
    core = core.replace("-", "").replace("_", "").lower()
    if len(core) < _MIN_DUMMY or not core.isascii() or not core.isalnum():
        return False
    if len(set(core)) == 1:
        return True
    return len(core) >= _MIN_SEQUENCE and _runs(core)


# A key body: one base64 run of 16+ chars soon after the BEGIN line (a key
# line is 64; an encrypted PEM's DEK-Info IV is 32 hex chars).
_KEY_BODY_RUN = re.compile(r"[A-Za-z0-9+/=]{16}")
_KEY_BODY_WINDOW = 4096


def key_header_without_body(text: str, header_end: int) -> bool:
    """A PEM/PGP BEGIN line with no key body after it: prose, a regex, a
    test that builds the key from variables."""
    return _KEY_BODY_RUN.search(text, header_end, header_end + _KEY_BODY_WINDOW) is None
