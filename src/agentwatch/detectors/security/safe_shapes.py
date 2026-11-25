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
- A command shape lowers only when EVERY segment of the whole command
  (all ``;``, ``&&``, ``||``, ``|``, ``&`` and newline parts) is itself a
  trusted shape (``Command.all_trusted``): a safe-looking first segment
  never vouches for a decoy after it.
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
        if c in _WORD_CH:
            j = i
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
# in the home directory (.ssh, .aws, .gnupg, .config, .git ...) is not one,
# nor one that can hold credentials (.gradle: gradle.properties; .expo:
# state.json; .m2, .npm, .cargo, .docker, .kube were never listed).
CACHE_DIRS = frozenset({
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".pytype", ".pyre",
    ".hypothesis", ".tox", ".nox", ".coverage", ".nyc_output",
    ".ipynb_checkpoints", ".next", ".nuxt", ".turbo", ".parcel-cache",
    ".svelte-kit", ".angular", ".vite", ".eslintcache", ".dart_tool", ".venv",
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


def tmp_path(word: str) -> bool:
    """A fixed literal path under /tmp/, at least one component below it, no
    `.`/`..`, no glob, no trailing slash. Never $TMPDIR: it is unset on most
    Linux systems, so `$TMPDIR/home/u` is `/home/u`."""
    return word.startswith("/tmp/") and _components(word[5:]) is not None


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


# Files a heredoc or `echo >` may write as plain data: data and docs
# extensions only. Never code (.py: conftest.py, setup.py, sitecustomize.py;
# .js, .sh ...), never config that runs code (package.json, composer.json,
# tox.ini, Makefile, *.pth), never under node_modules, and no hidden file or
# directory anywhere in the path (.bashrc, .git/hooks, .github/workflows).
DATA_EXTS = frozenset({
    "md", "markdown", "txt", "rst", "log", "csv", "tsv", "json", "jsonl", "yaml", "yml",
})
_CODE_JSON = frozenset({"package.json", "composer.json"})


def _user_path_rest(path: str) -> str | None:
    """The part of a user path after its root (relative, ~/, /tmp/, /home/,
    /Users/), or None for any other path."""
    if path.startswith("~/"):
        return path[2:]
    if path.startswith("/tmp/"):
        return path[5:]
    if path.startswith(("/home/", "/Users/")):
        return path[1:]
    if not path or path[:1] in ("/", "~", "-"):
        return None
    return path


def data_path(path: str) -> bool:
    rest = _user_path_rest(path)
    comps = None if rest is None else _components(rest)
    if comps is None or any(c.startswith(".") or c == "node_modules" for c in comps):
        return False
    name = comps[-1]
    dot = name.rfind(".")
    return (
        dot > 0 and name[dot + 1 :].lower() in DATA_EXTS and name.lower() not in _CODE_JSON
    )


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
# from an argument and never write a file an argument names (beyond what
# _data_segment checks). git, gh, echo and printf: subcommands and flags
# allowlisted exactly. No `cd` (it moves every relative path after it) and
# no network program: the only trusted curl/wget is a loopback fetch.
DATA_PROGRAMS = frozenset({
    "echo", "printf", "cat", "ls", "head", "tail", "wc", "grep", "pwd",
    "mkdir", "touch", "true", "git", "gh", "tee",
})
_ECHO_FLAGS = frozenset({"-n", "-e", "-E"})
_GIT_STATUS_FLAGS = frozenset({"-s", "--short", "-b", "--branch", "-sb"})
_GIT_ADD_FLAGS = frozenset({"-A", "--all", "-u", "--update"})
_GIT_COMMIT_FLAGS = frozenset({"-a", "--all", "--allow-empty", "-q", "--quiet"})
_GIT_COMMIT_MESSAGE = frozenset({"-m", "--message"})
_GH_DATA = frozenset({"pr", "issue"})
_GH_DATA_ACTIONS = frozenset({"create", "edit", "comment"})
_GH_VALUE_FLAGS = frozenset({"--title", "-t", "--body", "-b", "--base", "-B"})
_GH_BOOL_FLAGS = frozenset({"--draft", "-d"})
_DIGITS = re.compile(r"[0-9]{1,9}")

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
            if not path or not delim or not data_path(path):
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
        """Argument tokens of a command made only of data-program segments
        (``_data_segment``): nothing in it runs code from an argument, so a
        match inside one argument is text, not a command."""
        if not self.whole or not self.segments:
            return []
        spans: list[tuple[int, int]] = []
        for seg in self.segments:
            if not _data_segment(seg):
                return []
            argv0 = seg.argv[0]
            spans.extend((t.start, t.end) for t in seg.tokens if t is not argv0)
        return spans

    @cached_property
    def all_trusted(self) -> bool:
        """The whole command fits the grammar and every segment is one of
        the trusted shapes (``trusted_segment``). Every command shape needs
        this: a safe-looking segment never vouches for the next one."""
        return self.whole and bool(self.segments) and all(
            trusted_segment(seg) for seg in self.segments
        )

    def is_data(self, start: int, end: int, heredoc_only: bool = False) -> bool:
        """[start, end) lies inside one heredoc body or (unless
        *heredoc_only*) inside one argument of a data-program command."""
        if any(s <= start and end <= e for s, e in self.heredoc_spans):
            return True
        if heredoc_only:
            return False
        return any(s <= start and end <= e for s, e in self.literal_spans)


# ---------------------------------------------------------------------------
# Trusted segments
# ---------------------------------------------------------------------------


def _git_data(words: list[str], argv: list[Tok]) -> bool:
    """git status / add / commit with exactly allowlisted flags (no
    --output, -c, -C, --exec-path, alias, -F file ...)."""
    if len(words) < 2:
        return False
    sub, rest = words[1], argv[2:]
    if sub == "status":
        return all(t.kind == "word" and t.text in _GIT_STATUS_FLAGS for t in rest)
    if sub == "add":
        return all(
            t.kind == "word" and (t.text in _GIT_ADD_FLAGS or (
                not t.text.startswith("-") and _user_path_rest(t.text) is not None))
            for t in rest
        )
    if sub == "commit":
        k, messages = 0, 0
        while k < len(rest):
            t = rest[k]
            if t.kind == "word" and t.text in _GIT_COMMIT_MESSAGE and k + 1 < len(rest):
                messages += 1
                k += 2
                continue
            if t.kind != "word" or t.text not in _GIT_COMMIT_FLAGS:
                return False
            k += 1
        return messages > 0
    return False


def _gh_data(words: list[str], argv: list[Tok]) -> bool:
    """gh pr|issue create|edit|comment with --title/--body/--base values,
    --draft, and issue/PR numbers (no --body-file, no --web, no repo)."""
    if len(words) < 3 or words[1] not in _GH_DATA or words[2] not in _GH_DATA_ACTIONS:
        return False
    rest = argv[3:]
    k = 0
    while k < len(rest):
        t = rest[k]
        if t.kind == "word" and t.text in _GH_VALUE_FLAGS and k + 1 < len(rest):
            k += 2
            continue
        if t.kind != "word" or not (t.text in _GH_BOOL_FLAGS or _DIGITS.fullmatch(t.text)):
            return False
        k += 1
    return True


def _data_segment(seg: Segment) -> bool:
    """One simple command of a data program, with its exact constraints.
    Redirections only into data files or /dev/null (or from any file)."""
    argv = seg.argv
    if not argv or argv[0].kind != "word" or argv[0].text not in DATA_PROGRAMS:
        return False
    prog = argv[0].text
    words = [t.text for t in argv]
    if prog == "git" and not _git_data(words, argv):
        return False
    if prog == "gh" and not _gh_data(words, argv):
        return False
    if prog == "echo" and any(
        t.kind == "word" and t.text.startswith("-") and t.text not in _ECHO_FLAGS
        for t in argv[1:]
    ):
        return False
    if prog == "printf" and len(argv) > 1 and argv[1].text.startswith("-"):
        return False  # printf -v NAME assigns a shell variable
    if prog == "tee" and not all(w == "-a" or data_path(w) for w in words[1:]):
        return False
    for redir, target in seg.redirects:
        if redir.text.endswith("<") or target is None:
            continue
        if target.text != "/dev/null" and not data_path(target.text):
            return False
    return True


def trusted_segment(seg: Segment) -> bool:
    """A simple command of one of the trusted shapes: a data-program
    command, a shaped rm or chmod, `sleep N`, a loopback fetch, a plain
    dig, a pytest run of test paths."""
    return (
        _data_segment(seg)
        or rm_segment_safe(seg, allow_build=True)
        or chmod_segment_safe(seg)
        or _sleep_segment(seg)
        or loopback_fetch(seg)
        or dig_segment_safe(seg)
        or pytest_segment(seg)
    )


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


def rm_segment_safe(seg: Segment, allow_build: bool) -> bool:
    """`rm` with only -r/-R/-f/-v flags (and `--`) whose every operand is a
    literal /tmp path or a cache dot-dir (or, with *allow_build*, a
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
        if not (tmp_path(w) or cache_path(w) or (allow_build and build_path(w))):
            return False
        operands += 1
    return operands > 0


def rm_judge(command: Command, m: re.Match) -> Severity | None:
    """`rm -rf` of /tmp paths or cache dot-dirs, in a command whose every
    segment is trusted: medium."""
    if not command.all_trusted:
        return None
    seg = command.segment_at(m.start())
    if seg is None or not seg.argv or seg.argv[0].start != m.start() or m.end() > seg.end:
        return None
    return Severity.MEDIUM if rm_segment_safe(seg, allow_build=False) else None


# -- chmod -------------------------------------------------------------------

_CHMOD_FLAG_RE = re.compile(r"-[Rvcf]+")
_MODE3_RE = re.compile(r"[0-7]{3}")


def _chmod_target(word: str) -> bool:
    """A user path (relative, ~, ~/..., /tmp, /home, /Users) with no hidden
    component anywhere (~/.ssh, ~/.bashrc, .git/hooks keep their severity)."""
    if word == "~":
        return True
    rest = _user_path_rest(word)
    comps = None if rest is None else _components(rest)
    return comps is not None and not any(c.startswith(".") for c in comps)


def chmod_segment_safe(seg: Segment) -> bool:
    """`chmod NNN target...`: exactly three octal digits (no setuid, setgid
    or sticky bit), -R/-v/-c/-f flags, user paths only, no redirection."""
    argv = seg.argv
    if len(argv) < 3 or argv[0].kind != "word" or argv[0].text != "chmod" or seg.redirects:
        return False
    if argv[1].kind != "word" or not _MODE3_RE.fullmatch(argv[1].text):
        return False
    targets = 0
    for t in argv[2:]:
        if t.kind != "word":
            return False
        if t.text.startswith("-"):
            if not _CHMOD_FLAG_RE.fullmatch(t.text):
                return False
            continue
        if not _chmod_target(t.text):
            return False
        targets += 1
    return targets > 0


def chmod_judge(command: Command, m: re.Match) -> Severity | None:
    """A shaped chmod (``chmod_segment_safe``) in a command whose every
    segment is trusted: low."""
    if not command.all_trusted:
        return None
    seg = command.segment_at(m.start())
    if seg is None:
        return None
    argv = seg.argv
    if len(argv) < 2 or argv[0].start != m.start() or m.end() != argv[1].end:
        return None
    return Severity.LOW if chmod_segment_safe(seg) else None


# -- python socket ----------------------------------------------------------

_PYTEST_FLAG = re.compile(r"-[qxvsl]+|--tb=(?:short|long|line|no)|--maxfail=[0-9]{1,4}")
_PYTEST_ARG = re.compile(r"[A-Za-z0-9_./:\[\]-]+")
_PYTHONS = frozenset({"python", "python3"})


def pytest_segment(seg: Segment) -> bool:
    """`python[3] -m pytest` with test paths/node ids, -k/-m word
    expressions and a few output flags only (no -p plugin, no -c config,
    no quoted argument)."""
    argv = seg.argv
    if seg.redirects or len(argv) < 3 or any(t.kind != "word" for t in argv):
        return False
    if argv[0].text not in _PYTHONS or argv[1].text != "-m" or argv[2].text != "pytest":
        return False
    k = 3
    while k < len(argv):
        w = argv[k].text
        if w in ("-k", "-m"):
            if k + 1 >= len(argv) or not _PYTEST_ARG.fullmatch(argv[k + 1].text):
                return False
            k += 2
            continue
        if w.startswith("-"):
            if not _PYTEST_FLAG.fullmatch(w):
                return False
        elif not _PYTEST_ARG.fullmatch(w):
            return False
        k += 1
    return True


def socket_judge(command: Command, m: re.Match) -> Severity | None:
    """`python.*socket.*connect` only from test selection: every segment is
    trusted and the words come from a `python -m pytest` run of test paths
    (tests/test_websocket.py -k reconnect). Anything else, inline code in
    particular (`-c`, heredocs), keeps its severity: medium."""
    if not command.all_trusted:
        return None
    for seg in command.segments:
        text = command.cmd[seg.start : seg.end].lower()
        if ("socket" in text or "connect" in text) and not pytest_segment(seg):
            return None
    return Severity.MEDIUM


# -- sleep N; curl loopback -------------------------------------------------

# Loopback host, optional port, and a plain path: no {} or [] (curl URL
# globbing), no @ (userinfo), no backslash.
_LOOPBACK_URL = re.compile(
    r"(?:https?://)?(?:localhost|127\.0\.0\.1|\[::1\])(?::([0-9]{1,5}))?"
    r"(?:/[A-Za-z0-9._~%/?=&:+,-]*)?"
)
# curl flags that neither read nor write a file. Not -w/--write-out
# (%output{file} writes any file), -H (@file reads one), -d/-F/-T (upload),
# -K, -D, -c, -b, --trace*, --stderr, --libcurl, --etag-*, --hsts,
# --alt-svc, --output-dir, -x, --resolve, --connect-to, -L ...
_CURL_BOOL = re.compile(r"-[sSfiIvk]+")
_CURL_LONG_BOOL = frozenset({
    "--silent", "--show-error", "--fail", "--head", "--include", "--verbose",
})
_CURL_WITH_VALUE = frozenset({
    "-X", "--request", "-m", "--max-time", "--connect-timeout", "--retry",
    "-o", "--output",  # only /dev/null, checked below
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


def loopback_fetch(seg: Segment) -> bool:
    argv = seg.argv
    if not argv or argv[0].kind != "word" or argv[0].text not in ("curl", "wget"):
        return False
    if seg.redirects:
        return False
    curl = argv[0].text == "curl"
    if curl and not _curl_flags_ok(argv):
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
        url = _LOOPBACK_URL.fullmatch(w)
        if url is None or (url.group(1) and int(url.group(1)) > 65535):
            return False
        urls += 1
        k += 1
    return urls > 0


def _sleep_segment(seg: Segment) -> bool:
    argv = seg.argv
    return (
        len(argv) == 2 and argv[0].text == "sleep" and argv[1].kind == "word"
        and argv[1].text.isdigit() and not seg.redirects
    )


def sleep_fetch_judge(command: Command, m: re.Match) -> Severity | None:
    """`sleep N; curl|wget <loopback URLs>` as two whole simple commands, in
    a command whose every segment is trusted (so no loop, no decoy, no
    pipe into anything but trusted segments): medium."""
    if not command.all_trusted:
        return None
    segs = command.segments
    for k, seg in enumerate(segs[:-1]):
        argv = seg.argv
        if not argv or argv[0].start != m.start():
            continue
        if not _sleep_segment(seg) or seg.end_op != ";":
            return None
        fetch = segs[k + 1]
        if m.end() > fetch.end or fetch.end_op in ("|", "&"):
            return None
        return Severity.MEDIUM if loopback_fetch(fetch) else None
    return None


# -- dig ---------------------------------------------------------------------

_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,13}[a-z0-9])?")
_HEX_LABEL = re.compile(r"[0-9a-f]+")


def _plain_hostname(word: str) -> bool:
    """At most 3 labels of at most 15 lower-case letters, digits and
    hyphens; a label of 8+ chars must not look like data (all hex, or more
    than 2 digits). github.com and registry.npmjs.org pass; hex, base32 and
    token-like labels do not."""
    labels = word[:-1].split(".") if word.endswith(".") else word.split(".")
    if not 2 <= len(labels) <= 3:
        return False
    for label in labels:
        if not _LABEL_RE.fullmatch(label):
            return False
        if len(label) >= 8 and (
            _HEX_LABEL.fullmatch(label) or sum(ch.isdigit() for ch in label) > 2
        ):
            return False
    return True


def dig_segment_safe(seg: Segment) -> bool:
    argv = seg.argv
    if seg.redirects or not argv or argv[0].text != "dig":
        return False
    hosts = 0
    for t in argv[1:]:
        if t.kind != "word":
            return False
        if t.text == "+short":
            continue
        if not _plain_hostname(t.text):
            return False
        hosts += 1
    return hosts == 1


def dig_judge(command: Command, m: re.Match) -> Severity | None:
    """`dig [+short] host.name` (``_plain_hostname``) in a command whose
    every segment is trusted: low."""
    if not command.all_trusted:
        return None
    seg = command.segment_at(m.start())
    if seg is None or seg.end_op in ("|", "&"):
        return None
    if not seg.argv or seg.argv[0].start != m.start() or m.end() > seg.end:
        return None
    return Severity.LOW if dig_segment_safe(seg) else None


# -- skill install split over segments ---------------------------------------


def split_segments_judge(command: Command, m: re.Match) -> Severity | None:
    """The rule's words are in different simple commands, and EVERY segment
    is a trusted shape (no clone, no install script, no package manager):
    the rule matches inside none of them. Low."""
    if not command.all_trusted:
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
    if not command.heredoc_spans and not command.all_trusted:
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
            if not rm_segment_safe(seg, allow_build=True):
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


# A key body: a base64 run of 16+ chars ANYWHERE after the BEGIN line once
# whitespace (and JSON \\n/\\r/\\t escapes) is removed, so padding, short
# wrapped lines and space-separated groups still count as a body.
_KEY_BODY_RUN = re.compile(r"[A-Za-z0-9+/=]{16}")
_KEY_SPACE = re.compile(r"\s+|\\[nrt]")


def key_header_without_body(text: str, header_end: int) -> bool:
    """A PEM/PGP BEGIN line with nothing key-like after it in the whole
    text: prose, a regex, a test that builds the key from variables."""
    return _KEY_BODY_RUN.search(_KEY_SPACE.sub("", text[header_end:])) is None


# Characters a key value can continue with: an example glued to more key
# characters (AKIAIOSFODNN7EXAMPLE + a real key) is not the example. `=`
# only ends a value (base64 padding); before one it is the assignment.
_KEY_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-"
)


def bounded(text: str, start: int, end: int) -> bool:
    """[start, end) is a whole value: no key character right before it, and
    no key character or padding right after it."""
    return (start == 0 or text[start - 1] not in _KEY_CHARS) and (
        end >= len(text) or (text[end] not in _KEY_CHARS and text[end] != "=")
    )
