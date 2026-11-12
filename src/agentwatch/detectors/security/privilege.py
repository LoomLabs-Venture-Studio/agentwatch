"""Detectors for privilege escalation and dangerous commands.

The SET of commands that produce a finding is exactly develop's: the same
regexes (`DangerousCommandDetector.DANGEROUS_PATTERNS`, shared with the coach
guard, and `PRIVILEGE_COMMAND_PATTERNS`) decide that a finding exists, plus a
few new spellings they miss (`rm -fr`, `rm -r -f`, `rm --recursive --force`,
writes to `/etc/sudoers`, setuid `chmod` with leading zeros or a symbolic
`s`). The detector never drops a command develop would flag.

Only the SEVERITY is new, chosen by small regex rules on the matched text --
no shell parser, no attempt to prove a command is inert:

Everything is CRITICAL unless it fits a narrow allowlist:

* recursive `rm`: HIGH only for literal relative or /tmp, /var/tmp targets
  with no credential store, on a line with nothing else that could change
  what they mean (_rm_shape, _line_critical).
* `chmod`: MEDIUM only for a non-setuid mode on those paths (_chmod_shape).
* `sudo`/`doas`/`pkexec`: HIGH only with safe options and an exact
  allowlisted call: package install/update, a read-only systemctl verb,
  `service <name> status`, netstat (_sudo_shape).
* every other rule stays CRITICAL.

`analyze_command()` returns at most one finding per signal, the most severe.
Long inputs are capped and the back-tracking history/disk patterns are gated
on a literal check, so a 1 MB command stays well under a second.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from agentwatch.guard import DESTRUCTIVE_PATTERNS
from agentwatch.parser.models import ActionBuffer
from agentwatch.parser.security_patterns import PRIVILEGE_COMMAND_PATTERNS

from ..base import Category, SecurityDetector, Severity, Warning
from .secret_scanner import redact_truncate

DANGEROUS = "dangerous_command"
PRIVILEGE = "privilege_escalation"

# develop's dangerous_command patterns (identical to the pre-change detector,
# shared with the coach guard's DESTRUCTIVE_PATTERNS). DANGEROUS_PATTERNS below
# re-exposes them; a guard test asserts the first six are DESTRUCTIVE_PATTERNS
# and the list is 21 long, so the shape must not change.
_DEV_DANGEROUS_PATTERNS = [
    *DESTRUCTIVE_PATTERNS,
    r":\(\)\{:\|:&\};:",
    r"while\s+true.*fork",
    r"nc\s+-[el]",
    r"ncat\s+-[el]",
    r"socat\s+.*EXEC",
    r"bash\s+-i\s+>&\s*/dev/tcp",
    r"python.*socket.*connect",
    r"/bin/sh\s+-i",
    r"history\s+-c",
    r">\s*~/.bash_history",
    r"shred.*\.bash_history",
    r"rm.*\.bash_history",
    r"setenforce\s+0",
    r"iptables\s+-F",
    r"ufw\s+disable",
]

def _gated(pattern: str, literals: tuple[str, ...] | None = None):
    """(lowercase literals the pattern cannot match without, compiled pattern,
    back-tracks). A leading \\bword becomes word(?<!\\wword): the same matches,
    but re can jump straight to the literal (a leading \\b scans every char)."""
    if m := re.match(r"\\b([a-z]+)(.*)", pattern, re.DOTALL):
        word, rest = m.groups()
        pattern = rf"{word}(?<!\w{word}){rest}"
    if literals is None:
        lead = re.match(r"(?:[a-z0-9/>:.=-]|\\[.(){}|])+", pattern)
        literals = (lead.group().replace("\\", "").lower(),) if lead else ("",)
    backtracks = ".*" in pattern or ".+" in pattern
    return literals, re.compile(pattern, re.IGNORECASE), backtracks


# develop's patterns, each gated on a literal. Back-tracking ones (`.*`/`.+`)
# get every literal they need and are capped (see _search).
_BACKTRACKY_LITERALS = {
    r"while\s+true.*fork": ("while", "fork"),
    r"socat\s+.*EXEC": ("socat", "exec"),
    r"python.*socket.*connect": ("python", "socket", "connect"),
    r"shred.*\.bash_history": ("shred", ".bash_history"),
    r"rm.*\.bash_history": ("rm", ".bash_history"),
    r"dd\s+if=.+of=/dev": ("dd", "of=/dev"),
}
_DEV_D = [(p, _gated(p, _BACKTRACKY_LITERALS.get(p))) for p in _DEV_DANGEROUS_PATTERNS]
_DEV_P = [_gated(p) for p in PRIVILEGE_COMMAND_PATTERNS]
# dangerous rules other than develop's three `rm -rf` target patterns.
_DEV_D_NON_RM = [g for p, g in _DEV_D if not p.startswith(r"rm\s+-rf")]
_DEV_D_RM = [g for p, g in _DEV_D if p.startswith(r"rm\s+-rf")]
_DEV_D_ALL = [g for _, g in _DEV_D]
# develop's privilege patterns by family: sudo/su/doas/pkexec, chmod, the rest.
_DEV_P_SUDO = _DEV_P[:4]
_DEV_P_CHMOD = _DEV_P[4:6]
_DEV_P_OTHER = _DEV_P[6:]

_CAP = 20_000  # past this, a gated back-tracking pattern counts as matched

# Literal gates must be a superset of develop's IGNORECASE regexes. Python's
# re also matches these non-ASCII letters to ASCII ones under IGNORECASE (U+017F
# long s, the Kelvin sign, dotted and dotless I), and str.lower() alone misses
# them (casefold() misses dotless i). They are the only such code points: a
# test scans every one.
_FOLD = str.maketrans({"\u017f": "s", "\u212a": "k", "\u0130": "i", "\u0131": "i"})


def _fold(text: str) -> str:
    """*text* lowercased the way the gates compare it to their literals."""
    return text.translate(_FOLD).lower()


def _search(command: str, low: str, gated) -> bool:
    """Any gated pattern matches *command* (same verdict as develop's regex).
    *low* is _fold(command)."""
    for literals, pattern, backtracks in gated:
        if all(lit in low for lit in literals):
            if backtracks and len(command) > _CAP:
                return True  # too long to run safely: count as matched (fail safe)
            if pattern.search(command):
                return True
    return False

# --- new spellings develop misses (additions only) --------------------------
# Recursive+force rm is detected by _rm_calls (below); the leading characters
# of a target develop's `rm -rf` rules cover.
_RM_LEADING = ("/", "~", ".", "*")
_HOME_VAR = re.compile(r"(?:\$HOME|\$\{HOME\})(?:/|$)")  # $HOME, ${HOME}, "$HOME"/x
# a write to /etc/sudoers: checked only around each `/etc/sudoers` literal
# (see _sudoers_write), never by an unbounded regex over the whole command.
_SUDOERS = "/etc/sudoers"
_SUDOERS_WINDOW = 300  # chars before the literal that can hold the writer
_SUDOERS_MAX_HITS = 1000  # past this many occurrences: count as a write
_SUDOERS_WRITERS = {"tee", "cp", "mv", "install", "ln", "dd", "rsync"}
# setuid/setgid chmod: a numeric mode (leading zeros allowed) whose special
# triad sets the suid/sgid bit, or a symbolic mode granting `s`.
_CHMOD_CALL = re.compile(
    r"\bchmod\b(?:\s+-{1,2}[\w-]+|\s+--)*\s+(?P<mode>\S+)", re.IGNORECASE)

# --- severity helpers -------------------------------------------------------
# every rm call, with its flags and operands (used by the new-spelling rule).
_RM_SEG = re.compile(
    r"\brm\b(?P<flags>(?:\s+-{1,2}[\w-]+|\s+--)*)(?P<rest>(?:\s+[^\s;&|<>\n`]+)*)",
    re.IGNORECASE)

# words that raise privileges: each occurrence must fit _sudo_shape.
_ELEVATORS = {"sudo", "doas", "pkexec", "su", "sudoedit", "run0"}
# The only programs sudo/doas/pkexec may run at HIGH (exact name, no path), each
# with its own narrow argument rule below. Anything else under an elevator -- a
# path program, an interpreter, a shell, an editor, umount, ss, lsof -- is
# CRITICAL.
_SUDO_PROGRAMS = {"apt", "apt-get", "dnf", "yum", "pacman", "zypper", "snap", "flatpak",
                  "systemctl", "service", "netstat"}
# Package managers: HIGH only for these verbs (the first non-flag word), with
# flags from _PKG_FLAGS and plain registry package names. Every other verb
# (remove, purge, erase, builddep, history, try, ack, addrepo, shell, show, ...)
# stays CRITICAL. pacman has no verb word; its flags are the whole allowlist.
_PKG_VERBS = {
    "apt": {"install", "update", "upgrade"},
    "apt-get": {"install", "update", "upgrade"},
    "dnf": {"install", "update", "upgrade", "info", "list"},
    "yum": {"install", "update", "upgrade", "info", "list"},
    "zypper": {"install", "update"},
    "snap": {"install"},
    "flatpak": {"install", "update"},
}
_PKG_FLAGS = {"-y", "-q", "-qq", "--yes", "--assume-yes", "--quiet",
              "--no-install-recommends"}
_PACMAN_FLAGS = {"-S", "-Sy", "-Syu", "-Su", "-Ss", "-Q", "--noconfirm", "--needed"}
# a plain registry package name: no path, URL, version pin or option.
_PKG_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.-]*")
# a name that is really a local file (package, build spec, repo, assertion).
_PKG_FILE = re.compile(
    r"\.(?:u?deb|ddeb|rpm|spec|snap|assert|repo|flatpak\w*)$|\.pkg\.tar(?:\.|$)",
    re.IGNORECASE)
# systemctl: HIGH only as `systemctl <read-only verb> [unit | no-value flag]...`
# with the verb as the very first word (an option before it could take the
# verb as its value: `systemctl -p is-active stop sshd`). Verbs that print text
# page (`less` runs commands), so they also need --no-pager; is-* never page.
_SYSTEMCTL_READ_PAGED = {"status", "show", "cat", "list-units", "list-unit-files",
                         "list-timers", "list-sockets", "list-dependencies", "list-jobs"}
_SYSTEMCTL_READ = {"is-active", "is-enabled", "is-failed", "is-system-running"}
_SYSTEMCTL_FLAGS = {"--no-pager", "--quiet", "-q", "--full", "-l"}
_UNIT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9@_.:-]*")
# netstat only reads kernel tables: flag clusters only, no operand, no value.
_NETSTAT_ARG = re.compile(r"-[A-Za-z]+|--[a-z-]+")


def _systemctl_read_only(args: list[str]) -> bool:
    if not args:
        return False
    verb, rest = args[0], args[1:]
    if verb not in _SYSTEMCTL_READ and verb not in _SYSTEMCTL_READ_PAGED:
        return False
    if not all(a in _SYSTEMCTL_FLAGS or (not a.startswith("-") and _UNIT_NAME.fullmatch(a))
               for a in rest):
        return False
    return verb in _SYSTEMCTL_READ or "--no-pager" in rest


def _pkg_safe(prog: str, args: list[str]) -> bool:
    """A package-manager call that only installs/updates/queries plain names."""
    flags = [a for a in args if a.startswith("-")]
    words = [a for a in args if not a.startswith("-")]
    if prog == "pacman":
        verb_ok, allowed = bool(flags), _PACMAN_FLAGS
    else:
        verb_ok, allowed = bool(words) and words[0] in _PKG_VERBS[prog], _PKG_FLAGS
        words = words[1:]
    return verb_ok and all(f in allowed for f in flags) and all(
        _PKG_NAME.fullmatch(w) and not _PKG_FILE.search(w) for w in words)


# `service NAME VERB` runs /etc/init.d/NAME as root (or hands VERB to
# systemctl): HIGH only for `service <plain name> status`. A name with a path
# or `..` (`service ../../tmp/x start`), any flag (--status-all, --full-restart)
# and every other verb stay CRITICAL, like systemctl's.
_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_@+-]*(?:\.[A-Za-z0-9_@+-]+)*")


def _service_read_only(args: list[str]) -> bool:
    return (len(args) == 2 and args[1] == "status"
            and _SERVICE_NAME.fullmatch(args[0]) is not None)


# credential stores: a path part that IS one of these or starts with one
# (`.gnupg.bak`) keeps an rm/chmod CRITICAL. `.config` counts as a whole (gh,
# gcloud, op, hub, ... live there); so does any dot-file with `history` in it.
_CREDENTIAL_DIRS = (".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".netrc",
                    ".password-store", "keyrings", "keychains", ".pgpass",
                    ".git-credentials", ".npmrc", ".pypirc", ".vault-token", ".config",
                    ".claude", ".mozilla", ".cargo", ".terraform.d", ".m2",
                    # shell startup files: world-writable means code run as you
                    ".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile",
                    ".zshenv", ".login")
# multi-part credential locations (matched on the lowercased joined path).
_CREDENTIAL_PATHS = (".config/gcloud", ".local/share/keyrings", "library/keychains")
# entries directly under /tmp or /var/tmp that hold live credentials or
# sockets: Kerberos caches, ssh-agent sockets, X11/ICE sockets (any dot entry).
_TMP_SENSITIVE = ("krb5cc", "ssh-", "systemd-private-", "tmux-", ".")
# a cd/pushd/popd anywhere on the line (linear: one fixed-width boundary each side).
_CHANGES_DIR = re.compile(r"(?:^|[\s;&|(`])(?:cd|pushd|popd)(?=$|[\s;&|)`])")
# an absolute path anywhere on the line (at the start or after a space,
# redirect, separator, `=` or `:`). Linear: one fixed-width look-behind.
_ABS_PATH = re.compile(r"(?:^|(?<=[\s<>|;&(=:]))/[^\s<>|;&()'\"`]*")
# A segment with any of these cannot be split safely into words.
_META = set("$`\"'\\*?[](){}<>!~")
_SEGMENTS = re.compile(r"\|\||&&|[;\n|&]")  # linear split into simple commands
_SAFE_PATH = re.compile(r"[A-Za-z0-9._/+-]+")  # a plain literal path
# rm flags that do not change what is deleted beyond recursive/force.
_RM_SAFE_SHORT = re.compile(r"-[rRfvd]+")
_RM_SAFE_LONG = {"--recursive", "--force", "--verbose", "--dir", "--one-file-system"}
# chmod flags that do not change what is set.
_CHMOD_SAFE_SHORT = re.compile(r"-[Rvcf]+")
_CHMOD_SAFE_LONG = {"--recursive", "--verbose", "--changes", "--silent", "--quiet",
                    "--preserve-root"}
# sudo/doas/pkexec options: only these are understood. Every other option
# (-h/--host, -A/--askpass, -D/--chdir, -C, -U, -r, -t, -T, -p, -b, -P, -S, -E,
# -i, -s, -e, `--`, ...) keeps the command CRITICAL.
_SUDO_SAFE_SHORT = set("nHkKvl")
_SUDO_VALUE_SHORT = set("ug")  # value: rest of the cluster or the next word
_SUDO_LONG_VALUE = {"user", "group"}  # value: next word unless written with =
_SUDO_LONG_SAFE = {"non-interactive", "set-home", "list", "validate",
                   "reset-timestamp", "remove-timestamp"}



@dataclass(frozen=True)
class CommandFinding:
    signal: str  # DANGEROUS or PRIVILEGE
    severity: Severity
    reason: str  # fixed text, never command text


def _dev_dangerous(command: str) -> bool:
    """develop's dangerous_command verdict, made safe on long input."""
    return _search(command, _fold(command), _DEV_D_ALL)


def _rm_calls(command: str):
    """The operand list of each recursive+force `rm` in *command*."""
    if "rm" not in _fold(command):
        return
    for m in _RM_SEG.finditer(command):
        flags = m.group("flags").split()
        short = "".join(f[1:] for f in flags if re.fullmatch(r"-[A-Za-z]+", f))
        longs = {f for f in flags if f.startswith("--")}
        if ("r" in short.lower() or "--recursive" in longs) and (
                "f" in short.lower() or "--force" in longs):
            yield m.group("rest").split()


def _rm_flags_anywhere(command: str) -> bool:
    """`rm <x> -rf /`: GNU rm takes flags after operands too."""
    if len(command) > _CAP or "rm" not in _fold(command):
        return False
    for segment in _segments(command):
        words = segment.split()
        if not words or _prog(words[0]) != "rm":
            continue
        short = "".join(w[1:] for w in words[1:] if w[:1] == "-" and w[:2] != "--")
        longs = {w for w in words[1:] if w.startswith("--")}
        if not (("r" in short.lower() or "--recursive" in longs)
                and ("f" in short.lower() or "--force" in longs)):
            continue
        for w in words[1:]:
            o = _unquote(w)
            if not o.startswith("-") and (o[:1] in _RM_LEADING or _HOME_VAR.match(o)):
                return True
    return False


def _new_rm_match(command: str) -> bool:
    """A recursive+force rm of a target develop's `rm -rf` rules cover, in a
    spelling develop's literal patterns miss. Unions cleanly with develop."""
    if _rm_flags_anywhere(command):
        return True
    for ops in _rm_calls(command):
        if any(_unquote(op)[:1] in _RM_LEADING or _HOME_VAR.match(_unquote(op))
               for op in ops):
            return True
    return False


def _dangerous_match(command: str) -> bool:
    return _dev_dangerous(command) or _new_rm_match(command)


# A command without one of these words cannot match any privilege rule.
_PRIV_LITERALS = ("sudo", "su", "doas", "pkexec", "chmod", "chown", "chgrp", "setcap",
                  "getcap", "useradd", "usermod", "groupadd", "visudo", "systemctl",
                  "service", "sudoers")


def _privilege_match(command: str) -> bool:
    low = _fold(command)
    if not any(lit in low for lit in _PRIV_LITERALS):
        return False
    return bool(
        _search(command, low, _DEV_P)
        or _sudoers_write(command)
        or _chmod_setid(command)
    )


def _unquote(op: str) -> str:
    op = op.strip()
    if len(op) >= 2 and op[0] == op[-1] and op[0] in "\"'":
        op = op[1:-1]
    return op


def _prog(word: str) -> str:
    """Program name: lowercased basename without a .exe suffix."""
    return _fold(word.replace("\\", "/").rsplit("/", 1)[-1]).removesuffix(".exe")


def _sudoers_write(command: str) -> bool:
    """A write to /etc/sudoers: for each occurrence of the literal, the text
    just before it (inside its segment, at most _SUDOERS_WINDOW chars) ends in
    a redirect, `of=`, or a tee / cp / mv / install / ln / sed -i call. Linear:
    gated on the literal, bounded windows, capped number of occurrences."""
    low = _fold(command)
    if _SUDOERS not in low:
        return False
    start, hits = 0, 0
    while (at := low.find(_SUDOERS, start)) >= 0:
        hits += 1
        if hits > _SUDOERS_MAX_HITS:
            return True  # too many to check: count as a write (fail safe)
        if _writes_here(low[max(0, at - _SUDOERS_WINDOW):at]):
            return True
        start = at + 1
    return False


def _writes_here(window: str) -> bool:
    """*window* is the text just before an /etc/sudoers literal. True when the
    segment it ends ends in a redirect or `of=`, or runs a writer program (tee,
    cp, mv, install, ln, dd, rsync) or `sed -i`. Plain string work only."""
    cut = max(window.rfind(c) for c in "\n;&|")
    segment = window[cut + 1:]
    head, _, token = segment.rpartition(" ")
    if ">" in token or "of=" in token or head.rstrip().endswith(">"):
        return True
    words = [_prog(w) for w in head.split()]
    if _SUDOERS_WRITERS.intersection(words):
        return True
    return "sed" in words and any(
        w.startswith("-i") or w.startswith("--in-place") for w in head.split())


def _chmod_setid(command: str) -> bool:
    """A chmod whose mode sets setuid/setgid: numeric (leading zeros allowed)
    or symbolic with `s`."""
    if "chmod" not in _fold(command):
        return False
    for m in _CHMOD_CALL.finditer(command):
        mode = _unquote(m.group("mode"))
        if re.fullmatch(r"[0-7]{1,12}", mode):
            if int(mode, 8) & 0o6000:
                return True
        elif any(re.fullmatch(r"[ugoa]*(?:[-+=][rwxXst]*)+", part) and "s" in part
                 for part in mode.split(",")):
            return True
    return False


def _segments(command: str) -> list[str]:
    """The simple commands, split on ; && || | & and newlines (linear)."""
    return _SEGMENTS.split(command)


def _safe_words(segment: str) -> list[str] | None:
    """The segment split into words, or None when it holds a shell metacharacter
    (quote, $, backtick, glob, brace, redirection, subshell, escape) that makes
    a plain split unsafe."""
    if any(ch in _META for ch in segment):
        return None
    return segment.split()


def _credential(path: str) -> bool:
    """A path naming a credential store anywhere in it (case-insensitive): a
    part starting with a _CREDENTIAL_DIRS name, a dot-file with `history` in
    it, a _CREDENTIAL_PATHS location, or a sensitive entry right under /tmp or
    /var/tmp (_TMP_SENSITIVE)."""
    parts = [p for p in _fold(path).split("/") if p not in ("", ".")]
    if any(p.startswith(_CREDENTIAL_DIRS) or (p[:1] == "." and "history" in p)
           for p in parts):
        return True
    joined = "/".join(parts)
    if any(c in joined for c in _CREDENTIAL_PATHS):
        return True
    tmp = parts[1:] if parts[:1] == ["tmp"] else parts[2:] if parts[:2] == ["var", "tmp"] \
        else []
    return bool(tmp) and tmp[0].startswith(_TMP_SENSITIVE)


def _safe_target(op: str) -> bool:
    """Allowlist for a path an rm/chmod may touch at the lower severity:
    (a) a relative literal path, not `.` or `..`, with no `..` segment, or
    (b) an absolute literal path under /tmp/ or /var/tmp/ (after collapsing
    `//` and `/./`), with no `..` segment. Anything else is not safe.

    Symlinks are trusted: the path is judged by its text, never resolved. A
    link under /tmp (`rm -rf /tmp/x/` where x points at /etc) or a harmlessly
    named relative link stays HIGH (MEDIUM for chmod). The finding is still
    reported; only its severity can be too low."""
    if not _SAFE_PATH.fullmatch(op) or op.startswith("-"):
        return False
    parts = [p for p in op.split("/") if p not in ("", ".")]
    if ".." in parts or not parts:
        return False
    if _credential(op):
        return False
    if not op.startswith("/"):
        return True
    return (parts[0] == "tmp" and len(parts) >= 2) or (
        parts[:2] == ["var", "tmp"] and len(parts) >= 3)


def _all_occurrences_safe(command: str, progs: set[str], shape) -> bool | None:
    """True when every word naming one of *progs* anywhere in *command* is the
    program of its own segment and that segment fits *shape*; False when any
    occurrence does not; None when *command* holds no such word at all. A
    segment that cannot be split safely and mentions one of *progs* fails."""
    if len(command) > _CAP:
        return False
    seen = False
    for segment in _segments(command):
        low = _fold(segment)
        if not any(p in low for p in progs):
            continue
        words = _safe_words(segment)
        if words is None:
            # mentions the program but cannot be judged word by word
            if any(_prog(w.strip("\"'`$(){}<>;|&")) in progs for w in segment.split()) \
                    or any(re.search(rf"\b{p}\b", low) for p in progs):
                return False
            continue
        hits = [i for i, w in enumerate(words) if _prog(w) in progs]
        if not hits:
            continue
        seen = True
        if hits != [0] or not shape(words):
            return False
    return True if seen else None


def _rm_shape(words: list[str]) -> bool:
    """`rm` + only allowlisted flags + one or more safe targets."""
    flags = [w for w in words[1:] if w.startswith("-")]
    targets = [w for w in words[1:] if not w.startswith("-")]
    return bool(targets) and all(
        _RM_SAFE_SHORT.fullmatch(f) or f in _RM_SAFE_LONG for f in flags) and all(
        _safe_target(t) for t in targets)


def _cd_shape(words: list[str]) -> bool:
    """`cd <dir>` / `pushd <dir>` with exactly one target that keeps a later
    relative rm target harmless: a safe relative path or one under /tmp,
    /var/tmp (see _safe_target), or a literal path at least three levels below
    a home root (/home/<user>/<a>/..., /Users/<user>/<a>/...) with no
    credential directory. popd, a bare `cd`, `cd -`, a flag or anything else
    fails."""
    if _prog(words[0]) not in ("cd", "pushd") or len(words) != 2:
        return False
    target = words[1]
    if target[:1] in "+-":
        return False  # pushd +1, cd -, cd -P: a stack entry or a flag
    return _safe_target(target) or _home_path(target)


def _home_path(path: str) -> bool:
    """A literal absolute path at least three levels below a home root
    (/home/<user>/<a>/..., /Users/<user>/<a>/...) with no credential store."""
    if not path.startswith("/") or not _SAFE_PATH.fullmatch(path):
        return False
    parts = [p for p in path.split("/") if p not in ("", ".")]
    return (".." not in parts and len(parts) >= 3 and parts[0] in ("home", "Users")
            and not _credential(path))


def _cd_joins_credential(command: str) -> bool:
    """A cd/pushd target joined with an rm or chmod operand names a credential
    store (`cd .local && rm -rf ./share/keyrings`). Same verdict as _credential(d + "/" + t)
    over every pair, in linear time: a credential part lies wholly in d or in
    t, and a multi-part credential path crossing the join is some split
    `head/tail` of it with d ending in head and t starting with tail."""
    dirs, targets = [], []
    for segment in _segments(command):
        words = _safe_words(segment) or []
        if not words:
            continue
        if _prog(words[0]) in ("cd", "pushd"):
            dirs += words[1:]
        elif _prog(words[0]) in ("rm", "chmod"):
            targets += [w for w in words[1:] if not w.startswith("-")]
    if not dirs or not targets:
        return False
    if any(_credential(p) for p in dirs) or any(_credential(p) for p in targets):
        return True
    splits = [(c[:k], c[k + 1:]) for c in _CREDENTIAL_PATHS
              for k, ch in enumerate(c) if ch == "/"]

    def norm(path: str) -> str:
        return "/".join(p for p in _fold(path).split("/") if p not in ("", "."))

    heads = {h for d in map(norm, dirs) for h, _ in splits if d.endswith(h)}
    tails = {t for p in map(norm, targets) for _, t in splits if p.startswith(t)}
    return any(h in heads and t in tails for h, t in splits)


def _line_critical(command: str, gated, prog: str) -> bool:
    """What around an rm/chmod keeps it CRITICAL, whatever its own shape:
    a develop match in a segment whose program is not *prog* (`farm -rf /`),
    CDPATH or `~` anywhere, an absolute path anywhere on the line that is not
    under /tmp, /var/tmp or three levels below a home root (or /dev/null), a
    cd/pushd/popd that does not fit _cd_shape (it could move what a relative
    target means), or a cd target joined with an operand naming a credential
    store."""
    if len(command) > _CAP:
        return True
    low = _fold(command)
    if "cdpath" in low or "~" in command:
        return True
    for path in _ABS_PATH.findall(command):
        if path != "/dev/null" and not _safe_target(path) and not _home_path(path):
            return True
    for segment in _segments(command):
        if _search(segment, _fold(segment), gated):
            words = _safe_words(segment)
            if not words or _prog(words[0]) != prog:
                return True
    if _CHANGES_DIR.search(command):
        if _all_occurrences_safe(command, {"cd", "pushd", "popd"}, _cd_shape) is not True:
            return True
        if _cd_joins_credential(command):
            return True
    return False


def _rm_targets_critical(command: str) -> bool:
    """HIGH (False) only when every rm in the command is the program of a
    segment that fits _rm_shape and nothing else on the line keeps it
    CRITICAL (_line_critical); otherwise CRITICAL."""
    if _line_critical(command, _DEV_D_RM, "rm"):
        return True
    return _all_occurrences_safe(command, {"rm"}, _rm_shape) is not True


def _chmod_shape(words: list[str]) -> bool:
    """`chmod` + allowlisted flags + a non-setuid octal or s-free symbolic mode
    + one or more safe targets."""
    flags = [w for w in words[1:] if w.startswith("-")]
    rest = [w for w in words[1:] if not w.startswith("-")]
    if not all(_CHMOD_SAFE_SHORT.fullmatch(f) or f in _CHMOD_SAFE_LONG for f in flags):
        return False
    if len(rest) < 2:
        return False
    mode, paths = rest[0], rest[1:]
    if re.fullmatch(r"[0-7]{1,5}", mode):
        if int(mode, 8) > 0o7777 or int(mode, 8) & 0o6000:
            return False
    elif not all(re.fullmatch(r"[ugoa]*[-+=][rwxXt]*", part) for part in mode.split(",")):
        return False
    return all(_safe_target(p) for p in paths)


def _chmod_medium(command: str) -> bool:
    """MEDIUM only when every chmod in the command fits _chmod_shape and
    nothing else on the line keeps it CRITICAL (_line_critical)."""
    if _line_critical(command, _DEV_P_CHMOD, "chmod"):
        return False
    return _all_occurrences_safe(command, {"chmod"}, _chmod_shape) is True


def _sudo_shape(words: list[str]) -> bool:
    """sudo/doas/pkexec + options from the safe lists only (-u/-g consume their
    value) + either no program or an exact program from _SUDO_PROGRAMS whose
    arguments fit that program's rule. `su`, `sudoedit`, every other option
    and every other program fail."""
    elevator = _prog(words[0])
    if elevator not in ("sudo", "doas", "pkexec", "run0"):
        return False
    i = 1
    while i < len(words) and words[i].startswith("-"):
        flag = words[i]
        i += 1
        if flag.startswith("--"):
            name, _, value = flag[2:].partition("=")
            if name in _SUDO_LONG_VALUE:
                if not value:
                    i += 1  # the value is the next word
                continue
            if name not in _SUDO_LONG_SAFE or value:
                return False  # `--`, --login, --host, --chdir, anything unknown
            continue
        body = flag[1:]
        if not body:
            return False
        for k, ch in enumerate(body):
            if ch in _SUDO_VALUE_SHORT:
                if k == len(body) - 1:
                    i += 1  # the value is the next word
                break  # the rest of the cluster is the value
            if ch not in _SUDO_SAFE_SHORT:
                return False  # -i, -s, -e, -h, -A, -D or anything unknown
    if i >= len(words):
        return True  # no program: sudo -l, -v, -k
    prog, args = words[i], words[i + 1:]
    if prog in _PKG_VERBS or prog == "pacman":
        return _pkg_safe(prog, args)
    if prog == "systemctl":
        return _systemctl_read_only(args)
    if prog == "service":
        return _service_read_only(args)
    if prog == "netstat":
        return all(_NETSTAT_ARG.fullmatch(a) for a in args)
    return False  # NAME=value, a path, an interpreter, a shell, anything else


def _sudo_high(command: str) -> bool:
    """HIGH only when every sudo/doas/pkexec/su/sudoedit/run0 in the command
    is the program of a segment that fits _sudo_shape."""
    return _all_occurrences_safe(command, _ELEVATORS, _sudo_shape) is True


def _dangerous_finding(command: str) -> CommandFinding | None:
    if not _dangerous_match(command):
        return None
    # Any dangerous rule other than a plain recursive rm is CRITICAL (disk,
    # fork, nc, reverse shell, history wipe, SELinux/firewall off, ...).
    if _non_rm_dangerous(command):
        return CommandFinding(DANGEROUS, Severity.CRITICAL, "destructive command")
    sev = Severity.CRITICAL if _rm_targets_critical(command) else Severity.HIGH
    reason = ("recursive delete of a filesystem-level target"
              if sev == Severity.CRITICAL else "recursive delete")
    return CommandFinding(DANGEROUS, sev, reason)


def _privilege_finding(command: str) -> CommandFinding | None:
    if not _privilege_match(command):
        return None
    if len(command) > _CAP:
        return CommandFinding(PRIVILEGE, Severity.CRITICAL, "privilege escalation")
    low = _fold(command)
    best = None

    def worse(sev: Severity) -> None:
        nonlocal best
        if best is None or sev.score_impact > best.score_impact:
            best = sev

    if _search(command, low, _DEV_P_OTHER) or _sudoers_write(command):
        worse(Severity.CRITICAL)
    if _search(command, low, _DEV_P_SUDO):
        worse(Severity.HIGH if _sudo_high(command) else Severity.CRITICAL)
    if _search(command, low, _DEV_P_CHMOD) or _chmod_setid(command):
        worse(Severity.MEDIUM if _chmod_medium(command) else Severity.CRITICAL)
    if best is None:
        best = Severity.CRITICAL  # matched but uncategorized: keep CRITICAL
    reason = {Severity.CRITICAL: "privilege escalation",
              Severity.HIGH: "runs sudo", Severity.MEDIUM: "permission change"}[best]
    return CommandFinding(PRIVILEGE, best, reason)


# dangerous rules that stay CRITICAL (everything but the plain recursive-rm
# target patterns and the new rm spellings).


def _non_rm_dangerous(command: str) -> bool:
    """A dangerous rule other than develop's plain `rm -rf` target patterns
    (disk wipe, fork bomb, netcat, reverse shell, history wipe, SELinux or
    firewall off): always CRITICAL."""
    return _search(command, _fold(command), _DEV_D_NON_RM)


@lru_cache(maxsize=256)
def analyze_command(command: str) -> tuple[CommandFinding, ...]:
    """The dangerous_command and privilege_escalation findings for *command*
    (at most one each), or an empty tuple. The set of flagged commands is
    develop's plus the new spellings; only the severity is refined."""
    return tuple(f for f in (_dangerous_finding(command), _privilege_finding(command))
                 if f is not None)


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
    """Detects commands that run with raised privileges."""

    category = Category.PRIVILEGE
    name = "privilege_escalation"
    description = "Privilege escalation attempt detected"

    # Shared with `SessionStats.privilege_commands` (raw counter).
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
    """Detects dangerous or destructive commands."""

    category = Category.PRIVILEGE
    name = "dangerous_command"
    description = "Potentially dangerous command detected"

    # develop's patterns, shared with the coach hook's command guard. The
    # detector matches these (plus the new rm spellings) and only tiers the
    # severity; a guard test pins this list's shape.
    DANGEROUS_PATTERNS = _DEV_DANGEROUS_PATTERNS

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
