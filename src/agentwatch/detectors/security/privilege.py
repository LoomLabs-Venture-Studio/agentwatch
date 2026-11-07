"""Detectors for privilege escalation and dangerous commands.

The SET of commands that produce a finding is exactly develop's: the same
regexes (`DangerousCommandDetector.DANGEROUS_PATTERNS`, shared with the coach
guard, and `PRIVILEGE_COMMAND_PATTERNS`) decide that a finding exists, plus a
few new spellings they miss (`rm -fr`, `rm -r -f`, `rm --recursive --force`,
writes to `/etc/sudoers`, setuid `chmod` with leading zeros or a symbolic
`s`). The detector never drops a command develop would flag.

Only the SEVERITY is new, chosen by small regex rules on the matched text --
no shell parser, no attempt to prove a command is inert:

* recursive `rm`: CRITICAL when the target is the whole filesystem, the home
  directory, the working/parent directory, a top-level system directory, or
  anything with a variable, substitution or glob in it; otherwise HIGH (a
  path such as `/tmp/x`, `.pytest_cache` or `./build`).
* `chmod`: CRITICAL for setuid/setgid, otherwise MEDIUM.
* `sudo`/`doas`/`pkexec`/`su`: CRITICAL when it runs a shell, takes a
  login/shell flag, runs `su`, or is piped into; otherwise HIGH.
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

# Each develop pattern, split into the ones that are linear on any input and
# the ones that back-track (`.*`/`.+`); the latter are gated on a literal and
# capped so a crafted megabyte cannot make them quadratic.
_LINEAR_D = []
_BACKTRACKY_D = []  # (required lowercase literals, compiled pattern)
_BACKTRACKY_LITERALS = {
    r"while\s+true.*fork": ("while", "fork"),
    r"socat\s+.*EXEC": ("socat", "exec"),
    r"python.*socket.*connect": ("python", "socket", "connect"),
    r"shred.*\.bash_history": ("shred", ".bash_history"),
    r"rm.*\.bash_history": ("rm", ".bash_history"),
    r"dd\s+if=.+of=/dev": ("dd", "of=/dev"),
}
for _p in _DEV_DANGEROUS_PATTERNS:
    if _p in _BACKTRACKY_LITERALS:
        _BACKTRACKY_D.append((_BACKTRACKY_LITERALS[_p], re.compile(_p, re.IGNORECASE)))
    else:
        _LINEAR_D.append(_p)
_LINEAR_DANGEROUS = re.compile("|".join(_LINEAR_D), re.IGNORECASE)

# develop's privilege patterns are all linear.
_DEV_PRIVILEGE = re.compile("|".join(PRIVILEGE_COMMAND_PATTERNS), re.IGNORECASE)

_CAP = 20_000  # past this, a gated back-tracking pattern counts as matched

# --- new spellings develop misses (additions only) --------------------------
# Recursive+force rm is detected by _rm_calls (below); the leading characters
# of a target develop's `rm -rf` rules cover.
_RM_LEADING = ("/", "~", ".", "*")
_HOME_VAR = re.compile(r"(?:\$HOME|\$\{HOME\})(?:/|$)")  # $HOME, ${HOME}, "$HOME"/x
# a write to /etc/sudoers via redirect, tee, sed -i, dd of=, cp/mv/install/ln.
_SUDOERS_WRITE = re.compile(
    r">\s*\S*/etc/sudoers"
    r"|\btee\b[^\n|&;]*?\s/?\S*/etc/sudoers"
    r"|\bsed\b[^\n|&;]*?-i[^\n|&;]*?\s/?\S*/etc/sudoers"
    r"|\bdd\b[^\n|&;]*?\bof=\s*\S*/etc/sudoers"
    r"|\b(?:cp|mv|install|ln)\b[^\n|&;]*?\s/?\S*/etc/sudoers",
    re.IGNORECASE)
# setuid/setgid chmod: a numeric mode (leading zeros allowed) whose special
# triad sets the suid/sgid bit, or a symbolic mode granting `s`.
_CHMOD_CALL = re.compile(
    r"\bchmod\b(?:\s+-{1,2}[\w-]+|\s+--)*\s+(?P<mode>\S+)", re.IGNORECASE)

# --- severity helpers -------------------------------------------------------
# recursive flags: both recursive and force, in any spelling/order.
_RM_SEG = re.compile(
    r"\brm\b(?P<flags>(?:\s+-{1,2}[\w-]+|\s+--)*)(?P<rest>(?:\s+[^\s;&|<>\n`]+)*)",
    re.IGNORECASE)
_SYSTEM_DIRS = {
    "/", "/etc", "/usr", "/bin", "/sbin", "/var", "/boot", "/root", "/home",
    "/users", "/opt", "/srv", "/system", "/library", "/mnt/c", "c:", "/dev", "/proc",
}
_HOME_SINGLE = re.compile(r"/(?:home|users)/[^/]+$", re.IGNORECASE)
_LIB_DIR = re.compile(r"/lib\w*$", re.IGNORECASE)

_SUDO_FAMILY = re.compile(r"\bsudo\b|\bdoas\b|\bpkexec\b|\bsu\s+-", re.IGNORECASE)
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "tcsh", "csh", "ash", "mksh",
           "yash", "rbash", "rsh", "su", "login"}
# programs that run another command, a script, an editor or a remote: never a
# "safe program" for sudo to run.
_ESCAPE = _SHELLS | {
    "env", "nohup", "setsid", "exec", "eval", "xargs", "find", "watch", "timeout",
    "nice", "ionice", "stdbuf", "command", "builtin", "time", "chroot", "nsenter",
    "unshare", "flock", "runuser", "sg", "systemd-run", "strace", "ltrace", "gdb",
    "awk", "gawk", "perl", "python", "python2", "python3", "ruby", "node", "deno",
    "php", "lua", "tclsh", "expect", "irb", "pry", "ssh", "docker", "podman",
    "kubectl", "tmux", "screen", "vi", "vim", "nvim", "emacs", "nano", "ed",
    "less", "more", "man", "pager",
}
# A segment with any of these cannot be split safely into words.
_META = set("$`\"'\\*?[](){}<>!")
_SEGMENTS = re.compile(r"\|\||&&|[;\n|&]")  # linear split into simple commands
_SAFE_PATH = re.compile(r"[A-Za-z0-9._/@=:+-]+")  # a plain literal operand
# recursive-rm flag spellings that are safe to keep (no interactive/unknown flag).
_RM_SAFE_SHORT = re.compile(r"-[rRfvd]+")
_RM_SAFE_LONG = {"--recursive", "--force", "--verbose", "--dir", "--one-file-system"}
# chmod flags that do not change what is set.
_CHMOD_SAFE_SHORT = re.compile(r"-[Rvcf]+")
_CHMOD_SAFE_LONG = {"--recursive", "--verbose", "--changes", "--silent", "--quiet",
                    "--no-preserve-root", "--preserve-root"}
# sudo flags that neither open a shell nor take the next word as a value.
_SUDO_SAFE_SHORT = set("nHEkKvlbASPe")
# sudo flags that consume the following word.
_SUDO_VALUE_SHORT = set("ugpCUrtRD")

# privilege rules that are always CRITICAL (everything but sudo-family and chmod).
_PRIV_CRITICAL = re.compile(
    r"chown\s+root|chgrp\s+(?:root|wheel|admin)|setcap\b|getcap\b|useradd\b"
    r"|usermod\b|groupadd\b|visudo\b|systemctl\s+(?:enable|start|restart)"
    r"|service\s+\w+\s+(?:start|restart)", re.IGNORECASE)


@dataclass(frozen=True)
class CommandFinding:
    signal: str  # DANGEROUS or PRIVILEGE
    severity: Severity
    reason: str  # fixed text, never command text


def _dev_dangerous(command: str) -> bool:
    """develop's dangerous_command verdict, made safe on long input."""
    if _LINEAR_DANGEROUS.search(command):
        return True
    low = command.lower()
    for literals, pattern in _BACKTRACKY_D:
        if all(lit in low for lit in literals):
            if len(command) > _CAP:
                return True  # too long to verify: keep the finding (fail safe)
            if pattern.search(command):
                return True
    return False


def _rm_calls(command: str):
    """The operand list of each recursive+force `rm` in *command*."""
    if "rm" not in command:
        return
    for m in _RM_SEG.finditer(command):
        flags = m.group("flags").split()
        short = "".join(f[1:] for f in flags if re.fullmatch(r"-[A-Za-z]+", f))
        longs = {f for f in flags if f.startswith("--")}
        if ("r" in short.lower() or "--recursive" in longs) and (
                "f" in short.lower() or "--force" in longs):
            yield m.group("rest").split()


def _new_rm_match(command: str) -> bool:
    """A recursive+force rm of a target develop's `rm -rf` rules cover, in a
    spelling develop's literal patterns miss. Unions cleanly with develop."""
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
    low = command.lower()
    if not any(lit in low for lit in _PRIV_LITERALS):
        return False
    return bool(
        _DEV_PRIVILEGE.search(command)
        or _SUDOERS_WRITE.search(command)
        or _chmod_setid(command)
    )


def _unquote(op: str) -> str:
    op = op.strip()
    if len(op) >= 2 and op[0] == op[-1] and op[0] in "\"'":
        op = op[1:-1]
    return op


def _prog(word: str) -> str:
    """Program name: lowercased basename without a .exe suffix."""
    return word.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")


def _segments(command: str) -> list[str]:
    """The simple commands, split on ; && || | & and newlines (linear)."""
    return _SEGMENTS.split(command)


def _safe_words(segment: str) -> list[str] | None:
    """The segment split into words, or None when it holds a shell metacharacter
    (quote, $, backtick, glob, brace, redirection, subshell) that makes a plain
    split unsafe -- in which case the segment cannot be judged and stays
    CRITICAL."""
    if any(ch in _META for ch in segment):
        return None
    return segment.split()


def _safe_literal_path(op: str) -> bool:
    """An ordinary relative/absolute path that is not a filesystem-level target.
    Allowlist: it must be plain literal text, have no `..`, and not be `/`, `.`,
    a system directory or a single home directory."""
    if not _SAFE_PATH.fullmatch(op):
        return False  # $, glob, ~, quote, escape, ... -> not safe
    parts = op.split("/")
    if ".." in parts:
        return False
    core = op.rstrip("/") or "/"
    if core in (".", "/"):
        return False
    low = core.lower()
    return not (low in _SYSTEM_DIRS or _HOME_SINGLE.match(core) or _LIB_DIR.match(low))


def _rm_targets_critical(command: str) -> bool:
    """CRITICAL unless every recursive+force rm fits the safe allowlist shape:
    `rm` + only {-r,-R,-f,-v,-d,--recursive,--force,...} + one or more plain
    literal non-filesystem-level paths, and nothing else in that segment."""
    if len(command) > _CAP:
        return True  # too long to inspect: keep CRITICAL (fail safe)
    saw = False
    for segment in _segments(command):
        words = _safe_words(segment)
        if words is None:
            # cannot parse this segment: if it holds a recursive rm, stay CRITICAL
            if any(_rm_calls(segment)):
                return True
            continue
        if not words or _prog(words[0]) != "rm":
            continue  # rm reached through a wrapper is judged by _rm_calls below
        flags = [w for w in words[1:] if w.startswith("-")]
        targets = [w for w in words[1:] if not w.startswith("-")]
        recursive = any(f in ("-R", "--recursive") or (f[:1] == "-" and f[:2] != "--"
                        and "r" in f.lower()) for f in flags)
        force = any(f in ("--force",) or (f[:1] == "-" and f[:2] != "--"
                    and "f" in f.lower()) for f in flags)
        if not (recursive and force):
            continue
        saw = True
        safe_flags = all(_RM_SAFE_SHORT.fullmatch(f) or f in _RM_SAFE_LONG for f in flags)
        if not (safe_flags and targets and all(_safe_literal_path(t) for t in targets)):
            return True
    if saw:
        return False  # every recursive rm fit the safe shape -> HIGH
    # No safe rm segment seen, but a recursive rm was matched (wrapper, quoting,
    # metacharacters): we could not verify it -> keep CRITICAL.
    return any(_rm_calls(command))


def _chmod_setid(command: str) -> bool:
    for m in _CHMOD_CALL.finditer(command):
        mode = _unquote(m.group("mode"))
        if re.fullmatch(r"[0-7]+", mode):
            digits = mode.lstrip("0") or "0"
            if len(digits) >= 4 and int(digits[-4]) & 0o6:
                return True
        if re.search(r"[-+=][rwxXst]*s", mode):
            return True
    return False


def _chmod_medium(command: str) -> bool:
    """True (-> MEDIUM) only when every chmod segment fits the safe allowlist
    shape: `chmod [-R/-v/...]` + a non-setuid octal or symbolic-without-s mode
    + plain literal paths, and nothing else. Otherwise CRITICAL."""
    if len(command) > _CAP:
        return False
    saw = False
    for segment in _segments(command):
        words = _safe_words(segment)
        if words is None:
            if re.search(r"\bchmod\b", segment):
                return False
            continue
        if not words or _prog(words[0]) != "chmod":
            continue
        saw = True
        flags = [w for w in words[1:] if w.startswith("-") and w != "--"]
        rest = [w for w in words[1:] if not w.startswith("-")]
        if not all(_CHMOD_SAFE_SHORT.fullmatch(f) or f in _CHMOD_SAFE_LONG for f in flags):
            return False
        if not rest:
            return False
        mode, paths = rest[0], rest[1:]
        octal = re.fullmatch(r"[0-7]{3,4}", mode)
        symbolic = re.fullmatch(r"[ugoa]*[-+=][rwxX]*", mode)
        if octal:
            if len(mode) == 4 and int(mode[0]) & 0o6:
                return False  # setuid/setgid -> CRITICAL
        elif not symbolic:
            return False  # anything we do not fully recognize -> CRITICAL
        if not all(_safe_literal_path(p) for p in paths):
            return False
    return saw


def _sudo_high(command: str) -> bool:
    """True (-> HIGH) only when every sudo/doas/pkexec/su segment fits the safe
    allowlist shape: the elevator + allowlisted flags + at most a plain literal
    program that is not a shell or escape helper. Otherwise CRITICAL."""
    if len(command) > _CAP:
        return False
    for segment in _segments(command):
        words = _safe_words(segment)
        if words is None:
            if _SUDO_FAMILY.search(segment):
                return False
            continue
        if not words:
            continue
        prog = _prog(words[0])
        if prog == "su":
            return False  # su / su - / su root all escalate to a shell
        if prog not in ("sudo", "doas", "pkexec"):
            continue
        i = 1
        while i < len(words) and words[i].startswith("-"):
            flag = words[i]
            i += 1
            if flag == "--":
                break
            if flag.startswith("--"):
                name = flag[2:].split("=", 1)[0]
                if name in ("login", "shell", "edit"):
                    return False
                continue
            body = flag[1:]
            if body and all(c in _SUDO_SAFE_SHORT for c in body):
                continue
            if len(body) == 1 and body in _SUDO_VALUE_SHORT:
                i += 1  # consumes the following value word
                continue
            return False  # -i, -s, or any flag we do not recognize -> CRITICAL
        if i < len(words) and _prog(words[i]) in _ESCAPE:
            return False  # runs a shell or an escape helper
    return True


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
    best = None
    if _PRIV_CRITICAL.search(command):
        best = Severity.CRITICAL
    if _SUDOERS_WRITE.search(command):
        best = Severity.CRITICAL
    if _SUDO_FAMILY.search(command):
        sev = Severity.HIGH if _sudo_high(command) else Severity.CRITICAL
        best = sev if best is None else max(best, sev, key=lambda s: s.score_impact)
    if _CHMOD_NUMERIC.search(command) or _chmod_setid(command):
        sev = Severity.MEDIUM if _chmod_medium(command) else Severity.CRITICAL
        best = sev if best is None else max(best, sev, key=lambda s: s.score_impact)
    if best is None:
        best = Severity.CRITICAL  # matched but uncategorized: keep CRITICAL
    reason = {Severity.CRITICAL: "privilege escalation",
              Severity.HIGH: "runs sudo", Severity.MEDIUM: "permission change"}[best]
    return CommandFinding(PRIVILEGE, best, reason)


# dangerous rules that stay CRITICAL (everything but the plain recursive-rm
# target patterns and the new rm spellings).
_LINEAR_NON_RM = re.compile("|".join(
    p for p in _LINEAR_D if not p.startswith(r"rm\s+-rf")), re.IGNORECASE)
_CHMOD_NUMERIC = re.compile(r"chmod\s+[0-7]*[4567][0-7]*|chmod\s+\+s", re.IGNORECASE)


def _non_rm_dangerous(command: str) -> bool:
    """A dangerous rule other than a plain recursive rm: the linear non-rm
    patterns, or any of the back-tracking ones (disk wipe, reverse shell,
    fork bomb, history wipe), all of which are filesystem/system level and
    stay CRITICAL. Gated on literals and capped, like _dev_dangerous."""
    if _LINEAR_NON_RM.search(command):
        return True
    low = command.lower()
    for literals, pattern in _BACKTRACKY_D:
        if all(lit in low for lit in literals):
            if len(command) > _CAP:
                return True
            if pattern.search(command):
                return True
    return False


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
