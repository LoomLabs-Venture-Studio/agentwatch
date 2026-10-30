"""Command guard: the coach hook asks the user before a catastrophic call.

Runs on Claude Code's PreToolUse, before the loop breaker. A match returns a
fixed reason; coach turns it into `"permissionDecision": "ask"`, so Claude
Code shows the user a permission prompt. A false positive costs one click.

Bash commands are split with shlex into simple commands (on `;`, `&&`, `||`,
`|`, `&`, newlines, `(`, `)`, backticks and `$(`), leading `sudo`, `env`,
`VAR=value`, `nohup`, ... are skipped and `bash/sh/zsh -c '<script>'` is
checked recursively. Arguments of any other program are not inspected, so
`echo "rm -rf /"` or `git commit -m "rm -rf /"` pass. When shlex cannot parse
the command (unbalanced quotes), the raw string is matched against
DESTRUCTIVE_PATTERNS instead.

Stdlib only and imported on every PreToolUse: keep it cheap. It lives
outside `agentwatch.parser`, whose package __init__ imports the watchers
(~180 ms).
"""

from __future__ import annotations

import re
import shlex

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
# `:(){ :|:& };:` and renamed variants, spaces allowed (shlex garbles it).
_FORK_BOMB = re.compile(r"(\w+|:)\s*\(\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1")

_ROOT = {"/", "/*"}
_HOME = {"~", "~/", "~/*", "$HOME", "$HOME/", "$HOME/*", "${HOME}", "${HOME}/", "${HOME}/*"}
_CWD = {"*", ".", "./", "./*", "..", "../", "../*", ".*"}
_DISK = re.compile(r"/dev/(?:sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|disk\d)")
_HARMLESS_DEV = ("/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/fd/")
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
_PREFIXES = {"sudo", "doas", "env", "command", "exec", "nohup", "time", "nice"}
_SEPARATORS = set(";&|()`\n")
_READERS = {"cat", "less", "more", "head", "tail", "cp", "scp", "bat"}

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
    "secret": "agentwatch: this reads a file that may hold secrets ({}). Allow it?",
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
        elif word.rsplit("/", 1)[-1] in _PREFIXES:
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                # sudo -u USER / env -u NAME / nice -n N take a value
                i += 2 if argv[i] in ("-u", "-g", "-n", "-C") else 1
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


def _check_argv(argv: list[str], piped_from: set[str], depth: int) -> str | None:
    if not argv:
        return None
    prog, args = argv[0].rsplit("/", 1)[-1], argv[1:]
    for i, tok in enumerate(argv[:-1]):  # redirections, any program
        if tok in (">", ">>", ">|", "&>") and _DISK.match(argv[i + 1]):
            return REASONS["disk"]
        if tok == "<" and (label := secret_label(argv[i + 1])):
            return REASONS["secret"].format(label)
    if prog in _SHELLS:
        if piped_from & {"curl", "wget"}:
            return REASONS["pipe_shell"]
        for i, a in enumerate(args[:-1]):
            if re.fullmatch(r"-[a-z]*c[a-z]*", a):
                return check_command(args[i + 1], depth + 1)
        return None
    flags, ops = _flags(args)
    if prog == "rm" and flags & {"r", "R", "--recursive"}:
        for kind, targets in (("rm_root", _ROOT), ("rm_home", _HOME), ("rm_cwd", _CWD)):
            if any(op in targets or op.rstrip("/") in targets for op in ops):
                return REASONS[kind]
    if prog == "chmod" and flags & {"R", "--recursive"} and any(
            op in ("777", "0777", "a+rwx") for op in ops) and any(
            op in _ROOT | _HOME for op in ops):
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
        flags, _ = _flags(rest)
        if sub == "push" and ("--force" in flags or "f" in flags):
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


def check_command(command: str, depth: int = 0) -> str | None:
    """The ask reason for a Bash command, or None."""
    if depth > 3:
        return None
    if _FORK_BOMB.search(command):
        return REASONS["fork_bomb"]
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>`\n")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return REASONS["destructive"] if _FALLBACK.search(command) else None
    pipeline: set[str] = set()  # programs earlier in the current pipeline
    for argv, sep in _simple_commands(tokens):
        argv = _strip_prefixes(argv)
        if sep != "|":
            pipeline = set()
        reason = _check_argv(argv, pipeline, depth)
        if reason:
            return reason
        if argv:
            pipeline.add(argv[0].rsplit("/", 1)[-1])
    return None


def check(tool_name: str, tool_input: object) -> str | None:
    """The ask reason for a PreToolUse call, or None."""
    if not isinstance(tool_input, dict):
        return None
    if tool_name == "Bash" and isinstance(tool_input.get("command"), str):
        return check_command(tool_input["command"])
    if tool_name == "Read" and isinstance(tool_input.get("file_path"), str):
        label = secret_label(tool_input["file_path"])
        return REASONS["secret"].format(label) if label else None
    return None
