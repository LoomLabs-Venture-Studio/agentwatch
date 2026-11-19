"""`agentwatch ledger`: what one session ran, changed, deleted and contacted.

Built from one parsed log on demand; nothing is stored. One row per command,
file write, file edit, deleted path and network host (JSON schema 1, fields
only added later):

    ts, agent, tool, kind, target, success, outside_project, destructive, reason

- target: the command (one line, secrets redacted, bounded), the path, or the
  host (``host`` or ``host:port``, never a URL). The home dir is shown as ``~``.
  A URL inside a command or path loses its userinfo, query and fragment
  (``?…``), and a Slack / Discord webhook its path (``/…``): signed URLs keep
  their secret there, which the secret scanner does not know.
  Tool results, file contents and error text are never read into a row.
- destructive / reason: the command guard (guard.check_command) would ask
  (reason ``guard: <key>``), or it runs rm / git rm / git clean / git reset
  --hard / git push --force / --force-with-lease / find -delete / find -exec rm
  / xargs rm / del / Remove-Item (reason: that name). A write or edit of the
  guard's own settings file is ``guard: guard_off``. Guard asks that are not
  findings (``guard: secret`` for a secrets read, ``guard: too_long`` /
  ``guard: unchecked`` when it could not check) keep their reason but are not
  destructive unless the same command also deletes.
- Deleted paths are the operands of rm-like commands, taken from guard's own
  shlex split (guard._Scan + guard._tokens), one delete row each. find and
  xargs deletes have no delete rows (their paths are not in the command).
- outside_project: the path is not under the session's project dir (the cwd
  the log records, else ``--project``). Unknown project, a variable in the path
  (other than $HOME), a `cd` earlier in the same command, or a POSIX path under
  a Windows project: null, never a guess. Commands and hosts: null.

ponytail: the guard's Read-of-a-secrets-file ask is not a ledger row (reads are
not in the ledger); powershell syntax beyond plain words is not parsed.
"""

from __future__ import annotations

import ntpath
import posixpath
import re
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agentwatch import guard
from agentwatch.detectors.security.secret_scanner import one_line
from agentwatch.parser.models import Action, ToolType, is_tool_call

SCHEMA = 1
KINDS = ("command", "write", "edit", "delete", "network")
FIELDS = ("ts", "agent", "tool", "kind", "target", "success", "outside_project",
          "destructive", "reason")
TARGET_LIMIT = 200
TOOL_LIMIT = 80
SECRET_READ = "guard: secret"
# Guard asks that are reported (reason kept) but delete or rewrite nothing.
NOT_DESTRUCTIVE = frozenset({SECRET_READ, "guard: too_long", "guard: unchecked"})
# scheme://... up to whitespace, a quote or <>; linear (one character class).
_URL = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]{0,30}://[^\s'\"<>`]+")
_WEBHOOK_HOST = re.compile(r"hooks\.slack\.com", re.IGNORECASE)
_DISCORD_HOST = re.compile(r"(?:(?:ptb|canary)\.)?discord(?:app)?\.com", re.IGNORECASE)
_DISCORD_PATH = re.compile(r"/api/(?:v\d+/)?webhooks", re.IGNORECASE)

# guard reason text -> its key (the "secret" reason is a format string).
_GUARD_KEYS = [(text.split("{}", 1)[0], key) for key, text in guard.REASONS.items()]
_RM = {"rm", "rmdir", "unlink"}
_CMD_DEL = {"del", "erase", "rd"}  # cmd.exe: /q /s /f switches
_PS_DEL = {"remove-item", "ri"}
_PS_PATH = {"-path", "-literalpath", "-lp", "-pspath"}
_PS_VALUE = {"-include", "-exclude", "-filter", "-credential", "-stream"}
_CD = {"cd", "pushd", "popd", "chdir", "set-location", "sl"}
_CMD_SWITCH = re.compile(r"/[A-Za-z](?::\S*)?")
_WIN_ABS = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")
_DRIVE = re.compile(r"[A-Za-z]:\\")
_HOME_VAR = re.compile(r"^(?:~|\$HOME|\$\{HOME\})(?=[/\\]|$)")
_MAX_DEPTH = 3


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _home() -> str:
    try:
        return str(Path.home())
    except RuntimeError:
        return ""


def _home_re() -> re.Pattern[str] | None:
    """The home dir as written in either separator style, followed by a
    separator or a word end; case-insensitive for a Windows home."""
    home = _home().rstrip("/\\")
    if not home:
        return None
    alts = {re.escape(home), re.escape(home.replace("\\", "/"))}
    flags = re.IGNORECASE if _WIN_ABS.match(home) else 0
    return re.compile(r"(?:" + "|".join(sorted(alts)) + r")(?![\w.-])", flags)


def _scrub_url(m: re.Match[str]) -> str:
    """A URL without userinfo, query or fragment (each cut to ``…``); a Slack
    or Discord webhook also loses its path (the path is the secret)."""
    url = m.group()
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port is not None else ""
    except ValueError:
        return url.split("://", 1)[0] + "://…"
    if ":" in host:  # IPv6
        host = f"[{host}]"
    path = parts.path
    if _WEBHOOK_HOST.fullmatch(host) or (
            _DISCORD_HOST.fullmatch(host) and _DISCORD_PATH.match(path)):
        path = "/…" if path else ""
    tail = "?…" if parts.query or parts.fragment or url.rstrip("?#") != url else ""
    return f"{parts.scheme}://{host}{port}{path}{tail}"


def scrub_urls(text: str) -> str:
    """Every scheme://... URL in *text* without userinfo, query, fragment or a
    webhook's secret path. Signed URLs (S3 X-Amz-Signature, Azure SAS sig=)
    carry their secret in the query, which the secret scanner does not know."""
    return _URL.sub(_scrub_url, text)


def show(text: str, home_re: re.Pattern[str] | None, limit: int = TARGET_LIMIT) -> str:
    """*text* with URLs scrubbed (scrub_urls), the home dir as ``~`` (like
    config_scan.show: / form for a path), one line, secrets redacted, at most
    *limit* chars."""
    text = scrub_urls(text)
    if home_re is not None:
        text = home_re.sub("~", text)
    return one_line(text, limit)


def _show_path(path: str, home_re: re.Pattern[str] | None) -> str:
    path = scrub_urls(path)
    if home_re is not None and home_re.match(path):
        path = home_re.sub("~", path, count=1).replace("\\", "/")
    elif _WIN_ABS.match(path):
        path = path.replace("\\", "/")
    return one_line(path, TARGET_LIMIT)


# ---------------------------------------------------------------------------
# Project dir
# ---------------------------------------------------------------------------

def session_cwd(log: Path, actions: list[Action], agent: str) -> str | None:
    """The session's working directory as the log records it, else None.

    Claude Code: the first ``cwd`` its entries record. Codex: session_meta.cwd.
    Copilot CLI: session.start context.cwd. Gemini: projects.json's entry for
    the log's project. OpenCode / Kilo Code: the session row's directory.
    Others: a ``cwd`` on a parsed entry, if any.
    """
    try:
        if agent == "claude-code":
            from agentwatch.cc_stats import recorded_cwd

            cwd = recorded_cwd(log)
        elif agent == "codex":
            from agentwatch.discovery import _read_codex_session_meta

            cwd = (_read_codex_session_meta(log) or {}).get("cwd")
        elif agent == "copilot":
            from agentwatch.agents.copilot import _session_start_cwd

            cwd = _session_start_cwd(log)
        elif agent == "gemini":
            from agentwatch.agents.gemini import project_cwd

            cwd = project_cwd(log)
        elif agent in ("opencode", "kilo-code"):
            from agentwatch.parser.opencode import session_directory

            sid = next((a.session_id for a in actions if a.session_id), None)
            cwd = session_directory(log, sid) if sid else None
        else:
            cwd = next((c for a in actions if isinstance(a.raw, dict)
                        and isinstance(c := a.raw.get("cwd"), str) and c), None)
    except Exception:  # a header we cannot read: unknown, never a guess
        return None
    return cwd if isinstance(cwd, str) and cwd else None


def _absolute(path: str, base: str) -> str | None:
    """*path* made absolute against *base* (its style), normalised; None when
    it can't be known without guessing."""
    home = _HOME_VAR.match(path)
    if home:
        if not _home():
            return None
        path = _home() + path[home.end():]
    elif "$" in path or "`" in path or path.startswith("~") or "%" in path:
        return None
    if _WIN_ABS.match(base):
        if path.startswith("/") and not path.startswith("//"):
            return None  # Git Bash /c/... or a real POSIX path: can't tell
        return ntpath.normpath(ntpath.join(base, path))
    if _WIN_ABS.match(path):
        return None
    return posixpath.normpath(posixpath.join(base, path))


def outside(path: str | None, project: str | None, base: str | None = None) -> bool | None:
    """True when *path* is not under *project*; None when either is unknown.
    A relative *path* is read against *base* (default: the project)."""
    if not path or not project:
        return None
    full = _absolute(path, base or project)
    root = _absolute(project, project) if _WIN_ABS.match(project) or \
        project.startswith("/") else None
    if full is None or root is None:
        return None
    sep = "\\" if _WIN_ABS.match(root) else "/"
    if sep == "\\":
        full, root = full.lower(), root.lower()
    return not (full == root or full.startswith(root.rstrip(sep) + sep))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _guard_reason(command: str) -> str | None:
    """``guard: <key>`` when the command guard would ask about *command*."""
    text = guard.check_command(command)
    if text is None:
        return None
    key = next((k for prefix, k in _GUARD_KEYS if text.startswith(prefix)), "destructive")
    return f"guard: {key}"


def _simple_commands(command: str) -> tuple[list[list[str]], list[str]]:
    """Each simple command's argv from the program on, read by the guard's own
    scanner and shlex split (comments cut), plus the substitution bodies
    (`$(...)`, backticks, `<(...)`) bash also runs."""
    if len(command) > guard.MAX_PARSE:
        return [], []
    bodies: list[str] = []
    try:
        try:
            scan = guard._Scan(command)
            text, bodies, _ = scan.result()
            text = scan.skeleton(text) or text
        except guard._UnparsedError:
            text = command
        if _DRIVE.search(text):  # C:\x: shlex would eat the backslashes
            text = text.replace("\\", "\\\\")
        tokens = guard._tokens(text)
    except Exception:  # unbalanced quotes or a scanner limit: no operands
        return [], []
    return [argv for raw, _sep in guard._simple_commands(tokens)
            if (argv := guard._strip_prefixes(raw))], bodies


def _operands(prog: str, args: list[str]) -> list[str]:
    """The paths an rm-like command deletes."""
    if prog in _RM:
        return [op for op in guard._flags(args)[1] if op not in ("<", ">")]
    if prog in _CMD_DEL:
        return [a for a in args if not _CMD_SWITCH.fullmatch(a)]
    out, i = [], 0  # Remove-Item
    while i < len(args):
        a, low = args[i], args[i].lower()
        if low in _PS_PATH and i + 1 < len(args):
            out += args[i + 1].split(",")
            i += 2
        elif low in _PS_VALUE:
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            out += a.split(",")
            i += 1
    return [p for p in out if p]


def _git(args: list[str]) -> tuple[str | None, list[str]]:
    """(reason, deleted paths) of a git command."""
    while args and args[0].startswith("-"):  # git -C dir / -c k=v
        args = args[2:] if args[0] in ("-C", "-c") else args[1:]
    sub, rest = (args[0], args[1:]) if args else ("", [])
    flags, ops = guard._flags(rest)
    if sub == "rm":
        return "git rm", [] if "--cached" in flags else ops
    if sub == "clean" and not ({"n"} & flags or "--dry-run" in flags):
        return "git clean", []
    if sub == "reset" and "--hard" in flags:
        return "git reset --hard", []
    if sub == "push":
        if "f" in flags or "--force" in flags or any(op.startswith("+") for op in ops):
            return "git push --force", []
        if any(f.split("=", 1)[0] == "--force-with-lease" for f in flags):
            return "git push --force-with-lease", []
    return None, []


def _find(args: list[str]) -> str | None:
    """`find ... -delete` or `find ... -exec rm ...` (paths unknown)."""
    for i, a in enumerate(args):
        if a == "-delete":
            return "find -delete"
        if a in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(args) \
                and guard._prog(args[i + 1]) in _RM | _CMD_DEL:
            return "find -exec rm"
    return None


def _xargs(args: list[str]) -> str | None:
    """`xargs [options] rm ...` (paths unknown: they come from stdin)."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if not a.startswith("-") or a == "-":
            break
        # -I {} / -d x / -n 1 ...: a short option with a separate value
        i += 2 if len(a) == 2 and a[1] in guard._XARGS_VALUE else 1
    if i < len(args) and guard._prog(args[i]) in _RM | _CMD_DEL:
        return "xargs rm"
    return None


def _wrapped(prog: str, args: list[str]) -> str | None:
    """The script a shell -c, cmd /c or powershell -Command runs, else None."""
    if guard._is_shell(prog):
        for i, a in enumerate(args[:-1]):
            if re.fullmatch(r"-[a-z]*c[a-z]*", a) or a == "--command":
                return args[i + 1]
        return None
    if prog == "cmd":
        for i, a in enumerate(args):
            if m := re.match(r"/{1,2}[ckr]", a, re.IGNORECASE):
                rest = ([a[m.end():]] if a[m.end():] else []) + args[i + 1:]
                return " ".join(rest) or None
        return None
    if prog in ("powershell", "pwsh"):
        for i, a in enumerate(args):
            o = a.lstrip("-/").lower()
            if a[:1] in "-/" and (o == "c" or (len(o) >= 3 and "command".startswith(o))):
                return " ".join(args[i + 1:]) or None
    return None


def command_effects(command: str, depth: int = 0
                    ) -> tuple[str | None, list[tuple[str, bool]], bool]:
    """(own destructive reason, [(deleted path, a `cd` ran before it)], any
    `cd`) for *command*."""
    reason: str | None = None
    deleted: list[tuple[str, bool]] = []
    cd = False
    argvs, bodies = _simple_commands(command)
    if depth < _MAX_DEPTH:
        for body in dict.fromkeys(bodies):
            r, d, _ = command_effects(body, depth + 1)
            reason = reason or r
            deleted += d
    for argv in argvs:
        prog, args = guard._prog(argv[0]), argv[1:]
        if prog in _CD:
            cd = True
            continue
        if depth < _MAX_DEPTH and (script := _wrapped(prog, args)) is not None:
            # A cd inside `bash -c` does not move this shell; one before it does.
            r, d, _ = command_effects(script, depth + 1)
            reason = reason or r
            deleted += [(p, after or cd) for p, after in d]
            continue
        r, paths = None, []
        if prog in _RM:
            r, paths = "rm", _operands(prog, args)
        elif prog in _CMD_DEL:
            r, paths = "del", _operands(prog, args)
        elif prog in _PS_DEL:
            r, paths = "Remove-Item", _operands(prog, args)
        elif prog == "git":
            r, paths = _git(args)
        elif prog == "find":
            r = _find(args)
        elif prog in guard._XARGS:
            r = _xargs(args)
        reason = reason or r
        deleted += [(p, cd) for p in paths]
    return reason, deleted, cd


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------

def _iso(dt: datetime | None) -> str | None:
    """ISO 8601 with an offset; the parsers' naive timestamps are UTC."""
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def _host(a: Action) -> str:
    host = re.split(r"[/?#\s]", str(a.network_host or ""), maxsplit=1)[0]
    if a.network_port is not None:
        host = f"{host}:{a.network_port}" if host else f":{a.network_port}"
    return one_line(host, TARGET_LIMIT)


def _file_kind(a: Action) -> str | None:
    if a.file_path and re.search(r"delete|remove", a.tool_name, re.IGNORECASE):
        return "delete"
    if a.tool_type == ToolType.WRITE:
        return "write"
    if a.tool_type == ToolType.EDIT:
        return "edit"
    return None


def build(actions: list[Action], agent: str, project: str | None) -> list[dict[str, Any]]:
    """Ledger rows for a whole parsed log (results already merged), in log order."""
    home_re = _home_re()
    rows: list[dict[str, Any]] = []

    def row(a: Action, kind: str, target: str, out: bool | None = None,
            reason: str | None = None, destructive: bool | None = None) -> None:
        rows.append({
            "ts": _iso(a.timestamp), "agent": agent,
            "tool": one_line(a.tool_name, TOOL_LIMIT), "kind": kind, "target": target,
            "success": bool(a.success), "outside_project": out,
            "destructive": reason is not None if destructive is None else destructive,
            "reason": reason,
        })

    for a in actions:
        if not is_tool_call(a):
            continue
        base = a.raw.get("cwd") if isinstance(a.raw, dict) else None
        base = base if isinstance(base, str) and base else project
        if a.command:
            cmd = str(a.command)
            own, deleted, _ = command_effects(cmd)
            reason = _guard_reason(cmd) or own
            # A secrets read is reported (reason kept) but deletes nothing:
            # destructive only if the command also deletes or rewrites.
            # too_long / unchecked: the guard could not read it, not a finding.
            destructive = own is not None or (
                reason is not None and reason not in NOT_DESTRUCTIVE)
            row(a, "command", show(cmd, home_re), None, reason, destructive)
            for path, after_cd in deleted:
                # After a cd only an absolute path is known.
                absolute = path.startswith("/") or _WIN_ABS.match(path) or _HOME_VAR.match(path)
                out = outside(path, project, base) if absolute or not after_cd else None
                row(a, "delete", _show_path(path, home_re), out, own or reason or "rm", True)
        elif (kind := _file_kind(a)) is not None:
            path = str(a.file_path or "")
            reason = "guard: guard_off" if path and guard.is_guard_file(path) else None
            if kind == "delete":
                reason = reason or "delete tool"
            row(a, kind, _show_path(path, home_re), outside(path, project, base), reason)
        if a.network_host or a.network_port is not None:
            row(a, "network", _host(a))
    return rows


def summary(rows: list[dict[str, Any]], project_known: bool) -> dict[str, Any]:
    """Counts only (for `check --json`'s ledger_summary): no targets."""
    by_kind = Counter(r["kind"] for r in rows)
    return {
        "schema": SCHEMA,
        "rows": len(rows),
        "by_kind": {k: by_kind.get(k, 0) for k in KINDS},
        "destructive": sum(r["destructive"] for r in rows),
        "outside_project": sum(r["outside_project"] is True for r in rows),
        "failed": sum(not r["success"] for r in rows),
        "project_known": project_known,
        "reasons": dict(Counter(r["reason"] for r in rows if r["reason"]).most_common()),
    }


def blast_radius_line(s: dict[str, Any]) -> str | None:
    """`check`'s one text line, only when something is destructive or outside."""
    parts = []
    if s["destructive"]:
        parts.append(f"{s['destructive']} destructive")
    if s["outside_project"]:
        parts.append(f"{s['outside_project']} outside the project")
    if not parts:
        return None
    return f"  Blast radius: {', '.join(parts)} (agentwatch ledger lists them)"


def _flagged(r: dict[str, Any]) -> bool:
    return r["destructive"] or r["outside_project"] is True


def render(rows: list[dict[str, Any]], log_name: str, session_id: str | None, agent: str,
           project: str | None, project_from: str | None,
           kinds: Iterable[str] | None = None) -> list[str]:
    """*rows*: every row of the session (the header counts all of them);
    *kinds*: list only rows of these kinds."""
    head = f"Ledger for {one_line(log_name, 200)}"
    if session_id:
        head += f" (session {one_line(session_id, 80)})"
    where = (f"{_show_path(project, _home_re())} (from {project_from})" if project
             else "unknown (outside-project not judged; pass --project)")
    by_kind = Counter(r["kind"] for r in rows)
    counts = ", ".join(f"{by_kind.get(k, 0)} {k}" for k in KINDS)
    s = summary(rows, project is not None)
    lines = [head, "", f"  Agent: {agent}   Project: {where}",
             f"  Rows: {counts}; {s['destructive']} destructive, "
             f"{s['outside_project']} outside the project, {s['failed']} failed"]
    shown = rows
    if kinds:
        kinds = tuple(kinds)
        lines.append(f"  (showing: {','.join(kinds)})")
        shown = [r for r in rows if r["kind"] in kinds]
    flagged = [r for r in shown if _flagged(r)]
    rest = [r for r in shown if not _flagged(r)]
    for title, group in (("Destructive or outside the project", flagged), ("Other", rest)):
        if not group:
            continue
        lines += ["", f"  {title}:"]
        for r in group:
            when = datetime.fromisoformat(r["ts"]).strftime("%H:%M:%S") if r["ts"] else "-"
            status = "ok" if r["success"] else "FAIL"
            marks = ""
            if r["destructive"]:
                marks += f"  [destructive: {r['reason']}]"
            elif r["reason"]:
                marks += f"  [{r['reason']}]"
            if r["outside_project"] is True:
                marks += "  [outside project]"
            lines.append(f"  {when:>8}  {r['kind']:<7}  {r['tool'][:16]:<16}  {status:<4}  "
                         f"{r['target']}{marks}")
    if not rows:
        lines += ["", "  Nothing ran, changed, was deleted or contacted."]
    elif not shown:
        lines += ["", "  No rows of these kinds."]
    return lines


def csv_rows(rows: list[dict[str, Any]]) -> Iterable[list[Any]]:
    """Header plus one list per row; booleans as true/false, null as empty,
    formula-leading text quoted like report.write_csv."""
    from agentwatch.report import csv_cell

    yield list(FIELDS)
    for r in rows:
        yield [csv_cell(str(r[f]).lower() if isinstance(r[f], bool) else r[f]) for f in FIELDS]
