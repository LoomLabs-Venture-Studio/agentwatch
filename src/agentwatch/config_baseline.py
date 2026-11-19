"""`agentwatch config-scan --baseline`: pin the skills, plugins and MCP servers
installed now, and report what changed since on later scans.

The baseline (``history.data_dir()/config-baseline.json``, schema 1, 0600)
holds keys and digests only: (agent, kind, scope, name) plus an HMAC-SHA256
under the per-user secret-fingerprint key, never file contents, commands or
env values, so an env secret in an MCP entry cannot be tested offline against
a stored plain hash. Items from the user's own configs sit in "user"; items
from a --path project in "projects"[<project>], so pinning one project never
reports another's items as removed.

Without a baseline file there is no drift check and nothing is written (the
skill-script checks run on every scan, in config_scan.scan).
A malformed or unreadable baseline gives one note and no drift findings.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

from agentwatch.config_scan import Finding, Report, Scanner, show
from agentwatch.detectors.security.secret_scanner import one_line

SCHEMA = 1
FILE_NAME = "config-baseline.json"
MAX_BYTES = 64 * 1024 * 1024
DRIFT_KINDS = ("drift_changed", "drift_added", "drift_removed")
_FIELDS = ("agent", "kind", "scope", "name", "digest")
_LABEL = {"skill": "Skill", "plugin": "Plugin", "mcp_server": "MCP server"}
_SEVERITY = {"drift_changed": "medium", "drift_added": "low", "drift_removed": "low"}
_WHAT = {"drift_changed": "changed since the baseline",
         "drift_added": "is new since the baseline",
         "drift_removed": "was removed since the baseline"}
_WHY = ("Skills, plugins and MCP servers run with your agent's access; one that "
        "changes without you knowing can run new code or send data somewhere new.")
_FIX = {"drift_changed": "Review what changed; if you made the change, run "
                         "`agentwatch config-scan --baseline` to accept it.",
        "drift_added": "Check where it came from; if you added it, run "
                       "`agentwatch config-scan --baseline` to accept it.",
        "drift_removed": "If you didn't remove it, find out what did; otherwise run "
                         "`agentwatch config-scan --baseline` to accept it."}

Key = tuple[str, str, str, str]


class BaselineError(Exception):
    """The baseline could not be read or written; str() is the reason."""


def path() -> Path:
    from agentwatch.history import data_dir

    return data_dir() / FILE_NAME


def exists() -> bool:
    return os.path.lexists(path())


def _section(raw: object) -> dict[Key, str]:
    if not isinstance(raw, dict) or not isinstance(raw.get("created"), str) \
            or not isinstance(raw.get("items"), list):
        raise BaselineError("unexpected format")
    items: dict[Key, str] = {}
    for it in raw["items"]:
        if not isinstance(it, dict) or not all(isinstance(it.get(f), str) for f in _FIELDS):
            raise BaselineError("unexpected format")
        items[(it["agent"], it["kind"], it["scope"], it["name"])] = it["digest"]
    return items


def load() -> dict:
    """The baseline at path(), validated. Raises BaselineError."""
    p = path()
    try:
        st = p.lstat()
        if not stat.S_ISREG(st.st_mode):
            raise BaselineError("not a regular file")
        if os.name == "posix" and st.st_uid != os.getuid():
            raise BaselineError("not owned by you")
        if st.st_size > MAX_BYTES:
            raise BaselineError("too large")
        with open(p, "rb") as fh:
            data = json.loads(fh.read(MAX_BYTES + 1).decode("utf-8"))
    except OSError as exc:
        raise BaselineError(exc.strerror or "unreadable") from None
    except (ValueError, UnicodeDecodeError):
        raise BaselineError("not valid JSON") from None
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise BaselineError("unknown schema")
    projects = data.get("projects", {})
    if not isinstance(projects, dict):
        raise BaselineError("unexpected format")
    _section(data.get("user"))
    for sec in projects.values():
        _section(sec)
    return data


def _items_json(items: dict[Key, str]) -> list[dict]:
    return [dict(zip(_FIELDS, (*k, d), strict=True)) for k, d in sorted(items.items())]


def _split(scanner: Scanner) -> tuple[dict[Key, str], dict[Key, str]]:
    user: dict[Key, str] = {}
    proj: dict[Key, str] = {}
    for k, (section, digest) in scanner.items.items():
        (proj if section == "project" else user)[k] = digest
    return user, proj


def _project_key(scanner: Scanner) -> str | None:
    """The projects key of a --path project; None when it is the home dir."""
    return None if scanner.project == scanner.home else show(scanner.project)


def save(scanner: Scanner) -> dict:
    """Pin *scanner*'s items: replace the user section and this project's,
    keep other projects'. Returns the report's baseline info. Raises
    BaselineError."""
    from agentwatch.coach import _private_dir
    from agentwatch.detectors.security.secret_scanner import _atomic_write_bytes

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    user, proj = _split(scanner)
    try:
        projects = load().get("projects", {}) if exists() else {}
    except BaselineError:
        projects = {}  # replaced by this pin
    data = {"schema": SCHEMA, "user": {"created": now, "items": _items_json(user)},
            "projects": dict(projects)}
    pk = _project_key(scanner)
    if pk is not None:
        data["projects"][pk] = {"created": now, "items": _items_json(proj)}
    p = path()
    try:
        if not _private_dir(p.parent):
            raise BaselineError(f"{show(p.parent)} is not owned by you")
        _atomic_write_bytes(p, (json.dumps(data, indent=1, sort_keys=True) + "\n").encode(),
                            0o600)
    except OSError as exc:
        raise BaselineError(exc.strerror or str(exc)) from None
    return {"created": now, "items": len(user) + (len(proj) if pk is not None else 0),
            "pinned": True}


def when(created: str) -> str:
    return created.replace("T", " ").removesuffix("Z")[:16] + " UTC"


def compare(scanner: Scanner, data: dict) -> tuple[list[Finding], dict]:
    """Drift findings of *scanner*'s items against the baseline *data*, and
    the report's baseline info {created, items}."""
    user, proj = _split(scanner)
    pairs = [(_section(data["user"]), user, data["user"]["created"])]
    pk = _project_key(scanner)
    projects = data.get("projects", {})
    if pk is not None and pk in projects:
        pairs.append((_section(projects[pk]), proj, projects[pk]["created"]))
    created = min(c for _, _, c in pairs)
    findings: list[Finding] = []
    for old, new, since in pairs:
        for key in sorted(old.keys() | new.keys()):
            if key in old and key in new:
                if old[key] == new[key]:
                    continue
                kind = "drift_changed"
            else:
                kind = "drift_added" if key in new else "drift_removed"
            agent, item_kind, scope, name = key
            label = _LABEL.get(item_kind, item_kind)
            file = f"{scope}/{name}" if item_kind == "skill" else scope
            findings.append(Finding(
                _SEVERITY[kind], kind, agent, file, name,
                f'{label} "{one_line(name, 80)}" {_WHAT[kind]} ({when(since)})',
                _WHY, _FIX[kind]))
    return findings, {"created": created, "items": sum(len(o) for o, _, _ in pairs)}


def run(project: Path, pin: bool) -> tuple[Report, str | None]:
    """config-scan with drift pinning: (report, note for stderr or None).

    pin: write a new baseline (the accept action). Otherwise, with no
    baseline file, the plain scan (skill-script checks included, nothing
    written); with one, the scan plus drift findings."""
    from agentwatch.config_scan import scan
    from agentwatch.detectors.security.secret_scanner import fingerprint_key

    if pin:
        key = fingerprint_key(create=True)
        if key is None:
            raise BaselineError("the fingerprint key could not be read or created")
        scanner = Scanner(project, key=key, scripts=True)
        report = scanner.run()
        report.baseline = save(scanner)
        return report, None
    if not exists():
        return scan(project), None
    note = None
    try:
        data = load()
        key = fingerprint_key(create=False)
        if key is None:
            raise BaselineError("the fingerprint key it was made with is missing")
    except BaselineError as exc:
        data, key = None, None
        note = (f"agentwatch: config baseline {show(path())} not used ({exc}); no drift "
                "check. Run `agentwatch config-scan --baseline` to pin again.")
    scanner = Scanner(project, key=key, scripts=True)
    report = scanner.run()
    if data is not None:
        findings, report.baseline = compare(scanner, data)
        report.findings.extend(findings)
    return report, note
