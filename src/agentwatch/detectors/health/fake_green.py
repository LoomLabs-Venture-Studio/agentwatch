"""Fake green: tests skipped, weakened or deleted instead of the code fixed.

Reads the text of an edit (old/new strings, a V4A patch, a Cline
SEARCH/REPLACE diff) where the parser keeps it in ``Action.raw``, plus Bash
commands. Precision over recall: only test files count (fixtures, snapshots
and golden files never do), a skip with a platform/env condition is ignored,
a test deleted in one place and re-added in another (same name) is a move,
and assertions moved into a helper keep the window's count level.

Severity: HIGH when the last test run before the change failed, otherwise
MEDIUM (a new skip, ``.only`` or config exclusion) or LOW (removed
assertions, deleted tests or files, test-command flags).
"""

from __future__ import annotations

import json
import re
import shlex
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..base import Category, Detector, Severity, Warning
from ..security.secret_scanner import one_line

if TYPE_CHECKING:
    from agentwatch.parser.models import Action, ActionBuffer

# --- paths -----------------------------------------------------------------

_TEST_PATH = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec)/"
    r"|(?:^|/)test_[^/]*\.py$|_test\.(?:py|go)$"
    r"|\.(?:test|spec)\.[cm]?[jt]sx?$|_spec\.rb$"
    r"|(?:^|/)src/test/|Tests?\.(?:java|kt|cs)$",
    re.IGNORECASE,
)
_NOT_TEST = re.compile(
    r"(?:^|/)(?:fixtures?|__snapshots__|snapshots?|testdata|golden|goldens|__pycache__"
    r"|\.pytest_cache|node_modules|\.cache|coverage|htmlcov)(?:/|$)"
    r"|\.(?:snap|golden|pyc)$|(?:^|/)tmp/|(?:^|/)temp/",
    re.IGNORECASE,
)
_CONFIG_NAMES = frozenset({
    "pyproject.toml", "pytest.ini", "setup.cfg", "tox.ini", "conftest.py", "package.json",
})
_CONFIG_PREFIXES = ("jest.config.", "vitest.config.")
_CONFIG_EXCLUDE = re.compile(
    r"testPathIgnorePatterns|collect_ignore|addopts.*(?:--ignore|--deselect|-k\s)"
)


def _norm(path: str) -> str:
    return path.replace("\\", "/")


def is_test_path(path: str | None) -> bool:
    """A test source file: not a fixture, snapshot, cache or temp file."""
    if not path:
        return False
    p = _norm(path)
    return bool(_TEST_PATH.search(p)) and not _NOT_TEST.search(p)


def _is_config(path: str) -> bool:
    name = _norm(path).rsplit("/", 1)[-1]
    return name in _CONFIG_NAMES or name.startswith(_CONFIG_PREFIXES)


def _short(path: str) -> str:
    """Last two path parts: enough to name the file, no home dir in messages."""
    return "/".join(_norm(path).rstrip("/").split("/")[-2:])


# --- line patterns -------------------------------------------------------------

_SKIP = re.compile(
    r"@pytest\.mark\.(?:skipif|skip|xfail)\b|\bpytest\.(?:skip|xfail)\s*\("
    r"|@unittest\.(?:skip\w*|expectedFailure)\b|\bself\.skipTest\s*\("
    r"|\b(?:it|test|describe|context|suite)\.skip\s*\(|\bx(?:it|describe|test)\s*\("
    r"|\bt\.Skip(?:f|Now)?\s*\(|@Disabled\b|@Ignore\b|#\[ignore\b"
)
_ONLY = re.compile(r"\b(?:it|test|describe|context)\.only\s*\(|\bf(?:it|describe)\s*\(")
# A skip that depends on the platform or environment is a legitimate skip.
_CONDITIONAL = re.compile(
    r"skipif|skipUnless|skip_if|importorskip|sys\.platform|platform\.|os\.name|os\.environ"
    r"|getenv|sys\.version|runtime\.GOOS|testing\.Short|process\.platform|process\.env"
    r"|shutil\.which|cfg_attr|@(?:En|Dis)abled(?:On|If)"
)
_ALWAYS = re.compile(r"skipif\(\s*(?:True|1)\b")  # skipif(True, ...) is not conditional
_IF_LINE = re.compile(r"^\s*(?:if|else if|elif)\b")
_COMMENT = re.compile(r"^\s*(?:#|//|/\*|\*)")
_ASSERT = re.compile(
    r"^\s*assert\b|\bassert\w*!?\s*\(|\bexpect\s*\(|\b(?:assert|require)\.\w+\s*\("
    r"|\bt\.(?:Error|Fatal)f?\s*\(|\bXCTAssert\w*\s*\("
)
_TRIVIAL = re.compile(
    r"^\s*assert\s*\(?\s*(?:True|1)\s*\)?\s*(?:,.*)?$|assertTrue\(\s*(?:True|1)\s*\)"
    r"|expect\(\s*(?:true|1)\s*\)\.to(?:Be|Equal|BeTruthy)\(\s*(?:true|1)?\s*\)"
    r"|assert\.True\(\s*t\s*,\s*true\s*\)|assert!\(\s*true\s*\)"
)
_TEST_DEF = re.compile(
    r"^\s*(?:async\s+)?def\s+(test\w*)\s*\(|^\s*(?:it|test)\s*\(\s*(['\"`])(.+?)\2"
    r"|^func\s+(Test\w+)\s*\("
)


def _def_names(lines) -> list[str]:
    names = []
    for line in lines:
        m = _TEST_DEF.match(line)
        if m:
            names.append(m[1] or m[3] or m[4])
    return names


def _skips(lines: list[str], marker: re.Pattern) -> list[str]:
    """Unconditional skip (or .only) markers in *lines*, as their match text."""
    found = []
    for i, line in enumerate(lines):
        if _COMMENT.match(line):
            continue
        m = marker.search(line)
        if not m:
            continue
        conditional = _CONDITIONAL.search(line) and not _ALWAYS.search(line)
        if conditional or (i and _IF_LINE.match(lines[i - 1])):
            continue
        found.append(m[0].rstrip("( ").strip())
    return found


def _assert_counts(lines) -> tuple[int, int, int]:
    """(real assertions, trivial assertions, commented-out assertions)."""
    real = trivial = commented = 0
    for line in lines:
        if _COMMENT.match(line):
            commented += bool(_ASSERT.search(_COMMENT.sub("", line, count=1)))
        elif _TRIVIAL.search(line):
            trivial += 1
        elif _ASSERT.search(line):
            real += 1
    return real, trivial, commented


# --- edits ---------------------------------------------------------------------

@dataclass
class _Change:
    path: str
    kind: str  # "edit" | "write" (whole new content) | "delete"
    removed: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    new_text: str = ""


def _diff(path: str, old: str, new: str) -> _Change:
    """Lines only in *old* / only in *new* (multiset): context and moved lines cancel."""
    o, n = Counter(old.splitlines()), Counter(new.splitlines())
    return _Change(path, "edit", list((o - n).elements()), list((n - o).elements()), new)


_PATCH_HEAD = re.compile(r"^\*\*\* (Update|Add|Delete) File: (.+?)\s*$")


def _patch_changes(text: str) -> list[_Change]:
    """V4A patch (Codex apply_patch, OpenCode/Cline apply_patch)."""
    out: list[_Change] = []
    cur: list | None = None  # [kind, path, minus lines, plus lines]
    files: list[list] = []
    for line in text.splitlines():
        m = _PATCH_HEAD.match(line)
        if m:
            cur = [m[1], m[2], [], []]
            files.append(cur)
        elif line.startswith("***"):
            continue
        elif cur is not None and line.startswith("-"):
            cur[2].append(line[1:])
        elif cur is not None and line.startswith("+"):
            cur[3].append(line[1:])
    for kind, path, minus, plus in files:
        if kind == "Delete":
            out.append(_Change(path, "delete"))
        elif kind == "Add":
            out.append(_Change(path, "write"))
        else:
            out.append(_diff(path, "\n".join(minus), "\n".join(plus)))
    return out


_SEARCH_REPLACE = re.compile(
    r"^[-<]{3,} SEARCH>?[ \t]*\n(.*?)^={3,}[ \t]*\n(.*?)^[+>]{3,} REPLACE", re.M | re.S
)
_OLD_NEW = (
    ("old_string", "new_string"), ("old_str", "new_str"),
    ("oldString", "newString"), ("old_text", "new_text"),
)
_PATH_KEYS = ("file_path", "path", "filePath", "absolutePath")


def _args(action: "Action") -> dict:
    """The tool's input as the agent sent it, wherever the parser kept it."""
    raw = action.raw if isinstance(action.raw, dict) else {}
    if raw.get("type") == "tool_use":  # Claude Code, Cline
        args = raw.get("input")
    elif isinstance(raw.get("data"), dict):  # Copilot CLI tool.execution_start
        args = raw["data"].get("arguments")
    elif "args" in raw:  # Gemini CLI
        args = raw["args"]
    elif isinstance(raw.get("state"), dict):  # OpenCode / Kilo
        args = raw["state"].get("input")
    elif isinstance(raw.get("payload"), dict):  # Codex
        payload = raw["payload"]
        args = payload.get("arguments")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {"input": args}
        if not isinstance(args, dict) and isinstance(payload.get("input"), str):
            args = {"input": payload["input"]}  # custom_tool_call
    else:
        args = None
    return args if isinstance(args, dict) else {}


def _edit_changes(action: "Action") -> list[_Change]:
    args = _args(action)
    texts = [v for v in args.values() if isinstance(v, str)] + [action.command or ""]
    patch = next((t for t in texts if "*** Begin Patch" in t), None)
    if patch is not None:
        return _patch_changes(patch)
    if not action.is_file_edit:
        return []
    path = next((args[k] for k in _PATH_KEYS if isinstance(args.get(k), str)), None)
    path = path or action.file_path
    if not path:
        return []
    if isinstance(args.get("edits"), list):  # MultiEdit
        pairs = [(e.get("old_string"), e.get("new_string"))
                 for e in args["edits"] if isinstance(e, dict)]
        old = "\n".join(o for o, _ in pairs if isinstance(o, str))
        new = "\n".join(n for _, n in pairs if isinstance(n, str))
        return [_diff(path, old, new)]
    for old_key, new_key in _OLD_NEW:
        if isinstance(args.get(old_key), str) and isinstance(args.get(new_key), str):
            return [_diff(path, args[old_key], args[new_key])]
    if isinstance(args.get("diff"), str):  # Cline replace_in_file
        blocks = _SEARCH_REPLACE.findall(args["diff"])
        if blocks:
            return [_diff(path, "\n".join(o for o, _ in blocks), "\n".join(n for _, n in blocks))]
    for key in ("content", "file_text"):
        if isinstance(args.get(key), str):
            kind = "write" if args[key].strip() else "delete"
            return [_Change(path, kind)]
    return []


# --- commands ------------------------------------------------------------------

_SEGMENT_SPLIT = re.compile(r"&&|\|\||[;|\n]")
_PREFIX = re.compile(
    r"^(?:['\"(]\s*|(?:ba|z)?sh\s+-l?c\s+|\w+=\S*\s+"
    r"|(?:uv|poetry|pdm|hatch|pipenv|rye)\s+run\s+|npx\s+|bunx\s+|pnpm\s+exec\s+|time\s+|timeout\s+\S+\s+|sudo\s+)+"
)
_RUNNER = re.compile(
    r"^(?:pytest|py\.test|python\d*(?:\.\d+)?\s+-m\s+(?:pytest|unittest)|jest|vitest|mocha"
    r"|go\s+test|cargo\s+(?:test|nextest)|(?:npm|yarn|pnpm|bun)\s+(?:run\s+)?test"
    r"|rspec|phpunit|dotnet\s+test|mvn\s+test|gradlew?\s+test|\./gradlew\s+test|tox|nox"
    r"|make\s+test|ctest)\b"
)
_HIDE_FLAGS = (
    (re.compile(r"--deselect\b"), "--deselect"),
    (re.compile(r"\s-k\s*=?\s*['\"]?\s*not\b"), '-k "not ..."'),
    (re.compile(r"--passWithNoTests\b"), "--passWithNoTests"),
    (re.compile(r"\s-skip[\s=]"), "-skip"),
    (re.compile(r"\s--skip[\s=]"), "--skip"),
)
_IGNORE_RESULT = re.compile(r"\|\|\s*(?:true|:|exit\s+0)\b")
_FAIL_OUTPUT = re.compile(
    r"\b[1-9]\d* (?:failed|failing|errors?)\b|^FAILED\b|^FAIL\b|--- FAIL|test result: FAILED"
    r"|Tests:\s+[1-9]\d* failed",
    re.M,
)
_RM = re.compile(r"^(?:rm|unlink|del|erase|Remove-Item|ri|git\s+rm)\b")


def _runner(command: str) -> bool:
    return any(
        _RUNNER.match(_PREFIX.sub("", seg.strip()))
        for seg in _SEGMENT_SPLIT.split(command)
    )


def _rm_targets(command: str) -> list[str]:
    targets = []
    for seg in re.split(r"&&|\|\||[;\n]", command):
        seg = seg.strip()
        if not _RM.match(seg):
            continue
        try:
            words = shlex.split(seg, posix=True)
        except ValueError:
            words = seg.split()
        targets += [w for w in words[1:] if not w.startswith("-") and w != "rm"]
    return targets


def _output(action: "Action") -> str:
    text = action.incoming_message or action.error_message or action.raw.get("content")
    return text[-4000:] if isinstance(text, str) else ""


# --- detector --------------------------------------------------------------------

@dataclass
class _Info:
    """What an action's input says, cached: it never changes after parsing."""
    test_run: bool = False
    hide: list[str] = field(default_factory=list)  # test-command flags
    changes: list[_Change] = field(default_factory=list)
    rm: list[str] = field(default_factory=list)


@dataclass
class _Finding:
    severity: Severity
    index: int
    action: "Action"
    what: str
    file: str | None = None
    command: str | None = None
    evidence: str | None = None
    after_failure: bool = False


_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


class FakeGreenDetector(Detector):
    """Tests skipped, weakened or deleted instead of the code being fixed."""

    category = Category.PROGRESS
    name = "test_tampering"
    description = "Tests skipped, weakened or deleted instead of fixed"

    def __init__(self, window: int = 100):
        self.window = window
        self._cache: dict[int, tuple["Action", _Info]] = {}

    def _info(self, action: "Action") -> _Info:
        hit = self._cache.get(id(action))
        if hit is not None and hit[0] is action:
            return hit[1]
        info = _Info()
        cmd = action.command if isinstance(action.command, str) else ""
        if action.is_bash and cmd:
            info.test_run = _runner(cmd)
            if info.test_run:
                info.hide = [label for rx, label in _HIDE_FLAGS if rx.search(cmd)]
                if _IGNORE_RESULT.search(cmd):
                    info.hide.append("|| true")
            info.rm = [t for t in _rm_targets(cmd) if is_test_path(t)]
        info.changes = _edit_changes(action)
        self._cache[id(action)] = (action, info)
        return info

    def check(self, buffer: "ActionBuffer") -> Warning | None:
        recent = buffer.last(self.window, activity=True)
        infos = [self._info(a) for a in recent]
        live = {id(a) for a in recent}
        self._cache = {k: v for k, v in self._cache.items() if k in live}

        # Window-wide context: tests re-added anywhere (moves), files the agent
        # wrote whole (its own scratch tests), assertion balance (helpers).
        added_defs: set[str] = set()
        written: set[str] = set()
        assert_net = 0
        for action, info in zip(recent, infos):
            if not action.success:
                continue
            for c in info.changes:
                if c.kind == "write":
                    written.add(_norm(c.path).rsplit("/", 1)[-1])
                if is_test_path(c.path) and c.kind == "edit":
                    added_defs.update(_def_names(c.added))
                    assert_net += _assert_counts(c.added)[0] - _assert_counts(c.removed)[0]

        findings: list[_Finding] = []
        passes: list[int] = []  # indexes of passing test runs
        last_run_failed = False
        for i, (action, info) in enumerate(zip(recent, infos)):
            if info.test_run:
                for flag in info.hide:
                    hard = flag == "|| true"
                    sev = (Severity.HIGH if hard else Severity.MEDIUM) if last_run_failed \
                        else Severity.LOW
                    what = ("ignored the test result (|| true)" if hard
                            else f"ran tests with {flag}")
                    findings.append(_Finding(sev, i, action, what, command=action.command,
                                             after_failure=last_run_failed))
                failed = not action.success or bool(_FAIL_OUTPUT.search(_output(action)))
                if failed:
                    last_run_failed = True
                elif not info.hide:
                    last_run_failed = False
                    passes.append(i)
                continue
            if not action.success:
                continue
            for path in info.rm:
                if _norm(path).rstrip("/").rsplit("/", 1)[-1] in written:
                    continue
                findings.append(self._edit_finding(
                    i, action, path, "deleted the test file", None, last_run_failed, strong=False
                ))
            for c in info.changes:
                f = self._change_finding(i, action, c, added_defs, written, assert_net,
                                         last_run_failed)
                if f is not None:
                    findings.append(f)

        if not findings:
            return None
        worst = max(findings, key=lambda f: (_RANK[f.severity], f.index))
        then_passed = any(p > worst.index for p in passes)
        target = _short(worst.file) if worst.file else one_line(worst.command or "", 80)
        lead = ("Tests weakened after a failing run" if worst.after_failure
                else "Tests weakened")
        message = f"{lead}: {target} — {worst.what}"
        if worst.after_failure and then_passed:
            message += " (then tests passed)"
        details: dict = {
            "change": worst.what,
            "after_failing_run": worst.after_failure,
            "then_passed": then_passed,
            "findings": len(findings),
        }
        if worst.file:
            details["file_path"] = worst.file
        if worst.command:
            details["last_command"] = one_line(worst.command, 200)
        if worst.evidence:
            details["evidence"] = one_line(worst.evidence, 120)
        return Warning(
            category=self.category,
            severity=worst.severity,
            signal=self.name,
            message=message,
            suggestion=(
                "Restore the test and fix the code it checks. Skip or delete a test "
                "only if it is really wrong, and say so."
            ),
            details=details,
        ).with_cost([worst.action], buffer)

    @staticmethod
    def _edit_finding(i, action, path, what, evidence, after_failure, strong) -> _Finding:
        if after_failure:
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM if strong else Severity.LOW
        return _Finding(sev, i, action, what, file=path, evidence=evidence,
                        after_failure=after_failure)

    def _change_finding(self, i, action, c: _Change, added_defs, written, assert_net,
                        after_failure) -> _Finding | None:
        if c.kind == "delete":
            if not is_test_path(c.path) or _norm(c.path).rsplit("/", 1)[-1] in written:
                return None
            return self._edit_finding(i, action, c.path, "deleted the test file", None,
                                      after_failure, strong=False)
        if c.kind != "edit":
            return None
        if _is_config(c.path) and not is_test_path(c.path):
            new = [line for line in c.added if _CONFIG_EXCLUDE.search(line)]
            old = [line for line in c.removed if _CONFIG_EXCLUDE.search(line)]
            if len(new) > len(old):
                m = _CONFIG_EXCLUDE.search(new[0])
                return self._edit_finding(i, action, c.path,
                                          f"excluded tests in config ({m[0].split()[0]})",
                                          new[0], after_failure, strong=True)
            return None
        if not is_test_path(c.path):
            return None

        skips_new, skips_old = _skips(c.added, _SKIP), _skips(c.removed, _SKIP)
        if len(skips_new) > len(skips_old):
            marker = skips_new[0]
            names = _def_names(c.new_text.splitlines())
            what = f"added {marker}" + (f" to {names[0]}" if names else "")
            return self._edit_finding(i, action, c.path, what, marker, after_failure, strong=True)
        only_new, only_old = _skips(c.added, _ONLY), _skips(c.removed, _ONLY)
        if len(only_new) > len(only_old):
            return self._edit_finding(i, action, c.path, f"focused tests with {only_new[0]}",
                                      only_new[0], after_failure, strong=True)

        removed_defs = _def_names(c.removed)
        gone = [n for n in removed_defs if n not in added_defs]
        if gone and len(removed_defs) > len(_def_names(c.added)):
            what = (f"deleted {gone[0]}" if len(gone) == 1
                    else f"deleted {len(gone)} tests ({', '.join(gone[:3])})")
            return self._edit_finding(i, action, c.path, what, None, after_failure, strong=False)

        real_old, _, _ = _assert_counts(c.removed)
        real_new, trivial_new, commented_new = _assert_counts(c.added)
        lost = real_old - real_new
        if lost > 0 and assert_net < 0:
            if trivial_new:
                what = "replaced an assertion with a trivial one"
                evidence = next(line for line in c.added if _TRIVIAL.search(line)).strip()
            elif commented_new:
                what = f"commented out {_plural(min(lost, commented_new), 'assertion')}"
                evidence = None
            else:
                what = f"removed {_plural(lost, 'assertion')}"
                evidence = None
            return self._edit_finding(i, action, c.path, what, evidence, after_failure,
                                      strong=False)
        return None
