#!/usr/bin/env python3
"""Measure security false alarms over local Claude Code sessions (Sprint 50).

Runs the scan ``agentwatch security-scan --log PATH`` runs (security
registry, ``registry.scan``, ``calculate_security_score``,
``cli._security_exit_code``; no ``--analytics-log``)
over every Claude Code session log under ``claude_config.config_dirs()``
(``$CLAUDE_CONFIG_DIR`` and ``~/.claude``, via the claude-code adapter's
``history_logs()``; subagent logs included unless ``--no-subagents``) and
prints:

- the session exit-code distribution (0 secure / 1 at risk / 2 compromised;
  3 = nothing to scan, ``error`` = unreadable), as ``security-scan`` would exit
- per signal and rule: counts by severity and the number of sessions affected
- with ``--examples N``: up to N one-line evidence samples per signal/rule,
  (the whole text redacted before it is cut, then ``secret_scanner.one_line``)

"Rule" is the detector sub-pattern that fired, found by re-matching the
detector's own pattern list (imported, not copied) against the action the
finding came from; secret_leak uses its secret_type@channel. The scan itself
is never changed by this attribution.

Read-only and local: nothing is written. Evidence comes from real
transcripts, so never paste ``--examples`` output into a commit, issue or PR.

Usage (from the repo root, in a dev venv):
    python scripts/fp_corpus.py [--examples 3] [--json] [--no-subagents] [--jobs N]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low")
EVIDENCE_CHARS = 120

# Signals whose detector reads Action.command.
_COMMAND_SIGNALS = {
    "privilege_escalation", "dangerous_command", "c2_beacon", "dns_exfil",
    "skill_install", "secret_in_command", "data_upload",
}


def _rule_patterns() -> dict[str, list[str]]:
    """signal -> the detector's own sub-pattern list (imported, not copied)."""
    from agentwatch.detectors.security.credentials import SecretInOutputDetector
    from agentwatch.detectors.security.injection import (
        HiddenInstructionDetector,
        PromptInjectionDetector,
    )
    from agentwatch.detectors.security.network import (
        C2CommunicationDetector,
        DNSExfiltrationDetector,
    )
    from agentwatch.detectors.security.privilege import (
        DangerousCommandDetector,
        PrivilegeEscalationDetector,
        SensitiveDirectoryAccessDetector,
    )
    from agentwatch.detectors.security.supply_chain import SkillInstallDetector
    from agentwatch.parser.security_patterns import (
        CREDENTIAL_EXTRA_PATTERNS,
        INJECTION_PATTERNS,
        SENSITIVE_PATHS,
    )

    return {
        "privilege_escalation": list(PrivilegeEscalationDetector.PRIVILEGE_PATTERNS),
        "dangerous_command": list(DangerousCommandDetector.DANGEROUS_PATTERNS),
        "c2_beacon": list(C2CommunicationDetector.BEACON_INDICATORS),
        "dns_exfil": list(DNSExfiltrationDetector.DNS_EXFIL_PATTERNS),
        "skill_install": list(SkillInstallDetector.INSTALL_PATTERNS),
        "secret_in_command": list(SecretInOutputDetector.SECRET_PATTERNS),
        "secret_in_output": list(SecretInOutputDetector.SECRET_PATTERNS),
        "credential_access": SENSITIVE_PATHS + CREDENTIAL_EXTRA_PATTERNS,
        "sensitive_directory": list(SensitiveDirectoryAccessDetector.SENSITIVE_DIRS),
        "hidden_instruction": list(HiddenInstructionDetector.HIDDEN_PATTERNS),
        "prompt_injection/high": list(PromptInjectionDetector.HIGH_CONFIDENCE_PATTERNS),
        "prompt_injection/medium": list(INJECTION_PATTERNS),
    }


_COMPILED: dict[str, list[tuple[str, re.Pattern]]] = {}


def _patterns(key: str) -> list[tuple[str, re.Pattern]]:
    if not _COMPILED:
        for sig, pats in _rule_patterns().items():
            # Same flags as each detector: SENSITIVE_DIRS is case-sensitive.
            flags = 0 if sig == "sensitive_directory" else re.IGNORECASE
            _COMPILED[sig] = [(p, re.compile(p, flags | re.MULTILINE)) for p in pats]
    return _COMPILED.get(key, [])


def _texts(signal: str, action) -> list[str]:
    """The Action fields the detector for *signal* reads."""
    if signal in _COMMAND_SIGNALS:
        return [action.command or ""]
    if signal == "secret_in_output":
        return [action.outgoing_data or ""]
    if signal == "credential_access":
        return [action.file_path or ""]
    if signal == "sensitive_directory":
        return [action.file_path or action.command or ""]
    if signal == "hidden_instruction":
        raw = action.raw.get("content") if isinstance(action.raw, dict) else None
        return [(action.incoming_message or "") + (str(raw) if raw else "")]
    if signal == "prompt_injection":
        return [action.incoming_message or ""]
    return []


_SEGMENT_SPLIT = re.compile(r"\n|;|&&|\|\||\|")


def _segment(text: str, start: int, end: int) -> str:
    """The shell segment(s) text[start:end] spans (split on ; && || | newline)."""
    cuts = [x.end() for x in _SEGMENT_SPLIT.finditer(text)]
    lo = max((c for c in cuts if c <= start), default=0)
    hi = min((c for c in cuts if c > end), default=len(text) + 1)
    return text[lo:hi]


def _evidence(signal: str, text: str, rx: re.Pattern, raw_start: int) -> str:
    """One display line around *rx*'s match in *text*.

    The WHOLE text is redacted before any cut: a window cut first can split a
    secret, drop its prefix (``sk-ant-api03-``) and leave a body the redactor
    no longer recognises. The match is then found again in the redacted text
    (offsets shift); if redaction swallowed it (the match was itself a
    secret), the window sits at the raw offset, clamped. Every cut is of
    redacted text only.
    """
    from agentwatch.detectors.security.secret_scanner import one_line, redact_secrets

    safe = redact_secrets(text)
    m = rx.search(safe)
    start, end = (m.start(), m.end()) if m else (min(raw_start, len(safe)),) * 2
    if signal in _COMMAND_SIGNALS or signal == "sensitive_directory":
        ev = _segment(safe, start, end)
    else:
        ev = safe[max(0, start - 40): end + 40]
    return one_line(ev, EVIDENCE_CHARS)


def _attribute(signal: str, details: dict, actions: list) -> tuple[str, str]:
    """(rule, evidence) for one finding.

    For findings that keep the (truncated, redacted) command, the action is
    the first one whose command starts with it and re-matches (several
    commands can share that prefix, so this is a best guess); for paths, the
    action with that path; otherwise the first action in the session that
    matches. ("?", "") when nothing re-matches. A hidden_instruction found
    only by the HTML-comment keyword check (no pattern re-matches) is
    reported as rule "html_comment_keyword" with NO evidence.
    """
    from agentwatch.detectors.security.secret_scanner import one_line, redact_truncate

    if signal == "secret_leak":
        rule = f"{details.get('secret_type')}@{details.get('channel')}"
        return rule, one_line(details.get("matched_prefix") or "", EVIDENCE_CHARS)
    key = signal
    if signal == "prompt_injection":
        key = f"prompt_injection/{details.get('confidence')}"
    pats = _patterns(key)
    if not pats:
        return "-", ""
    candidates = actions
    shown = details.get("command")
    if signal in _COMMAND_SIGNALS and shown:
        candidates = [
            a for a in actions
            if a.command and redact_truncate(a.command, len(shown)) == shown
        ] or actions
    elif signal == "credential_access" and details.get("path"):
        candidates = [a for a in actions if a.file_path == details["path"]] or actions
    for action in candidates:
        for text in _texts(signal, action):
            if not text:
                continue
            for raw, rx in pats:
                m = rx.search(text)
                if m:
                    return raw, _evidence(signal, text, rx, m.start())
    if signal == "hidden_instruction":
        return "html_comment_keyword", ""
    return "?", ""


def scan_log(path: str, examples: int) -> dict:
    """One session, scanned like `agentwatch security-scan --log PATH` (same
    registry, scan, score and exit code; no --analytics-log is passed)."""
    from agentwatch.cli import EXIT_NO_DATA, _security_exit_code
    from agentwatch.detectors.registry import create_registry
    from agentwatch.health.score import calculate_security_score
    from agentwatch.parser.logs import parse_file
    from agentwatch.parser.models import ActionBuffer

    registry = create_registry(mode="security")
    buffer = ActionBuffer()
    actions: list = []

    def keep(stream):
        for a in stream:
            actions.append(a)
            yield a

    try:
        warnings = registry.scan(keep(parse_file(Path(path))), buffer)
    except Exception as e:  # unreadable/unsupported: counted, never fatal
        return {"exit": "error", "error": type(e).__name__, "findings": []}
    if len(buffer) == 0:
        return {"exit": str(EXIT_NO_DATA), "findings": []}
    findings = []
    for w in warnings:
        try:
            rule, evidence = _attribute(w.signal, w.details or {}, actions)
        except Exception:
            rule, evidence = "?", ""
        findings.append({
            "signal": w.signal,
            "category": w.category.value,
            "severity": w.severity.value,
            "rule": rule,
            "evidence": evidence if examples else "",
        })
    score = calculate_security_score(warnings)
    return {"exit": str(_security_exit_code(score)), "score": score, "findings": findings}


def session_logs(include_subagents: bool) -> list[tuple[Path, bool]]:
    from agentwatch.agents import ADAPTERS

    adapter = next(a for a in ADAPTERS if a.name == "claude-code")
    out = []
    for p in sorted(set(adapter.history_logs())):
        sub = "subagents" in p.parts
        if include_subagents or not sub:
            out.append((p, sub))
    return out


def run(logs: list[tuple[Path, bool]], examples: int, jobs: int | None) -> list[dict]:
    paths = [str(p) for p, _ in logs]
    if len(paths) >= 8 and jobs != 1:
        from concurrent.futures import ProcessPoolExecutor

        with ProcessPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(scan_log, paths, [examples] * len(paths), chunksize=2))
    else:
        results = [scan_log(p, examples) for p in paths]
    for (_, sub), res in zip(logs, results):
        res["subagent"] = sub
    return results


def summarize(results: list[dict], examples: int) -> dict:
    def dist(rows):
        c = Counter(r["exit"] for r in rows)
        return {k: c.get(k, 0) for k in ("0", "1", "2", "3", "error")}

    def worst(rows):
        """Sessions by their worst finding's severity ("none" = no finding)."""
        c = Counter(
            next((k for k in SEVERITIES if any(f["severity"] == k for f in r["findings"])),
                 "none")
            for r in rows if r["exit"] in ("0", "1", "2")
        )
        return {k: c.get(k, 0) for k in (*SEVERITIES, "none")}

    signals: dict[tuple[str, str], dict] = {}
    for idx, res in enumerate(results):
        for f in res["findings"]:
            s = signals.setdefault((f["signal"], f["rule"]), {
                "signal": f["signal"],
                "category": f["category"],
                "rule": f["rule"],
                "severity": Counter(),
                "sessions": set(),
                "examples": [],
            })
            s["severity"][f["severity"]] += 1
            s["sessions"].add(idx)
            ev = f["evidence"]
            if examples and ev and len(s["examples"]) < examples and ev not in s["examples"]:
                s["examples"].append(ev)
    rows = []
    for s in signals.values():
        row = {
            "signal": s["signal"],
            "category": s["category"],
            "rule": s["rule"],
            "severity": {k: s["severity"].get(k, 0) for k in SEVERITIES},
            "total": sum(s["severity"].values()),
            "sessions": len(s["sessions"]),
        }
        if examples:
            row["examples"] = s["examples"]
        rows.append(row)
    rank = {k: i for i, k in enumerate(SEVERITIES)}
    rows.sort(key=lambda r: (
        min((rank[k] for k in SEVERITIES if r["severity"][k]), default=9),
        -r["sessions"], r["signal"], r["rule"],
    ))
    main = [r for r in results if not r["subagent"]]
    return {
        "schema": 1,
        "logs": len(results),
        "main_sessions": len(main),
        "subagent_logs": len(results) - len(main),
        "exit_distribution": {
            "all": dist(results),
            "main": dist(main),
            "subagent": dist([r for r in results if r["subagent"]]),
        },
        "worst_severity": {
            "all": worst(results),
            "main": worst(main),
            "subagent": worst([r for r in results if r["subagent"]]),
        },
        "errors": dict(Counter(r["error"] for r in results if r["exit"] == "error")),
        "signals": rows,
    }


def render(summary: dict) -> str:
    lines = [
        f"Scanned {summary['logs']} logs "
        f"({summary['main_sessions']} sessions, {summary['subagent_logs']} subagent logs)",
        "",
        "Exit codes (0 secure, 1 at risk, 2 compromised, 3 nothing to scan):",
    ]
    for name, d in summary["exit_distribution"].items():
        lines.append(f"  {name:9} " + "  ".join(f"{k}={v}" for k, v in d.items()))
    lines += ["", "Sessions by worst finding severity:"]
    for name, d in summary["worst_severity"].items():
        lines.append(f"  {name:9} " + "  ".join(f"{k}={v}" for k, v in d.items()))
    if summary["errors"]:
        lines.append("  errors: " + ", ".join(f"{k}={v}" for k, v in summary["errors"].items()))
    lines += ["", f"{'signal':22} {'crit':>5} {'high':>5} {'med':>5} {'low':>5} {'sess':>5}  rule"]
    for r in summary["signals"]:
        sv = r["severity"]
        lines.append(
            f"{r['signal']:22} {sv['critical']:5} {sv['high']:5} {sv['medium']:5} "
            f"{sv['low']:5} {r['sessions']:5}  {r['rule']}"
        )
        for ex in r.get("examples", []):
            lines.append(f"{'':24}e.g. {ex}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--examples", type=int, default=0, metavar="N",
                    help="up to N redacted one-line evidence samples per signal/rule")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--no-subagents", action="store_true", help="skip subagent logs")
    ap.add_argument("--jobs", type=int, default=None, help="worker processes (1 = serial)")
    args = ap.parse_args(argv)

    examples = max(args.examples, 0)
    logs = session_logs(include_subagents=not args.no_subagents)
    summary = summarize(run(logs, examples, args.jobs), examples)
    print(json.dumps(summary, indent=2) if args.json else render(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
