"""Command-line interface for agentwatch."""

from __future__ import annotations

import json
import math
import sqlite3
import sys
from pathlib import Path

import click

from agentwatch import __version__
from agentwatch.detectors import create_registry
from agentwatch.detectors.base import Warning, format_tokens, format_usd
from agentwatch.detectors.base import waste_summary as _waste
from agentwatch.discovery import (
    AgentProcess,
    build_agent_tree,
    build_teams,
    find_running_agents,
)
from agentwatch.health import calculate_health, calculate_security_score
from agentwatch.health.score import calculate_efficiency
from agentwatch.llm import (
    DEFAULT_OLLAMA_MODEL,
    MAX_WARNINGS_TO_ASSESS,
    GoalAlignmentAssessment,
    LlmUnavailableError,
    OllamaAnalyzer,
)
from agentwatch.parser import ActionBuffer, find_latest_session, parse_file
from agentwatch.parser.logs import (
    LogUnreadableError,
    UnsupportedLogFormatError,
    ensure_supported_log,
)
from agentwatch.siem import SiemExportError, SiemLogger
from agentwatch.themes import (
    SECURITY_TIER_EXIT_CODES,
    ascii_safe,
    get_theme,
    list_themes,
    security_label_from_score,
    security_status_from_score,
    security_tier_from_score,
    set_theme,
)

# Every --log/--analytics-log names one file: a directory is a clean usage
# error here, not an IsADirectoryError traceback from the parser.
_LOG_FILE = click.Path(exists=True, dir_okay=False, path_type=Path)
# --siem-log/--audit-log are appended to and may not exist yet; same rule.
_OUT_FILE = click.Path(dir_okay=False, path_type=Path)


def _export_siem_log(
    siem_log: Path,
    warnings: list[Warning],
    buffer: ActionBuffer,
    *,
    report_type: str,
    score: float,
) -> None:
    """Append *warnings* + a run summary to *siem_log* as JSON-lines.

    Exits the process with a clear error if the `siem` extra isn't
    installed, rather than silently skipping export the caller explicitly
    asked for.
    """
    session_id = buffer.actions[0].session_id if buffer.actions else None
    security_stats = {
        "credential_accesses": buffer.stats.credential_accesses,
        "privilege_commands": buffer.stats.privilege_commands,
        "network_connections": buffer.stats.network_connections,
        "injection_attempts": buffer.stats.injection_attempts,
    }
    try:
        with SiemLogger(siem_log, session_id=session_id) as siem:
            for warning in warnings:
                siem.log_warning(warning)
            siem.log_report_summary(
                report_type, score, len(warnings), security_stats=security_stats
            )
    except SiemExportError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


def _export_audit_log(path: Path, audit_entries: list[dict], buffer: ActionBuffer) -> None:
    """Append one JSON-line per security detector's `check_with_audit()`
    entry to *path* -- a "prove you checked" compliance trail covering
    every detector that ran this scan, whether it triggered a `Warning` or
    not. Deliberately distinct from `--siem-log`, which only ever records
    positive findings; this is a full accounting of what was checked.

    Opens in append mode (like `SiemLogger`) so repeated runs against the
    same path accumulate rather than clobber each other.
    """
    session_id = buffer.actions[0].session_id if buffer.actions else None
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for entry in audit_entries:
            record = dict(entry)
            record["session_id"] = session_id
            f.write(json.dumps(record) + "\n")


def _run_llm_assessment(warnings: list[Warning], llm_model: str) -> OllamaAnalyzer | None:
    """Best-effort Tier-2 triage of up to the first `MAX_WARNINGS_TO_ASSESS`
    *warnings*, mutating `warning.details["llm_assessment"]` in place.

    Deliberately never raises out to the caller: Tier 2 being unavailable
    (Ollama not running, model not pulled) or a single assessment call
    failing must never fail the surrounding `check`/`security-scan` run --
    it degrades to a printed warning and Tier-1-only results, matching this
    feature's "opt-in enrichment, not a dependency" design (see
    `llm.py`'s module docstring).

    Returns the constructed, already-`check_available()`-gated
    `OllamaAnalyzer` on success (or `None` if Tier 2 is unavailable) so
    callers can reuse the same instance for other Tier-2 calls -- e.g.
    goal-alignment assessment -- without re-checking availability.
    """
    try:
        analyzer = OllamaAnalyzer(model=llm_model)
        analyzer.check_available()
    except LlmUnavailableError as exc:
        click.echo(f"  (Tier-2 LLM analysis skipped: {exc})", err=True)
        return None

    assessed = 0
    for warning in warnings:
        if assessed >= MAX_WARNINGS_TO_ASSESS:
            break
        try:
            assessment = analyzer.assess_warning(warning)
        except Exception as exc:
            click.echo(f"  (Tier-2 LLM assessment failed for one warning: {exc})", err=True)
            continue
        warning.details["llm_assessment"] = assessment.to_dict()
        assessed += 1

    return analyzer


def _run_goal_alignment(
    analyzer: OllamaAnalyzer, buffer: ActionBuffer
) -> GoalAlignmentAssessment | None:
    """Best-effort Tier-2 goal-alignment advisory for *buffer*, called once
    per scan (not once per warning). Reuses an already-`check_available()`-
    gated *analyzer* (from `_run_llm_assessment`) rather than re-checking
    Ollama availability a second time.

    Like `_run_llm_assessment`, a failed call here must never fail the
    surrounding `check`/`security-scan` run -- it degrades to no advisory
    output. Returns `None` both when the assessment call itself fails and
    when `assess_goal_alignment()` honestly reports "nothing to assess"
    (no stated task found -- see `llm.py`'s docstring); `_print_goal_
    alignment` treats both the same way: print nothing.
    """
    try:
        return analyzer.assess_goal_alignment(buffer)
    except Exception as exc:
        click.echo(f"  (Tier-2 goal-alignment assessment failed: {exc})", err=True)
        return None


def _print_llm_assessments(warnings: list[Warning]) -> None:
    """Print a dedicated section for any warnings carrying a Tier-2
    `llm_assessment` (set by `_run_llm_assessment`)."""
    assessed = [w for w in warnings if "llm_assessment" in w.details]
    if not assessed:
        return

    click.echo()
    click.echo(click.style("  TIER-2 LLM ASSESSMENT (local Ollama, advisory only)", bold=True))
    click.echo("  " + "-" * 48)
    for w in assessed:
        verdict = w.details["llm_assessment"]
        ltp = verdict["likely_true_positive"]
        verdict_label = (
            "likely real" if ltp is True else "likely false positive" if ltp is False else "unclear"
        )
        click.echo(f"  [{w.signal}] {verdict_label} ({verdict['confidence']} confidence)")
        if verdict["rationale"]:
            click.echo(f"      {verdict['rationale']}")
    click.echo()


def _print_goal_alignment(assessment: GoalAlignmentAssessment | None) -> None:
    """Print the Tier-2 goal-alignment advisory block, if any.

    Prints nothing when *assessment* is `None` -- covers both
    `assess_goal_alignment()`'s own "no stated task found in this buffer"
    short-circuit (the documented Codex-session case) and
    `_run_goal_alignment`'s failure catch alike; neither is an error worth
    a placeholder line, matching how a Codex session simply never gets this
    section at all.

    ASCII-only, plain bracketed labels by design -- this deliberately does
    not route through `themes.py`. Wiring every new status concept into the
    theme system has its own multi-sprint history in this repo (see
    PLAYBOOK.md Task #8/#9); a two-state advisory label isn't worth
    repeating that here.
    """
    if assessment is None:
        return

    if assessment.aligned is True:
        label = "[ALIGNED]"
    elif assessment.aligned is False:
        label = "[POSSIBLE DRIFT]"
    else:
        label = "[UNCLEAR]"

    summary = assessment.drift_summary or "(model response could not be parsed)"

    click.echo()
    click.echo(click.style("  TIER-2 GOAL ALIGNMENT (advisory, not scored)", bold=True))
    click.echo("  " + "-" * 48)
    click.echo(f"  {label} {summary}")
    click.echo()


def _default_log() -> tuple[Path | None, str | None]:
    """Pick a log when --log is omitted (#47).

    Prefers the newest Claude Code session for the current directory. If
    there is none, falls back to the newest session anywhere and returns a
    note naming that project, so reports can say so.
    """
    from agentwatch.cc_stats import CLAUDE_PROJECTS_DIR, cwd_to_project_dir

    project_dir = cwd_to_project_dir()
    log = find_latest_session(project_dir) if project_dir else None
    if log is not None:
        return log, None
    log = find_latest_session()
    if log is None:
        return None, None
    try:
        project = log.relative_to(CLAUDE_PROJECTS_DIR).parts[0]
    except ValueError:
        project = str(log.parent)
    return log, f"No session for {Path.cwd()}; using newest session from {project}"


def _waste_line(waste: dict) -> str:
    """'Waste: ~$X on N findings (Y% of session cost)'; tokens when unpriced."""
    def pct(part: float, whole: float) -> str:
        share = part / whole * 100
        return "<1%" if share < 0.5 else f"{share:.0f}%"

    n = waste["findings"]
    cost, session_cost = waste["cost_usd"], waste["session_cost_usd"]
    if cost is not None:
        amount = format_usd(cost)
        share = f" ({pct(cost, session_cost)} of session cost)" if session_cost else ""
    else:
        amount = f"{format_tokens(waste['tokens'])} tok"
        session = waste["session_tokens"]
        share = f" ({pct(waste['tokens'], session)} of session tokens)" if session else ""
    return f"  Waste: {amount} on {n} finding{'s' if n != 1 else ''}{share}"


def print_health_report(
    report,
    security_mode: bool = False,
    stats=None,
    efficiency=None,
    note: str | None = None,
) -> None:
    """Print a formatted health report to stdout.

    `stats` (a `SessionStats`, optional) surfaces `peak_context_tokens` --
    the high-water mark of any single action's context size, which survives
    compaction and so is a more durable signal than the current window fill.
    Purely informational: not folded into `report.overall_score`.
    """
    click.echo()
    click.echo("═" * 50)
    if security_mode:
        click.echo("  SECURITY REPORT")
    else:
        click.echo("  HEALTH REPORT")
    click.echo("═" * 50)
    if note:
        click.echo(click.style(f"  Fallback: {note}", fg="yellow"))
    click.echo()

    # Overall score - use theme-aware colors
    theme = get_theme()
    status_color = theme.color_for(report.status)
    click.echo(
        f"  Overall:   {report.emoji} "
        + click.style(
            f"{report.status.upper()} ({report.overall_score}%)",
            fg=status_color,
            bold=True,
        )
    )
    click.echo()

    # Category breakdown
    for cat, score in report.category_scores.items():
        if score.warnings or score.score < 100:
            click.echo(f"  {cat.value.title():12} {score.emoji} {score.score}%")

    click.echo()

    if efficiency is not None:
        click.echo(
            f"  Efficiency: {efficiency.score}% ({efficiency.status}), "
            f"{efficiency.context_usage_pct:.0f}% ctx, "
            f"{efficiency.cache_hit_rate * 100:.0f}% cache hit"
        )
    if stats is not None and stats.peak_context_tokens:
        click.echo(f"  Peak context: {stats.peak_context_tokens:,} tokens (single action)")
    waste = _waste(report.warnings, stats) if stats is not None else None
    if waste:
        click.echo(click.style(_waste_line(waste), bold=True))
    if efficiency is not None or (stats is not None and stats.peak_context_tokens) or waste:
        click.echo()

    # Warnings
    if report.warnings:
        click.echo(f"  {theme.emoji_for(theme.level_2)} {len(report.warnings)} warning(s):")
        click.echo()
        for w in report.warnings[:10]:  # Limit to 10
            severity_color = {
                "low": "blue",
                "medium": "yellow",
                "high": "red",
                "critical": "red",
            }
            click.echo(
                f"     {w.emoji} "
                + click.style(f"[{w.signal}]", fg=severity_color[w.severity.value])
                + f" {w.message}"
                + (click.style(f"  {w.cost_label}", bold=True) if w.cost_label else "")
            )
            # Show key details
            if w.details:
                arrow = ascii_safe("→", "->")
                for key in ("last_error", "error_pattern", "last_command", "file"):
                    if key in w.details and w.details[key]:
                        click.echo(f"        {arrow} {w.details[key][:100]}")
                        break
                if "sample_errors" in w.details and w.details["sample_errors"]:
                    click.echo(f"        {arrow} {w.details['sample_errors'][0][:100]}")
            # Show suggestion
            if w.suggestion:
                marker = ascii_safe("💡", "[TIP]")
                click.echo(click.style(f"        {marker} {w.suggestion[:120]}", dim=True))
            click.echo()

        if len(report.warnings) > 10:
            click.echo(f"     ... and {len(report.warnings) - 10} more")
    else:
        click.echo(f"  {theme.emoji_for(theme.level_0)} No issues detected")

    click.echo()


def print_security_alert(warnings) -> None:
    """Print security alerts in a prominent format."""
    critical = [w for w in warnings if w.severity.value == "critical"]
    high = [w for w in warnings if w.severity.value == "high"]
    theme = get_theme()

    if critical:
        click.echo()
        critical_marker = theme.emoji_for(theme.level_3)
        click.echo(
            click.style(
                f"{critical_marker} CRITICAL SECURITY ALERTS {critical_marker}",
                fg="red",
                bold=True,
            )
        )
        click.echo("=" * 50)
        for w in critical:
            click.echo(f"  {w.emoji} [{w.signal}] {w.message}")
            if w.details:
                for k, v in list(w.details.items())[:3]:
                    click.echo(f"      {k}: {v}")
        click.echo()

    if high:
        click.echo()
        click.echo(
            click.style(
                f"{theme.emoji_for(theme.level_2)} HIGH SEVERITY WARNINGS", fg="yellow", bold=True
            )
        )
        click.echo("-" * 50)
        for w in high:
            click.echo(f"  {w.emoji} [{w.signal}] {w.message}")
        click.echo()


@click.group()
@click.version_option(version=__version__)
@click.option(
    "--theme", "-t",
    type=click.Choice(list_themes()),
    default="agent",
    help="Status label theme (default: agent)",
)
def cli(theme: str):
    """AgentWatch - Health and security monitoring for AI agents."""
    set_theme(theme)


@cli.command()
@click.option(
    "--log", "-l",
    type=_LOG_FILE,
    help="Path to agent log file (JSONL, Aider Markdown chat history, or "
         "Cursor's state.vscdb); auto-detects if not specified",
)
@click.option(
    "--analytics-log",
    type=_LOG_FILE,
    default=None,
    help="Path to an Aider --analytics-log JSONL sidecar (optional, "
         "backfills tokens/cost onto an Aider Markdown --log)",
)
@click.option(
    "--security", "-s",
    is_flag=True,
    help="Enable security detectors",
)
@click.option(
    "--json", "json_output",
    is_flag=True,
    help="Output as JSON",
)
@click.option(
    "--siem-log",
    type=_OUT_FILE,
    default=None,
    help="Append findings as JSON-lines to this file for SIEM ingestion "
         "(requires the 'siem' extra: pip install \"agentwatch-monitor[siem]\")",
)
@click.option(
    "--llm",
    is_flag=True,
    help="Enable Tier-2 semantic triage of warnings via a local Ollama model "
         "(requires the 'llm' extra and a running `ollama serve`; degrades "
         "to Tier-1-only if unavailable)",
)
@click.option(
    "--llm-model",
    default=DEFAULT_OLLAMA_MODEL,
    show_default=True,
    help="Local Ollama model to use for --llm",
)
def check(
    log: Path | None,
    analytics_log: Path | None,
    security: bool,
    json_output: bool,
    siem_log: Path | None,
    llm: bool,
    llm_model: str,
):
    """Run a one-time health check on agent logs."""
    # Find log file
    note = None
    if log is None:
        log, note = _default_log()
        if log is None:
            click.echo("No log files found. Specify a path with --log", err=True)
            sys.exit(1)
        click.echo(f"Using log: {log}", err=True)

    # Parse logs and run checks over the whole session
    mode = "all" if security else "health"
    registry = create_registry(mode=mode)
    buffer = ActionBuffer()
    try:
        warnings = registry.scan(parse_file(log, analytics_log=analytics_log), buffer)
    except (UnsupportedLogFormatError, LogUnreadableError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    if len(buffer) == 0:
        click.echo("No actions found in log file", err=True)
        sys.exit(1)

    # Calculate scores (Tier-1 only -- LLM assessment below is advisory
    # enrichment applied to warning.details after scoring, never before)
    report = calculate_health(warnings, include_security=security)
    # Informational, like the TUI's efficiency bar: not part of the exit code.
    efficiency = calculate_efficiency(warnings, buffer)

    goal_alignment: GoalAlignmentAssessment | None = None
    if llm:
        analyzer = _run_llm_assessment(warnings, llm_model)
        if analyzer is not None:
            goal_alignment = _run_goal_alignment(analyzer, buffer)

    if siem_log is not None:
        _export_siem_log(
            siem_log, warnings, buffer, report_type="health", score=report.overall_score
        )

    if json_output:
        output = report.to_dict()
        output["session_fallback"] = note
        output["efficiency"] = efficiency.to_dict()
        output["goal_alignment"] = goal_alignment.to_dict() if goal_alignment else None
        output["waste"] = _waste(warnings, buffer.stats)
        click.echo(json.dumps(output, indent=2))
    else:
        print_health_report(
            report,
            security_mode=security,
            stats=buffer.stats,
            efficiency=efficiency,
            note=note,
        )

        # Extra security output
        if security and report.security_warnings:
            print_security_alert(report.security_warnings)

        if llm:
            _print_llm_assessments(warnings)
            _print_goal_alignment(goal_alignment)

    # Exit code based on score thresholds (theme-independent)
    # < 40 = level_3 (critical/stuck) -> exit 2
    # < 60 = level_2 (warning/spinning) -> exit 1
    # >= 60 = level_0/level_1 (healthy/productive or degraded/struggling) -> exit 0
    if report.overall_score < 40:
        sys.exit(2)
    elif report.overall_score < 60:
        sys.exit(1)
    sys.exit(0)


def _check_webhook(ctx, param, value: str | None) -> str | None:
    """http(s) only. The URL is a secret: never echoed, even when invalid."""
    if value is None:
        return None
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(value)
        ok = parts.scheme in ("http", "https") and bool(parts.hostname)
    except ValueError:  # e.g. "http://[::1/x"
        ok = False
    if not ok:
        raise click.BadParameter("must be an http:// or https:// URL (value not shown)")
    if parts.scheme == "http":
        from agentwatch.alerts import mask_url

        click.echo(f"agentwatch: warning: webhook {mask_url(value)} is plain http; "
                   "alert text is sent unencrypted", err=True)
    return value


def _check_budget(ctx, param, value: float | None) -> float | None:
    # FloatRange would let nan through.
    if value is not None and not (math.isfinite(value) and value > 0):
        raise click.BadParameter("must be a positive amount in USD")
    return value


def _alert_options(f):
    """--notify / --notify-min / --webhook / --budget, shared by watch and watch-all."""
    f = click.option(
        "--budget",
        type=float,
        callback=_check_budget,
        default=None,
        metavar="USD",
        help="Alert once per session when its estimated cost reaches USD "
             "(turns on --notify unless --webhook is given)",
    )(f)
    f = click.option(
        "--webhook",
        envvar="AGENTWATCH_WEBHOOK",
        show_envvar=True,
        callback=_check_webhook,
        default=None,
        metavar="URL",
        help='POST each alert as JSON {"text": ...} (Slack-compatible) to URL. '
             "The URL is treated as a secret and never printed",
    )(f)
    f = click.option(
        "--notify-existing",
        is_flag=True,
        help="Also alert on findings a session already has when it is first "
             "seen (default: those are a silent baseline)",
    )(f)
    f = click.option(
        "--notify-min",
        type=click.Choice(["high", "critical"]),
        default="critical",
        show_default=True,
        help="Lowest finding severity that alerts (--notify and --webhook)",
    )(f)
    return click.option(
        "--notify",
        is_flag=True,
        help="Desktop notification when a session turns Critical or a new "
             "finding at --notify-min or above appears",
    )(f)


def _make_alerter(notify: bool, notify_min: str, notify_existing: bool, webhook: str | None,
                  budget: float | None = None, headless: bool = False):
    if budget is not None and not webhook:
        notify = True  # --budget alone needs a sink: desktop (board decision)
    if not (notify or webhook or headless):
        return None
    from agentwatch.alerts import Alerter, print_line

    return Alerter(notify=notify, notify_min=notify_min, webhook=webhook,
                   log=print_line if headless else None, notify_existing=notify_existing,
                   budget=budget)


@cli.command()
@click.option(
    "--log", "-l",
    type=_LOG_FILE,
    help="Path to agent log file (JSONL, Aider Markdown chat history, or "
         "Cursor's state.vscdb); auto-detects if not specified",
)
@click.option(
    "--security", "-s",
    is_flag=True,
    help="Enable security detectors",
)
@click.option(
    "--siem-log",
    type=_OUT_FILE,
    default=None,
    help="Append findings as JSON-lines to this file for SIEM ingestion, "
         "as new warnings appear (requires the 'siem' extra: pip install "
         "\"agentwatch-monitor[siem]\")",
)
@click.option(
    "--llm",
    is_flag=True,
    help="Enable Tier-2 semantic triage of warnings via a local Ollama model, "
         "refreshed periodically in the background (requires the 'llm' extra "
         "and a running `ollama serve`; degrades to Tier-1-only if unavailable)",
)
@click.option(
    "--llm-model",
    default=DEFAULT_OLLAMA_MODEL,
    show_default=True,
    help="Local Ollama model to use for --llm",
)
@_alert_options
def watch(
    log: Path | None,
    security: bool,
    siem_log: Path | None,
    llm: bool,
    llm_model: str,
    notify: bool,
    notify_min: str,
    notify_existing: bool,
    webhook: str | None,
    budget: float | None,
):
    """Watch agent logs in real-time with a TUI dashboard."""
    # Import here to avoid slow startup for non-watch commands
    from agentwatch.ui.app import AgentWatchApp

    # Find log file
    if log is None:
        log, _ = _default_log()
        if log is None:
            click.echo("No log files found. Specify a path with --log", err=True)
            sys.exit(1)
    try:
        ensure_supported_log(log)
    except UnsupportedLogFormatError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    app = AgentWatchApp(
        log_path=log,
        security_mode=security,
        siem_log=siem_log,
        llm=llm,
        llm_model=llm_model,
        alerter=_make_alerter(notify, notify_min, notify_existing, webhook, budget),
    )
    app.run()


@cli.command()
@click.option(
    "--json", "json_output",
    is_flag=True,
    help="Output as JSON for scripting",
)
def ps(json_output: bool):
    """Discover and list running AI agent processes."""
    agents = find_running_agents()

    has_subagents = any(a.depth > 0 for a in agents)

    if json_output:
        # Always a flat list of agent objects, with or without sub-agents, so
        # scripts can rely on one shape. Rebuild the tree from parent_agent_pid,
        # depth and team_id.
        team_names = {t.team_id: t.name for t in build_teams(agents)}
        output = [
            {
                "pid": a.pid,
                "parent_pid": a.parent_pid,
                "parent_agent_pid": a.parent_agent_pid,
                "team_id": a.team_id,
                "team_name": team_names.get(a.team_id),
                "depth": a.depth,
                "agent_type": a.agent_type,
                "project": a.project_name,
                "working_directory": str(a.working_directory) if a.working_directory else None,
                "log_file": str(a.log_file) if a.log_file else None,
                "session_id": a.session_id,
                "cpu_percent": a.cpu_percent,
                "memory_mb": round(a.memory_mb, 1),
                "uptime": a.uptime,
            }
            for a in agents
        ]
        click.echo(json.dumps(output, indent=2))
        return

    click.echo()
    click.echo("╔══════════════════════════════════════════════════╗")
    click.echo("  ACTIVE AGENTS")
    click.echo("╚══════════════════════════════════════════════════╝")
    click.echo()

    if not agents:
        click.echo("  No running agent processes found.")
        click.echo()
        return

    if has_subagents:
        _print_teams_view(agents)
    else:
        _print_agents_view(agents)


@cli.command()
@click.option(
    "--json", "json_output",
    is_flag=True,
    help="Output as JSON for scripting",
)
def detect(json_output: bool):
    """List programs on this machine that are using AI right now."""
    from agentwatch import ai_detect  # call-time lookup: tests monkeypatch detect

    result = ai_detect.detect()

    if json_output:
        click.echo(json.dumps({
            "usages": [
                {
                    "pid": u.pid,
                    "name": u.name,
                    "display_name": u.display_name,
                    "exe": u.exe,
                    "providers": sorted(u.providers),
                    "connections": u.connections,
                    "local_runtime": u.local_runtime,
                    "adapter": u.adapter,
                }
                for u in result.usages
            ],
            "partial": result.partial,
            "unresolved": result.unresolved,
        }, indent=2))
        return

    click.echo()
    click.echo("╔══════════════════════════════════════════════════╗")
    click.echo("  AI IN USE ON THIS MACHINE")
    click.echo("╚══════════════════════════════════════════════════╝")
    click.echo()

    all_domains = sum(len(d) for d in ai_detect.AI_PROVIDERS.values())
    if len(result.unresolved) == all_domains:
        click.echo(
            "  Could not resolve any AI domain (offline?); only local runtimes were checked."
        )
        click.echo()

    if not result.usages:
        click.echo("  No programs using AI found.")
    else:
        click.echo(
            f"  {'PID':<8}{'PROGRAM':<20}{'PROVIDERS':<22}{'CONNS':>6}  {'LOCAL':<11}SUPPORTED"
        )
        for u in result.usages:
            label = u.display_name
            name = label if len(label) <= 18 else label[:15] + "..."
            providers = ",".join(sorted(u.providers)) or "-"
            if len(providers) > 20:
                providers = providers[:17] + "..."
            supported = (
                click.style(u.adapter, fg="green") if u.adapter
                else click.style("no", fg="yellow")
            )
            click.echo(
                f"  {u.pid:<8}{name:<20}{providers:<22}{u.connections:>6}  "
                f"{u.local_runtime or '-':<11}{supported}"
            )
        unmonitored = sum(1 for u in result.usages if u.adapter is None)
        click.echo()
        click.echo(
            f"  {len(result.usages)} program(s) using AI "
            f"({unmonitored} not monitored by agentwatch)"
        )

    if result.partial:
        click.echo("  Partial scan: run as administrator/root to see all processes")
    if result.unresolved and len(result.unresolved) < all_domains:
        click.echo(f"  Could not resolve: {', '.join(result.unresolved)}")
    click.echo()


def _clock(dt) -> str:
    return dt.astimezone().strftime("%H:%M:%S")


def _hostport(ip: str, port: int) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _proc(name: str, pid: int) -> str:
    from agentwatch.net import _printable  # process names can carry control chars

    return f"{_printable(name)}({pid})"


def _ai_warn(text: str) -> str:
    return click.style(text, fg="yellow", bold=True)


def _net_line(ep) -> str:
    lan = " LAN" if ep.lan else ""
    flag = _ai_warn(f" AI-PROVIDER {ep.ai_provider}") if ep.ai_provider else ""
    return (
        f"{_clock(ep.first_seen)}  OUT  {ep.runtime}  {_proc(ep.process, ep.pid)} -> "
        f"{ep.host} [{ep.host_source}] {_hostport(ep.ip, ep.port)} {ep.kind}{lan}{flag}"
    )


def _unwatched_line(unwatched) -> str:
    return (f"{len(unwatched)} agent(s) without a verifiable own process not watched "
            "(editor-hosted, Codex app-server threads, or unreadable; use --pid <pid>)")


def _print_net_summary(endpoints, targets) -> None:
    click.echo("  Watched: " + (", ".join(f"{t.runtime} {_proc(t.process, t.pid)}" for t in targets)
                                or "nothing"))
    if not endpoints:
        click.echo("  No outgoing connections seen.")
        return
    head, *lines = _table_lines(
        [("RUNTIME", "PROCESS", "HOST", "ENDPOINT", "FIRST SEEN", "LAST SEEN")] + [
            (e.runtime, _proc(e.process, e.pid),
             f"{e.host} [{e.host_source}]" + (" LAN" if e.lan else "")
             + (f" AI-PROVIDER {e.ai_provider}" if e.ai_provider else ""),
             f"{_hostport(e.ip, e.port)}/{e.kind}", _clock(e.first_seen), _clock(e.last_seen))
            for e in endpoints])
    click.echo(head)
    for e, line in zip(endpoints, lines):
        click.echo(_ai_warn(line) if e.ai_provider else line)
    click.echo(f"\n  {len(endpoints)} outgoing endpoint(s)")
    flagged = [e for e in endpoints if e.ai_provider]
    if flagged:
        names = {t.pid: t.process for t in targets}
        sources = dict.fromkeys(f"{e.runtime} {_proc(names.get(e.target_pid, '?'), e.target_pid)}"
                                for e in flagged)
        click.echo("  " + _ai_warn(f"{len(flagged)} connection(s) to cloud AI providers "
                                   f"(from {', '.join(sources)})"))


def _warn(listener, text: str) -> str:
    if not listener.exposed:
        return text
    return click.style(text, fg="red" if listener.scope == "all interfaces" else "yellow")


def _listen_line(lst) -> str:
    where = f"EXPOSED ({lst.scope})" if lst.exposed else lst.scope
    return _warn(lst, f"{_clock(lst.first_seen)}  LISTEN  {lst.runtime}  "
                      f"{_proc(lst.process, lst.pid)} {_hostport(lst.ip, lst.port)}  {where}")


def _client_desc(c) -> str:
    if c.scope == "local":
        return (_proc(c.process, c.pid) if c.pid else _hostport(c.ip, c.port)) + " [local]"
    name = "" if c.host_source == "ip" else f" {c.host} [{c.host_source}]"
    return f"{_hostport(c.ip, c.port)} [{c.scope}]{name}"


def _client_line(c) -> str:
    return (f"{_clock(c.first_seen)}  IN  {c.runtime}  "
            f"{_hostport(c.listener_ip, c.listener_port)} <- {_client_desc(c)}")


def _table_lines(rows) -> list[str]:
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    return ["  " + "  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in rows]


def _print_incoming(listeners, clients) -> None:
    click.echo()
    if not listeners:
        click.echo("  No listening sockets seen.")
        return
    click.echo("  LISTENERS")
    head, *lines = _table_lines(
        [("RUNTIME", "PROCESS", "ADDRESS", "SCOPE", "FIRST SEEN", "LAST SEEN")] + [
            (lst.runtime, _proc(lst.process, lst.pid), _hostport(lst.ip, lst.port),
             f"EXPOSED ({lst.scope})" if lst.exposed else lst.scope,
             _clock(lst.first_seen), _clock(lst.last_seen))
            for lst in listeners])
    click.echo(head)
    for lst, line in zip(listeners, lines):
        click.echo(_warn(lst, line))
    click.echo()
    if clients:
        click.echo("  CLIENTS")
        for line in _table_lines(
            [("RUNTIME", "LISTENER", "CLIENT", "FIRST SEEN", "LAST SEEN")] + [
                (c.runtime, _hostport(c.listener_ip, c.listener_port), _client_desc(c),
                 _clock(c.first_seen), _clock(c.last_seen))
                for c in clients]):
            click.echo(line)
    else:
        click.echo("  No clients seen.")
    exposed = sum(lst.exposed for lst in listeners)
    if exposed:
        click.echo("\n  " + click.style(f"{exposed} listener(s) reachable from other machines",
                                         fg="red", bold=True))


@cli.command()
@click.option("--interval", type=click.FloatRange(min=0.1), default=1.0, show_default=True,
              help="Seconds between polls")
@click.option("--once", is_flag=True, help="Take one sample, print the summary and exit")
@click.option("--json", "json_output", is_flag=True,
              help="NDJSON events (one JSON document with --once)")
@click.option("--pid", "pids", type=click.IntRange(min=1), multiple=True,
              help="Also watch this process and its children (repeatable; not 0, which "
                   "is the System Idle Process on Windows)")
@click.option("--duration", type=click.FloatRange(min=0, min_open=True), default=None,
              help="Stop after this many seconds and print the summary (headless runs)")
@click.option("--local", is_flag=True,
              help="Also watch running agents with their own process (Claude Code, Aider, "
                   "...); their AI-provider traffic is flagged, like every target's")
def net(interval: float, once: bool, json_output: bool, pids: tuple[int, ...],
        duration: float | None, local: bool):
    """Show which external servers local AI runtimes (Ollama, LM Studio, ...) talk to,
    and which of their listeners are reachable from other machines."""
    import signal
    import time
    from dataclasses import asdict
    from datetime import datetime, timezone

    from agentwatch import net as netmod  # call-time lookup: tests monkeypatch it

    if once and duration is not None:
        raise click.UsageError("--duration has no effect with --once; use one of them")
    tracker = netmod.Tracker(netmod.Namer())
    agents = netmod.LocalAgents() if local else None
    no_target = netmod.NO_TARGET_LOCAL if local else netmod.NO_RUNTIME

    def find_targets():
        if agents is None:
            return netmod.find_targets(pids)
        agents.scan()
        return netmod.find_targets(pids, agents.targets)

    def unwatched() -> list[str]:
        return agents.unwatched if agents else []

    if once:
        missing = netmod.missing_pids(pids)
        status = 1 if pids and set(pids) <= set(missing) else 0  # every --pid gone
        targets = find_targets()
        tracker.poll(targets)
        endpoints = tracker.summary(wait=0)  # poll() already waited for rDNS
        listeners, clients = tracker.incoming()
        if json_output:
            doc = {"targets": [asdict(t) for t in targets],
                   "outgoing": [e.to_dict() for e in endpoints],
                   "listeners": [r.to_dict() for r in listeners],
                   "clients": [r.to_dict() for r in clients], "missing_pids": missing,
                   "unwatched_agents": unwatched()}
            if not targets:
                doc["message"] = no_target
            click.echo(json.dumps(doc, indent=2))
            sys.exit(status)
        for pid in missing:
            click.echo(f"pid {pid} not found", err=True)
        if not targets:
            click.echo(no_target)
        else:
            _print_net_summary(endpoints, targets)
            _print_incoming(listeners, clients)
        if unwatched():
            click.echo("\n  " + _unwatched_line(unwatched()))
        sys.exit(status)

    def emit(event: str, text: str, **fields) -> None:
        click.echo(json.dumps({"event": event, **fields}) if json_output else text)

    def stop(signum, frame):
        raise KeyboardInterrupt

    # SIGTERM / SIGBREAK (Ctrl+Break, console close on Windows) take the Ctrl+C path.
    previous = {}
    for name in ("SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                previous[sig] = signal.signal(sig, stop)
            except (ValueError, OSError):  # not the main thread
                pass

    if not json_output:
        click.echo("Watching connections of local AI runtimes" + (" and agents" if local else "")
                   + " (Ctrl+C for summary)")
    current: dict[int, object] = {}
    watched: dict[int, object] = {}
    missing: set[int] = set()
    waiting = False
    told_unwatched = False
    deadline = time.monotonic() + duration if duration else None
    try:
        while True:
            gone = set(netmod.missing_pids(pids)) - missing
            targets = find_targets()
            now = datetime.now(timezone.utc)
            if unwatched() and not told_unwatched:  # once: the count, not every change
                told_unwatched = True
                emit("unwatched", _unwatched_line(unwatched()), time=now.isoformat(),
                     unwatched_agents=unwatched())
            if gone:
                missing |= gone
                if json_output:
                    emit("missing", "", time=now.isoformat(), missing_pids=sorted(gone))
                else:
                    for pid in sorted(gone):
                        click.echo(f"{_clock(now)}  pid {pid} not found", err=True)
            seen = {t.pid: t for t in targets}
            for state, pid_set, side in (("started", seen.keys() - current.keys(), seen),
                                         ("stopped", current.keys() - seen.keys(), current)):
                for pid in sorted(pid_set):
                    t = side[pid]
                    emit("target", f"{_clock(now)}  {state.upper()} {t.runtime}  "
                         f"{_proc(t.process, t.pid)}", state=state, time=now.isoformat(),
                         **asdict(t))
            current = seen
            watched.update(seen)
            if not targets and not waiting:
                emit("waiting", f"{no_target} Waiting for one to start...", message=no_target)
            waiting = not targets
            for rec in tracker.poll(targets, now):
                if isinstance(rec, netmod.Listener):
                    emit("listener", _listen_line(rec), **rec.to_dict())
                elif isinstance(rec, netmod.Client):
                    emit("client", _client_line(rec), **rec.to_dict())
                else:
                    emit("outgoing", _net_line(rec), **rec.to_dict())
            if deadline is None:
                time.sleep(interval)
            elif (left := deadline - time.monotonic()) > 0:
                time.sleep(min(interval, left))
            else:
                break
    except KeyboardInterrupt:
        pass
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    endpoints = tracker.summary()
    listeners, clients = tracker.incoming()
    if json_output:
        emit("summary", "", targets=[asdict(t) for t in watched.values()],
             outgoing=[e.to_dict() for e in endpoints],
             listeners=[r.to_dict() for r in listeners], clients=[r.to_dict() for r in clients],
             missing_pids=sorted(missing), unwatched_agents=unwatched())
    else:
        click.echo()
        _print_net_summary(endpoints, list(watched.values()))
        _print_incoming(listeners, clients)


def _print_agents_view(agents: list[AgentProcess]) -> None:
    """Print agents as a simple list (no sub-agents present)."""
    # Table header
    click.echo(
        f"  {'PID':<12}{'TYPE':<16}{'PROJECT':<18}{'SESSION':<10}{'CPU':>6}{'MEM':>8}{'STATUS':>10}"
    )

    for a in agents:
        project = a.project_name or "---"
        if len(project) > 16:
            project = project[:13] + "..."

        session = a.session_id[:8] if a.session_id else "---"
        cpu_str = f"{a.cpu_percent:.1f}%"
        mem_str = f"{a.memory_mb:.0f}MB"
        status = click.style("active", fg="green")

        click.echo(
            f"  {a.pid:<12}{a.agent_type:<16}{project:<18}{session:<10}"
            f"{cpu_str:>6}{mem_str:>8}   {status}"
        )

    click.echo()
    click.echo(f"  {len(agents)} active agent(s) found.")
    click.echo()


def _print_teams_view(agents: list[AgentProcess]) -> None:
    """Print agents grouped by team."""
    team_list = build_teams(agents)

    for team in team_list:
        # Team header
        team_label = f"TEAM: {team.name}"
        if team.subagent_count > 0:
            team_label += f" ({team.member_count} agents, {team.subagent_count} sub)"
        click.echo(click.style(f"  {team_label}", fg="yellow", bold=True))

        # Table header
        click.echo(
            f"    {'PID':<12}{'TYPE':<16}{'PROJECT':<16}{'SESSION':<10}"
            f"{'CPU':>6}{'MEM':>8}{'ROLE':>8}"
        )

        for a in team.members:
            if a.depth == 0:
                prefix = ""
                role = click.style("root", fg="green")
            else:
                prefix = "  " * a.depth + "├── "
                role = click.style(f"L{a.depth}", fg="cyan")

            project = a.project_name or "---"
            max_proj_len = max(14 - len(prefix), 6)
            if len(project) > max_proj_len:
                project = project[: max_proj_len - 3] + "..."

            session = a.session_id[:8] if a.session_id else "---"
            cpu_str = f"{a.cpu_percent:.1f}%"
            mem_str = f"{a.memory_mb:.0f}MB"
            proj_col = f"{prefix}{project}"

            click.echo(
                f"    {a.pid:<12}{a.agent_type:<16}{proj_col:<16}{session:<10}"
                f"{cpu_str:>6}{mem_str:>8}   {role}"
            )

        click.echo()

    # Summary
    total_teams = len(team_list)
    multi_teams = sum(1 for t in team_list if t.subagent_count > 0)
    click.echo(
        f"  {len(agents)} agent(s) in {total_teams} team(s)"
        + (f" ({multi_teams} with sub-agents)" if multi_teams > 0 else "")
        + "."
    )
    click.echo()


@cli.command()
@click.option(
    "--security", "-s",
    is_flag=True,
    help="Enable security detectors",
)
@click.option(
    "--all-logs",
    is_flag=True,
    help="Scan all log directories instead of using process-based discovery",
)
@click.option(
    "--siem-log",
    type=_OUT_FILE,
    default=None,
    help="Append findings as JSON-lines to this file for SIEM ingestion, "
         "as new warnings appear, per agent (requires the 'siem' extra: "
         "pip install \"agentwatch-monitor[siem]\")",
)
@click.option(
    "--llm",
    is_flag=True,
    help="Enable Tier-2 semantic triage of warnings via a local Ollama model, "
         "refreshed periodically in the background, per agent (requires the "
         "'llm' extra and a running `ollama serve`; degrades to Tier-1-only "
         "if unavailable)",
)
@click.option(
    "--llm-model",
    default=DEFAULT_OLLAMA_MODEL,
    show_default=True,
    help="Local Ollama model to use for --llm",
)
@click.option(
    "--headless",
    is_flag=True,
    help="No dashboard: print one line per new warning to stdout (for "
         "background runs). Waits for agents if none are running yet",
)
@_alert_options
def watch_all(
    security: bool,
    all_logs: bool,
    siem_log: Path | None,
    llm: bool,
    llm_model: str,
    headless: bool,
    notify: bool,
    notify_min: str,
    notify_existing: bool,
    webhook: str | None,
    budget: float | None,
):
    """Watch agent logs in real-time with a multi-agent dashboard.

    By default, auto-discovers active agent processes and monitors only their
    log files. Use --all-logs to scan all known log directories instead.
    """
    alerter = _make_alerter(notify, notify_min, notify_existing, webhook, budget, headless)
    from agentwatch.parser.logs import DEFAULT_SEARCH_PATHS
    from agentwatch.ui.multi_app import MultiAgentWatchApp

    if all_logs:
        # Legacy behavior: scan all log directories
        watch_paths = [p for p in DEFAULT_SEARCH_PATHS if p.exists()]
        if not watch_paths:
            click.echo("No agent log directories found.", err=True)
            sys.exit(1)
        app = MultiAgentWatchApp(
            watch_paths=watch_paths,
            security_mode=security,
            siem_log=siem_log,
            llm=llm,
            llm_model=llm_model,
            alerter=alerter,
        )
    else:
        # Process-based discovery
        agents = build_agent_tree(find_running_agents())
        if not agents and not headless:
            click.echo("No running agent processes found.", err=True)
            click.echo("Use --all-logs to scan all log directories instead.", err=True)
            sys.exit(1)
        app = MultiAgentWatchApp(
            agent_processes=agents,
            security_mode=security,
            siem_log=siem_log,
            llm=llm,
            llm_model=llm_model,
            alerter=alerter,
        )

    if headless:
        # Same engine, Textual's headless driver: no screen I/O; Ctrl+C exits
        # through the app's normal shutdown (on_unmount closes SIEM logs).
        click.echo("agentwatch: watching headless (Ctrl+C to stop)", err=True)
        app.run(headless=True)
        return
    app.run()


@cli.command()
@click.option(
    "--security", "-s",
    is_flag=True,
    help="Include security detectors",
)
def list_detectors(security: bool):
    """List all available detectors."""
    mode = "all" if security else "health"
    registry = create_registry(mode=mode)

    click.echo()
    click.echo("Available Detectors:")
    click.echo("=" * 50)

    detectors_by_cat = registry.list_detectors()

    for cat, detectors in sorted(detectors_by_cat.items()):
        click.echo()
        click.echo(click.style(f"  {cat.upper()}", bold=True))
        bullet = ascii_safe("•", "*")
        for d in detectors:
            click.echo(f"    {bullet} {d}")

    click.echo()
    click.echo(f"Total: {len(registry.detectors)} detectors")
    click.echo()


@cli.command()
@click.option(
    "--log", "-l",
    type=_LOG_FILE,
    help="Path to agent log file (JSONL, Aider Markdown chat history, or "
         "Cursor's state.vscdb)",
)
@click.option(
    "--analytics-log",
    type=_LOG_FILE,
    default=None,
    help="Path to an Aider --analytics-log JSONL sidecar (optional, "
         "backfills tokens/cost onto an Aider Markdown --log)",
)
@click.option(
    "--json", "json_output",
    is_flag=True,
    help="Output as JSON",
)
@click.option(
    "--siem-log",
    type=_OUT_FILE,
    default=None,
    help="Append findings as JSON-lines to this file for SIEM ingestion "
         "(requires the 'siem' extra: pip install \"agentwatch-monitor[siem]\")",
)
@click.option(
    "--audit-log",
    type=_OUT_FILE,
    default=None,
    help="Append one JSON-lines entry per security detector's run (triggered "
         "or not) to this file -- a 'prove you checked' compliance trail, "
         "distinct from --siem-log which only records positive findings.",
)
@click.option(
    "--llm",
    is_flag=True,
    help="Enable Tier-2 semantic triage of warnings via a local Ollama model "
         "(requires the 'llm' extra and a running `ollama serve`; degrades "
         "to Tier-1-only if unavailable)",
)
@click.option(
    "--llm-model",
    default=DEFAULT_OLLAMA_MODEL,
    show_default=True,
    help="Local Ollama model to use for --llm",
)
def security_scan(
    log: Path | None,
    analytics_log: Path | None,
    json_output: bool,
    siem_log: Path | None,
    audit_log: Path | None,
    llm: bool,
    llm_model: str,
):
    """Run a security-focused scan on agent logs.

    Exit codes: 0 = secure (score 100), 1 = at risk (score 50-99),
    2 = compromised (score below 50).
    """
    note = None
    if log is None:
        log, note = _default_log()
        if log is None:
            click.echo("No log files found. Specify a path with --log", err=True)
            sys.exit(1)
        click.echo(f"Using log: {log}", err=True)

    # Parse logs and run only security detectors, over the whole session
    registry = create_registry(mode="security")
    buffer = ActionBuffer()
    try:
        warnings = registry.scan(parse_file(log, analytics_log=analytics_log), buffer)
    except (UnsupportedLogFormatError, LogUnreadableError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    if len(buffer) == 0:
        click.echo("No actions found in log file", err=True)
        sys.exit(1)

    security_score = calculate_security_score(warnings)

    if audit_log is not None:
        # Separate pass via check_with_audit() -- deliberately not reused
        # for `warnings` above, so the default (no --audit-log) path's
        # detector-ordering/behavior is provably unchanged.
        _, audit_entries = registry.check_security_with_audit(buffer)
        _export_audit_log(audit_log, audit_entries, buffer)

    goal_alignment: GoalAlignmentAssessment | None = None
    if llm:
        analyzer = _run_llm_assessment(warnings, llm_model)
        if analyzer is not None:
            goal_alignment = _run_goal_alignment(analyzer, buffer)

    if siem_log is not None:
        _export_siem_log(siem_log, warnings, buffer, report_type="security", score=security_score)

    # Raw per-action security-stat counters (SessionStats.credential_accesses
    # / .privilege_commands / .network_connections / .injection_attempts --
    # see the design-decision comment on SessionStats in parser/models.py:
    # these are raw pattern-match counts, not "how many Warnings fired").
    security_stats = {
        "credential_accesses": buffer.stats.credential_accesses,
        "privilege_commands": buffer.stats.privilege_commands,
        "network_connections": buffer.stats.network_connections,
        "injection_attempts": buffer.stats.injection_attempts,
    }

    if json_output:
        output = {
            "security_score": security_score,
            "status": security_tier_from_score(security_score),
            "warnings": [w.to_dict() for w in warnings],
            "action_count": len(buffer),
            "security_stats": security_stats,
            "goal_alignment": goal_alignment.to_dict() if goal_alignment else None,
            "session_fallback": note,
        }
        click.echo(json.dumps(output, indent=2))
    else:
        click.echo()
        click.echo("═" * 50)
        click.echo("  SECURITY SCAN RESULTS")
        click.echo("═" * 50)
        if note:
            click.echo(click.style(f"  Fallback: {note}", fg="yellow"))
        click.echo()

        # Theme-driven, sharing security_status_from_score() with
        # ui/app.py's SecurityStatus widget rather than hand-copying the
        # same SECURE/AT-RISK/COMPROMISED thresholds a second time (that
        # duplication is exactly how this class of bug -- fix the emoji in
        # one copy, miss the other -- was introduced).
        # Verdict text is security wording (SECURE / AT RISK / COMPROMISED);
        # emoji and colour still come from the theme's tier for that score.
        theme = get_theme()
        tier_status = security_status_from_score(security_score)
        emoji = theme.emoji_for(tier_status)
        color = theme.color_for(tier_status)
        label = security_label_from_score(security_score)
        click.echo(
            click.style(f"  {emoji} {label} ({security_score}%)", fg=color, bold=True)
        )

        click.echo()
        click.echo(f"  Analyzed {len(buffer)} actions")
        click.echo(f"  Found {len(warnings)} security issue(s)")
        click.echo(
            "  Raw signal counts: "
            f"credential_accesses={security_stats['credential_accesses']}  "
            f"privilege_commands={security_stats['privilege_commands']}  "
            f"network_connections={security_stats['network_connections']}  "
            f"injection_attempts={security_stats['injection_attempts']}"
        )
        click.echo()

        if warnings:
            print_security_alert(warnings)

        if llm:
            _print_llm_assessments(warnings)
            _print_goal_alignment(goal_alignment)

    sys.exit(SECURITY_TIER_EXIT_CODES[security_tier_from_score(security_score)])


@cli.command()
def themes():
    """List all available status themes."""
    from agentwatch.themes import THEMES

    click.echo()
    click.echo("Available Status Themes:")
    click.echo("=" * 60)
    click.echo()

    arrow = ascii_safe("→", "->")
    for name, theme in THEMES.items():
        is_default = " (default)" if name == "agent" else ""
        click.echo(click.style(f"  {name}{is_default}", bold=True))
        click.echo(
            f"    {theme.emoji_0} {theme.level_0} {arrow} {theme.emoji_1} {theme.level_1} "
            f"{arrow} {theme.emoji_2} {theme.level_2} {arrow} {theme.emoji_3} {theme.level_3}"
        )
        click.echo()

    click.echo("Use --theme <name> to select a theme.")
    click.echo()


@cli.command()
@click.option(
    "--all", "all_projects",
    is_flag=True,
    help="Show stats across all projects (default: current project only)",
)
@click.option(
    "--session", "session_id",
    type=str,
    default=None,
    help="Analyze a specific session ID",
)
@click.option(
    "--json", "json_output",
    is_flag=True,
    help="Output as JSON",
)
@click.option(
    "--burn",
    is_flag=True,
    help="Show where tokens burn — trivial vs substantive breakdown",
)
@click.option(
    "--list", "list_trivial",
    is_flag=True,
    help="List every trivial command (use with --burn)",
)
@click.option(
    "--prompts",
    is_flag=True,
    help="Include the user prompt that triggered each trivial call (use with --burn --list)",
)
def stats(
    all_projects: bool,
    session_id: str | None,
    json_output: bool,
    burn: bool,
    list_trivial: bool,
    prompts: bool,
):
    """Show Claude Code token usage statistics.

    Parses conversation logs from ~/.claude/projects/ and displays a
    breakdown of token usage by tool type and bash command category.

    \b
    Use --burn to see how many tokens went to trivial commands
    (git, ls, npm run dev, etc.) that you could have run yourself.
    Use --burn --list to see every trivial command.
    Use --burn --list --prompts to also show what you said that triggered them.
    """
    from agentwatch.cc_stats import compute_stats

    # --list / --prompts imply --burn
    if list_trivial or prompts:
        burn = True
    if prompts:
        list_trivial = True

    report = compute_stats(all_projects=all_projects, session_id=session_id)

    if report.message_count == 0:
        if all_projects:
            click.echo("No Claude Code session logs found.", err=True)
        else:
            click.echo(
                "No Claude Code session logs found for this project.\n"
                "Run from a project directory or use --all for all projects.",
                err=True,
            )
        sys.exit(1)

    if json_output:
        click.echo(json.dumps(report.to_dict(), indent=2))
    elif burn:
        _print_burn_report(report)
        if list_trivial:
            _print_trivial_list(report, show_prompts=prompts)
    else:
        _print_stats_report(report)


def _make_bar(fraction: float, width: int = 40) -> str:
    """Render a unicode bar chart."""
    filled = int(fraction * width)
    return "\u2588" * filled + "\u2591" * (width - filled)


def _fmt_tokens(n: int) -> str:
    """Format a token count with commas."""
    return f"{n:,}"


def _usd(cost: float | None) -> str:
    """Dollar amount for `stats`; "n/a" when the model has no listed price."""
    return "n/a" if cost is None else f"${cost:,.2f}"


def _print_stats_report(report) -> None:
    """Print a formatted token usage report."""
    from agentwatch.cc_stats import ToolCategory

    click.echo()
    click.echo("\u2554" + "\u2550" * 50 + "\u2557")
    click.echo("  TOKEN USAGE STATS")
    click.echo("\u255a" + "\u2550" * 50 + "\u255d")
    click.echo()

    # Session info
    click.echo(f"  Project:  {report.project_name}")
    click.echo(
        f"  Sessions: {report.session_count}"
        f" | Messages: {report.message_count:,}"
        f" | Tool calls: {report.tool_call_count:,}"
    )
    click.echo()

    # Totals
    est_cost = report.totals.estimated_cost_usd()
    click.echo("  TOTALS")
    click.echo("  " + "\u2500" * 50)
    click.echo(
        f"  Input:   {_fmt_tokens(report.totals.input_tokens):>12}"
        f"    Cache write: {_fmt_tokens(report.totals.cache_write_tokens):>12}"
    )
    click.echo(
        f"  Output:  {_fmt_tokens(report.totals.output_tokens):>12}"
        f"    Cache read:  {_fmt_tokens(report.totals.cache_read_tokens):>12}"
    )
    click.echo(
        f"  Total:   {_fmt_tokens(report.totals.total_tokens):>12}"
        f"    Est. cost:   {click.style(f'{_usd(est_cost):>11}', bold=True)}"
    )
    click.echo()

    # Breakdown by tool
    if report.by_tool:
        click.echo("  BREAKDOWN BY TOOL")
        click.echo("  " + "\u2500" * 50)

        total = report.totals.total_tokens or 1
        sorted_tools = sorted(
            report.by_tool.items(),
            key=lambda x: x[1].total_tokens,
            reverse=True,
        )

        for cat, bucket in sorted_tools:
            pct = bucket.total_tokens / total * 100
            cost = bucket.estimated_cost_usd()
            count_str = (
                f"{bucket.call_count:>5}"
                if cat != ToolCategory.Thinking
                else "  ---"
            )
            click.echo(
                f"  {cat.value:<14} {count_str}"
                f" {_fmt_tokens(bucket.total_tokens):>12}"
                f" {pct:>5.1f}%"
                f"   {_usd(cost):>7}"
            )
            click.echo(f"    {_make_bar(pct / 100)}")

        click.echo()

    # Bash sub-breakdown
    if report.by_bash_category:
        click.echo("  BASH COMMAND BREAKDOWN")
        click.echo("  " + "\u2500" * 50)

        bash_total = sum(
            b.total_tokens for b in report.by_bash_category.values()
        ) or 1
        sorted_bash = sorted(
            report.by_bash_category.items(),
            key=lambda x: x[1].total_tokens,
            reverse=True,
        )

        for cat, bucket in sorted_bash:
            pct = bucket.total_tokens / bash_total * 100
            click.echo(
                f"  {cat.value:<14} {bucket.call_count:>5}"
                f" {_fmt_tokens(bucket.total_tokens):>12}"
                f" {pct:>5.1f}%"
            )

        click.echo()

    # Cache efficiency
    click.echo("  CACHE EFFICIENCY")
    click.echo("  " + "\u2500" * 50)
    ratio = report.cache_hit_ratio
    click.echo(f"  Hit ratio: {ratio * 100:.1f}%  {_make_bar(ratio)}")
    click.echo()


def _print_burn_report(report) -> None:
    """Print trivial vs substantive token burn analysis."""
    click.echo()
    click.echo("\u2554" + "\u2550" * 50 + "\u2557")
    click.echo("  TOKEN BURN ANALYSIS")
    click.echo("\u255a" + "\u2550" * 50 + "\u255d")
    click.echo()

    click.echo(f"  Project:  {report.project_name}")
    click.echo(
        f"  Sessions: {report.session_count}"
        f" | Messages: {report.message_count:,}"
        f" | Tool calls: {report.tool_call_count:,}"
    )
    click.echo()

    total = report.totals.total_tokens or 1
    triv = report.trivial
    sub = report.substantive

    triv_pct = triv.total_tokens / total * 100
    sub_pct = sub.total_tokens / total * 100
    triv_cost = triv.estimated_cost_usd()
    sub_cost = sub.estimated_cost_usd()

    # Trivial
    click.echo(
        "  "
        + click.style("TRIVIAL", fg="yellow", bold=True)
        + "  (commands you could run yourself)"
    )
    click.echo("  " + "\u2500" * 50)
    click.echo(
        f"  Calls: {triv.call_count:>6,}"
        f"    Tokens: {_fmt_tokens(triv.total_tokens):>12}"
        f"    {triv_pct:>5.1f}%"
    )
    click.echo(
        f"  Est. cost: {click.style(_usd(triv_cost), fg='yellow', bold=True)}"
    )
    click.echo(f"    {_make_bar(triv_pct / 100)}")
    click.echo()

    # Top trivial commands
    if report.top_trivial_commands:
        sorted_cmds = sorted(
            report.top_trivial_commands.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]
        click.echo("  Top trivial commands:")
        times_symbol = ascii_safe("\u00d7", "x")
        for cmd, count in sorted_cmds:
            click.echo(f"    {cmd:<20} {click.style(f'{times_symbol}{count}', dim=True)}")
        click.echo()

    # Substantive
    click.echo(
        "  "
        + click.style("SUBSTANTIVE", fg="green", bold=True)
        + "  (AI reasoning, code generation, search)"
    )
    click.echo("  " + "\u2500" * 50)
    click.echo(
        f"  Calls: {sub.call_count:>6,}"
        f"    Tokens: {_fmt_tokens(sub.total_tokens):>12}"
        f"    {sub_pct:>5.1f}%"
    )
    click.echo(
        f"  Est. cost: {click.style(_usd(sub_cost), fg='green', bold=True)}"
    )
    click.echo(f"    {_make_bar(sub_pct / 100)}")
    click.echo()

    # Verdict
    click.echo("  VERDICT")
    click.echo("  " + "\u2500" * 50)
    if triv_pct > 30:
        click.echo(
            "  "
            + click.style(
                f"{triv_pct:.0f}% of tokens went to trivial ops.",
                fg="red",
                bold=True,
            )
        )
        click.echo(
            f"  You could save ~{_usd(triv_cost)} by running simple commands yourself."
        )
    elif triv_pct > 15:
        click.echo(
            "  "
            + click.style(
                f"{triv_pct:.0f}% of tokens on trivial ops — room to improve.",
                fg="yellow",
            )
        )
    else:
        click.echo(
            "  "
            + click.style(
                f"Only {triv_pct:.0f}% trivial — good token efficiency.",
                fg="green",
            )
        )
    click.echo()


def _print_trivial_list(report, *, show_prompts: bool = False) -> None:
    """Print detailed list of trivial calls."""
    calls = sorted(
        report.trivial_calls,
        key=lambda c: c.total_tokens,
        reverse=True,
    )

    if not calls:
        click.echo("  No trivial calls found.")
        click.echo()
        return

    click.echo()
    click.echo(
        f"  TRIVIAL CALLS ({len(calls)})"
    )
    click.echo("  " + "\u2500" * 50)

    for tc in calls:
        cmd_display = tc.command if len(tc.command) <= 60 else tc.command[:57] + "..."
        click.echo(
            f"  $ {click.style(cmd_display, bold=True)}"
            f"   {_fmt_tokens(tc.total_tokens):>10} tok"
            f"   {_usd(tc.estimated_cost_usd)}"
        )
        if show_prompts and tc.user_prompt:
            prompt = tc.user_prompt.strip().replace("\n", " ")
            if len(prompt) > 80:
                prompt = prompt[:77] + "..."
            click.echo(
                click.style(f"    prompt: \"{prompt}\"", dim=True)
            )

    click.echo()
    costs = [tc.estimated_cost_usd for tc in calls]
    total_cost = None if None in costs else sum(costs)
    click.echo(
        f"  {len(calls)} trivial calls"
        f" | {_fmt_tokens(sum(tc.total_tokens for tc in calls))} tokens"
        f" | {_usd(total_cost)} est. cost"
    )
    click.echo()


@cli.command()
@click.option(
    "--all", "all_projects",
    is_flag=True,
    help="Scan all projects under ~/.claude/projects/ (default: current project only)",
)
@click.option(
    "--session", "session_id",
    type=str,
    default=None,
    help="Restrict scan to a specific session ID",
)
@click.option(
    "--json", "json_output",
    is_flag=True,
    help="Output as JSON for scripting/piping",
)
@click.option(
    "--redact",
    is_flag=True,
    help="Replace detected secrets with [REDACTED] in the log files",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Run scan and impact assessment, print report, but don't modify any files",
)
@click.option(
    "--force",
    is_flag=True,
    help="Redact active or just-written logs too (default: skip/refuse them). "
    "Risky: lines a running agent writes during the rewrite can be lost.",
)
@click.option(
    "--pii",
    is_flag=True,
    help="Also find (and with --redact, hide) personal info: emails, phones, SSNs, cards",
)
def audit(
    all_projects: bool,
    session_id: str | None,
    json_output: bool,
    redact: bool,
    dry_run: bool,
    force: bool,
    pii: bool,
):
    """Scan log history for leaked secrets and credentials.

    Performs a passive forensic audit of existing JSONL session logs,
    checking for API keys, tokens, passwords, and other secrets across
    all action channels (file writes, bash commands, model output, etc.).

    \b
    By default scans the current project. Use --all for all projects.
    Use --redact to replace found secrets with [REDACTED] in the log files.

    \b
    Exit codes: 0 = no high or critical findings, 1 = at least one high,
    2 = at least one critical. Medium, low and --pii findings never fail.
    """
    from agentwatch.cc_stats import (
        cwd_to_project_dir,
        find_all_project_dirs,
        project_dir_to_name,
    )
    from agentwatch.detectors.security.pii import _PII_PATTERNS
    from agentwatch.detectors.security.secret_scanner import (
        _SECRET_PATTERNS,
        AuditFinding,
        LogBusyError,
        assess_impact,
        audit_log_file,
        redact_log_file,
    )

    # Without --pii, call exactly as before (no patterns kwarg).
    pat = {"patterns": _SECRET_PATTERNS + _PII_PATTERNS} if pii else {}

    if all_projects:
        dirs = find_all_project_dirs()
    else:
        project_dir = cwd_to_project_dir()
        if project_dir is None:
            click.echo(
                "No Claude Code session logs found for this project.\n"
                "Run from a project directory or use --all for all projects.",
                err=True,
            )
            sys.exit(1)
        dirs = [project_dir]

    all_findings: list[AuditFinding] = []
    sessions_scanned = 0
    project_names: list[str] = []

    for pdir in dirs:
        proj_name = project_dir_to_name(pdir)
        project_names.append(proj_name)

        if session_id:
            jsonl = pdir / f"{session_id}.jsonl"
            files = [jsonl] if jsonl.is_file() else []
        else:
            files = sorted(pdir.glob("*.jsonl"))

        for jsonl_path in files:
            sessions_scanned += 1
            try:
                findings = audit_log_file(jsonl_path, project_name=proj_name, **pat)
                all_findings.extend(findings)
            except (OSError, json.JSONDecodeError, UnsupportedLogFormatError):
                continue

    if sessions_scanned == 0:
        if all_projects:
            click.echo("No Claude Code session logs found.", err=True)
        else:
            click.echo(
                "No Claude Code session logs found for this project.\n"
                "Run from a project directory or use --all for all projects.",
                err=True,
            )
        sys.exit(1)

    # Always run impact assessment
    assess_impact(all_findings)

    # Determine which log files belong to active sessions
    active_log_files: set[str] = set()
    for f in all_findings:
        if f.impact and f.impact.is_active_session:
            active_log_files.add(f.log_file)

    # --redact: replace secrets in affected log files
    redact_count = 0
    skipped_active: list[str] = []
    backups: list[Path] = []
    redact_errors: list[dict[str, str]] = []
    if redact and all_findings and not dry_run:
        affected_files: dict[str, Path] = {}
        for pdir in dirs:
            for f in all_findings:
                fp = pdir / f.log_file
                if fp.is_file():
                    affected_files[str(fp)] = fp
        if force and affected_files:
            click.echo(
                click.style(
                    "  WARNING: --force rewrites logs that a running agent may still be "
                    "writing. Lines appended during the rewrite are detected and the run "
                    "aborts if the file keeps changing, but an agent that holds the log "
                    "open can keep writing to the replaced copy and lose those lines. "
                    "Close the session first when you can.",
                    fg="red",
                    bold=True,
                ),
                err=True,
            )
        for fp_str, fp in affected_files.items():
            # Skip active session logs unless --force
            if not force and fp.name in active_log_files:
                skipped_active.append(fp.name)
                continue
            # One bad file must not abort the run and skip the remaining files.
            try:
                redact_count += redact_log_file(fp, backups=backups, force=force, **pat)
            except LogBusyError:
                # Written to a moment ago: same outcome as an active session.
                skipped_active.append(fp.name)
            except (OSError, UnicodeError, ValueError, NotImplementedError) as exc:
                redact_errors.append({"log_file": str(fp), "error": str(exc)})

    if json_output:
        finding_dicts = []
        for f in all_findings:
            d: dict = {
                "secret_type": f.secret_type,
                "channel": f.channel,
                "severity": f.severity,
                "file_path": f.file_path,
                "matched_prefix": f.matched_prefix,
                "log_file": f.log_file,
                "session_id": f.session_id,
                "project_name": f.project_name,
                "remediation": f.remediation,
                "timestamp": f.timestamp,
            }
            if f.impact:
                d["is_active_session"] = f.impact.is_active_session
                d["active_pid"] = f.impact.active_pid
                d["still_in_source"] = f.impact.still_in_source
                d["source_line"] = f.impact.source_line
                d["env_var_matches"] = f.impact.env_var_matches
            finding_dicts.append(d)

        output: dict = {
            "projects": project_names,
            "sessions_scanned": sessions_scanned,
            "total_findings": len(all_findings),
            "redacted": redact_count if redact and not dry_run else None,
            "skipped_active": sorted(set(skipped_active)) if skipped_active else [],
            "backups": [str(b) for b in backups],
            "redact_errors": redact_errors,
            "findings": finding_dicts,
        }
        click.echo(json.dumps(output, indent=2))
    else:
        _print_audit_report(all_findings, sessions_scanned, project_names)

        if dry_run:
            click.echo(
                click.style("  --dry-run: no files modified.", dim=True)
            )
            click.echo()
        elif redact and (redact_count > 0 or backups or redact_errors):
            if redact_count > 0:
                click.echo(
                    click.style(
                        f"  Redacted {redact_count} secret(s) from log files.",
                        fg="green",
                        bold=True,
                    )
                )
            for err in redact_errors:
                click.echo(
                    click.style(
                        f"  Failed to redact {err['log_file']}: {err['error']}",
                        fg="red",
                    )
                )
            if backups:
                click.echo(
                    click.style(
                        "  Backups with the ORIGINAL (unredacted) secrets were kept at:",
                        fg="yellow",
                        bold=True,
                    )
                )
                for b in backups:
                    click.echo(f"    {b}")
                click.echo(
                    click.style(
                        "  Delete them once you've verified the redacted logs.",
                        fg="yellow",
                    )
                )
            click.echo()

        if skipped_active:
            for log_name in sorted(set(skipped_active)):
                click.echo(
                    click.style(
                        f"  Skipped {log_name} (active session or modified in the last "
                        "few seconds). Use --force to redact.",
                        fg="yellow",
                    )
                )
            click.echo()

    # Exit code: 2 if critical, 1 if high, 0 if clean
    severities = {f.severity for f in all_findings}
    if "critical" in severities:
        sys.exit(2)
    elif "high" in severities:
        sys.exit(1)
    sys.exit(0)


def _history_db():
    from agentwatch.history import connect

    try:
        return connect()
    except (OSError, RuntimeError, sqlite3.Error) as e:
        click.echo(f"Error: history DB: {e}", err=True)
        sys.exit(1)


def _sync_line(counts: dict, seconds: float) -> str:
    scanned = counts["new"] + counts["updated"]
    line = (f"Synced {scanned} log(s) ({counts['new']} new, {counts['updated']} updated), "
            f"{counts['unchanged']} unchanged in {seconds:.1f}s")
    if counts["active"]:
        line += f"; {counts['active']} still being written (--include-active)"
    return line


@cli.group()
def history():
    """Local session history behind `agentwatch report`.

    Stores per session: agent, session id, project folder name, times,
    actions, tokens, cost, health score and findings (signal, severity, cost,
    a short redacted message). No transcript text, prompts, commands or full
    paths. Kept until `history prune`.
    """


@history.command("sync")
@click.option("--days", type=click.FloatRange(min=0, min_open=True), default=None,
              help="Only logs written in the last N days")
@click.option("--include-active", is_flag=True,
              help="Also logs written in the last 60 s (sessions still running)")
def history_sync(days: float | None, include_active: bool):
    """Record every agent's sessions (only new or changed logs are read)."""
    import time

    from agentwatch.history import sync

    t = time.perf_counter()
    counts = sync(_history_db(), days=days, include_active=include_active)
    click.echo(_sync_line(counts, time.perf_counter() - t))


@history.command("prune")
@click.option("--older-than", "older_than", required=True, metavar="Nd",
              help="Delete sessions last active more than N days ago, e.g. 90d")
def history_prune(older_than: str):
    """Delete old sessions. A later sync without --days reads their logs
    again if they are still on disk."""
    import re

    from agentwatch.history import prune

    m = re.fullmatch(r"(\d+)d?", older_than.strip())
    if not m:
        raise click.BadParameter("use a number of days, e.g. 90d", param_hint="--older-than")
    n = prune(_history_db(), int(m.group(1)))
    click.echo(f"Removed {n} session(s) last active more than {m.group(1)} days ago")


@history.command("path")
def history_path():
    """Print the history DB location."""
    from agentwatch.history import db_path

    click.echo(str(db_path()))


@cli.command()
@click.option("--days", type=click.IntRange(min=1), default=7, show_default=True,
              help="Report period")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON (stable schema)")
@click.option("--agent", default=None, help="Only this agent (e.g. claude-code)")
@click.option("--project", default=None, help="Only this project folder name")
@click.option("--no-sync", is_flag=True, help="Use the history DB as is")
def report(days: int, json_output: bool, agent: str | None, project: str | None,
           no_sync: bool):
    """What your agents cost you: spend, waste, costliest findings, trend.

    Syncs the history first (this period and the one before), then reports
    on sessions whose last action is in the last N days.
    """
    from agentwatch.history import sync
    from agentwatch.report import build, render

    conn = _history_db()
    if not no_sync:
        counts = sync(conn, days=2 * days)
        if counts["new"] + counts["updated"] and not json_output:
            click.echo(f"(synced {counts['new'] + counts['updated']} log(s))", err=True)
    rep = build(conn, days=days, agent=agent, project=project)
    if json_output:
        click.echo(json.dumps(rep, indent=2))
    else:
        click.echo("\n".join(render(rep)))


@cli.command(hidden=True)
def hook():
    """Claude Code coach hook: reads hook JSON on stdin (see plugin/)."""
    from agentwatch.coach import main as coach_main

    coach_main()


@cli.command()
@click.option("--ok", is_flag=True, help="When healthy, print a dim check mark and 'agentwatch'")
def statusline(ok: bool):
    """Claude Code status line: a short warning (loop ~$1.40) when unhealthy.

    Reads the status line JSON on stdin and the coach's state for that
    session (needs the agentwatch plugin's hook). Prints nothing when healthy,
    with no recent state, or on any error. See the README for settings.json.
    """
    from agentwatch.statusline import main as statusline_main

    statusline_main(ok)


@cli.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--secrets-only", is_flag=True, help="Hide secrets only, not personal info")
@click.option(
    "--in-place", is_flag=True, help="Overwrite the file, keeping the original as <file>.bak"
)
@click.option("--dry-run", is_flag=True, help="List what would be hidden; write nothing")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def scrub(path: Path, secrets_only: bool, in_place: bool, dry_run: bool, json_output: bool):
    """Hide secrets and personal info in one file before sharing it.

    \b
    Writes a cleaned copy beside the file (notes.txt -> notes.scrubbed.txt)
    unless --in-place. Exit codes: 0 done (dry run: nothing found),
    1 dry run found something, 2 error.
    """
    from agentwatch.detectors.security.pii import _PII_PATTERNS
    from agentwatch.detectors.security.secret_scanner import _SECRET_PATTERNS, scrub_file

    patterns = _SECRET_PATTERNS if secrets_only else _SECRET_PATTERNS + _PII_PATTERNS
    try:
        r = scrub_file(path, patterns=patterns, in_place=in_place, dry_run=dry_run)
    except (OSError, ValueError, UnicodeError) as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)

    if json_output:
        click.echo(json.dumps({
            "file": str(r.file),
            "output": str(r.output) if r.output else None,
            "backup": str(r.backup) if r.backup else None,
            "dry_run": r.dry_run,
            "redacted": r.redacted,
            "findings": r.findings,
        }, indent=2))
    else:
        if dry_run:
            click.echo(f"Would hide {r.redacted} value(s) in {r.file} (dry run, nothing written).")
        else:
            click.echo(f"Hid {r.redacted} value(s) in {r.file}.")
        if r.output and not r.backup:
            click.echo(f"Clean copy: {r.output}")
        if r.backup:
            click.echo(click.style(
                f"Original (with the unhidden values) kept at {r.backup}. "
                "Delete it once you've checked the file.",
                fg="yellow",
            ))
        for f in r.findings:
            click.echo(f"  line {f['line']:>5}  {f['type']:<24} {f['preview']}")
    sys.exit(1 if dry_run and r.redacted else 0)


def _print_audit_report(
    findings: list,
    sessions_scanned: int,
    project_names: list[str],
) -> None:
    """Print a formatted secret audit report."""
    click.echo()
    click.echo("=" * 54)
    click.echo("  SECRET AUDIT REPORT")
    click.echo("=" * 54)
    click.echo()
    click.echo(
        f"  Scanned: {sessions_scanned} session(s) across"
        f" {len(project_names)} project(s)"
    )
    click.echo()

    if not findings:
        clean = sessions_scanned
        click.echo(click.style("  No secrets found.", fg="green", bold=True))
        click.echo(f"  {clean} session(s) clean.")
        click.echo()
        return

    # Group by severity
    critical = [f for f in findings if f.severity == "critical"]
    high = [f for f in findings if f.severity == "high"]
    medium = [f for f in findings if f.severity == "medium"]
    low = [f for f in findings if f.severity == "low"]

    for label, color, group in [
        ("CRITICAL", "red", critical),
        ("HIGH", "yellow", high),
        ("MEDIUM", "blue", medium),
        ("LOW", "cyan", low),
    ]:
        if not group:
            continue
        emoji = {
            "CRITICAL": "\U0001f6a8", "HIGH": "\u26a0\ufe0f ", "MEDIUM": "\u2139\ufe0f ",
            "LOW": "\u2139\ufe0f ",
        }[label]
        click.echo(
            f"  {emoji} "
            + click.style(f"{label} ({len(group)})", fg=color, bold=True)
        )
        click.echo()

        for f in group:
            click.echo(
                f"     {click.style(f.secret_type, bold=True)}"
                f" in {f.channel}"
            )
            parts = []
            if f.file_path:
                parts.append(f"File: {f.file_path}")
            parts.append(f"Match: {f.matched_prefix}")
            click.echo(f"        {' | '.join(parts)}")

            # Log line with active session annotation
            log_line = f"        Log: {f.log_file}"
            if f.session_id:
                log_line += f" | Session: {f.session_id[:8]}"
            if f.impact and f.impact.is_active_session:
                log_line += click.style(
                    f" (ACTIVE SESSION pid={f.impact.active_pid})",
                    fg="red",
                    bold=True,
                )
            click.echo(log_line)

            # Impact: still in source
            if f.impact and f.impact.still_in_source:
                click.echo(
                    click.style(
                        f"        Still in source: {f.file_path}:{f.impact.source_line}",
                        fg="yellow",
                    )
                )

            # Impact: env var matches
            if f.impact and f.impact.env_var_matches:
                click.echo(
                    click.style(
                        f"        In env: {', '.join(f.impact.env_var_matches)}",
                        fg="yellow",
                    )
                )

            click.echo(
                click.style(f"        \U0001f4a1 {f.remediation}", dim=True)
            )
            click.echo()

    # Summary: sessions with no findings
    sessions_with_findings = len({f.session_id for f in findings if f.session_id})
    clean = sessions_scanned - sessions_with_findings
    if clean > 0:
        click.echo(f"  No issues: {clean} session(s) clean")
    click.echo()


def _ensure_utf8_stdio() -> None:
    """Force UTF-8 on stdout/stderr.

    Windows consoles default Python's stdout/stderr to the legacy code page
    (e.g. cp1252), which can't encode the box-drawing characters used in
    report output and crashes with UnicodeEncodeError. macOS/Linux terminals
    are already UTF-8, so this is a no-op there.
    """
    if sys.platform == "win32":
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")


def main():
    """Main entry point for agentwatch CLI."""
    _ensure_utf8_stdio()
    cli()


def _build_guard_cli():
    """Construct the `agentguard` Click group (security-focused CLI).

    Factored out of `security_main()` so it can be reached directly (e.g. by
    tests using Click's `CliRunner`) without spawning a real process.
    """
    # Override defaults to always include security
    @click.group()
    @click.version_option(version=__version__)
    def guard_cli():
        """AgentGuard - Security monitoring for AI agents."""
        pass

    @guard_cli.command(name="scan")
    @click.option("--log", "-l", type=_LOG_FILE)
    @click.option("--json", "json_output", is_flag=True)
    def guard_scan(log, json_output):
        """Run security scan."""
        ctx = click.Context(security_scan)
        ctx.invoke(security_scan, log=log, json_output=json_output)

    @guard_cli.command(name="watch")
    @click.option("--log", "-l", type=_LOG_FILE)
    def guard_watch(log):
        """Watch for security issues in real-time."""
        ctx = click.Context(watch)
        ctx.invoke(watch, log=log, security=True)

    @guard_cli.command(name="check")
    @click.option("--log", "-l", type=_LOG_FILE)
    @click.option("--json", "json_output", is_flag=True)
    def guard_check(log, json_output):
        """Run full check with security enabled."""
        ctx = click.Context(check)
        ctx.invoke(check, log=log, security=True, json_output=json_output)

    @guard_cli.command(name="watch-all")
    @click.option("--all-logs", is_flag=True, help="Scan all log directories")
    def guard_watch_all(all_logs):
        """Watch all agents for security issues."""
        ctx = click.Context(watch_all)
        ctx.invoke(watch_all, security=True, all_logs=all_logs)

    @guard_cli.command(name="audit")
    @click.option("--all", "all_projects", is_flag=True, help="Scan all projects")
    @click.option("--session", "session_id", type=str, default=None)
    @click.option("--json", "json_output", is_flag=True)
    @click.option("--redact", is_flag=True, help="Replace secrets with [REDACTED]")
    @click.option("--dry-run", is_flag=True, help="Print report without modifying files")
    @click.option("--force", is_flag=True, help="Redact active session logs too")
    def guard_audit(all_projects, session_id, json_output, redact, dry_run, force):
        """Audit log history for leaked secrets."""
        ctx = click.Context(audit)
        ctx.invoke(
            audit,
            all_projects=all_projects,
            session_id=session_id,
            json_output=json_output,
            redact=redact,
            dry_run=dry_run,
            force=force,
        )

    return guard_cli


def security_main():
    """Entry point for agentguard CLI (security-focused)."""
    _ensure_utf8_stdio()
    guard_cli = _build_guard_cli()
    guard_cli()


if __name__ == "__main__":
    main()
