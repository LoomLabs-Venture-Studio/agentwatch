"""Command-line interface for agentwatch."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from agentwatch import __version__
from agentwatch.detectors import create_registry
from agentwatch.detectors.base import Warning
from agentwatch.discovery import (
    AgentProcess,
    build_agent_tree,
    build_teams,
    find_running_agents,
)
from agentwatch.health import calculate_health, calculate_security_score
from agentwatch.llm import (
    DEFAULT_OLLAMA_MODEL,
    MAX_WARNINGS_TO_ASSESS,
    GoalAlignmentAssessment,
    LlmUnavailableError,
    OllamaAnalyzer,
)
from agentwatch.parser import ActionBuffer, find_latest_session, parse_file
from agentwatch.siem import SiemExportError, SiemLogger
from agentwatch.themes import (
    ascii_safe,
    get_theme,
    list_themes,
    security_status_from_score,
    set_theme,
)


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


def print_health_report(report, security_mode: bool = False, stats=None) -> None:
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

    if stats is not None and stats.peak_context_tokens:
        click.echo(f"  Peak context: {stats.peak_context_tokens:,} tokens (single action)")
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
    type=click.Path(exists=True, path_type=Path),
    help="Path to agent log file (JSONL, Aider Markdown chat history, or "
         "Cursor's state.vscdb); auto-detects if not specified",
)
@click.option(
    "--analytics-log",
    type=click.Path(exists=True, path_type=Path),
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
    type=click.Path(path_type=Path),
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
    if log is None:
        log = find_latest_session()
        if log is None:
            click.echo("No log files found. Specify a path with --log", err=True)
            sys.exit(1)
        click.echo(f"Using log: {log}")

    # Parse logs
    buffer = ActionBuffer()
    for action in parse_file(log, analytics_log=analytics_log):
        buffer.add(action)

    if len(buffer) == 0:
        click.echo("No actions found in log file", err=True)
        sys.exit(1)

    # Create registry and run checks
    mode = "all" if security else "health"
    registry = create_registry(mode=mode)
    warnings = registry.check_all(buffer)

    # Calculate scores (Tier-1 only -- LLM assessment below is advisory
    # enrichment applied to warning.details after scoring, never before)
    report = calculate_health(warnings, include_security=security)

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
        output["goal_alignment"] = goal_alignment.to_dict() if goal_alignment else None
        click.echo(json.dumps(output, indent=2))
    else:
        print_health_report(report, security_mode=security, stats=buffer.stats)

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


@cli.command()
@click.option(
    "--log", "-l",
    type=click.Path(exists=True, path_type=Path),
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
    type=click.Path(path_type=Path),
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
def watch(
    log: Path | None,
    security: bool,
    siem_log: Path | None,
    llm: bool,
    llm_model: str,
):
    """Watch agent logs in real-time with a TUI dashboard."""
    # Import here to avoid slow startup for non-watch commands
    from agentwatch.ui.app import AgentWatchApp

    # Find log file
    if log is None:
        log = find_latest_session()
        if log is None:
            click.echo("No log files found. Specify a path with --log", err=True)
            sys.exit(1)

    app = AgentWatchApp(
        log_path=log,
        security_mode=security,
        siem_log=siem_log,
        llm=llm,
        llm_model=llm_model,
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
        if has_subagents:
            team_list = build_teams(agents)
            output = []
            for t in team_list:
                output.append({
                    "team_id": t.team_id,
                    "team_name": t.name,
                    "member_count": t.member_count,
                    "subagent_count": t.subagent_count,
                    "max_depth": t.max_depth,
                    "members": [
                        {
                            "pid": a.pid,
                            "parent_pid": a.parent_pid,
                            "parent_agent_pid": a.parent_agent_pid,
                            "depth": a.depth,
                            "team_id": a.team_id,
                            "agent_type": a.agent_type,
                            "project": a.project_name,
                            "working_directory": str(a.working_directory),
                            "log_file": str(a.log_file) if a.log_file else None,
                            "session_id": a.session_id,
                            "cpu_percent": a.cpu_percent,
                            "memory_mb": round(a.memory_mb, 1),
                            "uptime": a.uptime,
                        }
                        for a in t.members
                    ],
                })
            click.echo(json.dumps(output, indent=2))
        else:
            output = []
            for a in agents:
                output.append({
                    "pid": a.pid,
                    "parent_pid": a.parent_pid,
                    "agent_type": a.agent_type,
                    "project": a.project_name,
                    "working_directory": str(a.working_directory),
                    "log_file": str(a.log_file) if a.log_file else None,
                    "session_id": a.session_id,
                    "cpu_percent": a.cpu_percent,
                    "memory_mb": round(a.memory_mb, 1),
                    "uptime": a.uptime,
                })
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


def _print_agents_view(agents: list[AgentProcess]) -> None:
    """Print agents as a simple list (no sub-agents present)."""
    # Table header
    click.echo(
        f"  {'PID':<8}{'TYPE':<14}{'PROJECT':<18}{'SESSION':<10}{'CPU':>6}{'MEM':>8}{'STATUS':>10}"
    )

    for a in agents:
        project = a.project_name
        if len(project) > 16:
            project = project[:13] + "..."

        session = a.session_id[:8] if a.session_id else "---"
        cpu_str = f"{a.cpu_percent:.1f}%"
        mem_str = f"{a.memory_mb:.0f}MB"
        status = click.style("active", fg="green")

        click.echo(
            f"  {a.pid:<8}{a.agent_type:<14}{project:<18}{session:<10}"
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
            f"    {'PID':<8}{'TYPE':<14}{'PROJECT':<16}{'SESSION':<10}"
            f"{'CPU':>6}{'MEM':>8}{'ROLE':>8}"
        )

        for a in team.members:
            if a.depth == 0:
                prefix = ""
                role = click.style("root", fg="green")
            else:
                prefix = "  " * a.depth + "├── "
                role = click.style(f"L{a.depth}", fg="cyan")

            project = a.project_name
            max_proj_len = max(14 - len(prefix), 6)
            if len(project) > max_proj_len:
                project = project[: max_proj_len - 3] + "..."

            session = a.session_id[:8] if a.session_id else "---"
            cpu_str = f"{a.cpu_percent:.1f}%"
            mem_str = f"{a.memory_mb:.0f}MB"
            proj_col = f"{prefix}{project}"

            click.echo(
                f"    {a.pid:<8}{a.agent_type:<14}{proj_col:<16}{session:<10}"
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
    type=click.Path(path_type=Path),
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
def watch_all(
    security: bool,
    all_logs: bool,
    siem_log: Path | None,
    llm: bool,
    llm_model: str,
):
    """Watch agent logs in real-time with a multi-agent dashboard.

    By default, auto-discovers active agent processes and monitors only their
    log files. Use --all-logs to scan all known log directories instead.
    """
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
        )
    else:
        # Process-based discovery
        agents = build_agent_tree(find_running_agents())
        if not agents:
            click.echo("No running agent processes found.", err=True)
            click.echo("Use --all-logs to scan all log directories instead.", err=True)
            sys.exit(1)
        app = MultiAgentWatchApp(
            agent_processes=agents,
            security_mode=security,
            siem_log=siem_log,
            llm=llm,
            llm_model=llm_model,
        )

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
    type=click.Path(exists=True, path_type=Path),
    help="Path to agent log file (JSONL, Aider Markdown chat history, or "
         "Cursor's state.vscdb)",
)
@click.option(
    "--analytics-log",
    type=click.Path(exists=True, path_type=Path),
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
    type=click.Path(path_type=Path),
    default=None,
    help="Append findings as JSON-lines to this file for SIEM ingestion "
         "(requires the 'siem' extra: pip install \"agentwatch-monitor[siem]\")",
)
@click.option(
    "--audit-log",
    type=click.Path(path_type=Path),
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
    """Run a security-focused scan on agent logs."""
    if log is None:
        log = find_latest_session()
        if log is None:
            click.echo("No log files found. Specify a path with --log", err=True)
            sys.exit(1)
        click.echo(f"Using log: {log}")

    # Parse logs
    buffer = ActionBuffer()
    for action in parse_file(log, analytics_log=analytics_log):
        buffer.add(action)

    if len(buffer) == 0:
        click.echo("No actions found in log file", err=True)
        sys.exit(1)

    # Run only security detectors
    registry = create_registry(mode="security")
    warnings = registry.check_all(buffer)

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
            "status": (
                "secure" if security_score == 100
                else "at_risk" if security_score > 50
                else "compromised"
            ),
            "warnings": [w.to_dict() for w in warnings],
            "action_count": len(buffer),
            "security_stats": security_stats,
            "goal_alignment": goal_alignment.to_dict() if goal_alignment else None,
        }
        click.echo(json.dumps(output, indent=2))
    else:
        click.echo()
        click.echo("═" * 50)
        click.echo("  SECURITY SCAN RESULTS")
        click.echo("═" * 50)
        click.echo()

        # Theme-driven, sharing security_status_from_score() with
        # ui/app.py's SecurityStatus widget rather than hand-copying the
        # same SECURE/AT-RISK/COMPROMISED thresholds a second time (that
        # duplication is exactly how this class of bug -- fix the emoji in
        # one copy, miss the other -- was introduced).
        theme = get_theme()
        status = security_status_from_score(security_score)
        emoji = theme.emoji_for(status)
        color = theme.color_for(status)
        click.echo(
            click.style(f"  {emoji} {status.upper()} ({security_score}%)", fg=color, bold=True)
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

    # Exit code
    if security_score < 50:
        sys.exit(2)
    elif security_score < 100:
        sys.exit(1)
    sys.exit(0)


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
    est_cost = report.totals.estimated_cost_usd(report.model)
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
        f"    Est. cost:   {click.style(f'${est_cost:>10,.2f}', bold=True)}"
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
            cost = bucket.estimated_cost_usd(report.model)
            count_str = (
                f"{bucket.call_count:>5}"
                if cat != ToolCategory.Thinking
                else "  ---"
            )
            click.echo(
                f"  {cat.value:<14} {count_str}"
                f" {_fmt_tokens(bucket.total_tokens):>12}"
                f" {pct:>5.1f}%"
                f"   ${cost:>6,.2f}"
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
    triv_cost = triv.estimated_cost_usd(report.model)
    sub_cost = sub.estimated_cost_usd(report.model)

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
        f"  Est. cost: {click.style(f'${triv_cost:,.2f}', fg='yellow', bold=True)}"
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
        f"  Est. cost: {click.style(f'${sub_cost:,.2f}', fg='green', bold=True)}"
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
            f"  You could save ~${triv_cost:,.2f} by running simple commands yourself."
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
            f"   ${tc.estimated_cost_usd:,.2f}"
        )
        if show_prompts and tc.user_prompt:
            prompt = tc.user_prompt.strip().replace("\n", " ")
            if len(prompt) > 80:
                prompt = prompt[:77] + "..."
            click.echo(
                click.style(f"    prompt: \"{prompt}\"", dim=True)
            )

    click.echo()
    total_cost = sum(tc.estimated_cost_usd for tc in calls)
    click.echo(
        f"  {len(calls)} trivial calls"
        f" | {_fmt_tokens(sum(tc.total_tokens for tc in calls))} tokens"
        f" | ${total_cost:,.2f} est. cost"
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
    help="Allow redacting active session logs (default: skip them)",
)
def audit(
    all_projects: bool,
    session_id: str | None,
    json_output: bool,
    redact: bool,
    dry_run: bool,
    force: bool,
):
    """Scan log history for leaked secrets and credentials.

    Performs a passive forensic audit of existing JSONL session logs,
    checking for API keys, tokens, passwords, and other secrets across
    all action channels (file writes, bash commands, model output, etc.).

    \b
    By default scans the current project. Use --all for all projects.
    Use --redact to replace found secrets with [REDACTED] in the log files.
    """
    from agentwatch.cc_stats import (
        cwd_to_project_dir,
        find_all_project_dirs,
        project_dir_to_name,
    )
    from agentwatch.detectors.security.secret_scanner import (
        AuditFinding,
        assess_impact,
        audit_log_file,
        redact_log_file,
    )

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
                findings = audit_log_file(jsonl_path, project_name=proj_name)
                all_findings.extend(findings)
            except (OSError, json.JSONDecodeError):
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
    if redact and all_findings and not dry_run:
        affected_files: dict[str, Path] = {}
        for pdir in dirs:
            for f in all_findings:
                fp = pdir / f.log_file
                if fp.is_file():
                    affected_files[str(fp)] = fp
        for fp_str, fp in affected_files.items():
            # Skip active session logs unless --force
            if not force and fp.name in active_log_files:
                skipped_active.append(fp.name)
                continue
            try:
                redact_count += redact_log_file(fp)
            except OSError:
                continue

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
        elif redact and redact_count > 0:
            click.echo(
                click.style(
                    f"  Redacted {redact_count} secret(s) from log files.",
                    fg="green",
                    bold=True,
                )
            )
            click.echo()

        if skipped_active:
            for log_name in sorted(set(skipped_active)):
                click.echo(
                    click.style(
                        f"  Skipped {log_name} (active session). Use --force to redact.",
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

    for label, color, group in [
        ("CRITICAL", "red", critical),
        ("HIGH", "yellow", high),
        ("MEDIUM", "blue", medium),
    ]:
        if not group:
            continue
        emoji = {
            "CRITICAL": "\U0001f6a8", "HIGH": "\u26a0\ufe0f ", "MEDIUM": "\u2139\ufe0f ",
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
    @click.option("--log", "-l", type=click.Path(exists=True, path_type=Path))
    @click.option("--json", "json_output", is_flag=True)
    def guard_scan(log, json_output):
        """Run security scan."""
        ctx = click.Context(security_scan)
        ctx.invoke(security_scan, log=log, json_output=json_output)

    @guard_cli.command(name="watch")
    @click.option("--log", "-l", type=click.Path(exists=True, path_type=Path))
    def guard_watch(log):
        """Watch for security issues in real-time."""
        ctx = click.Context(watch)
        ctx.invoke(watch, log=log, security=True)

    @guard_cli.command(name="check")
    @click.option("--log", "-l", type=click.Path(exists=True, path_type=Path))
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
