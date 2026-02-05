"""Command-line interface for agentwatch."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from agentwatch.detectors import create_registry
from agentwatch.discovery import AgentProcess, AgentTeam, find_running_agents, build_agent_tree, build_teams
from agentwatch.health import calculate_health, calculate_security_score
from agentwatch.parser import ActionBuffer, find_latest_session, parse_file, find_log_files
from agentwatch.themes import get_theme, set_theme, list_themes


def print_health_report(report, security_mode: bool = False) -> None:
    """Print a formatted health report to stdout."""
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
    
    # Warnings
    if report.warnings:
        click.echo(f"  ⚠️  {len(report.warnings)} warning(s):")
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
                for key in ("last_error", "error_pattern", "last_command", "file"):
                    if key in w.details and w.details[key]:
                        click.echo(f"        → {w.details[key][:100]}")
                        break
                if "sample_errors" in w.details and w.details["sample_errors"]:
                    click.echo(f"        → {w.details['sample_errors'][0][:100]}")
            # Show suggestion
            if w.suggestion:
                click.echo(click.style(f"        💡 {w.suggestion[:120]}", dim=True))
            click.echo()

        if len(report.warnings) > 10:
            click.echo(f"     ... and {len(report.warnings) - 10} more")
    else:
        click.echo("  ✅ No issues detected")
    
    click.echo()


def print_security_alert(warnings) -> None:
    """Print security alerts in a prominent format."""
    critical = [w for w in warnings if w.severity.value == "critical"]
    high = [w for w in warnings if w.severity.value == "high"]
    
    if critical:
        click.echo()
        click.echo(click.style("🚨 CRITICAL SECURITY ALERTS 🚨", fg="red", bold=True))
        click.echo("=" * 50)
        for w in critical:
            click.echo(f"  {w.emoji} [{w.signal}] {w.message}")
            if w.details:
                for k, v in list(w.details.items())[:3]:
                    click.echo(f"      {k}: {v}")
        click.echo()
    
    if high:
        click.echo()
        click.echo(click.style("⚠️  HIGH SEVERITY WARNINGS", fg="yellow", bold=True))
        click.echo("-" * 50)
        for w in high:
            click.echo(f"  {w.emoji} [{w.signal}] {w.message}")
        click.echo()


@click.group()
@click.version_option(version="0.2.0")
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
    help="Path to JSONL log file (auto-detects if not specified)",
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
def check(log: Path | None, security: bool, json_output: bool):
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
    for action in parse_file(log):
        buffer.add(action)
    
    if len(buffer) == 0:
        click.echo("No actions found in log file", err=True)
        sys.exit(1)
    
    # Create registry and run checks
    mode = "all" if security else "health"
    registry = create_registry(mode=mode)
    warnings = registry.check_all(buffer)
    
    # Calculate scores
    report = calculate_health(warnings, include_security=security)
    
    if json_output:
        click.echo(json.dumps(report.to_dict(), indent=2))
    else:
        print_health_report(report, security_mode=security)
        
        # Extra security output
        if security and report.security_warnings:
            print_security_alert(report.security_warnings)
    
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
    help="Path to JSONL log file (auto-detects if not specified)",
)
@click.option(
    "--security", "-s",
    is_flag=True,
    help="Enable security detectors",
)
def watch(log: Path | None, security: bool):
    """Watch agent logs in real-time with a TUI dashboard."""
    # Import here to avoid slow startup for non-watch commands
    from agentwatch.ui.app import AgentWatchApp
    
    # Find log file
    if log is None:
        log = find_latest_session()
        if log is None:
            click.echo("No log files found. Specify a path with --log", err=True)
            sys.exit(1)
    
    app = AgentWatchApp(log_path=log, security_mode=security)
    app.run()


@cli.command()
@click.option(
    "--json", "json_output",
    is_flag=True,
    help="Output as JSON for scripting",
)
@click.option(
    "--flat",
    is_flag=True,
    help="Flat list without tree hierarchy",
)
@click.option(
    "--teams",
    is_flag=True,
    help="Group agents by team",
)
def ps(json_output: bool, flat: bool, teams: bool):
    """Discover and list running AI agent processes."""
    agents = find_running_agents()

    if json_output:
        if teams:
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

    if teams:
        _print_teams_view(agents)
    else:
        _print_agents_view(agents, flat)


def _print_agents_view(agents: list[AgentProcess], flat: bool) -> None:
    """Print agents in tree or flat view."""
    display_agents = agents if flat else build_agent_tree(agents)

    # Table header
    click.echo(
        f"  {'PID':<8}{'TYPE':<14}{'PROJECT':<22}{'CPU':>6}{'MEM':>8}{'STATUS':>10}"
    )

    for a in display_agents:
        if flat or a.depth == 0:
            prefix = ""
        else:
            prefix = "  " * a.depth + "\\-- "

        project = a.project_name
        max_proj_len = max(20 - len(prefix), 6)
        if len(project) > max_proj_len:
            project = project[: max_proj_len - 3] + "..."

        cpu_str = f"{a.cpu_percent:.1f}%"
        mem_str = f"{a.memory_mb:.0f}MB"

        if a.depth > 0 and not flat:
            status = click.style("sub", fg="cyan")
        else:
            status = click.style("active", fg="green")

        proj_col = f"{prefix}{project}"
        click.echo(
            f"  {a.pid:<8}{a.agent_type:<14}{proj_col:<22}{cpu_str:>6}{mem_str:>8}   {status}"
        )

    click.echo()
    root_count = sum(1 for a in agents if a.depth == 0)
    sub_count = sum(1 for a in agents if a.depth > 0)
    if sub_count > 0:
        click.echo(f"  {len(agents)} active agent(s) found ({root_count} root, {sub_count} subagent(s)).")
    else:
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
            f"    {'PID':<8}{'TYPE':<14}{'PROJECT':<20}{'CPU':>6}{'MEM':>8}{'ROLE':>8}"
        )

        for a in team.members:
            if a.depth == 0:
                prefix = ""
                role = click.style("root", fg="green")
            else:
                prefix = "  " * a.depth + "├── "
                role = click.style(f"L{a.depth}", fg="cyan")

            project = a.project_name
            max_proj_len = max(18 - len(prefix), 6)
            if len(project) > max_proj_len:
                project = project[: max_proj_len - 3] + "..."

            cpu_str = f"{a.cpu_percent:.1f}%"
            mem_str = f"{a.memory_mb:.0f}MB"
            proj_col = f"{prefix}{project}"

            click.echo(
                f"    {a.pid:<8}{a.agent_type:<14}{proj_col:<20}{cpu_str:>6}{mem_str:>8}   {role}"
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
def watch_all(security: bool, all_logs: bool):
    """Watch agent logs in real-time with a multi-agent dashboard.

    By default, auto-discovers active agent processes and monitors only their
    log files. Use --all-logs to scan all known log directories instead.
    """
    from agentwatch.ui.multi_app import MultiAgentWatchApp
    from agentwatch.parser.logs import DEFAULT_SEARCH_PATHS

    if all_logs:
        # Legacy behavior: scan all log directories
        watch_paths = [p for p in DEFAULT_SEARCH_PATHS if p.exists()]
        if not watch_paths:
            click.echo("No agent log directories found.", err=True)
            sys.exit(1)
        app = MultiAgentWatchApp(watch_paths=watch_paths, security_mode=security)
    else:
        # Process-based discovery
        agents = build_agent_tree(find_running_agents())
        if not agents:
            click.echo("No running agent processes found.", err=True)
            click.echo("Use --all-logs to scan all log directories instead.", err=True)
            sys.exit(1)
        app = MultiAgentWatchApp(agent_processes=agents, security_mode=security)

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
        for d in detectors:
            click.echo(f"    • {d}")
    
    click.echo()
    click.echo(f"Total: {len(registry.detectors)} detectors")
    click.echo()


@cli.command()
@click.option(
    "--log", "-l",
    type=click.Path(exists=True, path_type=Path),
    help="Path to JSONL log file",
)
@click.option(
    "--json", "json_output",
    is_flag=True,
    help="Output as JSON",
)
def security_scan(log: Path | None, json_output: bool):
    """Run a security-focused scan on agent logs."""
    if log is None:
        log = find_latest_session()
        if log is None:
            click.echo("No log files found. Specify a path with --log", err=True)
            sys.exit(1)
        click.echo(f"Using log: {log}")
    
    # Parse logs
    buffer = ActionBuffer()
    for action in parse_file(log):
        buffer.add(action)
    
    if len(buffer) == 0:
        click.echo("No actions found in log file", err=True)
        sys.exit(1)
    
    # Run only security detectors
    registry = create_registry(mode="security")
    warnings = registry.check_all(buffer)
    
    security_score = calculate_security_score(warnings)
    
    if json_output:
        output = {
            "security_score": security_score,
            "status": "secure" if security_score == 100 else "at_risk" if security_score > 50 else "compromised",
            "warnings": [w.to_dict() for w in warnings],
            "action_count": len(buffer),
        }
        click.echo(json.dumps(output, indent=2))
    else:
        click.echo()
        click.echo("═" * 50)
        click.echo("  SECURITY SCAN RESULTS")
        click.echo("═" * 50)
        click.echo()
        
        if security_score == 100:
            click.echo(click.style("  ✅ SECURE (100%)", fg="green", bold=True))
        elif security_score > 50:
            click.echo(click.style(f"  ⚠️  AT RISK ({security_score}%)", fg="yellow", bold=True))
        else:
            click.echo(click.style(f"  🚨 COMPROMISED ({security_score}%)", fg="red", bold=True))
        
        click.echo()
        click.echo(f"  Analyzed {len(buffer)} actions")
        click.echo(f"  Found {len(warnings)} security issue(s)")
        click.echo()
        
        if warnings:
            print_security_alert(warnings)
    
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

    for name, theme in THEMES.items():
        is_default = " (default)" if name == "agent" else ""
        click.echo(click.style(f"  {name}{is_default}", bold=True))
        click.echo(f"    {theme.emoji_0} {theme.level_0} → {theme.emoji_1} {theme.level_1} → {theme.emoji_2} {theme.level_2} → {theme.emoji_3} {theme.level_3}")
        click.echo()

    click.echo("Use --theme <name> to select a theme.")
    click.echo()


def main():
    """Main entry point for agentwatch CLI."""
    cli()


def security_main():
    """Entry point for agentguard CLI (security-focused)."""
    # Override defaults to always include security
    @click.group()
    @click.version_option(version="0.2.0")
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
    
    guard_cli()


if __name__ == "__main__":
    main()
