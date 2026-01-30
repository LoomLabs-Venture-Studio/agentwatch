"""Command-line interface for agentwatch."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from agentwatch.detectors import create_registry
from agentwatch.discovery import AgentProcess, find_running_agents
from agentwatch.health import calculate_health, calculate_security_score
from agentwatch.parser import ActionBuffer, find_latest_session, parse_file, find_log_files


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
    
    # Overall score
    status_color = {
        "healthy": "green",
        "degraded": "yellow",
        "warning": "bright_yellow",
        "critical": "red",
    }
    click.echo(
        f"  Overall:   {report.emoji} "
        + click.style(
            f"{report.status.upper()} ({report.overall_score}%)",
            fg=status_color[report.status],
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
def cli():
    """AgentWatch - Health and security monitoring for AI agents."""
    pass


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
    
    # Exit code based on status
    if report.status == "critical":
        sys.exit(2)
    elif report.status == "warning":
        sys.exit(1)
    sys.exit(0)  # healthy and degraded


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
def ps(json_output: bool):
    """Discover and list running AI agent processes."""
    agents = find_running_agents()

    if json_output:
        output = []
        for a in agents:
            output.append({
                "pid": a.pid,
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

    # Table header
    click.echo(
        f"  {'PID':<8}{'TYPE':<14}{'PROJECT':<22}{'CPU':>6}{'MEM':>8}{'STATUS':>10}"
    )

    for a in agents:
        project = a.project_name
        if len(project) > 20:
            project = project[:17] + "..."
        cpu_str = f"{a.cpu_percent:.1f}%"
        mem_str = f"{a.memory_mb:.0f}MB"
        status = click.style("active", fg="green")
        click.echo(
            f"  {a.pid:<8}{a.agent_type:<14}{project:<22}{cpu_str:>6}{mem_str:>8}   {status}"
        )

    click.echo()
    click.echo(f"  {len(agents)} active agent(s) found.")
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
        agents = find_running_agents()
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
