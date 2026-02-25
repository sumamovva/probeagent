"""ProbeAgent CLI — Typer-based command-line interface."""

from __future__ import annotations

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from probeagent import __version__
from probeagent.attacks import ATTACK_REGISTRY
from probeagent.core.engine import AttackEngine
from probeagent.core.models import OutputFormat, ProbeConfig, Severity
from probeagent.core.reporter import Reporter
from probeagent.core.scoring import calculate_resilience_score
from probeagent.targets.base import Target
from probeagent.targets.http_target import HTTPTarget
from probeagent.targets.openclaw_target import OpenClawTarget
from probeagent.utils.config import load_env, load_profile, write_default_config

_TARGET_TYPES = {
    "http": HTTPTarget,
    "openclaw": OpenClawTarget,
}

console = Console()

_SEVERITY_COLORS = {
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"probeagent {__version__}")
        raise typer.Exit()


app = typer.Typer(
    name="probeagent",
    help="Offensive security testing for AI agents.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """ProbeAgent — Offensive security testing for AI agents."""


@app.command()
def attack(
    target_url: str = typer.Argument(..., help="URL of the target agent to attack."),
    profile: str = typer.Option("quick", "--profile", "-p", help="Attack profile name."),
    target_type: str = typer.Option("http", "--target-type", help="Target type: http, openclaw."),
    output: str = typer.Option(
        "terminal", "--output", "-o", help="Output format: terminal, markdown, json."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output-file", "-f", help="Write report to file."
    ),
    timeout: float = typer.Option(30.0, "--timeout", "-t", help="Request timeout in seconds."),
) -> None:
    """Run security attacks against a target AI agent."""
    load_env()

    # Load profile
    try:
        profile_data = load_profile(profile)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    output_format = OutputFormat(output)

    config = ProbeConfig(
        target_url=target_url,
        profile=profile,
        attacks=profile_data.get("attacks", []),
        max_turns=profile_data.get("max_turns", 1),
        attacker_model=profile_data.get("attacker_model", "gpt-4"),
        target_type=target_type,
        output_format=output_format,
        output_file=output_file,
        timeout=timeout,
    )

    # Resolve target class
    target_cls = _TARGET_TYPES.get(target_type)
    if target_cls is None:
        console.print(f"[red]Error:[/red] Unknown target type '{target_type}'. Use: {', '.join(_TARGET_TYPES)}")
        raise typer.Exit(1)

    # Show config
    config_text = (
        f"Target:   {config.target_url}\n"
        f"Type:     {target_type}\n"
        f"Profile:  {config.profile}\n"
        f"Attacks:  {', '.join(config.attacks)}\n"
        f"Turns:    {config.max_turns}\n"
        f"Timeout:  {config.timeout}s"
    )
    console.print(Panel(config_text, title="Attack Configuration", border_style="blue"))

    # Validate target
    target = target_cls(target_url, timeout=timeout)
    info = asyncio.run(_validate_target(target))
    asyncio.run(target.close())

    if not info.reachable:
        console.print(f"\n[red]Target unreachable:[/red] {info.error}")
        raise typer.Exit(1)

    console.print(
        f"\n[green]Target reachable[/green] — "
        f"format: {info.detected_format}, "
        f"latency: {info.response_time_ms}ms"
    )

    # Run attacks
    console.print("\n[bold]Running attacks...[/bold]\n")
    engine = AttackEngine(config)

    try:
        results = asyncio.run(engine.run())
    except ConnectionError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Attack engine error:[/red] {e}")
        raise typer.Exit(1)

    # Score and report
    score = calculate_resilience_score(results)
    reporter = Reporter()
    report_text = reporter.report(score, info, config, output_format, output_file)

    if output_format == OutputFormat.TERMINAL:
        console.print(report_text)
    else:
        console.print(report_text)
        if output_file:
            console.print(f"\n[green]Report written to:[/green] {output_file}")


@app.command("list-attacks")
def list_attacks() -> None:
    """List all available attack modules."""
    table = Table(title="Available Attacks", show_lines=True)
    table.add_column("Name", style="bold")
    table.add_column("Severity")
    table.add_column("Description")

    for name, info in ATTACK_REGISTRY.items():
        severity = info["severity"]
        color = _SEVERITY_COLORS.get(severity, "white")
        table.add_row(
            info["display_name"],
            Text(severity.value.upper(), style=color),
            info["description"],
        )

    console.print(table)


@app.command()
def validate(
    target_url: str = typer.Argument(..., help="URL of the target to validate."),
    target_type: str = typer.Option("http", "--target-type", help="Target type: http, openclaw."),
    timeout: float = typer.Option(30.0, "--timeout", "-t", help="Request timeout in seconds."),
) -> None:
    """Validate connectivity and detect format of a target."""
    target_cls = _TARGET_TYPES.get(target_type)
    if target_cls is None:
        console.print(f"[red]Error:[/red] Unknown target type '{target_type}'. Use: {', '.join(_TARGET_TYPES)}")
        raise typer.Exit(1)
    target = target_cls(target_url, timeout=timeout)
    info = asyncio.run(_validate_target(target))
    asyncio.run(target.close())

    if info.reachable:
        panel_text = (
            f"URL:             {info.url}\n"
            f"Reachable:       [green]Yes[/green]\n"
            f"Status Code:     {info.status_code}\n"
            f"Format:          {info.detected_format}\n"
            f"Response Time:   {info.response_time_ms}ms"
        )
        console.print(Panel(panel_text, title="Target Validation", border_style="green"))
    else:
        panel_text = (
            f"URL:        {info.url}\n"
            f"Reachable:  [red]No[/red]\n"
            f"Error:      {info.error}"
        )
        console.print(Panel(panel_text, title="Target Validation", border_style="red"))
        raise typer.Exit(1)


@app.command()
def init() -> None:
    """Create a default .probeagent.yaml config file in the current directory."""
    path = write_default_config()
    console.print(f"[green]Created config:[/green] {path}")


async def _validate_target(target: Target):
    return await target.validate()
