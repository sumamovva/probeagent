# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""ProbeAgent CLI — Typer-based command-line interface."""

from __future__ import annotations

import asyncio
import time
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from probeagent import __version__
from probeagent.attacks import ATTACK_REGISTRY
from probeagent.core.engine import AttackEngine
from probeagent.core.frameworks import primary_codes
from probeagent.core.models import (
    OutputFormat,
    ProbeConfig,
    ResilienceScore,
    Severity,
    TargetInfo,
    Verdict,
)
from probeagent.core.reporter import Reporter
from probeagent.core.scoring import (
    FAIL_ON_CHOICES,
    FAIL_ON_DEFAULT,
    calculate_resilience_score,
    meets_fail_threshold,
)
from probeagent.targets.base import Target
from probeagent.targets.http_target import HTTPTarget
from probeagent.targets.mcp_target import MCPTarget
from probeagent.targets.mock_target import MockTarget
from probeagent.targets.openclaw_target import OpenClawTarget
from probeagent.utils.config import load_env, load_profile, write_default_config


def _parse_headers(raw: list[str] | None) -> dict[str, str]:
    """Parse 'Key: Value' or 'Key=Value' header strings into a dict."""
    if not raw:
        return {}
    headers: dict[str, str] = {}
    for item in raw:
        for sep in (":", "="):
            if sep in item:
                k, v = item.split(sep, 1)
                headers[k.strip()] = " ".join(v.split())
                break
        else:
            raise typer.BadParameter(f"Invalid header format: {item!r} (use 'Key: Value')")
    return headers


def _format_elapsed(seconds: float) -> str:
    """Format elapsed seconds as M:SS."""
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}:{secs:02d}"


_TARGET_TYPES = {
    "http": HTTPTarget,
    "openclaw": OpenClawTarget,
    "mock": MockTarget,
    "mcp": MCPTarget,
}

console = Console()
# Human chrome (config panel, progress, status lines) is routed here in machine-output
# modes so stdout carries ONLY the report and stays pipeable, e.g. `-o json | jq`.
err_console = Console(stderr=True)

# CI-meaningful exit codes.
EXIT_OK = 0  # scan completed, nothing at/above --fail-on
EXIT_FINDINGS = 1  # findings at or above --fail-on
EXIT_EXECUTION_ERROR = 2  # unreachable target, bad config/auth, engine crash

_SEVERITY_COLORS = {
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}

_VERDICT_COLORS = {
    Verdict.COMPROMISED: "red",
    Verdict.RESISTED: "green",
    Verdict.BLOCKED: "yellow",
}


def _verdict_label(verdict: Verdict | None) -> str:
    return verdict.value if verdict is not None else "No verdict"


def _verdict_style(score: ResilienceScore) -> str:
    return _VERDICT_COLORS.get(score.headline_verdict, "white")


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
        "terminal", "--output", "-o", help="Output format: terminal, markdown, json, log."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output-file", "-f", help="Write report to file."
    ),
    timeout: float = typer.Option(30.0, "--timeout", "-t", help="Request timeout in seconds."),
    parallel: bool = typer.Option(False, "--parallel", help="Run attack categories in parallel."),
    converters: Optional[str] = typer.Option(
        None,
        "--converters",
        "-c",
        help="Evasion converters, comma-separated or a preset (basic, advanced, stealth).",
    ),
    redteam: bool = typer.Option(
        False,
        "--redteam",
        help="Dynamic red-team via PyRIT's adaptive attacker (requires the 'pyrit' extra).",
    ),
    header: Optional[list[str]] = typer.Option(
        None,
        "--header",
        "-H",
        help="HTTP header as 'Key: Value' (repeatable, e.g. -H 'Authorization: Bearer token').",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        "-m",
        help=(
            "Model id sent in the request body for OpenAI-compatible endpoints "
            "(e.g. anthropic/claude-3.5-sonnet for OpenRouter). HTTP targets only."
        ),
    ),
    seeds: Optional[str] = typer.Option(
        None,
        "--seeds",
        help="Path to an attack-seed corpus (jsonl/json/yaml/txt) run as the seed_corpus attack.",
    ),
    fail_on: str = typer.Option(
        FAIL_ON_DEFAULT,
        "--fail-on",
        help=(
            "Exit non-zero (1) when an attack grades at or above this verdict: "
            "compromised (default), blocked, resisted, or never. Blocked is opt-in."
        ),
    ),
) -> None:
    """Run security attacks against a target AI agent.

    Exit codes: 0 = scan completed, nothing at/above --fail-on; 1 = findings at or
    above --fail-on; 2 = execution error (unreachable target, bad config, crash).
    """
    load_env()

    # Validate config up front — bad config is an execution error (exit 2).
    if fail_on not in FAIL_ON_CHOICES:
        console.print(
            f"[red]Error:[/red] Invalid --fail-on '{fail_on}'. Use: {', '.join(FAIL_ON_CHOICES)}"
        )
        raise typer.Exit(EXIT_EXECUTION_ERROR)
    try:
        output_format = OutputFormat(output)
    except ValueError:
        console.print(
            f"[red]Error:[/red] Invalid --output '{output}'. "
            f"Use: {', '.join(f.value for f in OutputFormat)}"
        )
        raise typer.Exit(EXIT_EXECUTION_ERROR)

    try:
        parsed_headers = _parse_headers(header)
    except typer.BadParameter as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(EXIT_EXECUTION_ERROR)

    # Load profile
    try:
        profile_data = load_profile(profile)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(EXIT_EXECUTION_ERROR)

    # Parse converter argument
    converter_list = None
    if converters:
        from probeagent.integrations.converters import parse_converter_arg

        converter_list = parse_converter_arg(converters)

    # Load an external seed corpus into the seed_corpus attack, if requested.
    attacks_list = list(profile_data.get("attacks", []))
    if seeds:
        from probeagent.attacks.seed_corpus import SeedCorpusAttack
        from probeagent.core.seeds import load_seeds

        try:
            SeedCorpusAttack.STRATEGIES = load_seeds(seeds)
        except (FileNotFoundError, ValueError) as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(EXIT_EXECUTION_ERROR)
        if "seed_corpus" not in attacks_list:
            attacks_list.append("seed_corpus")
        console.print(
            f"[green]Loaded[/green] {len(SeedCorpusAttack.STRATEGIES)} seed(s) from {seeds}"
        )

    config = ProbeConfig(
        target_url=target_url,
        profile=profile,
        attacks=attacks_list,
        max_turns=profile_data.get("max_turns", 1),
        attacker_model=profile_data.get("attacker_model", "gpt-4"),
        target_type=target_type,
        output_format=output_format,
        output_file=output_file,
        timeout=timeout,
        parallel=parallel,
        converters=converter_list,
        redteam=redteam,
        headers=parsed_headers,
        model=model,
        seeds=seeds,
    )

    # Resolve target class
    target_cls = _TARGET_TYPES.get(target_type)
    if target_cls is None:
        console.print(
            f"[red]Error:[/red] Unknown target type '{target_type}'. Use: {', '.join(_TARGET_TYPES)}"
        )
        raise typer.Exit(EXIT_EXECUTION_ERROR)

    # Show config
    config_text = (
        f"Target:   {config.target_url}\n"
        f"Type:     {target_type}\n"
        f"Profile:  {config.profile}\n"
        f"Attacks:  {', '.join(config.attacks)}\n"
        f"Turns:    {config.max_turns}\n"
        f"Timeout:  {config.timeout}s\n"
        f"Parallel: {'Yes' if config.parallel else 'No'}"
    )
    if config.model:
        config_text += f"\nModel:    {config.model}"
    # In machine-output modes, all human chrome goes to stderr so stdout is pure report.
    chrome = console if output_format == OutputFormat.TERMINAL else err_console
    chrome.print(Panel(config_text, title="Attack Configuration", border_style="blue"))

    # Validate target
    target_kwargs: dict = {"timeout": timeout, "headers": parsed_headers}
    # Only HTTPTarget accepts model=; mock/openclaw would raise TypeError.
    if config.model and target_cls is HTTPTarget:
        target_kwargs["model"] = config.model
    target = target_cls(target_url, **target_kwargs)
    info = asyncio.run(_validate_target(target))

    if not info.reachable:
        chrome.print(f"\n[red]Target unreachable:[/red] {info.error}")
        raise typer.Exit(EXIT_EXECUTION_ERROR)

    chrome.print(
        f"\n[green]Target reachable[/green] — "
        f"format: {info.detected_format}, "
        f"latency: {info.response_time_ms}ms"
    )

    # Run attacks
    status = chrome.status("[bold]Running attacks...[/bold]", spinner="dots")
    start_time = time.monotonic()
    status.start()

    def on_progress(name: str, current: int, total: int, results: list) -> None:
        elapsed = _format_elapsed(time.monotonic() - start_time)
        compromised = sum(1 for r in results if r.verdict == Verdict.COMPROMISED)
        resisted = sum(1 for r in results if r.verdict == Verdict.RESISTED)
        blocked = sum(1 for r in results if r.verdict == Verdict.BLOCKED)
        verdicts = f"  {compromised}C {resisted}R {blocked}B" if results else ""
        status.update(
            f"[bold]Attacking[/bold] [cyan]{name}[/cyan] ({current}/{total})"
            f" · {elapsed} elapsed{verdicts}"
        )

    engine = AttackEngine(config, on_progress=on_progress)

    try:
        results = asyncio.run(engine.run())
    except ConnectionError as e:
        status.stop()
        chrome.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(EXIT_EXECUTION_ERROR)
    except Exception as e:
        status.stop()
        chrome.print(f"[red]Attack engine error:[/red] {e}")
        raise typer.Exit(EXIT_EXECUTION_ERROR)
    finally:
        status.stop()

    # Score and report
    score = calculate_resilience_score(results)
    reporter = Reporter()
    report_text = reporter.report(score, info, config, output_format, output_file)

    # The report goes to stdout. In machine modes write it RAW via print() — routing it
    # through console.print would mangle JSON (brackets parse as rich markup, long lines
    # soft-wrap). Chrome goes to stderr so `-o json | jq` sees only clean JSON.
    if output_format == OutputFormat.TERMINAL:
        console.print(report_text)
    else:
        print(report_text)
        if output_file:
            chrome.print(f"\n[green]Report written to:[/green] {output_file}")

    # CI gate: fail (exit 1) when findings reach the --fail-on threshold. The scan
    # itself completed successfully, so this is distinct from an execution error (2).
    if meets_fail_threshold(score, fail_on):
        chrome.print(
            f"\n[red]FAIL:[/red] findings at or above --fail-on '{fail_on}' "
            f"({score.compromised} Compromised · {score.blocked} Blocked · "
            f"{score.resisted} Resisted)."
        )
        raise typer.Exit(EXIT_FINDINGS)

    # No attack produced a gradeable verdict — every one errored or was skipped, so
    # the target was never actually exercised. This must NOT read as a clean pass:
    # a broken/misrouted target (e.g. all 404/502) would otherwise turn CI green.
    if score.headline_verdict is None and score.total > 0:
        chrome.print(
            f"\n[red]ERROR:[/red] no attack produced a gradeable result "
            f"({score.errors} errored of {score.total}). The target was not exercised — "
            "this is not a pass. Check the target URL/path (OpenAI-compatible agents "
            "usually need /v1/chat/completions) and that the target is reachable."
        )
        raise typer.Exit(EXIT_EXECUTION_ERROR)
    raise typer.Exit(EXIT_OK)


@app.command("list-attacks")
def list_attacks(
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit attack metadata as JSON.",
    ),
) -> None:
    """List all available attack modules."""
    if json_output:
        import json

        attacks = [
            {
                "name": name,
                "display_name": info["display_name"],
                "severity": info["severity"].value,
                "framework_tags": list(info.get("framework_tags", ())),
                "atlas_tags": list(info.get("atlas_tags", ())),
                "description": info["description"],
            }
            for name, info in ATTACK_REGISTRY.items()
        ]
        typer.echo(json.dumps(attacks))
        return

    table = Table(title="Available Attacks", show_lines=True)
    table.add_column("Name", style="bold")
    table.add_column("Severity")
    table.add_column("OWASP")
    table.add_column("Description")

    for name, info in ATTACK_REGISTRY.items():
        severity = info["severity"]
        color = _SEVERITY_COLORS.get(severity, "white")
        owasp = " ".join(primary_codes(info.get("framework_tags", ()))) or "—"
        table.add_row(
            info["display_name"],
            Text(severity.value.upper(), style=color),
            Text(owasp, style="cyan"),
            info["description"],
        )

    console.print(table)


@app.command()
def validate(
    target_url: str = typer.Argument(..., help="URL of the target to validate."),
    target_type: str = typer.Option("http", "--target-type", help="Target type: http, openclaw."),
    timeout: float = typer.Option(30.0, "--timeout", "-t", help="Request timeout in seconds."),
    header: Optional[list[str]] = typer.Option(
        None,
        "--header",
        "-H",
        help="HTTP header as 'Key: Value' (repeatable).",
    ),
) -> None:
    """Validate connectivity and detect format of a target."""
    parsed_headers = _parse_headers(header)
    target_cls = _TARGET_TYPES.get(target_type)
    if target_cls is None:
        console.print(
            f"[red]Error:[/red] Unknown target type '{target_type}'. Use: {', '.join(_TARGET_TYPES)}"
        )
        raise typer.Exit(1)
    target = target_cls(target_url, timeout=timeout, headers=parsed_headers)
    info = asyncio.run(_validate_target(target))

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
        panel_text = f"URL:        {info.url}\nReachable:  [red]No[/red]\nError:      {info.error}"
        console.print(Panel(panel_text, title="Target Validation", border_style="red"))
        raise typer.Exit(1)


@app.command()
def game(
    target_url: str = typer.Argument(
        None, help="URL of the target agent (can also enter in browser)."
    ),
    profile: str = typer.Option(
        "quick", "--profile", "-p", help="Attack profile: quick, standard, thorough."
    ),
    target_type: str = typer.Option("http", "--target-type", help="Target type: http, openclaw."),
    port: int = typer.Option(1337, "--port", help="Port for the game UI server."),
    header: Optional[list[str]] = typer.Option(
        None,
        "--header",
        "-H",
        help="HTTP header as 'Key: Value' (repeatable).",
    ),
) -> None:
    """Launch the Tactical Display UI in your browser."""
    try:
        import uvicorn
    except ImportError:
        console.print(
            "[red]Error:[/red] Missing dependencies. Install with:\n"
            "  pip install 'probeagent-ai[game]'"
        )
        raise typer.Exit(1)

    import json
    import threading
    import webbrowser

    from probeagent.web.server import PREFILL_PATH, app as web_app

    # Write pre-fill config to temp file (file-based IPC — most reliable mechanism)
    parsed_headers = _parse_headers(header)
    prefill_data = {"profile": profile, "type": target_type}
    if target_url:
        prefill_data["target"] = target_url
        prefill_data["autostart"] = "1"
    if parsed_headers:
        prefill_data["headers"] = parsed_headers
    PREFILL_PATH.write_text(json.dumps(prefill_data))

    url = f"http://localhost:{port}"

    console.print("\n[bold green]PROBE://AGENT[/bold green] — Tactical Display Mode\n")
    console.print(f"  Game UI: [cyan]{url}[/cyan]\n")

    # Open browser after a short delay to let server start
    threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    uvicorn.run(web_app, host="0.0.0.0", port=port, log_level="warning")


@app.command()
def demo(
    live: bool = typer.Option(False, "--live", help="Use real API (starts demo email agent)."),
    game: bool = typer.Option(False, "--game", help="Launch Tactical Display UI after attacks."),
    profile: str = typer.Option("quick", "--profile", "-p", help="Attack profile name."),
) -> None:
    """Run a full demo — attack a vulnerable + hardened target and compare results."""
    import subprocess
    import sys
    import time

    load_env()

    agent_proc = None
    vuln_url: str
    hard_url: str
    target_type: str

    if live:
        # Start the real demo agent server
        import pathlib

        demo_script = pathlib.Path("tools/demo_email_agent.py")
        if not demo_script.exists():
            console.print(
                "[red]Error:[/red] Demo agent script not found (tools/demo_email_agent.py).\n"
                "The --live flag requires a local checkout of the repository.\n"
                "See: https://github.com/sumamovva/probeagent"
            )
            raise typer.Exit(1)

        console.print("\n[bold]Starting demo email agent...[/bold]")

        agent_proc = subprocess.Popen(
            [sys.executable, str(demo_script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for health check
        import httpx

        for i in range(30):
            try:
                r = httpx.get("http://localhost:8000/", timeout=2)
                if r.status_code == 200:
                    console.print("[green]Agent server ready.[/green]")
                    break
            except Exception:
                pass
            if i == 29:
                console.print("[red]Error: Agent server failed to start within 30s.[/red]")
                if agent_proc:
                    agent_proc.terminate()
                raise typer.Exit(1)
            time.sleep(1)

        vuln_url = "http://localhost:8000/webhook/email-agent"
        hard_url = "http://localhost:8000/webhook/email-agent-hardened"
        target_type = "openclaw"
    else:
        vuln_url = "mock://vulnerable"
        hard_url = "mock://hardened"
        target_type = "mock"

    try:
        # Load profile
        try:
            profile_data = load_profile(profile)
        except FileNotFoundError as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(1)

        attacks = profile_data.get("attacks", [])
        max_turns = profile_data.get("max_turns", 1)

        # ── Attack vulnerable target ──
        console.print(f"\n[bold red]{'=' * 50}[/bold red]")
        console.print("[bold red]  ATTACKING VULNERABLE TARGET[/bold red]")
        console.print(f"[bold red]{'=' * 50}[/bold red]\n")

        vuln_config = ProbeConfig(
            target_url=vuln_url,
            profile=profile,
            attacks=attacks,
            max_turns=max_turns,
            target_type=target_type,
            parallel=True,
        )
        vuln_engine = AttackEngine(vuln_config)
        vuln_results = asyncio.run(vuln_engine.run())
        vuln_score = calculate_resilience_score(vuln_results)

        reporter = Reporter()
        vuln_info = TargetInfo(url=vuln_url, reachable=True, detected_format=target_type)
        vuln_report = reporter.report(vuln_score, vuln_info, vuln_config, OutputFormat.TERMINAL)
        console.print(vuln_report)

        # ── Attack hardened target ──
        console.print(f"\n[bold green]{'=' * 50}[/bold green]")
        console.print("[bold green]  ATTACKING HARDENED TARGET[/bold green]")
        console.print(f"[bold green]{'=' * 50}[/bold green]\n")

        hard_config = ProbeConfig(
            target_url=hard_url,
            profile=profile,
            attacks=attacks,
            max_turns=max_turns,
            target_type=target_type,
            parallel=True,
        )
        hard_engine = AttackEngine(hard_config)
        hard_results = asyncio.run(hard_engine.run())
        hard_score = calculate_resilience_score(hard_results)

        hard_info = TargetInfo(url=hard_url, reachable=True, detected_format=target_type)
        hard_report = reporter.report(hard_score, hard_info, hard_config, OutputFormat.TERMINAL)
        console.print(hard_report)

        # ── Side-by-side comparison ──
        console.print(f"\n[bold]{'=' * 50}[/bold]")
        console.print("[bold]  COMPARISON[/bold]")
        console.print(f"[bold]{'=' * 50}[/bold]\n")

        comp_table = Table(title="Vulnerable vs Hardened", show_lines=True)
        comp_table.add_column("Metric", style="bold")
        comp_table.add_column("Vulnerable", justify="center")
        comp_table.add_column("Hardened", justify="center")

        comp_table.add_row(
            "Verdict",
            Text(_verdict_label(vuln_score.headline_verdict), style=_verdict_style(vuln_score)),
            Text(_verdict_label(hard_score.headline_verdict), style=_verdict_style(hard_score)),
        )
        comp_table.add_row(
            "Compromised",
            str(vuln_score.compromised),
            str(hard_score.compromised),
        )
        comp_table.add_row(
            "Resisted",
            str(vuln_score.resisted),
            str(hard_score.resisted),
        )
        comp_table.add_row(
            "Blocked",
            str(vuln_score.blocked),
            str(hard_score.blocked),
        )
        comp_table.add_row(
            "Total",
            str(vuln_score.total),
            str(hard_score.total),
        )
        console.print(comp_table)

        # ── Save report ──
        report_path = "demo_report.md"
        combined_report = reporter.report(vuln_score, vuln_info, vuln_config, OutputFormat.MARKDOWN)
        combined_report += "\n\n---\n\n"
        combined_report += reporter.report(
            hard_score, hard_info, hard_config, OutputFormat.MARKDOWN
        )
        with open(report_path, "w") as f:
            f.write(combined_report)
        console.print(f"\n[green]Report saved to:[/green] {report_path}")

        # ── Launch Tactical Display if requested ──
        if game:
            console.print("\n[bold]Launching Tactical Display...[/bold]")
            # Reuse the game command logic
            try:
                import uvicorn
            except ImportError:
                console.print(
                    "[red]Error:[/red] Missing dependencies. Install with:\n"
                    "  pip install 'probeagent-ai[game]'"
                )
                raise typer.Exit(1)

            import json
            import threading
            import webbrowser

            from probeagent.web.server import PREFILL_PATH, app as web_app

            prefill_data = {"profile": profile, "type": target_type}
            prefill_data["target"] = vuln_url
            PREFILL_PATH.write_text(json.dumps(prefill_data))

            url = "http://localhost:1337"
            console.print("\n[bold green]PROBE://AGENT[/bold green] — Tactical Display Mode")
            console.print(f"  Game UI: [cyan]{url}[/cyan]\n")
            threading.Timer(1.5, lambda: webbrowser.open(url)).start()
            uvicorn.run(web_app, host="0.0.0.0", port=1337, log_level="warning")

    finally:
        if agent_proc:
            console.print("\n[dim]Stopping demo agent server...[/dim]")
            agent_proc.terminate()
            agent_proc.wait(timeout=5)


@app.command()
def init() -> None:
    """Create a default .probeagent.yaml config file in the current directory."""
    path = write_default_config()
    console.print(f"[green]Created config:[/green] {path}")


async def _validate_target(target: Target):
    try:
        return await target.validate()
    finally:
        await target.close()
