"""Report rendering — terminal (Rich), Markdown, and JSON output."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from probeagent import __version__
from probeagent.core.models import (
    AttackOutcome,
    OutputFormat,
    ProbeConfig,
    ResilienceGrade,
    ResilienceScore,
    Severity,
    TargetInfo,
)

_GRADE_COLORS = {
    ResilienceGrade.A: "green",
    ResilienceGrade.B: "cyan",
    ResilienceGrade.C: "yellow",
    ResilienceGrade.D: "red",
    ResilienceGrade.F: "red",
}

_SEVERITY_COLORS = {
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}

_OUTCOME_COLORS = {
    AttackOutcome.SUCCEEDED: "red",
    AttackOutcome.FAILED: "green",
    AttackOutcome.ERROR: "yellow",
    AttackOutcome.SKIPPED: "dim",
    AttackOutcome.UNDETERMINED: "yellow",
}


class Reporter:
    """Renders resilience reports in multiple formats."""

    def report(
        self,
        score: ResilienceScore,
        target_info: TargetInfo,
        config: ProbeConfig,
        output_format: OutputFormat = OutputFormat.TERMINAL,
        output_file: str | None = None,
    ) -> str:
        """Generate a report and optionally write it to a file.

        Returns the rendered report as a string.
        """
        if output_format == OutputFormat.TERMINAL:
            text = self._render_terminal(score, target_info, config)
        elif output_format == OutputFormat.MARKDOWN:
            text = self._render_markdown(score, target_info, config)
        elif output_format == OutputFormat.JSON:
            text = self._render_json(score, target_info, config)
        else:
            text = self._render_terminal(score, target_info, config)

        if output_file:
            Path(output_file).write_text(text)

        return text

    def _render_terminal(
        self,
        score: ResilienceScore,
        target_info: TargetInfo,
        config: ProbeConfig,
    ) -> str:
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=100)

        # Header
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        header_text = (
            f"Target:  {target_info.url}\n"
            f"Profile: {config.profile}\n"
            f"Time:    {now}"
        )
        console.print(Panel(header_text, title="ProbeAgent Report", border_style="blue"))

        # Score card
        color = _GRADE_COLORS.get(score.grade, "white")
        grade_text = Text(f"  {score.grade.value}  ", style=f"bold {color}")
        score_detail = (
            f"Total: {score.total}  |  "
            f"Succeeded: {score.succeeded}  |  "
            f"Failed: {score.failed}  |  "
            f"Errors: {score.errors}"
        )
        console.print(Panel(grade_text, title="Resilience Grade", border_style=color))
        console.print(f"  {score_detail}\n")

        # Attack results table
        if score.summaries:
            table = Table(title="Attack Results", show_lines=True)
            table.add_column("Attack", style="bold")
            table.add_column("Severity")
            table.add_column("Outcome")
            table.add_column("Success Rate")

            for s in score.summaries:
                sev_color = _SEVERITY_COLORS.get(s.severity, "white")
                rate = f"{s.success_rate:.0%}"
                outcome_str = f"{s.succeeded}/{s.total} succeeded"
                table.add_row(
                    s.display_name,
                    Text(s.severity.value.upper(), style=sev_color),
                    outcome_str,
                    rate,
                )
            console.print(table)
            console.print()

        # Successful attack transcripts
        succeeded_results = [
            r for r in score.raw_results if r.outcome == AttackOutcome.SUCCEEDED
        ]
        if succeeded_results:
            console.print(
                Panel("[bold red]Successful Attacks[/bold red]", border_style="red")
            )
            for r in succeeded_results[:10]:
                console.print(f"  [bold]{r.attack_name}[/bold]")
                if r.turns:
                    for turn in r.turns[:10]:
                        content = turn.content[:200]
                        if len(turn.content) > 200:
                            content += "..."
                        console.print(f"    [{turn.role}] {content}")
                elif r.transcript:
                    t = r.transcript[:200]
                    if len(r.transcript) > 200:
                        t += "..."
                    console.print(f"    {t}")
                console.print()

        return buf.getvalue()

    def _render_markdown(
        self,
        score: ResilienceScore,
        target_info: TargetInfo,
        config: ProbeConfig,
    ) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines = [
            "# ProbeAgent Security Report",
            "",
            f"**Target:** {target_info.url}",
            f"**Profile:** {config.profile}",
            f"**Timestamp:** {now}",
            f"**ProbeAgent Version:** {__version__}",
            "",
            "## Resilience Grade",
            "",
            f"**Grade: {score.grade.value}**",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Total | {score.total} |",
            f"| Succeeded | {score.succeeded} |",
            f"| Failed | {score.failed} |",
            f"| Errors | {score.errors} |",
            f"| Skipped | {score.skipped} |",
            "",
        ]

        if score.summaries:
            lines.extend([
                "## Attack Summary",
                "",
                "| Attack | Severity | Succeeded | Total | Success Rate |",
                "|--------|----------|-----------|-------|-------------|",
            ])
            for s in score.summaries:
                rate = f"{s.success_rate:.0%}"
                lines.append(
                    f"| {s.display_name} | {s.severity.value.upper()} "
                    f"| {s.succeeded} | {s.total} | {rate} |"
                )
            lines.append("")

        succeeded_results = [
            r for r in score.raw_results if r.outcome == AttackOutcome.SUCCEEDED
        ]
        if succeeded_results:
            lines.extend(["## Successful Attack Details", ""])
            for r in succeeded_results:
                lines.append(f"### {r.attack_name}")
                lines.append("")
                if r.score_rationale:
                    lines.append(f"**Rationale:** {r.score_rationale}")
                    lines.append("")
                if r.turns:
                    lines.append("**Transcript:**")
                    lines.append("```")
                    for turn in r.turns:
                        lines.append(f"[{turn.role}] {turn.content}")
                    lines.append("```")
                elif r.transcript:
                    lines.append("**Transcript:**")
                    lines.append(f"```\n{r.transcript}\n```")
                lines.append("")

        return "\n".join(lines)

    def _render_json(
        self,
        score: ResilienceScore,
        target_info: TargetInfo,
        config: ProbeConfig,
    ) -> str:
        now = datetime.now(timezone.utc).isoformat()
        data = {
            "probeagent_version": __version__,
            "timestamp": now,
            "target": {
                "url": target_info.url,
                "reachable": target_info.reachable,
                "response_time_ms": target_info.response_time_ms,
                "detected_format": target_info.detected_format,
            },
            "config": {
                "profile": config.profile,
                "attacks": config.attacks,
                "max_turns": config.max_turns,
                "attacker_model": config.attacker_model,
            },
            "resilience_score": {
                "grade": score.grade.value,
                "total": score.total,
                "succeeded": score.succeeded,
                "failed": score.failed,
                "errors": score.errors,
                "skipped": score.skipped,
                "highest_severity_succeeded": (
                    score.highest_severity_succeeded.value
                    if score.highest_severity_succeeded
                    else None
                ),
            },
            "attack_summaries": [
                {
                    "attack_name": s.attack_name,
                    "display_name": s.display_name,
                    "severity": s.severity.value,
                    "total": s.total,
                    "succeeded": s.succeeded,
                    "failed": s.failed,
                    "success_rate": s.success_rate,
                }
                for s in score.summaries
            ],
            "attack_results": [
                {
                    "id": r.id,
                    "attack_name": r.attack_name,
                    "outcome": r.outcome.value,
                    "severity": r.severity.value,
                    "success": r.success,
                    "execution_time": r.execution_time,
                    "score_rationale": r.score_rationale,
                    "error": r.error,
                    "turns": [
                        {"role": t.role, "content": t.content} for t in r.turns
                    ],
                    "metadata": r.metadata,
                }
                for r in score.raw_results
            ],
        }
        return json.dumps(data, indent=2)
