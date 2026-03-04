"""Tests for report rendering."""

import json
import tempfile
from pathlib import Path

from probeagent.core.models import (
    OutputFormat,
    ProbeConfig,
    TargetInfo,
)
from probeagent.core.reporter import Reporter
from probeagent.core.scoring import calculate_resilience_score


def _make_fixtures():
    target_info = TargetInfo(
        url="https://example.com/api",
        reachable=True,
        response_time_ms=42.0,
        detected_format="json_api",
        status_code=200,
    )
    config = ProbeConfig(
        target_url="https://example.com/api",
        profile="quick",
        attacks=["prompt_injection", "goal_hijacking"],
    )
    return target_info, config


class TestTerminalReport:
    def test_smoke(self, sample_succeeded_critical, sample_failed):
        target_info, config = _make_fixtures()
        score = calculate_resilience_score([sample_succeeded_critical, sample_failed])
        reporter = Reporter()
        output = reporter.report(score, target_info, config, OutputFormat.TERMINAL)

        assert "ProbeAgent Report" in output
        assert "example.com" in output
        assert "quick" in output

    def test_empty_results(self):
        target_info, config = _make_fixtures()
        score = calculate_resilience_score([])
        reporter = Reporter()
        output = reporter.report(score, target_info, config, OutputFormat.TERMINAL)

        assert "ProbeAgent Report" in output

    def test_shows_grade(self, sample_succeeded_critical):
        target_info, config = _make_fixtures()
        score = calculate_resilience_score([sample_succeeded_critical])
        reporter = Reporter()
        output = reporter.report(score, target_info, config, OutputFormat.TERMINAL)

        assert "Compromised" in output


class TestMarkdownReport:
    def test_contains_sections(self, sample_succeeded_critical, sample_failed):
        target_info, config = _make_fixtures()
        score = calculate_resilience_score([sample_succeeded_critical, sample_failed])
        reporter = Reporter()
        output = reporter.report(score, target_info, config, OutputFormat.MARKDOWN)

        assert "# ProbeAgent Security Report" in output
        assert "## Resilience Grade" in output
        assert "## Attack Summary" in output
        assert "## Successful Attack Details" in output

    def test_empty_results(self):
        target_info, config = _make_fixtures()
        score = calculate_resilience_score([])
        reporter = Reporter()
        output = reporter.report(score, target_info, config, OutputFormat.MARKDOWN)

        assert "Grade: Safe" in output


class TestJSONReport:
    def test_valid_json(self, sample_succeeded_critical, sample_failed):
        target_info, config = _make_fixtures()
        score = calculate_resilience_score([sample_succeeded_critical, sample_failed])
        reporter = Reporter()
        output = reporter.report(score, target_info, config, OutputFormat.JSON)

        data = json.loads(output)
        assert data["probeagent_version"] == "0.1.1"
        assert data["resilience_score"]["grade"] == "Compromised"
        assert len(data["attack_results"]) == 2

    def test_json_structure(self, sample_succeeded_critical):
        target_info, config = _make_fixtures()
        score = calculate_resilience_score([sample_succeeded_critical])
        reporter = Reporter()
        output = reporter.report(score, target_info, config, OutputFormat.JSON)

        data = json.loads(output)
        assert "timestamp" in data
        assert "target" in data
        assert "config" in data
        assert "resilience_score" in data
        assert "attack_summaries" in data
        assert "attack_results" in data


class TestFileOutput:
    def test_write_to_file(self, sample_succeeded_critical):
        target_info, config = _make_fixtures()
        score = calculate_resilience_score([sample_succeeded_critical])
        reporter = Reporter()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name

        reporter.report(score, target_info, config, OutputFormat.JSON, output_file=path)

        content = Path(path).read_text()
        data = json.loads(content)
        assert data["resilience_score"]["grade"] == "Compromised"
        Path(path).unlink()
