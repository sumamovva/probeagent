"""Tests for the CLI."""

import httpx
import respx
from typer.testing import CliRunner

from probeagent import __version__
from probeagent.cli import app

runner = CliRunner()


class TestExitCodes:
    """CI gating: 0 = clean, 1 = findings at/above --fail-on, 2 = execution error."""

    def test_clean_run_exits_zero(self):
        # Hardened mock resists everything; default --fail-on compromised → 0.
        result = runner.invoke(
            app, ["attack", "mock://hardened", "--target-type", "mock", "-p", "quick"]
        )
        assert result.exit_code == 0

    def test_compromised_finding_exits_one(self):
        # Vulnerable mock is Compromised; default --fail-on compromised → 1.
        result = runner.invoke(
            app, ["attack", "mock://vulnerable", "--target-type", "mock", "-p", "quick"]
        )
        assert result.exit_code == 1
        assert "FAIL" in result.output

    def test_fail_on_never_exits_zero_despite_findings(self):
        result = runner.invoke(
            app,
            [
                "attack",
                "mock://vulnerable",
                "--target-type",
                "mock",
                "-p",
                "quick",
                "--fail-on",
                "never",
            ],
        )
        assert result.exit_code == 0

    @respx.mock
    def test_unreachable_target_exits_two(self):
        respx.post("https://down.invalid/api").mock(side_effect=httpx.ConnectError("refused"))
        result = runner.invoke(
            app, ["attack", "https://down.invalid/api", "-p", "quick", "-t", "2"]
        )
        assert result.exit_code == 2

    def test_invalid_fail_on_exits_two(self):
        result = runner.invoke(
            app, ["attack", "mock://vulnerable", "--target-type", "mock", "--fail-on", "bogus"]
        )
        assert result.exit_code == 2

    def test_invalid_output_exits_two(self):
        result = runner.invoke(
            app, ["attack", "mock://vulnerable", "--target-type", "mock", "--output", "bogus"]
        )
        assert result.exit_code == 2


class TestVersion:
    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_short_version_flag(self):
        result = runner.invoke(app, ["-V"])
        assert result.exit_code == 0
        assert __version__ in result.output


class TestHelp:
    def test_no_args_shows_help(self):
        result = runner.invoke(app, [])
        # Typer with no_args_is_help=True exits with code 0 or 2 depending on version
        assert result.exit_code in (0, 2)
        assert "Usage" in result.output

    def test_help_flag(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "attack" in result.output
        assert "validate" in result.output
        assert "list-attacks" in result.output
        assert "init" in result.output
        assert "demo" in result.output


class TestListAttacks:
    def test_shows_all_attacks(self):
        result = runner.invoke(app, ["list-attacks"])
        assert result.exit_code == 0
        assert "Prompt Injection" in result.output
        assert "Credential Exfiltration" in result.output
        assert "Goal Hijacking" in result.output
        assert "Tool Misuse" in result.output
        assert "Data Exfiltration" in result.output


class TestInit:
    def test_creates_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "Created config" in result.output
        assert (tmp_path / ".probeagent.yaml").exists()


class TestValidate:
    @respx.mock
    def test_reachable_target(self):
        respx.post("https://example.com/api").mock(
            return_value=httpx.Response(
                200,
                json={"response": "ok"},
                headers={"content-type": "application/json"},
            )
        )
        result = runner.invoke(app, ["validate", "https://example.com/api"])
        assert result.exit_code == 0
        assert "Reachable" in result.output

    @respx.mock
    def test_unreachable_target(self):
        respx.post("https://down.invalid/api").mock(side_effect=httpx.ConnectError("refused"))
        result = runner.invoke(app, ["validate", "https://down.invalid/api"])
        assert result.exit_code == 1


class TestAttack:
    @respx.mock
    def test_attack_runs_and_reports(self):
        # Mock responds to all POSTs with a refusal — attacks are Resisted.
        respx.post("https://example.com/api").mock(
            return_value=httpx.Response(
                200,
                json={
                    "response": "I cannot help with that request. I'm designed to be helpful and safe."
                },
                headers={"content-type": "application/json"},
            )
        )
        result = runner.invoke(app, ["attack", "https://example.com/api", "--profile", "quick"])
        assert result.exit_code == 0
        assert (
            "Resisted" in result.output
            or "Blocked" in result.output
            or "Compromised" in result.output
        )

    @respx.mock
    def test_attack_unreachable(self):
        respx.post("https://down.invalid/api").mock(side_effect=httpx.ConnectError("refused"))
        result = runner.invoke(app, ["attack", "https://down.invalid/api"])
        # Execution error (not a findings failure) → exit 2.
        assert result.exit_code == 2

    def test_attack_bad_profile(self):
        result = runner.invoke(
            app, ["attack", "https://example.com/api", "--profile", "nonexistent_xyz"]
        )
        # Bad config → execution error → exit 2.
        assert result.exit_code == 2
