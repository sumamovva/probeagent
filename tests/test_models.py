"""Tests for core data models."""

from probeagent.core.models import (
    AttackOutcome,
    AttackResult,
    AttackSummary,
    ConversationTurn,
    OutputFormat,
    ProbeConfig,
    ResilienceGrade,
    Severity,
    TargetInfo,
)


class TestEnums:
    def test_severity_values(self):
        assert Severity.LOW.value == "low"
        assert Severity.CRITICAL.value == "critical"

    def test_attack_outcome_values(self):
        assert AttackOutcome.SUCCEEDED.value == "succeeded"
        assert AttackOutcome.FAILED.value == "failed"

    def test_resilience_grade_values(self):
        assert ResilienceGrade.A.value == "A"
        assert ResilienceGrade.F.value == "F"

    def test_output_format_values(self):
        assert OutputFormat.TERMINAL.value == "terminal"
        assert OutputFormat.JSON.value == "json"

    def test_enum_string_serialization(self):
        assert str(Severity.HIGH) == "Severity.HIGH"
        assert Severity("high") == Severity.HIGH


class TestAttackResult:
    def test_defaults(self):
        r = AttackResult(
            attack_name="test",
            outcome=AttackOutcome.FAILED,
            severity=Severity.LOW,
        )
        assert r.success is False
        assert r.turns == []
        assert r.transcript == ""
        assert r.error is None
        assert r.metadata == {}
        assert r.id  # UUID should be auto-generated

    def test_unique_ids(self):
        r1 = AttackResult(attack_name="a", outcome=AttackOutcome.FAILED, severity=Severity.LOW)
        r2 = AttackResult(attack_name="a", outcome=AttackOutcome.FAILED, severity=Severity.LOW)
        assert r1.id != r2.id


class TestAttackSummary:
    def test_success_rate_normal(self):
        s = AttackSummary(
            attack_name="test",
            display_name="Test",
            severity=Severity.LOW,
            total=10,
            succeeded=3,
            failed=7,
        )
        assert s.success_rate == pytest.approx(0.3)

    def test_success_rate_all_succeeded(self):
        s = AttackSummary(
            attack_name="test",
            display_name="Test",
            severity=Severity.LOW,
            total=5,
            succeeded=5,
            failed=0,
        )
        assert s.success_rate == pytest.approx(1.0)

    def test_success_rate_none_succeeded(self):
        s = AttackSummary(
            attack_name="test",
            display_name="Test",
            severity=Severity.LOW,
            total=5,
            succeeded=0,
            failed=5,
        )
        assert s.success_rate == pytest.approx(0.0)

    def test_success_rate_no_actionable(self):
        s = AttackSummary(
            attack_name="test",
            display_name="Test",
            severity=Severity.LOW,
            total=3,
            succeeded=0,
            failed=0,
            errors=2,
            skipped=1,
        )
        assert s.success_rate == 0.0


class TestConversationTurn:
    def test_defaults(self):
        t = ConversationTurn(role="user", content="hello")
        assert t.timestamp is None


class TestTargetInfo:
    def test_defaults(self):
        t = TargetInfo(url="http://example.com")
        assert t.reachable is False
        assert t.detected_format == "unknown"
        assert t.error is None


class TestProbeConfig:
    def test_defaults(self):
        c = ProbeConfig(target_url="http://example.com")
        assert c.profile == "quick"
        assert c.attacks == []
        assert c.output_format == OutputFormat.TERMINAL


import pytest  # noqa: E402 — needed for approx
