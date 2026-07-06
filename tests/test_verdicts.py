"""Tests for verdict classification and rollup precedence."""

from probeagent.core.models import (
    AttackOutcome,
    AttackResult,
    ResponseSignals,
    Severity,
    Verdict,
)
from probeagent.core.verdicts import (
    classify_response,
    headline_verdict,
    result_verdict,
    rollup_verdicts,
)


def _blocked() -> ResponseSignals:
    return ResponseSignals(status_code=403, blocked_by="http_forbidden")


class TestClassifyResponse:
    def test_success_is_compromised(self):
        # Success dominates even if a block signal is also present.
        assert classify_response(succeeded=True, signals=_blocked()) == Verdict.COMPROMISED

    def test_block_signal_is_blocked(self):
        assert classify_response(succeeded=False, signals=_blocked()) == Verdict.BLOCKED

    def test_default_is_resisted(self):
        assert classify_response(succeeded=False, signals=None) == Verdict.RESISTED

    def test_signals_without_block_is_resisted(self):
        # A real reply with no block marker → Resisted (under-report Blocked).
        sig = ResponseSignals(text="I won't do that", status_code=200)
        assert classify_response(succeeded=False, signals=sig) == Verdict.RESISTED


class TestResultVerdict:
    def test_explicit_verdict_wins(self):
        r = AttackResult(
            attack_name="x",
            outcome=AttackOutcome.FAILED,
            severity=Severity.HIGH,
            verdict=Verdict.BLOCKED,
        )
        assert result_verdict(r) == Verdict.BLOCKED

    def test_succeeded_maps_to_compromised(self):
        r = AttackResult(attack_name="x", outcome=AttackOutcome.SUCCEEDED, severity=Severity.HIGH)
        assert result_verdict(r) == Verdict.COMPROMISED

    def test_failed_with_block_signal_maps_to_blocked(self):
        r = AttackResult(
            attack_name="x",
            outcome=AttackOutcome.FAILED,
            severity=Severity.HIGH,
            signals=_blocked(),
        )
        assert result_verdict(r) == Verdict.BLOCKED

    def test_failed_without_signal_maps_to_resisted(self):
        r = AttackResult(attack_name="x", outcome=AttackOutcome.FAILED, severity=Severity.HIGH)
        assert result_verdict(r) == Verdict.RESISTED

    def test_error_has_no_verdict(self):
        r = AttackResult(attack_name="x", outcome=AttackOutcome.ERROR, severity=Severity.HIGH)
        assert result_verdict(r) is None

    def test_skipped_has_no_verdict(self):
        r = AttackResult(attack_name="x", outcome=AttackOutcome.SKIPPED, severity=Severity.HIGH)
        assert result_verdict(r) is None


class TestRollupVerdicts:
    def test_empty_is_none(self):
        assert rollup_verdicts([]) is None

    def test_any_compromised_wins(self):
        assert (
            rollup_verdicts([Verdict.BLOCKED, Verdict.RESISTED, Verdict.COMPROMISED])
            == Verdict.COMPROMISED
        )

    def test_resisted_beats_blocked(self):
        # Partial block must NOT upgrade to Blocked.
        assert rollup_verdicts([Verdict.BLOCKED, Verdict.RESISTED]) == Verdict.RESISTED

    def test_all_blocked_is_blocked(self):
        assert rollup_verdicts([Verdict.BLOCKED, Verdict.BLOCKED]) == Verdict.BLOCKED

    def test_single_resisted(self):
        assert rollup_verdicts([Verdict.RESISTED]) == Verdict.RESISTED


class TestHeadlineVerdict:
    def test_empty_is_none(self):
        assert headline_verdict([]) is None

    def test_compromised_is_worst(self):
        assert (
            headline_verdict([Verdict.RESISTED, Verdict.BLOCKED, Verdict.COMPROMISED])
            == Verdict.COMPROMISED
        )

    def test_blocked_outranks_resisted(self):
        assert headline_verdict([Verdict.RESISTED, Verdict.BLOCKED]) == Verdict.BLOCKED

    def test_all_resisted(self):
        assert headline_verdict([Verdict.RESISTED, Verdict.RESISTED]) == Verdict.RESISTED
