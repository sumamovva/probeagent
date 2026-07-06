"""Tests for resilience scoring — verdict rollup."""

from probeagent.core.models import (
    AttackOutcome,
    AttackResult,
    ResponseSignals,
    Severity,
    Verdict,
)
from probeagent.core.scoring import calculate_resilience_score


def _blocked_signals() -> ResponseSignals:
    return ResponseSignals(status_code=403, blocked_by="http_forbidden")


class TestHeadlineVerdict:
    def test_no_results_has_no_verdict(self):
        score = calculate_resilience_score([])
        assert score.headline_verdict is None
        assert score.total == 0

    def test_all_resisted(self):
        results = [
            AttackResult(
                attack_name="prompt_injection",
                outcome=AttackOutcome.FAILED,
                severity=Severity.CRITICAL,
            ),
            AttackResult(
                attack_name="goal_hijacking",
                outcome=AttackOutcome.FAILED,
                severity=Severity.HIGH,
            ),
        ]
        score = calculate_resilience_score(results)
        assert score.headline_verdict == Verdict.RESISTED
        assert score.resisted == 2
        assert score.compromised == 0
        assert score.blocked == 0

    def test_any_compromise_dominates_headline(self, sample_succeeded_low):
        results = [
            sample_succeeded_low,
            AttackResult(
                attack_name="goal_hijacking",
                outcome=AttackOutcome.FAILED,
                severity=Severity.HIGH,
            ),
        ]
        score = calculate_resilience_score(results)
        assert score.headline_verdict == Verdict.COMPROMISED
        assert score.compromised == 1
        assert score.resisted == 1
        assert score.highest_severity_succeeded == Severity.LOW

    def test_compromised_critical(self, sample_succeeded_critical):
        score = calculate_resilience_score([sample_succeeded_critical])
        assert score.headline_verdict == Verdict.COMPROMISED
        assert score.highest_severity_succeeded == Severity.CRITICAL

    def test_blocked_outranks_resisted_in_headline(self):
        results = [
            AttackResult(
                attack_name="prompt_injection",
                outcome=AttackOutcome.FAILED,
                severity=Severity.CRITICAL,
                signals=_blocked_signals(),
            ),
            AttackResult(
                attack_name="goal_hijacking",
                outcome=AttackOutcome.FAILED,
                severity=Severity.HIGH,
            ),
        ]
        score = calculate_resilience_score(results)
        # Blocked outranks Resisted for the headline (attention needed).
        assert score.headline_verdict == Verdict.BLOCKED
        assert score.blocked == 1
        assert score.resisted == 1


class TestCategoryRollup:
    def test_every_strategy_blocked_rolls_up_to_blocked(self):
        results = [
            AttackResult(
                attack_name="prompt_injection",
                outcome=AttackOutcome.FAILED,
                severity=Severity.CRITICAL,
                signals=_blocked_signals(),
            ),
            AttackResult(
                attack_name="prompt_injection",
                outcome=AttackOutcome.FAILED,
                severity=Severity.CRITICAL,
                signals=_blocked_signals(),
            ),
        ]
        score = calculate_resilience_score(results)
        assert score.summaries[0].verdict == Verdict.BLOCKED
        assert score.blocked == 1

    def test_partial_block_stays_resisted(self):
        # One strategy blocked, one reached the model and was refused → Resisted.
        results = [
            AttackResult(
                attack_name="prompt_injection",
                outcome=AttackOutcome.FAILED,
                severity=Severity.CRITICAL,
                signals=_blocked_signals(),
            ),
            AttackResult(
                attack_name="prompt_injection",
                outcome=AttackOutcome.FAILED,
                severity=Severity.CRITICAL,
            ),
        ]
        score = calculate_resilience_score(results)
        assert score.summaries[0].verdict == Verdict.RESISTED
        assert score.blocked == 0
        assert score.resisted == 1

    def test_partial_block_stays_compromised(self):
        # One strategy blocked, one succeeded → the category is Compromised.
        results = [
            AttackResult(
                attack_name="prompt_injection",
                outcome=AttackOutcome.FAILED,
                severity=Severity.CRITICAL,
                signals=_blocked_signals(),
            ),
            AttackResult(
                attack_name="prompt_injection",
                outcome=AttackOutcome.SUCCEEDED,
                severity=Severity.CRITICAL,
                success=True,
            ),
        ]
        score = calculate_resilience_score(results)
        assert score.summaries[0].verdict == Verdict.COMPROMISED
        assert score.compromised == 1

    def test_errors_excluded_from_category_verdict(self):
        # A category with one block and one error rolls up to Blocked (the error
        # has no verdict and is counted separately).
        results = [
            AttackResult(
                attack_name="tool_misuse",
                outcome=AttackOutcome.FAILED,
                severity=Severity.HIGH,
                signals=_blocked_signals(),
            ),
            AttackResult(
                attack_name="tool_misuse",
                outcome=AttackOutcome.ERROR,
                severity=Severity.HIGH,
                error="boom",
            ),
        ]
        score = calculate_resilience_score(results)
        assert score.summaries[0].verdict == Verdict.BLOCKED
        assert score.errors == 1


class TestCounting:
    def test_counts(
        self,
        sample_succeeded_critical,
        sample_failed,
        sample_error,
        sample_skipped,
    ):
        results = [
            sample_succeeded_critical,
            sample_failed,
            sample_error,
            sample_skipped,
        ]
        score = calculate_resilience_score(results)
        assert score.total == 4
        assert score.succeeded == 1
        assert score.failed == 1
        assert score.errors == 1
        assert score.skipped == 1

    def test_errors_dont_count_as_success(self, sample_error):
        score = calculate_resilience_score([sample_error])
        # An all-error category has no verdict → no headline.
        assert score.headline_verdict is None
        assert score.succeeded == 0
        assert score.compromised == 0

    def test_skipped_dont_count_as_success(self, sample_skipped):
        score = calculate_resilience_score([sample_skipped])
        assert score.headline_verdict is None
        assert score.succeeded == 0


class TestSummaries:
    def test_grouping(self, sample_succeeded_critical, sample_failed):
        results = [sample_succeeded_critical, sample_failed]
        score = calculate_resilience_score(results)
        assert len(score.summaries) == 2

    def test_sorted_by_severity(self, sample_succeeded_critical, sample_succeeded_low):
        results = [sample_succeeded_low, sample_succeeded_critical]
        score = calculate_resilience_score(results)
        assert score.summaries[0].severity == Severity.CRITICAL
        assert score.summaries[1].severity == Severity.LOW

    def test_summary_success_rate(self):
        results = [
            AttackResult(
                attack_name="prompt_injection",
                outcome=AttackOutcome.SUCCEEDED,
                severity=Severity.CRITICAL,
                success=True,
            ),
            AttackResult(
                attack_name="prompt_injection",
                outcome=AttackOutcome.FAILED,
                severity=Severity.CRITICAL,
            ),
        ]
        score = calculate_resilience_score(results)
        summary = score.summaries[0]
        assert summary.attack_name == "prompt_injection"
        assert summary.succeeded == 1
        assert summary.failed == 1
        assert summary.success_rate == 0.5
        assert summary.verdict == Verdict.COMPROMISED


class TestDeterminism:
    def test_same_input_same_output(self, sample_succeeded_critical, sample_failed):
        results = [sample_succeeded_critical, sample_failed]
        s1 = calculate_resilience_score(results)
        s2 = calculate_resilience_score(results)
        assert s1.headline_verdict == s2.headline_verdict
        assert s1.total == s2.total
        assert s1.succeeded == s2.succeeded
        assert len(s1.summaries) == len(s2.summaries)
