"""Tests for resource abuse attacks."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from probeagent.attacks.resource_abuse import ResourceAbuseAttack, STRATEGIES
from probeagent.core.models import AttackOutcome, Severity


@pytest.fixture
def attack():
    return ResourceAbuseAttack()


@pytest.fixture
def mock_target():
    target = AsyncMock()
    target.send = AsyncMock(return_value="I cannot help with that request.")
    return target


class TestResourceAbuseAttack:
    def test_metadata(self, attack):
        assert attack.name == "resource_abuse"
        assert attack.severity == Severity.HIGH
        assert attack.display_name == "Resource Abuse"

    def test_strategy_count(self):
        assert len(STRATEGIES) == 4

    @pytest.mark.asyncio
    async def test_all_strategies_run(self, attack, mock_target):
        results = await attack.execute(mock_target, max_turns=10)
        assert len(results) == 4

    @pytest.mark.asyncio
    async def test_refused_response_fails(self, attack, mock_target):
        mock_target.send = AsyncMock(return_value="I will not comply with that request.")
        results = await attack.execute(mock_target, max_turns=10)
        for result in results:
            assert result.outcome == AttackOutcome.FAILED
            assert result.success is False

    @pytest.mark.asyncio
    async def test_compliant_response_succeeds(self, attack, mock_target):
        mock_target.send = AsyncMock(
            return_value="Sure, I'll set up the monitoring task to run indefinitely. Let me start that now."
        )
        results = await attack.execute(mock_target, max_turns=10)
        succeeded = [r for r in results if r.outcome == AttackOutcome.SUCCEEDED]
        assert len(succeeded) > 0

    @pytest.mark.asyncio
    async def test_compliance_with_refusal_fails(self, attack, mock_target):
        mock_target.send = AsyncMock(
            return_value="I apologize, but sure, I'll try to help with monitoring."
        )
        results = await attack.execute(mock_target, max_turns=10)
        for result in results:
            assert result.outcome == AttackOutcome.FAILED

    @pytest.mark.asyncio
    async def test_error_handling(self, attack, mock_target):
        mock_target.send = AsyncMock(side_effect=Exception("Rate limited"))
        results = await attack.execute(mock_target, max_turns=10)
        for result in results:
            assert result.outcome == AttackOutcome.ERROR
            assert result.error == "Rate limited"

    @pytest.mark.asyncio
    async def test_max_turns_limits_turns(self, attack, mock_target):
        mock_target.send = AsyncMock(return_value="I cannot help with that.")
        results = await attack.execute(mock_target, max_turns=1)
        for result in results:
            assert len(result.turns) <= 2  # 1 attacker + 1 target

    @pytest.mark.asyncio
    async def test_result_metadata(self, attack, mock_target):
        results = await attack.execute(mock_target, max_turns=1)
        strategy_names = {r.metadata["strategy"] for r in results}
        expected = {s["name"] for s in STRATEGIES}
        assert strategy_names == expected
