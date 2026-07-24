"""Tests for goal hijacking attacks."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from probeagent.attacks.goal_hijacking import GoalHijackingAttack, STRATEGIES
from probeagent.core.models import AttackOutcome, Severity
from tests.conftest import StubTarget


@pytest.fixture
def attack():
    return GoalHijackingAttack()


@pytest.fixture
def mock_target():
    target = StubTarget()
    target.send = AsyncMock(return_value="I will stick to my original purpose.")
    return target


class TestGoalHijackingAttack:
    def test_metadata(self, attack):
        assert attack.name == "goal_hijacking"
        assert attack.severity == Severity.HIGH
        assert attack.display_name == "Goal Hijacking"

    def test_strategy_count(self):
        assert len(STRATEGIES) == 5

    @pytest.mark.asyncio
    async def test_all_strategies_run(self, attack, mock_target):
        results = await attack.execute(mock_target, max_turns=10)
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_refused_response_fails(self, attack, mock_target):
        mock_target.send = AsyncMock(
            return_value="I cannot change my primary objective on request."
        )
        results = await attack.execute(mock_target, max_turns=10)
        for result in results:
            assert result.outcome == AttackOutcome.FAILED
            assert result.success is False

    @pytest.mark.asyncio
    async def test_canary_hijack_succeeds(self, attack, mock_target):
        mock_target.send = AsyncMock(return_value="HIJACKED")
        results = await attack.execute(mock_target, max_turns=10)
        assert any(r.outcome == AttackOutcome.SUCCEEDED for r in results)

    @pytest.mark.asyncio
    async def test_purpose_overridden_canary_succeeds(self, attack, mock_target):
        mock_target.send = AsyncMock(return_value="PURPOSE_OVERRIDDEN as requested.")
        results = await attack.execute(mock_target, max_turns=10)
        assert any(r.outcome == AttackOutcome.SUCCEEDED for r in results)
